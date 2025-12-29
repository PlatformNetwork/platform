//! Centralized LLM Proxy - All LLM requests go through platform-server
//!
//! This ensures:
//! - Miner API keys are never exposed to validators
//! - All costs are tracked centrally per agent
//! - Platform owner has full visibility into LLM usage

use crate::db::queries;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, Json};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// ============================================================================
// REQUEST/RESPONSE TYPES
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct LlmChatRequest {
    /// Agent hash to identify which miner's API key to use
    pub agent_hash: String,
    /// Validator making the request (for audit)
    pub validator_hotkey: String,
    /// Chat messages
    pub messages: Vec<ChatMessage>,
    /// Model to use (optional, defaults to provider's default)
    pub model: Option<String>,
    /// Max tokens (optional)
    pub max_tokens: Option<u32>,
    /// Temperature (optional)
    pub temperature: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct LlmChatResponse {
    pub success: bool,
    pub content: Option<String>,
    pub model: Option<String>,
    pub usage: Option<LlmUsage>,
    pub cost_usd: Option<f64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

// ============================================================================
// PROVIDER CONFIGS
// ============================================================================

const OPENROUTER_API_URL: &str = "https://openrouter.ai/api/v1/chat/completions";
const OPENROUTER_DEFAULT_MODEL: &str = "anthropic/claude-3.5-sonnet";

// Pricing per 1M tokens (approximate)
const PRICING_INPUT_PER_M: f64 = 3.0;
const PRICING_OUTPUT_PER_M: f64 = 15.0;

// ============================================================================
// HANDLER
// ============================================================================

/// POST /api/v1/llm/chat - Centralized LLM proxy
pub async fn chat(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LlmChatRequest>,
) -> Result<Json<LlmChatResponse>, (StatusCode, Json<LlmChatResponse>)> {
    // Get submission to find miner's API key
    let submission = queries::get_submission_by_hash(&state.db, &req.agent_hash)
        .await
        .map_err(|e| {
            error!("Failed to get submission: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LlmChatResponse {
                    success: false,
                    content: None,
                    model: None,
                    usage: None,
                    cost_usd: None,
                    error: Some("Failed to get submission".to_string()),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(LlmChatResponse {
                    success: false,
                    content: None,
                    model: None,
                    usage: None,
                    cost_usd: None,
                    error: Some("Agent not found".to_string()),
                }),
            )
        })?;

    let api_key = submission.api_key.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(LlmChatResponse {
                success: false,
                content: None,
                model: None,
                usage: None,
                cost_usd: None,
                error: Some("No API key configured for this agent".to_string()),
            }),
        )
    })?;

    let provider = submission.api_provider.as_deref().unwrap_or("openrouter");

    debug!(
        "LLM request for agent {} from validator {} via {}",
        &req.agent_hash[..16],
        &req.validator_hotkey[..16.min(req.validator_hotkey.len())],
        provider
    );

    // Make LLM request based on provider
    let result = match provider {
        "openrouter" => call_openrouter(&api_key, &req).await,
        "openai" => call_openai(&api_key, &req).await,
        "anthropic" => call_anthropic(&api_key, &req).await,
        _ => call_openrouter(&api_key, &req).await, // Default to OpenRouter
    };

    match result {
        Ok((content, model, usage)) => {
            // Calculate cost
            let cost_usd = calculate_cost(&usage);

            // Update agent's total cost
            if let Err(e) = queries::add_agent_cost(&state.db, &req.agent_hash, cost_usd).await {
                warn!("Failed to update agent cost: {}", e);
            }

            info!(
                "LLM response for {} - tokens: {}, cost: ${:.4}",
                &req.agent_hash[..16],
                usage.total_tokens,
                cost_usd
            );

            Ok(Json(LlmChatResponse {
                success: true,
                content: Some(content),
                model: Some(model),
                usage: Some(usage),
                cost_usd: Some(cost_usd),
                error: None,
            }))
        }
        Err(e) => {
            error!("LLM request failed for {}: {}", &req.agent_hash[..16], e);
            Err((
                StatusCode::BAD_GATEWAY,
                Json(LlmChatResponse {
                    success: false,
                    content: None,
                    model: None,
                    usage: None,
                    cost_usd: None,
                    error: Some(e),
                }),
            ))
        }
    }
}

// ============================================================================
// PROVIDER IMPLEMENTATIONS
// ============================================================================

async fn call_openrouter(
    api_key: &str,
    req: &LlmChatRequest,
) -> Result<(String, String, LlmUsage), String> {
    let client = Client::new();
    let model = req.model.as_deref().unwrap_or(OPENROUTER_DEFAULT_MODEL);

    let body = serde_json::json!({
        "model": model,
        "messages": req.messages,
        "max_tokens": req.max_tokens.unwrap_or(4096),
        "temperature": req.temperature.unwrap_or(0.7),
    });

    let response = client
        .post(OPENROUTER_API_URL)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .header("HTTP-Referer", "https://platform.network")
        .header("X-Title", "Platform Network")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!("OpenRouter error {}: {}", status, text));
    }

    let data: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Invalid response: {}", e))?;

    let content = data["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let usage = LlmUsage {
        prompt_tokens: data["usage"]["prompt_tokens"].as_u64().unwrap_or(0) as u32,
        completion_tokens: data["usage"]["completion_tokens"].as_u64().unwrap_or(0) as u32,
        total_tokens: data["usage"]["total_tokens"].as_u64().unwrap_or(0) as u32,
    };

    let model_used = data["model"].as_str().unwrap_or(model).to_string();

    Ok((content, model_used, usage))
}

async fn call_openai(
    api_key: &str,
    req: &LlmChatRequest,
) -> Result<(String, String, LlmUsage), String> {
    let client = Client::new();
    let model = req.model.as_deref().unwrap_or("gpt-4o");

    let body = serde_json::json!({
        "model": model,
        "messages": req.messages,
        "max_tokens": req.max_tokens.unwrap_or(4096),
        "temperature": req.temperature.unwrap_or(0.7),
    });

    let response = client
        .post("https://api.openai.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!("OpenAI error {}: {}", status, text));
    }

    let data: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Invalid response: {}", e))?;

    let content = data["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let usage = LlmUsage {
        prompt_tokens: data["usage"]["prompt_tokens"].as_u64().unwrap_or(0) as u32,
        completion_tokens: data["usage"]["completion_tokens"].as_u64().unwrap_or(0) as u32,
        total_tokens: data["usage"]["total_tokens"].as_u64().unwrap_or(0) as u32,
    };

    Ok((content, model.to_string(), usage))
}

async fn call_anthropic(
    api_key: &str,
    req: &LlmChatRequest,
) -> Result<(String, String, LlmUsage), String> {
    let client = Client::new();
    let model = req.model.as_deref().unwrap_or("claude-3-5-sonnet-20241022");

    // Convert messages to Anthropic format
    let system = req
        .messages
        .iter()
        .find(|m| m.role == "system")
        .map(|m| m.content.clone());

    let messages: Vec<_> = req
        .messages
        .iter()
        .filter(|m| m.role != "system")
        .map(|m| {
            serde_json::json!({
                "role": m.role,
                "content": m.content
            })
        })
        .collect();

    let mut body = serde_json::json!({
        "model": model,
        "messages": messages,
        "max_tokens": req.max_tokens.unwrap_or(4096),
    });

    if let Some(sys) = system {
        body["system"] = serde_json::Value::String(sys);
    }

    let response = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!("Anthropic error {}: {}", status, text));
    }

    let data: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Invalid response: {}", e))?;

    let content = data["content"][0]["text"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let usage = LlmUsage {
        prompt_tokens: data["usage"]["input_tokens"].as_u64().unwrap_or(0) as u32,
        completion_tokens: data["usage"]["output_tokens"].as_u64().unwrap_or(0) as u32,
        total_tokens: (data["usage"]["input_tokens"].as_u64().unwrap_or(0)
            + data["usage"]["output_tokens"].as_u64().unwrap_or(0)) as u32,
    };

    Ok((content, model.to_string(), usage))
}

fn calculate_cost(usage: &LlmUsage) -> f64 {
    let input_cost = (usage.prompt_tokens as f64 / 1_000_000.0) * PRICING_INPUT_PER_M;
    let output_cost = (usage.completion_tokens as f64 / 1_000_000.0) * PRICING_OUTPUT_PER_M;
    input_cost + output_cost
}
