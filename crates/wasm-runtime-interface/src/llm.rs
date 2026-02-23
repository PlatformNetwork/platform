//! LLM Host Functions for WASM Challenges
//!
//! Provides host functions that allow WASM code to perform LLM inference
//! via the Chutes API (llm.chutes.ai). Gated by `LlmPolicy`.
//!
//! # Host Functions
//!
//! - `llm_chat_completion(req_ptr, req_len, resp_ptr, resp_len) -> i32` — Send chat completion request
//! - `llm_is_available() -> i32` — Check if LLM inference is available (has API key)

use crate::runtime::{HostFunctionRegistrar, RuntimeState, WasmRuntimeError};
use serde::{Deserialize, Serialize};
use std::fmt;
use tracing::warn;
use wasmtime::{Caller, Linker, Memory};

const MAX_CHAT_REQUEST_SIZE: u64 = 4 * 1024 * 1024;
const LLM_REQUEST_TIMEOUT_SECS: u64 = 60;

pub const HOST_LLM_NAMESPACE: &str = "platform_llm";
pub const HOST_LLM_CHAT_COMPLETION: &str = "llm_chat_completion";
pub const HOST_LLM_IS_AVAILABLE: &str = "llm_is_available";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum LlmHostStatus {
    Success = 0,
    Disabled = -1,
    InvalidRequest = -2,
    ApiError = -3,
    BufferTooSmall = -4,
    RateLimited = -5,
    InternalError = -100,
}

impl LlmHostStatus {
    pub fn to_i32(self) -> i32 {
        self as i32
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LlmPolicy {
    pub enabled: bool,
    #[serde(skip)]
    pub api_key: Option<String>,
    pub endpoint: String,
    pub max_requests: u32,
    pub allowed_models: Vec<String>,
}

impl fmt::Debug for LlmPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LlmPolicy")
            .field("enabled", &self.enabled)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("endpoint", &self.endpoint)
            .field("max_requests", &self.max_requests)
            .field("allowed_models", &self.allowed_models)
            .finish()
    }
}

impl Default for LlmPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: None,
            endpoint: "https://llm.chutes.ai/v1/chat/completions".to_string(),
            max_requests: 10,
            allowed_models: Vec::new(),
        }
    }
}

impl LlmPolicy {
    pub fn with_api_key(api_key: String) -> Self {
        Self {
            enabled: true,
            api_key: Some(api_key),
            ..Default::default()
        }
    }

    pub fn is_available(&self) -> bool {
        self.enabled && self.api_key.is_some()
    }
}

pub struct LlmState {
    pub policy: LlmPolicy,
    pub requests_made: u32,
}

impl LlmState {
    pub fn new(policy: LlmPolicy) -> Self {
        Self {
            policy,
            requests_made: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LlmHostFunctions;

impl LlmHostFunctions {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LlmHostFunctions {
    fn default() -> Self {
        Self::new()
    }
}

impl HostFunctionRegistrar for LlmHostFunctions {
    fn register(&self, linker: &mut Linker<RuntimeState>) -> Result<(), WasmRuntimeError> {
        linker
            .func_wrap(
                HOST_LLM_NAMESPACE,
                HOST_LLM_CHAT_COMPLETION,
                |mut caller: Caller<RuntimeState>,
                 req_ptr: i32,
                 req_len: i32,
                 resp_ptr: i32,
                 resp_len: i32|
                 -> i32 {
                    handle_chat_completion(&mut caller, req_ptr, req_len, resp_ptr, resp_len)
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_LLM_NAMESPACE,
                HOST_LLM_IS_AVAILABLE,
                |caller: Caller<RuntimeState>| -> i32 { handle_is_available(&caller) },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        Ok(())
    }
}

fn handle_is_available(caller: &Caller<RuntimeState>) -> i32 {
    let state = &caller.data().llm_state;
    if state.policy.is_available() {
        1
    } else {
        0
    }
}

fn handle_chat_completion(
    caller: &mut Caller<RuntimeState>,
    req_ptr: i32,
    req_len: i32,
    resp_ptr: i32,
    resp_len: i32,
) -> i32 {
    let policy_available;
    let requests_made;
    let max_requests;
    {
        let state = &caller.data().llm_state;
        policy_available = state.policy.is_available();
        requests_made = state.requests_made;
        max_requests = state.policy.max_requests;
    }

    if !policy_available {
        return LlmHostStatus::Disabled.to_i32();
    }

    if requests_made >= max_requests {
        return LlmHostStatus::RateLimited.to_i32();
    }

    if req_ptr < 0 || req_len < 0 || resp_ptr < 0 || resp_len < 0 {
        return LlmHostStatus::InvalidRequest.to_i32();
    }

    let request_bytes = match read_wasm_memory(caller, req_ptr, req_len as usize) {
        Ok(b) => b,
        Err(err) => {
            warn!(error = %err, "llm_chat_completion: failed to read request from wasm memory");
            return LlmHostStatus::InternalError.to_i32();
        }
    };

    let api_key;
    let endpoint;
    {
        let state = &caller.data().llm_state;
        api_key = match &state.policy.api_key {
            Some(k) => k.clone(),
            None => return LlmHostStatus::Disabled.to_i32(),
        };
        endpoint = state.policy.endpoint.clone();
    }

    #[derive(Deserialize)]
    struct ChatRequest {
        model: String,
        messages: Vec<ChatMessage>,
        max_tokens: u32,
        temperature: f32,
    }

    #[derive(Deserialize)]
    struct ChatMessage {
        role: String,
        content: String,
    }

    if request_bytes.len() as u64 > MAX_CHAT_REQUEST_SIZE {
        return LlmHostStatus::InvalidRequest.to_i32();
    }

    let chat_req: ChatRequest = match bincode::deserialize(&request_bytes) {
        Ok(r) => r,
        Err(_) => return LlmHostStatus::InvalidRequest.to_i32(),
    };

    {
        let state = &caller.data().llm_state;
        let allowed = &state.policy.allowed_models;
        if !allowed.is_empty() && !allowed.contains(&chat_req.model) {
            warn!(
                model = %chat_req.model,
                "llm_chat_completion: model not in allowed list"
            );
            return LlmHostStatus::InvalidRequest.to_i32();
        }
    }

    #[derive(Serialize)]
    struct OpenAiRequest {
        model: String,
        messages: Vec<OpenAiMessage>,
        #[serde(skip_serializing_if = "Option::is_none")]
        max_tokens: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        temperature: Option<f32>,
    }

    #[derive(Serialize)]
    struct OpenAiMessage {
        role: String,
        content: String,
    }

    let openai_req = OpenAiRequest {
        model: chat_req.model,
        messages: chat_req
            .messages
            .into_iter()
            .map(|m| OpenAiMessage {
                role: m.role,
                content: m.content,
            })
            .collect(),
        max_tokens: Some(chat_req.max_tokens),
        temperature: Some(chat_req.temperature),
    };

    let json_body = match serde_json::to_vec(&openai_req) {
        Ok(b) => b,
        Err(_) => return LlmHostStatus::InvalidRequest.to_i32(),
    };

    let client = reqwest::blocking::Client::new();
    let http_response = match client
        .post(&endpoint)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", api_key))
        .body(json_body)
        .timeout(std::time::Duration::from_secs(LLM_REQUEST_TIMEOUT_SECS))
        .send()
    {
        Ok(r) => r,
        Err(err) => {
            warn!(error = %err, "llm_chat_completion: HTTP request failed");
            return LlmHostStatus::ApiError.to_i32();
        }
    };

    let response_body = match http_response.bytes() {
        Ok(b) => b.to_vec(),
        Err(err) => {
            warn!(error = %err, "llm_chat_completion: failed to read response body");
            return LlmHostStatus::ApiError.to_i32();
        }
    };

    #[derive(Deserialize)]
    struct OpenAiResponse {
        choices: Option<Vec<OpenAiChoice>>,
        usage: Option<OpenAiUsage>,
    }

    #[derive(Deserialize)]
    struct OpenAiChoice {
        message: Option<OpenAiRespMessage>,
    }

    #[derive(Deserialize)]
    struct OpenAiRespMessage {
        content: Option<String>,
    }

    #[derive(Deserialize)]
    struct OpenAiUsage {
        prompt_tokens: Option<u32>,
        completion_tokens: Option<u32>,
        total_tokens: Option<u32>,
    }

    let openai_resp: OpenAiResponse = match serde_json::from_slice(&response_body) {
        Ok(r) => r,
        Err(err) => {
            warn!(error = %err, "llm_chat_completion: failed to parse OpenAI response");
            return LlmHostStatus::ApiError.to_i32();
        }
    };

    let content = openai_resp
        .choices
        .and_then(|mut c| c.pop())
        .and_then(|c| c.message)
        .and_then(|m| m.content)
        .unwrap_or_default();

    #[derive(Serialize)]
    struct LlmResponsePayload {
        content: String,
        usage: Option<LlmUsagePayload>,
    }

    #[derive(Serialize)]
    struct LlmUsagePayload {
        prompt_tokens: u32,
        completion_tokens: u32,
        total_tokens: u32,
    }

    let usage = openai_resp.usage.map(|u| LlmUsagePayload {
        prompt_tokens: u.prompt_tokens.unwrap_or(0),
        completion_tokens: u.completion_tokens.unwrap_or(0),
        total_tokens: u.total_tokens.unwrap_or(0),
    });

    let response_payload = LlmResponsePayload { content, usage };

    let response_bytes = match bincode::serialize(&response_payload) {
        Ok(b) => b,
        Err(_) => return LlmHostStatus::InternalError.to_i32(),
    };

    if response_bytes.len() > resp_len as usize {
        return LlmHostStatus::BufferTooSmall.to_i32();
    }

    if let Err(err) = write_wasm_memory(caller, resp_ptr, &response_bytes) {
        warn!(error = %err, "llm_chat_completion: failed to write response to wasm memory");
        return LlmHostStatus::InternalError.to_i32();
    }

    caller.data_mut().llm_state.requests_made += 1;

    response_bytes.len() as i32
}

fn read_wasm_memory(
    caller: &mut Caller<RuntimeState>,
    ptr: i32,
    len: usize,
) -> Result<Vec<u8>, String> {
    if ptr < 0 {
        return Err("negative pointer".to_string());
    }
    let ptr = ptr as usize;
    let memory = get_memory(caller).ok_or_else(|| "memory export not found".to_string())?;
    let end = ptr
        .checked_add(len)
        .ok_or_else(|| "pointer overflow".to_string())?;
    let data = memory.data(caller);
    if end > data.len() {
        return Err("memory read out of bounds".to_string());
    }
    Ok(data[ptr..end].to_vec())
}

fn write_wasm_memory(
    caller: &mut Caller<RuntimeState>,
    ptr: i32,
    bytes: &[u8],
) -> Result<(), String> {
    if ptr < 0 {
        return Err("negative pointer".to_string());
    }
    let ptr = ptr as usize;
    let memory = get_memory(caller).ok_or_else(|| "memory export not found".to_string())?;
    let end = ptr
        .checked_add(bytes.len())
        .ok_or_else(|| "pointer overflow".to_string())?;
    let data = memory.data_mut(caller);
    if end > data.len() {
        return Err("memory write out of bounds".to_string());
    }
    data[ptr..end].copy_from_slice(bytes);
    Ok(())
}

fn get_memory(caller: &mut Caller<RuntimeState>) -> Option<Memory> {
    let memory_export = caller.data().memory_export.clone();
    caller
        .get_export(&memory_export)
        .and_then(|export| export.into_memory())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llm_host_status_values() {
        assert_eq!(LlmHostStatus::Success.to_i32(), 0);
        assert_eq!(LlmHostStatus::Disabled.to_i32(), -1);
        assert_eq!(LlmHostStatus::InvalidRequest.to_i32(), -2);
        assert_eq!(LlmHostStatus::ApiError.to_i32(), -3);
        assert_eq!(LlmHostStatus::BufferTooSmall.to_i32(), -4);
        assert_eq!(LlmHostStatus::RateLimited.to_i32(), -5);
        assert_eq!(LlmHostStatus::InternalError.to_i32(), -100);
    }

    #[test]
    fn test_llm_policy_default() {
        let policy = LlmPolicy::default();
        assert!(!policy.enabled);
        assert!(policy.api_key.is_none());
        assert!(!policy.is_available());
    }

    #[test]
    fn test_llm_policy_with_api_key() {
        let policy = LlmPolicy::with_api_key("test-key".to_string());
        assert!(policy.enabled);
        assert!(policy.is_available());
        assert_eq!(policy.api_key, Some("test-key".to_string()));
    }

    #[test]
    fn test_llm_state_creation() {
        let state = LlmState::new(LlmPolicy::default());
        assert_eq!(state.requests_made, 0);
        assert!(!state.policy.is_available());
    }

    #[test]
    fn test_llm_policy_debug_redacts_api_key() {
        let policy = LlmPolicy::with_api_key("super-secret-key-12345".to_string());
        let debug_output = format!("{:?}", policy);
        assert!(!debug_output.contains("super-secret-key-12345"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_llm_policy_serialize_skips_api_key() {
        let policy = LlmPolicy::with_api_key("secret-key".to_string());
        let serialized = bincode::serialize(&policy).unwrap();
        let deserialized: LlmPolicy = bincode::deserialize(&serialized).unwrap();
        assert!(deserialized.api_key.is_none());
    }
}
