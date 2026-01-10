//! Bridge API - Generic proxy to challenge containers
//!
//! This module provides a generic bridge endpoint that proxies requests to
//! any challenge container via `/api/v1/bridge/{challenge_name}/*`
//!
//! Example:
//!   POST /api/v1/bridge/term-challenge/submit
//!   GET  /api/v1/bridge/term-challenge/leaderboard
//!   POST /api/v1/bridge/math-challenge/submit

use crate::state::AppState;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Get challenge endpoint URL by name
/// Looks up in challenge manager or environment variable CHALLENGE_{NAME}_URL
fn get_challenge_url(state: &AppState, challenge_name: &str) -> Option<String> {
    // Normalize challenge name (replace - with _)
    let env_name = challenge_name.to_uppercase().replace('-', "_");

    // First check environment variable: CHALLENGE_{NAME}_URL
    let env_key = format!("CHALLENGE_{}_URL", env_name);
    if let Ok(url) = std::env::var(&env_key) {
        debug!("Found {} = {}", env_key, url);
        return Some(url);
    }

    // Also check legacy TERM_CHALLENGE_URL for backward compatibility
    if challenge_name == "term-challenge" || challenge_name == "term" {
        if let Ok(url) = std::env::var("TERM_CHALLENGE_URL") {
            return Some(url);
        }
    }

    // Then check challenge manager
    if let Some(ref manager) = state.challenge_manager {
        // Try exact name
        if let Some(endpoint) = manager.get_endpoint(challenge_name) {
            return Some(endpoint);
        }

        // Try with -server suffix
        let with_server = format!("{}-server", challenge_name);
        if let Some(endpoint) = manager.get_endpoint(&with_server) {
            return Some(endpoint);
        }

        // Try challenge- prefix
        let with_prefix = format!("challenge-{}", challenge_name);
        if let Some(endpoint) = manager.get_endpoint(&with_prefix) {
            return Some(endpoint);
        }
    }

    None
}

/// Generic proxy to any challenge
async fn proxy_to_challenge(
    state: &AppState,
    challenge_name: &str,
    path: &str,
    request: Request<Body>,
) -> Response {
    let base_url = match get_challenge_url(state, challenge_name) {
        Some(url) => url,
        None => {
            warn!(
                "Challenge '{}' not available - no endpoint configured",
                challenge_name
            );
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "Challenge not found",
                    "challenge": challenge_name,
                    "hint": format!("Set CHALLENGE_{}_URL or ensure challenge is running",
                        challenge_name.to_uppercase().replace('-', "_"))
                })),
            )
                .into_response();
        }
    };

    let url = format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    debug!(
        "Proxying to challenge '{}': {} -> {}",
        challenge_name, path, url
    );

    let method = request.method().clone();
    let headers = request.headers().clone();

    let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to read request body: {}", e);
            return (StatusCode::BAD_REQUEST, "Failed to read request body").into_response();
        }
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .unwrap();

    let mut req_builder = client.request(method, &url);
    for (key, value) in headers.iter() {
        if key != "host" && key != "content-length" {
            req_builder = req_builder.header(key, value);
        }
    }

    if !body_bytes.is_empty() {
        req_builder = req_builder.body(body_bytes.to_vec());
    }

    match req_builder.send().await {
        Ok(resp) => {
            let status = resp.status();
            let headers = resp.headers().clone();

            match resp.bytes().await {
                Ok(body) => {
                    let mut response = Response::builder().status(status);
                    for (key, value) in headers.iter() {
                        response = response.header(key, value);
                    }
                    response
                        .body(Body::from(body))
                        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
                }
                Err(e) => {
                    error!("Failed to read response: {}", e);
                    StatusCode::BAD_GATEWAY.into_response()
                }
            }
        }
        Err(e) => {
            if e.is_timeout() {
                (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(serde_json::json!({
                        "error": "Challenge timeout",
                        "challenge": challenge_name
                    })),
                )
                    .into_response()
            } else if e.is_connect() {
                warn!(
                    "Cannot connect to challenge '{}' at {}: {}",
                    challenge_name, base_url, e
                );
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "Challenge not reachable",
                        "challenge": challenge_name,
                        "url": base_url
                    })),
                )
                    .into_response()
            } else {
                error!("Proxy error for '{}': {}", challenge_name, e);
                (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": format!("Proxy error: {}", e),
                        "challenge": challenge_name
                    })),
                )
                    .into_response()
            }
        }
    }
}

/// ANY /api/v1/bridge/{challenge_name}/*path - Generic bridge to any challenge
///
/// Routes:
///   /api/v1/bridge/term-challenge/submit -> term-challenge /api/v1/submit
///   /api/v1/bridge/term-challenge/leaderboard -> term-challenge /leaderboard (root-level)
///   /api/v1/bridge/term-challenge/get_weights -> term-challenge /get_weights (root-level)
///   /api/v1/bridge/math-challenge/evaluate -> math-challenge /api/v1/evaluate
pub async fn bridge_to_challenge(
    State(state): State<Arc<AppState>>,
    Path((challenge_name, path)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    info!(
        "Bridge request: challenge='{}' path='/{}'",
        challenge_name, path
    );

    // Root-level endpoints that don't need /api/v1/ prefix
    const ROOT_LEVEL_ENDPOINTS: &[&str] = &["get_weights", "leaderboard", "evaluate", "health"];

    // Construct the API path
    let api_path = if path.starts_with("api/") {
        // Already has api/ prefix
        format!("/{}", path)
    } else if ROOT_LEVEL_ENDPOINTS
        .iter()
        .any(|e| path == *e || path.starts_with(&format!("{}/", e)))
    {
        // Root-level endpoints on challenge servers
        format!("/{}", path)
    } else {
        // Default: add /api/v1/ prefix
        format!("/api/v1/{}", path)
    };

    proxy_to_challenge(&state, &challenge_name, &api_path, request).await
}

/// GET /api/v1/bridge - List available challenges
pub async fn list_bridges(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let mut challenges = vec![];

    // Check known challenge environment variables
    for name in &["TERM_CHALLENGE", "MATH_CHALLENGE", "CODE_CHALLENGE"] {
        let env_key = format!("{}_URL", name);
        if std::env::var(&env_key).is_ok() {
            challenges.push(name.to_lowercase().replace('_', "-"));
        }
    }

    // Add from challenge manager
    if let Some(ref manager) = state.challenge_manager {
        for id in manager.list_challenge_ids() {
            if !challenges.contains(&id) {
                challenges.push(id);
            }
        }
    }

    Json(serde_json::json!({
        "bridges": challenges,
        "usage": "/api/v1/bridge/{challenge_name}/{path}",
        "example": "/api/v1/bridge/term-challenge/submit"
    }))
}
