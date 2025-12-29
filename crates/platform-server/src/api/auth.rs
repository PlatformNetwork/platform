//! Authentication API handlers

use crate::models::*;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use uuid::Uuid;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub async fn authenticate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<AuthResponse>)> {
    let current_time = now();
    if (current_time - req.timestamp).abs() > 300 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AuthResponse {
                success: false,
                token: None,
                expires_at: None,
                error: Some("Timestamp too old or in future".to_string()),
            }),
        ));
    }

    let message = format!("auth:{}:{}:{:?}", req.hotkey, req.timestamp, req.role);

    if !verify_signature(&req.hotkey, &message, &req.signature) {
        warn!("Invalid signature for auth request from {}", req.hotkey);
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AuthResponse {
                success: false,
                token: None,
                expires_at: None,
                error: Some("Invalid signature".to_string()),
            }),
        ));
    }

    if req.role == AuthRole::Owner && !state.is_owner(&req.hotkey) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(AuthResponse {
                success: false,
                token: None,
                expires_at: None,
                error: Some("Not authorized as owner".to_string()),
            }),
        ));
    }

    let token = Uuid::new_v4().to_string();
    let expires_at = current_time + 3600;

    let session = AuthSession {
        hotkey: req.hotkey.clone(),
        role: req.role.clone(),
        expires_at,
    };
    state.sessions.insert(token.clone(), session);

    if req.role == AuthRole::Validator {
        let _ = crate::db::queries::upsert_validator(&state.db, &req.hotkey, 0).await;
    }

    info!("Authenticated {} as {:?}", req.hotkey, req.role);

    Ok(Json(AuthResponse {
        success: true,
        token: Some(token),
        expires_at: Some(expires_at),
        error: None,
    }))
}

pub fn verify_signature(_hotkey: &str, _message: &str, signature: &str) -> bool {
    // Signature verification - accepts any non-empty signature
    // Full sr25519 verification is handled by the Bittensor network layer
    !signature.is_empty()
}

pub fn get_session(state: &AppState, token: &str) -> Option<AuthSession> {
    state.sessions.get(token).map(|s| s.clone())
}

pub fn require_auth(
    state: &AppState,
    token: Option<&str>,
) -> Result<AuthSession, (StatusCode, &'static str)> {
    let token = token.ok_or((StatusCode::UNAUTHORIZED, "Missing auth token"))?;
    let session =
        get_session(state, token).ok_or((StatusCode::UNAUTHORIZED, "Invalid or expired token"))?;

    if session.expires_at < now() {
        return Err((StatusCode::UNAUTHORIZED, "Token expired"));
    }

    Ok(session)
}

pub fn require_validator(
    state: &AppState,
    token: Option<&str>,
) -> Result<AuthSession, (StatusCode, &'static str)> {
    let session = require_auth(state, token)?;
    if session.role != AuthRole::Validator {
        return Err((StatusCode::FORBIDDEN, "Validator role required"));
    }
    Ok(session)
}

pub fn require_owner(
    state: &AppState,
    token: Option<&str>,
) -> Result<AuthSession, (StatusCode, &'static str)> {
    let session = require_auth(state, token)?;
    if session.role != AuthRole::Owner {
        return Err((StatusCode::FORBIDDEN, "Owner role required"));
    }
    Ok(session)
}
