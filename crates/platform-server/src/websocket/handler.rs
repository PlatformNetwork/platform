//! WebSocket connection handler

use crate::api::auth::verify_signature;
use crate::db::queries;
use crate::models::WsEvent;
use crate::state::AppState;
use crate::websocket::events::WsConnection;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    /// Validator hotkey (SS58 format)
    pub hotkey: Option<String>,
    /// Timestamp for signature verification
    pub timestamp: Option<i64>,
    /// Signature of "ws_connect:{hotkey}:{timestamp}"
    pub signature: Option<String>,
    /// Role (validator, miner, etc.)
    pub role: Option<String>,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Query(query): Query<WsQuery>,
) -> Response {
    // Verify authentication if hotkey is provided
    if let Some(ref hotkey) = query.hotkey {
        let timestamp = match query.timestamp {
            Some(ts) => ts,
            None => {
                warn!(
                    "WebSocket connection rejected: missing timestamp for hotkey {}",
                    hotkey
                );
                return (StatusCode::UNAUTHORIZED, "Missing timestamp").into_response();
            }
        };

        let signature = match &query.signature {
            Some(sig) => sig,
            None => {
                warn!(
                    "WebSocket connection rejected: missing signature for hotkey {}",
                    hotkey
                );
                return (StatusCode::UNAUTHORIZED, "Missing signature").into_response();
            }
        };

        // Verify timestamp is recent (within 5 minutes)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        if (now - timestamp).abs() > 300 {
            warn!(
                "WebSocket connection rejected: timestamp too old for hotkey {}",
                hotkey
            );
            return (StatusCode::UNAUTHORIZED, "Timestamp too old").into_response();
        }

        // Verify signature
        let message = format!("ws_connect:{}:{}", hotkey, timestamp);
        if !verify_signature(hotkey, &message, signature) {
            warn!(
                "WebSocket connection rejected: invalid signature for hotkey {}",
                hotkey
            );
            return (StatusCode::UNAUTHORIZED, "Invalid signature").into_response();
        }

        info!(
            "WebSocket authenticated for hotkey: {}",
            &hotkey[..16.min(hotkey.len())]
        );
    }

    let conn_id = Uuid::new_v4();
    ws.on_upgrade(move |socket| handle_socket(socket, state, conn_id, query))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>, conn_id: Uuid, query: WsQuery) {
    let (mut sender, mut receiver) = socket.split();

    let conn = WsConnection {
        id: conn_id,
        hotkey: query.hotkey.clone(),
        role: query.role.clone(),
    };
    state.broadcaster.add_connection(conn);

    info!(
        "WebSocket connected: {} (hotkey: {:?}, role: {:?})",
        conn_id, query.hotkey, query.role
    );

    // Register validator in DB when they connect with a hotkey
    // Lookup stake from metagraph (not from client - can't trust client-provided stake)
    if let Some(ref hotkey) = query.hotkey {
        let stake = state.get_validator_stake(hotkey);
        if let Err(e) = queries::upsert_validator(&state.db, hotkey, stake).await {
            warn!("Failed to register validator {}: {}", hotkey, e);
        } else {
            info!(
                "Validator {} registered (stake: {} TAO from metagraph)",
                &hotkey[..16.min(hotkey.len())],
                stake / 1_000_000_000 // Convert RAO to TAO for logging
            );
        }
    }

    let mut event_rx = state.broadcaster.subscribe();

    let send_task = tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(event) => {
                    let msg = match serde_json::to_string(&event) {
                        Ok(json) => json,
                        Err(e) => {
                            error!("Failed to serialize event: {}", e);
                            continue;
                        }
                    };

                    if sender.send(Message::Text(msg)).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Lagged(n)) => {
                    warn!("WebSocket {} lagged by {} messages", conn_id, n);
                }
                Err(RecvError::Closed) => {
                    break;
                }
            }
        }
    });

    let state_clone = state.clone();
    let recv_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    handle_client_message(&state_clone, conn_id, &text).await;
                }
                Ok(Message::Ping(_)) => {
                    debug!("Received ping from {}", conn_id);
                }
                Ok(Message::Pong(_)) => {
                    debug!("Received pong from {}", conn_id);
                }
                Ok(Message::Close(_)) => {
                    info!("WebSocket {} closed by client", conn_id);
                    break;
                }
                Err(e) => {
                    error!("WebSocket error for {}: {}", conn_id, e);
                    break;
                }
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    state.broadcaster.remove_connection(&conn_id);
    info!("WebSocket disconnected: {}", conn_id);
}

async fn handle_client_message(_state: &AppState, conn_id: Uuid, text: &str) {
    let msg: Result<WsEvent, _> = serde_json::from_str(text);

    match msg {
        Ok(WsEvent::Ping) => {
            debug!("Received ping from {}", conn_id);
        }
        Ok(_) => {
            debug!("Received event from {}: {}", conn_id, text);
        }
        Err(e) => {
            warn!("Invalid message from {}: {} - {}", conn_id, text, e);
        }
    }
}
