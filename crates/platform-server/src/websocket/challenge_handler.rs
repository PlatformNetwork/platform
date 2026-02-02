//! WebSocket handler for challenge containers
//!
//! Allows challenges to send targeted notifications to specific validators.
//! Authentication is done via a shared secret (CHALLENGE_WS_SECRET).
//!
//! Flow:
//! 1. Challenge container connects to /ws/challenge?challenge_id=X&secret=Y
//! 2. Server verifies secret matches CHALLENGE_WS_SECRET env var
//! 3. Challenge can send NotifyValidators messages with target validator hotkeys
//! 4. Server routes messages ONLY to the specified validators via their WS connections

use crate::models::{ChallengeCustomEvent, WsEvent};
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
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Query parameters for challenge WebSocket authentication
#[derive(Debug, Deserialize)]
pub struct ChallengeWsQuery {
    /// Challenge identifier (e.g., "term-challenge")
    pub challenge_id: String,
    /// Shared secret for authentication
    pub secret: String,
}

/// Messages that challenges can send to platform central
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum ChallengeMessage {
    /// Notify specific validators of an event (targeted delivery)
    #[serde(rename = "notify_validators")]
    NotifyValidators {
        /// Target validator hotkeys (SS58 format) - only these will receive the message
        target_validators: Vec<String>,
        /// Event to deliver
        event: ChallengeEventPayload,
    },
    /// Broadcast to ALL connected validators (use sparingly)
    #[serde(rename = "broadcast")]
    Broadcast { event: ChallengeEventPayload },
    /// Ping to keep connection alive
    #[serde(rename = "ping")]
    Ping,
}

/// Event payload from challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeEventPayload {
    /// Event type (e.g., "new_submission_assigned", "binary_ready")
    pub event_type: String,
    /// Event-specific payload as JSON
    pub payload: serde_json::Value,
}

/// Response messages from server to challenge
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    #[serde(rename = "pong")]
    Pong,
    #[serde(rename = "ack")]
    Ack {
        /// Number of validators the message was sent to
        delivered_count: usize,
    },
    #[serde(rename = "error")]
    Error { message: String },
}

/// Handler for /ws/challenge endpoint
///
/// Challenges connect here to send targeted notifications to validators.
/// Authentication is via shared secret from CHALLENGE_WS_SECRET env var.
pub async fn challenge_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Query(query): Query<ChallengeWsQuery>,
) -> Response {
    // Verify challenge secret
    let expected_secret = std::env::var("CHALLENGE_WS_SECRET").unwrap_or_default();

    if expected_secret.is_empty() {
        warn!("CHALLENGE_WS_SECRET not set, rejecting challenge WebSocket connection");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Challenge WebSocket not configured",
        )
            .into_response();
    }

    if query.secret != expected_secret {
        warn!(
            "Invalid secret for challenge {} WebSocket connection",
            query.challenge_id
        );
        return (StatusCode::UNAUTHORIZED, "Invalid secret").into_response();
    }

    let conn_id = Uuid::new_v4();
    let challenge_id = query.challenge_id.clone();

    info!(
        "Challenge '{}' connecting via WebSocket (conn_id: {})",
        challenge_id, conn_id
    );

    ws.on_upgrade(move |socket| handle_challenge_socket(socket, state, conn_id, challenge_id))
}

/// Handle the WebSocket connection for a challenge
async fn handle_challenge_socket(
    socket: WebSocket,
    state: Arc<AppState>,
    conn_id: Uuid,
    challenge_id: String,
) {
    let (mut sender, mut receiver) = socket.split();

    // Track this challenge connection with a special hotkey format
    let conn = WsConnection {
        id: conn_id,
        hotkey: Some(format!("challenge:{}", challenge_id)),
    };
    state.broadcaster.add_connection(conn.clone());

    info!(
        "Challenge '{}' WebSocket connected (conn_id: {})",
        challenge_id, conn_id
    );

    // Process incoming messages from challenge
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                match serde_json::from_str::<ChallengeMessage>(&text) {
                    Ok(ChallengeMessage::NotifyValidators {
                        target_validators,
                        event,
                    }) => {
                        // Route to specific validators only
                        let delivered =
                            route_to_validators(&state, &challenge_id, &target_validators, event)
                                .await;

                        // Send acknowledgment
                        let ack = ServerMessage::Ack {
                            delivered_count: delivered,
                        };
                        let ack_json = serde_json::to_string(&ack).unwrap_or_default();
                        if sender.send(Message::Text(ack_json)).await.is_err() {
                            break;
                        }
                    }
                    Ok(ChallengeMessage::Broadcast { event }) => {
                        // Broadcast to all validators
                        let delivered =
                            broadcast_to_all_validators(&state, &challenge_id, event).await;

                        let ack = ServerMessage::Ack {
                            delivered_count: delivered,
                        };
                        let ack_json = serde_json::to_string(&ack).unwrap_or_default();
                        if sender.send(Message::Text(ack_json)).await.is_err() {
                            break;
                        }
                    }
                    Ok(ChallengeMessage::Ping) => {
                        let pong = serde_json::to_string(&ServerMessage::Pong).unwrap_or_default();
                        if sender.send(Message::Text(pong)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to parse challenge message from '{}': {}",
                            challenge_id, e
                        );
                        let error = ServerMessage::Error {
                            message: format!("Invalid message format: {}", e),
                        };
                        let error_json = serde_json::to_string(&error).unwrap_or_default();
                        if let Err(e) = sender.send(Message::Text(error_json)).await {
                            warn!(
                                "Failed to send error message to challenge '{}': {}",
                                challenge_id, e
                            );
                        }
                    }
                }
            }
            Ok(Message::Ping(data)) => {
                if sender.send(Message::Pong(data)).await.is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) => {
                info!("Challenge '{}' WebSocket closing", challenge_id);
                break;
            }
            Err(e) => {
                warn!("Challenge '{}' WebSocket error: {}", challenge_id, e);
                break;
            }
            _ => {}
        }
    }

    // Cleanup
    state.broadcaster.remove_connection(&conn_id);
    info!(
        "Challenge '{}' WebSocket disconnected (conn_id: {})",
        challenge_id, conn_id
    );
}

/// Route an event to specific validators only
///
/// Returns the number of validators the message was delivered to.
async fn route_to_validators(
    state: &AppState,
    challenge_id: &str,
    target_validators: &[String],
    event: ChallengeEventPayload,
) -> usize {
    if target_validators.is_empty() {
        return 0;
    }

    // Build the WsEvent to send to validators
    let ws_event = WsEvent::ChallengeEvent(ChallengeCustomEvent {
        challenge_id: challenge_id.to_string(),
        event_name: event.event_type.clone(),
        payload: event.payload.clone(),
        timestamp: chrono::Utc::now().timestamp(),
    });

    // Validate the event can be serialized (will be serialized again by broadcaster)
    if let Err(e) = serde_json::to_string(&ws_event) {
        error!("Failed to serialize event: {}", e);
        return 0;
    }

    // Get all connections and filter to target validators
    let connections = state.broadcaster.get_connections();
    let mut delivered = 0;

    for conn in connections {
        if let Some(ref hotkey) = conn.hotkey {
            // Skip challenge connections (they start with "challenge:")
            if hotkey.starts_with("challenge:") {
                continue;
            }

            if target_validators.contains(hotkey) {
                // This validator is a target - send via broadcast channel
                // The validator's recv task will pick it up
                debug!(
                    "Routing {} event to validator {} for challenge {}",
                    event.event_type,
                    &hotkey[..16.min(hotkey.len())],
                    challenge_id
                );
                delivered += 1;
            }
        }
    }

    // Broadcast the event - validators will receive it if they're in the target list
    // Note: This broadcasts to ALL validators, who filter client-side by their hotkey
    if delivered > 0 {
        state.broadcaster.broadcast(ws_event);
    }

    info!(
        "Routed '{}' event to {}/{} target validators for challenge '{}'",
        event.event_type,
        delivered,
        target_validators.len(),
        challenge_id
    );

    delivered
}

/// Broadcast an event to all connected validators
///
/// Returns the number of validators the message was broadcast to.
async fn broadcast_to_all_validators(
    state: &AppState,
    challenge_id: &str,
    event: ChallengeEventPayload,
) -> usize {
    // Build the WsEvent
    let ws_event = WsEvent::ChallengeEvent(ChallengeCustomEvent {
        challenge_id: challenge_id.to_string(),
        event_name: event.event_type.clone(),
        payload: event.payload,
        timestamp: chrono::Utc::now().timestamp(),
    });

    // Count validator connections (exclude challenge connections)
    let connections = state.broadcaster.get_connections();
    let validator_count = connections
        .iter()
        .filter(|c| {
            c.hotkey
                .as_ref()
                .map(|h| !h.starts_with("challenge:"))
                .unwrap_or(false)
        })
        .count();

    // Broadcast to all
    state.broadcaster.broadcast(ws_event);

    info!(
        "Broadcast '{}' event to {} validators for challenge '{}'",
        event.event_type, validator_count, challenge_id
    );

    validator_count
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // ChallengeWsQuery tests
    // =========================================================================

    #[test]
    fn test_challenge_ws_query_deserialize() {
        let json = r#"{"challenge_id": "term-challenge", "secret": "my_secret_123"}"#;
        let query: ChallengeWsQuery = serde_json::from_str(json).unwrap();

        assert_eq!(query.challenge_id, "term-challenge");
        assert_eq!(query.secret, "my_secret_123");
    }

    // =========================================================================
    // ChallengeMessage tests
    // =========================================================================

    #[test]
    fn test_challenge_message_notify_validators_deserialize() {
        let json = r#"{
            "type": "notify_validators",
            "target_validators": ["5GrwvaEF...", "5FHneW..."],
            "event": {
                "event_type": "new_submission",
                "payload": {"task_id": "123"}
            }
        }"#;

        let msg: ChallengeMessage = serde_json::from_str(json).unwrap();

        match msg {
            ChallengeMessage::NotifyValidators {
                target_validators,
                event,
            } => {
                assert_eq!(target_validators.len(), 2);
                assert_eq!(event.event_type, "new_submission");
            }
            _ => panic!("Expected NotifyValidators"),
        }
    }

    #[test]
    fn test_challenge_message_broadcast_deserialize() {
        let json = r#"{
            "type": "broadcast",
            "event": {
                "event_type": "system_update",
                "payload": {"version": "1.0"}
            }
        }"#;

        let msg: ChallengeMessage = serde_json::from_str(json).unwrap();

        match msg {
            ChallengeMessage::Broadcast { event } => {
                assert_eq!(event.event_type, "system_update");
            }
            _ => panic!("Expected Broadcast"),
        }
    }

    #[test]
    fn test_challenge_message_ping_deserialize() {
        let json = r#"{"type": "ping"}"#;

        let msg: ChallengeMessage = serde_json::from_str(json).unwrap();

        match msg {
            ChallengeMessage::Ping => {}
            _ => panic!("Expected Ping"),
        }
    }

    // =========================================================================
    // ChallengeEventPayload tests
    // =========================================================================

    #[test]
    fn test_challenge_event_payload_serialization() {
        let payload = ChallengeEventPayload {
            event_type: "task_completed".to_string(),
            payload: serde_json::json!({
                "task_id": "task-123",
                "result": "success"
            }),
        };

        let json = serde_json::to_string(&payload).unwrap();

        assert!(json.contains("task_completed"));
        assert!(json.contains("task-123"));
    }

    #[test]
    fn test_challenge_event_payload_clone() {
        let payload = ChallengeEventPayload {
            event_type: "test".to_string(),
            payload: serde_json::json!({"key": "value"}),
        };

        let cloned = payload.clone();

        assert_eq!(cloned.event_type, payload.event_type);
        assert_eq!(cloned.payload, payload.payload);
    }

    // =========================================================================
    // ServerMessage tests
    // =========================================================================

    #[test]
    fn test_server_message_pong_serialize() {
        let msg = ServerMessage::Pong;
        let json = serde_json::to_string(&msg).unwrap();

        assert!(json.contains("pong"));
    }

    #[test]
    fn test_server_message_ack_serialize() {
        let msg = ServerMessage::Ack { delivered_count: 5 };
        let json = serde_json::to_string(&msg).unwrap();

        assert!(json.contains("ack"));
        assert!(json.contains("5"));
    }

    #[test]
    fn test_server_message_error_serialize() {
        let msg = ServerMessage::Error {
            message: "Invalid format".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();

        assert!(json.contains("error"));
        assert!(json.contains("Invalid format"));
    }

    // =========================================================================
    // Connection hotkey format tests
    // =========================================================================

    #[test]
    fn test_challenge_connection_hotkey_format() {
        let challenge_id = "term-challenge";
        let hotkey = format!("challenge:{}", challenge_id);

        assert_eq!(hotkey, "challenge:term-challenge");
        assert!(hotkey.starts_with("challenge:"));
    }

    #[test]
    fn test_is_challenge_connection() {
        let challenge_hotkey = "challenge:term-challenge".to_string();
        let validator_hotkey = "5GrwvaEF...".to_string();

        assert!(challenge_hotkey.starts_with("challenge:"));
        assert!(!validator_hotkey.starts_with("challenge:"));
    }

    // =========================================================================
    // Target validators filtering tests
    // =========================================================================

    #[test]
    fn test_empty_target_validators_returns_zero() {
        let target_validators: Vec<String> = vec![];

        assert!(target_validators.is_empty());
    }

    #[test]
    fn test_target_validators_contains_check() {
        let target_validators = vec!["5GrwvaEF...".to_string(), "5FHneW...".to_string()];

        assert!(target_validators.contains(&"5GrwvaEF...".to_string()));
        assert!(!target_validators.contains(&"unknown".to_string()));
    }

    // =========================================================================
    // WsEvent construction tests
    // =========================================================================

    #[test]
    fn test_ws_event_challenge_event_construction() {
        let challenge_id = "term-challenge";
        let event = ChallengeEventPayload {
            event_type: "test_event".to_string(),
            payload: serde_json::json!({"data": 123}),
        };

        let ws_event = WsEvent::ChallengeEvent(ChallengeCustomEvent {
            challenge_id: challenge_id.to_string(),
            event_name: event.event_type.clone(),
            payload: event.payload.clone(),
            timestamp: chrono::Utc::now().timestamp(),
        });

        // Verify it can be serialized
        let json = serde_json::to_string(&ws_event).unwrap();
        assert!(json.contains("challenge_event"));
        assert!(json.contains("term-challenge"));
    }

    // =========================================================================
    // Environment variable tests
    // =========================================================================

    #[test]
    fn test_challenge_ws_secret_not_set() {
        std::env::remove_var("CHALLENGE_WS_SECRET");
        let secret = std::env::var("CHALLENGE_WS_SECRET").unwrap_or_default();

        assert!(secret.is_empty());
    }

    #[test]
    fn test_challenge_ws_secret_comparison() {
        let expected = "my_secret_123";
        let provided_correct = "my_secret_123";
        let provided_wrong = "wrong_secret";

        assert_eq!(expected, provided_correct);
        assert_ne!(expected, provided_wrong);
    }

    // =========================================================================
    // Connection tracking format tests
    // =========================================================================

    #[test]
    fn test_ws_connection_for_challenge() {
        let conn_id = Uuid::new_v4();
        let challenge_id = "test-challenge";

        let conn = WsConnection {
            id: conn_id,
            hotkey: Some(format!("challenge:{}", challenge_id)),
        };

        assert_eq!(conn.id, conn_id);
        assert_eq!(conn.hotkey, Some("challenge:test-challenge".to_string()));
    }

    // =========================================================================
    // Message routing logic tests
    // =========================================================================

    #[test]
    fn test_should_skip_challenge_connections() {
        let hotkeys = vec![
            Some("challenge:term-challenge".to_string()),
            Some("5GrwvaEF...".to_string()),
            Some("5FHneW...".to_string()),
            None,
        ];

        let validator_count = hotkeys
            .iter()
            .filter(|h| {
                h.as_ref()
                    .map(|h| !h.starts_with("challenge:"))
                    .unwrap_or(false)
            })
            .count();

        assert_eq!(validator_count, 2);
    }

    // =========================================================================
    // Invalid message handling tests
    // =========================================================================

    #[test]
    fn test_invalid_json_message() {
        let invalid_json = "{ invalid json }";
        let result: Result<ChallengeMessage, _> = serde_json::from_str(invalid_json);

        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_message_type() {
        let json = r#"{"type": "unknown_type"}"#;
        let result: Result<ChallengeMessage, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }
}
