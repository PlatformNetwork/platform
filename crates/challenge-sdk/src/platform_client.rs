//! Platform WebSocket Client
//!
//! Connects challenge containers to platform-server via WebSocket.
//! Platform-server initiates evaluation requests, challenge responds with results.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐         ┌──────────────────┐
//! │    Challenge    │◄───WS───│  Platform Server │
//! │   Container     │         │   (orchestrator) │
//! └─────────────────┘         └──────────────────┘
//!         │                           │
//!    No keypairs              Has all keypairs
//!    Stateless eval           Manages auth/signing
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::error::ChallengeError;
use crate::server::{EvaluationRequest, EvaluationResponse, ServerChallenge};

// ============================================================================
// PROTOCOL MESSAGES
// ============================================================================

/// Messages from platform-server to challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ServerMessage {
    /// Authentication response
    #[serde(rename = "auth_response")]
    AuthResponse {
        success: bool,
        error: Option<String>,
        session_id: Option<String>,
    },

    /// Evaluation request
    #[serde(rename = "evaluate")]
    Evaluate(EvaluationRequest),

    /// Cancel an evaluation
    #[serde(rename = "cancel")]
    Cancel { request_id: String, reason: String },

    /// Configuration update
    #[serde(rename = "config_update")]
    ConfigUpdate { config: serde_json::Value },

    /// Health check
    #[serde(rename = "health_check")]
    HealthCheck,

    /// Ping
    #[serde(rename = "ping")]
    Ping { timestamp: i64 },

    /// Shutdown notice
    #[serde(rename = "shutdown")]
    Shutdown {
        reason: String,
        restart_expected: bool,
    },
}

/// Messages from challenge to platform-server
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ChallengeMessage {
    /// Authentication
    #[serde(rename = "auth")]
    Auth {
        challenge_id: String,
        auth_token: String,
        instance_id: Option<String>,
        version: Option<String>,
    },

    /// Evaluation result
    #[serde(rename = "result")]
    Result(EvaluationResponse),

    /// Progress update
    #[serde(rename = "progress")]
    Progress {
        request_id: String,
        progress: f64,
        message: Option<String>,
    },

    /// Health status
    #[serde(rename = "health")]
    Health {
        healthy: bool,
        load: f64,
        pending: u32,
    },

    /// Pong
    #[serde(rename = "pong")]
    Pong { timestamp: i64 },

    /// Log
    #[serde(rename = "log")]
    Log { level: String, message: String },
}

// ============================================================================
// CLIENT CONFIGURATION
// ============================================================================

/// Platform client configuration
#[derive(Debug, Clone)]
pub struct PlatformClientConfig {
    /// WebSocket URL to platform-server
    pub url: String,
    /// Challenge ID
    pub challenge_id: String,
    /// Authentication token
    pub auth_token: String,
    /// Instance ID (for multiple replicas)
    pub instance_id: Option<String>,
    /// Reconnect settings
    pub reconnect_delay: Duration,
    pub max_reconnect_attempts: u32,
}

impl PlatformClientConfig {
    /// Create from environment variables
    pub fn from_env() -> Result<Self, ChallengeError> {
        Ok(Self {
            url: std::env::var("PLATFORM_WS_URL")
                .unwrap_or_else(|_| "ws://localhost:8000/challenges/ws".to_string()),
            challenge_id: std::env::var("CHALLENGE_ID")
                .map_err(|_| ChallengeError::Config("CHALLENGE_ID not set".to_string()))?,
            auth_token: std::env::var("PLATFORM_AUTH_TOKEN")
                .map_err(|_| ChallengeError::Config("PLATFORM_AUTH_TOKEN not set".to_string()))?,
            instance_id: std::env::var("INSTANCE_ID").ok(),
            reconnect_delay: Duration::from_secs(5),
            max_reconnect_attempts: 10,
        })
    }
}

// ============================================================================
// PLATFORM CLIENT
// ============================================================================

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
    Reconnecting,
}

/// Platform WebSocket client
pub struct PlatformClient<C: ServerChallenge + 'static> {
    config: PlatformClientConfig,
    challenge: Arc<C>,
    state: Arc<RwLock<ConnectionState>>,
    message_tx: Option<mpsc::Sender<ChallengeMessage>>,
    pending_count: Arc<RwLock<u32>>,
    started_at: Instant,
}

impl<C: ServerChallenge + 'static> PlatformClient<C> {
    /// Create new client
    pub fn new(config: PlatformClientConfig, challenge: C) -> Self {
        Self {
            config,
            challenge: Arc::new(challenge),
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            message_tx: None,
            pending_count: Arc::new(RwLock::new(0)),
            started_at: Instant::now(),
        }
    }

    /// Connect and run the client
    pub async fn run(&mut self) -> Result<(), ChallengeError> {
        let mut reconnect_attempts = 0;

        loop {
            match self.connect_and_handle().await {
                Ok(_) => {
                    info!("Connection closed normally");
                    break;
                }
                Err(e) => {
                    error!("Connection error: {}", e);
                    reconnect_attempts += 1;

                    if reconnect_attempts >= self.config.max_reconnect_attempts {
                        return Err(ChallengeError::Connection(
                            "Max reconnect attempts exceeded".to_string(),
                        ));
                    }

                    *self.state.write().await = ConnectionState::Reconnecting;
                    info!(
                        "Reconnecting in {:?} (attempt {}/{})",
                        self.config.reconnect_delay,
                        reconnect_attempts,
                        self.config.max_reconnect_attempts
                    );
                    tokio::time::sleep(self.config.reconnect_delay).await;
                }
            }
        }

        Ok(())
    }

    /// Connect and handle messages
    async fn connect_and_handle(&mut self) -> Result<(), ChallengeError> {
        *self.state.write().await = ConnectionState::Connecting;

        info!("Connecting to platform: {}", self.config.url);

        // Connect WebSocket
        let (ws_stream, _) = tokio_tungstenite::connect_async(&self.config.url)
            .await
            .map_err(|e| ChallengeError::Connection(format!("WebSocket error: {}", e)))?;

        let (mut write, mut read) = ws_stream.split();

        // Create message channel
        let (msg_tx, mut msg_rx) = mpsc::channel::<ChallengeMessage>(100);
        self.message_tx = Some(msg_tx.clone());

        // Send authentication
        *self.state.write().await = ConnectionState::Authenticating;

        let auth_msg = ChallengeMessage::Auth {
            challenge_id: self.config.challenge_id.clone(),
            auth_token: self.config.auth_token.clone(),
            instance_id: self.config.instance_id.clone(),
            version: Some(self.challenge.version().to_string()),
        };

        let auth_json = serde_json::to_string(&auth_msg)
            .map_err(|e| ChallengeError::Serialization(e.to_string()))?;

        write
            .send(tokio_tungstenite::tungstenite::Message::Text(auth_json))
            .await
            .map_err(|e| ChallengeError::Connection(format!("Failed to send auth: {}", e)))?;

        // Spawn write task
        let state_write = Arc::clone(&self.state);
        tokio::spawn(async move {
            while let Some(msg) = msg_rx.recv().await {
                match serde_json::to_string(&msg) {
                    Ok(json) => {
                        if write
                            .send(tokio_tungstenite::tungstenite::Message::Text(json))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Failed to serialize message: {}", e);
                    }
                }
            }
        });

        // Handle incoming messages
        let challenge = Arc::clone(&self.challenge);
        let state = Arc::clone(&self.state);
        let pending_count = Arc::clone(&self.pending_count);

        while let Some(msg_result) = read.next().await {
            match msg_result {
                Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                    match serde_json::from_str::<ServerMessage>(&text) {
                        Ok(server_msg) => {
                            self.handle_server_message(
                                server_msg,
                                &msg_tx,
                                &challenge,
                                &state,
                                &pending_count,
                            )
                            .await?;
                        }
                        Err(e) => {
                            warn!("Failed to parse server message: {}", e);
                        }
                    }
                }
                Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => {
                    info!("Server closed connection");
                    break;
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }

        *self.state.write().await = ConnectionState::Disconnected;
        Ok(())
    }

    /// Handle a message from the server
    async fn handle_server_message(
        &self,
        msg: ServerMessage,
        msg_tx: &mpsc::Sender<ChallengeMessage>,
        challenge: &Arc<C>,
        state: &Arc<RwLock<ConnectionState>>,
        pending_count: &Arc<RwLock<u32>>,
    ) -> Result<(), ChallengeError> {
        match msg {
            ServerMessage::AuthResponse {
                success,
                error,
                session_id,
            } => {
                if success {
                    *state.write().await = ConnectionState::Connected;
                    info!("Authenticated successfully, session: {:?}", session_id);
                } else {
                    error!("Authentication failed: {:?}", error);
                    return Err(ChallengeError::Auth(
                        error.unwrap_or_else(|| "Unknown error".to_string()),
                    ));
                }
            }

            ServerMessage::Evaluate(request) => {
                let request_id = request.request_id.clone();
                info!("Received evaluation request: {}", request_id);

                // Increment pending
                {
                    let mut count = pending_count.write().await;
                    *count += 1;
                }

                // Clone what we need for the spawned task
                let challenge = Arc::clone(challenge);
                let msg_tx = msg_tx.clone();
                let pending_count = Arc::clone(pending_count);

                // Spawn evaluation task
                tokio::spawn(async move {
                    let start = Instant::now();
                    let result = challenge.evaluate(request).await;

                    // Decrement pending
                    {
                        let mut count = pending_count.write().await;
                        *count = count.saturating_sub(1);
                    }

                    let response = match result {
                        Ok(mut resp) => {
                            resp.execution_time_ms = start.elapsed().as_millis() as i64;
                            resp
                        }
                        Err(e) => EvaluationResponse::error(&request_id, e.to_string())
                            .with_time(start.elapsed().as_millis() as i64),
                    };

                    if msg_tx
                        .send(ChallengeMessage::Result(response))
                        .await
                        .is_err()
                    {
                        error!("Failed to send evaluation result");
                    }
                });
            }

            ServerMessage::Cancel { request_id, reason } => {
                info!("Evaluation cancelled: {} - {}", request_id, reason);
                // Cancellation is logged; running tasks complete naturally
            }

            ServerMessage::ConfigUpdate { config } => {
                info!("Received config update: {:?}", config);
                // Config updates are logged; hot-reload not supported
            }

            ServerMessage::HealthCheck => {
                let pending = *pending_count.read().await;
                const MAX_CONCURRENT: f64 = 4.0;
                let load = pending as f64 / MAX_CONCURRENT;

                let _ = msg_tx
                    .send(ChallengeMessage::Health {
                        healthy: true,
                        load: load.min(1.0),
                        pending,
                    })
                    .await;
            }

            ServerMessage::Ping { timestamp } => {
                if let Err(e) = msg_tx.send(ChallengeMessage::Pong { timestamp }).await {
                    warn!("Failed to send Pong message: {}", e);
                }
            }

            ServerMessage::Shutdown {
                reason,
                restart_expected,
            } => {
                info!(
                    "Server shutdown: {} (restart: {})",
                    reason, restart_expected
                );
                return Err(ChallengeError::Connection("Server shutdown".to_string()));
            }
        }

        Ok(())
    }

    /// Get current connection state
    pub async fn state(&self) -> ConnectionState {
        *self.state.read().await
    }

    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        *self.state.read().await == ConnectionState::Connected
    }
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/// Run a challenge as a platform client
pub async fn run_as_client<C: ServerChallenge + 'static>(
    challenge: C,
) -> Result<(), ChallengeError> {
    let config = PlatformClientConfig::from_env()?;
    let mut client = PlatformClient::new(config, challenge);
    client.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{ServerChallenge, ValidationRequest, ValidationResponse};
    use async_trait::async_trait;
    use serde_json::json;

    // Mock challenge for testing
    struct TestChallenge;

    #[async_trait]
    impl ServerChallenge for TestChallenge {
        fn challenge_id(&self) -> &str {
            "test-challenge"
        }

        fn name(&self) -> &str {
            "Test Challenge"
        }

        fn version(&self) -> &str {
            "1.0.0"
        }

        async fn evaluate(
            &self,
            request: EvaluationRequest,
        ) -> Result<EvaluationResponse, ChallengeError> {
            Ok(EvaluationResponse::success(
                &request.request_id,
                0.5,
                json!({}),
            ))
        }
    }

    #[test]
    fn test_connection_state_variants() {
        // Test that all connection states are different
        assert_ne!(ConnectionState::Disconnected, ConnectionState::Connecting);
        assert_ne!(ConnectionState::Connecting, ConnectionState::Connected);
        assert_ne!(ConnectionState::Connected, ConnectionState::Reconnecting);
        assert_ne!(
            ConnectionState::Authenticating,
            ConnectionState::Disconnected
        );
    }

    #[test]
    fn test_platform_client_config_new() {
        let config = PlatformClientConfig {
            url: "ws://localhost:8000/ws".to_string(),
            challenge_id: "test-challenge".to_string(),
            auth_token: "test-token".to_string(),
            instance_id: Some("instance-1".to_string()),
            reconnect_delay: Duration::from_secs(5),
            max_reconnect_attempts: 10,
        };

        assert_eq!(config.url, "ws://localhost:8000/ws");
        assert_eq!(config.challenge_id, "test-challenge");
        assert_eq!(config.auth_token, "test-token");
        assert_eq!(config.instance_id, Some("instance-1".to_string()));
        assert_eq!(config.reconnect_delay, Duration::from_secs(5));
        assert_eq!(config.max_reconnect_attempts, 10);
    }

    #[test]
    fn test_platform_client_creation() {
        let config = PlatformClientConfig {
            url: "ws://localhost:8000/ws".to_string(),
            challenge_id: "test".to_string(),
            auth_token: "token".to_string(),
            instance_id: None,
            reconnect_delay: Duration::from_secs(5),
            max_reconnect_attempts: 10,
        };

        let challenge = TestChallenge;
        let client = PlatformClient::new(config, challenge);

        // Verify client was created successfully
        assert_eq!(client.config.challenge_id, "test");
    }

    #[test]
    fn test_server_message_serialization() {
        // Test AuthResponse
        let msg = ServerMessage::AuthResponse {
            success: true,
            error: None,
            session_id: Some("session-123".to_string()),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("auth_response"));

        // Test Ping
        let msg = ServerMessage::Ping {
            timestamp: 1234567890,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("ping"));
    }

    #[test]
    fn test_challenge_message_serialization() {
        // Test Auth message
        let msg = ChallengeMessage::Auth {
            challenge_id: "test".to_string(),
            auth_token: "token".to_string(),
            instance_id: None,
            version: Some("1.0.0".to_string()),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("auth"));
        assert!(json.contains("test"));

        // Test Health message
        let msg = ChallengeMessage::Health {
            healthy: true,
            load: 0.5,
            pending: 2,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("health"));
    }

    #[test]
    fn test_server_message_deserialization() {
        // Test deserializing AuthResponse
        let json = r#"{"type":"auth_response","data":{"success":true,"error":null,"session_id":"session-123"}}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();

        match msg {
            ServerMessage::AuthResponse {
                success,
                session_id,
                ..
            } => {
                assert!(success);
                assert_eq!(session_id, Some("session-123".to_string()));
            }
            _ => panic!("Expected AuthResponse"),
        }
    }

    #[test]
    fn test_challenge_message_deserialization() {
        // Test deserializing Progress message
        let json = r#"{"type":"progress","data":{"request_id":"req-123","progress":0.75,"message":"Processing"}}"#;
        let msg: ChallengeMessage = serde_json::from_str(json).unwrap();

        match msg {
            ChallengeMessage::Progress {
                request_id,
                progress,
                message,
            } => {
                assert_eq!(request_id, "req-123");
                assert_eq!(progress, 0.75);
                assert_eq!(message, Some("Processing".to_string()));
            }
            _ => panic!("Expected Progress"),
        }
    }

    #[test]
    fn test_server_message_evaluate() {
        let eval_req = EvaluationRequest {
            request_id: "req-1".to_string(),
            submission_id: "sub-1".to_string(),
            participant_id: "participant-1".to_string(),
            data: json!({"test": "data"}),
            metadata: None,
            epoch: 1,
            deadline: None,
        };

        let msg = ServerMessage::Evaluate(eval_req.clone());

        // Serialize and deserialize
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: ServerMessage = serde_json::from_str(&json).unwrap();

        match deserialized {
            ServerMessage::Evaluate(req) => {
                assert_eq!(req.request_id, "req-1");
                assert_eq!(req.submission_id, "sub-1");
            }
            _ => panic!("Expected Evaluate"),
        }
    }

    #[test]
    fn test_challenge_message_result() {
        let eval_resp = EvaluationResponse::success("req-1", 0.95, json!({"result": "ok"}));

        let msg = ChallengeMessage::Result(eval_resp.clone());

        // Serialize and deserialize
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: ChallengeMessage = serde_json::from_str(&json).unwrap();

        match deserialized {
            ChallengeMessage::Result(resp) => {
                assert_eq!(resp.request_id, "req-1");
                assert_eq!(resp.score, 0.95);
                assert!(resp.success);
            }
            _ => panic!("Expected Result"),
        }
    }

    #[test]
    fn test_server_message_cancel() {
        let msg = ServerMessage::Cancel {
            request_id: "req-123".to_string(),
            reason: "Timeout".to_string(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("cancel"));
        assert!(json.contains("req-123"));
        assert!(json.contains("Timeout"));
    }

    #[test]
    fn test_server_message_shutdown() {
        let msg = ServerMessage::Shutdown {
            reason: "Maintenance".to_string(),
            restart_expected: true,
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("shutdown"));
        assert!(json.contains("Maintenance"));
    }

    #[test]
    fn test_challenge_message_log() {
        let msg = ChallengeMessage::Log {
            level: "info".to_string(),
            message: "Test log message".to_string(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("log"));
        assert!(json.contains("info"));
        assert!(json.contains("Test log message"));
    }
}
