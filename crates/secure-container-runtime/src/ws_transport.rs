//! WebSocket transport for container broker
//!
//! Allows challenges to connect via WebSocket instead of Unix socket.
//! Supports JWT authentication for secure remote access.

use crate::protocol::{decode_request, encode_response, Response};
use crate::types::ContainerError;
use crate::ContainerBroker;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use tracing::{debug, error, info, warn};

/// WebSocket server configuration
#[derive(Debug, Clone)]
pub struct WsConfig {
    /// Address to bind (e.g., "0.0.0.0:8090")
    pub bind_addr: String,
    /// JWT secret for authentication (if None, auth disabled)
    pub jwt_secret: Option<String>,
    /// Allowed challenge IDs (if empty, all allowed)
    pub allowed_challenges: Vec<String>,
    /// Max connections per challenge
    pub max_connections_per_challenge: usize,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8090".to_string(),
            jwt_secret: std::env::var("BROKER_JWT_SECRET").ok(),
            allowed_challenges: vec![],
            max_connections_per_challenge: 10,
        }
    }
}

/// JWT claims for WebSocket authentication
#[derive(Debug, Serialize, Deserialize)]
pub struct WsClaims {
    /// Challenge ID
    pub challenge_id: String,
    /// Owner/Validator ID
    pub owner_id: String,
    /// Expiration timestamp
    pub exp: u64,
    /// Issued at timestamp
    pub iat: u64,
}

/// Authentication message sent by client on connect
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthMessage {
    /// JWT token
    pub token: String,
}

/// Connection state
struct WsConnection {
    challenge_id: String,
    owner_id: String,
    authenticated: bool,
}

/// Run WebSocket server for the broker
pub async fn run_ws_server(broker: Arc<ContainerBroker>, config: WsConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.bind_addr).await?;
    info!(addr = %config.bind_addr, "WebSocket broker server listening");

    let connections: Arc<RwLock<std::collections::HashMap<String, usize>>> =
        Arc::new(RwLock::new(std::collections::HashMap::new()));

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let broker = broker.clone();
                let config = config.clone();
                let connections = connections.clone();

                tokio::spawn(async move {
                    if let Err(e) =
                        handle_ws_connection(stream, addr, broker, config, connections).await
                    {
                        error!(error = %e, addr = %addr, "WebSocket connection error");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "WebSocket accept error");
            }
        }
    }
}

async fn handle_ws_connection(
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    broker: Arc<ContainerBroker>,
    config: WsConfig,
    connections: Arc<RwLock<std::collections::HashMap<String, usize>>>,
) -> anyhow::Result<()> {
    let ws_stream = accept_async(stream).await?;
    let (mut write, mut read) = ws_stream.split();

    info!(addr = %addr, "New WebSocket connection");

    // Authentication phase - always expect an auth message first
    let mut conn_state = WsConnection {
        challenge_id: String::new(),
        owner_id: String::new(),
        authenticated: false,
    };

    // Always wait for auth message (even if we don't validate JWT)
    let auth_timeout = tokio::time::Duration::from_secs(10);
    match tokio::time::timeout(auth_timeout, read.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => {
            if config.jwt_secret.is_some() {
                // JWT validation required
                match authenticate(&text, &config) {
                    Ok(claims) => {
                        conn_state.challenge_id = claims.challenge_id;
                        conn_state.owner_id = claims.owner_id;
                        conn_state.authenticated = true;

                        // Check connection limit
                        let mut conns = connections.write().await;
                        let count = conns.entry(conn_state.challenge_id.clone()).or_insert(0);
                        if *count >= config.max_connections_per_challenge {
                            let err_response = Response::Error {
                                error: ContainerError::PolicyViolation(
                                    "Too many connections".to_string(),
                                ),
                                request_id: "auth".to_string(),
                            };
                            let _ = write
                                .send(Message::Text(encode_response(&err_response)))
                                .await;
                            return Ok(());
                        }
                        *count += 1;
                        drop(conns);

                        info!(
                            addr = %addr,
                            challenge_id = %conn_state.challenge_id,
                            "WebSocket authenticated"
                        );

                        // Send auth success
                        let success = Response::Pong {
                            version: "authenticated".to_string(),
                            request_id: "auth".to_string(),
                        };
                        write.send(Message::Text(encode_response(&success))).await?;
                    }
                    Err(e) => {
                        warn!(addr = %addr, error = %e, "WebSocket auth failed");
                        let err_response = Response::Error {
                            error: ContainerError::Unauthorized(e.to_string()),
                            request_id: "auth".to_string(),
                        };
                        write
                            .send(Message::Text(encode_response(&err_response)))
                            .await?;
                        return Ok(());
                    }
                }
            } else {
                // No JWT validation - try to parse auth message to get challenge_id
                // but don't fail if it's invalid
                if let Ok(auth_msg) = serde_json::from_str::<AuthMessage>(&text) {
                    // Try to decode JWT without validation to get challenge_id
                    if let Ok(claims) = decode_jwt_unverified(&auth_msg.token) {
                        conn_state.challenge_id = claims.challenge_id;
                        conn_state.owner_id = claims.owner_id;
                    }
                }
                conn_state.authenticated = true;

                info!(
                    addr = %addr,
                    challenge_id = %conn_state.challenge_id,
                    "WebSocket connected (no auth required)"
                );

                // Send success response
                let success = Response::Pong {
                    version: "authenticated".to_string(),
                    request_id: "auth".to_string(),
                };
                write.send(Message::Text(encode_response(&success))).await?;
            }
        }
        _ => {
            warn!(addr = %addr, "WebSocket auth timeout or invalid message");
            return Ok(());
        }
    }

    // Main message loop
    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                let response = process_request(&text, &conn_state, &broker, &config).await;
                write
                    .send(Message::Text(encode_response(&response)))
                    .await?;
            }
            Ok(Message::Ping(data)) => {
                write.send(Message::Pong(data)).await?;
            }
            Ok(Message::Close(_)) => {
                debug!(addr = %addr, "WebSocket closed by client");
                break;
            }
            Err(e) => {
                error!(addr = %addr, error = %e, "WebSocket read error");
                break;
            }
            _ => {}
        }
    }

    // Cleanup connection count
    if conn_state.authenticated && !conn_state.challenge_id.is_empty() {
        let mut conns = connections.write().await;
        if let Some(count) = conns.get_mut(&conn_state.challenge_id) {
            *count = count.saturating_sub(1);
        }
    }

    Ok(())
}

fn authenticate(text: &str, config: &WsConfig) -> anyhow::Result<WsClaims> {
    let auth_msg: AuthMessage = serde_json::from_str(text)?;

    let secret = config
        .jwt_secret
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No JWT secret configured"))?;

    // Decode and validate JWT
    let key = jsonwebtoken::DecodingKey::from_secret(secret.as_bytes());
    let validation = jsonwebtoken::Validation::default();

    let token_data = jsonwebtoken::decode::<WsClaims>(&auth_msg.token, &key, &validation)?;

    // Check if challenge is allowed
    if !config.allowed_challenges.is_empty()
        && !config
            .allowed_challenges
            .contains(&token_data.claims.challenge_id)
    {
        anyhow::bail!("Challenge not allowed: {}", token_data.claims.challenge_id);
    }

    Ok(token_data.claims)
}

/// Decode JWT without signature validation (for extracting claims when auth is disabled)
fn decode_jwt_unverified(token: &str) -> anyhow::Result<WsClaims> {
    // Use dangerous_insecure_decode to skip signature validation
    let key = jsonwebtoken::DecodingKey::from_secret(&[]);
    let mut validation = jsonwebtoken::Validation::default();
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.validate_aud = false;

    let token_data = jsonwebtoken::decode::<WsClaims>(token, &key, &validation)?;
    Ok(token_data.claims)
}

async fn process_request(
    text: &str,
    conn: &WsConnection,
    broker: &ContainerBroker,
    _config: &WsConfig,
) -> Response {
    // Parse request
    let request = match decode_request(text) {
        Ok(r) => r,
        Err(e) => {
            return Response::Error {
                error: ContainerError::InvalidRequest(e.to_string()),
                request_id: "unknown".to_string(),
            };
        }
    };

    let request_id = request.request_id().to_string();

    // Verify challenge_id matches authenticated connection
    if let Some(req_challenge) = request.challenge_id() {
        if !conn.challenge_id.is_empty() && req_challenge != conn.challenge_id {
            return Response::Error {
                error: ContainerError::Unauthorized(format!(
                    "Challenge mismatch: authenticated as {}, requested {}",
                    conn.challenge_id, req_challenge
                )),
                request_id,
            };
        }
    }

    // Forward to broker
    broker.handle_request(request).await
}

/// Generate a JWT token for a challenge
pub fn generate_token(
    challenge_id: &str,
    owner_id: &str,
    secret: &str,
    ttl_secs: u64,
) -> anyhow::Result<String> {
    use jsonwebtoken::{encode, EncodingKey, Header};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let claims = WsClaims {
        challenge_id: challenge_id.to_string(),
        owner_id: owner_id.to_string(),
        iat: now,
        exp: now + ttl_secs,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify_token() {
        let secret = "test-secret-key-123";
        let token = generate_token("term-challenge", "validator-1", secret, 3600).unwrap();

        // Verify token
        let key = jsonwebtoken::DecodingKey::from_secret(secret.as_bytes());
        let validation = jsonwebtoken::Validation::default();
        let decoded = jsonwebtoken::decode::<WsClaims>(&token, &key, &validation).unwrap();

        assert_eq!(decoded.claims.challenge_id, "term-challenge");
        assert_eq!(decoded.claims.owner_id, "validator-1");
    }

    #[test]
    fn test_generate_token_different_ttl() {
        let secret = "secret-key";
        let token = generate_token("ch1", "owner1", secret, 7200).unwrap();
        
        let key = jsonwebtoken::DecodingKey::from_secret(secret.as_bytes());
        let validation = jsonwebtoken::Validation::default();
        let decoded = jsonwebtoken::decode::<WsClaims>(&token, &key, &validation).unwrap();
        
        assert!(decoded.claims.exp > decoded.claims.iat);
        assert_eq!(decoded.claims.exp - decoded.claims.iat, 7200);
    }

    #[test]
    fn test_ws_config_default() {
        let config = WsConfig::default();
        assert_eq!(config.bind_addr, "0.0.0.0:8090");
        assert_eq!(config.max_connections_per_challenge, 10);
        assert_eq!(config.allowed_challenges.len(), 0);
    }

    #[test]
    fn test_ws_config_from_env() {
        std::env::set_var("BROKER_JWT_SECRET", "test-secret");
        let config = WsConfig::default();
        assert_eq!(config.jwt_secret, Some("test-secret".to_string()));
        std::env::remove_var("BROKER_JWT_SECRET");
    }

    #[test]
    fn test_ws_claims_fields() {
        let claims = WsClaims {
            challenge_id: "challenge-123".into(),
            owner_id: "owner-456".into(),
            iat: 1000,
            exp: 2000,
        };
        
        assert_eq!(claims.challenge_id, "challenge-123");
        assert_eq!(claims.owner_id, "owner-456");
        assert_eq!(claims.iat, 1000);
        assert_eq!(claims.exp, 2000);
    }

    #[test]
    fn test_auth_message_serialization() {
        let auth_msg = AuthMessage {
            token: "test-jwt-token".into(),
        };
        
        let json = serde_json::to_string(&auth_msg).unwrap();
        assert!(json.contains("test-jwt-token"));
        
        let decoded: AuthMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.token, "test-jwt-token");
    }

    #[test]
    fn test_ws_config_custom() {
        let config = WsConfig {
            bind_addr: "127.0.0.1:9000".into(),
            jwt_secret: Some("my-secret".into()),
            allowed_challenges: vec!["ch1".into(), "ch2".into()],
            max_connections_per_challenge: 5,
        };
        
        assert_eq!(config.bind_addr, "127.0.0.1:9000");
        assert_eq!(config.jwt_secret, Some("my-secret".into()));
        assert_eq!(config.allowed_challenges.len(), 2);
        assert_eq!(config.max_connections_per_challenge, 5);
    }
}
