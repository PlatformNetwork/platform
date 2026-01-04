//! WebSocket client for communicating with the container broker
//!
//! This client connects to the broker via WebSocket with JWT authentication.
//! Use this for challenges running in containers without Unix socket access.

use crate::protocol::{Request, Response};
use crate::types::*;
use anyhow::{bail, Result};
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use tokio_tungstenite::{connect_async, tungstenite::Message};

/// WebSocket client for the secure container runtime broker
pub struct WsContainerClient {
    ws_url: String,
    jwt_token: String,
    challenge_id: String,
    owner_id: String,
}

impl WsContainerClient {
    /// Create a new WebSocket client
    pub fn new(ws_url: &str, jwt_token: &str, challenge_id: &str, owner_id: &str) -> Self {
        Self {
            ws_url: ws_url.to_string(),
            jwt_token: jwt_token.to_string(),
            challenge_id: challenge_id.to_string(),
            owner_id: owner_id.to_string(),
        }
    }

    /// Create client from environment variables
    /// Requires: CONTAINER_BROKER_WS_URL, CONTAINER_BROKER_JWT
    /// Optional: CHALLENGE_UUID (preferred), CHALLENGE_ID, VALIDATOR_HOTKEY (for owner_id)
    pub fn from_env() -> Option<Self> {
        let ws_url = std::env::var("CONTAINER_BROKER_WS_URL").ok()?;
        let jwt_token = std::env::var("CONTAINER_BROKER_JWT").ok()?;
        // Prefer CHALLENGE_UUID (matches JWT token) over CHALLENGE_ID (human-readable name)
        let challenge_id = std::env::var("CHALLENGE_UUID")
            .or_else(|_| std::env::var("CHALLENGE_ID"))
            .unwrap_or_else(|_| "unknown-challenge".to_string());
        let owner_id =
            std::env::var("VALIDATOR_HOTKEY").unwrap_or_else(|_| "unknown-owner".to_string());
        Some(Self::new(&ws_url, &jwt_token, &challenge_id, &owner_id))
    }

    /// Send a request and get response
    async fn send_request(&self, request: Request) -> Result<Response> {
        // Connect to WebSocket
        let (ws_stream, _) = connect_async(&self.ws_url).await.map_err(|e| {
            anyhow::anyhow!("Failed to connect to broker at {}: {}", self.ws_url, e)
        })?;

        let (mut write, mut read) = ws_stream.split();

        // Send auth message with JWT
        let auth_msg = serde_json::json!({ "token": self.jwt_token });
        write
            .send(Message::Text(auth_msg.to_string()))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send auth: {}", e))?;

        // Wait for auth response (should be Pong or Error)
        if let Some(Ok(Message::Text(text))) = read.next().await {
            let response: Response = serde_json::from_str(&text)
                .map_err(|e| anyhow::anyhow!("Failed to parse auth response: {} - {}", e, text))?;
            if let Response::Error { error, .. } = response {
                bail!("Auth failed: {}", error);
            }
            // Auth succeeded (got Pong), continue
        } else {
            bail!("No auth response from broker");
        }

        // Send actual request
        let request_json = serde_json::to_string(&request)
            .map_err(|e| anyhow::anyhow!("Failed to serialize request: {}", e))?;
        write
            .send(Message::Text(request_json))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        // Read response
        if let Some(Ok(Message::Text(text))) = read.next().await {
            let response: Response = serde_json::from_str(&text)
                .map_err(|e| anyhow::anyhow!("Failed to parse response: {} - {}", e, text))?;
            return Ok(response);
        }

        bail!("No response from broker")
    }

    /// Generate a unique request ID
    fn request_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Ping the broker
    pub async fn ping(&self) -> Result<String> {
        let request = Request::Ping {
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::Pong { version, .. } => Ok(version),
            Response::Error { error, .. } => bail!("Ping failed: {}", error),
            other => bail!("Unexpected response: {:?}", other),
        }
    }

    /// Create a container
    pub async fn create_container(&self, config: ContainerConfig) -> Result<(String, String)> {
        let request = Request::Create {
            config,
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::Created {
                container_id,
                container_name,
                ..
            } => Ok((container_id, container_name)),
            Response::Error { error, .. } => bail!("Create failed: {}", error),
            other => bail!("Unexpected response: {:?}", other),
        }
    }

    /// Start a container
    pub async fn start_container(&self, container_id: &str) -> Result<ContainerStartResult> {
        let request = Request::Start {
            container_id: container_id.to_string(),
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::Started {
                ports, endpoint, ..
            } => Ok(ContainerStartResult { ports, endpoint }),
            Response::Error { error, .. } => bail!("Start failed: {}", error),
            other => bail!("Unexpected response: {:?}", other),
        }
    }

    /// Stop a container
    pub async fn stop_container(&self, container_id: &str, timeout_secs: u32) -> Result<()> {
        let request = Request::Stop {
            container_id: container_id.to_string(),
            timeout_secs,
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::Stopped { .. } => Ok(()),
            Response::Error { error, .. } => bail!("Stop failed: {}", error),
            other => bail!("Unexpected response: {:?}", other),
        }
    }

    /// Remove a container
    pub async fn remove_container(&self, container_id: &str, force: bool) -> Result<()> {
        let request = Request::Remove {
            container_id: container_id.to_string(),
            force,
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::Removed { .. } => Ok(()),
            Response::Error { error, .. } => bail!("Remove failed: {}", error),
            other => bail!("Unexpected response: {:?}", other),
        }
    }

    /// Execute a command in a container
    pub async fn exec(
        &self,
        container_id: &str,
        command: Vec<String>,
        working_dir: Option<String>,
        timeout_secs: u32,
    ) -> Result<ExecResult> {
        let request = Request::Exec {
            container_id: container_id.to_string(),
            command,
            working_dir,
            timeout_secs,
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::ExecResult { result, .. } => Ok(result),
            Response::Error { error, .. } => bail!("Exec failed: {}", error),
            other => bail!("Unexpected response: {:?}", other),
        }
    }

    /// Get container logs
    pub async fn logs(&self, container_id: &str, tail: usize) -> Result<String> {
        let request = Request::Logs {
            container_id: container_id.to_string(),
            tail,
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::LogsResult { logs, .. } => Ok(logs),
            Response::Error { error, .. } => bail!("Logs failed: {}", error),
            other => bail!("Unexpected response: {:?}", other),
        }
    }

    /// List containers
    pub async fn list_containers(
        &self,
        challenge_id: Option<&str>,
        owner_id: Option<&str>,
    ) -> Result<Vec<ContainerInfo>> {
        let request = Request::List {
            challenge_id: challenge_id.map(|s| s.to_string()),
            owner_id: owner_id.map(|s| s.to_string()),
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::ContainerList { containers, .. } => Ok(containers),
            Response::Error { error, .. } => bail!("List failed: {}", error),
            other => bail!("Unexpected response: {:?}", other),
        }
    }

    /// Pull an image
    pub async fn pull_image(&self, image: &str) -> Result<()> {
        let request = Request::Pull {
            image: image.to_string(),
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::Pulled { .. } => Ok(()),
            Response::Error { error, .. } => bail!("Pull failed: {}", error),
            other => bail!("Unexpected response: {:?}", other),
        }
    }

    /// Get challenge_id
    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    /// Get owner_id
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }
}

/// Result of starting a container
#[derive(Debug, Clone)]
pub struct ContainerStartResult {
    pub ports: HashMap<u16, u16>,
    pub endpoint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_env_missing() {
        // Should return None when env vars are not set
        std::env::remove_var("CONTAINER_BROKER_WS_URL");
        std::env::remove_var("CONTAINER_BROKER_JWT");
        assert!(WsContainerClient::from_env().is_none());
    }
}
