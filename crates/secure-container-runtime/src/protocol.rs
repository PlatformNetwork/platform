//! Protocol for broker-client communication over Unix socket

use crate::types::*;
use serde::{Deserialize, Serialize};

/// Request from client to broker
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum Request {
    /// Create a new container
    Create {
        config: ContainerConfig,
        /// Request ID for correlation
        request_id: String,
    },

    /// Start a container
    Start {
        container_id: String,
        request_id: String,
    },

    /// Stop a container
    Stop {
        container_id: String,
        /// Timeout in seconds before force kill
        timeout_secs: u32,
        request_id: String,
    },

    /// Remove a container
    Remove {
        container_id: String,
        /// Force remove even if running
        force: bool,
        request_id: String,
    },

    /// Execute a command in a container
    Exec {
        container_id: String,
        command: Vec<String>,
        /// Working directory (optional)
        working_dir: Option<String>,
        /// Timeout in seconds
        timeout_secs: u32,
        request_id: String,
    },

    /// Get container info
    Inspect {
        container_id: String,
        request_id: String,
    },

    /// List containers for a challenge
    List {
        challenge_id: Option<String>,
        owner_id: Option<String>,
        request_id: String,
    },

    /// Get container logs
    Logs {
        container_id: String,
        /// Number of lines from tail (0 = all)
        tail: usize,
        request_id: String,
    },

    /// Pull an image
    Pull { image: String, request_id: String },

    /// Build an image from Dockerfile
    Build {
        /// Tag for the image (e.g. "term-compiler:latest")
        tag: String,
        /// Dockerfile content (base64 encoded)
        dockerfile: String,
        /// Build context (optional tar.gz, base64 encoded)
        context: Option<String>,
        request_id: String,
    },

    /// Health check
    Ping { request_id: String },

    /// Copy file from container using Docker archive API
    /// Returns file contents as base64-encoded data
    CopyFrom {
        container_id: String,
        /// Path inside container to copy from
        path: String,
        request_id: String,
    },

    /// Copy file to container using Docker archive API
    /// File contents should be base64-encoded
    CopyTo {
        container_id: String,
        /// Path inside container to copy to
        path: String,
        /// Base64-encoded file contents
        data: String,
        request_id: String,
    },
}

impl Request {
    pub fn request_id(&self) -> &str {
        match self {
            Request::Create { request_id, .. } => request_id,
            Request::Start { request_id, .. } => request_id,
            Request::Stop { request_id, .. } => request_id,
            Request::Remove { request_id, .. } => request_id,
            Request::Exec { request_id, .. } => request_id,
            Request::Inspect { request_id, .. } => request_id,
            Request::List { request_id, .. } => request_id,
            Request::Logs { request_id, .. } => request_id,
            Request::Pull { request_id, .. } => request_id,
            Request::Build { request_id, .. } => request_id,
            Request::Ping { request_id, .. } => request_id,
            Request::CopyFrom { request_id, .. } => request_id,
            Request::CopyTo { request_id, .. } => request_id,
        }
    }

    /// Get request type as string for logging
    pub fn request_type(&self) -> &'static str {
        match self {
            Request::Create { .. } => "create",
            Request::Start { .. } => "start",
            Request::Stop { .. } => "stop",
            Request::Remove { .. } => "remove",
            Request::Exec { .. } => "exec",
            Request::Inspect { .. } => "inspect",
            Request::List { .. } => "list",
            Request::Logs { .. } => "logs",
            Request::Pull { .. } => "pull",
            Request::Build { .. } => "build",
            Request::Ping { .. } => "ping",
            Request::CopyFrom { .. } => "copy_from",
            Request::CopyTo { .. } => "copy_to",
        }
    }

    /// Get challenge_id if applicable
    pub fn challenge_id(&self) -> Option<&str> {
        match self {
            Request::Create { config, .. } => Some(&config.challenge_id),
            Request::List { challenge_id, .. } => challenge_id.as_deref(),
            _ => None,
        }
    }

    /// Get owner_id if applicable
    pub fn owner_id(&self) -> Option<&str> {
        match self {
            Request::Create { config, .. } => Some(&config.owner_id),
            Request::List { owner_id, .. } => owner_id.as_deref(),
            _ => None,
        }
    }
}

/// Response from broker to client
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Container created successfully
    Created {
        container_id: String,
        container_name: String,
        request_id: String,
    },

    /// Container started
    Started {
        container_id: String,
        ports: std::collections::HashMap<u16, u16>,
        endpoint: Option<String>,
        request_id: String,
    },

    /// Container stopped
    Stopped {
        container_id: String,
        request_id: String,
    },

    /// Container removed
    Removed {
        container_id: String,
        request_id: String,
    },

    /// Exec result
    ExecResult {
        result: ExecResult,
        request_id: String,
    },

    /// Container info
    Info {
        info: ContainerInfo,
        request_id: String,
    },

    /// List of containers
    ContainerList {
        containers: Vec<ContainerInfo>,
        request_id: String,
    },

    /// Container logs
    LogsResult { logs: String, request_id: String },

    /// Image pulled
    Pulled { image: String, request_id: String },

    /// Image built
    Built {
        image_id: String,
        logs: String,
        request_id: String,
    },

    /// Pong response
    Pong { version: String, request_id: String },

    /// File copied from container - base64-encoded data
    CopyFromResult {
        /// Base64-encoded file contents
        data: String,
        /// Original file size in bytes
        size: usize,
        request_id: String,
    },

    /// File copied to container successfully
    CopyToResult { request_id: String },

    /// Error response
    Error {
        error: ContainerError,
        request_id: String,
    },
}

impl Response {
    pub fn request_id(&self) -> &str {
        match self {
            Response::Created { request_id, .. } => request_id,
            Response::Started { request_id, .. } => request_id,
            Response::Stopped { request_id, .. } => request_id,
            Response::Removed { request_id, .. } => request_id,
            Response::ExecResult { request_id, .. } => request_id,
            Response::Info { request_id, .. } => request_id,
            Response::ContainerList { request_id, .. } => request_id,
            Response::LogsResult { request_id, .. } => request_id,
            Response::Pulled { request_id, .. } => request_id,
            Response::Built { request_id, .. } => request_id,
            Response::Pong { request_id, .. } => request_id,
            Response::CopyFromResult { request_id, .. } => request_id,
            Response::CopyToResult { request_id, .. } => request_id,
            Response::Error { request_id, .. } => request_id,
        }
    }

    pub fn is_error(&self) -> bool {
        matches!(self, Response::Error { .. })
    }

    pub fn error(request_id: String, error: ContainerError) -> Self {
        Response::Error { error, request_id }
    }
}

/// Encode a request to JSON line
pub fn encode_request(request: &Request) -> String {
    serde_json::to_string(request).unwrap_or_default()
}

/// Decode a request from JSON
pub fn decode_request(data: &str) -> Result<Request, serde_json::Error> {
    serde_json::from_str(data)
}

/// Encode a response to JSON line
pub fn encode_response(response: &Response) -> String {
    serde_json::to_string(response).unwrap_or_default()
}

/// Decode a response from JSON
pub fn decode_response(data: &str) -> Result<Response, serde_json::Error> {
    serde_json::from_str(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let request = Request::Ping {
            request_id: "test-123".to_string(),
        };

        let json = encode_request(&request);
        let decoded: Request = decode_request(&json).unwrap();

        assert_eq!(decoded.request_id(), "test-123");
    }

    #[test]
    fn test_response_serialization() {
        let response = Response::Pong {
            version: "1.0.0".to_string(),
            request_id: "test-123".to_string(),
        };

        let json = encode_response(&response);
        let decoded: Response = decode_response(&json).unwrap();

        assert_eq!(decoded.request_id(), "test-123");
    }

    #[test]
    fn test_create_request() {
        let config = ContainerConfig {
            image: "ghcr.io/platformnetwork/test:latest".to_string(),
            challenge_id: "challenge-1".to_string(),
            owner_id: "owner-1".to_string(),
            ..Default::default()
        };

        let request = Request::Create {
            config,
            request_id: "req-1".to_string(),
        };

        let json = encode_request(&request);
        assert!(json.contains("challenge-1"));
        assert!(json.contains("create"));
    }
}
