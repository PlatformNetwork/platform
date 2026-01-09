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
    use std::collections::HashMap;

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
            config: config.clone(),
            request_id: "req-1".to_string(),
        };

        let json = encode_request(&request);
        let decoded = decode_request(&json).unwrap();
        
        // Assert via decode + match instead of brittle string contains
        match decoded {
            Request::Create { config: decoded_config, request_id } => {
                assert_eq!(decoded_config.challenge_id, "challenge-1");
                assert_eq!(decoded_config.image, "ghcr.io/platformnetwork/test:latest");
                assert_eq!(decoded_config.owner_id, "owner-1");
                assert_eq!(request_id, "req-1");
            }
            _ => panic!("Expected Create variant"),
        }
    }

    #[test]
    fn test_request_type_all_variants() {
        // Table-driven test to reduce duplication and ease future enum growth
        let config = ContainerConfig::default();
        
        let test_cases = vec![
            (Request::Create { config: config.clone(), request_id: "1".into() }, "create"),
            (Request::Start { container_id: "c1".into(), request_id: "1".into() }, "start"),
            (Request::Stop { container_id: "c1".into(), timeout_secs: 10, request_id: "1".into() }, "stop"),
            (Request::Remove { container_id: "c1".into(), force: false, request_id: "1".into() }, "remove"),
            (Request::Exec { container_id: "c1".into(), command: vec![], working_dir: None, timeout_secs: 30, request_id: "1".into() }, "exec"),
            (Request::Inspect { container_id: "c1".into(), request_id: "1".into() }, "inspect"),
            (Request::List { challenge_id: None, owner_id: None, request_id: "1".into() }, "list"),
            (Request::Logs { container_id: "c1".into(), tail: 100, request_id: "1".into() }, "logs"),
            (Request::Pull { image: "alpine".into(), request_id: "1".into() }, "pull"),
            (Request::Build { tag: "test:1".into(), dockerfile: "".into(), context: None, request_id: "1".into() }, "build"),
            (Request::Ping { request_id: "1".into() }, "ping"),
            (Request::CopyFrom { container_id: "c1".into(), path: "/file".into(), request_id: "1".into() }, "copy_from"),
            (Request::CopyTo { container_id: "c1".into(), path: "/file".into(), data: "".into(), request_id: "1".into() }, "copy_to"),
        ];

        for (request, expected_type) in test_cases {
            assert_eq!(request.request_type(), expected_type, "Mismatch for {:?}", request);
        }
    }

    #[test]
    fn test_request_challenge_id() {
        let config = ContainerConfig {
            challenge_id: "challenge-123".into(),
            ..Default::default()
        };
        
        let create_req = Request::Create { config, request_id: "1".into() };
        assert_eq!(create_req.challenge_id(), Some("challenge-123"));
        
        let ping_req = Request::Ping { request_id: "1".into() };
        assert_eq!(ping_req.challenge_id(), None);
        
        let list_req = Request::List { challenge_id: Some("ch-456".into()), owner_id: None, request_id: "1".into() };
        assert_eq!(list_req.challenge_id(), Some("ch-456"));
    }

    #[test]
    fn test_request_owner_id() {
        let config = ContainerConfig {
            owner_id: "owner-123".into(),
            ..Default::default()
        };
        
        let create_req = Request::Create { config, request_id: "1".into() };
        assert_eq!(create_req.owner_id(), Some("owner-123"));
        
        let ping_req = Request::Ping { request_id: "1".into() };
        assert_eq!(ping_req.owner_id(), None);
        // Table-driven test for response request_id extraction
        let exec_result = ExecResult { stdout: "".into(), stderr: "".into(), exit_code: 0, duration_ms: 100, timed_out: false };
        
        let test_cases = vec![
            (Response::Created { container_id: "c1".into(), container_name: "name".into(), request_id: "r1".into() }, "r1"),
            (Response::Started { container_id: "c1".into(), ports: HashMap::new(), endpoint: None, request_id: "r2".into() }, "r2"),
            (Response::Stopped { container_id: "c1".into(), request_id: "r3".into() }, "r3"),
            (Response::Removed { container_id: "c1".into(), request_id: "r4".into() }, "r4"),
            (Response::ExecResult { result: exec_result, request_id: "r5".into() }, "r5"),
        ];

        for (response, expected_id) in test_cases {
            assert_eq!(response.request_id(), expected_id, "Mismatch for {:?}", response);
        }
        assert_eq!(Response::Created { container_id: "c1".into(), container_name: "name".into(), request_id: "r1".into() }.request_id(), "r1");
        assert_eq!(Response::Started { container_id: "c1".into(), ports: HashMap::new(), endpoint: None, request_id: "r2".into() }.request_id(), "r2");
        assert_eq!(Response::Stopped { container_id: "c1".into(), request_id: "r3".into() }.request_id(), "r3");
        assert_eq!(Response::Removed { container_id: "c1".into(), request_id: "r4".into() }.request_id(), "r4");
        
        let exec_result = ExecResult { stdout: "".into(), stderr: "".into(), exit_code: 0, duration_ms: 100, timed_out: false };
        assert_eq!(Response::ExecResult { result: exec_result, request_id: "r5".into() }.request_id(), "r5");
    }

    #[test]
    fn test_response_is_error() {
        let error_resp = Response::Error { 
            error: ContainerError::InvalidRequest("test".into()), 
            request_id: "1".into() 
        };
        assert!(error_resp.is_error());
        
        let success_resp = Response::Pong { version: "1.0".into(), request_id: "1".into() };
        assert!(!success_resp.is_error());
    }

    #[test]
    fn test_response_error_constructor() {
        let resp = Response::error("req-123".into(), ContainerError::ContainerNotFound("c1".into()));
        assert!(resp.is_error());
        assert_eq!(resp.request_id(), "req-123");
    }

    #[test]
    fn test_all_request_variants_serialization() {
        let requests = vec![
            Request::Start { container_id: "c1".into(), request_id: "1".into() },
            Request::Stop { container_id: "c1".into(), timeout_secs: 10, request_id: "2".into() },
            Request::Remove { container_id: "c1".into(), force: true, request_id: "3".into() },
            Request::Exec { container_id: "c1".into(), command: vec!["ls".into()], working_dir: Some("/tmp".into()), timeout_secs: 30, request_id: "4".into() },
            Request::Inspect { container_id: "c1".into(), request_id: "5".into() },
            Request::List { challenge_id: Some("ch1".into()), owner_id: Some("owner1".into()), request_id: "6".into() },
            Request::Logs { container_id: "c1".into(), tail: 50, request_id: "7".into() },
            Request::Pull { image: "alpine:latest".into(), request_id: "8".into() },
            Request::Build { tag: "test:1".into(), dockerfile: "FROM alpine".into(), context: Some("data".into()), request_id: "9".into() },
            Request::CopyFrom { container_id: "c1".into(), path: "/app/file.txt".into(), request_id: "10".into() },
            Request::CopyTo { container_id: "c1".into(), path: "/app/data.txt".into(), data: "base64data".into(), request_id: "11".into() },
        ];

        for request in requests {
            let json = encode_request(&request);
            let decoded = decode_request(&json).unwrap();
            assert_eq!(decoded.request_id(), request.request_id());
        }
    }

    #[test]
    fn test_all_response_variants_serialization() {
        let responses = vec![
            Response::Pulled { image: "alpine".into(), request_id: "1".into() },
            Response::Built { image_id: "sha256:abc".into(), logs: "build logs".into(), request_id: "2".into() },
            Response::LogsResult { logs: "container logs".into(), request_id: "3".into() },
            Response::CopyFromResult { data: "base64".into(), size: 1024, request_id: "4".into() },
            Response::CopyToResult { request_id: "5".into() },
        ];

        for response in responses {
            let json = encode_response(&response);
            let decoded = decode_response(&json).unwrap();
            assert_eq!(decoded.request_id(), response.request_id());
        }
    }

    #[test]
    fn test_response_info_and_list() {
        // Use fixed timestamp to prevent flakiness
        let fixed_time = chrono::DateTime::parse_from_rfc3339("2026-01-09T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let info = ContainerInfo {
            id: "c1".into(),
            name: "test".into(),
            challenge_id: "ch1".into(),
            owner_id: "owner1".into(),
            image: "alpine".into(),
            state: ContainerState::Running,
            created_at: fixed_time,
            ports: HashMap::new(),
            endpoint: None,
            labels: HashMap::new(),
        };

        let resp = Response::Info { info: info.clone(), request_id: "r1".into() };
        assert_eq!(resp.request_id(), "r1");
        
        let list_resp = Response::ContainerList { containers: vec![info], request_id: "r2".into() };
        assert_eq!(list_resp.request_id(), "r2");
    }

    #[test]
    fn test_decode_invalid_json() {
        assert!(decode_request("invalid json").is_err());
        assert!(decode_response("{\"invalid\": true}").is_err());
    }
}
