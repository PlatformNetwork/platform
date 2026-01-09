//! Core types for secure container runtime

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Container creation configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerConfig {
    /// Docker image to use (must be whitelisted)
    pub image: String,

    /// Challenge ID that owns this container
    pub challenge_id: String,

    /// Owner identifier (validator hotkey, miner ID, etc.)
    pub owner_id: String,

    /// Container name (optional, will be auto-generated if not provided)
    pub name: Option<String>,

    /// Command to run
    pub cmd: Option<Vec<String>>,

    /// Environment variables
    pub env: HashMap<String, String>,

    /// Working directory
    pub working_dir: Option<String>,

    /// Resource limits
    pub resources: ResourceLimits,

    /// Network configuration
    pub network: NetworkConfig,

    /// Volume mounts (host:container, read-only enforced for security)
    pub mounts: Vec<MountConfig>,

    /// Labels for container (challenge metadata)
    pub labels: HashMap<String, String>,

    /// User to run container as (e.g., "root", "1000:1000")
    /// If None, uses the image default
    pub user: Option<String>,
}

/// Resource limits for containers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Memory limit in bytes
    pub memory_bytes: i64,

    /// CPU limit (1.0 = 1 CPU core)
    pub cpu_cores: f64,

    /// Maximum number of PIDs (prevents fork bombs)
    pub pids_limit: i64,

    /// Disk quota in bytes (0 = no limit)
    pub disk_quota_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_bytes: 2 * 1024 * 1024 * 1024, // 2GB
            cpu_cores: 1.0,
            pids_limit: 256,
            disk_quota_bytes: 0,
        }
    }
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network mode: "none", "bridge", "isolated"
    pub mode: NetworkMode,

    /// Exposed ports (container_port -> host_port, 0 = dynamic)
    pub ports: HashMap<u16, u16>,

    /// Whether to allow internet access
    pub allow_internet: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Isolated,
            ports: HashMap::new(),
            allow_internet: false,
        }
    }
}

/// Network mode for containers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// No network access
    None,
    /// Bridge network (isolated from host)
    Bridge,
    /// Isolated network (only challenge containers)
    Isolated,
}

/// Mount configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountConfig {
    /// Source path on host (will be validated)
    pub source: String,

    /// Target path in container
    pub target: String,

    /// Always read-only for security
    pub read_only: bool,
}

/// Container status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerState {
    Creating,
    Running,
    Paused,
    Stopped,
    Removing,
    Dead,
    Unknown,
}

/// Information about a running container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    /// Container ID (short form)
    pub id: String,

    /// Container name
    pub name: String,

    /// Challenge ID
    pub challenge_id: String,

    /// Owner ID
    pub owner_id: String,

    /// Image used
    pub image: String,

    /// Current state
    pub state: ContainerState,

    /// Created timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Assigned ports (container_port -> host_port)
    pub ports: HashMap<u16, u16>,

    /// Endpoint URL (if applicable)
    pub endpoint: Option<String>,

    /// Labels
    pub labels: HashMap<String, String>,
}

/// Result of command execution in container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    /// Standard output
    pub stdout: String,

    /// Standard error
    pub stderr: String,

    /// Exit code
    pub exit_code: i32,

    /// Duration in milliseconds
    pub duration_ms: u64,

    /// Whether the command timed out
    pub timed_out: bool,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Action performed
    pub action: AuditAction,

    /// Challenge ID
    pub challenge_id: String,

    /// Owner ID
    pub owner_id: String,

    /// Container ID (if applicable)
    pub container_id: Option<String>,

    /// Success/failure
    pub success: bool,

    /// Error message (if failed)
    pub error: Option<String>,

    /// Additional details
    pub details: HashMap<String, String>,
}

/// Audit action types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    ContainerCreate,
    ContainerStart,
    ContainerStop,
    ContainerRemove,
    ContainerExec,
    ImagePull,
    ImageBuild,
    PolicyViolation,
}

/// Error types for container operations
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
pub enum ContainerError {
    #[error("Image not whitelisted: {0}")]
    ImageNotWhitelisted(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Container not found: {0}")]
    ContainerNotFound(String),

    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Docker error: {0}")]
    DockerError(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

/// Standard labels applied to all containers
pub mod labels {
    pub const CHALLENGE_ID: &str = "platform.challenge.id";
    pub const OWNER_ID: &str = "platform.owner.id";
    pub const CREATED_BY: &str = "platform.created-by";
    pub const BROKER_VERSION: &str = "platform.broker.version";
    pub const MANAGED: &str = "platform.managed";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_config_default() {
        let config = ContainerConfig::default();
        assert!(config.image.is_empty());
        assert!(config.challenge_id.is_empty());
        assert!(config.owner_id.is_empty());
        assert!(config.name.is_none());
        assert!(config.cmd.is_none());
        assert!(config.env.is_empty());
        assert!(config.mounts.is_empty());
        assert!(config.labels.is_empty());
    }

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.memory_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(limits.cpu_cores, 1.0);
        assert_eq!(limits.pids_limit, 256);
        assert_eq!(limits.disk_quota_bytes, 0);
    }

    #[test]
    fn test_network_config_default() {
        let network = NetworkConfig::default();
        assert_eq!(network.mode, NetworkMode::Isolated);
        assert!(network.ports.is_empty());
        assert!(!network.allow_internet);
    }

    #[test]
    fn test_network_mode_serialization() {
        let modes = vec![
            NetworkMode::None,
            NetworkMode::Bridge,
            NetworkMode::Isolated,
        ];

        for mode in modes {
            let json = serde_json::to_string(&mode).unwrap();
            let decoded: NetworkMode = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, mode);
        }
    }

    #[test]
    fn test_container_state_serialization() {
        let states = vec![
            ContainerState::Creating,
            ContainerState::Running,
            ContainerState::Stopped,
            ContainerState::Paused,
            ContainerState::Removing,
            ContainerState::Dead,
            ContainerState::Unknown,
        ];

        for state in states {
            let json = serde_json::to_string(&state).unwrap();
            let decoded: ContainerState = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, state);
        }
    }

    #[test]
    fn test_mount_config_serialization() {
        let mount = MountConfig {
            source: "/host/path".into(),
            target: "/container/path".into(),
            read_only: true,
        };

        let json = serde_json::to_string(&mount).unwrap();
        let decoded: MountConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(decoded.source, "/host/path");
        assert_eq!(decoded.target, "/container/path");
        assert!(decoded.read_only);
    }

    #[test]
    fn test_exec_result_fields() {
        let result = ExecResult {
            stdout: "output".into(),
            stderr: "error".into(),
            exit_code: 0,
            duration_ms: 1500,
            timed_out: false,
        };

        assert_eq!(result.stdout, "output");
        assert_eq!(result.stderr, "error");
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.duration_ms, 1500);
        assert!(!result.timed_out);
    }

    #[test]
    fn test_audit_action_serialization() {
        let actions = vec![
            AuditAction::ContainerCreate,
            AuditAction::ContainerStart,
            AuditAction::ContainerStop,
            AuditAction::ContainerRemove,
            AuditAction::ContainerExec,
            AuditAction::ImagePull,
            AuditAction::ImageBuild,
            AuditAction::PolicyViolation,
        ];

        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let decoded: AuditAction = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, action);
        }
    }

    #[test]
    fn test_audit_entry_serialization() {
        let mut details = HashMap::new();
        details.insert("key".into(), "value".into());

        let entry = AuditEntry {
            timestamp: chrono::Utc::now(),
            action: AuditAction::ContainerCreate,
            challenge_id: "ch1".into(),
            owner_id: "owner1".into(),
            container_id: Some("container1".into()),
            success: true,
            error: None,
            details,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let decoded: AuditEntry = serde_json::from_str(&json).unwrap();
        
        assert_eq!(decoded.action, AuditAction::ContainerCreate);
        assert_eq!(decoded.challenge_id, "ch1");
        assert!(decoded.success);
    }

    #[test]
    fn test_container_error_display() {
        let errors = vec![
            ContainerError::ImageNotWhitelisted("test:latest".into()),
            ContainerError::PolicyViolation("test".into()),
            ContainerError::ContainerNotFound("c1".into()),
            ContainerError::ResourceLimitExceeded("memory".into()),
            ContainerError::PermissionDenied("test".into()),
            ContainerError::InvalidConfig("test".into()),
            ContainerError::DockerError("test".into()),
            ContainerError::InternalError("test".into()),
            ContainerError::Unauthorized("test".into()),
            ContainerError::InvalidRequest("test".into()),
        ];

        for error in errors {
            let msg = format!("{}", error);
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_container_error_serialization() {
        let error = ContainerError::PolicyViolation("docker socket blocked".into());
        let json = serde_json::to_string(&error).unwrap();
        let decoded: ContainerError = serde_json::from_str(&json).unwrap();
        
        match decoded {
            ContainerError::PolicyViolation(msg) => assert_eq!(msg, "docker socket blocked"),
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_container_info_serialization() {
        let mut ports = HashMap::new();
        ports.insert(8080, 38080);

        let mut labels = HashMap::new();
        labels.insert("key".into(), "value".into());

        let info = ContainerInfo {
            id: "c1".into(),
            name: "test-container".into(),
            challenge_id: "ch1".into(),
            owner_id: "owner1".into(),
            image: "alpine:latest".into(),
            state: ContainerState::Running,
            created_at: chrono::Utc::now(),
            ports,
            endpoint: Some("http://test:8080".into()),
            labels,
        };

        let json = serde_json::to_string(&info).unwrap();
        let decoded: ContainerInfo = serde_json::from_str(&json).unwrap();
        
        assert_eq!(decoded.id, "c1");
        assert_eq!(decoded.name, "test-container");
        assert_eq!(decoded.state, ContainerState::Running);
    }

    #[test]
    fn test_labels_constants() {
        assert_eq!(labels::CHALLENGE_ID, "platform.challenge.id");
        assert_eq!(labels::OWNER_ID, "platform.owner.id");
        assert_eq!(labels::CREATED_BY, "platform.created-by");
        assert_eq!(labels::BROKER_VERSION, "platform.broker.version");
        assert_eq!(labels::MANAGED, "platform.managed");
    }

    #[test]
    fn test_container_config_with_all_fields() {
        let mut env = HashMap::new();
        env.insert("KEY".into(), "VALUE".into());

        let mut labels = HashMap::new();
        labels.insert("label1".into(), "value1".into());

        let config = ContainerConfig {
            image: "test:latest".into(),
            challenge_id: "ch1".into(),
            owner_id: "owner1".into(),
            name: Some("test".into()),
            cmd: Some(vec!["sh".into()]),
            env,
            working_dir: Some("/app".into()),
            resources: ResourceLimits::default(),
            network: NetworkConfig::default(),
            mounts: vec![],
            labels,
            user: Some("1000:1000".into()),
        };

        let json = serde_json::to_string(&config).unwrap();
        let decoded: ContainerConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(decoded.image, "test:latest");
        assert_eq!(decoded.challenge_id, "ch1");
        assert_eq!(decoded.user, Some("1000:1000".into()));
    }
}
