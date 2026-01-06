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
