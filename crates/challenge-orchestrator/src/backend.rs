//! Container backend abstraction
//!
//! This module selects the concrete runtime bridge that the orchestrator uses
//! to manipulate containers. In production it proxies through the
//! `secure-container-runtime` broker while still allowing direct Docker access
//! when a developer explicitly opts into `DEVELOPMENT_MODE=true`.
//!
//! ## Backend Selection (Priority Order)
//!
//! 1. If `DEVELOPMENT_MODE=true` -> Direct Docker (local dev only)
//! 2. If `CONTAINER_BROKER_SOCKET` is set -> Use that socket path
//! 3. If default socket exists (`/var/run/platform/broker.sock`) -> Use broker
//! 4. Otherwise -> Error (production requires broker)
//!
//! ## Security
//!
//! The secure backend enforces:
//! - Image allow-listing (`ghcr.io/platformnetwork/`)
//! - Non-privileged containers with resource limits baked in
//! - Network isolation handled by the broker
//! - No direct Docker socket exposure for workloads

use crate::{ChallengeContainerConfig, ChallengeDocker, ChallengeInstance, ContainerStatus};
use async_trait::async_trait;
use secure_container_runtime::{
    CleanupResult as BrokerCleanupResult, ContainerConfig, ContainerConfigBuilder, ContainerError,
    ContainerInfo, ContainerStartResult, ContainerState, NetworkMode, SecureContainerClient,
};
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

/// Default broker socket path
pub const DEFAULT_BROKER_SOCKET: &str = "/var/run/platform/broker.sock";
const BROKER_SOCKET_OVERRIDE_ENV: &str = "BROKER_SOCKET_OVERRIDE";

fn default_broker_socket_path() -> String {
    std::env::var(BROKER_SOCKET_OVERRIDE_ENV).unwrap_or_else(|_| DEFAULT_BROKER_SOCKET.to_string())
}

/// Container backend trait for managing challenge containers
#[async_trait]
pub trait ContainerBackend: Send + Sync {
    /// Start a challenge container
    async fn start_challenge(
        &self,
        config: &ChallengeContainerConfig,
    ) -> anyhow::Result<ChallengeInstance>;

    /// Stop a container
    async fn stop_container(&self, container_id: &str) -> anyhow::Result<()>;

    /// Remove a container
    async fn remove_container(&self, container_id: &str) -> anyhow::Result<()>;

    /// Check if a container is running
    async fn is_container_running(&self, container_id: &str) -> anyhow::Result<bool>;

    /// Pull an image
    async fn pull_image(&self, image: &str) -> anyhow::Result<()>;

    /// Get container logs
    async fn get_logs(&self, container_id: &str, tail: usize) -> anyhow::Result<String>;

    /// Cleanup all containers for a challenge
    async fn cleanup_challenge(&self, challenge_id: &str) -> anyhow::Result<usize>;

    /// List containers for a challenge
    async fn list_challenge_containers(&self, challenge_id: &str) -> anyhow::Result<Vec<String>>;
}

#[async_trait]
pub trait SecureContainerBridge: Send + Sync {
    async fn create_container(
        &self,
        config: ContainerConfig,
    ) -> Result<(String, String), ContainerError>;
    async fn start_container(
        &self,
        container_id: &str,
    ) -> Result<ContainerStartResult, ContainerError>;
    async fn get_endpoint(&self, container_id: &str, port: u16) -> Result<String, ContainerError>;
    async fn stop_container(
        &self,
        container_id: &str,
        timeout_secs: u32,
    ) -> Result<(), ContainerError>;
    async fn remove_container(&self, container_id: &str, force: bool)
        -> Result<(), ContainerError>;
    async fn inspect(&self, container_id: &str) -> Result<ContainerInfo, ContainerError>;
    async fn pull_image(&self, image: &str) -> Result<(), ContainerError>;
    async fn logs(&self, container_id: &str, tail: usize) -> Result<String, ContainerError>;
    async fn cleanup_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<BrokerCleanupResult, ContainerError>;
    async fn list_by_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Vec<ContainerInfo>, ContainerError>;
}

struct SecureClientBridge {
    client: SecureContainerClient,
}

impl SecureClientBridge {
    fn new(socket_path: &str) -> Self {
        Self {
            client: SecureContainerClient::new(socket_path),
        }
    }
}

#[async_trait]
impl SecureContainerBridge for SecureClientBridge {
    async fn create_container(
        &self,
        config: ContainerConfig,
    ) -> Result<(String, String), ContainerError> {
        self.client.create_container(config).await
    }

    async fn start_container(
        &self,
        container_id: &str,
    ) -> Result<ContainerStartResult, ContainerError> {
        self.client.start_container(container_id).await
    }

    async fn get_endpoint(&self, container_id: &str, port: u16) -> Result<String, ContainerError> {
        self.client.get_endpoint(container_id, port).await
    }

    async fn stop_container(
        &self,
        container_id: &str,
        timeout_secs: u32,
    ) -> Result<(), ContainerError> {
        self.client.stop_container(container_id, timeout_secs).await
    }

    async fn remove_container(
        &self,
        container_id: &str,
        force: bool,
    ) -> Result<(), ContainerError> {
        self.client.remove_container(container_id, force).await
    }

    async fn inspect(&self, container_id: &str) -> Result<ContainerInfo, ContainerError> {
        self.client.inspect(container_id).await
    }

    async fn pull_image(&self, image: &str) -> Result<(), ContainerError> {
        self.client.pull_image(image).await
    }

    async fn logs(&self, container_id: &str, tail: usize) -> Result<String, ContainerError> {
        self.client.logs(container_id, tail).await
    }

    async fn cleanup_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<BrokerCleanupResult, ContainerError> {
        self.client.cleanup_challenge(challenge_id).await
    }

    async fn list_by_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Vec<ContainerInfo>, ContainerError> {
        self.client.list_by_challenge(challenge_id).await
    }
}

/// Secure container backend using the broker
pub struct SecureBackend {
    client: Arc<dyn SecureContainerBridge>,
    validator_id: String,
}

impl SecureBackend {
    /// Create a new secure backend
    pub fn new(socket_path: &str, validator_id: &str) -> Self {
        Self::with_bridge(SecureClientBridge::new(socket_path), validator_id)
    }

    #[cfg(test)]
    fn test_backend_slot() -> &'static std::sync::Mutex<Option<SecureBackend>> {
        use std::sync::{Mutex, OnceLock};
        static SLOT: OnceLock<Mutex<Option<SecureBackend>>> = OnceLock::new();
        SLOT.get_or_init(|| Mutex::new(None))
    }

    #[cfg(test)]
    fn take_test_backend() -> Option<SecureBackend> {
        Self::test_backend_slot().lock().unwrap().take()
    }

    #[cfg(test)]
    pub(crate) fn set_test_backend(backend: SecureBackend) {
        Self::test_backend_slot().lock().unwrap().replace(backend);
    }

    /// Build a backend from an arbitrary bridge (used for tests)
    pub fn with_bridge(
        client: impl SecureContainerBridge + 'static,
        validator_id: impl Into<String>,
    ) -> Self {
        Self {
            client: Arc::new(client),
            validator_id: validator_id.into(),
        }
    }

    /// Create from environment or default socket
    pub fn from_env() -> Option<Self> {
        #[cfg(test)]
        if let Some(backend) = Self::take_test_backend() {
            return Some(backend);
        }

        let validator_id =
            std::env::var("VALIDATOR_HOTKEY").unwrap_or_else(|_| "unknown".to_string());

        // Priority 1: Explicit socket path from env
        if let Ok(socket) = std::env::var("CONTAINER_BROKER_SOCKET") {
            if Path::new(&socket).exists() {
                info!(socket = %socket, "Using broker socket from environment");
                return Some(Self::new(&socket, &validator_id));
            }
            warn!(socket = %socket, "Broker socket from env does not exist");
        }

        // Priority 2: Default socket path (allow override for tests)
        let default_socket = default_broker_socket_path();
        if Path::new(&default_socket).exists() {
            info!(socket = %default_socket, "Using default broker socket");
            return Some(Self::new(&default_socket, &validator_id));
        }

        None
    }

    /// Check if broker is available
    pub fn is_available() -> bool {
        if let Ok(socket) = std::env::var("CONTAINER_BROKER_SOCKET") {
            if Path::new(&socket).exists() {
                return true;
            }
        }
        let default_socket = default_broker_socket_path();
        Path::new(&default_socket).exists()
    }
}

#[async_trait]
impl ContainerBackend for SecureBackend {
    async fn start_challenge(
        &self,
        config: &ChallengeContainerConfig,
    ) -> anyhow::Result<ChallengeInstance> {
        info!(
            challenge = %config.name,
            image = %config.docker_image,
            "Starting challenge via secure broker"
        );

        // Build container config
        let container_config = ContainerConfigBuilder::new(
            &config.docker_image,
            &config.challenge_id.to_string(),
            &self.validator_id,
        )
        .memory((config.memory_mb * 1024 * 1024) as i64)
        .cpu(config.cpu_cores)
        .network_mode(NetworkMode::Isolated)
        .expose(8080)
        .env("CHALLENGE_ID", &config.challenge_id.to_string())
        .env("MECHANISM_ID", &config.mechanism_id.to_string())
        .build();

        // Create and start container
        let (container_id, _container_name) = self
            .client
            .create_container(container_config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create container: {}", e))?;

        self.client
            .start_container(&container_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to start container: {}", e))?;

        // Get endpoint
        let endpoint = self
            .client
            .get_endpoint(&container_id, 8080)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get endpoint: {}", e))?;

        info!(
            container_id = %container_id,
            endpoint = %endpoint,
            "Challenge container started via broker"
        );

        Ok(ChallengeInstance {
            challenge_id: config.challenge_id,
            container_id,
            image: config.docker_image.clone(),
            endpoint,
            started_at: chrono::Utc::now(),
            status: ContainerStatus::Running,
        })
    }

    async fn stop_container(&self, container_id: &str) -> anyhow::Result<()> {
        self.client
            .stop_container(container_id, 30)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to stop container: {}", e))
    }

    async fn remove_container(&self, container_id: &str) -> anyhow::Result<()> {
        self.client
            .remove_container(container_id, true)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to remove container: {}", e))
    }

    async fn is_container_running(&self, container_id: &str) -> anyhow::Result<bool> {
        match self.client.inspect(container_id).await {
            Ok(info) => Ok(info.state == ContainerState::Running),
            Err(_) => Ok(false),
        }
    }

    async fn pull_image(&self, image: &str) -> anyhow::Result<()> {
        self.client
            .pull_image(image)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to pull image: {}", e))
    }

    async fn get_logs(&self, container_id: &str, tail: usize) -> anyhow::Result<String> {
        self.client
            .logs(container_id, tail)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get logs: {}", e))
    }

    async fn cleanup_challenge(&self, challenge_id: &str) -> anyhow::Result<usize> {
        let result = self
            .client
            .cleanup_challenge(challenge_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to cleanup: {}", e))?;

        if !result.success() {
            warn!(errors = ?result.errors, "Some cleanup errors occurred");
        }

        Ok(result.removed)
    }

    async fn list_challenge_containers(&self, challenge_id: &str) -> anyhow::Result<Vec<String>> {
        let containers = self
            .client
            .list_by_challenge(challenge_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to list containers: {}", e))?;

        Ok(containers.into_iter().map(|c| c.id).collect())
    }
}

/// Direct Docker backend (for local development)
#[derive(Clone)]
pub struct DirectDockerBackend {
    docker: Arc<dyn ChallengeDocker>,
}

impl DirectDockerBackend {
    /// Create a new direct Docker backend
    pub async fn new() -> anyhow::Result<Self> {
        #[cfg(test)]
        if let Some(result) = Self::take_test_result() {
            return result;
        }

        let docker = crate::docker::DockerClient::connect().await?;
        Ok(Self::with_docker(docker))
    }

    /// Build a backend from a custom docker implementation (used for tests)
    pub fn with_docker(docker: impl ChallengeDocker + 'static) -> Self {
        Self {
            docker: Arc::new(docker),
        }
    }

    #[cfg(test)]
    fn test_backend_slot() -> &'static std::sync::Mutex<Option<anyhow::Result<DirectDockerBackend>>>
    {
        use std::sync::OnceLock;
        static SLOT: OnceLock<std::sync::Mutex<Option<anyhow::Result<DirectDockerBackend>>>> =
            OnceLock::new();
        SLOT.get_or_init(|| std::sync::Mutex::new(None))
    }

    #[cfg(test)]
    fn take_test_result() -> Option<anyhow::Result<DirectDockerBackend>> {
        Self::test_backend_slot().lock().unwrap().take()
    }

    #[cfg(test)]
    pub(crate) fn set_test_result(result: anyhow::Result<DirectDockerBackend>) {
        Self::test_backend_slot().lock().unwrap().replace(result);
    }
}

#[async_trait]
impl ContainerBackend for DirectDockerBackend {
    async fn start_challenge(
        &self,
        config: &ChallengeContainerConfig,
    ) -> anyhow::Result<ChallengeInstance> {
        self.docker.start_challenge(config).await
    }

    async fn stop_container(&self, container_id: &str) -> anyhow::Result<()> {
        self.docker.stop_container(container_id).await
    }

    async fn remove_container(&self, container_id: &str) -> anyhow::Result<()> {
        self.docker.remove_container(container_id).await
    }

    async fn is_container_running(&self, container_id: &str) -> anyhow::Result<bool> {
        self.docker.is_container_running(container_id).await
    }

    async fn pull_image(&self, image: &str) -> anyhow::Result<()> {
        self.docker.pull_image(image).await
    }

    async fn get_logs(&self, container_id: &str, tail: usize) -> anyhow::Result<String> {
        self.docker.get_logs(container_id, tail).await
    }

    async fn cleanup_challenge(&self, challenge_id: &str) -> anyhow::Result<usize> {
        let containers = self.docker.list_challenge_containers().await?;
        let mut removed = 0;

        for container_id in containers {
            if container_id.contains(&challenge_id.to_string()) {
                let _ = self.docker.stop_container(&container_id).await;
                if self.docker.remove_container(&container_id).await.is_ok() {
                    removed += 1;
                }
            }
        }

        Ok(removed)
    }

    async fn list_challenge_containers(&self, _challenge_id: &str) -> anyhow::Result<Vec<String>> {
        self.docker.list_challenge_containers().await
    }
}

/// Create the appropriate backend based on environment
///
/// Priority order:
/// 1. DEVELOPMENT_MODE=true -> Direct Docker (local dev only)
/// 2. Broker socket available -> Secure broker (production default)
/// 3. No broker + not dev mode -> Error (production requires broker)
pub async fn create_backend() -> anyhow::Result<Box<dyn ContainerBackend>> {
    match select_backend_mode() {
        BackendMode::Development => {
            info!("DEVELOPMENT_MODE=true: Using direct Docker (local development)");
            let direct = DirectDockerBackend::new().await?;
            Ok(Box::new(direct))
        }
        BackendMode::Secure => {
            if let Some(secure) = SecureBackend::from_env() {
                info!("Using secure container broker (production mode)");
                Ok(Box::new(secure))
            } else {
                let default_socket = default_broker_socket_path();
                Err(anyhow::anyhow!(
                    "Secure container broker is unavailable. Start broker at {} or set CONTAINER_BROKER_SOCKET.",
                    default_socket
                ))
            }
        }
        BackendMode::Unavailable => {
            let default_socket = default_broker_socket_path();
            Err(anyhow::anyhow!(
                "No container backend available. Start broker at {} or set DEVELOPMENT_MODE=true for local Docker.",
                default_socket
            ))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendMode {
    Development,
    Secure,
    Unavailable,
}

pub fn select_backend_mode() -> BackendMode {
    if is_development_mode() {
        BackendMode::Development
    } else if SecureBackend::is_available() {
        BackendMode::Secure
    } else {
        BackendMode::Unavailable
    }
}

/// Check if running in secure mode (broker available)
pub fn is_secure_mode() -> bool {
    SecureBackend::is_available()
}

/// Check if in development mode
pub fn is_development_mode() -> bool {
    std::env::var("DEVELOPMENT_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::CleanupResult as DockerCleanupResult;
    use chrono::Utc;
    use platform_core::ChallengeId;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tempfile::{tempdir, NamedTempFile};

    fn reset_env() {
        for key in [
            "DEVELOPMENT_MODE",
            "CONTAINER_BROKER_SOCKET",
            "VALIDATOR_HOTKEY",
            BROKER_SOCKET_OVERRIDE_ENV,
        ] {
            std::env::remove_var(key);
        }
    }

    #[test]
    #[serial]
    fn test_is_development_mode_reflects_env() {
        reset_env();
        assert!(!is_development_mode());

        std::env::set_var("DEVELOPMENT_MODE", "1");
        assert!(is_development_mode());

        std::env::set_var("DEVELOPMENT_MODE", "false");
        assert!(!is_development_mode());
        reset_env();
    }

    #[test]
    #[serial]
    fn test_secure_backend_from_env_detects_socket() {
        reset_env();
        let temp_socket = NamedTempFile::new().expect("temp socket path");
        let socket_path = temp_socket.path().to_path_buf();
        std::env::set_var("CONTAINER_BROKER_SOCKET", &socket_path);
        std::env::set_var("VALIDATOR_HOTKEY", "validator123");

        let backend = SecureBackend::from_env().expect("should create backend from env");
        assert_eq!(backend.validator_id, "validator123");

        reset_env();
        drop(temp_socket);
    }

    #[test]
    #[serial]
    fn test_is_secure_mode_uses_env_socket() {
        reset_env();
        let temp_socket = NamedTempFile::new().expect("temp socket path");
        let socket_path = temp_socket.path().to_path_buf();
        std::env::set_var("CONTAINER_BROKER_SOCKET", &socket_path);

        assert!(is_secure_mode());

        reset_env();
        drop(temp_socket);
    }

    #[test]
    #[serial]
    fn test_secure_backend_is_available_with_override_socket() {
        reset_env();
        let temp_socket = NamedTempFile::new().expect("temp socket path");
        let socket_path = temp_socket.path().to_path_buf();
        std::env::set_var(BROKER_SOCKET_OVERRIDE_ENV, &socket_path);

        assert!(SecureBackend::is_available());

        reset_env();
        drop(temp_socket);
    }

    #[test]
    #[serial]
    fn test_select_backend_mode_prefers_development_mode() {
        reset_env();
        std::env::set_var("DEVELOPMENT_MODE", "true");

        assert_eq!(select_backend_mode(), BackendMode::Development);

        reset_env();
    }

    #[test]
    #[serial]
    fn test_select_backend_mode_prefers_secure_when_broker_available() {
        reset_env();
        let temp_socket = NamedTempFile::new().expect("temp socket path");
        let socket_path = temp_socket.path().to_path_buf();
        std::env::set_var(BROKER_SOCKET_OVERRIDE_ENV, &socket_path);

        assert_eq!(select_backend_mode(), BackendMode::Secure);

        reset_env();
        drop(temp_socket);
    }

    #[test]
    #[serial]
    fn test_select_backend_mode_unavailable_without_broker() {
        reset_env();
        let dir = tempdir().expect("temp dir");
        let missing_socket = dir.path().join("missing.sock");
        std::env::set_var(BROKER_SOCKET_OVERRIDE_ENV, &missing_socket);

        assert_eq!(select_backend_mode(), BackendMode::Unavailable);

        reset_env();
    }

    #[test]
    #[serial]
    fn test_secure_backend_from_env_uses_default_socket() {
        reset_env();
        let temp_socket = NamedTempFile::new().expect("temp socket path");
        let socket_path = temp_socket.path().to_path_buf();
        std::env::set_var(BROKER_SOCKET_OVERRIDE_ENV, &socket_path);

        let backend = SecureBackend::from_env().expect("backend from default socket");
        assert_eq!(backend.validator_id, "unknown");

        reset_env();
    }

    #[tokio::test]
    #[serial]
    async fn test_secure_backend_start_challenge_via_bridge() {
        reset_env();
        let bridge = RecordingSecureBridge::default();
        bridge.set_create_response("container-123", "challenge-container");
        bridge.set_endpoint("container-123", "http://sandbox:8080");

        let backend = SecureBackend::with_bridge(bridge.clone(), "validator-abc");
        let config = sample_config("ghcr.io/platformnetwork/demo:v1");

        let instance = backend
            .start_challenge(&config)
            .await
            .expect("start succeeds");

        assert_eq!(instance.container_id, "container-123");
        assert_eq!(instance.endpoint, "http://sandbox:8080");
        assert_eq!(instance.image, config.docker_image);

        let ops = bridge.operations();
        assert!(ops.iter().any(|op| op.starts_with("create:")));
        assert!(ops.iter().any(|op| op.starts_with("start:")));
        assert!(ops.iter().any(|op| op.starts_with("endpoint:")));

        reset_env();
    }

    #[tokio::test]
    #[serial]
    async fn test_secure_backend_covers_remaining_methods() {
        reset_env();
        let bridge = RecordingSecureBridge::default();
        bridge.set_inspect_state("running", ContainerState::Running);
        bridge.set_inspect_state("stopped", ContainerState::Stopped);
        bridge.set_logs("running", "log output");
        bridge.set_cleanup_result(BrokerCleanupResult {
            total: 2,
            stopped: 2,
            removed: 2,
            errors: Vec::new(),
        });
        bridge.set_list(
            "challenge-1",
            vec![
                container_info("alpha", ContainerState::Running),
                container_info("beta", ContainerState::Stopped),
            ],
        );
        let backend = SecureBackend::with_bridge(bridge.clone(), "validator-xyz");

        backend
            .stop_container("running")
            .await
            .expect("stop delegates");
        backend
            .remove_container("running")
            .await
            .expect("remove delegates");
        backend
            .pull_image("ghcr.io/platformnetwork/demo:v2")
            .await
            .expect("pull delegates");
        let logs = backend
            .get_logs("running", 50)
            .await
            .expect("logs delegates");
        assert_eq!(logs, "log output");
        assert!(backend
            .is_container_running("running")
            .await
            .expect("running state"));
        assert!(!backend
            .is_container_running("stopped")
            .await
            .expect("stopped state"));

        let removed = backend
            .cleanup_challenge("challenge-1")
            .await
            .expect("cleanup delegates");
        assert_eq!(removed, 2);

        let ids = backend
            .list_challenge_containers("challenge-1")
            .await
            .expect("list delegates");
        assert_eq!(ids, vec!["alpha".to_string(), "beta".to_string()]);

        let ops = bridge.operations();
        assert!(ops.iter().any(|op| op.starts_with("stop:")));
        assert!(ops.iter().any(|op| op.starts_with("remove:")));
        assert!(ops.iter().any(|op| op.starts_with("pull:")));
        assert!(ops.iter().any(|op| op.starts_with("logs:")));
        assert!(ops.iter().any(|op| op.starts_with("inspect:")));
        assert!(ops.iter().any(|op| op.starts_with("cleanup:")));
        assert!(ops.iter().any(|op| op.starts_with("list:")));

        reset_env();
    }

    #[tokio::test]
    #[serial]
    async fn test_direct_backend_delegates_to_docker() {
        let docker = RecordingChallengeDocker::default();
        docker.set_list(vec!["container-1".to_string(), "other".to_string()]);

        let backend = DirectDockerBackend::with_docker(docker.clone());
        let mut config = sample_config("ghcr.io/platformnetwork/demo:v3");
        config.challenge_id = ChallengeId::new();

        backend.pull_image(&config.docker_image).await.unwrap();
        let instance = backend.start_challenge(&config).await.unwrap();
        docker.set_running(&instance.container_id, true);
        docker.set_logs(&instance.container_id, "container logs");
        backend
            .stop_container(&instance.container_id)
            .await
            .unwrap();
        backend
            .remove_container(&instance.container_id)
            .await
            .unwrap();
        assert!(backend
            .is_container_running(&instance.container_id)
            .await
            .unwrap());
        let logs = backend.get_logs(&instance.container_id, 10).await.unwrap();
        assert_eq!(logs, "container logs");

        let listed = backend.list_challenge_containers("unused").await.unwrap();
        assert_eq!(listed.len(), 2);

        let ops = docker.operations();
        assert!(ops.iter().any(|op| op.starts_with("pull:")));
        assert!(ops.iter().any(|op| op.starts_with("start:")));
        assert!(ops.iter().any(|op| op.starts_with("stop:")));
        assert!(ops.iter().any(|op| op.starts_with("remove:")));
        assert!(ops.iter().any(|op| op.starts_with("logs:")));
    }

    #[tokio::test]
    #[serial]
    async fn test_direct_backend_cleanup_filters_by_challenge_id() {
        let docker = RecordingChallengeDocker::default();
        let challenge_id = ChallengeId::new();
        let challenge_str = challenge_id.to_string();
        docker.set_list(vec![
            format!("{challenge_str}-a"),
            "platform-helper".to_string(),
            format!("other-{challenge_str}"),
        ]);

        let backend = DirectDockerBackend::with_docker(docker.clone());
        let removed = backend
            .cleanup_challenge(&challenge_str)
            .await
            .expect("cleanup succeeds");
        assert_eq!(removed, 2);

        let ops = docker.operations();
        assert!(ops.iter().filter(|op| op.starts_with("stop:")).count() >= 2);
        assert!(ops.iter().filter(|op| op.starts_with("remove:")).count() >= 2);
    }

    #[tokio::test]
    #[serial]
    async fn test_create_backend_uses_direct_in_dev_mode() {
        reset_env();
        std::env::set_var("DEVELOPMENT_MODE", "true");
        let docker = RecordingChallengeDocker::default();
        DirectDockerBackend::set_test_result(Ok(DirectDockerBackend::with_docker(docker.clone())));

        let backend = create_backend().await.expect("backend");
        backend
            .pull_image("ghcr.io/platformnetwork/test:v1")
            .await
            .unwrap();

        assert!(docker
            .operations()
            .iter()
            .any(|op| op == "pull:ghcr.io/platformnetwork/test:v1"));

        reset_env();
    }

    #[tokio::test]
    #[serial]
    async fn test_create_backend_uses_secure_when_broker_available() {
        reset_env();
        let temp_socket = NamedTempFile::new().expect("temp socket path");
        let socket_path = temp_socket.path().to_path_buf();
        std::env::set_var(BROKER_SOCKET_OVERRIDE_ENV, &socket_path);

        let bridge = RecordingSecureBridge::default();
        SecureBackend::set_test_backend(SecureBackend::with_bridge(
            bridge.clone(),
            "validator-secure",
        ));

        let backend = create_backend().await.expect("secure backend");
        backend
            .pull_image("ghcr.io/platformnetwork/secure:v1")
            .await
            .unwrap();

        assert!(bridge
            .operations()
            .iter()
            .any(|op| op == "pull:ghcr.io/platformnetwork/secure:v1"));

        reset_env();
        drop(temp_socket);
    }

    #[tokio::test]
    #[serial]
    async fn test_create_backend_reports_error_without_broker() {
        reset_env();
        let dir = tempdir().expect("temp dir");
        let missing_socket = dir.path().join("missing.sock");
        std::env::set_var(BROKER_SOCKET_OVERRIDE_ENV, &missing_socket);

        let err = match create_backend().await {
            Ok(_) => panic!("expected error"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("No container backend available"));

        reset_env();
    }

    fn sample_config(image: &str) -> ChallengeContainerConfig {
        ChallengeContainerConfig {
            challenge_id: ChallengeId::new(),
            name: "challenge".to_string(),
            docker_image: image.to_string(),
            mechanism_id: 0,
            emission_weight: 1.0,
            timeout_secs: 300,
            cpu_cores: 1.0,
            memory_mb: 512,
            gpu_required: false,
        }
    }

    fn container_info(id: &str, state: ContainerState) -> ContainerInfo {
        ContainerInfo {
            id: id.to_string(),
            name: format!("{id}-container"),
            challenge_id: "challenge-1".to_string(),
            owner_id: "owner".to_string(),
            image: "ghcr.io/platformnetwork/demo".to_string(),
            state,
            created_at: Utc::now(),
            ports: HashMap::new(),
            endpoint: None,
            labels: HashMap::new(),
        }
    }

    #[derive(Clone, Default)]
    struct RecordingSecureBridge {
        inner: Arc<RecordingSecureBridgeInner>,
    }

    struct RecordingSecureBridgeInner {
        operations: Mutex<Vec<String>>,
        inspect_map: Mutex<HashMap<String, ContainerInfo>>,
        endpoint_map: Mutex<HashMap<String, String>>,
        logs_map: Mutex<HashMap<String, String>>,
        list_map: Mutex<HashMap<String, Vec<ContainerInfo>>>,
        cleanup_result: Mutex<BrokerCleanupResult>,
        create_response: Mutex<(String, String)>,
    }

    impl Default for RecordingSecureBridgeInner {
        fn default() -> Self {
            Self {
                operations: Mutex::new(Vec::new()),
                inspect_map: Mutex::new(HashMap::new()),
                endpoint_map: Mutex::new(HashMap::new()),
                logs_map: Mutex::new(HashMap::new()),
                list_map: Mutex::new(HashMap::new()),
                cleanup_result: Mutex::new(BrokerCleanupResult {
                    total: 0,
                    stopped: 0,
                    removed: 0,
                    errors: Vec::new(),
                }),
                create_response: Mutex::new(("container-id".to_string(), "container".to_string())),
            }
        }
    }

    impl RecordingSecureBridge {
        fn operations(&self) -> Vec<String> {
            self.inner.operations.lock().unwrap().clone()
        }

        fn set_inspect_state(&self, id: &str, state: ContainerState) {
            self.inner
                .inspect_map
                .lock()
                .unwrap()
                .insert(id.to_string(), container_info(id, state));
        }

        fn set_endpoint(&self, id: &str, endpoint: &str) {
            self.inner
                .endpoint_map
                .lock()
                .unwrap()
                .insert(id.to_string(), endpoint.to_string());
        }

        fn set_logs(&self, id: &str, logs: &str) {
            self.inner
                .logs_map
                .lock()
                .unwrap()
                .insert(id.to_string(), logs.to_string());
        }

        fn set_list(&self, challenge: &str, containers: Vec<ContainerInfo>) {
            self.inner
                .list_map
                .lock()
                .unwrap()
                .insert(challenge.to_string(), containers);
        }

        fn set_cleanup_result(&self, result: BrokerCleanupResult) {
            *self.inner.cleanup_result.lock().unwrap() = result;
        }

        fn set_create_response(&self, id: &str, name: &str) {
            *self.inner.create_response.lock().unwrap() = (id.to_string(), name.to_string());
        }
    }

    #[async_trait]
    impl SecureContainerBridge for RecordingSecureBridge {
        async fn create_container(
            &self,
            config: ContainerConfig,
        ) -> Result<(String, String), ContainerError> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("create:{}", config.challenge_id));
            Ok(self.inner.create_response.lock().unwrap().clone())
        }

        async fn start_container(
            &self,
            container_id: &str,
        ) -> Result<ContainerStartResult, ContainerError> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("start:{container_id}"));
            Ok(ContainerStartResult {
                container_id: container_id.to_string(),
                ports: HashMap::new(),
                endpoint: None,
            })
        }

        async fn get_endpoint(
            &self,
            container_id: &str,
            port: u16,
        ) -> Result<String, ContainerError> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("endpoint:{container_id}:{port}"));
            self.inner
                .endpoint_map
                .lock()
                .unwrap()
                .get(container_id)
                .cloned()
                .ok_or_else(|| ContainerError::ContainerNotFound(container_id.to_string()))
        }

        async fn stop_container(
            &self,
            container_id: &str,
            timeout_secs: u32,
        ) -> Result<(), ContainerError> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("stop:{container_id}:{timeout_secs}"));
            Ok(())
        }

        async fn remove_container(
            &self,
            container_id: &str,
            force: bool,
        ) -> Result<(), ContainerError> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("remove:{container_id}:{force}"));
            Ok(())
        }

        async fn inspect(&self, container_id: &str) -> Result<ContainerInfo, ContainerError> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("inspect:{container_id}"));
            self.inner
                .inspect_map
                .lock()
                .unwrap()
                .get(container_id)
                .cloned()
                .ok_or_else(|| ContainerError::ContainerNotFound(container_id.to_string()))
        }

        async fn pull_image(&self, image: &str) -> Result<(), ContainerError> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("pull:{image}"));
            Ok(())
        }

        async fn logs(&self, container_id: &str, tail: usize) -> Result<String, ContainerError> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("logs:{container_id}:{tail}"));
            self.inner
                .logs_map
                .lock()
                .unwrap()
                .get(container_id)
                .cloned()
                .ok_or_else(|| ContainerError::ContainerNotFound(container_id.to_string()))
        }

        async fn cleanup_challenge(
            &self,
            challenge_id: &str,
        ) -> Result<BrokerCleanupResult, ContainerError> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("cleanup:{challenge_id}"));
            Ok(self.inner.cleanup_result.lock().unwrap().clone())
        }

        async fn list_by_challenge(
            &self,
            challenge_id: &str,
        ) -> Result<Vec<ContainerInfo>, ContainerError> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("list:{challenge_id}"));
            Ok(self
                .inner
                .list_map
                .lock()
                .unwrap()
                .get(challenge_id)
                .cloned()
                .unwrap_or_default())
        }
    }

    #[derive(Clone, Default)]
    struct RecordingChallengeDocker {
        inner: Arc<RecordingChallengeDockerInner>,
    }

    #[derive(Default)]
    struct RecordingChallengeDockerInner {
        operations: Mutex<Vec<String>>,
        running: Mutex<HashMap<String, bool>>,
        logs: Mutex<HashMap<String, String>>,
        list: Mutex<Vec<String>>,
        next_id: Mutex<u64>,
    }

    impl RecordingChallengeDocker {
        fn operations(&self) -> Vec<String> {
            self.inner.operations.lock().unwrap().clone()
        }

        fn set_running(&self, id: &str, running: bool) {
            self.inner
                .running
                .lock()
                .unwrap()
                .insert(id.to_string(), running);
        }

        fn set_logs(&self, id: &str, logs: &str) {
            self.inner
                .logs
                .lock()
                .unwrap()
                .insert(id.to_string(), logs.to_string());
        }

        fn set_list(&self, items: Vec<String>) {
            *self.inner.list.lock().unwrap() = items;
        }

        fn next_instance(&self, config: &ChallengeContainerConfig) -> ChallengeInstance {
            let mut guard = self.inner.next_id.lock().unwrap();
            let value = *guard;
            *guard += 1;
            let suffix = value.to_string();
            sample_instance(
                config.challenge_id,
                &format!("container-{}", suffix),
                &config.docker_image,
                ContainerStatus::Running,
            )
        }
    }

    fn sample_instance(
        challenge_id: ChallengeId,
        container_id: &str,
        image: &str,
        status: ContainerStatus,
    ) -> ChallengeInstance {
        ChallengeInstance {
            challenge_id,
            container_id: container_id.to_string(),
            image: image.to_string(),
            endpoint: format!("http://{container_id}"),
            started_at: Utc::now(),
            status,
        }
    }

    #[async_trait]
    impl ChallengeDocker for RecordingChallengeDocker {
        async fn pull_image(&self, image: &str) -> anyhow::Result<()> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("pull:{image}"));
            Ok(())
        }

        async fn start_challenge(
            &self,
            config: &ChallengeContainerConfig,
        ) -> anyhow::Result<ChallengeInstance> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("start:{}", config.challenge_id));
            Ok(self.next_instance(config))
        }

        async fn stop_container(&self, container_id: &str) -> anyhow::Result<()> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("stop:{container_id}"));
            Ok(())
        }

        async fn remove_container(&self, container_id: &str) -> anyhow::Result<()> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("remove:{container_id}"));
            Ok(())
        }

        async fn is_container_running(&self, container_id: &str) -> anyhow::Result<bool> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("is_running:{container_id}"));
            Ok(*self
                .inner
                .running
                .lock()
                .unwrap()
                .get(container_id)
                .unwrap_or(&false))
        }

        async fn get_logs(&self, container_id: &str, tail: usize) -> anyhow::Result<String> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("logs:{container_id}:{tail}"));
            Ok(self
                .inner
                .logs
                .lock()
                .unwrap()
                .get(container_id)
                .cloned()
                .unwrap_or_default())
        }

        async fn list_challenge_containers(&self) -> anyhow::Result<Vec<String>> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push("list_containers".to_string());
            Ok(self.inner.list.lock().unwrap().clone())
        }

        async fn cleanup_stale_containers(
            &self,
            prefix: &str,
            _max_age_minutes: u64,
            _exclude_patterns: &[&str],
        ) -> anyhow::Result<DockerCleanupResult> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("cleanup:{prefix}"));
            Ok(DockerCleanupResult::default())
        }
    }
}
