//! Container backend abstraction
//!
//! Provides a unified interface for container management that can use:
//! - SecureContainerClient via broker (DEFAULT for production validators)
//! - Direct Docker (ONLY for local development when DEVELOPMENT_MODE=true)
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
//! In production, challenges MUST run through the secure broker.
//! The broker enforces:
//! - Image whitelisting (only ghcr.io/platformnetwork/)
//! - Non-privileged containers
//! - Resource limits
//! - No Docker socket access for challenges

use crate::{ChallengeContainerConfig, ChallengeDocker, ChallengeInstance, ContainerStatus};
use async_trait::async_trait;
use secure_container_runtime::{
    CleanupResult as BrokerCleanupResult, ContainerConfig, ContainerConfigBuilder, ContainerError,
    ContainerInfo, ContainerStartResult, ContainerState, NetworkMode, SecureContainerClient,
};
use std::path::Path;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Default broker socket path
pub const DEFAULT_BROKER_SOCKET: &str = "/var/run/platform/broker.sock";
const BROKER_SOCKET_OVERRIDE_ENV: &str = "BROKER_SOCKET_OVERRIDE";

/// Get the broker socket path, preferring an environment override.
///
/// If the `BROKER_SOCKET_OVERRIDE` environment variable is set, its value is returned;
/// otherwise the compiled `DEFAULT_BROKER_SOCKET` is returned.
///
/// # Examples
///
/// ```
/// use std::env;
/// // Ensure override is not set to observe default behavior
/// env::remove_var("BROKER_SOCKET_OVERRIDE");
/// let p = crate::default_broker_socket_path();
/// assert_eq!(p, crate::DEFAULT_BROKER_SOCKET.to_string());
///
/// // Set an override and observe it takes precedence
/// env::set_var("BROKER_SOCKET_OVERRIDE", "/tmp/override.sock");
/// assert_eq!(crate::default_broker_socket_path(), "/tmp/override.sock");
/// ```
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
    /// Creates a SecureClientBridge configured to communicate with the container broker at `socket_path`.
    ///
    /// `socket_path` is the filesystem path to the broker's Unix domain socket.
    ///
    /// # Examples
    ///
    /// ```
    /// let bridge = SecureClientBridge::new("/var/run/platform/broker.sock");
    /// ```
    fn new(socket_path: &str) -> Self {
        Self {
            client: SecureContainerClient::new(socket_path),
        }
    }
}

#[async_trait]
impl SecureContainerBridge for SecureClientBridge {
    /// Creates a container from the provided `ContainerConfig`.
    ///
    /// Returns the created container's ID and its name.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(bridge: &impl crate::SecureContainerBridge, config: crate::ContainerConfig) {
    /// let (id, name) = bridge.create_container(config).await.unwrap();
    /// assert!(!id.is_empty());
    /// assert!(!name.is_empty());
    /// # }
    /// ```
    async fn create_container(
        &self,
        config: ContainerConfig,
    ) -> Result<(String, String), ContainerError> {
        self.client.create_container(config).await
    }

    /// Starts an existing container through the secure bridge.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(client: &impl SecureContainerBridge) -> Result<(), ContainerError> {
    /// let result = client.start_container("container-id").await?;
    /// // `result` contains the outcome of the start operation.
    /// # Ok(())
    /// # }
    /// ```
    async fn start_container(
        &self,
        container_id: &str,
    ) -> Result<ContainerStartResult, ContainerError> {
        self.client.start_container(container_id).await
    }

    /// Get the host:port endpoint exposed for a container port.
    ///
    /// # Returns
    ///
    /// `Ok(String)` containing the endpoint in `host:port` form for the requested container and port, or `Err(ContainerError)` if the endpoint cannot be retrieved.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(backend: &impl crate::SecureContainerBridge) -> Result<(), crate::ContainerError> {
    /// let endpoint = backend.get_endpoint("container-id-123", 8080).await?;
    /// println!("Endpoint: {}", endpoint);
    /// # Ok(()) }
    /// ```
    async fn get_endpoint(&self, container_id: &str, port: u16) -> Result<String, ContainerError> {
        self.client.get_endpoint(container_id, port).await
    }

    /// Stop a container managed by the broker, allowing a graceful shutdown period.
    ///
    /// # Parameters
    ///
    /// - `container_id`: Identifier of the container to stop.
    /// - `timeout_secs`: Number of seconds to wait for graceful shutdown before forcefully stopping.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the container was stopped successfully, `Err(ContainerError)` otherwise.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(bridge: &impl crate::SecureContainerBridge) -> Result<(), crate::ContainerError> {
    /// bridge.stop_container("container-123", 30).await?;
    /// # Ok(()) }
    /// ```
    async fn stop_container(
        &self,
        container_id: &str,
        timeout_secs: u32,
    ) -> Result<(), ContainerError> {
        self.client.stop_container(container_id, timeout_secs).await
    }

    /// Remove a container by its identifier.
    ///
    /// Attempts to remove the container identified by `container_id`. The `force` flag
    /// indicates whether the removal should be forced.
    ///
    /// Returns `Ok(())` if the container was removed, `Err(ContainerError)` if the
    /// underlying removal operation failed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example<B: crate::backend::ContainerBackend>(backend: &B) -> Result<(), Box<dyn std::error::Error>> {
    /// backend.remove_container("container-abc123", true).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn remove_container(
        &self,
        container_id: &str,
        force: bool,
    ) -> Result<(), ContainerError> {
        self.client.remove_container(container_id, force).await
    }

    /// Inspect a container and obtain its metadata.
    ///
    /// Inspect the container identified by `container_id` and return its runtime and configuration
    /// information as a `ContainerInfo`.
    ///
    /// # Parameters
    ///
    /// - `container_id`: The identifier of the container to inspect.
    ///
    /// # Returns
    ///
    /// On success, returns the container's metadata as a `ContainerInfo`; on failure, returns a
    /// `ContainerError`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use futures::executor::block_on;
    /// # let backend = /* Arc<dyn SecureContainerBridge> */ todo!();
    /// let info = block_on(async { backend.inspect("container-id").await });
    /// ```
    async fn inspect(&self, container_id: &str) -> Result<ContainerInfo, ContainerError> {
        self.client.inspect(container_id).await
    }

    /// Pulls the specified container image through the configured secure broker.
    ///
    /// `image` should be a valid image reference (for example "nginx:latest" or "repo/image:tag").
    ///
    /// # Returns
    ///
    /// `Ok(())` if the image was pulled successfully, `Err(ContainerError)` if the broker reported an error.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example<B: crate::backend::ContainerBackend + ?Sized>(backend: &B) {
    /// backend.pull_image("nginx:latest").await.unwrap();
    /// # }
    /// ```
    async fn pull_image(&self, image: &str) -> Result<(), ContainerError> {
        self.client.pull_image(image).await
    }

    /// Retrieve logs for a container, limiting the output to the most recent `tail` lines.
    ///
    /// # Examples
    ///
    /// ```
    /// # async fn example<B: crate::backend::ContainerBackend + std::marker::Send + Sync>(backend: &B) {
    /// let logs = backend.logs("container_id", 100).await.unwrap();
    /// println!("{}", logs);
    /// # }
    /// ```
    async fn logs(&self, container_id: &str, tail: usize) -> Result<String, ContainerError> {
        self.client.logs(container_id, tail).await
    }

    /// Requests the broker to clean up all containers and resources for a challenge.
    ///
    /// Delegates cleanup to the configured secure container bridge and returns the broker's
    /// cleanup result which includes counts and any error details reported by the broker.
    ///
    /// # Returns
    ///
    /// `Ok(BrokerCleanupResult)` with cleanup details when the broker operation succeeds,
    /// `Err(ContainerError)` if the cleanup request fails or the bridge reports an error.
    async fn cleanup_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<BrokerCleanupResult, ContainerError> {
        self.client.cleanup_challenge(challenge_id).await
    }

    /// List containers associated with a challenge.
    ///
    /// Returns a vector of `ContainerInfo` entries for containers that belong to the given
    /// `challenge_id`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// // Acquire an implementation of `SecureContainerBridge` as `bridge` (specifics vary).
    /// // Then call:
    /// // let infos = bridge.list_by_challenge("challenge-123").await.unwrap();
    /// ```
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
    /// Constructs a SecureBackend connected to the secure container broker at the given socket and using the provided validator identifier.
    ///
    /// The `socket_path` is the filesystem path to the broker's Unix domain socket. `validator_id` is used to tag containers started by this backend.
    ///
    /// # Examples
    ///
    /// ```
    /// let backend = SecureBackend::new("/var/run/platform/broker.sock", "validator-abc");
    /// // use backend...
    /// ```
    ///
    /// # Returns
    ///
    /// A `SecureBackend` instance configured to communicate with the broker at `socket_path` and to use `validator_id` when naming or tagging containers.
    pub fn new(socket_path: &str, validator_id: &str) -> Self {
        Self::with_bridge(SecureClientBridge::new(socket_path), validator_id)
    }

    /// Provides a global, lazily initialized test slot for injecting or retrieving a `SecureBackend`.
    ///
    /// This helper returns a `'static` `Mutex<Option<SecureBackend>>` used by tests to set a test backend
    /// instance that other test helpers can take or inspect.
    ///
    /// # Examples
    ///
    /// ```
    /// // set the test backend
    /// let slot = test_backend_slot();
    /// {
    ///     let mut guard = slot.lock().unwrap();
    ///     *guard = Some(SecureBackend::with_bridge(...)); // example; construct a test backend
    /// }
    /// // read or take the backend later in another test helper
    /// {
    ///     let mut guard = slot.lock().unwrap();
    ///     let _backend = guard.take();
    /// }
    /// ```
    #[cfg(test)]
    fn test_backend_slot() -> &'static std::sync::Mutex<Option<SecureBackend>> {
        use std::sync::{Mutex, OnceLock};
        static SLOT: OnceLock<Mutex<Option<SecureBackend>>> = OnceLock::new();
        SLOT.get_or_init(|| Mutex::new(None))
    }

    /// Remove and return the current test `SecureBackend` stored in the internal test slot, if any.
    ///
    /// This takes the `Option` from the test slot, leaving `None` in its place.
    ///
    /// # Returns
    ///
    /// `Some(SecureBackend)` if a test backend was set, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// // In tests: set_test_backend(Some(secure_backend));
    /// // let backend = take_test_backend().expect("test backend should be present");
    /// ```
    #[cfg(test)]
    fn take_test_backend() -> Option<SecureBackend> {
        Self::test_backend_slot().lock().unwrap().take()
    }

    /// Sets the global test SecureBackend used by test helpers.
    ///
    /// This replaces the current test backend stored in the internal test slot with `backend`.
    ///
    /// # Examples
    ///
    /// ```
    /// // In test code:
    /// let test_backend = SecureBackend::with_bridge(RecordingSecureBridge::new(), "validator");
    /// set_test_backend(test_backend);
    /// ```
    #[cfg(test)]
    pub(crate) fn set_test_backend(backend: SecureBackend) {
        Self::test_backend_slot().lock().unwrap().replace(backend);
    }

    /// Creates a SecureBackend that uses the provided bridge for broker operations and the given validator identifier.
    ///
    /// This constructs a backend which delegates all SecureContainerBridge calls to `client` and records `validator_id`
    /// for container naming and metadata. Intended for injecting custom or test bridges.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let bridge = RecordingSecureBridge::default();
    /// let backend = SecureBackend::with_bridge(bridge, "validator-1");
    /// ```
    pub fn with_bridge(
        client: impl SecureContainerBridge + 'static,
        validator_id: impl Into<String>,
    ) -> Self {
        Self {
            client: Arc::new(client),
            validator_id: validator_id.into(),
        }
    }

    /// Constructs a SecureBackend from environment or the default broker socket when available.
    ///
    /// Checks for a broker socket in the following order:
    /// 1. The `CONTAINER_BROKER_SOCKET` environment variable (if set and the path exists).
    /// 2. The default broker socket path returned by `default_broker_socket_path()` (if it exists).
    /// The `VALIDATOR_HOTKEY` environment variable is read to populate the validator identifier; if unset, `"unknown"` is used.
    ///
    /// # Returns
    ///
    /// `Some(Self)` when a usable broker socket path is found and a backend can be constructed, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// // Attempt to build a backend from environment; handle the absence of a broker gracefully.
    /// if let Some(backend) = SecureBackend::from_env() {
    ///     // broker-backed backend is available
    ///     let _ = backend;
    /// } else {
    ///     // fall back to another backend
    /// }
    /// ```
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

    /// Determine whether a broker socket exists and is therefore available.
    
    ///
    
    /// This checks the `CONTAINER_BROKER_SOCKET` environment variable first: if it is set
    
    /// and points to an existing filesystem path, this function returns `true`. If the
    
    /// environment variable is not set or does not point to an existing path, the default
    
    /// broker socket path returned by `default_broker_socket_path()` is checked instead.
    
    ///
    
    /// # Examples
    
    ///
    
    /// ```
    
    /// use std::fs;
    
    /// use std::env;
    
    /// use std::path::PathBuf;
    
    ///
    
    /// // create a temporary socket file and point the env var at it
    
    /// let mut p = env::temp_dir();
    
    /// p.push("test_broker_socket.sock");
    
    /// let path = p.to_string_lossy().into_owned();
    
    /// let _f = fs::File::create(&path).unwrap();
    
    /// env::set_var("CONTAINER_BROKER_SOCKET", &path);
    
    ///
    
    /// assert!(crate::backend::is_available());
    
    ///
    
    /// // cleanup
    
    /// let _ = fs::remove_file(&path);
    
    /// env::remove_var("CONTAINER_BROKER_SOCKET");
    
    /// ```
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
    /// Creates a new DirectDockerBackend by connecting to the Docker daemon.
    ///
    /// Returns `Ok(DirectDockerBackend)` on success, or an error if a Docker client cannot be created (for example, if the Docker daemon is unavailable).
    /// In tests this constructor may return an injected test result instead of attempting a real Docker connection.
    ///
    /// # Examples
    ///
    /// ```
    /// # tokio_test::block_on(async {
    /// let backend = crate::backend::DirectDockerBackend::new().await.unwrap();
    /// // use backend...
    /// # });
    /// ```
    pub async fn new() -> anyhow::Result<Self> {
        #[cfg(test)]
        if let Some(result) = Self::take_test_result() {
            return result;
        }

        let docker = crate::docker::DockerClient::connect().await?;
        Ok(Self::with_docker(docker))
    }

    /// Constructs a DirectDockerBackend that uses the provided `ChallengeDocker` implementation.
    ///
    /// The supplied `docker` is stored inside the backend and used for all subsequent Docker-backed
    /// operations. This is primarily intended for testing with custom or mocked `ChallengeDocker`
    /// implementations.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // Provide any type that implements `ChallengeDocker` (e.g., a test double).
    /// let docker_impl = /* your ChallengeDocker implementation */;
    /// let backend = DirectDockerBackend::with_docker(docker_impl);
    /// ```
    pub fn with_docker(docker: impl ChallengeDocker + 'static) -> Self {
        Self {
            docker: Arc::new(docker),
        }
    }

    /// Returns a global, lazily-initialized mutex slot used by tests to inject or take a
    /// `DirectDockerBackend` construction result.
    ///
    /// The slot holds an `Option<anyhow::Result<DirectDockerBackend>>` so tests can store either
    /// a successful backend or an error for `DirectDockerBackend::new()` simulation.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::MutexGuard;
    /// // Acquire the slot and set a simulated error result for tests:
    /// let slot = crate::test_backend_slot();
    /// {
    ///     let mut guard = slot.lock().unwrap();
    ///     *guard = Some(Err(anyhow::anyhow!("simulated failure")));
    /// }
    /// // Later, a test can take or inspect the stored value.
    /// ```
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

    /// Sets the test result that DirectDockerBackend::new() will return during tests.
    ///
    /// This injects a precomputed `Result<DirectDockerBackend>` into the global test slot so test-only
    /// code that constructs a `DirectDockerBackend` can observe the supplied success or failure.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // Simulate a failure when DirectDockerBackend::new() is called in tests.
    /// set_test_result(Err(anyhow::anyhow!("simulated docker init failure")));
    /// ```
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

/// Selects and constructs the appropriate container backend based on environment and broker availability.
///
/// The selection priority is:
/// 1. If DEVELOPMENT_MODE is enabled, use the direct Docker backend (for local development).
/// 2. If a secure broker socket is available, use the secure broker backend.
/// 3. Otherwise, attempt a Docker fallback and return an error if that fails.
///
/// # Returns
///
/// `Ok` with a boxed `ContainerBackend` implementation when a backend is successfully created, `Err` otherwise.
///
/// # Examples
///
/// ```
/// # tokio_test::block_on(async {
/// let backend = crate::backend::create_backend().await;
/// match backend {
///     Ok(b) => {
///         // use the backend, e.g. b.pull_image("alpine:latest").await.unwrap();
///         drop(b);
///     }
///     Err(e) => {
///         eprintln!("failed to create backend: {}", e);
///     }
/// }
/// # });
/// ```
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
                warn!(
                    "Secure backend reported as available but failed to initialize; falling back to Docker"
                );
                create_docker_fallback_backend().await
            }
        }
        BackendMode::Fallback => create_docker_fallback_backend().await,
    }
}

/// Attempts to instantiate a direct Docker-backed ContainerBackend as a fallback when the broker is unavailable.
///
/// On success returns a boxed backend that talks directly to the local Docker daemon. On failure returns an error
/// describing that no container backend is available and suggesting starting the broker or enabling development mode.
///
/// # Examples
///
/// ```ignore
/// // Run inside an async context:
/// let backend = create_docker_fallback_backend().await?;
/// // `backend` is a `Box<dyn ContainerBackend>` ready to use with Docker.
/// # Ok::<(), anyhow::Error>(())
/// ```
async fn create_docker_fallback_backend() -> anyhow::Result<Box<dyn ContainerBackend>> {
    warn!("Broker not available. Attempting Docker fallback...");
    warn!("This should only happen in local development!");
    warn!("Set DEVELOPMENT_MODE=true to suppress this warning, or start the broker.");

    match DirectDockerBackend::new().await {
        Ok(direct) => {
            warn!("Using direct Docker - NOT RECOMMENDED FOR PRODUCTION");
            Ok(Box::new(direct))
        }
        Err(e) => {
            error!("Cannot connect to Docker: {}", e);
            error!("For production: Start the container-broker service");
            error!("For development: Set DEVELOPMENT_MODE=true and ensure Docker is running");
            let default_socket = default_broker_socket_path();
            Err(anyhow::anyhow!(
                "No container backend available. \
                 Start broker at {} or set DEVELOPMENT_MODE=true for local Docker",
                default_socket
            ))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendMode {
    Development,
    Secure,
    Fallback,
}

/// Selects which container backend mode the application should use.
///
/// Returns Development when development mode is enabled via the environment;
/// otherwise returns Secure if a container broker socket is available; otherwise returns Fallback.
///
/// # Examples
///
/// ```rust
/// use crate::backend::BackendMode;
/// let mode = crate::backend::select_backend_mode();
/// assert!(matches!(
///     mode,
///     BackendMode::Development | BackendMode::Secure | BackendMode::Fallback
/// ));
/// ```
pub fn select_backend_mode() -> BackendMode {
    if is_development_mode() {
        BackendMode::Development
    } else if SecureBackend::is_available() {
        BackendMode::Secure
    } else {
        BackendMode::Fallback
    }
}

/// Indicates whether a secure broker socket is available.
///
/// # Returns
/// `true` if a broker socket exists and secure mode is available, `false` otherwise.
///
/// # Examples
///
/// ```
/// // Example: assert that secure mode detection returns a boolean
/// let _ = is_secure_mode();
/// ```
pub fn is_secure_mode() -> bool {
    SecureBackend::is_available()
}

/// Determines whether development mode is enabled.
///
/// Treats the `DEVELOPMENT_MODE` environment variable as enabled when its value is `"true"` or `"1"`.
/// Returns `false` if the variable is unset or has any other value.
///
/// # Examples
///
/// ```
/// std::env::set_var("DEVELOPMENT_MODE", "1");
/// assert!(is_development_mode());
///
/// std::env::set_var("DEVELOPMENT_MODE", "true");
/// assert!(is_development_mode());
///
/// std::env::set_var("DEVELOPMENT_MODE", "0");
/// assert!(!is_development_mode());
///
/// std::env::remove_var("DEVELOPMENT_MODE");
/// assert!(!is_development_mode());
/// ```
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

    /// Clears environment variables used by backend selection and test helpers.
    
    ///
    
    /// Removes the following variables if present: `DEVELOPMENT_MODE`, `CONTAINER_BROKER_SOCKET`,
    
    /// `VALIDATOR_HOTKEY`, and the value of `BROKER_SOCKET_OVERRIDE_ENV`.
    
    ///
    
    /// # Examples
    
    ///
    
    /// ```
    
    /// use std::env;
    
    /// // ensure a variable is set
    
    /// env::set_var("DEVELOPMENT_MODE", "true");
    
    /// assert!(env::var_os("DEVELOPMENT_MODE").is_some());
    
    ///
    
    /// // clear the test-related vars
    
    /// reset_env();
    
    ///
    
    /// // the variable should be removed
    
    /// assert!(env::var_os("DEVELOPMENT_MODE").is_none());
    
    /// ```
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

    /// Verifies that backend selection chooses `Secure` when a broker socket path is present.
    ///
    /// # Examples
    ///
    /// ```
    /// // create a temporary socket path and set override env var
    /// let temp_socket = tempfile::NamedTempFile::new().expect("temp socket path");
    /// let socket_path = temp_socket.path().to_path_buf();
    /// std::env::set_var(BROKER_SOCKET_OVERRIDE_ENV, &socket_path);
    ///
    /// assert_eq!(select_backend_mode(), BackendMode::Secure);
    ///
    /// // cleanup
    /// std::env::remove_var(BROKER_SOCKET_OVERRIDE_ENV);
    /// drop(temp_socket);
    /// ```
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
    fn test_select_backend_mode_falls_back_without_broker() {
        reset_env();
        let dir = tempdir().expect("temp dir");
        let missing_socket = dir.path().join("missing.sock");
        std::env::set_var(BROKER_SOCKET_OVERRIDE_ENV, &missing_socket);

        assert_eq!(select_backend_mode(), BackendMode::Fallback);

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

    /// Ensures that create_backend selects the secure (broker-backed) backend when a broker socket is available.
    ///
    /// Sets the broker socket override and injects a test SecureBackend bridge, then verifies that
    /// a subsequent `pull_image` call is forwarded to the broker.
    ///
    /// # Examples
    ///
    /// ```
    /// // Configure a broker socket override and inject a RecordingSecureBridge as the test backend,
    /// // then call `create_backend().await` and assert that `pull_image` is handled by the broker.
    /// ```
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
    async fn test_create_backend_falls_back_when_secure_missing() {
        reset_env();
        let dir = tempdir().expect("temp dir");
        let missing_socket = dir.path().join("missing.sock");
        std::env::set_var(BROKER_SOCKET_OVERRIDE_ENV, &missing_socket);
        DirectDockerBackend::set_test_result(Ok(DirectDockerBackend::with_docker(
            RecordingChallengeDocker::default(),
        )));

        let backend = create_backend().await.expect("fallback backend");
        backend
            .pull_image("ghcr.io/platformnetwork/fallback:v1")
            .await
            .unwrap();

        reset_env();
    }

    #[tokio::test]
    #[serial]
    async fn test_create_docker_fallback_backend_reports_error() {
        reset_env();
        DirectDockerBackend::set_test_result(Err(anyhow::anyhow!("boom")));
        let err = match create_docker_fallback_backend().await {
            Ok(_) => panic!("expected error"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("No container backend available"));
        reset_env();
    }

    /// Builds a test-oriented ChallengeContainerConfig populated with sensible default values.
    ///
    /// The returned config uses `image` as the container image and fills other fields
    /// (IDs, resources, timeouts, and weights) with typical defaults suitable for tests.
    ///
    /// # Parameters
    ///
    /// - `image`: Docker image reference to set on the returned configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// let cfg = sample_config("example/image:latest");
    /// assert_eq!(cfg.docker_image, "example/image:latest");
    /// assert_eq!(cfg.memory_mb, 512);
    /// ```
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

    /// Creates a sample `ContainerInfo` populated with the given `id` and `state` and default test values for other fields.
    ///
    /// This is a test helper that returns a `ContainerInfo` whose `id` and `state` are set from the arguments; other fields
    /// (name, challenge_id, owner_id, image, timestamps, and empty maps) use fixed sample values.
    ///
    /// # Examples
    ///
    /// ```
    /// let info = container_info("abc123", ContainerState::Running);
    /// assert_eq!(info.id, "abc123");
    /// assert_eq!(info.state, ContainerState::Running);
    /// assert!(info.endpoint.is_none());
    /// ```
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
        /// Constructs a new RecordingSecureBridge with empty recorded operation lists and default simulated responses.
        ///
        /// The returned instance is initialized with:
        /// - empty vectors/maps for recorded operations and simulated inspect/endpoint/logs/list responses,
        /// - a `BrokerCleanupResult` with zeros and an empty error list,
        /// - a default `create_response` of `("container-id", "container")`.
        ///
        /// # Examples
        ///
        /// ```
        /// let bridge = RecordingSecureBridge::default();
        /// let create_resp = bridge.create_response.lock().unwrap();
        /// assert_eq!(create_resp.0, "container-id");
        /// assert_eq!(create_resp.1, "container");
        /// ```
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
        /// Retrieve a snapshot of recorded operation names.
        ///
        /// The returned vector contains the operations in the order they were recorded.
        ///
        /// # Returns
        ///
        /// A `Vec<String>` with the recorded operation names in chronological order.
        ///
        /// # Examples
        ///
        /// ```
        /// // assuming `recorder` is an instance with prior recorded operations
        /// let ops = recorder.operations();
        /// assert!(ops.iter().all(|s| !s.is_empty()));
        /// ```
        fn operations(&self) -> Vec<String> {
            self.inner.operations.lock().unwrap().clone()
        }

        /// Records inspect information for a container.
        ///
        /// Stores a `ContainerInfo` constructed from `state` under `id` in the bridge's internal
        /// inspection map so that subsequent lookups will return the stored value.
        ///
        /// # Examples
        ///
        /// ```
        /// let bridge = RecordingSecureBridge::default();
        /// bridge.set_inspect_state("container-123", ContainerState::Running);
        /// assert!(bridge
        ///     .inner
        ///     .inspect_map
        ///     .lock()
        ///     .unwrap()
        ///     .contains_key("container-123"));
        /// ```
        fn set_inspect_state(&self, id: &str, state: ContainerState) {
            self.inner
                .inspect_map
                .lock()
                .unwrap()
                .insert(id.to_string(), container_info(id, state));
        }

        /// Associates a container identifier with its exposed endpoint.
        ///
        /// Stores the provided `endpoint` string under the given `id` in the bridge's internal endpoint map.
        ///
        /// # Parameters
        ///
        /// - `id`: The container identifier to associate the endpoint with.
        /// - `endpoint`: The endpoint (for example, "http://127.0.0.1:8080") exposed by the container.
        ///
        /// # Examples
        ///
        /// ```
        /// // assuming `bridge` implements `set_endpoint`
        /// bridge.set_endpoint("container-123", "http://127.0.0.1:8080");
        /// ```
        fn set_endpoint(&self, id: &str, endpoint: &str) {
            self.inner
                .endpoint_map
                .lock()
                .unwrap()
                .insert(id.to_string(), endpoint.to_string());
        }

        /// Store or replace the stored logs for a container identifier.
        ///
        /// This updates the internal logs map so subsequent reads for the same `id` will
        /// return `logs`.
        ///
        /// # Examples
        ///
        /// ```
        /// let rec = RecordingSecureBridge::default();
        /// rec.set_logs("container-1", "line1\nline2");
        /// assert_eq!(
        ///     rec.inner.logs_map.lock().unwrap().get("container-1").map(String::as_str),
        ///     Some("line1\nline2")
        /// );
        /// ```
        fn set_logs(&self, id: &str, logs: &str) {
            self.inner
                .logs_map
                .lock()
                .unwrap()
                .insert(id.to_string(), logs.to_string());
        }

        /// Store the given container list under the specified challenge identifier in the bridge's internal mapping.
        ///
        /// This replaces any existing entry for the challenge with `containers`.
        ///
        /// # Examples
        ///
        /// ```
        /// // Assuming `bridge` implements the same API as the recording bridge used in tests:
        /// // let bridge = RecordingSecureBridge::new();
        /// // bridge.set_list("challenge-123", vec![container_info("c1")]);
        /// ```
        fn set_list(&self, challenge: &str, containers: Vec<ContainerInfo>) {
            self.inner
                .list_map
                .lock()
                .unwrap()
                .insert(challenge.to_string(), containers);
        }

        /// Sets the broker cleanup result returned by this recording bridge.
        ///
        /// This overwrites the bridge's current `cleanup_result` so subsequent cleanup calls
        /// will observe `result`.
        ///
        /// # Parameters
        ///
        /// - `result`: The `BrokerCleanupResult` to store and return for future cleanup requests.
        ///
        /// # Examples
        ///
        /// ```
        /// let bridge = RecordingSecureBridge::new();
        /// bridge.set_cleanup_result(BrokerCleanupResult::default());
        /// ```
        fn set_cleanup_result(&self, result: BrokerCleanupResult) {
            *self.inner.cleanup_result.lock().unwrap() = result;
        }

        /// Sets the simulated container creation response used by this recording bridge.
        ///
        /// `id` is the container identifier to return, and `name` is the created container's name.
        /// This is intended for tests to control what `create_container` will report.
        ///
        /// # Examples
        ///
        /// ```
        /// let bridge = RecordingSecureBridge::default();
        /// bridge.set_create_response("container-123", "challenge-abc");
        /// ```
        fn set_create_response(&self, id: &str, name: &str) {
            *self.inner.create_response.lock().unwrap() = (id.to_string(), name.to_string());
        }
    }

    #[async_trait]
    impl SecureContainerBridge for RecordingSecureBridge {
        /// Creates a container for the given configuration, recording the creation request and returning
        /// the preconfigured `(container_id, container_name)` or a `ContainerError`.
        ///
        /// The implementation records a `"create:{challenge_id}"` entry in the bridge's operation log
        /// and returns whatever value has been set on `create_response`.
        ///
        /// # Examples
        ///
        /// ```
        /// // Setup a RecordingSecureBridge with a preset response
        /// let bridge = RecordingSecureBridge::default();
        /// *bridge.inner.create_response.lock().unwrap() = ("cid".to_string(), "name".to_string());
        ///
        /// let cfg = ContainerConfig { challenge_id: "chal1".to_string(), ..Default::default() };
        /// let res = bridge.create_container(cfg).await.unwrap();
        /// assert_eq!(res, ("cid".to_string(), "name".to_string()));
        /// assert_eq!(bridge.inner.operations.lock().unwrap().last().unwrap(), "create:chal1");
        /// ```
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

        /// Records a start operation for the given container ID and returns a `ContainerStartResult` with no exposed ports or endpoint.
        ///
        /// # Examples
        ///
        /// ```
        /// // Given a `bridge` that exposes `start_container`, calling it records the start and returns an empty result.
        /// let res = futures::executor::block_on(bridge.start_container("container-1")).unwrap();
        /// assert_eq!(res.container_id, "container-1");
        /// assert!(res.ports.is_empty());
        /// assert!(res.endpoint.is_none());
        /// ```
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

        /// Retrieves the network endpoint for a container's exposed port.
        ///
        /// Returns the endpoint string associated with `container_id` and `port` when available,
        /// otherwise returns `ContainerError::ContainerNotFound`.
        ///
        /// # Examples
        ///
        /// ```
        /// # use std::sync::Arc;
        /// # async fn doc_example() -> Result<(), Box<dyn std::error::Error>> {
        /// // `bridge` would be an implementation providing `get_endpoint`.
        /// // let endpoint = bridge.get_endpoint("container-123", 8080).await?;
        /// // assert_eq!(endpoint, "127.0.0.1:32768");
        /// # Ok(()) }
        /// ```
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

        /// Stops the container identified by `container_id`, using `timeout_secs` as the shutdown timeout.
        ///
        /// Attempts to stop the container and returns success or a `ContainerError` on failure.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// # async fn run_example<B: crate::backend::ContainerBackend>(backend: &B) -> Result<(), crate::backend::ContainerError> {
        /// backend.stop_container("container-123", 30).await?;
        /// # Ok(())
        /// # }
        /// ```
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

        /// Records a remove operation for the specified container ID with the given `force` flag and returns success.
        ///
        /// # Examples
        ///
        /// ```
        /// # use futures::executor::block_on;
        /// # async fn run_example() {
        /// // `bridge` is an instance providing `remove_container`.
        /// // block_on is used here to run the async call in a synchronous example.
        /// // Replace `bridge` with the actual instance in real code.
        /// // block_on(async { bridge.remove_container("container-id", true).await.unwrap(); });
        /// # }
        /// ```
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

        /// Retrieves cached inspection information for a container by its ID.
        ///
        /// Looks up the container in the bridge's internal inspection map and returns the associated
        /// `ContainerInfo`.
        ///
        /// # Errors
        ///
        /// Returns `ContainerError::ContainerNotFound(container_id)` if no inspection entry exists for
        /// the provided `container_id`.
        ///
        /// # Examples
        ///
        /// ```
        /// # async fn example<B: std::ops::Deref<Target = dyn crate::backend::SecureContainerBridge>>(bridge: &B) {
        /// let res = bridge.inspect("example-container-id").await;
        /// match res {
        ///     Ok(info) => println!("found container with id: {}", info.id),
        ///     Err(crate::backend::ContainerError::ContainerNotFound(id)) => println!("not found: {}", id),
        ///     Err(_) => panic!("unexpected error"),
        /// }
        /// # }
        /// ```
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

        /// Records a request to pull the specified container image.
        ///
        /// This implementation appends a `pull:<image>` entry to the recorder's operations
        /// and reports success.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// # async fn example<B: ?Sized>() {}
        /// // Assuming `backend` implements `pull_image(&str)`:
        /// // backend.pull_image("alpine:latest").await.unwrap();
        /// ```
        async fn pull_image(&self, image: &str) -> Result<(), ContainerError> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("pull:{image}"));
            Ok(())
        }

        /// Retrieve the recorded logs for a given container identifier.
        ///
        /// The `tail` parameter is the requested number of trailing log lines and is recorded for inspection by tests.
        ///
        /// # Returns
        ///
        /// `Ok(String)` with the container's logs, or `Err(ContainerError::ContainerNotFound(_))` if no logs are recorded for `container_id`.
        ///
        /// # Examples
        ///
        /// ```
        /// # // Example usage (bridge must implement an async `logs` method with this signature)
        /// # use futures::executor::block_on;
        /// # async fn _example(bridge: &impl std::ops::Deref) {}
        /// // let output = block_on(bridge.logs("container-id", 100));
        /// ```
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

        /// Performs cleanup for the specified challenge and returns the preconfigured broker cleanup result.
        ///
        /// This implementation records the cleanup operation (appending `cleanup:{challenge_id}` to the
        /// bridge's internal operation log) and returns a clone of the bridge's configured
        /// `BrokerCleanupResult`.
        ///
        /// # Returns
        ///
        /// `Ok(BrokerCleanupResult)` containing the configured cleanup result.
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

        /// Retrieves all containers associated with a challenge.
        ///
        /// Returns the list of container inspection records for the challenge identified by `challenge_id`.
        ///
        /// # Examples
        ///
        /// ```
        /// // assuming `bridge` implements the same trait and is available in scope:
        /// # async fn run_example<B: ?Sized>(bridge: &B) where B: std::marker::Send {
        /// let containers = bridge.list_by_challenge("challenge-123").await.unwrap();
        /// assert!(containers.is_empty() || containers.iter().all(|c| !c.id.is_empty()));
        /// # }
        /// ```
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
        /// Retrieve a snapshot of recorded operation names.
        ///
        /// The returned vector contains the operations in the order they were recorded.
        ///
        /// # Returns
        ///
        /// A `Vec<String>` with the recorded operation names in chronological order.
        ///
        /// # Examples
        ///
        /// ```
        /// // assuming `recorder` is an instance with prior recorded operations
        /// let ops = recorder.operations();
        /// assert!(ops.iter().all(|s| !s.is_empty()));
        /// ```
        fn operations(&self) -> Vec<String> {
            self.inner.operations.lock().unwrap().clone()
        }

        /// Set the running state for a container identifier in the backend's internal registry.
        ///
        /// Updates the internal mapping so subsequent queries will reflect whether the given
        /// container `id` is considered running (`true`) or not (`false`).
        ///
        /// # Parameters
        ///
        /// - `id`: The container identifier to update.
        /// - `running`: `true` if the container is running, `false` otherwise.
        ///
        /// # Examples
        ///
        /// ```rust
        /// // Assume `backend` is an instance providing this method.
        /// // This example is illustrative and marked `ignore` to avoid doctest compilation.
        /// # #[allow(unused)]
        /// # fn example(backend: &impl std::ops::Deref) {}
        /// // Mark container "c1" as running:
        /// // backend.set_running("c1", true);
        /// ```
        fn set_running(&self, id: &str, running: bool) {
            self.inner
                .running
                .lock()
                .unwrap()
                .insert(id.to_string(), running);
        }

        /// Store or replace the logs string associated with a given identifier.
        ///
        /// This acquires a lock on the internal `logs` map and inserts the provided
        /// `logs` value under `id`, replacing any existing entry for that `id`.
        ///
        /// # Examples
        ///
        /// ```
        /// use std::collections::HashMap;
        /// use std::sync::Mutex;
        ///
        /// struct Inner {
        ///     logs: Mutex<HashMap<String, String>>,
        /// }
        ///
        /// struct Recorder {
        ///     inner: Inner,
        /// }
        ///
        /// impl Recorder {
        ///     fn set_logs(&self, id: &str, logs: &str) {
        ///         self.inner
        ///             .logs
        ///             .lock()
        ///             .unwrap()
        ///             .insert(id.to_string(), logs.to_string());
        ///     }
        /// }
        ///
        /// let recorder = Recorder {
        ///     inner: Inner {
        ///         logs: Mutex::new(HashMap::new()),
        ///     },
        /// };
        ///
        /// recorder.set_logs("container-1", "started\nready");
        /// let map = recorder.inner.logs.lock().unwrap();
        /// assert_eq!(map.get("container-1").map(|s| s.as_str()), Some("started\nready"));
        /// ```
        fn set_logs(&self, id: &str, logs: &str) {
            self.inner
                .logs
                .lock()
                .unwrap()
                .insert(id.to_string(), logs.to_string());
        }

        /// Replaces the stored list with the provided `items`.
        ///
        /// Acquires the inner list mutex and sets its contents to `items`.
        /// Panics if the mutex is poisoned.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// // Assuming `obj` has the `set_list` method shown:
        /// // obj.set_list(vec!["one".into(), "two".into()]);
        /// ```
        fn set_list(&self, items: Vec<String>) {
            *self.inner.list.lock().unwrap() = items;
        }

        /// Generate the next challenge instance with a unique container name.
        ///
        /// The returned instance is initialized for the same challenge and image as `config`,
        /// and has a container name of the form `container-<n>` where `<n>` is an incrementing
        /// internal counter. The instance's status is set to `Running`.
        ///
        /// # Examples
        ///
        /// ```
        /// // Shows the container name format produced by this method.
        /// let name = format!("container-{}", 42);
        /// assert_eq!(name, "container-42");
        /// ```
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

    /// Constructs a ChallengeInstance from the provided identifiers, image, and status.
    ///
    /// The returned instance has its `container_id`, `image`, and `status` set from the
    /// corresponding arguments, `endpoint` set to `http://{container_id}`, and `started_at`
    /// set to the current UTC time.
    ///
    /// # Examples
    ///
    /// ```
    /// # use chrono::Utc;
    /// # use crate::types::{ChallengeId, ContainerStatus, ChallengeInstance};
    /// let cid = ChallengeId::new("challenge-1");
    /// let inst = sample_instance(cid, "container-123", "example/image:latest", ContainerStatus::Running);
    /// assert_eq!(inst.container_id, "container-123");
    /// assert_eq!(inst.image, "example/image:latest");
    /// assert_eq!(inst.endpoint, "http://container-123");
    /// assert_eq!(inst.status, ContainerStatus::Running);
    /// ```
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
        /// Records a requested image pull into the recorder for testing purposes.
        ///
        /// This method notes that an image pull was requested by appending `pull:{image}`
        /// to the internal operations log and returns success.
        ///
        /// # Examples
        ///
        /// ```
        /// // In an async context:
        /// // let client = /* a recording client instance */;
        /// // client.pull_image("nginx:latest").await.unwrap();
        /// ```
        async fn pull_image(&self, image: &str) -> anyhow::Result<()> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("pull:{image}"));
            Ok(())
        }

        /// Record a start operation for the given challenge and produce the next challenge instance.
        ///
        /// This test helper appends a `start:<challenge_id>` entry to the internal operations log
        /// and returns a constructed `ChallengeInstance` based on `config`.
        ///
        /// # Parameters
        ///
        /// - `config`: Configuration used to derive the returned `ChallengeInstance`.
        ///
        /// # Returns
        ///
        /// `Ok(ChallengeInstance)` containing the next prepared instance for the provided `config`.
        ///
        /// # Examples
        ///
        /// ```
        /// # use futures::executor::block_on;
        /// # // `bridge` and `cfg` would be prepared test values in real tests.
        /// # let bridge = RecordingSecureBridge::default();
        /// # let cfg = ChallengeContainerConfig { challenge_id: "example".into(), ..Default::default() };
        /// let instance = block_on(bridge.start_challenge(&cfg)).unwrap();
        /// assert_eq!(instance.challenge_id, "example");
        /// ```
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

        /// Stops a container identified by `container_id`.
        ///
        /// This implementation records the stop request (for example, into an internal
        /// operations log) and returns success when the request has been recorded.
        ///
        /// # Examples
        ///
        /// ```
        /// // `backend` is any value with an async `stop_container(&self, &str) -> anyhow::Result<()>` method.
        /// let backend = /* construct backend */ ;
        /// let rt = tokio::runtime::Runtime::new().unwrap();
        /// rt.block_on(async {
        ///     backend.stop_container("container123").await.unwrap();
        /// });
        /// ```
        async fn stop_container(&self, container_id: &str) -> anyhow::Result<()> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("stop:{container_id}"));
            Ok(())
        }

        /// Records the removal of the container identified by `container_id` and succeeds.
        ///
        /// This implementation appends the string `"remove:{container_id}"` to the bridge's recorded operations and returns `Ok(())`.
        ///
        /// # Examples
        ///
        /// ```
        /// # tokio::test
        /// async fn example_record_remove() {
        ///     let bridge = RecordingSecureBridge::default();
        ///     bridge.remove_container("abc123").await.unwrap();
        ///     let ops = bridge.inner.operations.lock().unwrap();
        ///     assert_eq!(ops.last().map(|s| s.as_str()), Some("remove:abc123"));
        /// }
        /// ```
        async fn remove_container(&self, container_id: &str) -> anyhow::Result<()> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push(format!("remove:{container_id}"));
            Ok(())
        }

        /// Checks whether the container with the specified ID is currently running.
        ///
        /// # Examples
        ///
        /// ```
        /// // Call from an async context on a backend implementing the method:
        /// // let running = backend.is_container_running("container-id").await.unwrap();
        /// // assert!(running == true || running == false);
        /// ```
        pub(crate) async fn is_container_running(&self, container_id: &str) -> anyhow::Result<bool>;
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

        /// Retrieve recorded logs for a container and record the logs request in the operation history.
        ///
        /// The method appends a "logs:{container_id}:{tail}" entry to the bridge's operation log and returns
        /// the stored log string for `container_id`. If no logs are recorded for the given container, an
        /// empty string is returned.
        ///
        /// # Parameters
        ///
        /// - `container_id`: Identifier of the container whose logs are requested.
        /// - `tail`: Number of trailing lines requested (recorded for auditing; does not alter returned value
        ///   in the test recording bridge).
        ///
        /// # Returns
        ///
        /// `String` containing the recorded logs for the container, or an empty string if none exist.
        ///
        /// # Examples
        ///
        /// ```
        /// # // Example placeholder: in real usage, `bridge` is an instance that provides `get_logs`.
        /// # async fn example_usage() {
        /// #     // let logs = bridge.get_logs("container-1", 100).await.unwrap();
        /// # }
        /// ```
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

        /// Return the list of container IDs tracked by this backend.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// # async fn example(backend: &impl crate::ChallengeDocker) {
        /// let containers: Vec<String> = backend.list_challenge_containers().await.unwrap();
        /// # }
        /// ```
        async fn list_challenge_containers(&self) -> anyhow::Result<Vec<String>> {
            self.inner
                .operations
                .lock()
                .unwrap()
                .push("list_containers".to_string());
            Ok(self.inner.list.lock().unwrap().clone())
        }

        /// Record a cleanup operation request for stale containers identified by a name prefix.
        ///
        /// This method logs a cleanup intent for containers whose names start with `prefix`.
        ///
        /// # Parameters
        ///
        /// - `prefix`: Container name prefix used to select which containers to consider for cleanup.
        /// - `max_age_minutes`: Maximum age in minutes to consider a container "stale" (unused by this implementation).
        /// - `exclude_patterns`: List of name patterns to exclude from cleanup (unused by this implementation).
        ///
        /// # Returns
        ///
        /// `DockerCleanupResult` summarizing the outcome; currently always the default result (no removals).
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