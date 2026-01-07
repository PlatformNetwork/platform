//! Challenge Orchestrator
//!
//! Manages Docker containers for challenges. Provides:
//! - Container lifecycle (start, stop, update)
//! - Health monitoring
//! - Evaluation routing
//! - Hot-swap without core restart
//!
//! ## Backend Selection (Secure by Default)
//!
//! The orchestrator uses the **secure broker by default** in production.
//! Direct Docker is ONLY used when explicitly in development mode.
//!
//! Priority order:
//! 1. `DEVELOPMENT_MODE=true` -> Direct Docker (local dev only)
//! 2. Broker socket exists -> Secure broker (production default)
//! 3. No broker + not dev mode -> Fallback to Docker with warnings
//!
//! Default broker socket: `/var/run/platform/broker.sock`

pub mod backend;
pub mod config;
pub mod docker;
pub mod evaluator;
pub mod health;
pub mod lifecycle;

pub use backend::{
    create_backend, is_development_mode, is_secure_mode, ContainerBackend, DirectDockerBackend,
    SecureBackend, DEFAULT_BROKER_SOCKET,
};
pub use config::*;
pub use docker::{ChallengeDocker, CleanupResult, DockerClient};
pub use evaluator::*;
pub use health::*;
pub use lifecycle::*;
use parking_lot::RwLock;
use platform_core::ChallengeId;
use std::collections::HashMap;
use std::sync::Arc;

/// Main orchestrator managing all challenge containers
#[allow(dead_code)]
pub struct ChallengeOrchestrator {
    docker: Arc<dyn ChallengeDocker>,
    challenges: Arc<RwLock<HashMap<ChallengeId, ChallengeInstance>>>,
    health_monitor: HealthMonitor,
    config: OrchestratorConfig,
}

/// Default network name for Platform containers
pub const PLATFORM_NETWORK: &str = "platform-network";

impl ChallengeOrchestrator {
    /// Creates and initializes a new ChallengeOrchestrator from the provided configuration.
    ///
    /// In tests, if a test Docker client has been injected, that client will be used instead of
    /// auto-detecting the host Docker environment. Otherwise the function auto-detects a Docker
    /// client, ensures the platform network is available, and bootstraps the orchestrator.
    ///
    /// # Examples
    ///
    /// ```
    /// # tokio_test::block_on(async {
    /// let config = OrchestratorConfig::default();
    /// let orch = crate::ChallengeOrchestrator::new(config).await.unwrap();
    /// assert!(orch.list_challenges().is_empty());
    /// # });
    /// ```
    pub async fn new(config: OrchestratorConfig) -> anyhow::Result<Self> {
        #[cfg(test)]
        if let Some(docker) = Self::take_test_docker_client() {
            return Self::bootstrap_with_docker(docker, config).await;
        }

        // Auto-detect the network from the validator container
        // This ensures challenge containers are on the same network as the validator
        let docker = DockerClient::connect_auto_detect().await?;

        Self::bootstrap_with_docker(docker, config).await
    }

    /// Initializes a ChallengeOrchestrator using the provided Docker client and configuration.
    ///
    /// Ensures the platform network exists and attempts to connect the validator container to that
    /// network (a failure to connect is logged as a warning), then constructs and returns an
    /// orchestrator that uses the given Docker client.
    ///
    /// # Returns
    ///
    /// A configured `ChallengeOrchestrator` on success.
    ///
    /// # Examples
    ///
    /// ```
    /// # async fn example(docker: crate::docker::DockerClient, config: crate::config::OrchestratorConfig) -> anyhow::Result<()> {
    /// let orchestrator = crate::orchestrator::bootstrap_with_docker(docker, config).await?;
    /// // use `orchestrator`...
    /// # Ok(()) }
    /// ```
    async fn bootstrap_with_docker(
        docker: DockerClient,
        config: OrchestratorConfig,
    ) -> anyhow::Result<Self> {
        // Ensure the detected network exists (creates it if running outside Docker)
        docker.ensure_network().await?;

        // Connect the validator container to the platform network
        // This allows the validator to communicate with challenge containers by hostname
        if let Err(e) = docker.connect_self_to_network().await {
            tracing::warn!("Could not connect validator to platform network: {}", e);
        }

        Self::with_docker(docker, config).await
    }

    #[cfg(test)]
    fn test_docker_client_slot() -> &'static std::sync::Mutex<Option<DockerClient>> {
        use std::sync::{Mutex, OnceLock};
        static SLOT: OnceLock<Mutex<Option<DockerClient>>> = OnceLock::new();
        SLOT.get_or_init(|| Mutex::new(None))
    }

    /// Removes and returns the test Docker client stored in the global test slot.
    ///
    /// The stored client is taken (removed) from the slot so subsequent calls will return `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// // set_test_docker_client is available in the test-only API
    /// let client = DockerClient::new_for_testing();
    /// set_test_docker_client(client);
    /// assert!(take_test_docker_client().is_some());
    /// assert!(take_test_docker_client().is_none());
    /// ```
    #[cfg(test)]
    fn take_test_docker_client() -> Option<DockerClient> {
        Self::test_docker_client_slot().lock().unwrap().take()
    }

    #[cfg(test)]
    pub(crate) fn set_test_docker_client(docker: DockerClient) {
        Self::test_docker_client_slot()
            .lock()
            .unwrap()
            .replace(docker);
    }

    /// Creates a ChallengeOrchestrator that uses the provided Docker implementation.
    ///
    /// The returned orchestrator is initialized with an empty challenge registry and a
    /// HealthMonitor configured from `config`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use platform::orchestrator::{with_docker, OrchestratorConfig};
    /// # use platform::docker::TestDocker;
    /// # tokio_test::block_on(async {
    /// let config = OrchestratorConfig::default();
    /// let docker = TestDocker::new();
    /// let orchestrator = with_docker(docker, config).await.unwrap();
    /// # });
    /// ```
    ///
    /// A ChallengeOrchestrator on success.
    pub async fn with_docker(
        docker: impl ChallengeDocker + 'static,
        config: OrchestratorConfig,
    ) -> anyhow::Result<Self> {
        let docker = Arc::new(docker);
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let health_monitor = HealthMonitor::new(challenges.clone(), config.health_check_interval);

        Ok(Self {
            docker,
            challenges,
            health_monitor,
            config,
        })
    }

    /// Start the orchestrator (health monitoring loop)
    pub async fn start(&self) -> anyhow::Result<()> {
        self.health_monitor.start().await
    }

    /// Add and start a new challenge
    pub async fn add_challenge(&self, config: ChallengeContainerConfig) -> anyhow::Result<()> {
        // Pull image first to ensure it's available
        tracing::info!(
            image = %config.docker_image,
            challenge = %config.name,
            "Pulling Docker image before starting challenge"
        );
        self.docker.pull_image(&config.docker_image).await?;

        let instance = self.docker.start_challenge(&config).await?;
        self.challenges
            .write()
            .insert(config.challenge_id, instance);
        tracing::info!(challenge_id = %config.challenge_id, "Challenge container started");
        Ok(())
    }

    /// Refresh a challenge (re-pull image and restart container)
    pub async fn refresh_challenge(&self, challenge_id: ChallengeId) -> anyhow::Result<()> {
        // Get current config
        let instance = self
            .challenges
            .read()
            .get(&challenge_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Challenge not found: {}", challenge_id))?;

        tracing::info!(
            challenge_id = %challenge_id,
            image = %instance.image,
            "Refreshing challenge (re-pulling image and restarting)"
        );

        // Stop current container
        self.docker.stop_container(&instance.container_id).await?;

        // Re-pull the image (force fresh pull)
        self.docker.pull_image(&instance.image).await?;

        // We need the full config to restart - get it from state or recreate
        // For now, create a minimal config from the instance
        let config = ChallengeContainerConfig {
            challenge_id,
            name: format!("challenge-{}", challenge_id),
            docker_image: instance.image.clone(),
            mechanism_id: 0, // Default, should be stored
            emission_weight: 1.0,
            timeout_secs: 3600,
            cpu_cores: 2.0,
            memory_mb: 4096,
            gpu_required: false,
        };

        // Start new container
        let new_instance = self.docker.start_challenge(&config).await?;
        self.challenges.write().insert(challenge_id, new_instance);

        tracing::info!(challenge_id = %challenge_id, "Challenge refreshed successfully");
        Ok(())
    }

    /// Refresh all challenges (re-pull images and restart all containers)
    pub async fn refresh_all_challenges(&self) -> anyhow::Result<()> {
        let challenge_ids: Vec<ChallengeId> = self.challenges.read().keys().cloned().collect();

        tracing::info!(count = challenge_ids.len(), "Refreshing all challenges");

        for id in challenge_ids {
            if let Err(e) = self.refresh_challenge(id).await {
                tracing::error!(challenge_id = %id, error = %e, "Failed to refresh challenge");
            }
        }

        Ok(())
    }

    /// Update a challenge (pull new image, restart container)
    pub async fn update_challenge(&self, config: ChallengeContainerConfig) -> anyhow::Result<()> {
        // Stop old container if exists - get container_id first to avoid holding lock across await
        let old_container_id = {
            self.challenges
                .read()
                .get(&config.challenge_id)
                .map(|i| i.container_id.clone())
        };
        if let Some(container_id) = old_container_id {
            self.docker.stop_container(&container_id).await?;
        }

        // Pull new image and start
        self.docker.pull_image(&config.docker_image).await?;
        let instance = self.docker.start_challenge(&config).await?;
        self.challenges
            .write()
            .insert(config.challenge_id, instance);

        tracing::info!(
            challenge_id = %config.challenge_id,
            image = %config.docker_image,
            "Challenge container updated"
        );
        Ok(())
    }

    /// Remove a challenge
    pub async fn remove_challenge(&self, challenge_id: ChallengeId) -> anyhow::Result<()> {
        // Get container_id and remove from map first to avoid holding lock across await
        let container_id = self
            .challenges
            .write()
            .remove(&challenge_id)
            .map(|i| i.container_id);
        if let Some(container_id) = container_id {
            self.docker.stop_container(&container_id).await?;
            self.docker.remove_container(&container_id).await?;
            tracing::info!(challenge_id = %challenge_id, "Challenge container removed");
        }
        Ok(())
    }

    /// Get evaluator for running evaluations
    pub fn evaluator(&self) -> ChallengeEvaluator {
        ChallengeEvaluator::new(self.challenges.clone())
    }

    /// List active challenges
    pub fn list_challenges(&self) -> Vec<ChallengeId> {
        self.challenges.read().keys().cloned().collect()
    }

    /// Get challenge instance info
    pub fn get_challenge(&self, id: &ChallengeId) -> Option<ChallengeInstance> {
        self.challenges.read().get(id).cloned()
    }

    /// Sync challenges with network state
    pub async fn sync_challenges(
        &self,
        configs: &[ChallengeContainerConfig],
    ) -> anyhow::Result<()> {
        let current_ids: std::collections::HashSet<_> =
            self.challenges.read().keys().cloned().collect();
        let target_ids: std::collections::HashSet<_> =
            configs.iter().map(|c| c.challenge_id).collect();

        // Remove challenges not in target
        for id in current_ids.difference(&target_ids) {
            self.remove_challenge(*id).await?;
        }

        // Add/update challenges
        for config in configs {
            let needs_update = self
                .challenges
                .read()
                .get(&config.challenge_id)
                .map(|i| i.image != config.docker_image)
                .unwrap_or(true);

            if needs_update {
                self.update_challenge(config.clone()).await?;
            }
        }

        Ok(())
    }

    /// Clean up stale task containers from challenge evaluations
    ///
    /// This removes containers that match the pattern but excludes:
    /// - Main challenge containers (challenge-*)
    /// - Platform validator/watchtower containers
    ///
    /// Called periodically to prevent Docker from accumulating orphaned containers.
    pub async fn cleanup_stale_task_containers(&self) -> anyhow::Result<CleanupResult> {
        // Clean up term-challenge task containers older than 2 hours
        // Exclude:
        // - challenge-* (main challenge containers managed by orchestrator)
        // - platform-* (validator, watchtower)
        let result = self
            .docker
            .cleanup_stale_containers(
                "term-challenge-",
                120, // 2 hours old
                &["challenge-term-challenge", "platform-"],
            )
            .await?;

        Ok(result)
    }

    /// Access the orchestrator's Docker client for direct container operations.
    ///
    /// # Examples
    ///
    /// ```
    /// // Obtain an orchestrator instance, then get a reference to its Docker client:
    /// // let orchestrator = /* ChallengeOrchestrator::with_docker(...) or other constructor */;
    /// // let client = orchestrator.docker();
    /// ```
    pub fn docker(&self) -> &dyn ChallengeDocker {
        self.docker.as_ref()
    }
}

/// Running challenge instance
#[derive(Clone, Debug)]
pub struct ChallengeInstance {
    pub challenge_id: ChallengeId,
    pub container_id: String,
    pub image: String,
    pub endpoint: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub status: ContainerStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ContainerStatus {
    Starting,
    Running,
    Unhealthy,
    Stopped,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::DockerBridge;
    use async_trait::async_trait;
    use bollard::container::{
        Config, CreateContainerOptions, InspectContainerOptions, ListContainersOptions, LogOutput,
        LogsOptions, RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
    };
    use bollard::errors::Error as DockerError;
    use bollard::image::CreateImageOptions;
    use bollard::models::{
        ContainerCreateResponse, ContainerInspectResponse, ContainerSummary, CreateImageInfo,
        EndpointSettings, Network, NetworkSettings,
    };
    use bollard::network::{ConnectNetworkOptions, CreateNetworkOptions, ListNetworksOptions};
    use bollard::volume::CreateVolumeOptions;
    use chrono::Utc;
    use futures::{stream, Stream};
    use platform_core::ChallengeId;
    use std::collections::HashMap;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct TestDocker {
        inner: Arc<TestDockerInner>,
    }

    struct TestDockerInner {
        operations: Mutex<Vec<String>>,
        cleanup_result: Mutex<CleanupResult>,
        cleanup_calls: Mutex<Vec<(String, u64, Vec<String>)>>,
        next_container_id: AtomicUsize,
    }

    impl Default for TestDockerInner {
        /// Creates a default test Docker client with empty recorded operations, a default cleanup result,
        /// no recorded cleanup calls, and the next container id initialized to 1.
        ///
        /// # Examples
        ///
        /// ```
        /// let _client = TestDocker::default();
        /// ```
        fn default() -> Self {
            Self {
                operations: Mutex::new(Vec::new()),
                cleanup_result: Mutex::new(CleanupResult::default()),
                cleanup_calls: Mutex::new(Vec::new()),
                next_container_id: AtomicUsize::new(1),
            }
        }
    }

    impl TestDocker {
        /// Appends an operation entry to the internal operations log.
        ///
        /// The provided `entry` is converted into a `String` and pushed onto the internal
        /// operations vector protected by a mutex.
        ///
        /// # Examples
        ///
        /// ```
        /// recorder.record("pull:image");
        /// ```
        fn record(&self, entry: impl Into<String>) {
            self.inner.operations.lock().unwrap().push(entry.into());
        }

        /// Retrieve the recorded operations log.
        ///
        /// Returns a cloned list of operation entries (each entry is a `String`) in the order they were recorded.
        ///
        /// # Examples
        ///
        /// ```
        /// // `mock` is an instance with an internal operations log.
        /// let ops: Vec<String> = mock.operations();
        /// // inspect or assert on recorded operations
        /// assert!(ops.iter().all(|s| !s.is_empty()));
        /// ```
        fn operations(&self) -> Vec<String> {
            self.inner.operations.lock().unwrap().clone()
        }

        /// Update the stored cleanup result used by the orchestrator.
        ///
        /// The provided `result` replaces the current cached `CleanupResult`
        /// held inside the orchestrator's internal state.
        ///
        /// # Examples
        ///
        /// ```
        /// // Replace the cached cleanup result with a new value.
        /// orchestrator.set_cleanup_result(result);
        /// ```
        fn set_cleanup_result(&self, result: CleanupResult) {
            *self.inner.cleanup_result.lock().unwrap() = result;
        }

        /// Returns the recorded cleanup calls made to the component.
        ///
        /// The returned vector contains tuples in the form `(prefix, max_age_minutes, exclusions)`,
        /// where `prefix` is the container name prefix used for cleanup, `max_age_minutes` is the
        /// maximum age (in minutes) used to select stale containers, and `exclusions` lists
        /// container name substrings to exclude from cleanup.
        ///
        /// # Examples
        ///
        /// ```
        /// // `orchestrator` is a test instance that records cleanup calls.
        /// let calls = orchestrator.cleanup_calls();
        /// // Each element is (prefix, max_age_minutes, exclusions)
        /// for (prefix, age, excludes) in calls {
        ///     println!("prefix={} age={} excludes={:?}", prefix, age, excludes);
        /// }
        /// ```
        fn cleanup_calls(&self) -> Vec<(String, u64, Vec<String>)> {
            self.inner.cleanup_calls.lock().unwrap().clone()
        }

        /// Creates a synthetic ChallengeInstance for testing based on the given container configuration.
        ///
        /// The returned instance uses the config's `challenge_id` and `docker_image`. The `container_id`
        /// and `endpoint` include an incrementing index to ensure uniqueness; `started_at` is set to the
        /// current UTC time and `status` is `Running`.
        ///
        /// # Examples
        ///
        /// ```
        /// // Construct a minimal config with the fields required by `next_instance`.
        /// // Adjust field names as needed to match the real `ChallengeContainerConfig` in tests.
        /// let config = ChallengeContainerConfig {
        ///     challenge_id: "test-chal".into(),
        ///     docker_image: "example/image:latest".to_string(),
        ///     ..Default::default()
        /// };
        /// let td = TestDocker::default();
        /// let inst = td.next_instance(&config);
        /// assert!(inst.container_id.starts_with("container-test-chal-"));
        /// assert_eq!(inst.image, "example/image:latest");
        /// assert_eq!(inst.status, ContainerStatus::Running);
        /// ```
        fn next_instance(&self, config: &ChallengeContainerConfig) -> ChallengeInstance {
            let idx = self.inner.next_container_id.fetch_add(1, Ordering::SeqCst);
            let id_str = config.challenge_id.to_string();
            ChallengeInstance {
                challenge_id: config.challenge_id,
                container_id: format!("container-{id_str}-{idx}"),
                image: config.docker_image.clone(),
                endpoint: format!("http://{id_str}:{idx}"),
                started_at: Utc::now(),
                status: ContainerStatus::Running,
            }
        }
    }

    #[async_trait]
    impl ChallengeDocker for TestDocker {
        /// Pulls the specified Docker image and records the pull operation.
        ///
        /// The method records a "pull:<image>" operation and returns `Ok(())` on success.
        ///
        /// # Examples
        ///
        /// ```
        /// // Given a Docker client `client` that implements `pull_image`,
        /// // the simplest usage is:
        /// # async fn example(client: &impl std::ops::Deref<Target = dyn std::any::Any>) {}
        /// // client.pull_image("alpine:latest").await.unwrap();
        /// ```
        async fn pull_image(&self, image: &str) -> anyhow::Result<()> {
            self.record(format!("pull:{image}"));
            Ok(())
        }

        /// Starts a challenge container from the given container configuration and returns the resulting instance.
        ///
        /// # Examples
        ///
        /// ```
        /// // Given a Docker-like client `docker` and a `config` for a challenge:
        /// let instance = tokio_test::block_on(async { docker.start_challenge(&config).await.unwrap() });
        /// assert_eq!(instance.challenge_id, config.challenge_id);
        /// ```
        async fn start_challenge(
            &self,
            config: &ChallengeContainerConfig,
        ) -> anyhow::Result<ChallengeInstance> {
            self.record(format!("start:{}", config.challenge_id));
            Ok(self.next_instance(config))
        }

        /// Stop the container identified by `container_id`.
        ///
        /// Records the stop operation for the target container and attempts to stop it via the Docker backend.
        ///
        /// # Parameters
        ///
        /// - `container_id`: Identifier of the container to stop.
        ///
        /// # Returns
        ///
        /// `Ok(())` if the stop operation was recorded and completed successfully, `Err` if stopping the container failed.
        ///
        /// # Examples
        ///
        /// ```
        /// # async fn example(client: &impl crate::docker::ChallengeDocker) {
        /// client.stop_container("container-id").await.unwrap();
        /// # }
        /// ```
        async fn stop_container(&self, container_id: &str) -> anyhow::Result<()> {
            self.record(format!("stop:{container_id}"));
            Ok(())
        }

        /// Record that a container removal was requested for the given container id.
        ///
        /// This mock implementation appends the operation string `remove:<container_id>` to the
        /// test operation log so tests can assert that a removal was attempted.
        ///
        /// # Examples
        ///
        /// ```
        /// // assuming `td` is a test docker instance with an `operations: Mutex<Vec<String>>`
        /// td.remove_container("abc123").await.unwrap();
        /// assert_eq!(td.operations.lock().unwrap().last().unwrap(), "remove:abc123");
        /// ```
        async fn remove_container(&self, container_id: &str) -> anyhow::Result<()> {
            self.record(format!("remove:{container_id}"));
            Ok(())
        }

        /// Check whether a container with the given ID is running.
        ///
        /// # Arguments
        ///
        /// * `container_id` - The identifier of the container to query.
        ///
        /// # Returns
        ///
        /// `true` if the container is running, `false` otherwise.
        ///
        /// # Examples
        ///
        /// ```ignore
        /// let running = orchestrator.is_container_running("container-123").await.unwrap();
        /// ```
        async fn is_container_running(&self, container_id: &str) -> anyhow::Result<bool> {
            self.record(format!("is_running:{container_id}"));
            Ok(true)
        }

        /// Fetches the logs for the specified container and returns the last `tail` lines as a string.
        ///
        /// The `tail` parameter limits the returned content to the most-recent `tail` lines of the container log.
        ///
        /// # Examples
        ///
        /// ```
        /// # async fn example_usage() {
        /// // `client` is an instance that exposes `get_logs(&self, container_id: &str, tail: usize)`.
        /// let logs = client.get_logs("container-123", 50).await.unwrap();
        /// assert!(logs.contains("logs-container-123"));
        /// # }
        /// ```
        async fn get_logs(&self, container_id: &str, tail: usize) -> anyhow::Result<String> {
            self.record(format!("logs:{container_id}:{tail}"));
            Ok(format!("logs-{container_id}"))
        }

        /// List IDs of current challenge containers.
        ///
        /// # Examples
        ///
        /// ```rust
        /// # async fn example() {
        /// let docker = TestDocker::new();
        /// let ids = docker.list_challenge_containers().await.unwrap();
        /// assert!(ids.is_empty());
        /// # }
        /// ```
        async fn list_challenge_containers(&self) -> anyhow::Result<Vec<String>> {
            self.record("list_containers".to_string());
            Ok(Vec::new())
        }

        async fn cleanup_stale_containers(
            &self,
            prefix: &str,
            max_age_minutes: u64,
            exclude_patterns: &[&str],
        ) -> anyhow::Result<CleanupResult> {
            self.record(format!("cleanup:{prefix}:{max_age_minutes}"));
            self.inner.cleanup_calls.lock().unwrap().push((
                prefix.to_string(),
                max_age_minutes,
                exclude_patterns.iter().map(|s| s.to_string()).collect(),
            ));
            Ok(self.inner.cleanup_result.lock().unwrap().clone())
        }
    }

    /// Creates a `ChallengeContainerConfig` for the given challenge ID and Docker image using sensible defaults.
    ///
    /// The returned config sets the challenge name to `challenge-{challenge_id}`, uses the provided image,
    /// and applies default resource and runtime settings (mechanism_id 0, emission_weight 1.0, 300s timeout,
    /// 1.0 CPU core, 512 MB memory, no GPU).
    ///
    /// # Examples
    ///
    /// ```
    /// // Construct a config for a challenge (assumes `ChallengeId` implements `From<&str>`).
    /// let id = ChallengeId::from("challenge-1");
    /// let cfg = sample_config_with_id(id, "repo.example/challenge:latest");
    /// assert_eq!(cfg.docker_image, "repo.example/challenge:latest");
    /// ```
    fn sample_config_with_id(challenge_id: ChallengeId, image: &str) -> ChallengeContainerConfig {
        let id_str = challenge_id.to_string();
        ChallengeContainerConfig {
            challenge_id,
            name: format!("challenge-{id_str}"),
            docker_image: image.to_string(),
            mechanism_id: 0,
            emission_weight: 1.0,
            timeout_secs: 300,
            cpu_cores: 1.0,
            memory_mb: 512,
            gpu_required: false,
        }
    }

    /// Creates a ChallengeContainerConfig for the given image using a newly generated ChallengeId.
    ///
    /// The returned config is populated for the provided Docker image and uses a freshly generated
    /// ChallengeId produced by `ChallengeId::new()`.
    ///
    /// # Examples
    ///
    /// ```
    /// let cfg = sample_config("example/image:latest");
    /// assert_eq!(cfg.docker_image, "example/image:latest");
    /// ```
    fn sample_config(image: &str) -> ChallengeContainerConfig {
        sample_config_with_id(ChallengeId::new(), image)
    }

    /// Create a ChallengeOrchestrator backed by the provided test Docker implementation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::tests::TestDocker;
    /// # use crate::orchestrator::orchestrator_with_mock;
    /// #[tokio::test]
    /// async fn create_orchestrator_with_test_docker() {
    ///     let docker = TestDocker::default();
    ///     let orch = orchestrator_with_mock(docker).await;
    ///     assert!(orch.list_challenges().is_empty());
    /// }
    /// ```
    async fn orchestrator_with_mock(docker: TestDocker) -> ChallengeOrchestrator {
        ChallengeOrchestrator::with_docker(docker, OrchestratorConfig::default())
            .await
            .expect("build orchestrator")
    }

    #[tokio::test]
    async fn test_add_challenge_registers_instance() {
        let docker = TestDocker::default();
        let orchestrator = orchestrator_with_mock(docker.clone()).await;
        let config = sample_config("ghcr.io/platformnetwork/challenge:v1");
        let challenge_id = config.challenge_id;

        orchestrator
            .add_challenge(config.clone())
            .await
            .expect("add challenge");

        let stored = orchestrator
            .get_challenge(&challenge_id)
            .expect("challenge stored");
        assert_eq!(stored.image, config.docker_image);
        assert_eq!(orchestrator.list_challenges(), vec![challenge_id]);

        let ops = docker.operations();
        assert!(ops.contains(&format!("pull:{}", config.docker_image)));
        assert!(ops.contains(&format!("start:{}", challenge_id)));
    }

    #[tokio::test]
    async fn test_update_challenge_restarts_with_new_image() {
        let docker = TestDocker::default();
        let orchestrator = orchestrator_with_mock(docker.clone()).await;
        let mut config = sample_config("ghcr.io/platformnetwork/challenge:v1");
        let challenge_id = config.challenge_id;

        orchestrator
            .add_challenge(config.clone())
            .await
            .expect("initial add");
        let initial_instance = orchestrator
            .get_challenge(&challenge_id)
            .expect("initial instance");

        config.docker_image = "ghcr.io/platformnetwork/challenge:v2".into();
        orchestrator
            .update_challenge(config.clone())
            .await
            .expect("update succeeds");

        let updated = orchestrator
            .get_challenge(&challenge_id)
            .expect("updated instance");
        assert_eq!(updated.image, config.docker_image);
        assert_ne!(updated.container_id, initial_instance.container_id);

        let ops = docker.operations();
        assert!(ops
            .iter()
            .any(|op| op == &format!("stop:{}", initial_instance.container_id)));
        assert!(ops
            .iter()
            .any(|op| op == &format!("pull:{}", config.docker_image)));
    }

    #[tokio::test]
    async fn test_remove_challenge_stops_and_removes_container() {
        let docker = TestDocker::default();
        let orchestrator = orchestrator_with_mock(docker.clone()).await;
        let config = sample_config("ghcr.io/platformnetwork/challenge:remove");
        let challenge_id = config.challenge_id;

        orchestrator
            .add_challenge(config)
            .await
            .expect("added challenge");
        let container_id = orchestrator
            .get_challenge(&challenge_id)
            .unwrap()
            .container_id;

        orchestrator
            .remove_challenge(challenge_id)
            .await
            .expect("removed challenge");
        assert!(orchestrator.get_challenge(&challenge_id).is_none());

        let ops = docker.operations();
        assert!(ops.contains(&format!("stop:{container_id}")));
        assert!(ops.contains(&format!("remove:{container_id}")));
    }

    #[tokio::test]
    async fn test_refresh_challenge_repulls_image() {
        let docker = TestDocker::default();
        let orchestrator = orchestrator_with_mock(docker.clone()).await;
        let config = sample_config("ghcr.io/platformnetwork/challenge:refresh");
        let challenge_id = config.challenge_id;

        orchestrator
            .add_challenge(config.clone())
            .await
            .expect("added challenge");
        let initial = orchestrator
            .get_challenge(&challenge_id)
            .expect("initial instance");

        orchestrator
            .refresh_challenge(challenge_id)
            .await
            .expect("refresh succeeds");
        let refreshed = orchestrator
            .get_challenge(&challenge_id)
            .expect("refreshed instance");

        assert_eq!(refreshed.image, initial.image);
        assert_ne!(refreshed.container_id, initial.container_id);

        let ops = docker.operations();
        let pull_count = ops
            .iter()
            .filter(|op| *op == &format!("pull:{}", initial.image))
            .count();
        assert_eq!(pull_count, 2, "pull once for add, once for refresh");
    }

    #[tokio::test]
    async fn test_sync_challenges_handles_all_paths() {
        let docker = TestDocker::default();
        let orchestrator = orchestrator_with_mock(docker.clone()).await;
        let update_config = sample_config("ghcr.io/platformnetwork/challenge:update-v1");
        let remove_config = sample_config("ghcr.io/platformnetwork/challenge:remove-v1");
        let update_id = update_config.challenge_id;
        let remove_id = remove_config.challenge_id;

        orchestrator
            .add_challenge(update_config.clone())
            .await
            .expect("added update target");
        orchestrator
            .add_challenge(remove_config.clone())
            .await
            .expect("added removal target");

        let remove_container_id = orchestrator.get_challenge(&remove_id).unwrap().container_id;

        let new_id = ChallengeId::new();
        let desired = vec![
            sample_config_with_id(update_id, "ghcr.io/platformnetwork/challenge:update-v2"),
            sample_config_with_id(new_id, "ghcr.io/platformnetwork/challenge:new"),
        ];

        orchestrator
            .sync_challenges(&desired)
            .await
            .expect("sync succeeds");

        let ids = orchestrator.list_challenges();
        assert!(ids.contains(&update_id));
        assert!(ids.contains(&new_id));
        assert!(!ids.contains(&remove_id));

        let ops = docker.operations();
        assert!(ops.contains(&format!("stop:{remove_container_id}")));
        assert!(ops.contains(&format!("remove:{remove_container_id}")));
        assert!(ops
            .iter()
            .any(|op| op == &"pull:ghcr.io/platformnetwork/challenge:update-v2".to_string()));
        assert!(ops
            .iter()
            .any(|op| op == &"pull:ghcr.io/platformnetwork/challenge:new".to_string()));
    }

    #[tokio::test]
    async fn test_cleanup_stale_task_containers_propagates_result() {
        let docker = TestDocker::default();
        docker.set_cleanup_result(CleanupResult {
            total_found: 3,
            removed: 2,
            errors: vec!["dang".into()],
        });
        let orchestrator = orchestrator_with_mock(docker.clone()).await;

        let result = orchestrator
            .cleanup_stale_task_containers()
            .await
            .expect("cleanup ok");
        assert_eq!(result.total_found, 3);
        assert_eq!(result.removed, 2);
        assert_eq!(result.errors, vec!["dang".to_string()]);

        let calls = docker.cleanup_calls();
        assert_eq!(calls.len(), 1);
        let (prefix, max_age, excludes) = &calls[0];
        assert_eq!(prefix, "term-challenge-");
        assert_eq!(*max_age, 120);
        let expected: Vec<String> = vec![
            "challenge-term-challenge".to_string(),
            "platform-".to_string(),
        ];
        assert_eq!(excludes, &expected);
    }

    #[tokio::test]
    async fn test_refresh_all_challenges_refreshes_each_container() {
        let docker = TestDocker::default();
        let orchestrator = orchestrator_with_mock(docker.clone()).await;
        let config_a = sample_config("ghcr.io/platformnetwork/challenge:refresh-a");
        let config_b = sample_config("ghcr.io/platformnetwork/challenge:refresh-b");
        let id_a = config_a.challenge_id;
        let id_b = config_b.challenge_id;

        orchestrator
            .add_challenge(config_a.clone())
            .await
            .expect("added first challenge");
        orchestrator
            .add_challenge(config_b.clone())
            .await
            .expect("added second challenge");

        let first_initial = orchestrator
            .get_challenge(&id_a)
            .expect("first challenge present")
            .container_id;
        let second_initial = orchestrator
            .get_challenge(&id_b)
            .expect("second challenge present")
            .container_id;

        orchestrator
            .refresh_all_challenges()
            .await
            .expect("refresh all succeeds");

        let first_refreshed = orchestrator
            .get_challenge(&id_a)
            .expect("first challenge refreshed")
            .container_id;
        let second_refreshed = orchestrator
            .get_challenge(&id_b)
            .expect("second challenge refreshed")
            .container_id;

        assert_ne!(first_initial, first_refreshed);
        assert_ne!(second_initial, second_refreshed);

        let ops = docker.operations();
        assert!(ops.contains(&format!("stop:{first_initial}")));
        assert!(ops.contains(&format!("stop:{second_initial}")));
    }

    #[tokio::test]
    async fn test_start_launches_health_monitor() {
        let orchestrator = orchestrator_with_mock(TestDocker::default()).await;
        orchestrator
            .start()
            .await
            .expect("health monitor start succeeds");
    }

    #[tokio::test]
    async fn test_evaluator_method_returns_shared_state() {
        let docker = TestDocker::default();
        let orchestrator = orchestrator_with_mock(docker).await;
        let config = sample_config("ghcr.io/platformnetwork/challenge:evaluator");
        let challenge_id = config.challenge_id;

        orchestrator
            .add_challenge(config)
            .await
            .expect("challenge added");

        let evaluator = orchestrator.evaluator();
        let ids: Vec<_> = evaluator
            .list_challenges()
            .into_iter()
            .map(|status| status.challenge_id)
            .collect();

        assert_eq!(ids, vec![challenge_id]);
    }

    #[tokio::test]
    async fn test_docker_method_exposes_underlying_client() {
        let docker = TestDocker::default();
        let orchestrator = orchestrator_with_mock(docker.clone()).await;

        orchestrator
            .docker()
            .list_challenge_containers()
            .await
            .expect("list call succeeds");

        let ops = docker.operations();
        assert!(ops.contains(&"list_containers".to_string()));
    }

    /// Ensures `ChallengeOrchestrator::new` picks up a test Docker client injected via `set_test_docker_client`.
    ///
    /// This test verifies that when a test Docker client is provided through the orchestrator's test slot,
    /// constructing a new orchestrator uses that client to create and connect the platform network.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::env;
    /// # use crate::{ChallengeOrchestrator, OrchestratorConfig, PLATFORM_NETWORK};
    /// # use crate::tests::{TestDockerBridge, DockerClient};
    /// let bridge = TestDockerBridge::default();
    /// let docker = DockerClient::with_bridge(bridge.clone(), PLATFORM_NETWORK);
    /// ChallengeOrchestrator::set_test_docker_client(docker);
    ///
    /// let original_hostname = env::var("HOSTNAME").ok();
    /// env::set_var("HOSTNAME", "abcdef123456");
    ///
    /// let orchestrator = ChallengeOrchestrator::new(OrchestratorConfig::default())
    ///     .await
    ///     .expect("constructed orchestrator");
    /// assert_eq!(bridge.created_networks(), vec![PLATFORM_NETWORK.to_string()]);
    /// assert!(bridge
    ///     .connected_networks()
    ///     .iter()
    ///     .any(|name| name == PLATFORM_NETWORK));
    ///
    /// drop(orchestrator);
    ///
    /// if let Some(value) = original_hostname {
    ///     env::set_var("HOSTNAME", value);
    /// } else {
    ///     env::remove_var("HOSTNAME");
    /// }
    /// ```
    #[tokio::test]
    async fn test_new_uses_injected_docker_client() {
        let bridge = TestDockerBridge::default();
        let docker = DockerClient::with_bridge(bridge.clone(), PLATFORM_NETWORK);
        ChallengeOrchestrator::set_test_docker_client(docker);

        let original_hostname = std::env::var("HOSTNAME").ok();
        std::env::set_var("HOSTNAME", "abcdef123456");

        let orchestrator = ChallengeOrchestrator::new(OrchestratorConfig::default())
            .await
            .expect("constructed orchestrator");
        assert_eq!(
            bridge.created_networks(),
            vec![PLATFORM_NETWORK.to_string()]
        );
        assert!(bridge
            .connected_networks()
            .iter()
            .any(|name| name == PLATFORM_NETWORK));

        drop(orchestrator);

        if let Some(value) = original_hostname {
            std::env::set_var("HOSTNAME", value);
        } else {
            std::env::remove_var("HOSTNAME");
        }
    }

    #[derive(Clone, Default)]
    struct TestDockerBridge {
        inner: Arc<TestDockerBridgeInner>,
    }

    #[derive(Default)]
    struct TestDockerBridgeInner {
        available_networks: Mutex<Vec<String>>,
        created_networks: Mutex<Vec<String>>,
        connected_networks: Mutex<Vec<String>>,
    }

    impl TestDockerBridge {
        /// Get a clone of the network names that this orchestrator has recorded as created.
        ///
        /// The returned vector contains the names of networks that were created and stored internally.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// // Assuming `orch` is an instance of the orchestrator:
        /// // let names = orch.created_networks();
        /// // assert!(names.iter().all(|n| !n.is_empty()));
        /// ```
        fn created_networks(&self) -> Vec<String> {
            self.inner.created_networks.lock().unwrap().clone()
        }

        /// Get the current list of connected network names.
        ///
        /// The returned vector is a snapshot of the orchestrator's connected networks at the time of the call; each entry is an owned network name.
        ///
        /// # Examples
        ///
        /// ```
        /// let nets = orchestrator.connected_networks();
        /// // `nets` is a Vec<String> containing network names
        /// assert!(nets.iter().all(|n| !n.is_empty()));
        /// ```
        fn connected_networks(&self) -> Vec<String> {
            self.inner.connected_networks.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DockerBridge for TestDockerBridge {
        /// Performs a liveness check against the configured Docker backend.
        ///
        /// # Returns
        ///
        /// `Ok(())` if the Docker backend is reachable and responsive, `Err(DockerError)` otherwise.
        ///
        /// # Examples
        ///
        /// ```
        /// // Synchronously run the async ping in a simple executor for demonstration.
        /// // Replace `orchestrator` with a value implementing the method in your code.
        /// let _ = futures::executor::block_on(orchestrator.ping());
        /// ```
        async fn ping(&self) -> Result<(), DockerError> {
            Ok(())
        }

        /// Returns the client's available Docker networks as a vector of `Network` objects.
        ///
        /// The `_options` parameter is ignored; the function snapshots the client's internal
        /// available_networks and returns one `Network` per name with the `name` field set.
        ///
        /// # Examples
        ///
        /// ```
        /// let nets = futures::executor::block_on(client.list_networks(None)).unwrap();
        /// assert!(nets.iter().all(|n| n.name.is_some()));
        /// ```
        async fn list_networks(
            &self,
            _options: Option<ListNetworksOptions<String>>,
        ) -> Result<Vec<Network>, DockerError> {
            let networks = self.inner.available_networks.lock().unwrap().clone();
            Ok(networks
                .into_iter()
                .map(|name| Network {
                    name: Some(name),
                    ..Default::default()
                })
                .collect())
        }

        /// Registers a new network name with the test Docker implementation by adding the provided
        /// network name to both the created and available network lists.
        ///
        /// # Parameters
        ///
        /// - `options.name`: the network name to create.
        ///
        /// # Examples
        ///
        /// ```
        /// use bollard::network::CreateNetworkOptions;
        /// let docker = TestDocker::new();
        /// let opts = CreateNetworkOptions { name: "platform-network".to_string(), ..Default::default() };
        /// futures::executor::block_on(docker.create_network(opts)).unwrap();
        /// assert!(docker.inner.available_networks.lock().unwrap().contains(&"platform-network".to_string()));
        /// ```
        async fn create_network(
            &self,
            options: CreateNetworkOptions<String>,
        ) -> Result<(), DockerError> {
            self.inner
                .created_networks
                .lock()
                .unwrap()
                .push(options.name.clone());
            self.inner
                .available_networks
                .lock()
                .unwrap()
                .push(options.name);
            Ok(())
        }

        /// Builds a ContainerInspectResponse whose NetworkSettings.networks map contains
        /// the orchestrator's currently connected network names mapped to default EndpointSettings.
        ///
        /// # Examples
        ///
        /// ```
        /// # use futures::executor::block_on;
        /// // Assuming `bridge` implements the same method signature as shown.
        /// // let resp = block_on(bridge.inspect_container("id", None)).unwrap();
        /// // assert!(resp.network_settings.unwrap().networks.unwrap().contains_key("platform-network"));
        /// ```
        async fn inspect_container(
            &self,
            _id: &str,
            _options: Option<InspectContainerOptions>,
        ) -> Result<ContainerInspectResponse, DockerError> {
            let mut map = HashMap::new();
            for name in self
                .inner
                .connected_networks
                .lock()
                .unwrap()
                .iter()
                .cloned()
            {
                map.insert(name, EndpointSettings::default());
            }
            Ok(ContainerInspectResponse {
                network_settings: Some(NetworkSettings {
                    networks: Some(map),
                    ..Default::default()
                }),
                ..Default::default()
            })
        }

        /// Marks the bridge as connected to the given network and ensures the network is listed as available.
        ///
        /// The method records that this bridge is connected to `network` and makes sure the network
        /// name appears in the bridge's available networks.
        ///
        /// # Parameters
        ///
        /// - `network`: Name of the network to connect.
        ///
        /// # Returns
        ///
        /// `Ok(())` if the network was recorded successfully, `Err(DockerError)` if an underlying error occurred.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// // Assuming `bridge` implements `connect_network`.
        /// # async fn doc_example<B: std::future::Future<Output = ()>>() {}
        /// #
        /// // Example usage:
        /// // bridge.connect_network("platform-network", Default::default()).await.unwrap();
        /// ```
        async fn connect_network(
            &self,
            network: &str,
            _options: ConnectNetworkOptions<String>,
        ) -> Result<(), DockerError> {
            let mut connected = self.inner.connected_networks.lock().unwrap();
            if !connected.iter().any(|name| name == network) {
                connected.push(network.to_string());
            }
            let mut available = self.inner.available_networks.lock().unwrap();
            if !available.iter().any(|name| name == network) {
                available.push(network.to_string());
            }
            Ok(())
        }

        /// Produces a stream of image creation progress and informational messages for a requested image.
        ///
        /// The stream yields `Result<CreateImageInfo, DockerError>` items describing progress or errors and completes when image creation finishes.
        ///
        /// # Parameters
        /// - `options`: optional parameters that control how the image is created (e.g., image reference, auth), if provided.
        ///
        /// # Returns
        /// A stream that produces progress/info messages (`CreateImageInfo`) wrapped in `Result`; the stream ends when image creation completes.
        ///
        /// # Examples
        ///
        /// ```
        /// use futures::StreamExt;
        ///
        /// // `client` is an instance providing `create_image_stream`.
        /// let mut stream = client.create_image_stream(None);
        /// // In this implementation the stream may complete without yielding items.
        /// let next = futures::executor::block_on(async { stream.next().await });
        /// assert!(next.is_none() || next.unwrap().is_ok());
        /// ```
        fn create_image_stream(
            &self,
            _options: Option<CreateImageOptions<String>>,
        ) -> Pin<Box<dyn Stream<Item = Result<CreateImageInfo, DockerError>> + Send>> {
            Box::pin(stream::empty::<Result<CreateImageInfo, DockerError>>())
                as Pin<Box<dyn Stream<Item = Result<CreateImageInfo, DockerError>> + Send>>
        }

        /// Creates a Docker volume from the provided options.
        ///
        /// In this implementation the call is a no-op and always succeeds.
        ///
        /// # Examples
        ///
        /// ```
        /// # async fn example(client: &impl std::marker::Send) {
        /// // `options` is typically constructed with the desired volume name and labels.
        /// let options = Default::default();
        /// // `create_volume` is async; call from an async context.
        /// // Here we ignore the concrete client type for the example.
        /// // client.create_volume(options).await.unwrap();
        /// # }
        /// ```
        async fn create_volume(
            &self,
            _options: CreateVolumeOptions<String>,
        ) -> Result<(), DockerError> {
            Ok(())
        }

        /// Simulates creating a Docker container and returns a fixed test response.
        ///
        /// This test implementation always returns a `ContainerCreateResponse` with the
        /// container id set to `"test-container"` and an empty warnings list. It is
        /// intended for use in unit tests or test harnesses that require a predictable
        /// create-container result.
        ///
        /// # Examples
        ///
        /// ```
        /// # use futures::executor::block_on;
        /// # // assume `create_container` is available in scope on a test object `svc`
        /// let resp = block_on(svc.create_container(None, Default::default())).unwrap();
        /// assert_eq!(resp.id, "test-container");
        /// assert!(resp.warnings.is_empty());
        /// ```
        async fn create_container(
            &self,
            _options: Option<CreateContainerOptions<String>>,
            _config: Config<String>,
        ) -> Result<ContainerCreateResponse, DockerError> {
            Ok(ContainerCreateResponse {
                id: "test-container".to_string(),
                warnings: Vec::new(),
            })
        }

        /// Starts the container identified by `id`, applying the provided start options if any.
        
        ///
        
        /// `id` is the container identifier to start. `options` configures runtime start parameters
        
        /// such as entrypoint overrides, environment variables, and networking settings.
        
        ///
        
        /// # Returns
        
        ///
        
        /// `Ok(())` if the container was started successfully, `Err(DockerError)` if the start operation failed.
        
        ///
        
        /// # Examples
        
        ///
        
        /// ```
        
        /// # use crate::docker::DockerError;
        
        /// # async fn example(starter: &impl Fn(&str, Option<StartContainerOptions<String>>) -> futures::future::BoxFuture<'_, Result<(), DockerError>>) {
        
        /// let _ = starter("container-123", None).await;
        
        /// # }
        
        /// ```
        async fn start_container(
            &self,
            _id: &str,
            _options: Option<StartContainerOptions<String>>,
        ) -> Result<(), DockerError> {
            Ok(())
        }

        /// Stops the container with the given id.
        ///
        /// This implementation is a no-op and reports success without performing any action.
        ///
        /// # Examples
        ///
        /// ```
        /// // Callers can await this async operation; here we use a simple executor.
        /// // Replace `client` with an actual implementation of the Docker client that provides `stop_container`.
        /// # fn example() {
        /// let client = /* impl providing async fn stop_container(&self, id: &str, options: Option<()>) -> Result<(), _> */ ();
        /// // futures::executor::block_on(client.stop_container("container-id", None)).unwrap();
        /// # }
        /// ```
        ///
        /// # Returns
        ///
        /// `Ok(())` on success, or a `DockerError` on failure.
        async fn stop_container(
            &self,
            _id: &str,
            _options: Option<StopContainerOptions>,
        ) -> Result<(), DockerError> {
            Ok(())
        }

        /// Removes a container identified by `id` from the Docker runtime.
        ///
        /// Performs container removal using the provided optional `RemoveContainerOptions`. On success the container is removed and the function returns `Ok(())`.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// // Example uses local stand-ins for crate types to demonstrate calling the method.
        /// type RemoveContainerOptions = ();
        /// type DockerError = ();
        ///
        /// struct Dummy;
        ///
        /// impl Dummy {
        ///     async fn remove_container(
        ///         &self,
        ///         _id: &str,
        ///         _options: Option<RemoveContainerOptions>,
        ///     ) -> Result<(), DockerError> {
        ///         Ok(())
        ///     }
        /// }
        ///
        /// # futures::executor::block_on(async {
        /// let client = Dummy;
        /// client.remove_container("container-id", None).await.unwrap();
        /// # });
        /// ```
        async fn remove_container(
            &self,
            _id: &str,
            _options: Option<RemoveContainerOptions>,
        ) -> Result<(), DockerError> {
            Ok(())
        }

        /// Lists Docker containers according to the provided options.
        ///
        /// The optional `options` argument specifies filters and list parameters (such as all/only-running,
        /// name/image filters, or limit) to apply when enumerating containers.
        ///
        /// # Returns
        ///
        /// A `Vec<ContainerSummary>` containing a summary entry for each container that matches `options`.
        ///
        /// # Examples
        ///
        /// ```
        /// # async fn _example(orchestrator: &impl std::ops::Deref<Target = crate::docker::DockerClient>) {
        /// let summaries = orchestrator.list_containers(None).await.unwrap();
        /// for s in summaries {
        ///     println!("container id: {}", s.Id);
        /// }
        /// # }
        /// ```
        async fn list_containers(
            &self,
            _options: Option<ListContainersOptions<String>>,
        ) -> Result<Vec<ContainerSummary>, DockerError> {
            Ok(Vec::new())
        }

        /// Provides a stream of log frames for the specified container.
        ///
        /// The stream yields `Result<LogOutput, DockerError>` items representing log frames or errors;
        /// this implementation returns an empty stream that yields no items.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// // `obj` is an instance that implements this method.
        /// let stream = obj.logs_stream("container-id", Default::default());
        /// // `stream` implements `futures::Stream<Item = Result<LogOutput, DockerError>>`
        /// ```
        fn logs_stream(
            &self,
            _id: &str,
            _options: LogsOptions<String>,
        ) -> Pin<Box<dyn Stream<Item = Result<LogOutput, DockerError>> + Send>> {
            Box::pin(stream::empty::<Result<LogOutput, DockerError>>())
                as Pin<Box<dyn Stream<Item = Result<LogOutput, DockerError>> + Send>>
        }
    }
}