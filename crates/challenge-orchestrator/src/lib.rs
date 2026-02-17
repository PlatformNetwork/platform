//! Challenge Orchestrator
//!
//! Provides a high-level API for managing the full lifecycle of challenge
//! containers. The crate wires together networking bootstrap, backend
//! selection, container health monitoring, and the HTTP evaluator used by the
//! validator node.
//!
//! ### Responsibilities
//! - Detect the correct container backend (secure broker vs. direct Docker)
//! - Keep challenge containers on the `platform-network` with automatic
//!   self-attachment for the validator container
//! - Track every running challenge and expose health + evaluation helpers
//! - Refresh or hot-swap containers without bouncing the validator
//!
//! ### Backend Selection (Secure by Default)
//!
//! The orchestrator always prefers the secure broker. Direct Docker is only
//! selected when `DEVELOPMENT_MODE=true`, which explicitly opts into relaxed
//! security for local workflows.
//!
//! Priority order:
//! 1. `DEVELOPMENT_MODE=true` -> Direct Docker (local dev only)
//! 2. Broker socket exists -> Secure broker (production default)
//! 3. No broker + not dev mode -> Error (production requires broker)
//!
//! Default broker socket: `/var/run/platform/broker.sock`

pub mod backend;
pub mod config;
pub mod continuous;
pub mod docker;
pub mod evaluator;
pub mod health;
pub mod lifecycle;

pub use backend::{
    create_backend, is_development_mode, is_secure_mode, ContainerBackend, DirectDockerBackend,
    SecureBackend, DEFAULT_BROKER_SOCKET,
};
pub use config::*;
pub use continuous::*;
pub use docker::{ChallengeDocker, CleanupResult, DockerClient};
pub use evaluator::*;
pub use health::*;
pub use lifecycle::*;
use parking_lot::RwLock;
pub use platform_core::ChallengeContainerConfig;
use platform_core::ChallengeId;
use std::collections::HashMap;
use std::sync::Arc;

/// High-level façade that keeps container state, evaluator access, and health
/// monitoring in sync for every registered challenge.
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
    /// Create a new orchestrator by auto-detecting the Docker runtime inside
    /// the validator container and ensuring networking prerequisites exist.
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

    /// Reusable constructor path shared between production and tests once a
    /// concrete Docker client is available.
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

    /// Build an orchestrator with a custom Docker implementation
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
    #[deprecated(note = "Docker-based container cleanup is deprecated; prefer WASM-based challenge execution")]
    pub async fn cleanup_stale_task_containers(&self) -> anyhow::Result<CleanupResult> {
        tracing::warn!("Docker-based container cleanup is deprecated; prefer WASM-based challenge execution");
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

    /// Get the Docker client for direct operations
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
    use serial_test::serial;
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
        fn record(&self, entry: impl Into<String>) {
            self.inner.operations.lock().unwrap().push(entry.into());
        }

        fn operations(&self) -> Vec<String> {
            self.inner.operations.lock().unwrap().clone()
        }

        fn set_cleanup_result(&self, result: CleanupResult) {
            *self.inner.cleanup_result.lock().unwrap() = result;
        }

        fn cleanup_calls(&self) -> Vec<(String, u64, Vec<String>)> {
            self.inner.cleanup_calls.lock().unwrap().clone()
        }

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
        async fn pull_image(&self, image: &str) -> anyhow::Result<()> {
            self.record(format!("pull:{image}"));
            Ok(())
        }

        async fn start_challenge(
            &self,
            config: &ChallengeContainerConfig,
        ) -> anyhow::Result<ChallengeInstance> {
            self.record(format!("start:{}", config.challenge_id));
            Ok(self.next_instance(config))
        }

        async fn stop_container(&self, container_id: &str) -> anyhow::Result<()> {
            self.record(format!("stop:{container_id}"));
            Ok(())
        }

        async fn remove_container(&self, container_id: &str) -> anyhow::Result<()> {
            self.record(format!("remove:{container_id}"));
            Ok(())
        }

        async fn is_container_running(&self, container_id: &str) -> anyhow::Result<bool> {
            self.record(format!("is_running:{container_id}"));
            Ok(true)
        }

        async fn get_logs(&self, container_id: &str, tail: usize) -> anyhow::Result<String> {
            self.record(format!("logs:{container_id}:{tail}"));
            Ok(format!("logs-{container_id}"))
        }

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

    fn sample_config(image: &str) -> ChallengeContainerConfig {
        sample_config_with_id(ChallengeId::new(), image)
    }

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

    #[tokio::test]
    #[serial]
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
        fn created_networks(&self) -> Vec<String> {
            self.inner.created_networks.lock().unwrap().clone()
        }

        fn connected_networks(&self) -> Vec<String> {
            self.inner.connected_networks.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DockerBridge for TestDockerBridge {
        async fn ping(&self) -> Result<(), DockerError> {
            Ok(())
        }

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

        fn create_image_stream(
            &self,
            _options: Option<CreateImageOptions<String>>,
        ) -> Pin<Box<dyn Stream<Item = Result<CreateImageInfo, DockerError>> + Send>> {
            Box::pin(stream::empty::<Result<CreateImageInfo, DockerError>>())
                as Pin<Box<dyn Stream<Item = Result<CreateImageInfo, DockerError>> + Send>>
        }

        async fn create_volume(
            &self,
            _options: CreateVolumeOptions<String>,
        ) -> Result<(), DockerError> {
            Ok(())
        }

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

        async fn start_container(
            &self,
            _id: &str,
            _options: Option<StartContainerOptions<String>>,
        ) -> Result<(), DockerError> {
            Ok(())
        }

        async fn stop_container(
            &self,
            _id: &str,
            _options: Option<StopContainerOptions>,
        ) -> Result<(), DockerError> {
            Ok(())
        }

        async fn remove_container(
            &self,
            _id: &str,
            _options: Option<RemoveContainerOptions>,
        ) -> Result<(), DockerError> {
            Ok(())
        }

        async fn list_containers(
            &self,
            _options: Option<ListContainersOptions<String>>,
        ) -> Result<Vec<ContainerSummary>, DockerError> {
            Ok(Vec::new())
        }

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
