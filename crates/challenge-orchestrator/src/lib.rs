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
pub use docker::{CleanupResult, DockerClient};
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
    docker: DockerClient,
    challenges: Arc<RwLock<HashMap<ChallengeId, ChallengeInstance>>>,
    health_monitor: HealthMonitor,
    config: OrchestratorConfig,
}

/// Default network name for Platform containers
pub const PLATFORM_NETWORK: &str = "platform-network";

impl ChallengeOrchestrator {
    pub async fn new(config: OrchestratorConfig) -> anyhow::Result<Self> {
        // Auto-detect the network from the validator container
        // This ensures challenge containers are on the same network as the validator
        let docker = DockerClient::connect_auto_detect().await?;

        // Ensure the detected network exists (creates it if running outside Docker)
        docker.ensure_network().await?;

        // Connect the validator container to the platform network
        // This allows the validator to communicate with challenge containers by hostname
        if let Err(e) = docker.connect_self_to_network().await {
            tracing::warn!("Could not connect validator to platform network: {}", e);
        }

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

    /// Get the Docker client for direct operations
    pub fn docker(&self) -> &DockerClient {
        &self.docker
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
