//! Container lifecycle management

#[cfg(test)]
use crate::CleanupResult;
use crate::{ChallengeContainerConfig, ChallengeDocker, ChallengeInstance, ContainerStatus};
use parking_lot::RwLock;
use platform_core::ChallengeId;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info};

/// Manages the lifecycle of challenge containers
pub struct LifecycleManager {
    docker: Box<dyn ChallengeDocker>,
    challenges: Arc<RwLock<HashMap<ChallengeId, ChallengeInstance>>>,
    configs: Arc<RwLock<HashMap<ChallengeId, ChallengeContainerConfig>>>,
}

impl LifecycleManager {
    /// Creates a new LifecycleManager using the provided Docker implementation and shared challenges map.
    ///
    /// The returned manager stores the given docker implementation (boxed) and the provided `challenges` map,
    /// and initializes an empty, shared `configs` map for tracking container configurations.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::sync::{Arc, RwLock};
    /// use std::collections::HashMap;
    ///
    /// // Assume `MyDocker` implements `ChallengeDocker` and `ChallengeId`/`ChallengeInstance` are in scope.
    /// let challenges: Arc<RwLock<HashMap<ChallengeId, ChallengeInstance>>> = Arc::new(RwLock::new(HashMap::new()));
    /// let docker = MyDocker::new();
    /// let manager = LifecycleManager::new(docker, challenges);
    /// ```
    pub fn new(
        docker: impl ChallengeDocker + 'static,
        challenges: Arc<RwLock<HashMap<ChallengeId, ChallengeInstance>>>,
    ) -> Self {
        Self {
            docker: Box::new(docker),
            challenges,
            configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a challenge configuration (will start container)
    pub async fn add(&mut self, config: ChallengeContainerConfig) -> anyhow::Result<()> {
        let challenge_id = config.challenge_id;

        // Pull image first
        self.docker.pull_image(&config.docker_image).await?;

        // Start container
        let instance = self.docker.start_challenge(&config).await?;

        // Store config and instance
        self.configs.write().insert(challenge_id, config);
        self.challenges.write().insert(challenge_id, instance);

        info!(challenge_id = %challenge_id, "Challenge added and started");
        Ok(())
    }

    /// Update a challenge (new image version)
    pub async fn update(&mut self, config: ChallengeContainerConfig) -> anyhow::Result<()> {
        let challenge_id = config.challenge_id;

        // Stop existing container - get container_id first, then release lock before await
        let container_id = self
            .challenges
            .read()
            .get(&challenge_id)
            .map(|i| i.container_id.clone());
        if let Some(container_id) = container_id {
            self.docker.stop_container(&container_id).await?;
            self.docker.remove_container(&container_id).await?;
        }

        // Pull new image
        self.docker.pull_image(&config.docker_image).await?;

        // Start new container
        let instance = self.docker.start_challenge(&config).await?;

        // Update config and instance
        self.configs.write().insert(challenge_id, config);
        self.challenges.write().insert(challenge_id, instance);

        info!(challenge_id = %challenge_id, "Challenge updated");
        Ok(())
    }

    /// Remove a challenge
    pub async fn remove(&mut self, challenge_id: ChallengeId) -> anyhow::Result<()> {
        // Remove instance and get container_id before await
        let instance = self.challenges.write().remove(&challenge_id);
        if let Some(instance) = instance {
            self.docker.stop_container(&instance.container_id).await?;
            self.docker.remove_container(&instance.container_id).await?;
        }

        self.configs.write().remove(&challenge_id);

        info!(challenge_id = %challenge_id, "Challenge removed");
        Ok(())
    }

    /// Restart a challenge (same config)
    pub async fn restart(&mut self, challenge_id: ChallengeId) -> anyhow::Result<()> {
        let config = self
            .configs
            .read()
            .get(&challenge_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Challenge config not found"))?;

        self.update(config).await
    }

    /// Restart unhealthy challenges
    pub async fn restart_unhealthy(&mut self) -> Vec<(ChallengeId, anyhow::Result<()>)> {
        let unhealthy: Vec<_> = self
            .challenges
            .read()
            .iter()
            .filter(|(_, instance)| instance.status == ContainerStatus::Unhealthy)
            .map(|(id, _)| *id)
            .collect();

        let mut results = Vec::new();

        for challenge_id in unhealthy {
            let result = self.restart(challenge_id).await;
            if let Err(ref e) = result {
                error!(challenge_id = %challenge_id, error = %e, "Failed to restart unhealthy challenge");
            }
            results.push((challenge_id, result));
        }

        results
    }

    /// Sync with target state (add missing, remove extra, update changed)
    pub async fn sync(
        &mut self,
        target_configs: Vec<ChallengeContainerConfig>,
    ) -> anyhow::Result<SyncResult> {
        let mut result = SyncResult::default();

        let target_ids: std::collections::HashSet<_> =
            target_configs.iter().map(|c| c.challenge_id).collect();

        let current_ids: std::collections::HashSet<_> =
            self.configs.read().keys().cloned().collect();

        // Remove challenges not in target
        for id in current_ids.difference(&target_ids) {
            match self.remove(*id).await {
                Ok(_) => result.removed.push(*id),
                Err(e) => result.errors.push((*id, e.to_string())),
            }
        }

        // Add or update challenges
        for config in target_configs {
            let needs_update = self
                .configs
                .read()
                .get(&config.challenge_id)
                .map(|existing| existing.docker_image != config.docker_image)
                .unwrap_or(true);

            if needs_update {
                let is_new = !current_ids.contains(&config.challenge_id);

                match self.update(config.clone()).await {
                    Ok(_) => {
                        if is_new {
                            result.added.push(config.challenge_id);
                        } else {
                            result.updated.push(config.challenge_id);
                        }
                    }
                    Err(e) => {
                        result.errors.push((config.challenge_id, e.to_string()));
                    }
                }
            } else {
                result.unchanged.push(config.challenge_id);
            }
        }

        info!(
            added = result.added.len(),
            updated = result.updated.len(),
            removed = result.removed.len(),
            unchanged = result.unchanged.len(),
            errors = result.errors.len(),
            "Sync completed"
        );

        Ok(result)
    }

    /// Stop all challenges (for shutdown)
    pub async fn stop_all(&mut self) -> Vec<(ChallengeId, anyhow::Result<()>)> {
        let ids: Vec<_> = self.challenges.read().keys().cloned().collect();
        let mut results = Vec::new();

        for id in ids {
            let result = self.remove(id).await;
            results.push((id, result));
        }

        results
    }
}

/// Result of a sync operation
#[derive(Default, Debug)]
pub struct SyncResult {
    pub added: Vec<ChallengeId>,
    pub updated: Vec<ChallengeId>,
    pub removed: Vec<ChallengeId>,
    pub unchanged: Vec<ChallengeId>,
    pub errors: Vec<(ChallengeId, String)>,
}

impl SyncResult {
    pub fn is_success(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn total_changes(&self) -> usize {
        self.added.len() + self.updated.len() + self.removed.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_sync_result_default() {
        let result = SyncResult::default();
        assert!(result.is_success());
        assert_eq!(result.total_changes(), 0);
    }

    #[test]
    fn test_sync_result_with_changes() {
        let mut result = SyncResult::default();
        result.added.push(ChallengeId::new());
        result.updated.push(ChallengeId::new());

        assert!(result.is_success());
        assert_eq!(result.total_changes(), 2);
    }

    #[test]
    fn test_sync_result_with_errors() {
        let mut result = SyncResult::default();
        result
            .errors
            .push((ChallengeId::new(), "test error".to_string()));

        assert!(!result.is_success());
    }

    #[tokio::test]
    async fn test_restart_unhealthy_restarts_only_unhealthy() {
        let mock = MockDocker::default();
        let mut manager =
            LifecycleManager::new(mock.clone(), Arc::new(RwLock::new(HashMap::new())));

        let unhealthy_id = ChallengeId::new();
        let healthy_id = ChallengeId::new();
        let unhealthy_container_id = "container-unhealthy";
        let healthy_container_id = "container-healthy";

        manager.configs.write().insert(
            unhealthy_id,
            sample_config(unhealthy_id, "ghcr.io/org/unhealthy:1"),
        );
        manager.configs.write().insert(
            healthy_id,
            sample_config(healthy_id, "ghcr.io/org/healthy:1"),
        );

        manager.challenges.write().insert(
            unhealthy_id,
            sample_instance(
                unhealthy_id,
                unhealthy_container_id,
                "ghcr.io/org/unhealthy:1",
                ContainerStatus::Unhealthy,
            ),
        );
        manager.challenges.write().insert(
            healthy_id,
            sample_instance(
                healthy_id,
                healthy_container_id,
                "ghcr.io/org/healthy:1",
                ContainerStatus::Running,
            ),
        );

        let results = manager.restart_unhealthy().await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, unhealthy_id);
        assert!(results[0].1.is_ok());

        let ops = mock.operations();
        assert!(ops
            .iter()
            .any(|op| op == &format!("stop:{unhealthy_container_id}")));
        assert!(ops
            .iter()
            .any(|op| op == &format!("remove:{unhealthy_container_id}")));
        assert!(ops
            .iter()
            .any(|op| op == &format!("start:{}", unhealthy_id.to_string())));
        assert!(!ops
            .iter()
            .any(|op| op == &format!("stop:{healthy_container_id}")));
    }

    #[tokio::test]
    async fn test_sync_handles_add_update_remove() {
        let mock = MockDocker::default();
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let mut manager = LifecycleManager::new(mock.clone(), challenges);

        let update_id = ChallengeId::new();
        let remove_id = ChallengeId::new();
        let new_id = ChallengeId::new();

        manager
            .configs
            .write()
            .insert(update_id, sample_config(update_id, "ghcr.io/org/update:v1"));
        manager
            .configs
            .write()
            .insert(remove_id, sample_config(remove_id, "ghcr.io/org/remove:v1"));

        manager.challenges.write().insert(
            update_id,
            sample_instance(
                update_id,
                "container-update-old",
                "ghcr.io/org/update:v1",
                ContainerStatus::Running,
            ),
        );
        manager.challenges.write().insert(
            remove_id,
            sample_instance(
                remove_id,
                "container-remove-old",
                "ghcr.io/org/remove:v1",
                ContainerStatus::Running,
            ),
        );

        let result = manager
            .sync(vec![
                sample_config(update_id, "ghcr.io/org/update:v2"),
                sample_config(new_id, "ghcr.io/org/new:v1"),
            ])
            .await
            .expect("sync succeeds");

        assert_eq!(result.added, vec![new_id]);
        assert_eq!(result.updated, vec![update_id]);
        assert_eq!(result.removed, vec![remove_id]);
        assert!(result.errors.is_empty());
        assert!(result.unchanged.is_empty());

        let challenges = manager.challenges.read();
        assert!(challenges.contains_key(&update_id));
        assert!(challenges.contains_key(&new_id));
        assert!(!challenges.contains_key(&remove_id));
        drop(challenges);

        let ops = mock.operations();
        assert!(ops.iter().any(|op| op == "pull:ghcr.io/org/update:v2"));
        assert!(ops.iter().any(|op| op == "pull:ghcr.io/org/new:v1"));
        assert!(ops
            .iter()
            .any(|op| op == &format!("start:{}", update_id.to_string())));
        assert!(ops
            .iter()
            .any(|op| op == &format!("start:{}", new_id.to_string())));
        assert!(ops.iter().any(|op| op == "stop:container-update-old"));
        assert!(ops.iter().any(|op| op == "remove:container-update-old"));
        assert!(ops.iter().any(|op| op == "stop:container-remove-old"));
        assert!(ops.iter().any(|op| op == "remove:container-remove-old"));
    }

    #[tokio::test]
    async fn test_add_records_config_and_instance_state() {
        let mock = MockDocker::default();
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let mut manager = LifecycleManager::new(mock.clone(), challenges);
        let challenge_id = ChallengeId::new();
        let config = sample_config(challenge_id, "ghcr.io/org/add:v1");

        manager.add(config.clone()).await.expect("add succeeds");

        assert!(manager.challenges.read().contains_key(&challenge_id));
        assert!(manager.configs.read().contains_key(&challenge_id));

        let ops = mock.operations();
        assert!(ops.contains(&format!("pull:{}", config.docker_image)));
        assert!(ops.contains(&format!("start:{}", challenge_id)));
    }

    #[tokio::test]
    async fn test_stop_all_removes_every_challenge() {
        let mock = MockDocker::default();
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let mut manager = LifecycleManager::new(mock.clone(), challenges);

        let first_id = ChallengeId::new();
        let second_id = ChallengeId::new();

        manager
            .configs
            .write()
            .insert(first_id, sample_config(first_id, "ghcr.io/org/first:v1"));
        manager
            .configs
            .write()
            .insert(second_id, sample_config(second_id, "ghcr.io/org/second:v1"));

        manager.challenges.write().insert(
            first_id,
            sample_instance(
                first_id,
                "container-first",
                "ghcr.io/org/first:v1",
                ContainerStatus::Running,
            ),
        );
        manager.challenges.write().insert(
            second_id,
            sample_instance(
                second_id,
                "container-second",
                "ghcr.io/org/second:v1",
                ContainerStatus::Running,
            ),
        );

        let results = manager.stop_all().await;

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|(_, res)| res.is_ok()));
        assert!(manager.challenges.read().is_empty());
        assert!(manager.configs.read().is_empty());

        let ops = mock.operations();
        assert!(ops.contains(&"stop:container-first".to_string()));
        assert!(ops.contains(&"remove:container-first".to_string()));
        assert!(ops.contains(&"stop:container-second".to_string()));
        assert!(ops.contains(&"remove:container-second".to_string()));
    }

    #[derive(Clone, Default)]
    struct MockDocker {
        inner: Arc<MockDockerInner>,
    }

    #[derive(Default)]
    struct MockDockerInner {
        operations: Mutex<Vec<String>>,
    }

    impl MockDocker {
        /// Appends an operation description to the internal operations log.
        ///
        /// # Examples
        ///
        /// ```
        /// let inner = MockDockerInner::default();
        /// inner.record("start");
        /// assert_eq!(inner.operations.lock().unwrap().last().unwrap(), "start");
        /// ```
        fn record(&self, entry: impl Into<String>) {
            self.inner.operations.lock().unwrap().push(entry.into());
        }

        /// Retrieve the recorded docker operations in chronological order.
        ///
        /// # Returns
        ///
        /// A `Vec<String>` containing each recorded operation, ordered from oldest to newest.
        ///
        /// # Examples
        ///
        /// ```
        /// let mock = MockDocker::new();
        /// // ... perform operations that the mock records ...
        /// let ops = mock.operations();
        /// assert!(ops.len() >= 0);
        /// ```
        fn operations(&self) -> Vec<String> {
            self.inner.operations.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ChallengeDocker for MockDocker {
        /// Pulls the specified container image into the local Docker cache.
        ///
        /// The `image` argument is a Docker image reference (for example `"repo/image:tag"` or
        /// `"repo/image@sha256:<digest>"`). The function ensures the image is available locally,
        /// returning an error if the pull fails.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// // Assuming `docker` implements the method:
        /// // docker.pull_image("repo/image:latest").await?;
        /// ```
        async fn pull_image(&self, image: &str) -> anyhow::Result<()> {
            self.record(format!("pull:{image}"));
            Ok(())
        }

        /// Starts a challenge container according to the provided configuration and returns its runtime instance.
        ///
        /// # Parameters
        ///
        /// - `config`: configuration describing the challenge container to start.
        ///
        /// # Returns
        ///
        /// `ChallengeInstance` representing the started container, with its `status` set to `ContainerStatus::Running`.
        ///
        /// # Examples
        ///
        /// ```
        /// # use crate::{sample_config, ChallengeId};
        /// # tokio_test::block_on(async {
        /// let config = sample_config(ChallengeId::new(), "example-image:latest");
        /// let docker = crate::tests::MockDocker::default();
        /// let inst = docker.start_challenge(&config).await.unwrap();
        /// assert_eq!(inst.challenge_id, config.challenge_id);
        /// assert_eq!(inst.status, crate::ContainerStatus::Running);
        /// # });
        /// ```
        async fn start_challenge(
            &self,
            config: &ChallengeContainerConfig,
        ) -> anyhow::Result<ChallengeInstance> {
            self.record(format!("start:{}", config.challenge_id));
            Ok(sample_instance(
                config.challenge_id,
                &format!("container-{}", config.challenge_id),
                &config.docker_image,
                ContainerStatus::Running,
            ))
        }

        /// Records a stop operation for the container identified by `container_id`.
        ///
        /// In the mock implementation this does not stop a real container; it records the stop action and returns `Ok(())`.
        ///
        /// # Examples
        ///
        /// ```
        /// # use futures::executor::block_on;
        /// # // Assume `mock` implements `stop_container` and `operations`.
        /// # let mock = MockDocker::default();
        /// block_on(mock.stop_container("container-123")).unwrap();
        /// assert_eq!(mock.operations(), vec!["stop:container-123"]);
        /// ```
        async fn stop_container(&self, container_id: &str) -> anyhow::Result<()> {
            self.record(format!("stop:{container_id}"));
            Ok(())
        }

        /// Record the removal of a container identified by `container_id`.
        ///
        /// This method records a "remove:{container_id}" operation in the manager's internal operation log
        /// and returns success if the recording completes.
        ///
        /// # Parameters
        ///
        /// - `container_id`: The identifier of the container to record removal for.
        ///
        /// # Returns
        ///
        /// `Ok(())` if the removal record was recorded successfully, an `Err` if recording failed.
        ///
        /// # Examples
        ///
        /// ```
        /// struct Dummy;
        ///
        /// impl Dummy {
        ///     async fn remove_container(&self, _container_id: &str) -> anyhow::Result<()> {
        ///         // simulate the real method's contract for the example
        ///         Ok(())
        ///     }
        /// }
        ///
        /// # futures::executor::block_on(async {
        /// let d = Dummy;
        /// let res = d.remove_container("container-123").await;
        /// assert!(res.is_ok());
        /// # });
        /// ```
        async fn remove_container(&self, container_id: &str) -> anyhow::Result<()> {
            self.record(format!("remove:{container_id}"));
            Ok(())
        }

        /// Checks whether the container with the specified id is currently running.
        ///
        /// # Returns
        ///
        /// `true` if the container is running, `false` otherwise.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// # async fn example(manager: &impl crate::ChallengeDocker) -> anyhow::Result<()> {
        /// let is_running = manager.is_container_running("container123").await?;
        /// // `is_running` will be `true` or `false` depending on the container state
        /// assert!(is_running == true || is_running == false);
        /// # Ok(())
        /// # }
        /// ```
        async fn is_container_running(&self, container_id: &str) -> anyhow::Result<bool> {
            self.record(format!("is_running:{container_id}"));
            Ok(true)
        }

        /// Fetches the logs for the specified container, returning up to the last `tail` lines.
        ///
        /// # Parameters
        /// - `container_id`: Identifier of the container whose logs to retrieve.
        /// - `tail`: Number of trailing log lines to return.
        ///
        /// # Returns
        /// The container logs as a `String` on success.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// // `mgr` is an instance that exposes `get_logs`.
        /// let logs = mgr.get_logs("container-123", 100).await.unwrap();
        /// println!("{}", logs);
        /// ```
        async fn get_logs(&self, container_id: &str, tail: usize) -> anyhow::Result<String> {
            self.record(format!("logs:{container_id}:{tail}"));
            Ok(String::new())
        }

        /// Lists identifiers of challenge-related containers currently tracked by the lifecycle manager.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// # async fn example(manager: &crate::LifecycleManager) -> anyhow::Result<()> {
        /// let ids = manager.list_challenge_containers().await?;
        /// println!("containers: {:?}", ids);
        /// # Ok(())
        /// # }
        /// ```
        ///
        /// # Returns
        ///
        /// A vector of container identifier strings on success.
        async fn list_challenge_containers(&self) -> anyhow::Result<Vec<String>> {
            self.record("list_containers".to_string());
            Ok(Vec::new())
        }

        /// Records a cleanup request for stale containers that match the given prefix.
        ///
        /// This implementation records the cleanup operation and returns a default
        /// `CleanupResult`. The `max_age_minutes` and `exclude_patterns` parameters are
        /// accepted for API compatibility but are currently ignored.
        ///
        /// # Parameters
        ///
        /// - `prefix` — container name prefix to target for cleanup.
        ///
        /// # Returns
        ///
        /// `CleanupResult` summarizing cleanup actions (currently the default/empty result).
        ///
        /// # Examples
        ///
        /// ```
        /// // Example usage; replace `mgr` with an instance that provides this method.
        /// # async fn _example(mgr: &impl std::ops::Deref) {}
        /// // let result = mgr.cleanup_stale_containers("ch-", 60, &[]).await.unwrap();
        /// // assert_eq!(result, CleanupResult::default());
        /// ```
        async fn cleanup_stale_containers(
            &self,
            prefix: &str,
            _max_age_minutes: u64,
            _exclude_patterns: &[&str],
        ) -> anyhow::Result<CleanupResult> {
            self.record(format!("cleanup:{prefix}"));
            Ok(CleanupResult::default())
        }
    }

    /// Create a sample `ChallengeContainerConfig` for the given challenge ID and Docker image.
    ///
    /// The returned config is populated with sensible defaults for resource limits and timeouts:
    /// a 1.0 CPU core allocation, 512 MB memory, 3600 second timeout, no GPU required, and
    /// emission weight of 1.0. The `name` field is set to `challenge-<challenge_id>`.
    ///
    /// # Examples
    ///
    /// ```
    /// let id = ChallengeId::new();
    /// let cfg = sample_config(id.clone(), "registry/example:latest");
    /// assert_eq!(cfg.challenge_id, id);
    /// assert_eq!(cfg.docker_image, "registry/example:latest");
    /// assert_eq!(cfg.cpu_cores, 1.0);
    /// assert_eq!(cfg.memory_mb, 512);
    /// ```
    fn sample_config(challenge_id: ChallengeId, image: &str) -> ChallengeContainerConfig {
        ChallengeContainerConfig {
            challenge_id,
            name: format!("challenge-{challenge_id}"),
            docker_image: image.to_string(),
            mechanism_id: 0,
            emission_weight: 1.0,
            timeout_secs: 3600,
            cpu_cores: 1.0,
            memory_mb: 512,
            gpu_required: false,
        }
    }

    /// Creates a ChallengeInstance populated with the provided identifiers and metadata.
    ///
    /// The instance's `endpoint` is set to `http://{challenge_id}` and `started_at` is set to the current UTC time.
    ///
    /// # Examples
    ///
    /// ```
    /// let cid = ChallengeId::new();
    /// let inst = sample_instance(cid.clone(), "ctr-1", "img:latest", ContainerStatus::Running);
    /// assert_eq!(inst.challenge_id, cid);
    /// assert_eq!(inst.container_id, "ctr-1");
    /// assert_eq!(inst.image, "img:latest");
    /// assert_eq!(inst.endpoint, format!("http://{}", cid));
    /// assert!(matches!(inst.status, ContainerStatus::Running));
    /// ```
    fn sample_instance(
        challenge_id: ChallengeId,
        container_id: &str,
        image: &str,
        status: ContainerStatus,
    ) -> ChallengeInstance {
        let id_str = challenge_id.to_string();
        ChallengeInstance {
            challenge_id,
            container_id: container_id.to_string(),
            image: image.to_string(),
            endpoint: format!("http://{id_str}"),
            started_at: Utc::now(),
            status,
        }
    }
}