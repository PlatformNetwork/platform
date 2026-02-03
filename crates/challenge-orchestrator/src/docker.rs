//! Docker client wrapper for container management
//!
//! Provides the low-level primitives required when the orchestrator is
//! connected directly to Docker (typically during development or when the
//! secure broker is unavailable). Network bootstrap, log streaming, and image
//! pulls are all funneled through a thin trait (`DockerBridge`) that makes it
//! easy to stub the Docker daemon in tests.
//!
//! SECURITY: Only images from allow-listed registries
//! (`ghcr.io/platformnetwork/`) are allowed to be pulled or run. This prevents
//! malicious container attacks when bypassing the broker.

use crate::{ChallengeContainerConfig, ChallengeInstance, ContainerStatus};
use async_trait::async_trait;
use bollard::container::{
    Config, CreateContainerOptions, InspectContainerOptions, ListContainersOptions, LogsOptions,
    RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
};
use bollard::errors::Error as DockerError;
use bollard::image::CreateImageOptions;
use bollard::models::{
    ContainerCreateResponse, ContainerInspectResponse, ContainerSummary, CreateImageInfo,
    DeviceRequest, HostConfig, Network, PortBinding,
};
use bollard::network::{ConnectNetworkOptions, CreateNetworkOptions, ListNetworksOptions};
use bollard::volume::CreateVolumeOptions;
use bollard::Docker;
use futures::{Stream, StreamExt};
use platform_core::ALLOWED_DOCKER_PREFIXES;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

type ImageStream = Pin<Box<dyn Stream<Item = Result<CreateImageInfo, DockerError>> + Send>>;
type LogStream =
    Pin<Box<dyn Stream<Item = Result<bollard::container::LogOutput, DockerError>> + Send>>;

#[async_trait]
pub trait DockerBridge: Send + Sync {
    async fn ping(&self) -> Result<(), DockerError>;
    async fn list_networks(
        &self,
        options: Option<ListNetworksOptions<String>>,
    ) -> Result<Vec<Network>, DockerError>;
    async fn create_network(
        &self,
        options: CreateNetworkOptions<String>,
    ) -> Result<(), DockerError>;
    async fn inspect_container(
        &self,
        id: &str,
        options: Option<InspectContainerOptions>,
    ) -> Result<ContainerInspectResponse, DockerError>;
    async fn connect_network(
        &self,
        network: &str,
        options: ConnectNetworkOptions<String>,
    ) -> Result<(), DockerError>;
    fn create_image_stream(&self, options: Option<CreateImageOptions<String>>) -> ImageStream;
    async fn create_volume(&self, options: CreateVolumeOptions<String>) -> Result<(), DockerError>;
    async fn create_container(
        &self,
        options: Option<CreateContainerOptions<String>>,
        config: Config<String>,
    ) -> Result<ContainerCreateResponse, DockerError>;
    async fn start_container(
        &self,
        id: &str,
        options: Option<StartContainerOptions<String>>,
    ) -> Result<(), DockerError>;
    async fn stop_container(
        &self,
        id: &str,
        options: Option<StopContainerOptions>,
    ) -> Result<(), DockerError>;
    async fn remove_container(
        &self,
        id: &str,
        options: Option<RemoveContainerOptions>,
    ) -> Result<(), DockerError>;
    async fn list_containers(
        &self,
        options: Option<ListContainersOptions<String>>,
    ) -> Result<Vec<ContainerSummary>, DockerError>;
    fn logs_stream(&self, id: &str, options: LogsOptions<String>) -> LogStream;
}

#[derive(Clone)]
struct BollardBridge {
    docker: Docker,
}

impl BollardBridge {
    fn new(docker: Docker) -> Self {
        Self { docker }
    }
}

#[async_trait]
impl DockerBridge for BollardBridge {
    async fn ping(&self) -> Result<(), DockerError> {
        self.docker.ping().await.map(|_| ())
    }

    async fn list_networks(
        &self,
        options: Option<ListNetworksOptions<String>>,
    ) -> Result<Vec<Network>, DockerError> {
        self.docker.list_networks(options).await
    }

    async fn create_network(
        &self,
        options: CreateNetworkOptions<String>,
    ) -> Result<(), DockerError> {
        self.docker.create_network(options).await.map(|_| ())
    }

    async fn inspect_container(
        &self,
        id: &str,
        options: Option<InspectContainerOptions>,
    ) -> Result<ContainerInspectResponse, DockerError> {
        self.docker.inspect_container(id, options).await
    }

    async fn connect_network(
        &self,
        network: &str,
        options: ConnectNetworkOptions<String>,
    ) -> Result<(), DockerError> {
        self.docker.connect_network(network, options).await
    }

    fn create_image_stream(&self, options: Option<CreateImageOptions<String>>) -> ImageStream {
        Box::pin(self.docker.create_image(options, None, None))
    }

    async fn create_volume(&self, options: CreateVolumeOptions<String>) -> Result<(), DockerError> {
        self.docker.create_volume(options).await.map(|_| ())
    }

    async fn create_container(
        &self,
        options: Option<CreateContainerOptions<String>>,
        config: Config<String>,
    ) -> Result<ContainerCreateResponse, DockerError> {
        self.docker.create_container(options, config).await
    }

    async fn start_container(
        &self,
        id: &str,
        options: Option<StartContainerOptions<String>>,
    ) -> Result<(), DockerError> {
        self.docker.start_container(id, options).await
    }

    async fn stop_container(
        &self,
        id: &str,
        options: Option<StopContainerOptions>,
    ) -> Result<(), DockerError> {
        self.docker.stop_container(id, options).await
    }

    async fn remove_container(
        &self,
        id: &str,
        options: Option<RemoveContainerOptions>,
    ) -> Result<(), DockerError> {
        self.docker.remove_container(id, options).await
    }

    async fn list_containers(
        &self,
        options: Option<ListContainersOptions<String>>,
    ) -> Result<Vec<ContainerSummary>, DockerError> {
        self.docker.list_containers(options).await
    }

    fn logs_stream(&self, id: &str, options: LogsOptions<String>) -> LogStream {
        Box::pin(self.docker.logs(id, Some(options)))
    }
}

/// Docker client for managing challenge containers
///
/// The client ensures challenge containers are attached to the configured
/// network, reuses volumes when possible, and funnels blocking Docker API
/// calls through an async-friendly bridge.
pub struct DockerClient {
    docker: Arc<dyn DockerBridge>,
    network_name: String,
}

#[async_trait]
pub trait ChallengeDocker: Send + Sync {
    async fn pull_image(&self, image: &str) -> anyhow::Result<()>;
    async fn start_challenge(
        &self,
        config: &ChallengeContainerConfig,
    ) -> anyhow::Result<ChallengeInstance>;
    async fn stop_container(&self, container_id: &str) -> anyhow::Result<()>;
    async fn remove_container(&self, container_id: &str) -> anyhow::Result<()>;
    async fn is_container_running(&self, container_id: &str) -> anyhow::Result<bool>;
    async fn get_logs(&self, container_id: &str, tail: usize) -> anyhow::Result<String>;
    async fn list_challenge_containers(&self) -> anyhow::Result<Vec<String>>;
    async fn cleanup_stale_containers(
        &self,
        prefix: &str,
        max_age_minutes: u64,
        exclude_patterns: &[&str],
    ) -> anyhow::Result<CleanupResult>;
}

#[async_trait]
impl ChallengeDocker for DockerClient {
    async fn pull_image(&self, image: &str) -> anyhow::Result<()> {
        DockerClient::pull_image(self, image).await
    }

    async fn start_challenge(
        &self,
        config: &ChallengeContainerConfig,
    ) -> anyhow::Result<ChallengeInstance> {
        DockerClient::start_challenge(self, config).await
    }

    async fn stop_container(&self, container_id: &str) -> anyhow::Result<()> {
        DockerClient::stop_container(self, container_id).await
    }

    async fn remove_container(&self, container_id: &str) -> anyhow::Result<()> {
        DockerClient::remove_container(self, container_id).await
    }

    async fn is_container_running(&self, container_id: &str) -> anyhow::Result<bool> {
        DockerClient::is_container_running(self, container_id).await
    }

    async fn get_logs(&self, container_id: &str, tail: usize) -> anyhow::Result<String> {
        DockerClient::get_logs(self, container_id, tail).await
    }

    async fn list_challenge_containers(&self) -> anyhow::Result<Vec<String>> {
        DockerClient::list_challenge_containers(self).await
    }

    async fn cleanup_stale_containers(
        &self,
        prefix: &str,
        max_age_minutes: u64,
        exclude_patterns: &[&str],
    ) -> anyhow::Result<CleanupResult> {
        DockerClient::cleanup_stale_containers(self, prefix, max_age_minutes, exclude_patterns)
            .await
    }
}

impl DockerClient {
    fn from_bridge(docker: Arc<dyn DockerBridge>, network_name: impl Into<String>) -> Self {
        Self {
            docker,
            network_name: network_name.into(),
        }
    }

    /// Build a client from a custom bridge (used for tests/mocks)
    pub fn with_bridge(
        docker: impl DockerBridge + 'static,
        network_name: impl Into<String>,
    ) -> Self {
        Self::from_bridge(Arc::new(docker), network_name)
    }

    /// Connect to Docker daemon
    pub async fn connect() -> anyhow::Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;

        // Verify connection
        let bridge = Arc::new(BollardBridge::new(docker));
        bridge.ping().await?;
        info!("Connected to Docker daemon");

        Ok(Self::from_bridge(bridge, "platform-network"))
    }

    /// Connect with custom network name
    pub async fn connect_with_network(network_name: &str) -> anyhow::Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;
        let bridge = Arc::new(BollardBridge::new(docker));
        bridge.ping().await?;

        Ok(Self::from_bridge(bridge, network_name))
    }

    /// Connect and auto-detect the network from the validator container
    /// This ensures challenge containers are on the same network as the validator
    pub async fn connect_auto_detect() -> anyhow::Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;
        let bridge = Arc::new(BollardBridge::new(docker));
        bridge.ping().await?;
        info!("Connected to Docker daemon");

        // Try to detect the network from the current container
        let network_name = Self::detect_validator_network(&*bridge)
            .await
            .unwrap_or_else(|e| {
                warn!(
                    "Could not detect validator network: {}. Using default 'platform-network'",
                    e
                );
                "platform-network".to_string()
            });

        info!(network = %network_name, "Using network for challenge containers");

        Ok(Self::from_bridge(bridge, network_name))
    }

    /// Detect the network the validator container is running on
    async fn detect_validator_network(docker: &dyn DockerBridge) -> anyhow::Result<String> {
        // Get our container ID
        let container_id = Self::get_container_id_static()?;

        // Inspect our container to find its networks
        let inspect = docker.inspect_container(&container_id, None).await?;

        let networks = inspect
            .network_settings
            .as_ref()
            .and_then(|ns| ns.networks.as_ref())
            .ok_or_else(|| anyhow::anyhow!("No network settings found"))?;

        // Find a suitable network (prefer non-default networks)
        // Priority: user-defined bridge > any bridge > host
        let mut best_network: Option<String> = None;

        for name in networks.keys() {
            // Skip host and none networks
            if name == "host" || name == "none" {
                continue;
            }
            // Skip the default bridge network (containers can't communicate by name on it)
            if name == "bridge" {
                if best_network.is_none() {
                    best_network = Some(name.clone());
                }
                continue;
            }
            // Any other network is preferred (user-defined bridge)
            best_network = Some(name.clone());
            break;
        }

        best_network
            .ok_or_else(|| anyhow::anyhow!("No suitable network found for validator container"))
    }

    /// Static version of get_self_container_id for use before Self is constructed
    fn get_container_id_static() -> anyhow::Result<String> {
        // Method 1: Check hostname (Docker sets hostname to container ID by default)
        if let Ok(hostname) = std::env::var("HOSTNAME") {
            // Docker container IDs are 12+ hex characters
            if hostname.len() >= 12 && hostname.chars().all(|c| c.is_ascii_hexdigit()) {
                return Ok(hostname);
            }
        }

        // Method 2: Parse from cgroup (works on Linux)
        if let Ok(cgroup) = std::fs::read_to_string("/proc/self/cgroup") {
            for line in cgroup.lines() {
                if let Some(docker_pos) = line.rfind("/docker/") {
                    let id = &line[docker_pos + 8..];
                    if id.len() >= 12 {
                        return Ok(id[..12].to_string());
                    }
                }
                if let Some(containerd_pos) = line.rfind("cri-containerd-") {
                    let id = &line[containerd_pos + 15..];
                    if id.len() >= 12 {
                        return Ok(id[..12].to_string());
                    }
                }
            }
        }

        // Method 3: Check mountinfo
        if std::path::Path::new("/.dockerenv").exists() {
            if let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") {
                for line in mountinfo.lines() {
                    if line.contains("/docker/containers/") {
                        if let Some(start) = line.find("/docker/containers/") {
                            let rest = &line[start + 19..];
                            if let Some(end) = rest.find('/') {
                                let id = &rest[..end];
                                if id.len() >= 12 {
                                    return Ok(id[..12].to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        anyhow::bail!("Not running in a Docker container or unable to determine container ID")
    }

    /// Get a suitable suffix for container naming
    /// Priority: VALIDATOR_NAME env var > detected container ID > short hash of hostname
    fn get_validator_suffix() -> String {
        // 1. Check for explicit VALIDATOR_NAME override
        if let Ok(name) = std::env::var("VALIDATOR_NAME") {
            if !name.is_empty() {
                return name.to_lowercase().replace(['-', ' ', '_'], "");
            }
        }

        // 2. Try to detect container ID (works when running in Docker)
        if let Ok(container_id) = Self::get_container_id_static() {
            // Container IDs are 12+ hex chars, use first 12
            let suffix = if container_id.len() > 12 {
                &container_id[..12]
            } else {
                &container_id
            };
            return suffix.to_lowercase();
        }

        // 3. Fall back to short hash of hostname (for non-Docker environments)
        let hostname =
            std::env::var("HOSTNAME").unwrap_or_else(|_| format!("{:x}", std::process::id()));

        // Create a short hash of the hostname for uniqueness using std hash
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        hostname.hash(&mut hasher);
        format!("{:012x}", hasher.finish()) // 12 hex chars
    }

    /// Ensure the Docker network exists
    pub async fn ensure_network(&self) -> anyhow::Result<()> {
        let networks = self
            .docker
            .list_networks(None::<ListNetworksOptions<String>>)
            .await
            .map_err(anyhow::Error::from)?;

        let exists = networks.iter().any(|n| {
            n.name
                .as_ref()
                .map(|name| name == &self.network_name)
                .unwrap_or(false)
        });

        if !exists {
            use bollard::network::CreateNetworkOptions;

            let config = CreateNetworkOptions {
                name: self.network_name.clone(),
                driver: "bridge".to_string(),
                ..Default::default()
            };

            self.docker
                .create_network(config)
                .await
                .map_err(anyhow::Error::from)?;
            info!(network = %self.network_name, "Created Docker network");
        } else {
            debug!(network = %self.network_name, "Docker network already exists");
        }

        Ok(())
    }

    /// Connect the current container to the platform network
    /// This allows the validator to communicate with challenge containers via hostname
    pub async fn connect_self_to_network(&self) -> anyhow::Result<()> {
        // Get our container ID from the hostname or cgroup
        let container_id = self.get_self_container_id()?;

        // Check if already connected
        let inspect = self
            .docker
            .inspect_container(&container_id, None)
            .await
            .map_err(anyhow::Error::from)?;
        let networks = inspect
            .network_settings
            .as_ref()
            .and_then(|ns| ns.networks.as_ref());

        if let Some(nets) = networks {
            if nets.contains_key(&self.network_name) {
                debug!(
                    container = %container_id,
                    network = %self.network_name,
                    "Container already connected to network"
                );
                return Ok(());
            }
        }

        // Connect to the network
        use bollard::models::EndpointSettings;
        use bollard::network::ConnectNetworkOptions;

        let config = ConnectNetworkOptions {
            container: container_id.clone(),
            endpoint_config: EndpointSettings::default(),
        };

        self.docker
            .connect_network(&self.network_name, config)
            .await
            .map_err(anyhow::Error::from)?;

        info!(
            container = %container_id,
            network = %self.network_name,
            "Connected validator container to platform network"
        );

        Ok(())
    }

    /// Get the container ID of the current process (if running in Docker)
    fn get_self_container_id(&self) -> anyhow::Result<String> {
        // Method 1: Check hostname (Docker sets hostname to container ID by default)
        if let Ok(hostname) = std::env::var("HOSTNAME") {
            // Docker container IDs are 12+ hex characters
            if hostname.len() >= 12 && hostname.chars().all(|c| c.is_ascii_hexdigit()) {
                return Ok(hostname);
            }
        }

        // Method 2: Parse from cgroup (works on Linux)
        if let Ok(cgroup) = std::fs::read_to_string("/proc/self/cgroup") {
            for line in cgroup.lines() {
                // Docker cgroup format: .../docker/<container_id>
                if let Some(docker_pos) = line.rfind("/docker/") {
                    let id = &line[docker_pos + 8..];
                    if id.len() >= 12 {
                        return Ok(id[..12].to_string());
                    }
                }
                // Kubernetes/containerd format: .../cri-containerd-<container_id>
                if let Some(containerd_pos) = line.rfind("cri-containerd-") {
                    let id = &line[containerd_pos + 15..];
                    if id.len() >= 12 {
                        return Ok(id[..12].to_string());
                    }
                }
            }
        }

        // Method 3: Check /.dockerenv file exists
        if std::path::Path::new("/.dockerenv").exists() {
            // If we're in Docker but can't get ID, try the mountinfo
            if let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") {
                for line in mountinfo.lines() {
                    if line.contains("/docker/containers/") {
                        if let Some(start) = line.find("/docker/containers/") {
                            let rest = &line[start + 19..];
                            if let Some(end) = rest.find('/') {
                                let id = &rest[..end];
                                if id.len() >= 12 {
                                    return Ok(id[..12].to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        anyhow::bail!("Not running in a Docker container or unable to determine container ID")
    }

    /// Check if a Docker image is from an allowed registry
    /// SECURITY: This prevents pulling/running malicious containers
    /// In DEVELOPMENT_MODE, all local images are allowed for testing
    fn is_image_allowed(image: &str) -> bool {
        // In development mode, allow any image (for local testing)
        if std::env::var("DEVELOPMENT_MODE")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false)
        {
            return true;
        }
        let image_lower = image.to_lowercase();
        ALLOWED_DOCKER_PREFIXES
            .iter()
            .any(|prefix| image_lower.starts_with(&prefix.to_lowercase()))
    }

    /// Pull a Docker image (only from whitelisted registries)
    pub async fn pull_image(&self, image: &str) -> anyhow::Result<()> {
        // SECURITY: Verify image is from allowed registry before pulling
        if !Self::is_image_allowed(image) {
            error!(
                image = %image,
                "SECURITY: Attempted to pull image from non-whitelisted registry!"
            );
            anyhow::bail!(
                "Docker image '{}' is not from an allowed registry. \
                 Only images from ghcr.io/platformnetwork/ are permitted.",
                image
            );
        }

        info!(image = %image, "Pulling Docker image (whitelisted)");

        let options = CreateImageOptions {
            from_image: image.to_string(),
            ..Default::default()
        };

        let mut stream = self.docker.create_image_stream(Some(options));

        while let Some(result) = stream.next().await {
            match result {
                Ok(info) => {
                    if let Some(status) = info.status {
                        debug!(status = %status, "Pull progress");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Pull warning");
                }
            }
        }

        info!(image = %image, "Image pulled successfully");
        Ok(())
    }

    /// Start a challenge container (only from whitelisted registries)
    pub async fn start_challenge(
        &self,
        config: &ChallengeContainerConfig,
    ) -> anyhow::Result<ChallengeInstance> {
        // SECURITY: Verify image is from allowed registry before starting
        if !Self::is_image_allowed(&config.docker_image) {
            error!(
                image = %config.docker_image,
                challenge = %config.name,
                "SECURITY: Attempted to start container from non-whitelisted registry!"
            );
            anyhow::bail!(
                "Docker image '{}' is not from an allowed registry. \
                 Only images from ghcr.io/platformnetwork/ are permitted. \
                 Challenge '{}' rejected.",
                config.docker_image,
                config.name
            );
        }

        // Also run full config validation
        if let Err(reason) = config.validate() {
            error!(
                challenge = %config.name,
                reason = %reason,
                "Challenge config validation failed"
            );
            anyhow::bail!("Challenge config validation failed: {}", reason);
        }

        info!(
            image = %config.docker_image,
            challenge = %config.name,
            "Starting challenge container (whitelisted)"
        );

        // Ensure network exists
        self.ensure_network().await?;

        // Generate container name with validator identifier
        // Use container ID if running in Docker, otherwise fall back to VALIDATOR_NAME or short hostname hash
        let validator_suffix = Self::get_validator_suffix();
        let container_name = format!(
            "challenge-{}-{}",
            config.name.to_lowercase().replace(' ', "-"),
            validator_suffix
        );

        info!(
            container_name = %container_name,
            validator_suffix = %validator_suffix,
            "Generated challenge container name"
        );

        // Remove existing container if any (same name only)
        // NOTE: We do NOT clean up containers with different suffixes because
        // server and validator may run on the same host and need separate containers
        let _ = self.remove_container(&container_name).await;

        // Build port bindings - expose on a dynamic port
        let mut port_bindings = HashMap::new();
        port_bindings.insert(
            "8080/tcp".to_string(),
            Some(vec![PortBinding {
                host_ip: Some("127.0.0.1".to_string()),
                host_port: Some("0".to_string()), // Dynamic port
            }]),
        );

        // Create named Docker volume for persistent challenge data (survives container recreation)
        // Use container_name (includes validator suffix) so each validator has its own data
        let volume_name = format!("{}-data", container_name);

        // Create volumes if they don't exist (Docker will auto-create on mount, but explicit is clearer)
        let volume_opts = CreateVolumeOptions {
            name: volume_name.clone(),
            driver: "local".to_string(),
            ..Default::default()
        };
        if let Err(e) = self.docker.create_volume(volume_opts).await {
            // Volume might already exist, which is fine
            debug!("Volume creation result for {}: {:?}", volume_name, e);
        }

        // Create cache volume for downloaded datasets (shared across restarts)
        // Use challenge name only (not suffix) so cache persists even if container name changes
        let cache_volume_name = format!(
            "challenge-{}-cache",
            config.name.to_lowercase().replace(' ', "-")
        );
        let cache_volume_opts = CreateVolumeOptions {
            name: cache_volume_name.clone(),
            driver: "local".to_string(),
            ..Default::default()
        };
        if let Err(e) = self.docker.create_volume(cache_volume_opts).await {
            debug!("Volume creation result for {}: {:?}", cache_volume_name, e);
        }

        // Create named volumes for Docker-in-Docker task sharing
        // These volumes are shared between challenge containers and agent containers
        let tasks_volume = "term-challenge-tasks";
        let dind_cache_volume = "term-challenge-cache";
        let evals_volume = "term-challenge-evals";

        for vol_name in [tasks_volume, dind_cache_volume, evals_volume] {
            let vol_opts = CreateVolumeOptions {
                name: vol_name.to_string(),
                driver: "local".to_string(),
                ..Default::default()
            };
            if let Err(e) = self.docker.create_volume(vol_opts).await {
                debug!("Volume creation result for {}: {:?}", vol_name, e);
            }
        }

        // Build host config with resource limits
        let mut host_config = HostConfig {
            network_mode: Some(self.network_name.clone()),
            port_bindings: Some(port_bindings),
            nano_cpus: Some((config.cpu_cores * 1_000_000_000.0) as i64),
            memory: Some((config.memory_mb * 1024 * 1024) as i64),
            // Mount Docker socket for challenge containers to run agent evaluations
            // Use named Docker volumes for DinD - they are auto-created and persistent
            // Each volume is mounted to both internal path AND host path for DinD compatibility
            // Host path is /var/lib/docker/volumes/{name}/_data (standard Docker volume location)
            binds: Some(vec![
                "/var/run/docker.sock:/var/run/docker.sock:rw".to_string(),
                // Tasks volume - for task data
                format!("{}:/app/data/tasks:rw", tasks_volume),
                format!(
                    "{}:/var/lib/docker/volumes/{}/_data:rw",
                    tasks_volume, tasks_volume
                ),
                // Cache volume - for downloaded datasets
                format!("{}:/root/.cache/term-challenge:rw", dind_cache_volume),
                format!(
                    "{}:/var/lib/docker/volumes/{}/_data:rw",
                    dind_cache_volume, dind_cache_volume
                ),
                // Evals volume - for evaluation logs
                format!("{}:/tmp/term-challenge-evals:rw", evals_volume),
                format!(
                    "{}:/var/lib/docker/volumes/{}/_data:rw",
                    evals_volume, evals_volume
                ),
                // Challenge-specific persistent state volume
                format!("{}:/data:rw", volume_name),
            ]),
            ..Default::default()
        };

        // Add GPU if configured
        if config.gpu_required {
            host_config.device_requests = Some(vec![DeviceRequest {
                driver: Some("nvidia".to_string()),
                count: Some(1),
                device_ids: None,
                capabilities: Some(vec![vec!["gpu".to_string()]]),
                options: None,
            }]);
        }

        // Build environment variables
        // Note: Setting env overrides image ENV, so we include common vars
        let mut env: Vec<String> = Vec::new();
        // Use challenge NAME (not UUID) so validators can match events by name
        env.push(format!("CHALLENGE_ID={}", config.name));
        // Also pass the UUID for broker authentication (JWT token uses UUID)
        env.push(format!("CHALLENGE_UUID={}", config.challenge_id));
        env.push(format!("MECHANISM_ID={}", config.mechanism_id));
        // Pass through important environment variables from image defaults
        env.push("TASKS_DIR=/app/data/tasks".to_string());
        env.push("DATA_DIR=/data".to_string());
        // Set RUST_LOG based on VERBOSE env var
        let rust_log = if std::env::var("VERBOSE").is_ok() {
            "debug,hyper=info,h2=info,tower=info,tokio_postgres=debug".to_string()
        } else {
            "info,term_challenge=debug".to_string()
        };
        env.push(format!("RUST_LOG={}", rust_log));
        // Force challenge server to listen on port 8080 (orchestrator expects this)
        env.push("PORT=8080".to_string());
        // For Docker-in-Docker: use Docker volume paths on host
        // The HOST_*_DIR tells the challenge how to map container paths to host paths for DinD
        env.push("HOST_TASKS_DIR=/var/lib/docker/volumes/term-challenge-tasks/_data".to_string());
        env.push("HOST_CACHE_DIR=/var/lib/docker/volumes/term-challenge-cache/_data".to_string());
        env.push("CACHE_DIR=/root/.cache/term-challenge".to_string());
        env.push(
            "HOST_BENCHMARK_RESULTS_DIR=/var/lib/docker/volumes/term-challenge-evals/_data"
                .to_string(),
        );
        env.push("BENCHMARK_RESULTS_DIR=/tmp/term-challenge-evals".to_string());
        // Pass through DEVELOPMENT_MODE for local image support
        if let Ok(dev_mode) = std::env::var("DEVELOPMENT_MODE") {
            env.push(format!("DEVELOPMENT_MODE={}", dev_mode));
        }
        // Pass validator hotkey (from platform validator) for P2P signing
        if let Ok(validator_hotkey) = std::env::var("VALIDATOR_HOTKEY") {
            env.push(format!("VALIDATOR_HOTKEY={}", validator_hotkey));
        }
        // Pass validator secret key for signing requests (needed by challenge validator workers)
        if let Ok(validator_secret) = std::env::var("VALIDATOR_SECRET_KEY") {
            env.push(format!("VALIDATOR_SECRET={}", validator_secret));
        }
        // Pass owner/sudo hotkey for challenge sudo operations
        if let Ok(owner_hotkey) = std::env::var("OWNER_HOTKEY") {
            env.push(format!("OWNER_HOTKEY={}", owner_hotkey));
        }
        // Pass broadcast secret for event broadcasting (P2P gossipsub)
        if let Ok(broadcast_secret) = std::env::var("BROADCAST_SECRET") {
            env.push(format!("BROADCAST_SECRET={}", broadcast_secret));
        }
        // Optional: Pass DATABASE_URL for challenges that need external database storage.
        // Note: In a decentralized architecture, challenges should prefer local/embedded storage.
        // This is provided for backward compatibility with challenges that require SQL databases.
        if let Ok(db_url) = std::env::var("DATABASE_URL") {
            // Replace database name with challenge-specific name
            let challenge_db_name = config.name.to_lowercase().replace(['-', ' '], "_");
            if let Some(last_slash) = db_url.rfind('/') {
                let base_url = &db_url[..last_slash];
                let challenge_db_url = format!("{}/{}", base_url, challenge_db_name);
                env.push(format!("DATABASE_URL={}", challenge_db_url));
                debug!(challenge = %config.name, db = %challenge_db_name, "Set challenge DATABASE_URL");
            } else {
                // No slash found, just append
                env.push(format!("DATABASE_URL={}/{}", db_url, challenge_db_name));
            }
        }
        // Local hostname for broker (always local to validator container)
        // Priority: VALIDATOR_NAME -> VALIDATOR_CONTAINER_NAME -> system hostname
        let platform_host = std::env::var("VALIDATOR_NAME")
            .map(|name| format!("platform-{}", name))
            .unwrap_or_else(|_| {
                std::env::var("VALIDATOR_CONTAINER_NAME").unwrap_or_else(|_| {
                    // Fallback to actual hostname of current container
                    hostname::get()
                        .ok()
                        .and_then(|h| h.into_string().ok())
                        .unwrap_or_else(|| "localhost".to_string())
                })
            });

        // PLATFORM_PUBLIC_URL can be used for external access if needed
        let platform_url = std::env::var("PLATFORM_PUBLIC_URL").unwrap_or_else(|_| String::new());
        if !platform_url.is_empty() {
            env.push(format!("PLATFORM_URL={}", platform_url));
        }

        // Pass Container Broker WebSocket URL for secure container spawning
        // Challenges connect to this broker instead of using Docker socket directly
        // Note: Broker is always local, not affected by PLATFORM_PUBLIC_URL
        let broker_port = std::env::var("BROKER_WS_PORT").unwrap_or_else(|_| "8090".to_string());
        env.push(format!(
            "CONTAINER_BROKER_WS_URL=ws://{}:{}",
            platform_host, broker_port
        ));

        // Pass JWT token for broker authentication
        // Use BROKER_JWT_SECRET if set, otherwise generate a random one
        let jwt_secret = std::env::var("BROKER_JWT_SECRET").unwrap_or_else(|_| {
            use std::sync::OnceLock;
            static RANDOM_SECRET: OnceLock<String> = OnceLock::new();
            RANDOM_SECRET
                .get_or_init(|| {
                    let secret = uuid::Uuid::new_v4().to_string();
                    info!("Generated random BROKER_JWT_SECRET for this session");
                    secret
                })
                .clone()
        });

        // Generate a JWT token for this challenge
        // Token includes challenge_id and validator_hotkey for authorization
        // Use config.name (human-readable challenge name) instead of config.challenge_id (UUID)
        // This ensures JWT matches the challenge_id sent by the challenge container
        let challenge_id = config.name.to_string();
        let owner_id = std::env::var("VALIDATOR_HOTKEY").unwrap_or_else(|_| "unknown".to_string());

        // Use secure_container_runtime to generate token (10 years TTL - effectively infinite for container lifetime)
        if let Ok(token) = secure_container_runtime::generate_token(
            &challenge_id,
            &owner_id,
            &jwt_secret,
            315360000,
        ) {
            env.push(format!("CONTAINER_BROKER_JWT={}", token));
            debug!(challenge = %config.name, "Generated broker JWT token");
        } else {
            warn!(challenge = %config.name, "Failed to generate broker JWT token");
        }

        // Pass through EXTRA_* environment variables to challenge containers
        // This allows the platform server to pass custom configuration to challenges
        for (key, value) in std::env::vars() {
            if key.starts_with("EXTRA_") {
                env.push(format!("{}={}", key, value));
                debug!(challenge = %config.name, key = %key, "Passing extra env var to challenge");
            }
        }

        // Create container config
        let container_config = Config {
            image: Some(config.docker_image.clone()),
            hostname: Some(container_name.clone()),
            env: Some(env),
            host_config: Some(host_config),
            exposed_ports: Some({
                let mut ports = HashMap::new();
                ports.insert("8080/tcp".to_string(), HashMap::new());
                ports
            }),
            ..Default::default()
        };

        // Create container
        let options = CreateContainerOptions {
            name: container_name.clone(),
            platform: None,
        };

        let response = self
            .docker
            .create_container(Some(options), container_config)
            .await
            .map_err(anyhow::Error::from)?;
        let container_id = response.id;

        // Start container
        self.docker
            .start_container(&container_id, None::<StartContainerOptions<String>>)
            .await
            .map_err(anyhow::Error::from)?;

        // Get assigned port
        let inspect = self
            .docker
            .inspect_container(&container_id, None)
            .await
            .map_err(anyhow::Error::from)?;
        let port = inspect
            .network_settings
            .and_then(|ns| ns.ports)
            .and_then(|ports| ports.get("8080/tcp").cloned())
            .flatten()
            .and_then(|bindings| bindings.first().cloned())
            .and_then(|binding| binding.host_port)
            .unwrap_or_else(|| "8080".to_string());

        // Use container name for endpoint when running in Docker network
        // This allows validator containers to reach challenge containers
        let endpoint = format!("http://{}:8080", container_name);

        info!(
            container_id = %container_id,
            endpoint = %endpoint,
            host_port = %port,
            "Challenge container started"
        );

        Ok(ChallengeInstance {
            challenge_id: config.challenge_id,
            container_id,
            image: config.docker_image.clone(),
            endpoint,
            started_at: chrono::Utc::now(),
            status: ContainerStatus::Starting,
        })
    }

    /// Stop a container
    pub async fn stop_container(&self, container_id: &str) -> anyhow::Result<()> {
        let options = StopContainerOptions { t: 30 };

        match self
            .docker
            .stop_container(container_id, Some(options))
            .await
        {
            Ok(_) => {
                debug!(container_id = %container_id, "Container stopped");
                Ok(())
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 304, ..
            }) => {
                // Already stopped
                Ok(())
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {
                // Not found
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Remove a container
    pub async fn remove_container(&self, container_id: &str) -> anyhow::Result<()> {
        let options = RemoveContainerOptions {
            force: true,
            ..Default::default()
        };

        match self
            .docker
            .remove_container(container_id, Some(options))
            .await
        {
            Ok(_) => {
                debug!(container_id = %container_id, "Container removed");
                Ok(())
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {
                // Not found
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Check if a container is running
    pub async fn is_container_running(&self, container_id: &str) -> anyhow::Result<bool> {
        match self.docker.inspect_container(container_id, None).await {
            Ok(info) => {
                let running = info.state.and_then(|s| s.running).unwrap_or(false);
                Ok(running)
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// List all challenge containers
    pub async fn list_challenge_containers(&self) -> anyhow::Result<Vec<String>> {
        let mut filters: HashMap<String, Vec<String>> = HashMap::new();
        filters.insert("name".to_string(), vec!["challenge-".to_string()]);
        filters.insert("network".to_string(), vec![self.network_name.clone()]);

        let options = ListContainersOptions::<String> {
            all: true,
            filters,
            ..Default::default()
        };

        let containers = self
            .docker
            .list_containers(Some(options))
            .await
            .map_err(anyhow::Error::from)?;

        Ok(containers.into_iter().filter_map(|c| c.id).collect())
    }

    /// Get container logs
    pub async fn get_logs(&self, container_id: &str, tail: usize) -> anyhow::Result<String> {
        use futures::TryStreamExt;

        let options = LogsOptions::<String> {
            stdout: true,
            stderr: true,
            tail: tail.to_string(),
            ..Default::default()
        };

        let logs: Vec<_> = self
            .docker
            .logs_stream(container_id, options)
            .try_collect()
            .await?;

        let output = logs
            .into_iter()
            .map(|log| log.to_string())
            .collect::<Vec<_>>()
            .join("");

        Ok(output)
    }

    /// Clean up stale task containers created by challenge evaluations
    ///
    /// This removes containers that match the pattern but excludes:
    /// - Main challenge containers (challenge-*)
    /// - Platform validator containers
    /// - Watchtower containers
    ///
    /// Parameters:
    /// - `prefix`: Container name prefix to match (e.g., "term-challenge-")
    /// - `max_age_minutes`: Only remove containers older than this (0 = remove all matching)
    /// - `exclude_patterns`: Container names containing these patterns will be kept
    pub async fn cleanup_stale_containers(
        &self,
        prefix: &str,
        max_age_minutes: u64,
        exclude_patterns: &[&str],
    ) -> anyhow::Result<CleanupResult> {
        let mut result = CleanupResult::default();

        // List ALL containers (including stopped)
        let options: ListContainersOptions<String> = ListContainersOptions {
            all: true,
            ..Default::default()
        };

        let containers = self
            .docker
            .list_containers(Some(options))
            .await
            .map_err(anyhow::Error::from)?;
        let now = chrono::Utc::now().timestamp();
        let max_age_secs = (max_age_minutes * 60) as i64;

        for container in containers {
            let names = container.names.unwrap_or_default();
            let container_id = match container.id.as_ref() {
                Some(id) => id.clone(),
                None => continue,
            };

            // Check if container name matches prefix
            let matches_prefix = names.iter().any(|name| {
                let clean_name = name.trim_start_matches('/');
                clean_name.starts_with(prefix)
            });

            if !matches_prefix {
                continue;
            }

            // Check exclusion patterns
            let is_excluded = names.iter().any(|name| {
                let clean_name = name.trim_start_matches('/');
                exclude_patterns
                    .iter()
                    .any(|pattern| clean_name.contains(pattern))
            });

            if is_excluded {
                debug!(container = ?names, "Skipping excluded container");
                continue;
            }

            // Check age if max_age_minutes > 0
            if max_age_minutes > 0 {
                let created = container.created.unwrap_or(0);
                let age_secs = now - created;
                if age_secs < max_age_secs {
                    debug!(container = ?names, age_secs, "Container too young, skipping");
                    continue;
                }
            }

            // Remove the container
            result.total_found += 1;
            match self.remove_container(&container_id).await {
                Ok(_) => {
                    info!(container = ?names, "Removed stale container");
                    result.removed += 1;
                }
                Err(e) => {
                    warn!(container = ?names, error = %e, "Failed to remove container");
                    result.errors.push(format!("{:?}: {}", names, e));
                }
            }
        }

        if result.removed > 0 {
            info!(
                "Cleanup complete: removed {}/{} stale containers",
                result.removed, result.total_found
            );
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::EndpointSettings;
    use futures::StreamExt;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn reset_env(keys: &[&str]) {
        for key in keys {
            std::env::remove_var(key);
        }
    }

    #[test]
    #[serial]
    fn test_is_image_allowed_enforces_whitelist() {
        reset_env(&["DEVELOPMENT_MODE"]);
        assert!(DockerClient::is_image_allowed(
            "ghcr.io/platformnetwork/challenge:latest"
        ));
        assert!(!DockerClient::is_image_allowed(
            "docker.io/library/alpine:latest"
        ));
    }

    #[test]
    #[serial]
    fn test_is_image_allowed_allows_dev_mode_override() {
        std::env::set_var("DEVELOPMENT_MODE", "true");
        assert!(DockerClient::is_image_allowed(
            "docker.io/library/alpine:latest"
        ));
        reset_env(&["DEVELOPMENT_MODE"]);
    }

    #[test]
    #[serial]
    fn test_is_image_allowed_case_insensitive() {
        reset_env(&["DEVELOPMENT_MODE"]);
        assert!(DockerClient::is_image_allowed(
            "GHCR.IO/PLATFORMNETWORK/IMAGE:TAG"
        ));
    }

    #[test]
    #[serial]
    fn test_get_validator_suffix_prefers_validator_name() {
        reset_env(&["VALIDATOR_NAME", "HOSTNAME"]);
        std::env::set_var("VALIDATOR_NAME", "Node 42-Test");
        std::env::set_var("HOSTNAME", "should_not_be_used");

        let suffix = DockerClient::get_validator_suffix();
        assert_eq!(suffix, "node42test");

        reset_env(&["VALIDATOR_NAME", "HOSTNAME"]);
    }

    #[test]
    #[serial]
    fn test_get_validator_suffix_uses_container_id_from_hostname() {
        reset_env(&["VALIDATOR_NAME"]);
        std::env::set_var("HOSTNAME", "abcdef123456");

        let suffix = DockerClient::get_validator_suffix();
        assert_eq!(suffix, "abcdef123456");

        reset_env(&["HOSTNAME"]);
    }

    #[test]
    #[serial]
    fn test_extra_env_vars_collected() {
        // Clean up any existing EXTRA_ vars
        for (key, _) in std::env::vars() {
            if key.starts_with("EXTRA_") {
                std::env::remove_var(&key);
            }
        }

        // Set test EXTRA_ variables
        std::env::set_var("EXTRA_DEBUG", "1");
        std::env::set_var("EXTRA_CUSTOM_API_KEY", "test_key_123");
        std::env::set_var("NOT_EXTRA_VAR", "should_not_be_included");

        // Collect EXTRA_ vars the same way as in start_challenge
        let mut env: Vec<String> = Vec::new();
        for (key, value) in std::env::vars() {
            if key.starts_with("EXTRA_") {
                env.push(format!("{}={}", key, value));
            }
        }

        // Verify EXTRA_ vars are collected
        assert!(env.iter().any(|e| e == "EXTRA_DEBUG=1"));
        assert!(env.iter().any(|e| e == "EXTRA_CUSTOM_API_KEY=test_key_123"));
        assert!(!env.iter().any(|e| e.contains("NOT_EXTRA_VAR")));

        // Clean up
        std::env::remove_var("EXTRA_DEBUG");
        std::env::remove_var("EXTRA_CUSTOM_API_KEY");
        std::env::remove_var("NOT_EXTRA_VAR");
    }

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn test_docker_connect() {
        let client = DockerClient::connect().await;
        assert!(client.is_ok());
    }

    #[derive(Clone, Default)]
    struct RecordingBridge {
        inner: Arc<RecordingBridgeInner>,
    }

    #[derive(Default)]
    struct RecordingBridgeInner {
        networks: Mutex<Vec<Network>>,
        created_networks: Mutex<Vec<String>>,
        containers: Mutex<Vec<ContainerSummary>>,
        removed: Mutex<Vec<String>>,
        inspect_map: Mutex<HashMap<String, ContainerInspectResponse>>,
        connect_calls: Mutex<Vec<(String, String)>>,
    }

    impl RecordingBridge {
        fn with_networks(names: &[&str]) -> Self {
            let bridge = RecordingBridge::default();
            {
                let mut lock = bridge.inner.networks.lock().unwrap();
                for name in names {
                    lock.push(Network {
                        name: Some(name.to_string()),
                        ..Default::default()
                    });
                }
            }
            bridge
        }

        fn created_networks(&self) -> Vec<String> {
            self.inner.created_networks.lock().unwrap().clone()
        }

        fn set_inspect_networks(&self, container_id: &str, networks: &[&str]) {
            let mut map: HashMap<String, EndpointSettings> = HashMap::new();
            for name in networks {
                map.insert(name.to_string(), Default::default());
            }
            let response = ContainerInspectResponse {
                network_settings: Some(bollard::models::NetworkSettings {
                    networks: Some(map),
                    ..Default::default()
                }),
                ..Default::default()
            };
            self.inner
                .inspect_map
                .lock()
                .unwrap()
                .insert(container_id.to_string(), response);
        }

        fn set_containers(&self, containers: Vec<ContainerSummary>) {
            *self.inner.containers.lock().unwrap() = containers;
        }

        fn removed_containers(&self) -> Vec<String> {
            self.inner.removed.lock().unwrap().clone()
        }

        fn connect_calls(&self) -> Vec<(String, String)> {
            self.inner.connect_calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DockerBridge for RecordingBridge {
        async fn ping(&self) -> Result<(), DockerError> {
            Ok(())
        }

        async fn list_networks(
            &self,
            _options: Option<ListNetworksOptions<String>>,
        ) -> Result<Vec<Network>, DockerError> {
            Ok(self.inner.networks.lock().unwrap().clone())
        }

        async fn create_network(
            &self,
            options: CreateNetworkOptions<String>,
        ) -> Result<(), DockerError> {
            self.inner
                .created_networks
                .lock()
                .unwrap()
                .push(options.name);
            Ok(())
        }

        async fn inspect_container(
            &self,
            id: &str,
            _options: Option<InspectContainerOptions>,
        ) -> Result<ContainerInspectResponse, DockerError> {
            self.inner
                .inspect_map
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .ok_or_else(|| DockerError::IOError {
                    err: std::io::Error::new(std::io::ErrorKind::NotFound, "missing inspect"),
                })
        }

        async fn connect_network(
            &self,
            network: &str,
            options: ConnectNetworkOptions<String>,
        ) -> Result<(), DockerError> {
            self.inner
                .connect_calls
                .lock()
                .unwrap()
                .push((options.container, network.to_string()));
            Ok(())
        }

        fn create_image_stream(&self, _options: Option<CreateImageOptions<String>>) -> ImageStream {
            futures::stream::empty().boxed()
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
            panic!("not used in tests")
        }

        async fn start_container(
            &self,
            _id: &str,
            _options: Option<StartContainerOptions<String>>,
        ) -> Result<(), DockerError> {
            panic!("not used in tests")
        }

        async fn stop_container(
            &self,
            _id: &str,
            _options: Option<StopContainerOptions>,
        ) -> Result<(), DockerError> {
            panic!("not used in tests")
        }

        async fn remove_container(
            &self,
            id: &str,
            _options: Option<RemoveContainerOptions>,
        ) -> Result<(), DockerError> {
            self.inner.removed.lock().unwrap().push(id.to_string());
            Ok(())
        }

        async fn list_containers(
            &self,
            _options: Option<ListContainersOptions<String>>,
        ) -> Result<Vec<ContainerSummary>, DockerError> {
            Ok(self.inner.containers.lock().unwrap().clone())
        }

        fn logs_stream(&self, _id: &str, _options: LogsOptions<String>) -> LogStream {
            futures::stream::empty().boxed()
        }
    }

    #[tokio::test]
    async fn test_ensure_network_creates_when_missing() {
        let bridge = RecordingBridge::default();
        let client = DockerClient::with_bridge(bridge.clone(), "platform-network");
        client.ensure_network().await.unwrap();
        assert_eq!(
            bridge.created_networks(),
            vec!["platform-network".to_string()]
        );
    }

    #[tokio::test]
    async fn test_ensure_network_skips_existing() {
        let bridge = RecordingBridge::with_networks(&["platform-network"]);
        let client = DockerClient::with_bridge(bridge.clone(), "platform-network");
        client.ensure_network().await.unwrap();
        assert!(bridge.created_networks().is_empty());
    }

    #[tokio::test]
    #[serial]
    async fn test_connect_self_to_network_only_when_needed() {
        let bridge = RecordingBridge::default();
        let container_id = "aaaaaaaaaaaa";
        std::env::set_var("HOSTNAME", container_id);
        bridge.set_inspect_networks(container_id, &[]);
        let client = DockerClient::with_bridge(bridge.clone(), "platform-network");
        client.connect_self_to_network().await.unwrap();
        assert_eq!(
            bridge.connect_calls(),
            vec![(container_id.to_string(), "platform-network".to_string())]
        );

        let bridge2 = RecordingBridge::default();
        let container_two = "bbbbbbbbbbbb";
        std::env::set_var("HOSTNAME", container_two);
        bridge2.set_inspect_networks(container_two, &["platform-network"]);
        let client2 = DockerClient::with_bridge(bridge2.clone(), "platform-network");
        client2.connect_self_to_network().await.unwrap();
        assert!(bridge2.connect_calls().is_empty());
        std::env::remove_var("HOSTNAME");
    }

    fn make_container_summary(id: &str, name: &str, created: i64) -> ContainerSummary {
        ContainerSummary {
            id: Some(id.to_string()),
            names: Some(vec![format!("/{name}")]),
            created: Some(created),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_cleanup_stale_containers_filters_entries() {
        let bridge = RecordingBridge::default();
        let now = chrono::Utc::now().timestamp();
        bridge.set_containers(vec![
            make_container_summary("old", "term-challenge-old", now - 10_000),
            make_container_summary("exclude", "platform-helper", now - 10_000),
            make_container_summary("young", "term-challenge-young", now - 100),
        ]);
        let client = DockerClient::with_bridge(bridge.clone(), "platform-network");

        let result = client
            .cleanup_stale_containers("term-challenge-", 120, &["platform-"])
            .await
            .unwrap();
        assert_eq!(result.total_found, 1);
        assert_eq!(result.removed, 1);
        assert_eq!(bridge.removed_containers(), vec!["old".to_string()]);
    }
}

/// Result of container cleanup operation
#[derive(Debug, Default, Clone)]
pub struct CleanupResult {
    pub total_found: usize,
    pub removed: usize,
    pub errors: Vec<String>,
}

impl CleanupResult {
    pub fn success(&self) -> bool {
        self.errors.is_empty()
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::CleanupResult;

    #[test]
    fn test_cleanup_result_success_flag() {
        let mut result = CleanupResult::default();
        assert!(result.success());

        result.errors.push("boom".into());
        assert!(!result.success());
    }
}
