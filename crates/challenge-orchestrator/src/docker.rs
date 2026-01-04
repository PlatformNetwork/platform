//! Docker client wrapper for container management
//!
//! SECURITY: Only images from whitelisted registries (ghcr.io/platformnetwork/)
//! are allowed to be pulled or run. This prevents malicious container attacks.

use crate::{ChallengeContainerConfig, ChallengeInstance, ContainerStatus};
use bollard::container::{
    Config, CreateContainerOptions, ListContainersOptions, RemoveContainerOptions,
    StartContainerOptions, StopContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::{DeviceRequest, HostConfig, PortBinding};
use bollard::Docker;
use futures::StreamExt;
use platform_core::ALLOWED_DOCKER_PREFIXES;
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

/// Docker client for managing challenge containers
pub struct DockerClient {
    docker: Docker,
    network_name: String,
}

impl DockerClient {
    /// Connect to Docker daemon
    pub async fn connect() -> anyhow::Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;

        // Verify connection
        docker.ping().await?;
        info!("Connected to Docker daemon");

        Ok(Self {
            docker,
            network_name: "platform-network".to_string(),
        })
    }

    /// Connect with custom network name
    pub async fn connect_with_network(network_name: &str) -> anyhow::Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;
        docker.ping().await?;

        Ok(Self {
            docker,
            network_name: network_name.to_string(),
        })
    }

    /// Connect and auto-detect the network from the validator container
    /// This ensures challenge containers are on the same network as the validator
    pub async fn connect_auto_detect() -> anyhow::Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;
        docker.ping().await?;
        info!("Connected to Docker daemon");

        // Try to detect the network from the current container
        let network_name = Self::detect_validator_network_static(&docker)
            .await
            .unwrap_or_else(|e| {
                warn!(
                    "Could not detect validator network: {}. Using default 'platform-network'",
                    e
                );
                "platform-network".to_string()
            });

        info!(network = %network_name, "Using network for challenge containers");

        Ok(Self {
            docker,
            network_name,
        })
    }

    /// Detect the network the validator container is running on
    async fn detect_validator_network_static(docker: &Docker) -> anyhow::Result<String> {
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

        for (name, _settings) in networks {
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
        let networks = self.docker.list_networks::<String>(None).await?;

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

            self.docker.create_network(config).await?;
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
        let inspect = self.docker.inspect_container(&container_id, None).await?;
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
            .await?;

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
            from_image: image,
            ..Default::default()
        };

        let mut stream = self.docker.create_image(Some(options), None, None);

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
        let volume_opts = bollard::volume::CreateVolumeOptions {
            name: volume_name.as_str(),
            driver: "local",
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
        let cache_volume_opts = bollard::volume::CreateVolumeOptions {
            name: cache_volume_name.as_str(),
            driver: "local",
            ..Default::default()
        };
        if let Err(e) = self.docker.create_volume(cache_volume_opts).await {
            debug!("Volume creation result for {}: {:?}", cache_volume_name, e);
        }

        // Build host config with resource limits
        let mut host_config = HostConfig {
            network_mode: Some(self.network_name.clone()),
            port_bindings: Some(port_bindings),
            nano_cpus: Some((config.cpu_cores * 1_000_000_000.0) as i64),
            memory: Some((config.memory_mb * 1024 * 1024) as i64),
            // Mount Docker socket for challenge containers to run agent evaluations
            // Mount tasks directory both to internal path AND to host path for Docker-in-Docker
            // Mount persistent Docker volume for challenge state (evaluation progress, etc.)
            binds: Some(vec![
                "/var/run/docker.sock:/var/run/docker.sock:rw".to_string(),
                "/tmp/platform-tasks:/app/data/tasks:rw".to_string(), // Override internal tasks
                "/tmp/platform-tasks:/tmp/platform-tasks:rw".to_string(), // For DinD path mapping
                "/tmp/platform-cache:/root/.cache/term-challenge:rw".to_string(), // Cache bind mount for DinD
                "/tmp/platform-cache:/tmp/platform-cache:rw".to_string(), // For DinD path mapping
                "/tmp/platform-evals:/tmp/term-challenge-evals:rw".to_string(), // Eval logs for DinD
                "/tmp/platform-evals:/tmp/platform-evals:rw".to_string(), // For DinD path mapping
                format!("{}:/data:rw", volume_name), // Named volume for persistent state
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
        // For Docker-in-Docker: tasks are at /host-tasks on host (we mount below)
        // The HOST_TASKS_DIR tells the challenge how to map container paths to host paths
        env.push("HOST_TASKS_DIR=/tmp/platform-tasks".to_string());
        // For Docker-in-Docker: cache directory mapping (for downloaded datasets)
        env.push("HOST_CACHE_DIR=/tmp/platform-cache".to_string());
        env.push("CACHE_DIR=/root/.cache/term-challenge".to_string());
        // For Docker-in-Docker: eval logs directory mapping
        env.push("HOST_BENCHMARK_RESULTS_DIR=/tmp/platform-evals".to_string());
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
        // Pass broadcast secret for event broadcasting to platform-server
        if let Ok(broadcast_secret) = std::env::var("BROADCAST_SECRET") {
            env.push(format!("BROADCAST_SECRET={}", broadcast_secret));
        }
        // Pass DATABASE_URL with challenge-specific database name
        if let Ok(db_url) = std::env::var("DATABASE_URL") {
            // Replace database name with challenge name
            // Format: postgresql://user:pass@host:port/dbname -> postgresql://user:pass@host:port/challenge_name
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
        // Local hostname for broker (always local)
        let platform_host = std::env::var("VALIDATOR_NAME")
            .map(|name| format!("platform-{}", name))
            .unwrap_or_else(|_| {
                std::env::var("VALIDATOR_CONTAINER_NAME")
                    .unwrap_or_else(|_| "platform-server".to_string())
            });

        // Pass Platform URL for metagraph verification and API calls
        // Priority: PLATFORM_PUBLIC_URL (for validators to reach owner's server) > local
        let platform_url = std::env::var("PLATFORM_PUBLIC_URL")
            .unwrap_or_else(|_| format!("http://{}:8080", platform_host));
        env.push(format!("PLATFORM_URL={}", platform_url));

        // Pass Container Broker WebSocket URL for secure container spawning
        // Challenges connect to this broker instead of using Docker socket directly
        // Note: Broker is always local, not affected by PLATFORM_PUBLIC_URL
        let broker_port = std::env::var("BROKER_WS_PORT").unwrap_or_else(|_| "8090".to_string());
        env.push(format!(
            "CONTAINER_BROKER_WS_URL=ws://{}:{}",
            platform_host, broker_port
        ));

        // Pass JWT token for broker authentication (if set)
        if let Ok(jwt_secret) = std::env::var("BROKER_JWT_SECRET") {
            // Generate a JWT token for this challenge
            // Token includes challenge_id and validator_hotkey for authorization
            let challenge_id = config.challenge_id.to_string();
            let owner_id =
                std::env::var("VALIDATOR_HOTKEY").unwrap_or_else(|_| "unknown".to_string());

            // Use secure_container_runtime to generate token (3600s = 1 hour TTL)
            if let Ok(token) = secure_container_runtime::generate_token(
                &challenge_id,
                &owner_id,
                &jwt_secret,
                3600,
            ) {
                env.push(format!("CONTAINER_BROKER_JWT={}", token));
                debug!(challenge = %config.name, "Generated broker JWT token");
            } else {
                warn!(challenge = %config.name, "Failed to generate broker JWT token");
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
            name: &container_name,
            platform: None,
        };

        let response = self
            .docker
            .create_container(Some(options), container_config)
            .await?;
        let container_id = response.id;

        // Start container
        self.docker
            .start_container(&container_id, None::<StartContainerOptions<String>>)
            .await?;

        // Get assigned port
        let inspect = self.docker.inspect_container(&container_id, None).await?;
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
        let mut filters = HashMap::new();
        filters.insert("name", vec!["challenge-"]);
        filters.insert("network", vec![self.network_name.as_str()]);

        let options = ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        };

        let containers = self.docker.list_containers(Some(options)).await?;

        Ok(containers.into_iter().filter_map(|c| c.id).collect())
    }

    /// Get container logs
    pub async fn get_logs(&self, container_id: &str, tail: usize) -> anyhow::Result<String> {
        use bollard::container::LogsOptions;
        use futures::TryStreamExt;

        let options = LogsOptions::<String> {
            stdout: true,
            stderr: true,
            tail: tail.to_string(),
            ..Default::default()
        };

        let logs: Vec<_> = self
            .docker
            .logs(container_id, Some(options))
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
        let options = ListContainersOptions::<String> {
            all: true,
            ..Default::default()
        };

        let containers = self.docker.list_containers(Some(options)).await?;
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

/// Result of container cleanup operation
#[derive(Debug, Default)]
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
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn test_docker_connect() {
        let client = DockerClient::connect().await;
        assert!(client.is_ok());
    }
}
