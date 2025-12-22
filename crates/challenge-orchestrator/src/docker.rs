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
            network_name: "platformchain".to_string(),
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

        // Generate container name with validator identifier for dev mode
        // In dev mode with shared Docker socket, each validator needs unique container names
        let validator_suffix = std::env::var("VALIDATOR_NAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| format!("{:x}", std::process::id()));
        let container_name = format!(
            "challenge-{}-{}",
            config.name.to_lowercase().replace(' ', "-"),
            validator_suffix.to_lowercase().replace("-", "").replace(" ", "")
        );

        // Remove existing container if any
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

        // Build host config with resource limits
        let mut host_config = HostConfig {
            network_mode: Some(self.network_name.clone()),
            port_bindings: Some(port_bindings),
            nano_cpus: Some((config.cpu_cores * 1_000_000_000.0) as i64),
            memory: Some((config.memory_mb * 1024 * 1024) as i64),
            // Mount Docker socket for challenge containers to run agent evaluations
            // Mount tasks directory both to internal path AND to host path for Docker-in-Docker
            binds: Some(vec![
                "/var/run/docker.sock:/var/run/docker.sock:rw".to_string(),
                "/tmp/platform-tasks:/app/data/tasks:rw".to_string(),  // Override internal tasks
                "/tmp/platform-tasks:/tmp/platform-tasks:rw".to_string(),  // For DinD path mapping
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
        env.push(format!("CHALLENGE_ID={}", config.challenge_id));
        env.push(format!("MECHANISM_ID={}", config.mechanism_id));
        // Pass through important environment variables from image defaults
        env.push("TASKS_DIR=/app/data/tasks".to_string());
        env.push("DATA_DIR=/data".to_string());
        env.push("RUST_LOG=info,term_challenge=debug".to_string());
        // For Docker-in-Docker: tasks are at /host-tasks on host (we mount below)
        // The HOST_TASKS_DIR tells the challenge how to map container paths to host paths
        env.push("HOST_TASKS_DIR=/tmp/platform-tasks".to_string());
        // Pass through DEVELOPMENT_MODE for local image support
        if let Ok(dev_mode) = std::env::var("DEVELOPMENT_MODE") {
            env.push(format!("DEVELOPMENT_MODE={}", dev_mode));
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
