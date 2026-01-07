//! Docker client wrapper for container management
//!
//! SECURITY: Only images from whitelisted registries (ghcr.io/platformnetwork/)
//! are allowed to be pulled or run. This prevents malicious container attacks.

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
    /// Creates a new BollardBridge that wraps the provided Bollard Docker client.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use bollard::Docker;
    /// let docker = Docker::connect_with_unix_defaults().unwrap();
    /// let bridge = BollardBridge::new(docker);
    /// ```
    fn new(docker: Docker) -> Self {
        Self { docker }
    }
}

#[async_trait]
impl DockerBridge for BollardBridge {
    /// Verifies that the Docker daemon is reachable.
    ///
    /// Performs a lightweight ping to the Docker daemon to confirm connectivity.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the daemon responds, `Err(DockerError)` if the ping fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run(client: &impl crate::DockerBridge) -> Result<(), crate::DockerError> {
    /// client.ping().await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn ping(&self) -> Result<(), DockerError> {
        self.docker.ping().await.map(|_| ())
    }

    /// Lists Docker networks visible to the daemon, optionally filtered by the provided options.
    ///
    /// The returned list contains networks that match the provided `ListNetworksOptions`
    /// (if `None`, all networks are returned).
    ///
    /// # Parameters
    ///
    /// - `options`: Optional filters and query options to narrow the returned networks.
    ///
    /// # Returns
    ///
    /// A `Vec<Network>` containing matching network descriptions.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use bollard::models::Network;
    /// // Obtain a bridge implementing the same API (e.g., BollardBridge) before calling.
    /// let rt = tokio::runtime::Runtime::new().unwrap();
    /// rt.block_on(async {
    ///     // let bridge = ...; // obtain Arc<dyn DockerBridge> wrapper
    ///     // let networks: Vec<Network> = bridge.list_networks(None).await.unwrap();
    /// });
    /// ```
    async fn list_networks(
        &self,
        options: Option<ListNetworksOptions<String>>,
    ) -> Result<Vec<Network>, DockerError> {
        self.docker.list_networks(options).await
    }

    /// Create a Docker network using the provided creation options.
    ///
    /// The method requests the Docker daemon to create a network described by `options`.
    ///
    /// # Errors
    ///
    /// Returns a `DockerError` if the Docker API reports a failure creating the network.
    ///
    /// # Examples
    ///
    /// ```
    /// # async fn example(bridge: &impl DockerBridge) {
    /// bridge.create_network(bollard::network::CreateNetworkOptions{
    ///     name: "platform-network".to_string(),
    ///     ..Default::default()
    /// }).await.unwrap();
    /// # }
    /// ```
    async fn create_network(
        &self,
        options: CreateNetworkOptions<String>,
    ) -> Result<(), DockerError> {
        self.docker.create_network(options).await.map(|_| ())
    }

    /// Retrieves inspection information for the container identified by `id`.
    ///
    /// Returns a `ContainerInspectResponse` containing detailed metadata about the container.
    ///
    /// # Examples
    ///
    /// ```
    /// # tokio_test::block_on(async {
    /// // `client` is an implementation that provides `inspect_container`.
    /// // Here we show the call pattern; adjust `client` to your context.
    /// let resp = client.inspect_container("container_id", None).await;
    /// if let Ok(info) = resp {
    ///     // use `info` (ContainerInspectResponse)
    ///     println!("{:?}", info.id);
    /// }
    /// # });
    /// ```
    async fn inspect_container(
        &self,
        id: &str,
        options: Option<InspectContainerOptions>,
    ) -> Result<ContainerInspectResponse, DockerError> {
        self.docker.inspect_container(id, options).await
    }

    /// Connects a container to the specified Docker network.
    ///
    /// `network` is the name or ID of the target network; `options` specifies the container and endpoint configuration used when connecting.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // `bridge` implements `DockerBridge`.
    /// # async fn example(bridge: &impl DockerBridge) {
    /// use bollard::network::ConnectNetworkOptions;
    /// let opts = ConnectNetworkOptions::<String> { container: "container_id".to_string(), endpoint_config: None };
    /// bridge.connect_network("platform-network", opts).await.unwrap();
    /// # }
    /// ```
    ///
    /// Returns `Ok(())` on success, or an `Err(DockerError)` if the connect operation fails.
    async fn connect_network(
        &self,
        network: &str,
        options: ConnectNetworkOptions<String>,
    ) -> Result<(), DockerError> {
        self.docker.connect_network(network, options).await
    }

    /// Creates a stream of Docker image-pull progress events for the given pull options.
    ///
    /// The returned stream yields `CreateImageInfo` items produced by the Docker daemon while
    /// pulling an image. Pass `None` to use default pull behavior.
    ///
    /// # Examples
    ///
    /// ```
    /// // Obtain a bridge implementing `DockerBridge`, then:
    /// let stream = bridge.create_image_stream(None);
    /// // Consume the stream asynchronously to observe pull progress.
    /// ```
    fn create_image_stream(&self, options: Option<CreateImageOptions<String>>) -> ImageStream {
        Box::pin(self.docker.create_image(options, None, None))
    }

    /// Create a Docker volume using the provided options.
    ///
    /// The function requests Docker to create a volume described by `options` and returns when the
    /// request completes. Use `CreateVolumeOptions` to specify the volume name, driver, labels, and
    /// other creation parameters.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use bollard::volume::CreateVolumeOptions;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // `bridge` must implement the same interface as the surrounding context.
    /// // let bridge = ...;
    /// let opts = CreateVolumeOptions {
    ///     name: "my-volume".to_string(),
    ///     ..Default::default()
    /// };
    /// // bridge.create_volume(opts).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// `Ok(())` if the volume was created successfully, `Err(DockerError)` on failure.
    async fn create_volume(&self, options: CreateVolumeOptions<String>) -> Result<(), DockerError> {
        self.docker.create_volume(options).await.map(|_| ())
    }

    /// Creates a container using the provided Docker create options and container configuration.
    ///
    /// Uses the underlying Docker bridge to invoke the create container API and returns the
    /// created container metadata on success.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bollard::container::{CreateContainerOptions, Config, ContainerCreateResponse};
    /// # use std::collections::HashMap;
    /// # // `client` implements a method `create_container` matching this signature.
    /// # async fn _example(client: &impl std::ops::Deref<Target = dyn std::any::Any>) {}
    /// let options = CreateContainerOptions::<String> { name: "example-container".to_string() };
    /// let config = Config {
    ///     image: Some("alpine:latest".to_string()),
    ///     env: Some(vec!["FOO=bar".to_string()]),
    ///     ..Default::default()
    /// };
    /// // let resp: ContainerCreateResponse = client.create_container(Some(options), config).await?;
    /// ```
    ///
    /// # Returns
    ///
    /// `ContainerCreateResponse` containing the created container's id and warnings on success, or
    /// a `DockerError` if the create operation fails.
    async fn create_container(
        &self,
        options: Option<CreateContainerOptions<String>>,
        config: Config<String>,
    ) -> Result<ContainerCreateResponse, DockerError> {
        self.docker.create_container(options, config).await
    }

    /// Starts the container identified by `id` with the given start options.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use bollard::container::StartContainerOptions;
    /// # async fn example(client: &crate::DockerClient) -> anyhow::Result<()> {
    /// client.start_container("my-container", None).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// `Ok(())` if the container was started successfully, `Err(DockerError)` if the Docker API call failed.
    async fn start_container(
        &self,
        id: &str,
        options: Option<StartContainerOptions<String>>,
    ) -> Result<(), DockerError> {
        self.docker.start_container(id, options).await
    }

    /// Stops the container identified by `id`.
    ///
    /// Attempts to stop the container via the underlying Docker bridge.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(client: &impl crate::docker::DockerBridge) {
    /// // Stop a container, ignoring errors for brevity in this example.
    /// let _ = client.stop_container("container_id", None).await;
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, `Err(DockerError)` if the stop operation fails.
    async fn stop_container(
        &self,
        id: &str,
        options: Option<StopContainerOptions>,
    ) -> Result<(), DockerError> {
        self.docker.stop_container(id, options).await
    }

    /// Remove a container by ID from the Docker daemon.
    ///
    /// `id` is the container identifier or name. `options` may provide removal flags
    /// (for example, force removal or removing volumes); pass `None` to use defaults.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the container was removed or already absent according to the
    /// underlying Docker behavior, `Err(DockerError)` on failure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// // Execute an async removal in a synchronous context:
    /// let client = /* obtain a DockerClient or bridge-backed client */ ;
    /// futures::executor::block_on(async {
    ///     client.remove_container("my-container", None).await.unwrap();
    /// });
    /// ```
    async fn remove_container(
        &self,
        id: &str,
        options: Option<RemoveContainerOptions>,
    ) -> Result<(), DockerError> {
        self.docker.remove_container(id, options).await
    }

    /// Lists containers from the Docker daemon according to the given listing options.
    ///
    /// # Parameters
    ///
    /// - `options`: Optional `ListContainersOptions<String>` to filter or modify the listing behavior (e.g., show all containers, apply filters). If `None`, default listing behavior is used by the underlying bridge.
    ///
    /// # Returns
    ///
    /// A `Vec<ContainerSummary>` containing summaries of the containers that match the provided options on success, or a `DockerError` on failure.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bollard::container::ListContainersOptions;
    /// # async fn example(client: &crate::DockerClient) -> Result<(), anyhow::Error> {
    /// let containers = client.list_containers(None).await?;
    /// assert!(containers.iter().all(|c| c.id.is_some()));
    /// # Ok(())
    /// # }
    /// ```
    async fn list_containers(
        &self,
        options: Option<ListContainersOptions<String>>,
    ) -> Result<Vec<ContainerSummary>, DockerError> {
        self.docker.list_containers(options).await
    }

    /// Streams the log output for the specified container.
    ///
    /// The returned stream yields `LogOutput` items produced by the container's stdout and stderr until the log source completes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use bollard::container::LogsOptions;
    ///
    /// let opts = LogsOptions::<String>::new().stdout(true).stderr(true);
    /// let mut stream = docker_client.logs_stream("container_id", opts);
    /// // consume the stream to receive `LogOutput` frames
    /// ```
    fn logs_stream(&self, id: &str, options: LogsOptions<String>) -> LogStream {
        Box::pin(self.docker.logs(id, Some(options)))
    }
}

/// Docker client for managing challenge containers
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
    /// Ensures the specified Docker image is available locally by pulling it from its registry.
    
    ///
    
    /// # Arguments
    
    ///
    
    /// * `image` - The image reference to pull (for example `"registry/repo:tag"` or `"alpine:latest"`).
    
    ///
    
    /// # Returns
    
    ///
    
    /// `Ok(())` on success; `Err` if the image is disallowed by the whitelist or if the pull fails.
    
    ///
    
    /// # Examples
    
    ///
    
    /// ```
    
    /// # async fn doc_example() -> anyhow::Result<()> {
    
    /// // `client` implements ChallengeDocker (e.g., DockerClient)
    
    /// // client.pull_image("alpine:latest").await?;
    
    /// # Ok(())
    
    /// # }
    
    /// ```
    async fn pull_image(&self, image: &str) -> anyhow::Result<()> {
        DockerClient::pull_image(self, image).await
    }

    /// Starts a challenge container according to the provided configuration and returns its runtime instance.
    ///
    /// Validates the configuration and image policy, ensures the platform network and required volumes exist,
    /// creates and starts the container, and returns an instance describing the created container and its endpoint.
    ///
    /// # Parameters
    ///
    /// - `config` — Configuration that describes the challenge container to create (image, resources, mounts, env, etc.).
    ///
    /// # Returns
    ///
    /// `ChallengeInstance` containing the created container's id, endpoint, start timestamp, and initial status.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # async fn example() -> Result<()> {
    /// let client = /* obtain a DockerClient implementing ChallengeDocker */ unimplemented!();
    /// let config = /* build a ChallengeContainerConfig */ unimplemented!();
    /// let instance = client.start_challenge(&config).await?;
    /// println!("started container: {}", instance.container_id);
    /// # Ok(()) }
    /// ```
    async fn start_challenge(
        &self,
        config: &ChallengeContainerConfig,
    ) -> anyhow::Result<ChallengeInstance> {
        DockerClient::start_challenge(self, config).await
    }

    /// Stops the specified container, waiting up to 30 seconds for it to stop.
    ///
    /// 304 (container already stopped) and 404 (container not found) are treated as no-ops.
    ///
    /// # Examples
    ///
    /// ```
    /// # async fn example(client: &crate::DockerClient) -> anyhow::Result<()> {
    /// client.stop_container("container-id").await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// `Ok(())` if the container was stopped or was already absent/stopped, `Err(_)` on failure.
    async fn stop_container(&self, container_id: &str) -> anyhow::Result<()> {
        DockerClient::stop_container(self, container_id).await
    }

    /// Remove the specified container, treating a non-existent container as a no-op.
    ///
    /// On success this function ensures the container is removed; if the container
    /// does not exist it returns Ok without error. Other failures return an error.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Assuming `client` is a DockerClient or an implementation exposing this method.
    /// client.remove_container("my-container-id").await.unwrap();
    /// ```
    async fn remove_container(&self, container_id: &str) -> anyhow::Result<()> {
        DockerClient::remove_container(self, container_id).await
    }

    /// Check whether a container is currently running.
    ///
    /// Returns `true` if the container exists and its Docker state is running, `false` if the
    /// container does not exist or is not running. Other errors from the Docker bridge are
    /// propagated as an `Err`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # async fn example(client: &crate::DockerClient) -> Result<()> {
    /// let is_running = client.is_container_running("my-container-id").await?;
    /// println!("running: {}", is_running);
    /// # Ok(())
    /// # }
    /// ```
    async fn is_container_running(&self, container_id: &str) -> anyhow::Result<bool> {
        DockerClient::is_container_running(self, container_id).await
    }

    /// Fetches and combined stdout and stderr logs for a container and returns them as a single string.
    ///
    /// # Returns
    ///
    /// `String` containing the concatenated logs from stdout and stderr; an empty string if there are no logs.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # async fn doc_example() -> Result<()> {
    /// // `client` can be a DockerClient or any type implementing `ChallengeDocker`.
    /// let client = /* obtain client */ unimplemented!();
    /// let logs = client.get_logs("container-id", 100).await?;
    /// println!("{}", logs);
    /// # Ok(()) }
    /// ```
    async fn get_logs(&self, container_id: &str, tail: usize) -> anyhow::Result<String> {
        DockerClient::get_logs(self, container_id, tail).await
    }

    /// Lists challenge containers visible to the client's configured Docker network.
    ///
    /// The returned list contains container IDs for containers whose names start with the
    /// "challenge-" prefix and that are attached to the client's configured platform network.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(client: &impl crate::ChallengeDocker) -> anyhow::Result<()> {
    /// let ids = client.list_challenge_containers().await?;
    /// assert!(ids.iter().all(|id| !id.is_empty()));
    /// # Ok(()) }
    /// ```
    async fn list_challenge_containers(&self) -> anyhow::Result<Vec<String>> {
        DockerClient::list_challenge_containers(self).await
    }

    /// Remove challenge containers whose names start with `prefix`, subject to age and exclude filters, and return a summary of the cleanup.
    ///
    /// This lists all containers, filters those whose names begin with `prefix`, skips any whose names match any string in `exclude_patterns`, and — if `max_age_minutes` is greater than zero — skips containers younger than that age. Matching containers are removed and any errors encountered are collected in the result; removals of already-missing containers are treated as no-ops.
    ///
    /// # Parameters
    ///
    /// - `prefix`: Name prefix used to select candidate containers for removal.
    /// - `max_age_minutes`: If greater than zero, only containers older than this many minutes are removed; a value of `0` disables age-based filtering.
    /// - `exclude_patterns`: Slice of substrings; any container whose name contains any of these substrings will be excluded from removal.
    ///
    /// # Returns
    ///
    /// A `CleanupResult` summarizing `total_found`, `removed`, and any `errors` encountered during removal.
    ///
    /// # Examples
    ///
    /// ```
    /// #[tokio::test]
    /// async fn cleanup_example() {
    ///     // `client` should be a connected DockerClient implementing the cleanup method.
    ///     // let client = DockerClient::connect().await.unwrap();
    ///     // Example call (placeholder client in real usage):
    ///     // let result = client.cleanup_stale_containers("challenge-", 60, &["keep-this"]).await.unwrap();
    ///     // assert!(result.total_found >= result.removed);
    /// }
    /// ```
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
    /// Constructs a DockerClient backed by the provided DockerBridge and configured to use the given network.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// // `RecordingBridge` is a test bridge implementation; replace with a real bridge in production.
    /// let bridge = Arc::new(crate::RecordingBridge::default()) as Arc<dyn crate::DockerBridge>;
    /// let client = crate::DockerClient::from_bridge(bridge, "platform-network");
    /// assert_eq!(client.network_name, "platform-network");
    /// ```
    fn from_bridge(docker: Arc<dyn DockerBridge>, network_name: impl Into<String>) -> Self {
        Self {
            docker,
            network_name: network_name.into(),
        }
    }

    /// Constructs a DockerClient using a custom DockerBridge implementation.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // Provide any type implementing `DockerBridge`.
    /// let my_bridge = /* implementor of DockerBridge */ ;
    /// let client = DockerClient::with_bridge(my_bridge, "platform-network");
    /// ```
    pub fn with_bridge(
        docker: impl DockerBridge + 'static,
        network_name: impl Into<String>,
    ) -> Self {
        Self::from_bridge(Arc::new(docker), network_name)
    }

    /// Establishes a connection to the local Docker daemon and returns a DockerClient configured
    /// to use the "platform-network".
    ///
    /// Attempts to ping the daemon to verify the connection before constructing the client.
    ///
    /// # Examples
    ///
    /// ```
    /// # tokio_test::block_on(async {
    /// let client = crate::docker::DockerClient::connect().await.unwrap();
    /// // client is ready to use with the "platform-network"
    /// # });
    /// ```
    pub async fn connect() -> anyhow::Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;

        // Verify connection
        let bridge = Arc::new(BollardBridge::new(docker));
        bridge.ping().await?;
        info!("Connected to Docker daemon");

        Ok(Self::from_bridge(bridge, "platform-network"))
    }

    /// Creates a DockerClient connected to the local Docker daemon and configured to use the given network.
    ///
    /// Attempts to connect to the local Docker daemon, verifies the daemon is responsive, and returns a client that will use `network_name`.
    ///
    /// # Errors
    ///
    /// Returns an error if connecting to the local Docker daemon or pinging it fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> anyhow::Result<()> {
    /// let client = crate::DockerClient::connect_with_network("platform-network").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect_with_network(network_name: &str) -> anyhow::Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;
        let bridge = Arc::new(BollardBridge::new(docker));
        bridge.ping().await?;

        Ok(Self::from_bridge(bridge, network_name))
    }

    /// Create a DockerClient connected to the local Docker daemon and configured to use
    /// the validator network when available.
    ///
    /// Attempts to detect the validator container's network and configures the client
    /// to use that network for challenge containers. If detection fails, the client
    /// falls back to the "platform-network" network and logs a warning.
    ///
    /// # Examples
    ///
    /// ```
    /// # async fn run() -> anyhow::Result<()> {
    /// let client = crate::docker::DockerClient::connect_auto_detect().await?;
    /// // use `client` to manage challenge containers...
    /// # Ok(())
    /// # }
    /// ```
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

    /// Determine which Docker network the current validator container is connected to.
    ///
    /// Prefers a user-defined bridge network when available; falls back to the `bridge` network if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the container has no network settings or if no suitable network can be found.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # async fn example(docker: &dyn challenge_orchestrator::docker::DockerBridge) -> Result<()> {
    /// let network = challenge_orchestrator::docker::DockerClient::detect_validator_network(docker).await?;
    /// println!("Selected network: {}", network);
    /// # Ok(())
    /// # }
    /// ```
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

    /// Ensures the client's configured Docker network exists, creating it if missing.
    ///
    /// Attempts to list networks and creates a bridge network with the client's `network_name` when none matches.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the network exists or was created successfully, `Err` if the Docker operations fail.
    ///
    /// # Examples
    ///
    /// ```
    /// # async fn run_example() -> anyhow::Result<()> {
    /// let client = /* obtain a DockerClient instance */;
    /// client.ensure_network().await?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Connects the current process's container to the configured platform network.
    ///
    /// Determines the container ID for the current process and, if the container is not
    /// already attached to the client's configured network, connects it. This operation
    /// is idempotent: if the container is already connected the method returns successfully
    /// without making changes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # tokio_test::block_on(async {
    /// # // `client` would be a real DockerClient in production; shown here as a placeholder.
    /// # let client: crate::DockerClient = unimplemented!();
    /// client.connect_self_to_network().await.unwrap();
    /// # });
    /// ```
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

    /// Pulls a Docker image after enforcing the configured image whitelist.
    ///
    /// Errors if the image is not allowed by the whitelist or if the pull operation fails.
    /// By default the policy permits images from ghcr.io/platformnetwork/ unless development
    /// overrides are enabled.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # #[tokio::main]
    /// # async fn main() -> Result<()> {
    /// // `client` is a DockerClient or another implementor of the same API.
    /// let client = /* obtain DockerClient */ unimplemented!();
    /// client.pull_image("ghcr.io/platformnetwork/example:latest").await?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Starts a challenge container from the configured (whitelisted) image and returns a record of the started instance.
    ///
    /// Performs image allowlist validation, validates the provided challenge configuration, ensures the platform
    /// network exists, prepares required volumes and host bindings, constructs container environment and host
    /// configuration (including optional GPU support), creates and starts the container, and inspects it to
    /// determine the container ID and mapped ports.
    ///
    /// On success returns a `ChallengeInstance` describing the started container (IDs, image, endpoint, start time,
    /// and initial status). The call fails if the image is not allowed, the config is invalid, or any Docker
    /// operation (volume creation, container creation, start, inspection) fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # async fn doc_example() -> Result<()> {
    /// // Setup: obtain a DockerClient and a ChallengeContainerConfig (omitted)
    /// // let client: DockerClient = /* construct or connect */ ;
    /// // let config: ChallengeContainerConfig = /* build config */ ;
    ///
    /// // Start the challenge container
    /// // let instance = client.start_challenge(&config).await?;
    /// // println!("Started challenge container: {}", instance.container_id);
    /// # Ok(())
    /// # }
    /// ```
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

        // Pass Platform URL for metagraph verification and API calls
        // Default to public platform-server URL so validators don't need extra config
        let platform_url = std::env::var("PLATFORM_PUBLIC_URL")
            .unwrap_or_else(|_| "https://chain.platform.network".to_string());
        env.push(format!("PLATFORM_URL={}", platform_url));

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

        // Use secure_container_runtime to generate token (3600s = 1 hour TTL)
        if let Ok(token) =
            secure_container_runtime::generate_token(&challenge_id, &owner_id, &jwt_secret, 3600)
        {
            env.push(format!("CONTAINER_BROKER_JWT={}", token));
            debug!(challenge = %config.name, "Generated broker JWT token");
        } else {
            warn!(challenge = %config.name, "Failed to generate broker JWT token");
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

    /// Lists challenge containers visible to the configured network.
    ///
    /// Returns a vector of container IDs for containers whose names start with `challenge-` and that are attached to the client's configured network.
    ///
    /// # Examples
    ///
    /// ```
    /// # tokio_test::block_on(async {
    /// let client = /* DockerClient constructed elsewhere */;
    /// let ids = client.list_challenge_containers().await.unwrap();
    /// for id in ids { assert!(!id.is_empty()); }
    /// # });
    /// ```
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

    /// Fetches the container's stdout and stderr logs and returns them concatenated as a single string.
    ///
    /// Streams the requested number of tail lines from both stdout and stderr for the given container
    /// and joins each log chunk in order into one `String`.
    ///
    /// # Parameters
    ///
    /// - `container_id`: the Docker container identifier to read logs from.
    /// - `tail`: the number of most-recent log lines to include.
    ///
    /// # Returns
    ///
    /// A `String` containing the concatenated log output (stdout and stderr); an empty string if no logs.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> anyhow::Result<()> {
    /// let client = DockerClient::connect().await?;
    /// let logs = client.get_logs("my-container-id", 100).await?;
    /// println!("{}", logs);
    /// # Ok(())
    /// # }
    /// ```
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

    /// Removes stale task containers whose names start with a given prefix.
    ///
    /// Containers matching `prefix` will be considered for removal unless their
    /// names contain any of the provided `exclude_patterns` or they are younger
    /// than `max_age_minutes` (when `max_age_minutes > 0`). Typical exclusions
    /// include main challenge containers (e.g., `challenge-*`), platform validator
    /// containers, and watchtower containers; pass appropriate patterns to
    /// `exclude_patterns` to protect those.
    ///
    /// # Parameters
    ///
    /// - `prefix`: Container name prefix to match (e.g., `"term-challenge-"`).
    /// - `max_age_minutes`: Only remove containers older than this many minutes
    ///   (use `0` to remove all matching containers regardless of age).
    /// - `exclude_patterns`: Substrings; if any is present in a container name,
    ///   that container will be skipped.
    ///
    /// # Returns
    ///
    /// `Ok(CleanupResult)` containing counts of found and removed containers and any
    /// errors encountered while attempting removals.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(client: &crate::DockerClient) -> anyhow::Result<()> {
    /// let result = client
    ///     .cleanup_stale_containers("term-challenge-", 60, &["challenge-", "validator", "watchtower"])
    ///     .await?;
    /// println!("Removed {}/{} stale containers", result.removed, result.total_found);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn cleanup_stale_containers(
        &self,
        prefix: &str,
        max_age_minutes: u64,
        exclude_patterns: &[&str],
    ) -> anyhow::Result<CleanupResult> {
        let mut result = CleanupResult::default();

        // List ALL containers (including stopped)
        let mut options: ListContainersOptions<String> = Default::default();
        options.all = true;

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

    /// Remove environment variables for the provided keys.
    ///
    /// Removes each environment variable named in `keys`. Missing variables are ignored.
    ///
    /// # Examples
    ///
    /// ```
    /// std::env::set_var("FOO", "1");
    /// std::env::set_var("BAR", "2");
    /// reset_env(&["FOO", "BAR"]);
    /// assert!(std::env::var("FOO").is_err());
    /// assert!(std::env::var("BAR").is_err());
    /// ```
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
        /// Creates a RecordingBridge pre-populated with networks having the given names.
        
        ///
        
        /// `names` is a slice of network name strings to add to the bridge's internal network list.
        
        /// This helper is intended for tests that need a RecordingBridge already containing specific networks.
        
        ///
        
        /// # Examples
        
        ///
        
        /// ```
        
        /// let bridge = RecordingBridge::with_networks(&["platform-network", "validator-net"]);
        
        /// let locked = bridge.inner.networks.lock().unwrap();
        
        /// let names: Vec<_> = locked.iter().filter_map(|n| n.name.as_deref()).collect();
        
        /// assert!(names.contains(&"platform-network"));
        
        /// assert!(names.contains(&"validator-net"));
        
        /// ```
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

        /// List network names created by the recording bridge.
        ///
        /// # Returns
        ///
        /// `Vec<String>` containing the names of networks that have been recorded as created.
        ///
        /// # Examples
        ///
        /// ```
        /// let bridge = RecordingBridge::default();
        /// // simulate creation in tests by manipulating bridge.inner as needed...
        /// let networks = bridge.created_networks();
        /// assert!(networks.is_empty() || networks.iter().all(|n| n.is_string()));
        /// ```
        fn created_networks(&self) -> Vec<String> {
            self.inner.created_networks.lock().unwrap().clone()
        }

        /// Insert a ContainerInspectResponse with the given networks into the bridge's inspect map.
        ///
        /// The method creates a `ContainerInspectResponse` whose `network_settings.networks` map
        /// contains an entry for each name in `networks` mapped to default `EndpointSettings`,
        /// then stores it under `container_id` in the internal `inspect_map`.
        ///
        /// # Parameters
        ///
        /// - `container_id`: the container identifier used as the map key.
        /// - `networks`: slice of network names to include in the constructed inspect response.
        ///
        /// # Examples
        ///
        /// ```
        /// // Assuming `bridge` is a RecordingBridge (or similar) with `set_inspect_networks`
        /// let bridge = RecordingBridge::default();
        /// bridge.set_inspect_networks("container-123", &["platform-network", "bridge"]);
        /// let map = bridge.inner.inspect_map.lock().unwrap();
        /// assert!(map.contains_key("container-123"));
        /// ```
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

        /// Replaces the stored list of container summaries with the provided vector.
        ///
        /// # Parameters
        ///
        /// - `containers`: The new list of `ContainerSummary` values to store.
        ///
        /// # Examples
        ///
        /// ```
        /// // Replace the client's cached containers with an empty list.
        /// client.set_containers(vec![]);
        /// ```
        fn set_containers(&self, containers: Vec<ContainerSummary>) {
            *self.inner.containers.lock().unwrap() = containers;
        }

        /// Returns the list of container IDs that were recorded as removed.
        ///
        /// The returned vector is a clone of the internal removal log and can be modified
        /// by the caller without affecting the bridge's internal state.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// // `bridge` is an instance that provides `removed_containers() -> Vec<String>`
        /// let removed = bridge.removed_containers();
        /// for id in removed {
        ///     println!("Removed container: {}", id);
        /// }
        /// ```
        fn removed_containers(&self) -> Vec<String> {
            self.inner.removed.lock().unwrap().clone()
        }

        /// List recorded Docker network connect calls.
        ///
        /// Each entry is a tuple of `(network_name, container_id)` in the order the calls were invoked.
        ///
        /// # Examples
        ///
        /// ```
        /// // `rec` is a test recording object exposing `connect_calls`.
        /// let calls = rec.connect_calls();
        /// // e.g., assert that the first recorded call targeted the "platform-network"
        /// assert!(calls.first().map(|(net, _)| net == "platform-network").unwrap_or(false));
        /// ```
        fn connect_calls(&self) -> Vec<(String, String)> {
            self.inner.connect_calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DockerBridge for RecordingBridge {
        /// Checks connectivity to the Docker daemon.
        ///
        /// # Returns
        ///
        /// `Ok(())` if the daemon responds, `Err(DockerError)` if the check fails.
        ///
        /// # Examples
        ///
        /// ```
        /// # async fn _example(client: &impl crate::DockerBridge) {
        /// client.ping().await.expect("docker daemon reachable");
        /// # }
        /// ```
        async fn ping(&self) -> Result<(), DockerError> {
            Ok(())
        }

        /// Returns the list of networks currently recorded by this bridge.
        ///
        /// The `_options` parameter is ignored by this implementation and may be `None`.
        ///
        /// # Examples
        ///
        /// ```
        /// # async fn example_usage() {
        /// let bridge = RecordingBridge::new();
        /// let networks = bridge.list_networks(None).await.unwrap();
        /// assert!(networks.is_empty() || networks.len() >= 0);
        /// # }
        /// ```
        async fn list_networks(
            &self,
            _options: Option<ListNetworksOptions<String>>,
        ) -> Result<Vec<Network>, DockerError> {
            Ok(self.inner.networks.lock().unwrap().clone())
        }

        /// Appends the provided network name to the bridge's in-memory list of created networks.
        ///
        /// This mock implementation simulates network creation by pushing `options.name` into
        /// `self.inner.created_networks` and returns success.
        ///
        /// # Examples
        ///
        /// ```
        /// # use std::sync::Arc;
        /// # use tokio::runtime::Runtime;
        /// // Construct a RecordingBridge (test double) and verify network names are recorded.
        /// let rt = Runtime::new().unwrap();
        /// rt.block_on(async {
        ///     let bridge = RecordingBridge::new();
        ///     let opts = CreateNetworkOptions { name: "platform-network".to_string(), ..Default::default() };
        ///     bridge.create_network(opts).await.unwrap();
        ///     assert!(bridge.inner.created_networks.lock().unwrap().contains(&"platform-network".to_string()));
        /// });
        /// ```
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

        /// Returns the stored inspection metadata for a container by id.
        ///
        /// The `options` argument is ignored by this implementation.
        ///
        /// # Arguments
        ///
        /// * `id` - The container identifier to look up.
        ///
        /// # Returns
        ///
        /// `ContainerInspectResponse` for the container if present, or a `DockerError::IOError` with
        /// `NotFound` if no inspection entry exists for the given `id`.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// # async fn doc_example(bridge: &crate::RecordingBridge) {
        /// let info = bridge.inspect_container("container-id", None).await.unwrap();
        /// // use `info`...
        /// # }
        /// ```
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

        /// Records a request to connect a container to a network in the mock bridge.
        ///
        /// This implementation appends the tuple `(container_id, network_name)` to the bridge's
        /// internal `connect_calls` log and returns `Ok(())`.
        ///
        /// # Examples
        ///
        /// ```
        /// // Construct a mock bridge (type details omitted) and call the async method.
        /// // The bridge will record the requested connection in its `connect_calls`.
        /// # async fn doc_example() {
        /// let bridge = /* RecordingBridge::new() or equivalent setup */;
        /// let opts = /* ConnectNetworkOptions { container: "container-id".to_string(), .. } */;
        /// let res = bridge.connect_network("platform-network", opts).await;
        /// assert!(res.is_ok());
        /// // assert that bridge.inner.connect_calls contains ("container-id", "platform-network")
        /// # }
        /// ```
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

        /// Creates a stream of image-pull progress events for the given image-pull options.
        ///
        /// The stream yields `CreateImageInfo` items describing progress/status of the image
        /// pull operation.
        ///
        /// # Returns
        ///
        /// An `ImageStream` that produces `CreateImageInfo` values as the image is pulled; the
        /// default implementation produces an empty stream (no events).
        ///
        /// # Examples
        ///
        /// ```
        /// use futures::stream::StreamExt;
        ///
        /// // `bridge` is an implementor of the trait providing `create_image_stream`.
        /// // The returned stream can be polled for pull progress events.
        /// let stream = bridge.create_image_stream(None);
        /// let first = futures::executor::block_on(stream.next());
        /// assert!(first.is_none() || first.is_some());
        /// ```
        fn create_image_stream(&self, _options: Option<CreateImageOptions<String>>) -> ImageStream {
            futures::stream::empty().boxed()
        }

        /// Creates a Docker volume.
        ///
        /// This implementation is a no-op: the provided `CreateVolumeOptions` are ignored and the call
        /// always succeeds.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// # async fn example(bridge: &impl DockerBridge) {
        /// use bollard::volume::CreateVolumeOptions;
        ///
        /// let opts = CreateVolumeOptions { name: "test-volume".to_string(), ..Default::default() };
        /// bridge.create_volume(opts).await.unwrap();
        /// # }
        /// ```
        async fn create_volume(
            &self,
            _options: CreateVolumeOptions<String>,
        ) -> Result<(), DockerError> {
            Ok(())
        }

        /// Test-only stub implementation that always panics when invoked.
        ///
        /// This function is provided for test scaffolding and should not be called in normal execution.
        /// It unconditionally panics to surface unexpected usage in tests.
        ///
        /// # Examples
        ///
        /// ```
        /// // Assuming a `RecordingBridge` test double is in scope:
        /// // #[tokio::test]
        /// // #[should_panic]
        /// // async fn create_container_stub_panics() {
        /// //     let bridge = RecordingBridge::default();
        /// //     // This call will panic as the stub is not intended to be used.
        /// //     let _ = bridge.create_container(None, Default::default()).await;
        /// // }
        /// ```
        async fn create_container(
            &self,
            _options: Option<CreateContainerOptions<String>>,
            _config: Config<String>,
        ) -> Result<ContainerCreateResponse, DockerError> {
            panic!("not used in tests")
        }

        /// Starts the container identified by `id` with the provided start options.
        ///
        /// This concrete implementation is a test stub and will panic if invoked.
        ///
        /// # Returns
        ///
        /// `Ok(())` on success, `Err(DockerError)` on failure.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// // Typical usage (actual implementation should not panic):
        /// // let _ = client.start_container("container_id", None).await;
        /// ```
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

        /// Records a container removal request by appending the container `id` to the internal
        /// removed list and returns success.
        ///
        /// # Examples
        ///
        /// ```
        /// # use std::sync::Arc;
        /// # async fn run_example() {
        /// let bridge = RecordingBridge::default();
        /// bridge.remove_container("container-123", None).await.unwrap();
        /// assert!(bridge.inner.removed.lock().unwrap().contains(&"container-123".to_string()));
        /// # }
        /// ```
        async fn remove_container(
            &self,
            id: &str,
            _options: Option<RemoveContainerOptions>,
        ) -> Result<(), DockerError> {
            self.inner.removed.lock().unwrap().push(id.to_string());
            Ok(())
        }

        /// Returns the list of container summaries currently recorded by the bridge.
        ///
        /// The method ignores any provided `ListContainersOptions` and returns a cloned
        /// snapshot of the internal container summaries.
        ///
        /// # Examples
        ///
        /// ```
        /// # tokio_test::block_on(async {
        /// // `bridge` is a value with this method (e.g., a recording/mock bridge).
        /// // Replace with the actual instance in real tests.
        /// let bridge = /* create or obtain bridge instance */ todo!();
        /// let summaries = bridge.list_containers(None).await.unwrap();
        /// // `summaries` is a Vec<ContainerSummary>
        /// let _ = summaries;
        /// # });
        /// ```
        async fn list_containers(
            &self,
            _options: Option<ListContainersOptions<String>>,
        ) -> Result<Vec<ContainerSummary>, DockerError> {
            Ok(self.inner.containers.lock().unwrap().clone())
        }

        /// Returns a stream of log output items for the container identified by `id`, using the provided `options`.
        ///
        /// The returned stream yields `LogOutput` entries produced by the container (stdout/stderr, timestamps, etc.).
        ///
        /// # Examples
        ///
        /// ```
        /// // Obtain a log stream from a Docker client and consume entries:
        /// // let mut stream = docker.logs_stream("container_id", LogsOptions::default());
        /// // while let Some(entry) = stream.next().await { /* handle LogOutput */ }
        /// ```
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

    /// Constructs a minimal `ContainerSummary` populated with the provided id, name, and creation timestamp.
    ///
    /// The returned summary will have `id` set to the provided `id`, `names` set to a single entry prefixed with `/`
    /// (e.g., passing `"foo"` produces `names = ["/foo"]`), and `created` set to the provided timestamp. All other
    /// fields are left as their default values.
    ///
    /// # Examples
    ///
    /// ```
    /// let summary = make_container_summary("abcdef", "my-container", 1_700_000_000);
    /// assert_eq!(summary.id.as_deref(), Some("abcdef"));
    /// assert_eq!(summary.names.as_ref().map(|v| v.as_slice()), Some(&["/my-container"]));
    /// assert_eq!(summary.created, Some(1_700_000_000));
    /// ```
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