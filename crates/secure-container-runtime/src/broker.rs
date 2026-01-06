//! Container broker - manages Docker containers securely
//!
//! This is the only component that has access to the Docker socket.
//! It enforces security policies and provides a controlled interface.

use crate::policy::SecurityPolicy;
use crate::protocol::{Request, Response};
use crate::types::*;
use bollard::container::{
    Config, CreateContainerOptions, ListContainersOptions, LogsOptions, RemoveContainerOptions,
    StartContainerOptions, StopContainerOptions,
};
use bollard::exec::{CreateExecOptions, StartExecResults};
use bollard::image::CreateImageOptions;
use bollard::models::{HostConfig, PortBinding};
use bollard::Docker;
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

const BROKER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Container broker that manages Docker containers
pub struct ContainerBroker {
    docker: Docker,
    policy: SecurityPolicy,
    /// Network name for challenge containers
    network_name: String,
    /// Track containers by challenge
    containers_by_challenge: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Track containers by owner
    containers_by_owner: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Audit log
    audit_log: Arc<RwLock<Vec<AuditEntry>>>,
}

impl ContainerBroker {
    /// Create a new broker with default policy
    pub async fn new() -> anyhow::Result<Self> {
        Self::with_policy(SecurityPolicy::default()).await
    }

    /// Create a new broker with custom policy
    pub async fn with_policy(policy: SecurityPolicy) -> anyhow::Result<Self> {
        let docker = Docker::connect_with_local_defaults()
            .map_err(|e| anyhow::anyhow!("Failed to connect to Docker: {}", e))?;

        // Verify connection
        docker
            .ping()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to ping Docker: {}", e))?;

        info!("Container broker connected to Docker daemon");

        Ok(Self {
            docker,
            policy,
            network_name: "platform-network".to_string(),
            containers_by_challenge: Arc::new(RwLock::new(HashMap::new())),
            containers_by_owner: Arc::new(RwLock::new(HashMap::new())),
            audit_log: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Run the broker, listening on a Unix socket
    pub async fn run(&self, socket_path: &str) -> anyhow::Result<()> {
        // Remove old socket if exists
        let _ = std::fs::remove_file(socket_path);

        let listener = UnixListener::bind(socket_path)?;
        info!(socket = %socket_path, "Container broker listening");

        // Set socket permissions (only owner can access)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        }

        // Ensure network exists
        self.ensure_network().await?;

        // Cleanup stale containers from previous runs
        if let Err(e) = self.cleanup_stale_containers().await {
            warn!("Failed to cleanup stale containers: {}", e);
        }

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let broker = self.clone_internal();
                    tokio::spawn(async move {
                        if let Err(e) = broker.handle_client(stream).await {
                            error!(error = %e, "Client handler error");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "Accept error");
                }
            }
        }
    }

    /// Handle a single client connection
    async fn handle_client(&self, stream: UnixStream) -> anyhow::Result<()> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break; // Client disconnected
            }

            let request: Request = match serde_json::from_str(line.trim()) {
                Ok(req) => req,
                Err(e) => {
                    let response = Response::Error {
                        error: ContainerError::InvalidConfig(format!("Invalid request: {}", e)),
                        request_id: "unknown".to_string(),
                    };
                    writer
                        .write_all(serde_json::to_string(&response)?.as_bytes())
                        .await?;
                    writer.write_all(b"\n").await?;
                    continue;
                }
            };

            let response = self.handle_request(request).await;
            writer
                .write_all(serde_json::to_string(&response)?.as_bytes())
                .await?;
            writer.write_all(b"\n").await?;
        }

        Ok(())
    }

    /// Handle a single request
    pub async fn handle_request(&self, request: Request) -> Response {
        let request_id = request.request_id().to_string();

        // Log all incoming requests for debugging
        debug!(
            request_id = %request_id,
            request_type = %request.request_type(),
            "Handling broker request"
        );

        match request {
            Request::Ping { request_id } => Response::Pong {
                version: BROKER_VERSION.to_string(),
                request_id,
            },

            Request::Create { config, request_id } => {
                self.create_container(config, request_id).await
            }

            Request::Start {
                container_id,
                request_id,
            } => self.start_container(&container_id, request_id).await,

            Request::Stop {
                container_id,
                timeout_secs,
                request_id,
            } => {
                self.stop_container(&container_id, timeout_secs, request_id)
                    .await
            }

            Request::Remove {
                container_id,
                force,
                request_id,
            } => {
                self.remove_container(&container_id, force, request_id)
                    .await
            }

            Request::Exec {
                container_id,
                command,
                working_dir,
                timeout_secs,
                request_id,
            } => {
                self.exec_in_container(
                    &container_id,
                    command,
                    working_dir,
                    timeout_secs,
                    request_id,
                )
                .await
            }

            Request::Inspect {
                container_id,
                request_id,
            } => self.inspect_container(&container_id, request_id).await,

            Request::List {
                challenge_id,
                owner_id,
                request_id,
            } => {
                self.list_containers(challenge_id, owner_id, request_id)
                    .await
            }

            Request::Logs {
                container_id,
                tail,
                request_id,
            } => self.get_logs(&container_id, tail, request_id).await,

            Request::Pull { image, request_id } => self.pull_image(&image, request_id).await,

            Request::Build {
                tag,
                dockerfile,
                context,
                request_id,
            } => {
                self.build_image(&tag, &dockerfile, context, request_id)
                    .await
            }

            Request::CopyFrom {
                container_id,
                path,
                request_id,
            } => {
                self.copy_from_container(&container_id, &path, request_id)
                    .await
            }

            Request::CopyTo {
                container_id,
                path,
                data,
                request_id,
            } => {
                self.copy_to_container(&container_id, &path, &data, request_id)
                    .await
            }
        }
    }

    /// Create a container with policy enforcement
    async fn create_container(&self, config: ContainerConfig, request_id: String) -> Response {
        // Validate against security policy
        if let Err(e) = self.policy.validate(&config) {
            self.audit(
                AuditAction::ContainerCreate,
                &config.challenge_id,
                &config.owner_id,
                None,
                false,
                Some(e.to_string()),
            )
            .await;
            return Response::error(request_id, e);
        }

        // Auto-pull image if it doesn't exist locally
        if let Err(e) = self.ensure_image(&config.image).await {
            self.audit(
                AuditAction::ImagePull,
                &config.challenge_id,
                &config.owner_id,
                None,
                false,
                Some(e.to_string()),
            )
            .await;
            return Response::error(
                request_id.clone(),
                ContainerError::DockerError(e.to_string()),
            );
        }

        // Check container limits
        {
            let by_challenge = self.containers_by_challenge.read().await;
            let count = by_challenge
                .get(&config.challenge_id)
                .map(|v| v.len())
                .unwrap_or(0);
            if let Err(e) = self
                .policy
                .check_container_limit(&config.challenge_id, count)
            {
                return Response::error(request_id, e);
            }
        }

        {
            let by_owner = self.containers_by_owner.read().await;
            let count = by_owner.get(&config.owner_id).map(|v| v.len()).unwrap_or(0);
            if let Err(e) = self.policy.check_owner_limit(&config.owner_id, count) {
                return Response::error(request_id, e);
            }
        }

        // Generate container name
        let container_name = config.name.clone().unwrap_or_else(|| {
            format!(
                "platform-{}-{}",
                config.challenge_id.to_lowercase().replace(' ', "-"),
                &uuid::Uuid::new_v4().to_string()[..8]
            )
        });

        // Build labels
        let mut labels = config.labels.clone();
        labels.insert(
            labels::CHALLENGE_ID.to_string(),
            config.challenge_id.clone(),
        );
        labels.insert(labels::OWNER_ID.to_string(), config.owner_id.clone());
        labels.insert(
            labels::CREATED_BY.to_string(),
            "secure-container-runtime".to_string(),
        );
        labels.insert(
            labels::BROKER_VERSION.to_string(),
            BROKER_VERSION.to_string(),
        );
        labels.insert(labels::MANAGED.to_string(), "true".to_string());

        // Build port bindings
        let mut port_bindings = HashMap::new();
        for (container_port, host_port) in &config.network.ports {
            port_bindings.insert(
                format!("{}/tcp", container_port),
                Some(vec![PortBinding {
                    host_ip: Some("127.0.0.1".to_string()),
                    host_port: Some(if *host_port == 0 {
                        "0".to_string() // Dynamic
                    } else {
                        host_port.to_string()
                    }),
                }]),
            );
        }

        // Build environment
        let env: Vec<String> = config
            .env
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();

        // Build mounts
        let mounts: Vec<bollard::models::Mount> = config
            .mounts
            .iter()
            .map(|m| bollard::models::Mount {
                target: Some(m.target.clone()),
                source: Some(m.source.clone()),
                typ: Some(bollard::models::MountTypeEnum::BIND),
                read_only: Some(m.read_only),
                ..Default::default()
            })
            .collect();

        // Build host config with SECURITY settings
        let host_config = HostConfig {
            memory: Some(config.resources.memory_bytes),
            nano_cpus: Some((config.resources.cpu_cores * 1_000_000_000.0) as i64),
            pids_limit: Some(config.resources.pids_limit),
            network_mode: Some(match config.network.mode {
                NetworkMode::None => "none".to_string(),
                NetworkMode::Bridge => "bridge".to_string(),
                NetworkMode::Isolated => self.network_name.clone(),
            }),
            port_bindings: Some(port_bindings),
            mounts: Some(mounts),
            // SECURITY: Non-privileged container settings
            privileged: Some(false),
            cap_drop: Some(vec!["ALL".to_string()]),
            cap_add: Some(vec![
                "CHOWN".to_string(),
                "SETUID".to_string(),
                "SETGID".to_string(),
            ]),
            security_opt: Some(vec!["no-new-privileges:true".to_string()]),
            auto_remove: Some(false),
            ..Default::default()
        };

        // Build container config
        let container_config = Config {
            image: Some(config.image.clone()),
            hostname: Some(container_name.clone()),
            cmd: config.cmd.clone(),
            working_dir: config.working_dir.clone(),
            env: Some(env),
            labels: Some(labels),
            host_config: Some(host_config),
            ..Default::default()
        };

        // Create container
        let options = CreateContainerOptions {
            name: &container_name,
            platform: None,
        };

        match self
            .docker
            .create_container(Some(options), container_config)
            .await
        {
            Ok(response) => {
                let container_id = response.id[..12].to_string();

                // Track container
                {
                    let mut by_challenge = self.containers_by_challenge.write().await;
                    by_challenge
                        .entry(config.challenge_id.clone())
                        .or_default()
                        .push(container_id.clone());
                }
                {
                    let mut by_owner = self.containers_by_owner.write().await;
                    by_owner
                        .entry(config.owner_id.clone())
                        .or_default()
                        .push(container_id.clone());
                }

                self.audit(
                    AuditAction::ContainerCreate,
                    &config.challenge_id,
                    &config.owner_id,
                    Some(&container_id),
                    true,
                    None,
                )
                .await;

                info!(
                    container_id = %container_id,
                    challenge_id = %config.challenge_id,
                    "Container created"
                );

                Response::Created {
                    container_id,
                    container_name,
                    request_id,
                }
            }
            Err(e) => {
                self.audit(
                    AuditAction::ContainerCreate,
                    &config.challenge_id,
                    &config.owner_id,
                    None,
                    false,
                    Some(e.to_string()),
                )
                .await;
                Response::error(request_id, ContainerError::DockerError(e.to_string()))
            }
        }
    }

    /// Start a container
    async fn start_container(&self, container_id: &str, request_id: String) -> Response {
        match self
            .docker
            .start_container(container_id, None::<StartContainerOptions<String>>)
            .await
        {
            Ok(_) => {
                // Get assigned ports
                let ports = self.get_container_ports(container_id).await;
                let endpoint = ports.get(&8080).map(|p| format!("http://localhost:{}", p));

                info!(container_id = %container_id, "Container started");

                Response::Started {
                    container_id: container_id.to_string(),
                    ports,
                    endpoint,
                    request_id,
                }
            }
            Err(e) => Response::error(request_id, ContainerError::DockerError(e.to_string())),
        }
    }

    /// Stop a container
    async fn stop_container(
        &self,
        container_id: &str,
        timeout_secs: u32,
        request_id: String,
    ) -> Response {
        let options = StopContainerOptions {
            t: timeout_secs as i64,
        };

        match self
            .docker
            .stop_container(container_id, Some(options))
            .await
        {
            Ok(_) => {
                info!(container_id = %container_id, "Container stopped");
                Response::Stopped {
                    container_id: container_id.to_string(),
                    request_id,
                }
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 304, ..
            }) => {
                // Already stopped
                Response::Stopped {
                    container_id: container_id.to_string(),
                    request_id,
                }
            }
            Err(e) => Response::error(request_id, ContainerError::DockerError(e.to_string())),
        }
    }

    /// Remove a container
    async fn remove_container(
        &self,
        container_id: &str,
        force: bool,
        request_id: String,
    ) -> Response {
        let options = RemoveContainerOptions {
            force,
            ..Default::default()
        };

        match self
            .docker
            .remove_container(container_id, Some(options))
            .await
        {
            Ok(_) => {
                // Remove from tracking
                {
                    let mut by_challenge = self.containers_by_challenge.write().await;
                    for containers in by_challenge.values_mut() {
                        containers.retain(|id| id != container_id);
                    }
                }
                {
                    let mut by_owner = self.containers_by_owner.write().await;
                    for containers in by_owner.values_mut() {
                        containers.retain(|id| id != container_id);
                    }
                }

                info!(container_id = %container_id, "Container removed");
                Response::Removed {
                    container_id: container_id.to_string(),
                    request_id,
                }
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => Response::Removed {
                container_id: container_id.to_string(),
                request_id,
            },
            Err(e) => Response::error(request_id, ContainerError::DockerError(e.to_string())),
        }
    }

    /// Execute command in container
    async fn exec_in_container(
        &self,
        container_id: &str,
        command: Vec<String>,
        working_dir: Option<String>,
        timeout_secs: u32,
        request_id: String,
    ) -> Response {
        let exec_options = CreateExecOptions {
            cmd: Some(command),
            working_dir,
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            ..Default::default()
        };

        let exec = match self.docker.create_exec(container_id, exec_options).await {
            Ok(e) => e,
            Err(e) => {
                return Response::error(request_id, ContainerError::DockerError(e.to_string()))
            }
        };

        let start = std::time::Instant::now();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs as u64),
            self.run_exec(&exec.id),
        )
        .await;

        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok((stdout, stderr, exit_code))) => Response::ExecResult {
                result: ExecResult {
                    stdout,
                    stderr,
                    exit_code,
                    duration_ms,
                    timed_out: false,
                },
                request_id,
            },
            Ok(Err(e)) => Response::error(request_id, ContainerError::DockerError(e.to_string())),
            Err(_) => Response::ExecResult {
                result: ExecResult {
                    stdout: String::new(),
                    stderr: "Command timed out".to_string(),
                    exit_code: -1,
                    duration_ms,
                    timed_out: true,
                },
                request_id,
            },
        }
    }

    /// Run exec and collect output
    async fn run_exec(&self, exec_id: &str) -> anyhow::Result<(String, String, i32)> {
        let mut stdout = String::new();
        let mut stderr = String::new();

        match self.docker.start_exec(exec_id, None).await? {
            StartExecResults::Attached { mut output, .. } => {
                while let Some(chunk) = output.next().await {
                    match chunk? {
                        bollard::container::LogOutput::StdOut { message } => {
                            stdout.push_str(&String::from_utf8_lossy(&message));
                        }
                        bollard::container::LogOutput::StdErr { message } => {
                            stderr.push_str(&String::from_utf8_lossy(&message));
                        }
                        _ => {}
                    }
                }
            }
            StartExecResults::Detached => {}
        }

        let inspect = self.docker.inspect_exec(exec_id).await?;
        let exit_code = inspect.exit_code.unwrap_or(-1) as i32;

        Ok((stdout, stderr, exit_code))
    }

    /// Inspect a container
    async fn inspect_container(&self, container_id: &str, request_id: String) -> Response {
        match self.docker.inspect_container(container_id, None).await {
            Ok(info) => {
                let state = match info.state.as_ref().and_then(|s| s.status.as_ref()) {
                    Some(bollard::models::ContainerStateStatusEnum::RUNNING) => {
                        ContainerState::Running
                    }
                    Some(bollard::models::ContainerStateStatusEnum::PAUSED) => {
                        ContainerState::Paused
                    }
                    Some(bollard::models::ContainerStateStatusEnum::EXITED) => {
                        ContainerState::Stopped
                    }
                    Some(bollard::models::ContainerStateStatusEnum::DEAD) => ContainerState::Dead,
                    _ => ContainerState::Unknown,
                };

                let labels = info
                    .config
                    .as_ref()
                    .and_then(|c| c.labels.clone())
                    .unwrap_or_default();

                let container_info = ContainerInfo {
                    id: container_id.to_string(),
                    name: info
                        .name
                        .unwrap_or_default()
                        .trim_start_matches('/')
                        .to_string(),
                    challenge_id: labels
                        .get(labels::CHALLENGE_ID)
                        .cloned()
                        .unwrap_or_default(),
                    owner_id: labels.get(labels::OWNER_ID).cloned().unwrap_or_default(),
                    image: info
                        .config
                        .as_ref()
                        .and_then(|c| c.image.clone())
                        .unwrap_or_default(),
                    state,
                    created_at: info
                        .created
                        .as_ref()
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                        .unwrap_or_else(chrono::Utc::now),
                    ports: self.get_container_ports(container_id).await,
                    endpoint: None,
                    labels,
                };

                Response::Info {
                    info: container_info,
                    request_id,
                }
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => Response::error(
                request_id,
                ContainerError::ContainerNotFound(container_id.to_string()),
            ),
            Err(e) => Response::error(request_id, ContainerError::DockerError(e.to_string())),
        }
    }

    /// List containers
    async fn list_containers(
        &self,
        challenge_id: Option<String>,
        owner_id: Option<String>,
        request_id: String,
    ) -> Response {
        // Build label filters - all labels must match
        let mut label_filters = vec![format!("{}=true", labels::MANAGED)];

        if let Some(cid) = &challenge_id {
            label_filters.push(format!("{}={}", labels::CHALLENGE_ID, cid));
        }

        if let Some(oid) = &owner_id {
            label_filters.push(format!("{}={}", labels::OWNER_ID, oid));
        }

        let mut filters: HashMap<String, Vec<String>> = HashMap::new();
        filters.insert("label".to_string(), label_filters);

        let options = ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        };

        match self.docker.list_containers(Some(options)).await {
            Ok(containers) => {
                let mut infos = Vec::new();
                for c in containers {
                    if let Some(id) = c.id {
                        // Use short ID (12 chars) for consistency
                        let short_id = if id.len() >= 12 { &id[..12] } else { &id };
                        if let Response::Info { info, .. } =
                            self.inspect_container(short_id, "".to_string()).await
                        {
                            infos.push(info);
                        }
                    }
                }

                Response::ContainerList {
                    containers: infos,
                    request_id,
                }
            }
            Err(e) => Response::error(request_id, ContainerError::DockerError(e.to_string())),
        }
    }

    /// Get container logs
    async fn get_logs(&self, container_id: &str, tail: usize, request_id: String) -> Response {
        let options = LogsOptions::<String> {
            stdout: true,
            stderr: true,
            tail: tail.to_string(),
            ..Default::default()
        };

        let mut logs = String::new();
        let mut stream = self.docker.logs(container_id, Some(options));

        while let Some(result) = stream.next().await {
            match result {
                Ok(chunk) => {
                    logs.push_str(&chunk.to_string());
                }
                Err(e) => {
                    warn!(error = %e, "Error reading logs");
                    break;
                }
            }
        }

        Response::LogsResult { logs, request_id }
    }

    /// Pull an image
    async fn pull_image(&self, image: &str, request_id: String) -> Response {
        // Validate image is whitelisted
        if let Err(e) = self.policy.validate_image(image) {
            self.audit(
                AuditAction::ImagePull,
                "",
                "",
                None,
                false,
                Some(e.to_string()),
            )
            .await;
            return Response::error(request_id, e);
        }

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
                    return Response::error(request_id, ContainerError::DockerError(e.to_string()));
                }
            }
        }

        info!(image = %image, "Image pulled");
        self.audit(AuditAction::ImagePull, "", "", None, true, None)
            .await;

        Response::Pulled {
            image: image.to_string(),
            request_id,
        }
    }

    /// Build an image from Dockerfile
    async fn build_image(
        &self,
        tag: &str,
        dockerfile_b64: &str,
        context_b64: Option<String>,
        request_id: String,
    ) -> Response {
        use base64::Engine;
        use bollard::image::BuildImageOptions;

        // Verify policy allows building this tag
        // For now, only allow term-compiler images or specific tags
        // This is a basic check, could be expanded in SecurityPolicy
        if !tag.starts_with("term-compiler:") && !tag.starts_with("ghcr.io/") {
            let err = format!("Image tag not allowed: {}", tag);
            self.audit(
                AuditAction::ImageBuild,
                "",
                "",
                None,
                false,
                Some(err.clone()),
            )
            .await;
            return Response::error(request_id, ContainerError::PolicyViolation(err));
        }

        // Prepare build context (tar archive)
        let mut tar_buffer = Vec::new();

        // 1. If context provided, decode it (expecting tar/tar.gz)
        if let Some(ctx) = context_b64 {
            match base64::engine::general_purpose::STANDARD.decode(ctx) {
                Ok(data) => {
                    tar_buffer = data;
                }
                Err(e) => {
                    return Response::error(
                        request_id,
                        ContainerError::InvalidConfig(format!("Invalid base64 context: {}", e)),
                    );
                }
            }
        }

        // 2. Add Dockerfile to context if not empty
        // If tar_buffer is empty, create new tar. If not, we append or overwrite Dockerfile?
        // Simpler approach: Create a new tar containing just the Dockerfile if context is None.
        // If context is provided, assume it contains everything needed OR inject Dockerfile.
        // For term-compiler, we just need Dockerfile mostly.

        // Let's decode Dockerfile
        let dockerfile_content =
            match base64::engine::general_purpose::STANDARD.decode(dockerfile_b64) {
                Ok(d) => d,
                Err(e) => {
                    return Response::error(
                        request_id,
                        ContainerError::InvalidConfig(format!("Invalid base64 dockerfile: {}", e)),
                    );
                }
            };

        // If no context provided, create a tar with just the Dockerfile
        if tar_buffer.is_empty() {
            let mut builder = tar::Builder::new(Vec::new());

            let mut header = tar::Header::new_gnu();
            header.set_size(dockerfile_content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();

            if let Err(e) =
                builder.append_data(&mut header, "Dockerfile", dockerfile_content.as_slice())
            {
                return Response::error(
                    request_id,
                    ContainerError::InternalError(format!("Failed to create tar: {}", e)),
                );
            }

            if let Err(e) = builder.finish() {
                return Response::error(
                    request_id,
                    ContainerError::InternalError(format!("Failed to finish tar: {}", e)),
                );
            }

            tar_buffer = builder.into_inner().unwrap_or_default();
        }
        // NOTE: If context IS provided, we assume it's a valid tar that contains Dockerfile
        // or we rely on the Dockerfile string being ignored?
        // Actually bollard/Docker API takes "dockerfile" option to specify filename,
        // but typically expects the file inside the tar.
        // For this implementation, we'll assume:
        // - If context is None: create tar with Dockerfile content named "Dockerfile"
        // - If context is Some: use it as is, ignore dockerfile_content (or expect client to have put it in context)
        // BUT the API has `dockerfile` param. Let's support the simple case first (no context).

        let options = BuildImageOptions {
            t: tag,
            dockerfile: "Dockerfile",
            rm: true,
            forcerm: true,
            ..Default::default()
        };

        info!(tag = %tag, size = tar_buffer.len(), "Starting image build");

        let mut stream = self
            .docker
            .build_image(options, None, Some(tar_buffer.into()));
        let mut logs = String::new();
        let mut image_id = String::new();

        while let Some(result) = stream.next().await {
            match result {
                Ok(info) => {
                    if let Some(stream) = info.stream {
                        logs.push_str(&stream);
                    }
                    if let Some(aux) = info.aux {
                        if let Some(id) = aux.id {
                            image_id = id;
                        }
                    }
                    if let Some(error) = info.error {
                        logs.push_str(&format!("\nERROR: {}", error));
                        self.audit(
                            AuditAction::ImageBuild,
                            "",
                            "",
                            None,
                            false,
                            Some(error.clone()),
                        )
                        .await;
                        return Response::error(
                            request_id,
                            ContainerError::DockerError(format!("Build failed: {}", error)),
                        );
                    }
                }
                Err(e) => {
                    return Response::error(
                        request_id,
                        ContainerError::DockerError(format!("Build error: {}", e)),
                    );
                }
            }
        }

        info!(tag = %tag, id = %image_id, "Image built successfully");

        self.audit(AuditAction::ImageBuild, "", "", Some(&image_id), true, None)
            .await;

        Response::Built {
            image_id,
            logs,
            request_id,
        }
    }

    /// Copy a file from container using Docker archive API
    /// Returns base64-encoded file contents
    async fn copy_from_container(
        &self,
        container_id: &str,
        path: &str,
        request_id: String,
    ) -> Response {
        use bollard::container::DownloadFromContainerOptions;
        use futures::TryStreamExt;

        let options = DownloadFromContainerOptions { path };

        // Download returns a tar archive stream of Bytes chunks
        let stream = self
            .docker
            .download_from_container(container_id, Some(options));

        // Collect all chunks into a single buffer
        let chunks: Vec<bytes::Bytes> = match stream.try_collect().await {
            Ok(data) => data,
            Err(e) => {
                return Response::error(
                    request_id,
                    ContainerError::DockerError(format!(
                        "Failed to download from container: {}",
                        e
                    )),
                );
            }
        };

        // Concatenate all chunks into a single Vec<u8>
        let tar_data: Vec<u8> = chunks.into_iter().flat_map(|b| b.to_vec()).collect();

        // Extract the file from the tar archive
        let mut archive = tar::Archive::new(tar_data.as_slice());
        let mut entries = match archive.entries() {
            Ok(e) => e,
            Err(e) => {
                return Response::error(
                    request_id,
                    ContainerError::DockerError(format!("Failed to read tar archive: {}", e)),
                );
            }
        };

        // Get the first file from the archive (there should only be one)
        let mut file_data = Vec::new();
        if let Some(entry) = entries.next() {
            match entry {
                Ok(mut entry) => {
                    if let Err(e) = std::io::Read::read_to_end(&mut entry, &mut file_data) {
                        return Response::error(
                            request_id,
                            ContainerError::DockerError(format!(
                                "Failed to read file from tar: {}",
                                e
                            )),
                        );
                    }
                }
                Err(e) => {
                    return Response::error(
                        request_id,
                        ContainerError::DockerError(format!("Failed to read tar entry: {}", e)),
                    );
                }
            }
        }

        use base64::Engine;
        let size = file_data.len();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&file_data);

        info!(
            container_id = %container_id,
            path = %path,
            size = size,
            "Copied file from container"
        );

        Response::CopyFromResult {
            data: encoded,
            size,
            request_id,
        }
    }

    /// Copy a file to container using Docker archive API
    /// Accepts base64-encoded file contents
    async fn copy_to_container(
        &self,
        container_id: &str,
        path: &str,
        data: &str,
        request_id: String,
    ) -> Response {
        use base64::Engine;
        use bollard::container::UploadToContainerOptions;

        // Decode base64 data
        let file_data = match base64::engine::general_purpose::STANDARD.decode(data) {
            Ok(d) => d,
            Err(e) => {
                return Response::error(
                    request_id,
                    ContainerError::InvalidConfig(format!("Invalid base64 data: {}", e)),
                );
            }
        };

        // Parse the path to get directory and filename
        let path_obj = std::path::Path::new(path);
        let parent_dir = path_obj
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/".to_string());
        let filename = path_obj
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());

        // Create a tar archive with the file
        let mut tar_buffer = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buffer);
            let mut header = tar::Header::new_gnu();
            header.set_size(file_data.len() as u64);
            header.set_mode(0o755); // Make executable
            header.set_cksum();

            if let Err(e) = builder.append_data(&mut header, &filename, file_data.as_slice()) {
                return Response::error(
                    request_id,
                    ContainerError::DockerError(format!("Failed to create tar archive: {}", e)),
                );
            }

            if let Err(e) = builder.finish() {
                return Response::error(
                    request_id,
                    ContainerError::DockerError(format!("Failed to finish tar archive: {}", e)),
                );
            }
        }

        let options = UploadToContainerOptions {
            path: parent_dir,
            ..Default::default()
        };

        // Upload the tar archive
        match self
            .docker
            .upload_to_container(container_id, Some(options), tar_buffer.into())
            .await
        {
            Ok(_) => {
                info!(
                    container_id = %container_id,
                    path = %path,
                    size = file_data.len(),
                    "Copied file to container"
                );
                Response::CopyToResult { request_id }
            }
            Err(e) => Response::error(
                request_id,
                ContainerError::DockerError(format!("Failed to upload to container: {}", e)),
            ),
        }
    }

    /// Ensure an image exists locally, pulling it if necessary
    async fn ensure_image(&self, image: &str) -> anyhow::Result<()> {
        // Check if image exists locally
        match self.docker.inspect_image(image).await {
            Ok(_) => {
                debug!(image = %image, "Image already exists locally");
                return Ok(());
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {
                // Image not found, need to pull
                info!(image = %image, "Image not found locally, pulling...");
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to inspect image: {}", e));
            }
        }

        // Pull the image
        let options = CreateImageOptions {
            from_image: image,
            ..Default::default()
        };

        let mut stream = self.docker.create_image(Some(options), None, None);

        while let Some(result) = stream.next().await {
            match result {
                Ok(info) => {
                    if let Some(status) = info.status {
                        debug!(image = %image, status = %status, "Pull progress");
                    }
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Failed to pull image: {}", e));
                }
            }
        }

        info!(image = %image, "Image pulled successfully");
        Ok(())
    }

    /// Cleanup stale containers from previous runs
    async fn cleanup_stale_containers(&self) -> anyhow::Result<()> {
        use bollard::container::ListContainersOptions;

        // Find all containers managed by this broker
        let label_filter = format!("{}=true", labels::MANAGED);
        let mut filters = HashMap::new();
        filters.insert("label", vec![label_filter.as_str()]);

        let options = ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        };

        let containers = self.docker.list_containers(Some(options)).await?;
        let count = containers.len();

        if count == 0 {
            info!("No stale containers to cleanup");
            return Ok(());
        }

        info!("Cleaning up {} stale containers from previous run", count);

        for container in containers {
            if let Some(id) = container.id {
                let short_id = &id[..12.min(id.len())];
                debug!("Removing stale container: {}", short_id);

                // Force remove (stop + remove)
                let options = RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                };

                if let Err(e) = self.docker.remove_container(&id, Some(options)).await {
                    warn!("Failed to remove stale container {}: {}", short_id, e);
                }
            }
        }

        info!("Stale container cleanup complete");
        Ok(())
    }

    /// Ensure the challenge network exists
    async fn ensure_network(&self) -> anyhow::Result<()> {
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
                internal: true, // Isolated from host network
                ..Default::default()
            };

            self.docker.create_network(config).await?;
            info!(network = %self.network_name, "Created isolated challenge network");
        }

        Ok(())
    }

    /// Get assigned ports for a container
    async fn get_container_ports(&self, container_id: &str) -> HashMap<u16, u16> {
        let mut ports = HashMap::new();

        if let Ok(info) = self.docker.inspect_container(container_id, None).await {
            if let Some(network_settings) = info.network_settings {
                if let Some(port_map) = network_settings.ports {
                    for (container_port, bindings) in port_map {
                        if let Some(bindings) = bindings {
                            for binding in bindings {
                                if let Some(host_port) = binding.host_port {
                                    if let Ok(hp) = host_port.parse::<u16>() {
                                        let cp = container_port
                                            .split('/')
                                            .next()
                                            .and_then(|s| s.parse().ok())
                                            .unwrap_or(0);
                                        ports.insert(cp, hp);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        ports
    }

    /// Add audit log entry
    async fn audit(
        &self,
        action: AuditAction,
        challenge_id: &str,
        owner_id: &str,
        container_id: Option<&str>,
        success: bool,
        error: Option<String>,
    ) {
        let entry = AuditEntry {
            timestamp: chrono::Utc::now(),
            action,
            challenge_id: challenge_id.to_string(),
            owner_id: owner_id.to_string(),
            container_id: container_id.map(String::from),
            success,
            error,
            details: HashMap::new(),
        };

        let mut log = self.audit_log.write().await;
        log.push(entry);

        // Keep only last 10000 entries
        if log.len() > 10000 {
            log.drain(0..1000);
        }
    }

    /// Get audit log
    pub async fn get_audit_log(&self) -> Vec<AuditEntry> {
        self.audit_log.read().await.clone()
    }

    /// Clone internal state for spawning handlers
    fn clone_internal(&self) -> Self {
        Self {
            docker: self.docker.clone(),
            policy: self.policy.clone(),
            network_name: self.network_name.clone(),
            containers_by_challenge: self.containers_by_challenge.clone(),
            containers_by_owner: self.containers_by_owner.clone(),
            audit_log: self.audit_log.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn test_broker_creation() {
        let broker = ContainerBroker::new().await;
        assert!(broker.is_ok());
    }

    #[tokio::test]
    async fn test_policy_enforcement() {
        // Test that strict policy blocks non-whitelisted images
        let policy = SecurityPolicy::strict();

        let config = ContainerConfig {
            image: "malicious/image:latest".to_string(),
            challenge_id: "test".to_string(),
            owner_id: "test".to_string(),
            ..Default::default()
        };

        assert!(policy.validate(&config).is_err());
    }

    #[tokio::test]
    async fn test_default_policy_allows_images() {
        // Default policy allows all images
        let policy = SecurityPolicy::default();

        let config = ContainerConfig {
            image: "any/image:latest".to_string(),
            challenge_id: "test".to_string(),
            owner_id: "test".to_string(),
            ..Default::default()
        };

        assert!(policy.validate(&config).is_ok());
    }
}
