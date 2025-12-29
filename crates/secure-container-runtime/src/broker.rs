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
        let _request_id = request.request_id().to_string();

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
        // Test that policy validation works without Docker
        let policy = SecurityPolicy::default();

        let config = ContainerConfig {
            image: "malicious/image:latest".to_string(),
            challenge_id: "test".to_string(),
            owner_id: "test".to_string(),
            ..Default::default()
        };

        assert!(policy.validate(&config).is_err());
    }
}
