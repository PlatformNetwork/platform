//! Client for communicating with the container broker
//!
//! This client connects to the broker via Unix socket.
//! It does NOT have direct Docker socket access.

use crate::protocol::{Request, Response};
use crate::types::*;
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Client for the secure container runtime broker
pub struct SecureContainerClient {
    socket_path: String,
}

impl SecureContainerClient {
    /// Create a new client
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
        }
    }

    /// Create client with default socket path
    pub fn default_path() -> Self {
        Self::new("/var/run/platform/container-broker.sock")
    }

    /// Send a request and get response
    async fn send_request(&self, request: Request) -> Result<Response, ContainerError> {
        let stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
            ContainerError::InternalError(format!("Failed to connect to broker: {}", e))
        })?;

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // Send request
        let json = serde_json::to_string(&request).map_err(|e| {
            ContainerError::InternalError(format!("Failed to serialize request: {}", e))
        })?;

        writer
            .write_all(json.as_bytes())
            .await
            .map_err(|e| ContainerError::InternalError(format!("Failed to send request: {}", e)))?;
        writer
            .write_all(b"\n")
            .await
            .map_err(|e| ContainerError::InternalError(format!("Failed to send newline: {}", e)))?;

        // Read response
        let mut line = String::new();
        reader.read_line(&mut line).await.map_err(|e| {
            ContainerError::InternalError(format!("Failed to read response: {}", e))
        })?;

        let response: Response = serde_json::from_str(line.trim()).map_err(|e| {
            ContainerError::InternalError(format!("Failed to parse response: {}", e))
        })?;

        Ok(response)
    }

    /// Generate a unique request ID
    fn request_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Ping the broker
    pub async fn ping(&self) -> Result<String, ContainerError> {
        let request = Request::Ping {
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::Pong { version, .. } => Ok(version),
            Response::Error { error, .. } => Err(error),
            _ => Err(ContainerError::InternalError(
                "Unexpected response".to_string(),
            )),
        }
    }

    /// Create a container
    pub async fn create_container(
        &self,
        config: ContainerConfig,
    ) -> Result<(String, String), ContainerError> {
        let request = Request::Create {
            config,
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::Created {
                container_id,
                container_name,
                ..
            } => Ok((container_id, container_name)),
            Response::Error { error, .. } => Err(error),
            _ => Err(ContainerError::InternalError(
                "Unexpected response".to_string(),
            )),
        }
    }

    /// Start a container
    pub async fn start_container(
        &self,
        container_id: &str,
    ) -> Result<ContainerStartResult, ContainerError> {
        let request = Request::Start {
            container_id: container_id.to_string(),
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::Started {
                container_id,
                ports,
                endpoint,
                ..
            } => Ok(ContainerStartResult {
                container_id,
                ports,
                endpoint,
            }),
            Response::Error { error, .. } => Err(error),
            _ => Err(ContainerError::InternalError(
                "Unexpected response".to_string(),
            )),
        }
    }

    /// Stop a container
    pub async fn stop_container(
        &self,
        container_id: &str,
        timeout_secs: u32,
    ) -> Result<(), ContainerError> {
        let request = Request::Stop {
            container_id: container_id.to_string(),
            timeout_secs,
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::Stopped { .. } => Ok(()),
            Response::Error { error, .. } => Err(error),
            _ => Err(ContainerError::InternalError(
                "Unexpected response".to_string(),
            )),
        }
    }

    /// Remove a container
    pub async fn remove_container(
        &self,
        container_id: &str,
        force: bool,
    ) -> Result<(), ContainerError> {
        let request = Request::Remove {
            container_id: container_id.to_string(),
            force,
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::Removed { .. } => Ok(()),
            Response::Error { error, .. } => Err(error),
            _ => Err(ContainerError::InternalError(
                "Unexpected response".to_string(),
            )),
        }
    }

    /// Execute a command in a container
    pub async fn exec(
        &self,
        container_id: &str,
        command: Vec<String>,
        working_dir: Option<String>,
        timeout_secs: u32,
    ) -> Result<ExecResult, ContainerError> {
        let request = Request::Exec {
            container_id: container_id.to_string(),
            command,
            working_dir,
            timeout_secs,
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::ExecResult { result, .. } => Ok(result),
            Response::Error { error, .. } => Err(error),
            _ => Err(ContainerError::InternalError(
                "Unexpected response".to_string(),
            )),
        }
    }

    /// Inspect a container
    pub async fn inspect(&self, container_id: &str) -> Result<ContainerInfo, ContainerError> {
        let request = Request::Inspect {
            container_id: container_id.to_string(),
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::Info { info, .. } => Ok(info),
            Response::Error { error, .. } => Err(error),
            _ => Err(ContainerError::InternalError(
                "Unexpected response".to_string(),
            )),
        }
    }

    /// List containers
    pub async fn list(
        &self,
        challenge_id: Option<&str>,
        owner_id: Option<&str>,
    ) -> Result<Vec<ContainerInfo>, ContainerError> {
        let request = Request::List {
            challenge_id: challenge_id.map(String::from),
            owner_id: owner_id.map(String::from),
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::ContainerList { containers, .. } => Ok(containers),
            Response::Error { error, .. } => Err(error),
            _ => Err(ContainerError::InternalError(
                "Unexpected response".to_string(),
            )),
        }
    }

    /// Get container logs
    pub async fn logs(&self, container_id: &str, tail: usize) -> Result<String, ContainerError> {
        let request = Request::Logs {
            container_id: container_id.to_string(),
            tail,
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::LogsResult { logs, .. } => Ok(logs),
            Response::Error { error, .. } => Err(error),
            _ => Err(ContainerError::InternalError(
                "Unexpected response".to_string(),
            )),
        }
    }

    /// Pull an image
    pub async fn pull_image(&self, image: &str) -> Result<(), ContainerError> {
        let request = Request::Pull {
            image: image.to_string(),
            request_id: Self::request_id(),
        };

        match self.send_request(request).await? {
            Response::Pulled { .. } => Ok(()),
            Response::Error { error, .. } => Err(error),
            _ => Err(ContainerError::InternalError(
                "Unexpected response".to_string(),
            )),
        }
    }

    // =========================================================================
    // POWERFUL HELPER METHODS
    // =========================================================================

    /// List all containers for a specific challenge
    pub async fn list_by_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Vec<ContainerInfo>, ContainerError> {
        self.list(Some(challenge_id), None).await
    }

    /// List all containers for a specific owner
    pub async fn list_by_owner(
        &self,
        owner_id: &str,
    ) -> Result<Vec<ContainerInfo>, ContainerError> {
        self.list(None, Some(owner_id)).await
    }

    /// List all managed containers
    pub async fn list_all(&self) -> Result<Vec<ContainerInfo>, ContainerError> {
        self.list(None, None).await
    }

    /// Stop all containers for a challenge
    pub async fn stop_all_by_challenge(
        &self,
        challenge_id: &str,
        timeout_secs: u32,
    ) -> Result<usize, ContainerError> {
        let containers = self.list_by_challenge(challenge_id).await?;
        let mut stopped = 0;

        for container in containers {
            if container.state == ContainerState::Running
                && self
                    .stop_container(&container.id, timeout_secs)
                    .await
                    .is_ok()
            {
                stopped += 1;
            }
        }

        Ok(stopped)
    }

    /// Remove all containers for a challenge
    pub async fn remove_all_by_challenge(
        &self,
        challenge_id: &str,
        force: bool,
    ) -> Result<usize, ContainerError> {
        let containers = self.list_by_challenge(challenge_id).await?;
        let mut removed = 0;

        for container in containers {
            if self.remove_container(&container.id, force).await.is_ok() {
                removed += 1;
            }
        }

        Ok(removed)
    }

    /// Stop and remove all containers for a challenge (cleanup)
    pub async fn cleanup_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<CleanupResult, ContainerError> {
        let containers = self.list_by_challenge(challenge_id).await?;
        let total = containers.len();
        let mut stopped = 0;
        let mut removed = 0;
        let mut errors = Vec::new();

        for container in containers {
            // Stop if running
            if container.state == ContainerState::Running {
                match self.stop_container(&container.id, 10).await {
                    Ok(_) => stopped += 1,
                    Err(e) => errors.push(format!("Stop {}: {}", container.id, e)),
                }
            }

            // Remove
            match self.remove_container(&container.id, true).await {
                Ok(_) => removed += 1,
                Err(e) => errors.push(format!("Remove {}: {}", container.id, e)),
            }
        }

        Ok(CleanupResult {
            total,
            stopped,
            removed,
            errors,
        })
    }

    /// Get endpoint URL for a container (http://container-name:port)
    pub async fn get_endpoint(
        &self,
        container_id: &str,
        port: u16,
    ) -> Result<String, ContainerError> {
        let info = self.inspect(container_id).await?;

        // For containers on the platform network, use container name
        Ok(format!("http://{}:{}", info.name, port))
    }

    /// Get host endpoint URL (http://localhost:mapped-port)
    pub async fn get_host_endpoint(
        &self,
        container_id: &str,
        container_port: u16,
    ) -> Result<Option<String>, ContainerError> {
        let info = self.inspect(container_id).await?;

        if let Some(host_port) = info.ports.get(&container_port) {
            Ok(Some(format!("http://127.0.0.1:{}", host_port)))
        } else {
            Ok(None)
        }
    }

    /// Wait for container to be healthy (simple HTTP check)
    pub async fn wait_healthy(
        &self,
        container_id: &str,
        port: u16,
        path: &str,
        timeout_secs: u32,
    ) -> Result<bool, ContainerError> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs as u64);

        // Use exec to curl the endpoint from inside the container
        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("curl -sf http://localhost:{}{} > /dev/null", port, path),
        ];

        while start.elapsed() < timeout {
            match self.exec(container_id, cmd.clone(), None, 5).await {
                Ok(result) if result.exit_code == 0 => return Ok(true),
                _ => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }

        Ok(false)
    }

    /// Run a one-shot container (create, start, wait for completion, get logs, remove)
    pub async fn run_oneshot(
        &self,
        config: ContainerConfig,
        timeout_secs: u32,
    ) -> Result<OneshotResult, ContainerError> {
        let (container_id, _) = self.create_container(config).await?;
        self.start_container(&container_id).await?;

        // Wait for completion or timeout
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs as u64);

        loop {
            let info = self.inspect(&container_id).await?;

            if info.state == ContainerState::Stopped || info.state == ContainerState::Dead {
                break;
            }

            if start.elapsed() >= timeout {
                // Timeout - stop the container
                let _ = self.stop_container(&container_id, 5).await;
                let logs = self.logs(&container_id, 1000).await.unwrap_or_default();
                let _ = self.remove_container(&container_id, true).await;

                return Ok(OneshotResult {
                    success: false,
                    logs,
                    duration_secs: start.elapsed().as_secs_f64(),
                    timed_out: true,
                });
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        let logs = self.logs(&container_id, 10000).await.unwrap_or_default();
        let _ = self.remove_container(&container_id, true).await;

        Ok(OneshotResult {
            success: true,
            logs,
            duration_secs: start.elapsed().as_secs_f64(),
            timed_out: false,
        })
    }

    /// Get resource usage summary for a challenge
    pub async fn get_challenge_stats(
        &self,
        challenge_id: &str,
    ) -> Result<ChallengeStats, ContainerError> {
        let containers = self.list_by_challenge(challenge_id).await?;

        let running = containers
            .iter()
            .filter(|c| c.state == ContainerState::Running)
            .count();
        let stopped = containers
            .iter()
            .filter(|c| c.state == ContainerState::Stopped)
            .count();
        let total = containers.len();

        Ok(ChallengeStats {
            challenge_id: challenge_id.to_string(),
            total_containers: total,
            running_containers: running,
            stopped_containers: stopped,
            container_ids: containers.iter().map(|c| c.id.clone()).collect(),
        })
    }
}

/// Result of cleanup operation
#[derive(Debug, Clone)]
pub struct CleanupResult {
    pub total: usize,
    pub stopped: usize,
    pub removed: usize,
    pub errors: Vec<String>,
}

impl CleanupResult {
    pub fn success(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Result of one-shot container run
#[derive(Debug, Clone)]
pub struct OneshotResult {
    pub success: bool,
    pub logs: String,
    pub duration_secs: f64,
    pub timed_out: bool,
}

/// Statistics for a challenge's containers
#[derive(Debug, Clone)]
pub struct ChallengeStats {
    pub challenge_id: String,
    pub total_containers: usize,
    pub running_containers: usize,
    pub stopped_containers: usize,
    pub container_ids: Vec<String>,
}

/// Result of starting a container
pub struct ContainerStartResult {
    pub container_id: String,
    pub ports: HashMap<u16, u16>,
    pub endpoint: Option<String>,
}

/// Builder for ContainerConfig
pub struct ContainerConfigBuilder {
    config: ContainerConfig,
}

impl ContainerConfigBuilder {
    pub fn new(image: &str, challenge_id: &str, owner_id: &str) -> Self {
        Self {
            config: ContainerConfig {
                image: image.to_string(),
                challenge_id: challenge_id.to_string(),
                owner_id: owner_id.to_string(),
                ..Default::default()
            },
        }
    }

    pub fn name(mut self, name: &str) -> Self {
        self.config.name = Some(name.to_string());
        self
    }

    pub fn cmd(mut self, cmd: Vec<String>) -> Self {
        self.config.cmd = Some(cmd);
        self
    }

    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.config.env.insert(key.to_string(), value.to_string());
        self
    }

    pub fn envs(mut self, vars: HashMap<String, String>) -> Self {
        self.config.env.extend(vars);
        self
    }

    pub fn working_dir(mut self, dir: &str) -> Self {
        self.config.working_dir = Some(dir.to_string());
        self
    }

    pub fn memory(mut self, bytes: i64) -> Self {
        self.config.resources.memory_bytes = bytes;
        self
    }

    pub fn memory_gb(mut self, gb: f64) -> Self {
        self.config.resources.memory_bytes = (gb * 1024.0 * 1024.0 * 1024.0) as i64;
        self
    }

    pub fn cpu(mut self, cores: f64) -> Self {
        self.config.resources.cpu_cores = cores;
        self
    }

    pub fn pids(mut self, limit: i64) -> Self {
        self.config.resources.pids_limit = limit;
        self
    }

    pub fn network_mode(mut self, mode: NetworkMode) -> Self {
        self.config.network.mode = mode;
        self
    }

    pub fn port(mut self, container_port: u16, host_port: u16) -> Self {
        self.config.network.ports.insert(container_port, host_port);
        self
    }

    pub fn expose(mut self, port: u16) -> Self {
        self.config.network.ports.insert(port, 0); // Dynamic host port
        self
    }

    pub fn allow_internet(mut self, allow: bool) -> Self {
        self.config.network.allow_internet = allow;
        self
    }

    pub fn mount(mut self, source: &str, target: &str, read_only: bool) -> Self {
        self.config.mounts.push(MountConfig {
            source: source.to_string(),
            target: target.to_string(),
            read_only,
        });
        self
    }

    pub fn mount_readonly(self, source: &str, target: &str) -> Self {
        self.mount(source, target, true)
    }

    pub fn label(mut self, key: &str, value: &str) -> Self {
        self.config
            .labels
            .insert(key.to_string(), value.to_string());
        self
    }

    pub fn build(self) -> ContainerConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = ContainerConfigBuilder::new(
            "ghcr.io/platformnetwork/test:latest",
            "challenge-1",
            "owner-1",
        )
        .name("test-container")
        .env("FOO", "bar")
        .memory_gb(2.0)
        .cpu(1.0)
        .expose(8080)
        .build();

        assert_eq!(config.image, "ghcr.io/platformnetwork/test:latest");
        assert_eq!(config.challenge_id, "challenge-1");
        assert_eq!(config.name, Some("test-container".to_string()));
        assert_eq!(config.env.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(config.resources.memory_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(config.network.ports.get(&8080), Some(&0));
    }

    #[test]
    fn test_config_builder_all_methods() {
        let mut env_vars = HashMap::new();
        env_vars.insert("VAR1".into(), "val1".into());
        env_vars.insert("VAR2".into(), "val2".into());

        let config = ContainerConfigBuilder::new("alpine:latest", "ch1", "owner1")
            .name("test")
            .cmd(vec!["sh".into(), "-c".into(), "echo hello".into()])
            .env("KEY", "value")
            .envs(env_vars)
            .working_dir("/app")
            .memory(1024 * 1024 * 1024) // 1GB
            .cpu(0.5)
            .pids(128)
            .network_mode(NetworkMode::Bridge)
            .port(8080, 8080)
            .allow_internet(true)
            .mount("/tmp/data", "/data", false)
            .mount_readonly("/tmp/config", "/config")
            .label("version", "1.0")
            .build();

        assert_eq!(config.name, Some("test".into()));
        assert_eq!(config.cmd, Some(vec!["sh".into(), "-c".into(), "echo hello".into()]));
        assert_eq!(config.env.get("KEY"), Some(&"value".into()));
        assert_eq!(config.env.get("VAR1"), Some(&"val1".into()));
        assert_eq!(config.working_dir, Some("/app".into()));
        assert_eq!(config.resources.memory_bytes, 1024 * 1024 * 1024);
        assert_eq!(config.resources.cpu_cores, 0.5);
        assert_eq!(config.resources.pids_limit, 128);
        assert_eq!(config.network.mode, NetworkMode::Bridge);
        assert_eq!(config.network.ports.get(&8080), Some(&8080));
        assert_eq!(config.network.allow_internet, true);
        assert_eq!(config.mounts.len(), 2);
        assert_eq!(config.mounts[0].read_only, false);
        assert_eq!(config.mounts[1].read_only, true);
        assert_eq!(config.labels.get("version"), Some(&"1.0".into()));
    }

    #[test]
    fn test_config_builder_memory_gb() {
        let config = ContainerConfigBuilder::new("test:1", "ch1", "owner1")
            .memory_gb(4.5)
            .build();
        
        assert_eq!(config.resources.memory_bytes, (4.5 * 1024.0 * 1024.0 * 1024.0) as i64);
    }

    #[test]
    fn test_secure_container_client_new() {
        let client = SecureContainerClient::new("/custom/path.sock");
        assert_eq!(client.socket_path, "/custom/path.sock");
    }

    #[test]
    fn test_secure_container_client_default_path() {
        let client = SecureContainerClient::default_path();
        assert_eq!(client.socket_path, "/var/run/platform/container-broker.sock");
    }

    #[test]
    fn test_cleanup_result_success() {
        let result = CleanupResult {
            total: 5,
            stopped: 5,
            removed: 5,
            errors: vec![],
        };
        assert!(result.success());

        let result_with_errors = CleanupResult {
            total: 5,
            stopped: 4,
            removed: 4,
            errors: vec!["Failed to stop container".into()],
        };
        assert!(!result_with_errors.success());
    }

    #[test]
    fn test_oneshot_result_fields() {
        let result = OneshotResult {
            success: true,
            logs: "test output".into(),
            duration_secs: 1.5,
            timed_out: false,
        };
        
        assert!(result.success);
        assert_eq!(result.logs, "test output");
        assert_eq!(result.duration_secs, 1.5);
        assert!(!result.timed_out);
    }

    #[test]
    fn test_challenge_stats_fields() {
        let stats = ChallengeStats {
            challenge_id: "challenge-123".into(),
            total_containers: 10,
            running_containers: 7,
            stopped_containers: 3,
            container_ids: vec!["c1".into(), "c2".into()],
        };
        
        assert_eq!(stats.challenge_id, "challenge-123");
        assert_eq!(stats.total_containers, 10);
        assert_eq!(stats.running_containers, 7);
        assert_eq!(stats.stopped_containers, 3);
        assert_eq!(stats.container_ids.len(), 2);
    }

    #[test]
    fn test_container_start_result_fields() {
        let mut ports = HashMap::new();
        ports.insert(8080, 38080);
        
        let result = ContainerStartResult {
            container_id: "container-123".into(),
            ports: ports.clone(),
            endpoint: Some("http://test-container:8080".into()),
        };
        
        assert_eq!(result.container_id, "container-123");
        assert_eq!(result.ports, ports);
        assert_eq!(result.endpoint, Some("http://test-container:8080".into()));
    }
}
