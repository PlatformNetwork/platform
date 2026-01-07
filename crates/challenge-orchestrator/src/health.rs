//! Health monitoring for challenge containers

use crate::{ChallengeInstance, ContainerStatus};
use parking_lot::RwLock;
use platform_core::ChallengeId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{info, warn};

/// Health monitor for challenge containers
pub struct HealthMonitor {
    challenges: Arc<RwLock<HashMap<ChallengeId, ChallengeInstance>>>,
    check_interval: Duration,
    client: reqwest::Client,
}

impl HealthMonitor {
    pub fn new(
        challenges: Arc<RwLock<HashMap<ChallengeId, ChallengeInstance>>>,
        check_interval: Duration,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            challenges,
            check_interval,
            client,
        }
    }

    /// Start the health monitoring loop
    pub async fn start(&self) -> anyhow::Result<()> {
        let challenges = self.challenges.clone();
        let client = self.client.clone();
        let check_interval = self.check_interval;

        tokio::spawn(async move {
            let mut interval = interval(check_interval);

            loop {
                interval.tick().await;

                let instances: Vec<_> = challenges
                    .read()
                    .iter()
                    .map(|(id, instance)| (*id, instance.clone()))
                    .collect();

                for (challenge_id, instance) in instances {
                    let health_result = check_container_health(&client, &instance).await;

                    let new_status = match health_result {
                        Ok(true) => ContainerStatus::Running,
                        Ok(false) => ContainerStatus::Unhealthy,
                        Err(e) => {
                            warn!(
                                challenge_id = %challenge_id,
                                error = %e,
                                "Health check failed"
                            );
                            ContainerStatus::Unhealthy
                        }
                    };

                    // Update status if changed
                    if let Some(instance) = challenges.write().get_mut(&challenge_id) {
                        if instance.status != new_status {
                            info!(
                                challenge_id = %challenge_id,
                                old_status = ?instance.status,
                                new_status = ?new_status,
                                "Container status changed"
                            );
                            instance.status = new_status;
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Manually check health of a specific container
    pub async fn check(&self, challenge_id: &ChallengeId) -> Option<ContainerStatus> {
        let instance = self.challenges.read().get(challenge_id).cloned()?;

        let healthy = check_container_health(&self.client, &instance)
            .await
            .unwrap_or(false);

        let status = if healthy {
            ContainerStatus::Running
        } else {
            ContainerStatus::Unhealthy
        };

        // Update status
        if let Some(inst) = self.challenges.write().get_mut(challenge_id) {
            inst.status = status.clone();
        }

        Some(status)
    }

    /// Get all unhealthy challenges
    pub fn get_unhealthy(&self) -> Vec<ChallengeId> {
        self.challenges
            .read()
            .iter()
            .filter(|(_, instance)| instance.status == ContainerStatus::Unhealthy)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get health summary
    pub fn summary(&self) -> HealthSummary {
        let challenges = self.challenges.read();

        let total = challenges.len();
        let running = challenges
            .iter()
            .filter(|(_, i)| i.status == ContainerStatus::Running)
            .count();
        let unhealthy = challenges
            .iter()
            .filter(|(_, i)| i.status == ContainerStatus::Unhealthy)
            .count();
        let starting = challenges
            .iter()
            .filter(|(_, i)| i.status == ContainerStatus::Starting)
            .count();

        HealthSummary {
            total,
            running,
            unhealthy,
            starting,
            stopped: total - running - unhealthy - starting,
        }
    }
}

/// Check health of a container via HTTP
async fn check_container_health(
    client: &reqwest::Client,
    instance: &ChallengeInstance,
) -> anyhow::Result<bool> {
    let url = format!("{}/health", instance.endpoint);

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        return Ok(false);
    }

    // Try to parse health response
    if let Ok(health) = response.json::<HealthCheckResponse>().await {
        Ok(health.status == "ok" || health.status == "healthy")
    } else {
        // If we got a 200 but can't parse, assume healthy
        Ok(true)
    }
}

#[derive(serde::Deserialize)]
struct HealthCheckResponse {
    status: String,
}

/// Health summary for all containers
#[derive(Clone, Debug, serde::Serialize)]
pub struct HealthSummary {
    pub total: usize,
    pub running: usize,
    pub unhealthy: usize,
    pub starting: usize,
    pub stopped: usize,
}

impl HealthSummary {
    pub fn all_healthy(&self) -> bool {
        self.unhealthy == 0 && self.stopped == 0
    }

    pub fn percentage_healthy(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            (self.running as f64 / self.total as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::RwLock;
    use platform_core::ChallengeId;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Create a sample `ChallengeInstance` populated with deterministic placeholder values for testing.
    ///
    /// The returned instance uses fixed values for `container_id`, `image`, and `endpoint`; the `started_at`
    /// is set to the current time and the `status` is taken from the `status` parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// let inst = sample_instance(ContainerStatus::Starting);
    /// assert_eq!(inst.container_id, "cid");
    /// assert_eq!(inst.image, "ghcr.io/platformnetwork/example:latest");
    /// assert_eq!(inst.endpoint, "http://127.0.0.1:9000");
    /// assert_eq!(inst.status, ContainerStatus::Starting);
    /// ```
    fn sample_instance(status: ContainerStatus) -> ChallengeInstance {
        ChallengeInstance {
            challenge_id: ChallengeId::new(),
            container_id: "cid".into(),
            image: "ghcr.io/platformnetwork/example:latest".into(),
            endpoint: "http://127.0.0.1:9000".into(),
            started_at: chrono::Utc::now(),
            status,
        }
    }

    #[test]
    fn test_health_summary() {
        let summary = HealthSummary {
            total: 5,
            running: 4,
            unhealthy: 1,
            starting: 0,
            stopped: 0,
        };

        assert!(!summary.all_healthy());
        assert_eq!(summary.percentage_healthy(), 80.0);
    }

    #[test]
    fn test_all_healthy() {
        let summary = HealthSummary {
            total: 3,
            running: 3,
            unhealthy: 0,
            starting: 0,
            stopped: 0,
        };

        assert!(summary.all_healthy());
        assert_eq!(summary.percentage_healthy(), 100.0);
    }

    #[test]
    fn test_percentage_healthy_handles_zero_total() {
        let summary = HealthSummary {
            total: 0,
            running: 0,
            unhealthy: 0,
            starting: 0,
            stopped: 0,
        };

        assert_eq!(summary.percentage_healthy(), 100.0);
    }

    #[test]
    fn test_get_unhealthy_lists_ids() {
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let healthy_instance = sample_instance(ContainerStatus::Running);
        let healthy_id = healthy_instance.challenge_id;
        let unhealthy_instance = sample_instance(ContainerStatus::Unhealthy);
        let unhealthy_id = unhealthy_instance.challenge_id;

        {
            let mut guard = challenges.write();
            guard.insert(healthy_id, healthy_instance.clone());
            guard.insert(unhealthy_id, unhealthy_instance.clone());
        }

        let monitor = HealthMonitor::new(challenges, Duration::from_secs(5));
        let ids = monitor.get_unhealthy();

        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], unhealthy_id);
    }

    #[test]
    fn test_health_monitor_summary_counts_statuses() {
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        {
            let mut guard = challenges.write();
            guard.insert(
                ChallengeId::new(),
                sample_instance(ContainerStatus::Running),
            );
            guard.insert(
                ChallengeId::new(),
                sample_instance(ContainerStatus::Unhealthy),
            );
            guard.insert(
                ChallengeId::new(),
                sample_instance(ContainerStatus::Starting),
            );
        }

        let monitor = HealthMonitor::new(challenges, Duration::from_secs(5));
        let summary = monitor.summary();

        assert_eq!(summary.total, 3);
        assert_eq!(summary.running, 1);
        assert_eq!(summary.unhealthy, 1);
        assert_eq!(summary.starting, 1);
        assert_eq!(summary.stopped, 0);
    }

    /// Starts a one-shot HTTP test server that accepts a single connection and replies with the given status line and body.
    ///
    /// The server binds to localhost on an ephemeral port and returns its socket address and a JoinHandle for the spawned task.
    /// The spawned task accepts one connection, reads the request (up to 1024 bytes), writes a response composed from `status_line` and `body`, and then completes.
    ///
    /// # Examples
    ///
    /// ```
    /// # tokio::test
    /// # async fn _example() {
    /// let (addr, handle) = spawn_health_server("200 OK", r#"{"status":"ok"}"#).await;
    /// let url = format!("http://{}/health", addr);
    /// let res = reqwest::get(&url).await.unwrap();
    /// assert!(res.status().is_success());
    /// // ensure server task completes
    /// handle.await.unwrap();
    /// # }
    /// ```
    async fn spawn_health_server(
        status_line: &str,
        body: &str,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local server");
        let addr = listener.local_addr().expect("read addr");
        let body = body.to_string();
        let response = format!(
            "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(), body
        );

        let handle = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        (addr, handle)
    }

    /// Starts a lightweight TCP server that repeatedly accepts connections and responds with a fixed HTTP response.
    ///
    /// The server listens on 127.0.0.1 at an OS-assigned port and responds to every incoming connection with an HTTP response
    /// constructed from `status_line` and `body`. Each connection is handled in a spawned task so the server continues accepting
    /// subsequent connections until the listener or returned task is dropped or aborted.
    ///
    /// # Parameters
    ///
    /// - `status_line`: the HTTP status line to use (for example, `"HTTP/1.1 200 OK"` or `"HTTP/1.1 500 Internal Server Error"`).
    /// - `body`: the response body to include; `Content-Length` and `Content-Type: application/json` are added automatically.
    ///
    /// # Returns
    ///
    /// A tuple of `(addr, handle)` where:
    /// - `addr` is the socket address the server is bound to (useful for issuing HTTP requests to the server).
    /// - `handle` is a `tokio::task::JoinHandle<()>` for the background accept loop; aborting or awaiting it will stop the server.
    ///
    /// # Examples
    ///
    /// ```
    /// #[tokio::test]
    /// async fn spawn_repeating_health_server_example() {
    ///     let (addr, handle) = spawn_repeating_health_server("HTTP/1.1 200 OK", "{\"status\":\"ok\"}").await;
    ///     // addr can be used to make requests to the server (for example via reqwest).
    ///     // Stop the server when done.
    ///     handle.abort();
    ///     let _ = handle.await;
    /// }
    /// ```
    async fn spawn_repeating_health_server(
        status_line: &str,
        body: &str,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind repeating server");
        let addr = listener.local_addr().expect("read addr");
        let body = body.to_string();
        let response = Arc::new(format!(
            "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(), body
        ));

        let handle = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => break,
                };
                let resp = response.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let _ = socket.write_all(resp.as_bytes()).await;
                });
            }
        });

        (addr, handle)
    }

    /// Spawns a TCP server that accepts incoming connections and immediately closes them.
    
    ///
    
    /// The server listens on 127.0.0.1 on an OS-assigned port and runs until its listener is dropped
    
    /// or the returned task handle is aborted. This is useful for simulating a health endpoint that
    
    /// closes connections (causing request errors) in tests.
    
    ///
    
    /// # Examples
    
    ///
    
    /// ```
    
    /// # tokio::test
    
    /// # async fn example() {
    
    /// let (addr, handle) = spawn_closing_health_server().await;
    
    /// // connecting succeeds but the server will close the connection immediately
    
    /// let _stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    
    /// // stop the server task
    
    /// handle.abort();
    
    /// # }
    
    /// ```
    async fn spawn_closing_health_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind closing server");
        let addr = listener.local_addr().expect("read addr");
        let handle = tokio::spawn(async move {
            loop {
                let (socket, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => break,
                };
                drop(socket);
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn test_health_monitor_check_sets_running_on_success() {
        let (addr, handle) = spawn_health_server("200 OK", r#"{"status":"ok"}"#).await;
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let mut instance = sample_instance(ContainerStatus::Starting);
        instance.endpoint = format!("http://{}", addr);
        let challenge_id = instance.challenge_id;
        challenges.write().insert(challenge_id, instance);

        let monitor = HealthMonitor::new(challenges.clone(), Duration::from_secs(5));
        let status = monitor
            .check(&challenge_id)
            .await
            .expect("status should be returned");

        assert_eq!(status, ContainerStatus::Running);
        assert_eq!(
            challenges
                .read()
                .get(&challenge_id)
                .expect("challenge present")
                .status,
            ContainerStatus::Running
        );

        handle.await.expect("server finished");
    }

    #[tokio::test]
    async fn test_health_monitor_check_marks_unhealthy_on_failure() {
        let (addr, handle) =
            spawn_health_server("500 Internal Server Error", r#"{"status":"error"}"#).await;
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let mut instance = sample_instance(ContainerStatus::Running);
        instance.endpoint = format!("http://{}", addr);
        let challenge_id = instance.challenge_id;
        challenges.write().insert(challenge_id, instance);

        let monitor = HealthMonitor::new(challenges.clone(), Duration::from_secs(5));
        let status = monitor
            .check(&challenge_id)
            .await
            .expect("status should be returned");

        assert_eq!(status, ContainerStatus::Unhealthy);
        assert_eq!(
            challenges
                .read()
                .get(&challenge_id)
                .expect("challenge present")
                .status,
            ContainerStatus::Unhealthy
        );

        handle.await.expect("server finished");
    }

    #[tokio::test]
    async fn test_health_monitor_start_updates_status() {
        let (addr, handle) = spawn_repeating_health_server("200 OK", r#"{"status":"ok"}"#).await;
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let mut instance = sample_instance(ContainerStatus::Starting);
        instance.endpoint = format!("http://{}", addr);
        let challenge_id = instance.challenge_id;
        challenges.write().insert(challenge_id, instance);

        let monitor = HealthMonitor::new(challenges.clone(), Duration::from_millis(10));
        monitor.start().await.expect("monitor starts");

        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            if challenges
                .read()
                .get(&challenge_id)
                .map(|inst| inst.status == ContainerStatus::Running)
                .unwrap_or(false)
            {
                break;
            }

            if Instant::now() > deadline {
                panic!("status never updated to running");
            }

            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        handle.abort();
    }

    #[tokio::test]
    async fn test_health_monitor_start_marks_unhealthy_on_failed_response() {
        let (addr, handle) =
            spawn_repeating_health_server("500 Internal Server Error", r#"{"status":"error"}"#)
                .await;
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let mut instance = sample_instance(ContainerStatus::Running);
        instance.endpoint = format!("http://{}", addr);
        let challenge_id = instance.challenge_id;
        challenges.write().insert(challenge_id, instance);

        let monitor = HealthMonitor::new(challenges.clone(), Duration::from_millis(10));
        monitor.start().await.expect("monitor starts");

        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            if challenges
                .read()
                .get(&challenge_id)
                .map(|inst| inst.status == ContainerStatus::Unhealthy)
                .unwrap_or(false)
            {
                break;
            }

            if Instant::now() > deadline {
                panic!("status never updated to unhealthy");
            }

            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        handle.abort();
    }

    #[tokio::test]
    async fn test_health_monitor_start_handles_request_error() {
        let (addr, handle) = spawn_closing_health_server().await;
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let mut instance = sample_instance(ContainerStatus::Running);
        instance.endpoint = format!("http://{}", addr);
        let challenge_id = instance.challenge_id;
        challenges.write().insert(challenge_id, instance);

        let monitor = HealthMonitor::new(challenges.clone(), Duration::from_millis(10));
        monitor.start().await.expect("monitor starts");

        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            if challenges
                .read()
                .get(&challenge_id)
                .map(|inst| inst.status == ContainerStatus::Unhealthy)
                .unwrap_or(false)
            {
                break;
            }

            if Instant::now() > deadline {
                panic!("status never updated after request error");
            }

            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        handle.abort();
    }

    #[tokio::test]
    async fn test_health_monitor_check_treats_parse_error_as_healthy() {
        let (addr, handle) = spawn_health_server("200 OK", "not-json").await;
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let mut instance = sample_instance(ContainerStatus::Starting);
        instance.endpoint = format!("http://{}", addr);
        let challenge_id = instance.challenge_id;
        challenges.write().insert(challenge_id, instance);

        let monitor = HealthMonitor::new(challenges.clone(), Duration::from_secs(5));
        let status = monitor.check(&challenge_id).await.expect("status returned");

        assert_eq!(status, ContainerStatus::Running);
        assert_eq!(
            challenges
                .read()
                .get(&challenge_id)
                .expect("challenge present")
                .status,
            ContainerStatus::Running
        );

        handle.await.expect("server finished");
    }
}