//! Challenge evaluator - generic proxy for routing requests to challenge containers
//!
//! IMPORTANT: This evaluator is challenge-agnostic. Each challenge defines its own
//! request/response format. The evaluator simply proxies JSON payloads.
//!
//! For term-challenge specific formats, see term-challenge-repo/src/server.rs

use crate::{ChallengeInstance, ContainerStatus};
use parking_lot::RwLock;
use platform_core::ChallengeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Generic evaluator for routing requests to challenge containers
pub struct ChallengeEvaluator {
    challenges: Arc<RwLock<HashMap<ChallengeId, ChallengeInstance>>>,
    client: reqwest::Client,
}

impl ChallengeEvaluator {
    pub fn new(challenges: Arc<RwLock<HashMap<ChallengeId, ChallengeInstance>>>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3600))
            .build()
            .expect("Failed to create HTTP client");

        Self { challenges, client }
    }

    /// Send a generic evaluation request to a challenge container
    /// The request/response format is defined by each challenge, not by the orchestrator
    pub async fn evaluate_generic(
        &self,
        challenge_id: ChallengeId,
        request: serde_json::Value,
        timeout_secs: Option<u64>,
    ) -> Result<serde_json::Value, EvaluatorError> {
        let instance = self
            .challenges
            .read()
            .get(&challenge_id)
            .cloned()
            .ok_or(EvaluatorError::ChallengeNotFound(challenge_id))?;

        if instance.status != ContainerStatus::Running {
            return Err(EvaluatorError::ChallengeNotReady(challenge_id));
        }

        let url = format!("{}/evaluate", instance.endpoint);

        debug!(
            challenge_id = %challenge_id,
            "Sending evaluation request to {}", url
        );

        let response = self
            .client
            .post(&url)
            .json(&request)
            .timeout(Duration::from_secs(timeout_secs.unwrap_or(3600)))
            .send()
            .await
            .map_err(|e| EvaluatorError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(EvaluatorError::ChallengeError {
                status: status.as_u16(),
                message: body,
            });
        }

        let result = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| EvaluatorError::ParseError(e.to_string()))?;

        info!(
            challenge_id = %challenge_id,
            "Evaluation completed"
        );

        Ok(result)
    }

    /// Proxy any request to a challenge endpoint
    pub async fn proxy_request(
        &self,
        challenge_id: ChallengeId,
        endpoint: &str,
        method: reqwest::Method,
        body: Option<serde_json::Value>,
        timeout_secs: Option<u64>,
    ) -> Result<serde_json::Value, EvaluatorError> {
        let instance = self
            .challenges
            .read()
            .get(&challenge_id)
            .cloned()
            .ok_or(EvaluatorError::ChallengeNotFound(challenge_id))?;

        if instance.status != ContainerStatus::Running {
            return Err(EvaluatorError::ChallengeNotReady(challenge_id));
        }

        let url = format!("{}/{}", instance.endpoint, endpoint.trim_start_matches('/'));

        debug!(
            challenge_id = %challenge_id,
            method = %method,
            "Proxying request to {}", url
        );

        let mut req = self
            .client
            .request(method, &url)
            .timeout(Duration::from_secs(timeout_secs.unwrap_or(30)));

        if let Some(b) = body {
            req = req.json(&b);
        }

        let response = req
            .send()
            .await
            .map_err(|e| EvaluatorError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(EvaluatorError::ChallengeError {
                status: status.as_u16(),
                message: body,
            });
        }

        response
            .json()
            .await
            .map_err(|e| EvaluatorError::ParseError(e.to_string()))
    }

    /// Get challenge info
    pub async fn get_info(
        &self,
        challenge_id: ChallengeId,
    ) -> Result<ChallengeInfo, EvaluatorError> {
        let instance = self
            .challenges
            .read()
            .get(&challenge_id)
            .cloned()
            .ok_or(EvaluatorError::ChallengeNotFound(challenge_id))?;

        let url = format!("{}/info", instance.endpoint);

        let response = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| EvaluatorError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(EvaluatorError::ChallengeError {
                status: response.status().as_u16(),
                message: "Failed to get challenge info".to_string(),
            });
        }

        response
            .json()
            .await
            .map_err(|e| EvaluatorError::ParseError(e.to_string()))
    }

    /// Check health of a specific challenge
    pub async fn check_health(&self, challenge_id: ChallengeId) -> Result<bool, EvaluatorError> {
        let instance = self
            .challenges
            .read()
            .get(&challenge_id)
            .cloned()
            .ok_or(EvaluatorError::ChallengeNotFound(challenge_id))?;

        let url = format!("{}/health", instance.endpoint);

        match self
            .client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(e) => {
                warn!(challenge_id = %challenge_id, "Health check failed: {}", e);
                Ok(false)
            }
        }
    }

    /// List all available challenges with their status
    pub fn list_challenges(&self) -> Vec<ChallengeStatus> {
        self.challenges
            .read()
            .iter()
            .map(|(id, instance)| ChallengeStatus {
                challenge_id: *id,
                image: instance.image.clone(),
                status: instance.status.clone(),
                endpoint: instance.endpoint.clone(),
                started_at: instance.started_at,
            })
            .collect()
    }
}

/// Challenge info response (generic)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeInfo {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub mechanism_id: u8,
    #[serde(default)]
    pub emission_weight: f64,
    #[serde(default)]
    pub tasks_count: u32,
    pub description: Option<String>,
}

/// Challenge status for listing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeStatus {
    pub challenge_id: ChallengeId,
    pub image: String,
    pub status: ContainerStatus,
    pub endpoint: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

/// Evaluator errors
#[derive(Debug, thiserror::Error)]
pub enum EvaluatorError {
    #[error("Challenge not found: {0}")]
    ChallengeNotFound(ChallengeId),

    #[error("Challenge not ready: {0}")]
    ChallengeNotReady(ChallengeId),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Challenge error (status {status}): {message}")]
    ChallengeError { status: u16, message: String },

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Timeout")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::RwLock;
    use platform_core::ChallengeId;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio_test::block_on;

    /// Creates a pre-filled `ChallengeInstance` for tests using the given container `status`.
    ///
    /// The returned instance has deterministic placeholder values for `container_id`, `image`,
    /// and `endpoint`, with `started_at` set to the current UTC time.
    ///
    /// # Examples
    ///
    /// ```
    /// let inst = sample_instance(ContainerStatus::Running);
    /// assert_eq!(inst.status, ContainerStatus::Running);
    /// assert!(inst.image.contains("ghcr.io/platformnetwork/example"));
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
    fn test_challenge_info_deserialize() {
        let json = r#"{
            "name": "term-challenge",
            "version": "1.0.0",
            "description": "Terminal benchmark challenge"
        }"#;

        let info: ChallengeInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.name, "term-challenge");
        assert_eq!(info.mechanism_id, 0); // default
    }

    #[test]
    fn test_evaluate_generic_requires_running_status() {
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let instance = sample_instance(ContainerStatus::Starting);
        let challenge_id = instance.challenge_id;
        challenges.write().insert(challenge_id, instance.clone());

        let evaluator = ChallengeEvaluator::new(challenges);
        let err = block_on(evaluator.evaluate_generic(challenge_id, serde_json::json!({}), None))
            .expect_err("should fail when not running");

        match err {
            EvaluatorError::ChallengeNotReady(id) => assert_eq!(id, challenge_id),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_proxy_request_missing_challenge() {
        let evaluator = ChallengeEvaluator::new(Arc::new(RwLock::new(HashMap::new())));
        let challenge_id = ChallengeId::new();
        let err = block_on(evaluator.proxy_request(
            challenge_id,
            "status",
            reqwest::Method::GET,
            None,
            None,
        ))
        .expect_err("missing challenge should error");

        match err {
            EvaluatorError::ChallengeNotFound(id) => assert_eq!(id, challenge_id),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_proxy_request_requires_running_status() {
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let instance = sample_instance(ContainerStatus::Starting);
        let challenge_id = instance.challenge_id;
        challenges.write().insert(challenge_id, instance);

        let evaluator = ChallengeEvaluator::new(challenges);
        let err = evaluator
            .proxy_request(challenge_id, "health", reqwest::Method::GET, None, None)
            .await
            .expect_err("non-running challenge should be rejected");

        match err {
            EvaluatorError::ChallengeNotReady(id) => assert_eq!(id, challenge_id),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_list_challenges_returns_current_instances() {
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let instance_a = sample_instance(ContainerStatus::Running);
        let instance_b = sample_instance(ContainerStatus::Unhealthy);
        let id_a = instance_a.challenge_id;
        let id_b = instance_b.challenge_id;
        challenges.write().insert(id_a, instance_a.clone());
        challenges.write().insert(id_b, instance_b.clone());

        let evaluator = ChallengeEvaluator::new(challenges);
        let list = evaluator.list_challenges();
        assert_eq!(list.len(), 2);

        let status_map: std::collections::HashMap<ChallengeId, ContainerStatus> = list
            .into_iter()
            .map(|entry| (entry.challenge_id, entry.status))
            .collect();

        assert_eq!(status_map.get(&id_a), Some(&ContainerStatus::Running));
        assert_eq!(status_map.get(&id_b), Some(&ContainerStatus::Unhealthy));
    }

    #[tokio::test]
    async fn test_evaluate_generic_succeeds_with_ok_response() {
        let (addr, handle) =
            spawn_static_http_server("200 OK", r#"{"value": 42}"#, "application/json").await;
        let endpoint = format!("http://{}", addr);
        let (evaluator, challenge_id) = evaluator_with_instance(endpoint, ContainerStatus::Running);

        let response = evaluator
            .evaluate_generic(challenge_id, serde_json::json!({"input": 1}), Some(5))
            .await
            .expect("evaluation succeeds");

        assert_eq!(response["value"], 42);
        handle.await.expect("server finished");
    }

    #[tokio::test]
    async fn test_evaluate_generic_reports_challenge_error() {
        let (addr, handle) =
            spawn_static_http_server("500 Internal Server Error", "boom", "text/plain").await;
        let endpoint = format!("http://{}", addr);
        let (evaluator, challenge_id) = evaluator_with_instance(endpoint, ContainerStatus::Running);

        let err = evaluator
            .evaluate_generic(challenge_id, serde_json::json!({}), Some(5))
            .await
            .expect_err("should propagate challenge error");

        match err {
            EvaluatorError::ChallengeError { status, message } => {
                assert_eq!(status, 500);
                assert_eq!(message, "boom");
            }
            other => panic!("unexpected error: {:?}", other),
        }

        handle.await.expect("server finished");
    }

    #[tokio::test]
    async fn test_evaluate_generic_reports_parse_error() {
        let (addr, handle) = spawn_static_http_server("200 OK", "not json", "text/plain").await;
        let endpoint = format!("http://{}", addr);
        let (evaluator, challenge_id) = evaluator_with_instance(endpoint, ContainerStatus::Running);

        let err = evaluator
            .evaluate_generic(challenge_id, serde_json::json!({}), Some(5))
            .await
            .expect_err("invalid JSON should error");

        assert!(matches!(err, EvaluatorError::ParseError(_)));

        handle.await.expect("server finished");
    }

    #[tokio::test]
    async fn test_evaluate_generic_reports_network_error() {
        let (addr, handle) = spawn_drop_http_server().await;
        let endpoint = format!("http://{}", addr);
        let (evaluator, challenge_id) = evaluator_with_instance(endpoint, ContainerStatus::Running);

        let err = evaluator
            .evaluate_generic(challenge_id, serde_json::json!({}), Some(1))
            .await
            .expect_err("network failure should bubble up");

        assert!(matches!(err, EvaluatorError::NetworkError(_)));
        handle.await.expect("server finished");
    }

    #[tokio::test]
    async fn test_proxy_request_returns_payload() {
        let (addr, handle) =
            spawn_static_http_server("200 OK", r#"{"ok":true}"#, "application/json").await;
        let endpoint = format!("http://{}", addr);
        let (evaluator, challenge_id) = evaluator_with_instance(endpoint, ContainerStatus::Running);

        let response = evaluator
            .proxy_request(
                challenge_id,
                "custom/path",
                reqwest::Method::POST,
                Some(serde_json::json!({"payload": true})),
                Some(5),
            )
            .await
            .expect("proxy request succeeds");

        assert_eq!(response["ok"], true);
        handle.await.expect("server finished");
    }

    #[tokio::test]
    async fn test_proxy_request_reports_challenge_error() {
        let (addr, handle) =
            spawn_static_http_server("503 Service Unavailable", "oops", "text/plain").await;
        let endpoint = format!("http://{}", addr);
        let (evaluator, challenge_id) = evaluator_with_instance(endpoint, ContainerStatus::Running);

        let err = evaluator
            .proxy_request(challenge_id, "custom", reqwest::Method::GET, None, Some(5))
            .await
            .expect_err("should surface challenge error");

        match err {
            EvaluatorError::ChallengeError { status, message } => {
                assert_eq!(status, 503);
                assert_eq!(message, "oops");
            }
            other => panic!("unexpected error: {:?}", other),
        }

        handle.await.expect("server finished");
    }

    #[tokio::test]
    async fn test_get_info_fetches_metadata() {
        let body = r#"{"name":"demo","version":"0.1.0","mechanism_id":7}"#;
        let (addr, handle) = spawn_static_http_server("200 OK", body, "application/json").await;
        let endpoint = format!("http://{}", addr);
        let (evaluator, challenge_id) = evaluator_with_instance(endpoint, ContainerStatus::Running);

        let info = evaluator
            .get_info(challenge_id)
            .await
            .expect("info should deserialize");

        assert_eq!(info.name, "demo");
        assert_eq!(info.version, "0.1.0");
        assert_eq!(info.mechanism_id, 7);
        handle.await.expect("server finished");
    }

    #[tokio::test]
    async fn test_get_info_reports_error_status() {
        let (addr, handle) =
            spawn_static_http_server("404 Not Found", "missing", "text/plain").await;
        let endpoint = format!("http://{}", addr);
        let (evaluator, challenge_id) = evaluator_with_instance(endpoint, ContainerStatus::Running);

        let err = evaluator
            .get_info(challenge_id)
            .await
            .expect_err("should return challenge error for non-200 info");

        match err {
            EvaluatorError::ChallengeError { status, message } => {
                assert_eq!(status, 404);
                assert_eq!(message, "Failed to get challenge info");
            }
            other => panic!("unexpected error: {:?}", other),
        }

        handle.await.expect("server finished");
    }

    #[tokio::test]
    async fn test_check_health_reflects_status_code() {
        let (addr_ok, handle_ok) =
            spawn_static_http_server("200 OK", "{}", "application/json").await;
        let (evaluator, ok_id) =
            evaluator_with_instance(format!("http://{}", addr_ok), ContainerStatus::Running);

        assert!(evaluator
            .check_health(ok_id)
            .await
            .expect("health request succeeds"));
        handle_ok.await.expect("server finished");

        let (addr_err, handle_err) =
            spawn_static_http_server("503 Service Unavailable", "oops", "text/plain").await;
        let (evaluator, fail_id) =
            evaluator_with_instance(format!("http://{}", addr_err), ContainerStatus::Running);

        assert!(!evaluator
            .check_health(fail_id)
            .await
            .expect("health request succeeds"));
        handle_err.await.expect("server finished");
    }

    #[tokio::test]
    async fn test_check_health_handles_request_failure() {
        let (addr, handle) = spawn_drop_http_server().await;
        let (evaluator, challenge_id) =
            evaluator_with_instance(format!("http://{}", addr), ContainerStatus::Running);

        let result = evaluator
            .check_health(challenge_id)
            .await
            .expect("network errors should be converted to false");

        assert!(!result);
        handle.await.expect("server finished");
    }

    /// Create a ChallengeEvaluator pre-populated with a single ChallengeInstance.
    ///
    /// The provided `endpoint` is set as the instance's base URL and `status` is used
    /// as the instance's container status before registration.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// let (evaluator, challenge_id) = evaluator_with_instance(
    ///     "http://127.0.0.1:8000".to_string(),
    ///     ContainerStatus::Running,
    /// );
    /// // `evaluator` now contains a single registered instance reachable at the given endpoint,
    /// // and `challenge_id` is the registered instance's ID.
    /// ```
    ///
    /// # Returns
    ///
    /// A tuple `(ChallengeEvaluator, ChallengeId)` where the evaluator contains the registered instance
    /// and the second element is the instance's `ChallengeId`.
    fn evaluator_with_instance(
        endpoint: String,
        status: ContainerStatus,
    ) -> (ChallengeEvaluator, ChallengeId) {
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let mut instance = sample_instance(status);
        instance.endpoint = endpoint;
        let challenge_id = instance.challenge_id;
        challenges.write().insert(challenge_id, instance);
        (ChallengeEvaluator::new(challenges), challenge_id)
    }

    /// Starts a minimal one-shot HTTP server on localhost that accepts a single connection and replies with the provided status line, body, and Content-Type.
    ///
    /// The server binds to 127.0.0.1 on an ephemeral port and returns the bound socket address and a JoinHandle for the spawned task. The spawned task reads the incoming request, writes the formatted HTTP response, then shuts down after serving that one connection.
    ///
    /// # Examples
    ///
    /// ```
    /// # tokio_test::block_on(async {
    /// let (addr, handle) = spawn_static_http_server("200 OK", "hello", "text/plain").await;
    /// let url = format!("http://{}/", addr);
    /// let resp = reqwest::get(&url).await.unwrap();
    /// assert_eq!(resp.status().as_u16(), 200);
    /// let body = resp.text().await.unwrap();
    /// assert_eq!(body, "hello");
    /// let _ = handle.await;
    /// # });
    /// ```
    async fn spawn_static_http_server(
        status_line: &str,
        body: &str,
        content_type: &str,
    ) -> (std::net::SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local server");
        let addr = listener.local_addr().expect("read addr");
        let body = body.to_string();
        let content_type = content_type.to_string();
        let status_line = status_line.to_string();

        let handle = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(), body,
                    status = status_line,
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        (addr, handle)
    }

    /// Spawns a local TCP server that accepts a single connection and then drops it without responding.
    ///
    /// The server binds to an ephemeral localhost port and returns the socket address and a JoinHandle
    /// for the background task. This is useful for tests that need to simulate a peer that accepts a
    /// connection and then closes it to produce a client-side network error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use tokio::io::{AsyncReadExt, AsyncWriteExt};
    /// # use tokio::net::TcpStream;
    /// #
    /// # async fn run() {
    /// let (addr, _handle) = crate::spawn_drop_http_server().await;
    /// let mut stream = TcpStream::connect(addr).await.unwrap();
    /// // Send a request; the server will read and then drop the connection without replying.
    /// let _ = stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await;
    /// let mut buf = [0u8; 16];
    /// // Reading yields 0 bytes when the peer closes the connection.
    /// let n = stream.read(&mut buf).await.unwrap();
    /// assert_eq!(n, 0);
    /// # }
    /// # tokio::runtime::Runtime::new().unwrap().block_on(run());
    /// ```
    async fn spawn_drop_http_server() -> (std::net::SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local server");
        let addr = listener.local_addr().expect("read addr");

        let handle = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0u8; 1024];
                let _ = socket.read(&mut buf).await;
                // Drop connection without responding to trigger client-side network error.
            }
        });

        (addr, handle)
    }
}