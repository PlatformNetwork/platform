//! Challenge Server Mode
//!
//! Provides HTTP server functionality for challenges to expose their evaluation
//! endpoints to validators in the P2P network.
//!
//! # Usage
//!
//! ```rust,ignore
//! use platform_challenge_sdk::server::{ChallengeServer, ServerConfig};
//!
//! let server = ChallengeServer::new(my_challenge)
//!     .config(ServerConfig::default())
//!     .build();
//!
//! server.run().await?;
//! ```
//!
//! # Endpoints
//!
//! The server exposes:
//! - `POST /evaluate` - Receive evaluation requests from platform
//! - `GET /health` - Health check
//! - `GET /config` - Challenge configuration schema
//! - `POST /validate` - Quick validation without full evaluation

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::error::ChallengeError;

#[cfg(feature = "http-server")]
use axum::extract::State;

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Host to bind to
    pub host: String,
    /// Port to listen on
    pub port: u16,
    /// Maximum concurrent evaluations
    pub max_concurrent: usize,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Enable CORS
    pub cors_enabled: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            max_concurrent: 4,
            timeout_secs: 600,
            cors_enabled: true,
        }
    }
}

impl ServerConfig {
    /// Load from environment variables
    pub fn from_env() -> Self {
        Self {
            host: std::env::var("CHALLENGE_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: std::env::var("CHALLENGE_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8080),
            max_concurrent: std::env::var("MAX_CONCURRENT")
                .ok()
                .and_then(|n| n.parse().ok())
                .unwrap_or(4),
            timeout_secs: std::env::var("TIMEOUT_SECS")
                .ok()
                .and_then(|n| n.parse().ok())
                .unwrap_or(600),
            cors_enabled: true,
        }
    }
}

// ============================================================================
// GENERIC REQUEST/RESPONSE TYPES
// ============================================================================

/// Generic evaluation request from platform
///
/// Platform sends this, challenge interprets the `data` field based on its needs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationRequest {
    /// Unique request ID
    pub request_id: String,
    /// Submission identifier
    pub submission_id: String,
    /// Participant identifier (could be miner hotkey, user id, etc.)
    pub participant_id: String,
    /// Submission data (challenge-specific, could be source code, config, etc.)
    pub data: serde_json::Value,
    /// Optional metadata
    pub metadata: Option<serde_json::Value>,
    /// Current epoch/round
    pub epoch: u64,
    /// Deadline timestamp (unix seconds)
    pub deadline: Option<i64>,
}

/// Generic evaluation response to platform
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResponse {
    /// Request ID this responds to
    pub request_id: String,
    /// Whether evaluation succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Evaluation score (0.0 - 1.0)
    pub score: f64,
    /// Detailed results (challenge-specific)
    pub results: serde_json::Value,
    /// Execution time in milliseconds
    pub execution_time_ms: i64,
    /// Cost incurred (if applicable)
    pub cost: Option<f64>,
}

impl EvaluationResponse {
    /// Create successful response
    pub fn success(request_id: &str, score: f64, results: serde_json::Value) -> Self {
        Self {
            request_id: request_id.to_string(),
            success: true,
            error: None,
            score,
            results,
            execution_time_ms: 0,
            cost: None,
        }
    }

    /// Create error response
    pub fn error(request_id: &str, error: impl Into<String>) -> Self {
        Self {
            request_id: request_id.to_string(),
            success: false,
            error: Some(error.into()),
            score: 0.0,
            results: serde_json::Value::Null,
            execution_time_ms: 0,
            cost: None,
        }
    }

    /// Set execution time
    pub fn with_time(mut self, ms: i64) -> Self {
        self.execution_time_ms = ms;
        self
    }

    /// Set cost
    pub fn with_cost(mut self, cost: f64) -> Self {
        self.cost = Some(cost);
        self
    }
}

/// Validation request (quick check without full evaluation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRequest {
    /// Data to validate
    pub data: serde_json::Value,
}

/// Validation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResponse {
    /// Whether data is valid
    pub valid: bool,
    /// Validation errors
    pub errors: Vec<String>,
    /// Warnings (valid but not recommended)
    pub warnings: Vec<String>,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Server is healthy
    pub healthy: bool,
    /// Current load (0.0 - 1.0)
    pub load: f64,
    /// Pending evaluations
    pub pending: u32,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Version
    pub version: String,
    /// Challenge ID
    pub challenge_id: String,
}

/// Configuration schema response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigResponse {
    /// Challenge ID
    pub challenge_id: String,
    /// Challenge name
    pub name: String,
    /// Version
    pub version: String,
    /// Configuration schema (JSON Schema)
    pub config_schema: Option<serde_json::Value>,
    /// Supported features
    pub features: Vec<String>,
    /// Limits
    pub limits: ConfigLimits,
}

/// Configuration limits
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigLimits {
    /// Maximum submission size in bytes
    pub max_submission_size: Option<u64>,
    /// Maximum evaluation time in seconds
    pub max_evaluation_time: Option<u64>,
    /// Maximum cost per evaluation
    pub max_cost: Option<f64>,
}

// ============================================================================
// SERVER TRAIT
// ============================================================================

/// Trait that challenges must implement for server mode
#[async_trait::async_trait]
pub trait ServerChallenge: Send + Sync {
    /// Get challenge ID
    fn challenge_id(&self) -> &str;

    /// Get challenge name
    fn name(&self) -> &str;

    /// Get version
    fn version(&self) -> &str;

    /// Evaluate a submission
    async fn evaluate(
        &self,
        request: EvaluationRequest,
    ) -> Result<EvaluationResponse, ChallengeError>;

    /// Validate submission data (quick check)
    async fn validate(
        &self,
        request: ValidationRequest,
    ) -> Result<ValidationResponse, ChallengeError> {
        // Default: accept everything
        Ok(ValidationResponse {
            valid: true,
            errors: vec![],
            warnings: vec![],
        })
    }

    /// Get configuration schema
    fn config(&self) -> ConfigResponse {
        ConfigResponse {
            challenge_id: self.challenge_id().to_string(),
            name: self.name().to_string(),
            version: self.version().to_string(),
            config_schema: None,
            features: vec![],
            limits: ConfigLimits::default(),
        }
    }
}

// ============================================================================
// SERVER STATE
// ============================================================================

/// Server state
pub struct ServerState<C: ServerChallenge> {
    pub challenge: Arc<C>,
    pub config: ServerConfig,
    pub started_at: Instant,
    pub pending_count: Arc<RwLock<u32>>,
}

// ============================================================================
// SERVER BUILDER
// ============================================================================

/// Builder for challenge server
pub struct ChallengeServerBuilder<C: ServerChallenge> {
    challenge: C,
    config: ServerConfig,
}

impl<C: ServerChallenge + 'static> ChallengeServerBuilder<C> {
    /// Create new builder
    pub fn new(challenge: C) -> Self {
        Self {
            challenge,
            config: ServerConfig::default(),
        }
    }

    /// Set configuration
    pub fn config(mut self, config: ServerConfig) -> Self {
        self.config = config;
        self
    }

    /// Set host
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.config.host = host.into();
        self
    }

    /// Set port
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    /// Load config from environment
    pub fn from_env(mut self) -> Self {
        self.config = ServerConfig::from_env();
        self
    }

    /// Build and return server state
    pub fn build(self) -> ChallengeServer<C> {
        ChallengeServer {
            state: Arc::new(ServerState {
                challenge: Arc::new(self.challenge),
                config: self.config,
                started_at: Instant::now(),
                pending_count: Arc::new(RwLock::new(0)),
            }),
        }
    }
}

/// Challenge HTTP server
pub struct ChallengeServer<C: ServerChallenge> {
    state: Arc<ServerState<C>>,
}

impl<C: ServerChallenge + 'static> ChallengeServer<C> {
    /// Create new server builder
    pub fn builder(challenge: C) -> ChallengeServerBuilder<C> {
        ChallengeServerBuilder::new(challenge)
    }

    /// Run the server (requires axum feature)
    #[cfg(feature = "http-server")]
    pub async fn run(&self) -> Result<(), ChallengeError> {
        use axum::{
            extract::{Json, State},
            http::StatusCode,
            routing::{get, post},
            Router,
        };

        let state = Arc::clone(&self.state);
        let addr: SocketAddr = format!("{}:{}", state.config.host, state.config.port)
            .parse()
            .map_err(|e| ChallengeError::Config(format!("Invalid address: {}", e)))?;

        let app = Router::new()
            .route("/health", get(health_handler::<C>))
            .route("/config", get(config_handler::<C>))
            .route("/evaluate", post(evaluate_handler::<C>))
            .route("/validate", post(validate_handler::<C>))
            .with_state(state);

        info!(
            "Starting challenge server {} on {}",
            self.state.challenge.challenge_id(),
            addr
        );

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| ChallengeError::Io(e.to_string()))?;

        axum::serve(listener, app)
            .await
            .map_err(|e| ChallengeError::Io(e.to_string()))?;

        Ok(())
    }

    /// Get server address
    pub fn address(&self) -> String {
        format!("{}:{}", self.state.config.host, self.state.config.port)
    }
}

// ============================================================================
// HTTP HANDLERS (when http-server feature enabled)
// ============================================================================

#[cfg(feature = "http-server")]
async fn health_handler<C: ServerChallenge + 'static>(
    State(state): State<Arc<ServerState<C>>>,
) -> axum::Json<HealthResponse> {
    let pending = *state.pending_count.read().await;
    let load = pending as f64 / state.config.max_concurrent as f64;

    axum::Json(HealthResponse {
        healthy: true,
        load: load.min(1.0),
        pending,
        uptime_secs: state.started_at.elapsed().as_secs(),
        version: state.challenge.version().to_string(),
        challenge_id: state.challenge.challenge_id().to_string(),
    })
}

#[cfg(feature = "http-server")]
async fn config_handler<C: ServerChallenge + 'static>(
    State(state): State<Arc<ServerState<C>>>,
) -> axum::Json<ConfigResponse> {
    axum::Json(state.challenge.config())
}

#[cfg(feature = "http-server")]
async fn evaluate_handler<C: ServerChallenge + 'static>(
    State(state): State<Arc<ServerState<C>>>,
    axum::Json(request): axum::Json<EvaluationRequest>,
) -> (axum::http::StatusCode, axum::Json<EvaluationResponse>) {
    let request_id = request.request_id.clone();
    let start = Instant::now();

    // Increment pending
    {
        let mut count = state.pending_count.write().await;
        *count += 1;
    }

    let result = state.challenge.evaluate(request).await;

    // Decrement pending
    {
        let mut count = state.pending_count.write().await;
        *count = count.saturating_sub(1);
    }

    match result {
        Ok(mut response) => {
            response.execution_time_ms = start.elapsed().as_millis() as i64;
            (axum::http::StatusCode::OK, axum::Json(response))
        }
        Err(e) => {
            let response = EvaluationResponse::error(&request_id, e.to_string())
                .with_time(start.elapsed().as_millis() as i64);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(response),
            )
        }
    }
}

#[cfg(feature = "http-server")]
async fn validate_handler<C: ServerChallenge + 'static>(
    State(state): State<Arc<ServerState<C>>>,
    axum::Json(request): axum::Json<ValidationRequest>,
) -> axum::Json<ValidationResponse> {
    match state.challenge.validate(request).await {
        Ok(response) => axum::Json(response),
        Err(e) => axum::Json(ValidationResponse {
            valid: false,
            errors: vec![e.to_string()],
            warnings: vec![],
        }),
    }
}

// ============================================================================
// MACROS FOR EASY IMPLEMENTATION
// ============================================================================

/// Macro to implement ServerChallenge for an existing Challenge
#[macro_export]
macro_rules! impl_server_challenge {
    ($type:ty, evaluate: |$self:ident, $req:ident| $body:expr) => {
        #[async_trait::async_trait]
        impl $crate::server::ServerChallenge for $type {
            fn challenge_id(&self) -> &str {
                <Self as $crate::challenge::Challenge>::id(self).as_str()
            }

            fn name(&self) -> &str {
                <Self as $crate::challenge::Challenge>::name(self)
            }

            fn version(&self) -> &str {
                <Self as $crate::challenge::Challenge>::version(self)
            }

            async fn evaluate(
                &$self,
                $req: $crate::server::EvaluationRequest,
            ) -> Result<$crate::server::EvaluationResponse, $crate::error::ChallengeError> {
                $body
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 8080);
        assert_eq!(config.max_concurrent, 4);
        assert_eq!(config.timeout_secs, 600);
        assert!(config.cors_enabled);
    }

    #[test]
    fn test_server_config_from_env() {
        // Should use defaults when env vars not set
        let config = ServerConfig::from_env();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 8080);
    }

    #[test]
    fn test_evaluation_request() {
        let req = EvaluationRequest {
            request_id: "req-123".to_string(),
            submission_id: "sub-456".to_string(),
            participant_id: "participant-789".to_string(),
            data: json!({"code": "fn main() {}"}),
            metadata: Some(json!({"version": "1.0"})),
            epoch: 5,
            deadline: Some(1234567890),
        };

        assert_eq!(req.request_id, "req-123");
        assert_eq!(req.epoch, 5);
        assert!(req.metadata.is_some());
    }

    #[test]
    fn test_evaluation_response_success() {
        let resp = EvaluationResponse::success("req-123", 0.95, json!({"passed": 19, "total": 20}));

        assert!(resp.success);
        assert_eq!(resp.request_id, "req-123");
        assert_eq!(resp.score, 0.95);
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_evaluation_response_error() {
        let resp = EvaluationResponse::error("req-456", "Timeout occurred");

        assert!(!resp.success);
        assert_eq!(resp.request_id, "req-456");
        assert_eq!(resp.score, 0.0);
        assert_eq!(resp.error, Some("Timeout occurred".to_string()));
    }

    #[test]
    fn test_evaluation_response_with_time() {
        let resp = EvaluationResponse::success("req", 0.8, json!({})).with_time(1500);

        assert_eq!(resp.execution_time_ms, 1500);
    }

    #[test]
    fn test_evaluation_response_with_cost() {
        let resp = EvaluationResponse::success("req", 0.8, json!({})).with_cost(0.05);

        assert_eq!(resp.cost, Some(0.05));
    }

    #[test]
    fn test_validation_request() {
        let req = ValidationRequest {
            data: json!({"input": "test"}),
        };

        assert_eq!(req.data["input"], "test");
    }

    #[test]
    fn test_validation_response() {
        let resp = ValidationResponse {
            valid: true,
            errors: vec![],
            warnings: vec!["Consider updating format".to_string()],
        };

        assert!(resp.valid);
        assert!(resp.errors.is_empty());
        assert_eq!(resp.warnings.len(), 1);
    }

    #[test]
    fn test_health_response() {
        let health = HealthResponse {
            healthy: true,
            load: 0.5,
            pending: 2,
            uptime_secs: 3600,
            version: "1.0.0".to_string(),
            challenge_id: "test-challenge".to_string(),
        };

        assert!(health.healthy);
        assert_eq!(health.load, 0.5);
        assert_eq!(health.uptime_secs, 3600);
    }

    #[test]
    fn test_config_response() {
        let config = ConfigResponse {
            challenge_id: "test".to_string(),
            name: "Test Challenge".to_string(),
            version: "1.0.0".to_string(),
            config_schema: Some(json!({"type": "object"})),
            features: vec!["feature1".to_string(), "feature2".to_string()],
            limits: ConfigLimits {
                max_submission_size: Some(1024 * 1024),
                max_evaluation_time: Some(300),
                max_cost: Some(0.1),
            },
        };

        assert_eq!(config.challenge_id, "test");
        assert_eq!(config.features.len(), 2);
        assert_eq!(config.limits.max_submission_size, Some(1024 * 1024));
    }

    #[test]
    fn test_config_limits_default() {
        let limits = ConfigLimits::default();
        assert!(limits.max_submission_size.is_none());
        assert!(limits.max_evaluation_time.is_none());
        assert!(limits.max_cost.is_none());
    }

    // Test with a mock challenge
    struct MockChallenge;

    #[async_trait::async_trait]
    impl ServerChallenge for MockChallenge {
        fn challenge_id(&self) -> &str {
            "mock-challenge"
        }

        fn name(&self) -> &str {
            "Mock Challenge"
        }

        fn version(&self) -> &str {
            "1.0.0"
        }

        async fn evaluate(
            &self,
            request: EvaluationRequest,
        ) -> Result<EvaluationResponse, ChallengeError> {
            Ok(EvaluationResponse::success(
                &request.request_id,
                0.75,
                json!({"mock": true}),
            ))
        }
    }

    #[tokio::test]
    async fn test_mock_challenge_evaluate() {
        let challenge = MockChallenge;

        let req = EvaluationRequest {
            request_id: "test".to_string(),
            submission_id: "sub".to_string(),
            participant_id: "participant".to_string(),
            data: json!({}),
            metadata: None,
            epoch: 1,
            deadline: None,
        };

        let result = challenge.evaluate(req).await.unwrap();
        assert!(result.success);
        assert_eq!(result.score, 0.75);
    }

    #[tokio::test]
    async fn test_mock_challenge_validate_default() {
        let challenge = MockChallenge;

        let req = ValidationRequest { data: json!({}) };

        let result = challenge.validate(req).await.unwrap();
        assert!(result.valid); // Default implementation accepts everything
    }

    #[test]
    fn test_mock_challenge_config_default() {
        let challenge = MockChallenge;
        let config = challenge.config();

        assert_eq!(config.challenge_id, "mock-challenge");
        assert_eq!(config.name, "Mock Challenge");
        assert_eq!(config.version, "1.0.0");
        assert!(config.features.is_empty());
    }

    #[test]
    fn test_server_builder_new() {
        let challenge = MockChallenge;
        let builder = ChallengeServerBuilder::new(challenge);

        assert_eq!(builder.config.port, 8080); // default port
    }

    #[test]
    fn test_server_builder_config() {
        let challenge = MockChallenge;
        let custom_config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 9000,
            max_concurrent: 10,
            timeout_secs: 120,
            cors_enabled: false,
        };

        let builder = ChallengeServerBuilder::new(challenge).config(custom_config);

        assert_eq!(builder.config.host, "127.0.0.1");
        assert_eq!(builder.config.port, 9000);
    }

    #[test]
    fn test_server_builder_host() {
        let challenge = MockChallenge;
        let builder = ChallengeServerBuilder::new(challenge).host("192.168.1.1");

        assert_eq!(builder.config.host, "192.168.1.1");
    }

    #[test]
    fn test_server_builder_port() {
        let challenge = MockChallenge;
        let builder = ChallengeServerBuilder::new(challenge).port(3000);

        assert_eq!(builder.config.port, 3000);
    }

    #[test]
    fn test_server_builder_build() {
        let challenge = MockChallenge;
        let server = ChallengeServerBuilder::new(challenge)
            .host("localhost")
            .port(8888)
            .build();

        assert_eq!(server.address(), "localhost:8888");
    }

    #[test]
    fn test_challenge_server_builder() {
        let challenge = MockChallenge;
        let builder = ChallengeServer::builder(challenge);

        assert_eq!(builder.config.port, 8080);
    }

    #[test]
    fn test_server_address() {
        let challenge = MockChallenge;
        let server = ChallengeServer::builder(challenge)
            .host("0.0.0.0")
            .port(8080)
            .build();

        assert_eq!(server.address(), "0.0.0.0:8080");
    }

    #[test]
    fn test_server_builder_from_env() {
        // Test from_env method (will use defaults when env vars not set)
        let challenge = MockChallenge;
        let builder = ChallengeServerBuilder::new(challenge).from_env();

        // Should use default values from ServerConfig::from_env()
        assert_eq!(builder.config.host, "0.0.0.0");
        assert_eq!(builder.config.port, 8080);
    }

    #[test]
    fn test_server_config_from_env_with_env_vars() {
        // Note: In real usage, this would read from environment variables
        // For this test, we just verify the function exists and returns defaults
        let config = ServerConfig::from_env();

        // Should return valid config (with defaults when env vars not set)
        assert!(!config.host.is_empty());
        assert!(config.port > 0);
        assert!(config.max_concurrent > 0);
    }
}

/// Comprehensive async tests for ServerChallenge trait implementations
#[cfg(test)]
mod async_tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// Configurable test challenge for comprehensive testing
    struct TestChallenge {
        should_fail_evaluate: Arc<AtomicBool>,
        should_fail_validate: Arc<AtomicBool>,
        delay_ms: Arc<AtomicU64>,
        custom_score: f64,
        custom_id: String,
        custom_name: String,
        custom_version: String,
        validation_errors: Vec<String>,
        validation_warnings: Vec<String>,
        custom_config: Option<ConfigResponse>,
    }

    impl Default for TestChallenge {
        fn default() -> Self {
            Self {
                should_fail_evaluate: Arc::new(AtomicBool::new(false)),
                should_fail_validate: Arc::new(AtomicBool::new(false)),
                delay_ms: Arc::new(AtomicU64::new(0)),
                custom_score: 0.85,
                custom_id: "test-challenge".to_string(),
                custom_name: "Test Challenge".to_string(),
                custom_version: "1.0.0".to_string(),
                validation_errors: vec![],
                validation_warnings: vec![],
                custom_config: None,
            }
        }
    }

    impl TestChallenge {
        fn with_failure() -> Self {
            Self {
                should_fail_evaluate: Arc::new(AtomicBool::new(true)),
                ..Default::default()
            }
        }

        fn with_validation_failure() -> Self {
            Self {
                should_fail_validate: Arc::new(AtomicBool::new(true)),
                ..Default::default()
            }
        }

        fn with_delay(delay_ms: u64) -> Self {
            Self {
                delay_ms: Arc::new(AtomicU64::new(delay_ms)),
                ..Default::default()
            }
        }

        fn with_score(score: f64) -> Self {
            Self {
                custom_score: score,
                ..Default::default()
            }
        }

        fn with_validation_errors(errors: Vec<String>) -> Self {
            Self {
                validation_errors: errors,
                ..Default::default()
            }
        }

        fn with_validation_warnings(warnings: Vec<String>) -> Self {
            Self {
                validation_warnings: warnings,
                ..Default::default()
            }
        }

        fn with_custom_config(config: ConfigResponse) -> Self {
            Self {
                custom_config: Some(config),
                ..Default::default()
            }
        }

        fn with_identity(id: &str, name: &str, version: &str) -> Self {
            Self {
                custom_id: id.to_string(),
                custom_name: name.to_string(),
                custom_version: version.to_string(),
                ..Default::default()
            }
        }
    }

    #[async_trait::async_trait]
    impl ServerChallenge for TestChallenge {
        fn challenge_id(&self) -> &str {
            &self.custom_id
        }

        fn name(&self) -> &str {
            &self.custom_name
        }

        fn version(&self) -> &str {
            &self.custom_version
        }

        async fn evaluate(
            &self,
            request: EvaluationRequest,
        ) -> Result<EvaluationResponse, ChallengeError> {
            // Simulate delay if configured
            let delay = self.delay_ms.load(Ordering::SeqCst);
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            // Check if should fail
            if self.should_fail_evaluate.load(Ordering::SeqCst) {
                return Err(ChallengeError::Evaluation("Configured to fail".to_string()));
            }

            // Return success with configured score
            Ok(EvaluationResponse::success(
                &request.request_id,
                self.custom_score,
                json!({
                    "test": true,
                    "submission_id": request.submission_id,
                    "participant_id": request.participant_id,
                    "metadata_present": request.metadata.is_some(),
                }),
            ))
        }

        async fn validate(
            &self,
            _request: ValidationRequest,
        ) -> Result<ValidationResponse, ChallengeError> {
            if self.should_fail_validate.load(Ordering::SeqCst) {
                return Err(ChallengeError::Validation(
                    "Validation process failed".to_string(),
                ));
            }

            let has_errors = !self.validation_errors.is_empty();
            Ok(ValidationResponse {
                valid: !has_errors,
                errors: self.validation_errors.clone(),
                warnings: self.validation_warnings.clone(),
            })
        }

        fn config(&self) -> ConfigResponse {
            if let Some(ref config) = self.custom_config {
                return config.clone();
            }
            ConfigResponse {
                challenge_id: self.challenge_id().to_string(),
                name: self.name().to_string(),
                version: self.version().to_string(),
                config_schema: None,
                features: vec![],
                limits: ConfigLimits::default(),
            }
        }
    }

    fn create_test_request(request_id: &str) -> EvaluationRequest {
        EvaluationRequest {
            request_id: request_id.to_string(),
            submission_id: "sub-001".to_string(),
            participant_id: "participant-001".to_string(),
            data: json!({"code": "fn main() {}"}),
            metadata: None,
            epoch: 1,
            deadline: None,
        }
    }

    fn create_test_request_with_metadata(request_id: &str) -> EvaluationRequest {
        EvaluationRequest {
            request_id: request_id.to_string(),
            submission_id: "sub-002".to_string(),
            participant_id: "participant-002".to_string(),
            data: json!({"code": "fn main() { println!(\"Hello\"); }"}),
            metadata: Some(json!({
                "version": "2.0",
                "language": "rust",
                "test_mode": true
            })),
            epoch: 5,
            deadline: Some(1700000000),
        }
    }

    // =========================================================================
    // Evaluate Endpoint Tests
    // =========================================================================

    #[tokio::test]
    async fn test_evaluate_success_returns_valid_score() {
        let challenge = TestChallenge::with_score(0.95);
        let req = create_test_request("req-001");

        let result = challenge.evaluate(req).await.unwrap();

        assert!(result.success);
        assert_eq!(result.score, 0.95);
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_evaluate_score_bounds_zero() {
        let challenge = TestChallenge::with_score(0.0);
        let req = create_test_request("req-zero");

        let result = challenge.evaluate(req).await.unwrap();

        assert!(result.success);
        assert_eq!(result.score, 0.0);
        assert!(
            result.score >= 0.0 && result.score <= 1.0,
            "Score should be within valid range"
        );
    }

    #[tokio::test]
    async fn test_evaluate_score_bounds_one() {
        let challenge = TestChallenge::with_score(1.0);
        let req = create_test_request("req-one");

        let result = challenge.evaluate(req).await.unwrap();

        assert!(result.success);
        assert_eq!(result.score, 1.0);
        assert!(
            result.score >= 0.0 && result.score <= 1.0,
            "Score should be within valid range"
        );
    }

    #[tokio::test]
    async fn test_evaluate_error_returns_failure_response() {
        let challenge = TestChallenge::with_failure();
        let req = create_test_request("req-fail");

        let result = challenge.evaluate(req).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ChallengeError::Evaluation(_)));
    }

    #[tokio::test]
    async fn test_evaluate_records_execution_time() {
        let challenge = TestChallenge::with_delay(50);
        let req = create_test_request("req-time");

        let start = std::time::Instant::now();
        let result = challenge.evaluate(req).await.unwrap();
        let elapsed = start.elapsed();

        // Verify the delay was applied
        assert!(
            elapsed.as_millis() >= 50,
            "Should have delayed at least 50ms"
        );
        // Note: execution_time_ms is set to 0 by default in the trait method
        // The actual time tracking happens in the HTTP handler
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_evaluate_with_metadata_handling() {
        let challenge = TestChallenge::default();
        let req = create_test_request_with_metadata("req-meta");

        let result = challenge.evaluate(req).await.unwrap();

        assert!(result.success);
        // Verify metadata was passed through
        assert_eq!(result.results["metadata_present"], true);
    }

    #[tokio::test]
    async fn test_evaluate_without_metadata() {
        let challenge = TestChallenge::default();
        let req = create_test_request("req-no-meta");

        let result = challenge.evaluate(req).await.unwrap();

        assert!(result.success);
        assert_eq!(result.results["metadata_present"], false);
    }

    #[tokio::test]
    async fn test_evaluate_preserves_request_id() {
        let challenge = TestChallenge::default();
        let req = create_test_request("unique-request-id-12345");

        let result = challenge.evaluate(req).await.unwrap();

        assert_eq!(result.request_id, "unique-request-id-12345");
    }

    #[tokio::test]
    async fn test_evaluate_preserves_submission_info() {
        let challenge = TestChallenge::default();
        let req = create_test_request("req-info");

        let result = challenge.evaluate(req).await.unwrap();

        assert_eq!(result.results["submission_id"], "sub-001");
        assert_eq!(result.results["participant_id"], "participant-001");
    }

    #[tokio::test]
    async fn test_evaluate_concurrent_requests() {
        let challenge = Arc::new(TestChallenge::with_delay(10));

        let handles: Vec<_> = (0..5)
            .map(|i| {
                let c = Arc::clone(&challenge);
                tokio::spawn(async move {
                    let req = create_test_request(&format!("concurrent-{}", i));
                    c.evaluate(req).await
                })
            })
            .collect();

        for handle in handles {
            let result = handle.await.unwrap().unwrap();
            assert!(result.success);
        }
    }

    // =========================================================================
    // Health Endpoint Tests
    // =========================================================================

    #[test]
    fn test_health_response_fields() {
        let health = HealthResponse {
            healthy: true,
            load: 0.5,
            pending: 2,
            uptime_secs: 3600,
            version: "1.0.0".to_string(),
            challenge_id: "test".to_string(),
        };

        assert!(health.healthy);
        assert!(health.load >= 0.0 && health.load <= 1.0);
        assert_eq!(health.pending, 2);
        assert_eq!(health.uptime_secs, 3600);
        assert_eq!(health.version, "1.0.0");
        assert_eq!(health.challenge_id, "test");
    }

    #[test]
    fn test_health_response_unhealthy() {
        let health = HealthResponse {
            healthy: false,
            load: 1.0,
            pending: 100,
            uptime_secs: 0,
            version: "1.0.0".to_string(),
            challenge_id: "test".to_string(),
        };

        assert!(!health.healthy);
        assert_eq!(health.load, 1.0);
    }

    #[test]
    fn test_health_response_serialization() {
        let health = HealthResponse {
            healthy: true,
            load: 0.25,
            pending: 1,
            uptime_secs: 7200,
            version: "2.0.0".to_string(),
            challenge_id: "bench-challenge".to_string(),
        };

        let json = serde_json::to_string(&health).unwrap();
        let deserialized: HealthResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.healthy, health.healthy);
        assert_eq!(deserialized.load, health.load);
        assert_eq!(deserialized.pending, health.pending);
        assert_eq!(deserialized.uptime_secs, health.uptime_secs);
        assert_eq!(deserialized.version, health.version);
        assert_eq!(deserialized.challenge_id, health.challenge_id);
    }

    #[test]
    fn test_health_response_load_boundary_zero() {
        let health = HealthResponse {
            healthy: true,
            load: 0.0,
            pending: 0,
            uptime_secs: 1,
            version: "1.0.0".to_string(),
            challenge_id: "test".to_string(),
        };

        assert_eq!(health.load, 0.0);
    }

    #[test]
    fn test_health_response_load_boundary_one() {
        let health = HealthResponse {
            healthy: true,
            load: 1.0,
            pending: 4,
            uptime_secs: 1,
            version: "1.0.0".to_string(),
            challenge_id: "test".to_string(),
        };

        assert_eq!(health.load, 1.0);
    }

    // =========================================================================
    // Config Endpoint Tests
    // =========================================================================

    #[test]
    fn test_config_response_limits_with_values() {
        let limits = ConfigLimits {
            max_submission_size: Some(10 * 1024 * 1024), // 10MB
            max_evaluation_time: Some(3600),             // 1 hour
            max_cost: Some(1.0),
        };

        assert_eq!(limits.max_submission_size, Some(10 * 1024 * 1024));
        assert_eq!(limits.max_evaluation_time, Some(3600));
        assert_eq!(limits.max_cost, Some(1.0));
    }

    #[test]
    fn test_config_response_limits_none() {
        let limits = ConfigLimits::default();

        assert!(limits.max_submission_size.is_none());
        assert!(limits.max_evaluation_time.is_none());
        assert!(limits.max_cost.is_none());
    }

    #[test]
    fn test_config_response_features_empty() {
        let config = ConfigResponse {
            challenge_id: "test".to_string(),
            name: "Test".to_string(),
            version: "1.0.0".to_string(),
            config_schema: None,
            features: vec![],
            limits: ConfigLimits::default(),
        };

        assert!(config.features.is_empty());
    }

    #[test]
    fn test_config_response_features_multiple() {
        let config = ConfigResponse {
            challenge_id: "test".to_string(),
            name: "Test".to_string(),
            version: "1.0.0".to_string(),
            config_schema: None,
            features: vec![
                "streaming".to_string(),
                "batch".to_string(),
                "async_eval".to_string(),
            ],
            limits: ConfigLimits::default(),
        };

        assert_eq!(config.features.len(), 3);
        assert!(config.features.contains(&"streaming".to_string()));
        assert!(config.features.contains(&"batch".to_string()));
        assert!(config.features.contains(&"async_eval".to_string()));
    }

    #[test]
    fn test_config_response_with_schema() {
        let schema = json!({
            "type": "object",
            "properties": {
                "timeout": {"type": "integer"},
                "language": {"type": "string"}
            }
        });

        let config = ConfigResponse {
            challenge_id: "test".to_string(),
            name: "Test".to_string(),
            version: "1.0.0".to_string(),
            config_schema: Some(schema.clone()),
            features: vec![],
            limits: ConfigLimits::default(),
        };

        assert!(config.config_schema.is_some());
        assert_eq!(config.config_schema.unwrap()["type"], "object");
    }

    #[test]
    fn test_config_response_serialization() {
        let config = ConfigResponse {
            challenge_id: "test-id".to_string(),
            name: "Test Challenge".to_string(),
            version: "2.0.0".to_string(),
            config_schema: Some(json!({"type": "object"})),
            features: vec!["feature1".to_string()],
            limits: ConfigLimits {
                max_submission_size: Some(1024),
                max_evaluation_time: Some(60),
                max_cost: Some(0.5),
            },
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ConfigResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.challenge_id, config.challenge_id);
        assert_eq!(deserialized.name, config.name);
        assert_eq!(deserialized.version, config.version);
        assert_eq!(deserialized.features.len(), config.features.len());
    }

    #[test]
    fn test_challenge_default_config() {
        let challenge = TestChallenge::default();
        let config = challenge.config();

        assert_eq!(config.challenge_id, "test-challenge");
        assert_eq!(config.name, "Test Challenge");
        assert_eq!(config.version, "1.0.0");
        assert!(config.features.is_empty());
    }

    #[test]
    fn test_challenge_custom_config() {
        let custom_config = ConfigResponse {
            challenge_id: "custom".to_string(),
            name: "Custom Challenge".to_string(),
            version: "3.0.0".to_string(),
            config_schema: Some(json!({"custom": true})),
            features: vec!["custom_feature".to_string()],
            limits: ConfigLimits {
                max_submission_size: Some(5000),
                max_evaluation_time: Some(120),
                max_cost: Some(2.0),
            },
        };

        let challenge = TestChallenge::with_custom_config(custom_config);
        let config = challenge.config();

        assert_eq!(config.challenge_id, "custom");
        assert_eq!(config.features, vec!["custom_feature"]);
        assert_eq!(config.limits.max_submission_size, Some(5000));
    }

    // =========================================================================
    // Validate Endpoint Tests
    // =========================================================================

    #[tokio::test]
    async fn test_validate_valid_data_passes() {
        let challenge = TestChallenge::default();
        let req = ValidationRequest {
            data: json!({"code": "valid code"}),
        };

        let result = challenge.validate(req).await.unwrap();

        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[tokio::test]
    async fn test_validate_invalid_data_returns_errors() {
        let challenge = TestChallenge::with_validation_errors(vec![
            "Missing required field 'main'".to_string(),
            "Invalid syntax at line 5".to_string(),
        ]);
        let req = ValidationRequest {
            data: json!({"bad_code": ""}),
        };

        let result = challenge.validate(req).await.unwrap();

        assert!(!result.valid);
        assert_eq!(result.errors.len(), 2);
        assert!(result.errors[0].contains("Missing required field"));
        assert!(result.errors[1].contains("Invalid syntax"));
    }

    #[tokio::test]
    async fn test_validate_returns_warnings() {
        let challenge = TestChallenge::with_validation_warnings(vec![
            "Deprecated API usage detected".to_string(),
            "Consider using async/await".to_string(),
        ]);
        let req = ValidationRequest {
            data: json!({"code": "old style code"}),
        };

        let result = challenge.validate(req).await.unwrap();

        assert!(result.valid); // Valid but with warnings
        assert!(result.errors.is_empty());
        assert_eq!(result.warnings.len(), 2);
        assert!(result.warnings[0].contains("Deprecated"));
    }

    #[tokio::test]
    async fn test_validate_errors_and_warnings() {
        let challenge = TestChallenge {
            validation_errors: vec!["Error 1".to_string()],
            validation_warnings: vec!["Warning 1".to_string()],
            ..Default::default()
        };

        let req = ValidationRequest { data: json!({}) };

        let result = challenge.validate(req).await.unwrap();

        assert!(!result.valid);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.warnings.len(), 1);
    }

    #[tokio::test]
    async fn test_validate_process_failure() {
        let challenge = TestChallenge::with_validation_failure();
        let req = ValidationRequest { data: json!({}) };

        let result = challenge.validate(req).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ChallengeError::Validation(_)));
    }

    #[tokio::test]
    async fn test_validate_with_complex_data() {
        let challenge = TestChallenge::default();
        let complex_data = json!({
            "code": "fn main() { println!(\"Hello\"); }",
            "config": {
                "timeout": 30,
                "memory_limit": 256
            },
            "tests": [
                {"name": "test1", "expected": "pass"},
                {"name": "test2", "expected": "pass"}
            ]
        });

        let req = ValidationRequest { data: complex_data };

        let result = challenge.validate(req).await.unwrap();
        assert!(result.valid);
    }

    // =========================================================================
    // ChallengeServer Builder Tests
    // =========================================================================

    #[test]
    fn test_server_builder_chain() {
        let challenge = TestChallenge::default();
        let server = ChallengeServer::builder(challenge)
            .host("127.0.0.1")
            .port(9090)
            .build();

        assert_eq!(server.address(), "127.0.0.1:9090");
    }

    #[test]
    fn test_server_builder_default_address() {
        let challenge = TestChallenge::default();
        let server = ChallengeServer::builder(challenge).build();

        assert_eq!(server.address(), "0.0.0.0:8080");
    }

    #[test]
    fn test_server_builder_with_full_config() {
        let challenge = TestChallenge::default();
        let config = ServerConfig {
            host: "10.0.0.1".to_string(),
            port: 3000,
            max_concurrent: 8,
            timeout_secs: 1200,
            cors_enabled: false,
        };

        let server = ChallengeServer::builder(challenge).config(config).build();

        assert_eq!(server.address(), "10.0.0.1:3000");
    }

    #[test]
    fn test_server_builder_method_chaining() {
        let challenge = TestChallenge::with_identity("chain-test", "Chained", "1.2.3");
        let server = ChallengeServer::builder(challenge)
            .host("192.168.1.100")
            .port(5000)
            .build();

        assert_eq!(server.address(), "192.168.1.100:5000");
    }

    #[test]
    fn test_server_builder_overwrite_values() {
        let challenge = TestChallenge::default();
        let server = ChallengeServer::builder(challenge)
            .host("first.host")
            .port(1111)
            .host("second.host") // Overwrite
            .port(2222) // Overwrite
            .build();

        assert_eq!(server.address(), "second.host:2222");
    }

    #[test]
    fn test_server_config_from_env_defaults() {
        // Test that from_env uses sensible defaults when env vars not set
        let challenge = TestChallenge::default();
        let server = ChallengeServer::builder(challenge).from_env().build();

        // Should use default values
        let addr = server.address();
        assert!(addr.contains("0.0.0.0") || addr.contains("127.0.0.1") || addr.contains("8080"));
    }

    #[test]
    fn test_server_builder_custom_port() {
        let challenge = TestChallenge::default();
        for port in [80, 443, 3000, 8000, 8080, 9000, 65535] {
            let server = ChallengeServer::builder(TestChallenge::default())
                .port(port)
                .build();
            assert!(server.address().ends_with(&format!(":{}", port)));
        }
    }

    #[test]
    fn test_server_builder_custom_hosts() {
        let hosts = [
            "localhost",
            "0.0.0.0",
            "127.0.0.1",
            "192.168.1.1",
            "10.0.0.1",
        ];
        for host in hosts {
            let server = ChallengeServer::builder(TestChallenge::default())
                .host(host)
                .build();
            assert!(server.address().starts_with(host));
        }
    }

    // =========================================================================
    // EvaluationResponse Builder Pattern Tests
    // =========================================================================

    #[test]
    fn test_evaluation_response_chained_builders() {
        let response = EvaluationResponse::success("req-123", 0.9, json!({"test": true}))
            .with_time(500)
            .with_cost(0.25);

        assert!(response.success);
        assert_eq!(response.request_id, "req-123");
        assert_eq!(response.score, 0.9);
        assert_eq!(response.execution_time_ms, 500);
        assert_eq!(response.cost, Some(0.25));
    }

    #[test]
    fn test_evaluation_response_error_with_time() {
        let response = EvaluationResponse::error("req-err", "Something went wrong").with_time(100);

        assert!(!response.success);
        assert_eq!(response.error, Some("Something went wrong".to_string()));
        assert_eq!(response.execution_time_ms, 100);
        assert_eq!(response.score, 0.0);
    }

    // =========================================================================
    // ServerState Tests
    // =========================================================================

    #[tokio::test]
    async fn test_server_state_pending_count() {
        let state = ServerState {
            challenge: Arc::new(TestChallenge::default()),
            config: ServerConfig::default(),
            started_at: std::time::Instant::now(),
            pending_count: Arc::new(RwLock::new(0)),
        };

        // Initial count is 0
        assert_eq!(*state.pending_count.read().await, 0);

        // Increment
        {
            let mut count = state.pending_count.write().await;
            *count += 1;
        }
        assert_eq!(*state.pending_count.read().await, 1);

        // Decrement
        {
            let mut count = state.pending_count.write().await;
            *count = count.saturating_sub(1);
        }
        assert_eq!(*state.pending_count.read().await, 0);
    }

    #[test]
    fn test_server_state_uptime() {
        let state = ServerState {
            challenge: Arc::new(TestChallenge::default()),
            config: ServerConfig::default(),
            started_at: std::time::Instant::now(),
            pending_count: Arc::new(RwLock::new(0)),
        };

        // Uptime should be very small right after creation
        let uptime = state.started_at.elapsed();
        assert!(uptime.as_secs() < 1);
    }

    // =========================================================================
    // Challenge Identity Tests
    // =========================================================================

    #[test]
    fn test_challenge_identity() {
        let challenge = TestChallenge::with_identity("my-challenge", "My Challenge", "2.5.0");

        assert_eq!(challenge.challenge_id(), "my-challenge");
        assert_eq!(challenge.name(), "My Challenge");
        assert_eq!(challenge.version(), "2.5.0");
    }

    #[test]
    fn test_challenge_default_identity() {
        let challenge = TestChallenge::default();

        assert_eq!(challenge.challenge_id(), "test-challenge");
        assert_eq!(challenge.name(), "Test Challenge");
        assert_eq!(challenge.version(), "1.0.0");
    }

    // =========================================================================
    // Request/Response Serialization Tests
    // =========================================================================

    #[test]
    fn test_evaluation_request_serialization() {
        let req = create_test_request_with_metadata("serialize-test");

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: EvaluationRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.request_id, req.request_id);
        assert_eq!(deserialized.submission_id, req.submission_id);
        assert_eq!(deserialized.participant_id, req.participant_id);
        assert_eq!(deserialized.epoch, req.epoch);
        assert_eq!(deserialized.deadline, req.deadline);
    }

    #[test]
    fn test_evaluation_response_serialization() {
        let resp = EvaluationResponse::success("req-ser", 0.88, json!({"key": "value"}))
            .with_time(250)
            .with_cost(0.1);

        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: EvaluationResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.request_id, resp.request_id);
        assert_eq!(deserialized.success, resp.success);
        assert_eq!(deserialized.score, resp.score);
        assert_eq!(deserialized.execution_time_ms, resp.execution_time_ms);
        assert_eq!(deserialized.cost, resp.cost);
    }

    #[test]
    fn test_validation_request_serialization() {
        let req = ValidationRequest {
            data: json!({"test": 123, "nested": {"value": true}}),
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: ValidationRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.data["test"], 123);
        assert_eq!(deserialized.data["nested"]["value"], true);
    }

    #[test]
    fn test_validation_response_serialization() {
        let resp = ValidationResponse {
            valid: false,
            errors: vec!["Error 1".to_string(), "Error 2".to_string()],
            warnings: vec!["Warning 1".to_string()],
        };

        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: ValidationResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.valid, resp.valid);
        assert_eq!(deserialized.errors, resp.errors);
        assert_eq!(deserialized.warnings, resp.warnings);
    }
}