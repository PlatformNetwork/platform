use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationInput {
    pub agent_data: Vec<u8>,
    pub challenge_id: String,
    pub params: Vec<u8>,
    pub task_definition: Option<Vec<u8>>,
    pub environment_config: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationOutput {
    pub score: i64,
    pub valid: bool,
    pub message: String,
    pub metrics: Option<Vec<u8>>,
    pub details: Option<Vec<u8>>,
}

impl EvaluationOutput {
    pub fn success(score: i64, message: &str) -> Self {
        Self {
            score,
            valid: true,
            message: String::from(message),
            metrics: None,
            details: None,
        }
    }

    pub fn failure(message: &str) -> Self {
        Self {
            score: 0,
            valid: false,
            message: String::from(message),
            metrics: None,
            details: None,
        }
    }

    pub fn with_metrics(mut self, metrics: Vec<u8>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn with_details(mut self, details: Vec<u8>) -> Self {
        self.details = Some(details);
        self
    }
}

pub fn score_f64_scaled(value: f64) -> i64 {
    (value * 10_000.0) as i64
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskDefinition {
    pub task_id: String,
    pub description: String,
    pub command: String,
    pub expected_output: Option<String>,
    pub timeout_ms: u64,
    pub scoring_criteria: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxExecRequest {
    pub command: String,
    pub args: Vec<String>,
    pub env_vars: Vec<(String, String)>,
    pub working_dir: Option<String>,
    pub stdin: Option<Vec<u8>>,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxExecResponse {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_ms: u64,
}

impl SandboxExecResponse {
    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub passed: bool,
    pub score: f64,
    pub output: Option<String>,
    pub metrics: Option<Vec<u8>>,
}

impl TaskResult {
    pub fn success(task_id: &str, score: f64) -> Self {
        Self {
            task_id: String::from(task_id),
            passed: true,
            score,
            output: None,
            metrics: None,
        }
    }

    pub fn failure(task_id: &str, output: &str) -> Self {
        Self {
            task_id: String::from(task_id),
            passed: false,
            score: 0.0,
            output: Some(String::from(output)),
            metrics: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContainerRunRequest {
    pub image: String,
    pub command: Vec<String>,
    pub env_vars: Vec<(String, String)>,
    pub working_dir: Option<String>,
    pub stdin: Option<Vec<u8>>,
    pub memory_limit_mb: Option<u64>,
    pub cpu_limit: Option<u32>,
    pub network_mode: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContainerRunResponse {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_ms: u64,
}

/// Definition of a route exposed by a WASM challenge module.
///
/// Challenge implementations return a serialized list of these definitions from
/// [`Challenge::routes`] so the validator can register HTTP endpoints.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WasmRouteDefinition {
    /// HTTP method (e.g. `"GET"`, `"POST"`).
    pub method: String,
    /// URL path pattern (e.g. `"/status"`, `"/submit"`).
    pub path: String,
    /// Human-readable description of the route.
    pub description: String,
    /// Whether the route requires hotkey authentication.
    pub requires_auth: bool,
}

/// Incoming request forwarded to a WASM challenge route handler.
///
/// The validator serializes this struct and passes it to
/// [`Challenge::handle_route`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WasmRouteRequest {
    /// HTTP method of the incoming request.
    pub method: String,
    /// Matched URL path.
    pub path: String,
    /// Path parameters extracted from the URL pattern.
    pub params: Vec<(String, String)>,
    /// Query-string key/value pairs.
    pub query: Vec<(String, String)>,
    /// Raw request body bytes.
    pub body: Vec<u8>,
    /// Authenticated caller hotkey, if present.
    pub auth_hotkey: Option<String>,
}

/// Response returned by a WASM challenge route handler.
///
/// The WASM module serializes this struct and returns it from
/// [`Challenge::handle_route`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WasmRouteResponse {
    /// HTTP status code to return to the caller.
    pub status: u16,
    /// Raw response body bytes.
    pub body: Vec<u8>,
}
