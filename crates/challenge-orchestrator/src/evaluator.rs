//! Challenge evaluator - routes evaluation requests to containers

use crate::{ChallengeInstance, ContainerStatus};
use parking_lot::RwLock;
use platform_core::ChallengeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

/// Evaluator for routing evaluation requests to challenge containers
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

    /// Evaluate an agent on a specific challenge
    pub async fn evaluate(
        &self,
        challenge_id: ChallengeId,
        request: EvaluateRequest,
    ) -> Result<EvaluateResponse, EvaluatorError> {
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
            agent_hash = %request.agent_hash,
            "Sending evaluation request"
        );

        let response = self
            .client
            .post(&url)
            .json(&request)
            .timeout(Duration::from_secs(request.timeout_secs.unwrap_or(3600)))
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
            .json::<EvaluateResponse>()
            .await
            .map_err(|e| EvaluatorError::ParseError(e.to_string()))?;

        info!(
            challenge_id = %challenge_id,
            agent_hash = %request.agent_hash,
            score = result.score,
            "Evaluation completed"
        );

        Ok(result)
    }

    /// Evaluate an agent on all active challenges
    pub async fn evaluate_all(
        &self,
        agent_code: &str,
        agent_hash: &str,
        miner_hotkey: &str,
    ) -> Vec<(ChallengeId, Result<EvaluateResponse, EvaluatorError>)> {
        let challenge_ids: Vec<_> = self
            .challenges
            .read()
            .iter()
            .filter(|(_, instance)| instance.status == ContainerStatus::Running)
            .map(|(id, _)| *id)
            .collect();

        let mut results = Vec::new();

        for challenge_id in challenge_ids {
            let request = EvaluateRequest {
                agent_code: agent_code.to_string(),
                agent_hash: agent_hash.to_string(),
                miner_hotkey: miner_hotkey.to_string(),
                task_id: None,
                timeout_secs: None,
            };

            let result = self.evaluate(challenge_id, request).await;
            results.push((challenge_id, result));
        }

        results
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
    pub async fn check_health(
        &self,
        challenge_id: ChallengeId,
    ) -> Result<HealthResponse, EvaluatorError> {
        let instance = self
            .challenges
            .read()
            .get(&challenge_id)
            .cloned()
            .ok_or(EvaluatorError::ChallengeNotFound(challenge_id))?;

        let url = format!("{}/health", instance.endpoint);

        let response = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| EvaluatorError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(EvaluatorError::ChallengeError {
                status: response.status().as_u16(),
                message: "Health check failed".to_string(),
            });
        }

        response
            .json()
            .await
            .map_err(|e| EvaluatorError::ParseError(e.to_string()))
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

/// Evaluation request sent to challenge container
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluateRequest {
    /// Agent source code
    pub agent_code: String,
    /// Agent hash (SHA256)
    pub agent_hash: String,
    /// Miner hotkey
    pub miner_hotkey: String,
    /// Specific task to evaluate (optional, evaluates all if None)
    pub task_id: Option<String>,
    /// Timeout in seconds (optional)
    pub timeout_secs: Option<u64>,
}

/// Evaluation response from challenge container
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluateResponse {
    /// Overall score (0.0 - 1.0)
    pub score: f64,
    /// Number of tasks passed
    pub tasks_passed: u32,
    /// Total number of tasks
    pub tasks_total: u32,
    /// Detailed task results
    pub task_results: Vec<TaskResult>,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Container logs (optional)
    pub logs: Option<String>,
    /// Additional metrics
    #[serde(default)]
    pub metrics: HashMap<String, serde_json::Value>,
}

/// Individual task result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub task_name: String,
    pub passed: bool,
    pub score: f64,
    pub execution_time_ms: u64,
    pub error: Option<String>,
    pub output: Option<String>,
}

/// Challenge health response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_secs: u64,
    pub evaluations_count: u64,
}

/// Challenge info response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeInfo {
    pub name: String,
    pub version: String,
    pub mechanism_id: u8,
    pub emission_weight: f64,
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

    #[test]
    fn test_evaluate_request_serialization() {
        let request = EvaluateRequest {
            agent_code: "def main(): pass".to_string(),
            agent_hash: "abc123".to_string(),
            miner_hotkey: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
            task_id: None,
            timeout_secs: Some(3600),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("agent_code"));
        assert!(json.contains("miner_hotkey"));
    }

    #[test]
    fn test_evaluate_response_deserialization() {
        let json = r#"{
            "score": 0.85,
            "tasks_passed": 17,
            "tasks_total": 20,
            "task_results": [],
            "execution_time_ms": 12500,
            "logs": null,
            "metrics": {}
        }"#;

        let response: EvaluateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.score, 0.85);
        assert_eq!(response.tasks_passed, 17);
    }
}
