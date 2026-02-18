use platform_challenge_sdk_wasm::{EvaluationInput, EvaluationOutput};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalRequest {
    pub request_id: String,
    pub submission_id: String,
    pub participant_id: String,
    pub data: serde_json::Value,
    pub metadata: Option<serde_json::Value>,
    pub epoch: u64,
    pub deadline: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalResponse {
    pub request_id: String,
    pub success: bool,
    pub error: Option<String>,
    pub score: f64,
    pub results: serde_json::Value,
    pub execution_time_ms: i64,
    pub cost: Option<f64>,
}

impl EvalResponse {
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

    pub fn with_time(mut self, ms: i64) -> Self {
        self.execution_time_ms = ms;
        self
    }

    pub fn with_cost(mut self, cost: f64) -> Self {
        self.cost = Some(cost);
        self
    }
}

pub fn request_to_input(
    req: &EvalRequest,
    challenge_id: &str,
) -> Result<EvaluationInput, BridgeError> {
    let agent_data =
        serde_json::to_vec(&req.data).map_err(|e| BridgeError::Serialize(format!("data: {e}")))?;

    let params = match &req.metadata {
        Some(meta) => serde_json::to_vec(meta)
            .map_err(|e| BridgeError::Serialize(format!("metadata: {e}")))?,
        None => Vec::new(),
    };

    Ok(EvaluationInput {
        agent_data,
        challenge_id: challenge_id.to_string(),
        params,
        task_definition: None,
        environment_config: None,
    })
}

pub fn input_to_bytes(input: &EvaluationInput) -> Result<Vec<u8>, BridgeError> {
    bincode::serialize(input).map_err(|e| BridgeError::Serialize(e.to_string()))
}

pub fn bytes_to_output(bytes: &[u8]) -> Result<EvaluationOutput, BridgeError> {
    bincode::deserialize(bytes).map_err(|e| BridgeError::Deserialize(e.to_string()))
}

pub fn output_to_response(
    output: &EvaluationOutput,
    request_id: &str,
    execution_time_ms: i64,
) -> EvalResponse {
    if output.valid {
        let score = output.score as f64 / 10_000.0;
        let results = serde_json::json!({ "message": output.message });
        EvalResponse::success(request_id, score, results).with_time(execution_time_ms)
    } else {
        EvalResponse::error(request_id, &output.message).with_time(execution_time_ms)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("deserialization error: {0}")]
    Deserialize(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_request_to_input() {
        let req = EvalRequest {
            request_id: "req-1".into(),
            submission_id: "sub-1".into(),
            participant_id: "part-1".into(),
            data: json!({"code": "print('hello')"}),
            metadata: Some(json!({"lang": "python"})),
            epoch: 1,
            deadline: None,
        };

        let input = request_to_input(&req, "test-challenge").unwrap();
        assert_eq!(input.challenge_id, "test-challenge");
        assert!(!input.agent_data.is_empty());
        assert!(!input.params.is_empty());

        let data: serde_json::Value = serde_json::from_slice(&input.agent_data).unwrap();
        assert_eq!(data, json!({"code": "print('hello')"}));

        let meta: serde_json::Value = serde_json::from_slice(&input.params).unwrap();
        assert_eq!(meta, json!({"lang": "python"}));
    }

    #[test]
    fn test_request_to_input_no_metadata() {
        let req = EvalRequest {
            request_id: "req-1".into(),
            submission_id: "sub-1".into(),
            participant_id: "part-1".into(),
            data: json!("test"),
            metadata: None,
            epoch: 0,
            deadline: None,
        };

        let input = request_to_input(&req, "ch").unwrap();
        assert!(input.params.is_empty());
    }

    #[test]
    fn test_roundtrip_input_bytes() {
        let input = EvaluationInput {
            agent_data: vec![1, 2, 3],
            challenge_id: "test".into(),
            params: vec![4, 5, 6],
            task_definition: None,
            environment_config: None,
        };

        let bytes = input_to_bytes(&input).unwrap();
        let recovered: EvaluationInput = bincode::deserialize(&bytes).unwrap();
        assert_eq!(recovered.agent_data, input.agent_data);
        assert_eq!(recovered.challenge_id, input.challenge_id);
        assert_eq!(recovered.params, input.params);
    }

    #[test]
    fn test_bytes_to_output() {
        let output = EvaluationOutput::success(85, "great job");
        let bytes = bincode::serialize(&output).unwrap();
        let recovered = bytes_to_output(&bytes).unwrap();
        assert_eq!(recovered.score, 85);
        assert!(recovered.valid);
        assert_eq!(recovered.message, "great job");
    }

    #[test]
    fn test_output_to_response_success() {
        let output = EvaluationOutput::success(10000, "perfect");
        let resp = output_to_response(&output, "req-1", 42);
        assert!(resp.success);
        assert_eq!(resp.request_id, "req-1");
        assert!((resp.score - 1.0).abs() < f64::EPSILON);
        assert_eq!(resp.execution_time_ms, 42);
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_output_to_response_failure() {
        let output = EvaluationOutput::failure("bad input");
        let resp = output_to_response(&output, "req-2", 10);
        assert!(!resp.success);
        assert_eq!(resp.request_id, "req-2");
        assert!((resp.score - 0.0).abs() < f64::EPSILON);
        assert_eq!(resp.error.as_deref(), Some("bad input"));
    }
}
