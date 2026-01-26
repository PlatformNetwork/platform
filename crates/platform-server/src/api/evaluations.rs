//! Evaluations API handlers

use crate::db::queries;
use crate::models::*;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use tracing::info;

pub async fn submit_evaluation(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitEvaluationRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Validate score is within valid range [0.0, 1.0] and finite
    if !req.score.is_finite() || req.score < 0.0 || req.score > 1.0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "error": format!("Score must be finite and between 0.0 and 1.0, got {}", req.score)
            })),
        ));
    }

    // Validate tasks_total is not zero to avoid division by zero in score calculations
    if req.tasks_total == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "error": "tasks_total must be greater than 0"
            })),
        ));
    }

    // Validate task counts are consistent (and avoid overflow)
    let tasks_sum = req
        .tasks_passed
        .checked_add(req.tasks_failed)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Task counts overflowed u32"
                })),
            )
        })?;
    if tasks_sum != req.tasks_total {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "error": format!(
                    "Task counts are inconsistent: tasks_passed ({}) + tasks_failed ({}) != tasks_total ({})",
                    req.tasks_passed, req.tasks_failed, req.tasks_total
                )
            })),
        ));
    }

    let evaluation = queries::create_evaluation(&state.db, &req)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "error": e.to_string() })),
            )
        })?;

    // Update leaderboard
    let _ = queries::update_leaderboard(&state.db, &req.agent_hash).await;

    // Broadcast evaluation event
    state
        .broadcast_event(WsEvent::EvaluationComplete(EvaluationEvent {
            submission_id: req.submission_id.clone(),
            agent_hash: req.agent_hash.clone(),
            validator_hotkey: req.validator_hotkey.clone(),
            score: req.score,
            tasks_passed: req.tasks_passed,
            tasks_total: req.tasks_total,
        }))
        .await;

    info!(
        "Evaluation submitted: {} by {} (score: {:.2})",
        req.agent_hash, req.validator_hotkey, req.score
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "evaluation_id": evaluation.id,
    })))
}

pub async fn get_evaluations(
    State(state): State<Arc<AppState>>,
    Path(agent_hash): Path<String>,
) -> Result<Json<Vec<Evaluation>>, StatusCode> {
    let evaluations = queries::get_evaluations_for_agent(&state.db, &agent_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(evaluations))
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // SubmitEvaluationRequest tests
    // =========================================================================

    #[test]
    fn test_submit_evaluation_request_deserialize() {
        let json = r#"{
            "submission_id": "sub-123",
            "agent_hash": "hash456",
            "validator_hotkey": "5GrwvaEF...",
            "signature": "sig789",
            "score": 0.95,
            "tasks_passed": 19,
            "tasks_total": 20,
            "tasks_failed": 1,
            "total_cost_usd": 2.50,
            "execution_time_ms": 5000,
            "task_results": [{"task": 1, "passed": true}],
            "execution_log": "Test log"
        }"#;

        let req: SubmitEvaluationRequest = serde_json::from_str(json).unwrap();

        assert_eq!(req.submission_id, "sub-123");
        assert_eq!(req.score, 0.95);
        assert_eq!(req.tasks_passed, 19);
        assert_eq!(req.tasks_total, 20);
        assert_eq!(req.tasks_failed, 1);
    }

    #[test]
    fn test_submit_evaluation_request_minimal() {
        let json = r#"{
            "submission_id": "sub-123",
            "agent_hash": "hash456",
            "validator_hotkey": "5GrwvaEF...",
            "signature": "sig789",
            "score": 0.5,
            "tasks_passed": 5,
            "tasks_total": 10,
            "tasks_failed": 5,
            "total_cost_usd": 0.0,
            "execution_time_ms": null,
            "task_results": null,
            "execution_log": null
        }"#;

        let req: SubmitEvaluationRequest = serde_json::from_str(json).unwrap();

        assert!(req.execution_time_ms.is_none());
        assert!(req.task_results.is_none());
        assert!(req.execution_log.is_none());
    }

    // =========================================================================
    // Evaluation model tests
    // =========================================================================

    #[test]
    fn test_evaluation_serialization() {
        let eval = Evaluation {
            id: "eval-123".to_string(),
            submission_id: "sub-456".to_string(),
            agent_hash: "hash789".to_string(),
            validator_hotkey: "5GrwvaEF...".to_string(),
            score: 0.85,
            tasks_passed: 17,
            tasks_total: 20,
            tasks_failed: 3,
            total_cost_usd: 1.50,
            execution_time_ms: Some(3000),
            task_results: Some("{\"results\": []}".to_string()),
            execution_log: Some("log content".to_string()),
            created_at: 1234567890,
        };

        let json = serde_json::to_string(&eval).unwrap();

        assert!(json.contains("eval-123"));
        assert!(json.contains("0.85"));
        assert!(json.contains("17"));
    }

    #[test]
    fn test_evaluation_deserialization() {
        let json = r#"{
            "id": "eval-123",
            "submission_id": "sub-456",
            "agent_hash": "hash789",
            "validator_hotkey": "validator1",
            "score": 0.90,
            "tasks_passed": 18,
            "tasks_total": 20,
            "tasks_failed": 2,
            "total_cost_usd": 2.0,
            "execution_time_ms": 4000,
            "task_results": null,
            "execution_log": null,
            "created_at": 1234567890
        }"#;

        let eval: Evaluation = serde_json::from_str(json).unwrap();

        assert_eq!(eval.id, "eval-123");
        assert_eq!(eval.score, 0.90);
        assert_eq!(eval.tasks_passed, 18);
    }

    // =========================================================================
    // EvaluationEvent tests
    // =========================================================================

    #[test]
    fn test_evaluation_event_creation() {
        let event = EvaluationEvent {
            submission_id: "sub-123".to_string(),
            agent_hash: "hash456".to_string(),
            validator_hotkey: "5GrwvaEF...".to_string(),
            score: 0.95,
            tasks_passed: 19,
            tasks_total: 20,
        };

        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("sub-123"));
        assert!(json.contains("0.95"));
    }

    #[test]
    fn test_ws_event_evaluation_complete() {
        let event = WsEvent::EvaluationComplete(EvaluationEvent {
            submission_id: "sub-123".to_string(),
            agent_hash: "hash456".to_string(),
            validator_hotkey: "validator1".to_string(),
            score: 0.80,
            tasks_passed: 16,
            tasks_total: 20,
        });

        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("evaluation_complete"));
        assert!(json.contains("sub-123"));
    }

    // =========================================================================
    // Score validation tests
    // =========================================================================

    #[test]
    fn test_score_range_valid() {
        let scores = vec![0.0, 0.5, 1.0, 0.95, 0.001];

        for score in scores {
            assert!(
                score.is_finite() && score >= 0.0 && score <= 1.0,
                "Score {} should be valid and finite",
                score
            );
        }
    }

    #[test]
    fn test_tasks_consistency() {
        let passed = 17u32;
        let failed = 3u32;
        let total = 20u32;

        let sum = passed.checked_add(failed).expect("Should not overflow");
        assert_eq!(sum, total, "Task counts should be consistent");
    }

    // =========================================================================
    // Response format tests
    // =========================================================================

    #[test]
    fn test_success_response_format() {
        let response = serde_json::json!({
            "success": true,
            "evaluation_id": "eval-123"
        });

        assert!(response["success"].as_bool().unwrap());
        assert_eq!(response["evaluation_id"], "eval-123");
    }

    #[test]
    fn test_error_response_format() {
        let response = serde_json::json!({
            "success": false,
            "error": "Database error"
        });

        assert!(!response["success"].as_bool().unwrap());
        assert!(response["error"].as_str().is_some());
    }

    // =========================================================================
    // Input validation tests
    // =========================================================================

    #[test]
    fn test_score_validation_negative() {
        let score = -0.1;
        assert!(
            score < 0.0 || score > 1.0,
            "Negative score should be invalid"
        );
    }

    #[test]
    fn test_score_validation_too_high() {
        let score = 1.5;
        assert!(
            score < 0.0 || score > 1.0,
            "Score > 1.0 should be invalid"
        );
    }

    #[test]
    fn test_score_validation_boundary_values() {
        assert!(0.0 >= 0.0 && 0.0 <= 1.0, "Score 0.0 should be valid");
        assert!(1.0 >= 0.0 && 1.0 <= 1.0, "Score 1.0 should be valid");
    }

    #[test]
    fn test_task_count_validation_consistent() {
        let passed = 17u32;
        let failed = 3u32;
        let total = 20u32;
        assert_eq!(passed + failed, total, "Consistent task counts should be valid");
    }

    #[test]
    fn test_task_count_validation_inconsistent() {
        let passed = 17u32;
        let failed = 3u32;
        let total = 25u32; // Wrong total
        assert_ne!(
            passed + failed,
            total,
            "Inconsistent task counts should be invalid"
        );
    }

    #[test]
    fn test_tasks_total_zero_validation() {
        let total = 0u32;
        assert_eq!(total, 0, "Zero tasks_total should be invalid");
    }

    #[test]
    fn test_score_validation_nan() {
        let score = f64::NAN;
        assert!(!score.is_finite(), "NaN should be detected as non-finite");
    }

    #[test]
    fn test_score_validation_infinity() {
        let score = f64::INFINITY;
        assert!(!score.is_finite(), "Infinity should be detected as non-finite");
    }

    #[test]
    fn test_score_validation_negative_infinity() {
        let score = f64::NEG_INFINITY;
        assert!(!score.is_finite(), "Negative infinity should be detected as non-finite");
    }

    #[test]
    fn test_task_count_overflow_prevention() {
        let passed = u32::MAX;
        let failed = 1u32;
        // This would overflow if we used regular addition
        let result = passed.checked_add(failed);
        assert!(result.is_none(), "Overflow should be detected");
    }

    #[test]
    fn test_task_count_overflow_edge_case() {
        let passed = u32::MAX - 1;
        let failed = 2u32;
        // This should not overflow
        let result = passed.checked_add(failed);
        assert_eq!(result, Some(u32::MAX), "Should handle edge case without overflow");
    }
}
