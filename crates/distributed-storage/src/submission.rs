//! Submission storage types
//!
//! Types for storing and managing miner submissions and validator evaluations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonicalizes a JSON value to a deterministic string representation.
///
/// This ensures that JSON objects with the same key-value pairs but different
/// insertion orders produce identical strings. Keys in objects are sorted
/// lexicographically, and the process is applied recursively to nested values.
///
/// # Examples
///
/// ```
/// use serde_json::json;
///
/// // These two values have the same content but were created with different key orders
/// let v1 = json!({"b": 2, "a": 1});
/// let v2 = json!({"a": 1, "b": 2});
///
/// // canonicalize_json produces the same output for both
/// // (keys are sorted: "a" comes before "b")
/// ```
fn canonicalize_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut pairs: Vec<_> = map.iter().collect();
            pairs.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));
            let inner: Vec<String> = pairs
                .iter()
                .map(|(k, v)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_else(|_| format!("\"{}\"", k)),
                        canonicalize_json(v)
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonicalize_json).collect();
            format!("[{}]", inner.join(","))
        }
        _ => serde_json::to_string(value).unwrap_or_else(|_| "null".to_string()),
    }
}

/// A stored submission from a miner
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredSubmission {
    /// Challenge ID this submission is for
    pub challenge_id: String,
    /// Hash of the submission (for deduplication and lookup)
    pub submission_hash: String,
    /// Miner's hotkey (SS58 address)
    pub miner_hotkey: String,
    /// The source code of the submission (may be None if encrypted)
    pub source_code: Option<String>,
    /// Additional metadata about the submission
    pub metadata: serde_json::Value,
    /// When the submission was received
    pub submitted_at: DateTime<Utc>,
    /// List of validator hotkeys that have received this submission
    pub received_by: Vec<String>,
    /// Status of the submission
    pub status: SubmissionStatus,
}

/// Status of a submission
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubmissionStatus {
    /// Submission received but not yet validated
    Pending,
    /// Submission is being evaluated
    Evaluating,
    /// Submission has been fully evaluated
    Evaluated,
    /// Submission was rejected (invalid format, etc.)
    Rejected(String),
    /// Submission expired before evaluation
    Expired,
}

impl StoredSubmission {
    /// Create a new submission
    pub fn new(
        challenge_id: impl Into<String>,
        miner_hotkey: impl Into<String>,
        source_code: Option<String>,
        metadata: serde_json::Value,
    ) -> Self {
        let challenge_id = challenge_id.into();
        let miner_hotkey = miner_hotkey.into();

        // Compute submission hash using canonicalized JSON for deterministic hashing
        let mut hasher = Sha256::new();
        hasher.update(challenge_id.as_bytes());
        hasher.update(miner_hotkey.as_bytes());
        if let Some(ref code) = source_code {
            hasher.update(code.as_bytes());
        }
        hasher.update(canonicalize_json(&metadata).as_bytes());
        let submission_hash = hex::encode(hasher.finalize());

        Self {
            challenge_id,
            submission_hash,
            miner_hotkey,
            source_code,
            metadata,
            submitted_at: Utc::now(),
            received_by: Vec::new(),
            status: SubmissionStatus::Pending,
        }
    }

    /// Mark that a validator has received this submission
    pub fn mark_received_by(&mut self, validator_hotkey: &str) {
        if !self.received_by.contains(&validator_hotkey.to_string()) {
            self.received_by.push(validator_hotkey.to_string());
        }
    }

    /// Check if enough validators have received this submission
    pub fn has_quorum(&self, required: usize) -> bool {
        self.received_by.len() >= required
    }

    /// Serialize to JSON bytes for storage
    ///
    /// Uses JSON instead of bincode because the metadata field contains
    /// serde_json::Value which is not supported by bincode.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// A stored evaluation result from a validator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredEvaluation {
    /// Challenge ID
    pub challenge_id: String,
    /// Hash of the submission being evaluated
    pub submission_hash: String,
    /// Validator's hotkey (SS58 address)
    pub validator_hotkey: String,
    /// The computed score (0.0 to 1.0)
    pub score: f64,
    /// Time taken to execute the submission in milliseconds
    pub execution_time_ms: u64,
    /// Additional result data (challenge-specific)
    pub result_data: serde_json::Value,
    /// When the evaluation completed
    pub evaluated_at: DateTime<Utc>,
    /// Signature from the validator over the evaluation
    pub signature: Vec<u8>,
    /// Evaluation status
    pub status: EvaluationStatus,
}

/// Status of an evaluation
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvaluationStatus {
    /// Evaluation completed successfully
    Completed,
    /// Evaluation failed due to an error
    Failed(String),
    /// Evaluation timed out
    TimedOut,
    /// Evaluation skipped (validator chose not to evaluate)
    Skipped,
}

impl StoredEvaluation {
    /// Create a new successful evaluation
    pub fn new(
        challenge_id: impl Into<String>,
        submission_hash: impl Into<String>,
        validator_hotkey: impl Into<String>,
        score: f64,
        execution_time_ms: u64,
        result_data: serde_json::Value,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            challenge_id: challenge_id.into(),
            submission_hash: submission_hash.into(),
            validator_hotkey: validator_hotkey.into(),
            score: score.clamp(0.0, 1.0),
            execution_time_ms,
            result_data,
            evaluated_at: Utc::now(),
            signature,
            status: EvaluationStatus::Completed,
        }
    }

    /// Create a failed evaluation
    pub fn failed(
        challenge_id: impl Into<String>,
        submission_hash: impl Into<String>,
        validator_hotkey: impl Into<String>,
        error: impl Into<String>,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            challenge_id: challenge_id.into(),
            submission_hash: submission_hash.into(),
            validator_hotkey: validator_hotkey.into(),
            score: 0.0,
            execution_time_ms: 0,
            result_data: serde_json::Value::Null,
            evaluated_at: Utc::now(),
            signature,
            status: EvaluationStatus::Failed(error.into()),
        }
    }

    /// Create a timed-out evaluation
    pub fn timed_out(
        challenge_id: impl Into<String>,
        submission_hash: impl Into<String>,
        validator_hotkey: impl Into<String>,
        execution_time_ms: u64,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            challenge_id: challenge_id.into(),
            submission_hash: submission_hash.into(),
            validator_hotkey: validator_hotkey.into(),
            score: 0.0,
            execution_time_ms,
            result_data: serde_json::Value::Null,
            evaluated_at: Utc::now(),
            signature,
            status: EvaluationStatus::TimedOut,
        }
    }

    /// Check if this evaluation was successful
    pub fn is_successful(&self) -> bool {
        matches!(self.status, EvaluationStatus::Completed)
    }

    /// Get the unique key for this evaluation
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.challenge_id, self.submission_hash, self.validator_hotkey
        )
    }

    /// Serialize to JSON bytes for storage
    ///
    /// Uses JSON instead of bincode because the result_data field contains
    /// serde_json::Value which is not supported by bincode.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Aggregated evaluation results for a submission
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedEvaluations {
    /// Challenge ID
    pub challenge_id: String,
    /// Submission hash
    pub submission_hash: String,
    /// Miner hotkey
    pub miner_hotkey: String,
    /// Individual evaluations from validators
    pub evaluations: Vec<StoredEvaluation>,
    /// Final aggregated score
    pub final_score: Option<f64>,
    /// Confidence in the score (based on validator agreement)
    pub confidence: f64,
    /// When the aggregation was computed
    pub aggregated_at: DateTime<Utc>,
}

impl AggregatedEvaluations {
    /// Create a new aggregation from individual evaluations
    pub fn new(
        challenge_id: impl Into<String>,
        submission_hash: impl Into<String>,
        miner_hotkey: impl Into<String>,
        evaluations: Vec<StoredEvaluation>,
    ) -> Self {
        Self {
            challenge_id: challenge_id.into(),
            submission_hash: submission_hash.into(),
            miner_hotkey: miner_hotkey.into(),
            evaluations,
            final_score: None,
            confidence: 0.0,
            aggregated_at: Utc::now(),
        }
    }

    /// Compute the final score using median aggregation
    pub fn compute_median_score(&mut self) {
        let mut scores: Vec<f64> = self
            .evaluations
            .iter()
            .filter(|e| e.is_successful())
            .map(|e| e.score)
            .collect();

        if scores.is_empty() {
            self.final_score = None;
            self.confidence = 0.0;
            return;
        }

        scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let len = scores.len();
        let median = if len % 2 == 0 {
            (scores[len / 2 - 1] + scores[len / 2]) / 2.0
        } else {
            scores[len / 2]
        };

        self.final_score = Some(median);

        // Compute confidence based on variance
        let mean: f64 = scores.iter().sum::<f64>() / len as f64;
        let variance: f64 = scores.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / len as f64;
        let std_dev = variance.sqrt();

        // Higher confidence with lower variance
        self.confidence = (1.0 - std_dev).clamp(0.0, 1.0);
        self.aggregated_at = Utc::now();
    }

    /// Compute the final score using stake-weighted average
    pub fn compute_weighted_score(&mut self, stakes: &[(String, u64)]) {
        let stake_map: std::collections::HashMap<&str, u64> =
            stakes.iter().map(|(k, v)| (k.as_str(), *v)).collect();

        let successful: Vec<_> = self
            .evaluations
            .iter()
            .filter(|e| e.is_successful())
            .collect();

        if successful.is_empty() {
            self.final_score = None;
            self.confidence = 0.0;
            return;
        }

        let total_stake: u64 = successful
            .iter()
            .filter_map(|e| stake_map.get(e.validator_hotkey.as_str()))
            .sum();

        if total_stake == 0 {
            self.compute_median_score();
            return;
        }

        let weighted_sum: f64 = successful
            .iter()
            .map(|e| {
                let stake = stake_map.get(e.validator_hotkey.as_str()).unwrap_or(&0);
                e.score * (*stake as f64)
            })
            .sum();

        self.final_score = Some(weighted_sum / total_stake as f64);
        self.confidence = (successful.len() as f64 / self.evaluations.len() as f64).clamp(0.0, 1.0);
        self.aggregated_at = Utc::now();
    }

    /// Check if we have enough evaluations for consensus
    pub fn has_quorum(&self, required: usize) -> bool {
        let successful_count = self
            .evaluations
            .iter()
            .filter(|e| e.is_successful())
            .count();
        successful_count >= required
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submission_creation() {
        let submission = StoredSubmission::new(
            "challenge1",
            "5FHneW46...",
            Some("print('hello')".to_string()),
            serde_json::json!({"language": "python"}),
        );

        assert_eq!(submission.challenge_id, "challenge1");
        assert_eq!(submission.miner_hotkey, "5FHneW46...");
        assert!(!submission.submission_hash.is_empty());
        assert!(submission.received_by.is_empty());
        assert_eq!(submission.status, SubmissionStatus::Pending);
    }

    #[test]
    fn test_submission_received_by() {
        let mut submission = StoredSubmission::new(
            "challenge1",
            "5FHneW46...",
            Some("code".to_string()),
            serde_json::Value::Null,
        );

        submission.mark_received_by("validator1");
        submission.mark_received_by("validator2");
        submission.mark_received_by("validator1"); // Duplicate

        assert_eq!(submission.received_by.len(), 2);
        assert!(submission.has_quorum(2));
        assert!(!submission.has_quorum(3));
    }

    #[test]
    fn test_submission_serialization() {
        let submission = StoredSubmission::new(
            "challenge1",
            "5FHneW46...",
            Some("code".to_string()),
            serde_json::json!({"key": "value"}),
        );

        let bytes = submission.to_bytes().expect("serialization failed");
        let decoded = StoredSubmission::from_bytes(&bytes).expect("deserialization failed");

        assert_eq!(decoded.challenge_id, submission.challenge_id);
        assert_eq!(decoded.submission_hash, submission.submission_hash);
    }

    #[test]
    fn test_evaluation_creation() {
        let eval = StoredEvaluation::new(
            "challenge1",
            "hash123",
            "validator1",
            0.85,
            1500,
            serde_json::json!({"tasks_completed": 17}),
            vec![1, 2, 3, 4],
        );

        assert_eq!(eval.challenge_id, "challenge1");
        assert_eq!(eval.score, 0.85);
        assert!(eval.is_successful());
    }

    #[test]
    fn test_evaluation_score_clamping() {
        let eval1 = StoredEvaluation::new("c", "h", "v", 1.5, 0, serde_json::Value::Null, vec![]);
        assert_eq!(eval1.score, 1.0);

        let eval2 = StoredEvaluation::new("c", "h", "v", -0.5, 0, serde_json::Value::Null, vec![]);
        assert_eq!(eval2.score, 0.0);
    }

    #[test]
    fn test_evaluation_failed() {
        let eval = StoredEvaluation::failed(
            "challenge1",
            "hash123",
            "validator1",
            "Out of memory",
            vec![],
        );

        assert!(!eval.is_successful());
        assert!(matches!(eval.status, EvaluationStatus::Failed(_)));
    }

    #[test]
    fn test_evaluation_timed_out() {
        let eval =
            StoredEvaluation::timed_out("challenge1", "hash123", "validator1", 30000, vec![]);

        assert!(!eval.is_successful());
        assert_eq!(eval.status, EvaluationStatus::TimedOut);
        assert_eq!(eval.execution_time_ms, 30000);
    }

    #[test]
    fn test_evaluation_key() {
        let eval = StoredEvaluation::new(
            "challenge1",
            "hash123",
            "validator1",
            0.5,
            0,
            serde_json::Value::Null,
            vec![],
        );

        assert_eq!(eval.key(), "challenge1:hash123:validator1");
    }

    #[test]
    fn test_evaluation_serialization() {
        let eval = StoredEvaluation::new(
            "challenge1",
            "hash123",
            "validator1",
            0.75,
            2000,
            serde_json::json!({}),
            vec![1, 2, 3],
        );

        let bytes = eval.to_bytes().expect("serialization failed");
        let decoded = StoredEvaluation::from_bytes(&bytes).expect("deserialization failed");

        assert_eq!(decoded.score, eval.score);
        assert_eq!(decoded.signature, eval.signature);
    }

    #[test]
    fn test_aggregated_median_score() {
        let evaluations = vec![
            StoredEvaluation::new("c", "h", "v1", 0.8, 100, serde_json::Value::Null, vec![]),
            StoredEvaluation::new("c", "h", "v2", 0.6, 100, serde_json::Value::Null, vec![]),
            StoredEvaluation::new("c", "h", "v3", 0.9, 100, serde_json::Value::Null, vec![]),
        ];

        let mut agg = AggregatedEvaluations::new("c", "h", "miner1", evaluations);
        agg.compute_median_score();

        assert!(agg.final_score.is_some());
        assert!((agg.final_score.unwrap() - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_aggregated_weighted_score() {
        let evaluations = vec![
            StoredEvaluation::new("c", "h", "v1", 0.5, 100, serde_json::Value::Null, vec![]),
            StoredEvaluation::new("c", "h", "v2", 1.0, 100, serde_json::Value::Null, vec![]),
        ];

        let stakes = vec![("v1".to_string(), 100), ("v2".to_string(), 300)];

        let mut agg = AggregatedEvaluations::new("c", "h", "miner1", evaluations);
        agg.compute_weighted_score(&stakes);

        // Weighted: (0.5 * 100 + 1.0 * 300) / 400 = 0.875
        assert!(agg.final_score.is_some());
        assert!((agg.final_score.unwrap() - 0.875).abs() < 0.001);
    }

    #[test]
    fn test_aggregated_no_successful_evaluations() {
        let evaluations = vec![
            StoredEvaluation::failed("c", "h", "v1", "error", vec![]),
            StoredEvaluation::timed_out("c", "h", "v2", 1000, vec![]),
        ];

        let mut agg = AggregatedEvaluations::new("c", "h", "miner1", evaluations);
        agg.compute_median_score();

        assert!(agg.final_score.is_none());
        assert_eq!(agg.confidence, 0.0);
    }

    #[test]
    fn test_aggregated_quorum() {
        let evaluations = vec![
            StoredEvaluation::new("c", "h", "v1", 0.8, 100, serde_json::Value::Null, vec![]),
            StoredEvaluation::failed("c", "h", "v2", "error", vec![]),
            StoredEvaluation::new("c", "h", "v3", 0.9, 100, serde_json::Value::Null, vec![]),
        ];

        let agg = AggregatedEvaluations::new("c", "h", "miner1", evaluations);

        assert!(agg.has_quorum(2));
        assert!(!agg.has_quorum(3));
    }

    #[test]
    fn test_canonicalize_json_simple() {
        use crate::submission::canonicalize_json;

        // Test that object key order doesn't affect output
        let json1 = serde_json::json!({"a": 1, "b": 2});
        let json2 = serde_json::json!({"b": 2, "a": 1});

        assert_eq!(canonicalize_json(&json1), canonicalize_json(&json2));
        assert_eq!(canonicalize_json(&json1), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn test_canonicalize_json_nested() {
        use crate::submission::canonicalize_json;

        // Test nested objects with different key orders
        let json1 = serde_json::json!({
            "outer_b": {"inner_z": 1, "inner_a": 2},
            "outer_a": [3, 4]
        });
        let json2 = serde_json::json!({
            "outer_a": [3, 4],
            "outer_b": {"inner_a": 2, "inner_z": 1}
        });

        assert_eq!(canonicalize_json(&json1), canonicalize_json(&json2));
    }

    #[test]
    fn test_canonicalize_json_all_types() {
        use crate::submission::canonicalize_json;

        // Test all JSON value types
        assert_eq!(canonicalize_json(&serde_json::Value::Null), "null");
        assert_eq!(canonicalize_json(&serde_json::json!(true)), "true");
        assert_eq!(canonicalize_json(&serde_json::json!(false)), "false");
        assert_eq!(canonicalize_json(&serde_json::json!(42)), "42");
        assert_eq!(canonicalize_json(&serde_json::json!(3.14)), "3.14");
        assert_eq!(canonicalize_json(&serde_json::json!("hello")), r#""hello""#);
        assert_eq!(canonicalize_json(&serde_json::json!([1, 2, 3])), "[1,2,3]");
    }

    #[test]
    fn test_submission_hash_deterministic() {
        // Create two submissions with the same data but different JSON key insertion order
        // This tests that the submission hash is deterministic regardless of key order

        // Create metadata with keys in one order
        let mut map1 = serde_json::Map::new();
        map1.insert("zebra".to_string(), serde_json::json!("value_z"));
        map1.insert("alpha".to_string(), serde_json::json!("value_a"));
        map1.insert(
            "middle".to_string(),
            serde_json::json!({"nested_b": 2, "nested_a": 1}),
        );
        let metadata1 = serde_json::Value::Object(map1);

        // Create metadata with keys in different order
        let mut map2 = serde_json::Map::new();
        map2.insert("alpha".to_string(), serde_json::json!("value_a"));
        map2.insert(
            "middle".to_string(),
            serde_json::json!({"nested_a": 1, "nested_b": 2}),
        );
        map2.insert("zebra".to_string(), serde_json::json!("value_z"));
        let metadata2 = serde_json::Value::Object(map2);

        // Create submissions with the same logical metadata but different insertion orders
        let submission1 = StoredSubmission::new(
            "challenge_test",
            "miner_hotkey_test",
            Some("print('test')".to_string()),
            metadata1,
        );

        let submission2 = StoredSubmission::new(
            "challenge_test",
            "miner_hotkey_test",
            Some("print('test')".to_string()),
            metadata2,
        );

        // Both submissions should have the same hash
        assert_eq!(
            submission1.submission_hash, submission2.submission_hash,
            "Submission hashes should be identical for semantically equivalent metadata"
        );
    }
}
