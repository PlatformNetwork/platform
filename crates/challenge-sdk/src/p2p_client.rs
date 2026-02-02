//! P2P client for decentralized challenge communication
//!
//! Allows challenges to communicate with validators without central server.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐         ┌─────────────────┐
//! │    Challenge    │◄───P2P──│    Validator    │
//! │   Container     │         │      Node       │
//! └─────────────────┘         └─────────────────┘
//!         │                           │
//!    Evaluates                 Submits/receives
//!    submissions               evaluations
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use platform_challenge_sdk::p2p_client::{P2PChallengeClient, P2PChallengeConfig};
//!
//! let (tx, rx) = tokio::sync::mpsc::channel(100);
//! let config = P2PChallengeConfig {
//!     challenge_id: "my-challenge".to_string(),
//!     validator_hotkey: "validator-hotkey".to_string(),
//!     message_tx: tx,
//!     message_rx: Arc::new(RwLock::new(rx)),
//! };
//!
//! let client = P2PChallengeClient::new(config);
//! client.submit_evaluation("hash", 0.95, 1500, json!({})).await?;
//! ```

use crate::error::ChallengeError;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Default timeout for P2P requests in seconds
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// P2P challenge message types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum P2PChallengeMessage {
    /// Submit evaluation result
    EvaluationResult {
        /// Challenge identifier
        challenge_id: String,
        /// Hash of the submission being evaluated
        submission_hash: String,
        /// Evaluation score (0.0 - 1.0)
        score: f64,
        /// Execution time in milliseconds
        execution_time_ms: u64,
        /// Additional result data
        result_data: serde_json::Value,
    },
    /// Request submissions to evaluate
    RequestSubmissions {
        /// Challenge identifier
        challenge_id: String,
        /// Maximum number of submissions to return
        limit: usize,
    },
    /// Submissions response
    SubmissionsResponse {
        /// Challenge identifier
        challenge_id: String,
        /// List of pending submissions
        submissions: Vec<PendingSubmission>,
    },
    /// Vote on aggregated weights
    WeightVote {
        /// Challenge identifier
        challenge_id: String,
        /// Epoch number
        epoch: u64,
        /// Weight votes as (hotkey, weight) pairs
        weights: Vec<(String, f64)>,
    },
    /// Request weight aggregation
    RequestWeights {
        /// Challenge identifier
        challenge_id: String,
        /// Epoch number
        epoch: u64,
    },
    /// Aggregated weights response
    WeightsResponse {
        /// Challenge identifier
        challenge_id: String,
        /// Epoch number
        epoch: u64,
        /// Aggregated weights as (hotkey, weight) pairs
        weights: Vec<(String, f64)>,
    },
}

/// A submission pending evaluation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingSubmission {
    /// Hash of the submission
    pub submission_hash: String,
    /// Miner's hotkey (SS58 address)
    pub miner_hotkey: String,
    /// Source code or submission data
    pub source_code: String,
    /// Additional metadata
    pub metadata: serde_json::Value,
    /// Submission timestamp (unix seconds)
    pub submitted_at: i64,
}

/// Configuration for P2P challenge client
#[derive(Clone)]
pub struct P2PChallengeConfig {
    /// Challenge ID
    pub challenge_id: String,
    /// Validator hotkey (for signing messages)
    pub validator_hotkey: String,
    /// Channel for sending messages to P2P layer
    pub message_tx: mpsc::Sender<P2PChallengeMessage>,
    /// Channel for receiving messages from P2P layer
    pub message_rx: Arc<RwLock<mpsc::Receiver<P2PChallengeMessage>>>,
}

impl std::fmt::Debug for P2PChallengeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2PChallengeConfig")
            .field("challenge_id", &self.challenge_id)
            .field("validator_hotkey", &self.validator_hotkey)
            .finish_non_exhaustive()
    }
}

/// P2P challenge client for decentralized communication
///
/// This client allows challenges to communicate with validators
/// through P2P channels without requiring a central server.
pub struct P2PChallengeClient {
    config: P2PChallengeConfig,
}

impl P2PChallengeClient {
    /// Create a new P2P challenge client
    pub fn new(config: P2PChallengeConfig) -> Self {
        Self { config }
    }

    /// Get the challenge ID
    pub fn challenge_id(&self) -> &str {
        &self.config.challenge_id
    }

    /// Get the validator hotkey
    pub fn validator_hotkey(&self) -> &str {
        &self.config.validator_hotkey
    }

    /// Submit evaluation result to P2P network
    ///
    /// # Arguments
    ///
    /// * `submission_hash` - Hash of the submission that was evaluated
    /// * `score` - Evaluation score (0.0 - 1.0)
    /// * `execution_time_ms` - How long the evaluation took in milliseconds
    /// * `result_data` - Additional result data as JSON
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the message was sent successfully, or an error
    /// if the channel is closed or send failed.
    pub async fn submit_evaluation(
        &self,
        submission_hash: &str,
        score: f64,
        execution_time_ms: u64,
        result_data: serde_json::Value,
    ) -> Result<(), ChallengeError> {
        let msg = P2PChallengeMessage::EvaluationResult {
            challenge_id: self.config.challenge_id.clone(),
            submission_hash: submission_hash.to_string(),
            score: score.clamp(0.0, 1.0),
            execution_time_ms,
            result_data,
        };

        debug!(
            challenge_id = %self.config.challenge_id,
            submission_hash = %submission_hash,
            score = %score,
            "Submitting evaluation result via P2P"
        );

        self.config
            .message_tx
            .send(msg)
            .await
            .map_err(|e| ChallengeError::Network(format!("Failed to send evaluation: {}", e)))?;

        Ok(())
    }

    /// Request pending submissions from the network
    ///
    /// # Arguments
    ///
    /// * `limit` - Maximum number of submissions to request
    ///
    /// # Returns
    ///
    /// Returns a list of pending submissions or an error on timeout/failure.
    pub async fn get_pending_submissions(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingSubmission>, ChallengeError> {
        let msg = P2PChallengeMessage::RequestSubmissions {
            challenge_id: self.config.challenge_id.clone(),
            limit,
        };

        debug!(
            challenge_id = %self.config.challenge_id,
            limit = %limit,
            "Requesting pending submissions via P2P"
        );

        self.config.message_tx.send(msg).await.map_err(|e| {
            ChallengeError::Network(format!("Failed to request submissions: {}", e))
        })?;

        // Wait for response (with timeout)
        let mut rx = self.config.message_rx.write();
        match tokio::time::timeout(Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS), rx.recv())
            .await
        {
            Ok(Some(P2PChallengeMessage::SubmissionsResponse { submissions, .. })) => {
                debug!(
                    challenge_id = %self.config.challenge_id,
                    count = %submissions.len(),
                    "Received pending submissions"
                );
                Ok(submissions)
            }
            Ok(Some(other)) => {
                warn!(
                    challenge_id = %self.config.challenge_id,
                    "Received unexpected message while waiting for submissions: {:?}",
                    other
                );
                Ok(vec![])
            }
            Ok(None) => {
                warn!(
                    challenge_id = %self.config.challenge_id,
                    "P2P channel closed while waiting for submissions"
                );
                Ok(vec![])
            }
            Err(_) => Err(ChallengeError::Timeout(
                "Request submissions timeout".to_string(),
            )),
        }
    }

    /// Vote on weights for an epoch
    ///
    /// # Arguments
    ///
    /// * `epoch` - The epoch number to vote on
    /// * `weights` - Weight votes as (hotkey, weight) pairs
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the vote was submitted successfully.
    pub async fn vote_weights(
        &self,
        epoch: u64,
        weights: Vec<(String, f64)>,
    ) -> Result<(), ChallengeError> {
        // Clamp all weights to valid range
        let clamped_weights: Vec<(String, f64)> = weights
            .into_iter()
            .map(|(k, w)| (k, w.clamp(0.0, 1.0)))
            .collect();

        let msg = P2PChallengeMessage::WeightVote {
            challenge_id: self.config.challenge_id.clone(),
            epoch,
            weights: clamped_weights,
        };

        debug!(
            challenge_id = %self.config.challenge_id,
            epoch = %epoch,
            "Voting on weights via P2P"
        );

        self.config
            .message_tx
            .send(msg)
            .await
            .map_err(|e| ChallengeError::Network(format!("Failed to vote weights: {}", e)))?;

        Ok(())
    }

    /// Get aggregated weights for an epoch
    ///
    /// # Arguments
    ///
    /// * `epoch` - The epoch number to get weights for
    ///
    /// # Returns
    ///
    /// Returns aggregated weights as (hotkey, weight) pairs or an error on timeout.
    pub async fn get_weights(&self, epoch: u64) -> Result<Vec<(String, f64)>, ChallengeError> {
        let msg = P2PChallengeMessage::RequestWeights {
            challenge_id: self.config.challenge_id.clone(),
            epoch,
        };

        debug!(
            challenge_id = %self.config.challenge_id,
            epoch = %epoch,
            "Requesting weights via P2P"
        );

        self.config
            .message_tx
            .send(msg)
            .await
            .map_err(|e| ChallengeError::Network(format!("Failed to request weights: {}", e)))?;

        // Wait for response
        let mut rx = self.config.message_rx.write();
        match tokio::time::timeout(Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS), rx.recv())
            .await
        {
            Ok(Some(P2PChallengeMessage::WeightsResponse { weights, .. })) => {
                debug!(
                    challenge_id = %self.config.challenge_id,
                    epoch = %epoch,
                    count = %weights.len(),
                    "Received aggregated weights"
                );
                Ok(weights)
            }
            Ok(Some(other)) => {
                warn!(
                    challenge_id = %self.config.challenge_id,
                    "Received unexpected message while waiting for weights: {:?}",
                    other
                );
                Ok(vec![])
            }
            Ok(None) => {
                warn!(
                    challenge_id = %self.config.challenge_id,
                    "P2P channel closed while waiting for weights"
                );
                Ok(vec![])
            }
            Err(_) => Err(ChallengeError::Timeout(
                "Request weights timeout".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> (P2PChallengeConfig, mpsc::Receiver<P2PChallengeMessage>) {
        let (tx, rx) = mpsc::channel(100);
        let (_, inner_rx) = mpsc::channel(100);

        let config = P2PChallengeConfig {
            challenge_id: "test-challenge".to_string(),
            validator_hotkey: "test-validator".to_string(),
            message_tx: tx,
            message_rx: Arc::new(RwLock::new(inner_rx)),
        };

        (config, rx)
    }

    #[test]
    fn test_p2p_challenge_message_serialization() {
        let msg = P2PChallengeMessage::EvaluationResult {
            challenge_id: "test".to_string(),
            submission_hash: "hash123".to_string(),
            score: 0.95,
            execution_time_ms: 1500,
            result_data: serde_json::json!({"passed": true}),
        };

        let json = serde_json::to_string(&msg).expect("Serialization should work");
        let deserialized: P2PChallengeMessage =
            serde_json::from_str(&json).expect("Deserialization should work");

        if let P2PChallengeMessage::EvaluationResult {
            challenge_id,
            score,
            ..
        } = deserialized
        {
            assert_eq!(challenge_id, "test");
            assert!((score - 0.95).abs() < f64::EPSILON);
        } else {
            panic!("Wrong message type after deserialization");
        }
    }

    #[test]
    fn test_pending_submission_serialization() {
        let submission = PendingSubmission {
            submission_hash: "abc123".to_string(),
            miner_hotkey: "5GrwvaEF...".to_string(),
            source_code: "fn main() {}".to_string(),
            metadata: serde_json::json!({"version": "1.0"}),
            submitted_at: 1704067200,
        };

        let json = serde_json::to_string(&submission).expect("Serialization should work");
        let deserialized: PendingSubmission =
            serde_json::from_str(&json).expect("Deserialization should work");

        assert_eq!(deserialized.submission_hash, "abc123");
        assert_eq!(deserialized.source_code, "fn main() {}");
    }

    #[test]
    fn test_p2p_config_debug() {
        let (config, _rx) = create_test_config();
        let debug_str = format!("{:?}", config);

        assert!(debug_str.contains("test-challenge"));
        assert!(debug_str.contains("test-validator"));
    }

    #[test]
    fn test_p2p_client_accessors() {
        let (config, _rx) = create_test_config();
        let client = P2PChallengeClient::new(config);

        assert_eq!(client.challenge_id(), "test-challenge");
        assert_eq!(client.validator_hotkey(), "test-validator");
    }

    #[tokio::test]
    async fn test_submit_evaluation() {
        let (config, mut rx) = create_test_config();
        let client = P2PChallengeClient::new(config);

        let result = client
            .submit_evaluation("hash123", 0.85, 1000, serde_json::json!({"test": true}))
            .await;

        assert!(result.is_ok());

        // Verify message was sent
        let msg = rx.recv().await.expect("Should receive message");
        if let P2PChallengeMessage::EvaluationResult {
            submission_hash,
            score,
            execution_time_ms,
            ..
        } = msg
        {
            assert_eq!(submission_hash, "hash123");
            assert!((score - 0.85).abs() < f64::EPSILON);
            assert_eq!(execution_time_ms, 1000);
        } else {
            panic!("Wrong message type");
        }
    }

    #[tokio::test]
    async fn test_submit_evaluation_clamps_score() {
        let (config, mut rx) = create_test_config();
        let client = P2PChallengeClient::new(config);

        // Score above 1.0 should be clamped
        let _ = client
            .submit_evaluation("hash", 1.5, 100, serde_json::json!({}))
            .await;

        let msg = rx.recv().await.expect("Should receive message");
        if let P2PChallengeMessage::EvaluationResult { score, .. } = msg {
            assert!((score - 1.0).abs() < f64::EPSILON);
        } else {
            panic!("Wrong message type");
        }
    }

    #[tokio::test]
    async fn test_vote_weights() {
        let (config, mut rx) = create_test_config();
        let client = P2PChallengeClient::new(config);

        let weights = vec![("hotkey1".to_string(), 0.6), ("hotkey2".to_string(), 0.4)];

        let result = client.vote_weights(5, weights).await;
        assert!(result.is_ok());

        let msg = rx.recv().await.expect("Should receive message");
        if let P2PChallengeMessage::WeightVote { epoch, weights, .. } = msg {
            assert_eq!(epoch, 5);
            assert_eq!(weights.len(), 2);
        } else {
            panic!("Wrong message type");
        }
    }

    #[tokio::test]
    async fn test_vote_weights_clamps_values() {
        let (config, mut rx) = create_test_config();
        let client = P2PChallengeClient::new(config);

        let weights = vec![
            ("hotkey1".to_string(), -0.5), // Should clamp to 0.0
            ("hotkey2".to_string(), 1.5),  // Should clamp to 1.0
        ];

        let _ = client.vote_weights(1, weights).await;

        let msg = rx.recv().await.expect("Should receive message");
        if let P2PChallengeMessage::WeightVote { weights, .. } = msg {
            assert!((weights[0].1 - 0.0).abs() < f64::EPSILON);
            assert!((weights[1].1 - 1.0).abs() < f64::EPSILON);
        } else {
            panic!("Wrong message type");
        }
    }

    #[tokio::test]
    async fn test_request_submissions_sends_message() {
        let (tx, mut rx) = mpsc::channel(100);
        let (response_tx, response_rx) = mpsc::channel(100);

        let config = P2PChallengeConfig {
            challenge_id: "test-challenge".to_string(),
            validator_hotkey: "test-validator".to_string(),
            message_tx: tx,
            message_rx: Arc::new(RwLock::new(response_rx)),
        };

        let client = P2PChallengeClient::new(config);

        // Send request in select! so we can check both branches
        let request_future = client.get_pending_submissions(10);

        // Use select! to check that request was sent without waiting for timeout
        tokio::select! {
            _ = request_future => {
                // If we get here, means we got a response or error
            }
            msg = rx.recv() => {
                let msg = msg.expect("Should receive request message");
                if let P2PChallengeMessage::RequestSubmissions {
                    challenge_id,
                    limit,
                } = msg
                {
                    assert_eq!(challenge_id, "test-challenge");
                    assert_eq!(limit, 10);
                } else {
                    panic!("Wrong message type");
                }
            }
        }
    }

    #[tokio::test]
    async fn test_request_weights_sends_message() {
        let (tx, mut rx) = mpsc::channel(100);
        let (response_tx, response_rx) = mpsc::channel(100);

        let config = P2PChallengeConfig {
            challenge_id: "test-challenge".to_string(),
            validator_hotkey: "test-validator".to_string(),
            message_tx: tx,
            message_rx: Arc::new(RwLock::new(response_rx)),
        };

        let client = P2PChallengeClient::new(config);

        let request_future = client.get_weights(42);

        tokio::select! {
            _ = request_future => {
                // If we get here, means we got a response or error
            }
            msg = rx.recv() => {
                let msg = msg.expect("Should receive request message");
                if let P2PChallengeMessage::RequestWeights {
                    challenge_id,
                    epoch,
                } = msg
                {
                    assert_eq!(challenge_id, "test-challenge");
                    assert_eq!(epoch, 42);
                } else {
                    panic!("Wrong message type");
                }
            }
        }
    }

    #[test]
    fn test_all_message_variants_serialize() {
        let messages = vec![
            P2PChallengeMessage::EvaluationResult {
                challenge_id: "c1".to_string(),
                submission_hash: "h1".to_string(),
                score: 0.5,
                execution_time_ms: 100,
                result_data: serde_json::json!({}),
            },
            P2PChallengeMessage::RequestSubmissions {
                challenge_id: "c2".to_string(),
                limit: 10,
            },
            P2PChallengeMessage::SubmissionsResponse {
                challenge_id: "c3".to_string(),
                submissions: vec![],
            },
            P2PChallengeMessage::WeightVote {
                challenge_id: "c4".to_string(),
                epoch: 1,
                weights: vec![],
            },
            P2PChallengeMessage::RequestWeights {
                challenge_id: "c5".to_string(),
                epoch: 2,
            },
            P2PChallengeMessage::WeightsResponse {
                challenge_id: "c6".to_string(),
                epoch: 3,
                weights: vec![],
            },
        ];

        for msg in messages {
            let json = serde_json::to_string(&msg).expect("All message variants should serialize");
            let _: P2PChallengeMessage =
                serde_json::from_str(&json).expect("All message variants should deserialize");
        }
    }
}
