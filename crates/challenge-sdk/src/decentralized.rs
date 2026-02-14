//! Decentralized challenge runner
//!
//! Runs a challenge in P2P mode without central server. This module provides
//! the glue between the P2P communication layer and challenge evaluation.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                  Decentralized Runner                       │
//! │  ┌─────────────┐     ┌──────────────┐     ┌────────────┐  │
//! │  │  P2P Layer  │────▶│  Decentralized│────▶│ Challenge  │  │
//! │  │  (libp2p)   │◀────│   Runner      │◀────│ Evaluation │  │
//! │  └─────────────┘     └──────────────┘     └────────────┘  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use platform_challenge_sdk::decentralized::run_decentralized;
//! use platform_challenge_sdk::server::ServerChallenge;
//!
//! let (tx, rx) = tokio::sync::mpsc::channel(100);
//!
//! run_decentralized(
//!     my_challenge,
//!     tx,
//!     rx,
//!     "validator-hotkey".to_string(),
//! ).await?;
//! ```

use crate::error::ChallengeError;
use crate::p2p_client::{P2PChallengeMessage, PendingSubmission};
use crate::server::{EvaluationRequest, ServerChallenge};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Run challenge in decentralized P2P mode
///
/// This function runs a challenge in P2P mode, processing incoming messages
/// from the network and evaluating submissions without a central server.
///
/// # Arguments
///
/// * `challenge` - The challenge implementation to run
/// * `message_tx` - Channel to send messages to the P2P layer
/// * `message_rx` - Channel to receive messages from the P2P layer
/// * `validator_hotkey` - The validator's hotkey for authentication
///
/// # Returns
///
/// Returns `Ok(())` when the challenge runner completes (channel closes),
/// or an error if something goes wrong during execution.
///
/// # Example
///
/// ```rust,ignore
/// use platform_challenge_sdk::decentralized::run_decentralized;
///
/// let (tx, rx) = tokio::sync::mpsc::channel(100);
///
/// run_decentralized(
///     my_challenge,
///     tx,
///     rx,
///     "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
/// ).await?;
/// ```
pub async fn run_decentralized<C: ServerChallenge + Send + Sync + 'static>(
    challenge: C,
    message_tx: mpsc::Sender<P2PChallengeMessage>,
    mut message_rx: mpsc::Receiver<P2PChallengeMessage>,
    validator_hotkey: String,
) -> Result<(), ChallengeError> {
    let challenge = Arc::new(challenge);
    let challenge_id = challenge.challenge_id().to_string();

    info!(
        challenge_id = %challenge_id,
        validator = %validator_hotkey,
        "Starting decentralized challenge runner"
    );

    // Process incoming messages
    while let Some(msg) = message_rx.recv().await {
        match msg {
            P2PChallengeMessage::SubmissionsResponse {
                submissions,
                challenge_id: msg_challenge_id,
            } => {
                // Verify this is for our challenge
                if msg_challenge_id != challenge_id {
                    warn!(
                        expected = %challenge_id,
                        received = %msg_challenge_id,
                        "Received submissions for wrong challenge, ignoring"
                    );
                    continue;
                }

                debug!(
                    challenge_id = %challenge_id,
                    count = %submissions.len(),
                    "Processing submissions batch"
                );

                // Evaluate each submission
                for submission in submissions {
                    let result =
                        evaluate_submission(&challenge, &challenge_id, &submission, &message_tx)
                            .await;

                    if let Err(e) = result {
                        error!(
                            challenge_id = %challenge_id,
                            submission_hash = %submission.submission_hash,
                            error = %e,
                            "Failed to process submission"
                        );
                    }
                }
            }
            P2PChallengeMessage::RequestSubmissions { .. } => {
                // This is a request message, not something we handle here
                // The P2P layer handles routing these to the right place
                debug!("Ignoring RequestSubmissions message in runner");
            }
            P2PChallengeMessage::EvaluationResult { .. } => {
                // This is an outbound message type, not something we handle
                debug!("Ignoring EvaluationResult message in runner");
            }
            P2PChallengeMessage::WeightVote { .. } => {
                // Weight votes are handled by the P2P layer's consensus
                debug!("Ignoring WeightVote message in runner");
            }
            P2PChallengeMessage::RequestWeights { .. } => {
                // Request for weights, handled by P2P layer
                debug!("Ignoring RequestWeights message in runner");
            }
            P2PChallengeMessage::WeightsResponse { .. } => {
                // Weights response, may be used for verification
                debug!("Received weights response in runner");
            }
            P2PChallengeMessage::StoreSubmission {
                submission,
                challenge_id: msg_challenge_id,
            } => {
                if msg_challenge_id == challenge_id {
                    debug!(
                        challenge_id = %challenge_id,
                        submission_hash = %submission.submission_hash,
                        miner_hotkey = %submission.miner_hotkey,
                        "Received submission to store - forwarding to evaluation queue"
                    );
                    // Submissions are auto-queued for evaluation when stored via P2P
                    // The P2P layer handles distributed storage and replication
                } else {
                    warn!(
                        expected = %challenge_id,
                        received = %msg_challenge_id,
                        "Received StoreSubmission for wrong challenge, ignoring"
                    );
                }
            }
            P2PChallengeMessage::RequestEvaluationStatus { .. } => {
                // Request for evaluation status is handled by the P2P layer
                debug!("Ignoring RequestEvaluationStatus message in runner - handled by P2P layer");
            }
            P2PChallengeMessage::EvaluationStatusResponse { .. } => {
                // Evaluation status responses are handled by the client layer
                debug!("Ignoring EvaluationStatusResponse message in runner");
            }
        }
    }

    info!(
        challenge_id = %challenge_id,
        "Decentralized challenge runner completed"
    );

    Ok(())
}

/// Evaluate a single submission and send the result back to the P2P network
async fn evaluate_submission<C: ServerChallenge>(
    challenge: &Arc<C>,
    challenge_id: &str,
    submission: &PendingSubmission,
    message_tx: &mpsc::Sender<P2PChallengeMessage>,
) -> Result<(), ChallengeError> {
    let start_time = std::time::Instant::now();

    debug!(
        challenge_id = %challenge_id,
        submission_hash = %submission.submission_hash,
        miner = %submission.miner_hotkey,
        "Starting evaluation"
    );

    // Build evaluation request from submission
    let req = EvaluationRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        submission_id: submission.submission_hash.clone(),
        participant_id: submission.miner_hotkey.clone(),
        data: serde_json::json!({
            "source_code": submission.source_code,
            "metadata": submission.metadata,
        }),
        metadata: Some(serde_json::json!({
            "submitted_at": submission.submitted_at,
            "p2p_mode": true,
        })),
        epoch: 0, // Epoch is tracked by the P2P layer
        deadline: None,
    };

    // Perform evaluation
    match challenge.evaluate(req).await {
        Ok(resp) => {
            let execution_time_ms = start_time.elapsed().as_millis() as u64;

            info!(
                challenge_id = %challenge_id,
                submission_hash = %submission.submission_hash,
                score = %resp.score,
                execution_time_ms = %execution_time_ms,
                "Evaluation completed successfully"
            );

            // Send result back to network
            let result_msg = P2PChallengeMessage::EvaluationResult {
                challenge_id: challenge_id.to_string(),
                submission_hash: submission.submission_hash.clone(),
                score: resp.score,
                execution_time_ms,
                result_data: resp.results,
            };

            message_tx.send(result_msg).await.map_err(|e| {
                ChallengeError::Network(format!("Failed to send evaluation result: {}", e))
            })?;
        }
        Err(e) => {
            warn!(
                challenge_id = %challenge_id,
                submission_hash = %submission.submission_hash,
                error = %e,
                "Evaluation failed"
            );

            // Send failure result with zero score
            let result_msg = P2PChallengeMessage::EvaluationResult {
                challenge_id: challenge_id.to_string(),
                submission_hash: submission.submission_hash.clone(),
                score: 0.0,
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                result_data: serde_json::json!({
                    "error": e.to_string(),
                    "success": false,
                }),
            };

            message_tx.send(result_msg).await.map_err(|send_err| {
                ChallengeError::Network(format!("Failed to send error result: {}", send_err))
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{
        EvaluationResponse, ServerChallenge, ValidationRequest, ValidationResponse,
    };
    use async_trait::async_trait;
    use serde_json::json;

    struct MockChallenge {
        should_fail: bool,
    }

    #[async_trait]
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
            if self.should_fail {
                return Err(ChallengeError::Evaluation("Mock failure".to_string()));
            }

            Ok(EvaluationResponse::success(
                &request.request_id,
                0.85,
                json!({"mock": true, "passed": 17, "total": 20}),
            ))
        }
    }

    #[tokio::test]
    async fn test_run_decentralized_processes_submissions() {
        let (tx, rx) = mpsc::channel(10);
        let (result_tx, mut result_rx) = mpsc::channel(10);

        let challenge = MockChallenge { should_fail: false };

        // Start runner in background
        let runner_handle = tokio::spawn(async move {
            run_decentralized(challenge, result_tx, rx, "test-validator".to_string()).await
        });

        // Send submissions
        let submission = PendingSubmission {
            submission_hash: "hash123".to_string(),
            miner_hotkey: "miner1".to_string(),
            source_code: "fn main() {}".to_string(),
            metadata: json!({}),
            submitted_at: 1704067200,
        };

        tx.send(P2PChallengeMessage::SubmissionsResponse {
            challenge_id: "mock-challenge".to_string(),
            submissions: vec![submission],
        })
        .await
        .expect("Send should work");

        // Wait for result
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), result_rx.recv())
            .await
            .expect("Should receive result within timeout")
            .expect("Should have result");

        if let P2PChallengeMessage::EvaluationResult {
            submission_hash,
            score,
            ..
        } = result
        {
            assert_eq!(submission_hash, "hash123");
            assert!((score - 0.85).abs() < f64::EPSILON);
        } else {
            panic!("Expected EvaluationResult message");
        }

        // Close channel to stop runner
        drop(tx);

        // Wait for runner to complete
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), runner_handle).await;
    }

    #[tokio::test]
    async fn test_run_decentralized_handles_evaluation_errors() {
        let (tx, rx) = mpsc::channel(10);
        let (result_tx, mut result_rx) = mpsc::channel(10);

        let challenge = MockChallenge { should_fail: true };

        tokio::spawn(async move {
            let _ = run_decentralized(challenge, result_tx, rx, "test-validator".to_string()).await;
        });

        let submission = PendingSubmission {
            submission_hash: "failing-hash".to_string(),
            miner_hotkey: "miner2".to_string(),
            source_code: "invalid".to_string(),
            metadata: json!({}),
            submitted_at: 1704067200,
        };

        tx.send(P2PChallengeMessage::SubmissionsResponse {
            challenge_id: "mock-challenge".to_string(),
            submissions: vec![submission],
        })
        .await
        .expect("Send should work");

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), result_rx.recv())
            .await
            .expect("Should receive result within timeout")
            .expect("Should have result");

        if let P2PChallengeMessage::EvaluationResult {
            score, result_data, ..
        } = result
        {
            // Failed evaluations should have zero score
            assert!((score - 0.0).abs() < f64::EPSILON);
            assert!(result_data["error"].as_str().is_some());
            assert_eq!(result_data["success"], false);
        } else {
            panic!("Expected EvaluationResult message");
        }

        drop(tx);
    }

    #[tokio::test]
    async fn test_run_decentralized_ignores_wrong_challenge_id() {
        let (tx, rx) = mpsc::channel(10);
        let (result_tx, mut result_rx) = mpsc::channel(10);

        let challenge = MockChallenge { should_fail: false };

        tokio::spawn(async move {
            let _ = run_decentralized(challenge, result_tx, rx, "test-validator".to_string()).await;
        });

        // Send submission for wrong challenge
        let submission = PendingSubmission {
            submission_hash: "hash456".to_string(),
            miner_hotkey: "miner3".to_string(),
            source_code: "test".to_string(),
            metadata: json!({}),
            submitted_at: 1704067200,
        };

        tx.send(P2PChallengeMessage::SubmissionsResponse {
            challenge_id: "different-challenge".to_string(), // Wrong challenge ID
            submissions: vec![submission],
        })
        .await
        .expect("Send should work");

        // Should not receive any result because challenge ID doesn't match
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(500), result_rx.recv()).await;

        assert!(result.is_err(), "Should timeout because no result is sent");

        drop(tx);
    }

    #[tokio::test]
    async fn test_run_decentralized_completes_when_channel_closes() {
        let (tx, rx) = mpsc::channel(10);
        let (result_tx, _result_rx) = mpsc::channel(10);

        let challenge = MockChallenge { should_fail: false };

        let handle = tokio::spawn(async move {
            run_decentralized(challenge, result_tx, rx, "test-validator".to_string()).await
        });

        // Close the channel
        drop(tx);

        // Runner should complete successfully
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("Should complete within timeout")
            .expect("Task should not panic");

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_evaluate_submission_success() {
        let challenge = Arc::new(MockChallenge { should_fail: false });
        let (tx, mut rx) = mpsc::channel(10);

        let submission = PendingSubmission {
            submission_hash: "test-hash".to_string(),
            miner_hotkey: "miner".to_string(),
            source_code: "code".to_string(),
            metadata: json!({"key": "value"}),
            submitted_at: 1704067200,
        };

        let result = evaluate_submission(&challenge, "mock-challenge", &submission, &tx).await;

        assert!(result.is_ok());

        let msg = rx.recv().await.expect("Should have message");
        if let P2PChallengeMessage::EvaluationResult {
            challenge_id,
            submission_hash,
            score,
            ..
        } = msg
        {
            assert_eq!(challenge_id, "mock-challenge");
            assert_eq!(submission_hash, "test-hash");
            assert!((score - 0.85).abs() < f64::EPSILON);
        } else {
            panic!("Expected EvaluationResult");
        }
    }

    #[tokio::test]
    async fn test_evaluate_submission_failure() {
        let challenge = Arc::new(MockChallenge { should_fail: true });
        let (tx, mut rx) = mpsc::channel(10);

        let submission = PendingSubmission {
            submission_hash: "fail-hash".to_string(),
            miner_hotkey: "miner".to_string(),
            source_code: "bad code".to_string(),
            metadata: json!({}),
            submitted_at: 1704067200,
        };

        let result = evaluate_submission(&challenge, "mock-challenge", &submission, &tx).await;

        assert!(result.is_ok()); // Function completes even if evaluation fails

        let msg = rx.recv().await.expect("Should have message");
        if let P2PChallengeMessage::EvaluationResult {
            score, result_data, ..
        } = msg
        {
            assert!((score - 0.0).abs() < f64::EPSILON);
            assert_eq!(result_data["success"], false);
        } else {
            panic!("Expected EvaluationResult");
        }
    }
}