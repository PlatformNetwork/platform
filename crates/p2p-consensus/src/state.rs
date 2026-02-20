//! Decentralized state management for P2P consensus
//!
//! Manages the shared state across validators including challenges,
//! evaluations, weights, and validator information.

use crate::messages::{MerkleNode, MerkleProof, SequenceNumber};
use bincode::Options;
use parking_lot::RwLock;
use platform_core::{hash_data, ChallengeId, Hotkey, SignedMessage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info, warn};

const MAX_STATE_DESERIALIZATION_SIZE: u64 = 256 * 1024 * 1024;

/// Maximum size of agent log data in bytes (256 KB)
const MAX_AGENT_LOG_SIZE: usize = 256 * 1024;

/// Maximum number of pending agent log proposals (per-submission entries)
const MAX_AGENT_LOG_PROPOSALS: usize = 10_000;

/// Maximum number of validated agent log entries
const MAX_VALIDATED_AGENT_LOGS: usize = 50_000;

/// Errors related to state operations
#[derive(Error, Debug)]
pub enum StateError {
    #[error("State hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("Invalid merkle proof")]
    InvalidMerkleProof,
    #[error("Sequence number too old: current {current}, received {received}")]
    SequenceTooOld { current: u64, received: u64 },
    #[error("State serialization error: {0}")]
    Serialization(String),
    #[error("Challenge not found: {0}")]
    ChallengeNotFound(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
}

/// Evaluation record for a submission
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationRecord {
    /// Submission ID
    pub submission_id: String,
    /// Challenge ID
    pub challenge_id: ChallengeId,
    /// Miner who submitted
    pub miner: Hotkey,
    /// Agent code hash
    pub agent_hash: String,
    /// Evaluations from validators (validator hotkey -> score)
    pub evaluations: HashMap<Hotkey, ValidatorEvaluation>,
    /// Aggregated score (computed when finalized)
    pub aggregated_score: Option<f64>,
    /// Whether evaluation is finalized
    pub finalized: bool,
    /// Creation timestamp
    pub created_at: i64,
    /// Finalization timestamp
    pub finalized_at: Option<i64>,
}

/// Single validator's evaluation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorEvaluation {
    /// Score (0.0 to 1.0)
    pub score: f64,
    /// Validator's stake at evaluation time
    pub stake: u64,
    /// Evaluation timestamp
    pub timestamp: i64,
    /// Signature over (submission_id, score)
    pub signature: Vec<u8>,
}

/// Challenge configuration stored in state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeConfig {
    /// Challenge ID
    pub id: ChallengeId,
    /// Challenge name
    pub name: String,
    /// Weight allocation (0-100)
    pub weight: u16,
    /// Whether challenge is active
    pub is_active: bool,
    /// Creator hotkey
    pub creator: Hotkey,
    /// Creation timestamp
    pub created_at: i64,
}

/// Weight votes for epoch finalization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightVotes {
    /// Epoch number
    pub epoch: u64,
    /// Netuid
    pub netuid: u16,
    /// Votes from validators (hotkey -> weight vector)
    pub votes: HashMap<Hotkey, Vec<(u16, u16)>>,
    /// Whether weights have been finalized
    pub finalized: bool,
    /// Final aggregated weights (if finalized)
    pub final_weights: Option<Vec<(u16, u16)>>,
}

/// Leaderboard entry for a challenge
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaderboardEntry {
    pub miner: Hotkey,
    pub score: f64,
    pub submission_count: u32,
    pub last_submission_at: i64,
    pub rank: u32,
}

/// Record of an active evaluation job
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobRecord {
    pub submission_id: String,
    pub challenge_id: ChallengeId,
    pub assigned_validator: Hotkey,
    pub assigned_at: i64,
    pub timeout_at: i64,
    pub status: JobStatus,
}

/// Status of an evaluation job
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    InProgress,
    Completed,
    TimedOut,
}

/// Record of real-time task progress
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskProgressRecord {
    pub submission_id: String,
    pub challenge_id: ChallengeId,
    pub validator: Hotkey,
    pub task_index: u32,
    pub total_tasks: u32,
    pub status: String,
    pub progress_pct: f64,
    pub updated_at: i64,
}

/// The shared chain state for P2P consensus
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainState {
    /// Current sequence number (increments with each state change)
    pub sequence: SequenceNumber,
    /// Current epoch
    pub epoch: u64,
    /// State hash
    pub state_hash: [u8; 32],
    /// Active validators (hotkey -> stake)
    pub validators: HashMap<Hotkey, u64>,
    /// Active challenges
    pub challenges: HashMap<ChallengeId, ChallengeConfig>,
    /// Pending evaluations (submission_id -> record)
    pub pending_evaluations: HashMap<String, EvaluationRecord>,
    /// Completed evaluations (by epoch)
    pub completed_evaluations: HashMap<u64, Vec<EvaluationRecord>>,
    /// Current epoch's weight votes
    pub weight_votes: Option<WeightVotes>,
    /// Historical weights (epoch -> final weights)
    pub historical_weights: HashMap<u64, Vec<(u16, u16)>>,
    /// Sudo key
    pub sudo_key: Hotkey,
    /// Netuid
    pub netuid: u16,
    /// Last update timestamp
    pub last_updated: i64,
    /// Linked Bittensor/Subtensor block number
    pub bittensor_block: u64,
    /// Hash of the linked Bittensor/Subtensor block
    pub bittensor_block_hash: [u8; 32],
    /// Leaderboards per challenge
    #[serde(default)]
    pub leaderboard: HashMap<ChallengeId, Vec<LeaderboardEntry>>,
    /// Active evaluation jobs
    #[serde(default)]
    pub active_jobs: HashMap<String, JobRecord>,
    /// Real-time task progress records
    #[serde(default)]
    pub task_progress: HashMap<String, TaskProgressRecord>,
    /// Storage roots per challenge
    #[serde(default)]
    pub challenge_storage_roots: HashMap<ChallengeId, [u8; 32]>,
    /// Review assignments per submission
    #[serde(default)]
    pub review_assignments: HashMap<String, Vec<ReviewRecord>>,
    /// Agent logs awaiting consensus (submission_id -> validator_hotkey -> serialized logs)
    #[serde(default)]
    pub agent_log_proposals: HashMap<String, HashMap<Hotkey, Vec<u8>>>,
    /// Consensus-validated agent logs (submission_id -> validated logs)
    #[serde(default)]
    pub validated_agent_logs: HashMap<String, Vec<u8>>,
    /// Stored agent code registry (miner_hotkey -> latest agent code entry)
    #[serde(default)]
    pub agent_code_registry: HashMap<Hotkey, AgentCodeEntry>,
    /// Whether the network is in the bootstrap period (UID 0 dominance)
    #[serde(default)]
    pub bootstrap_active: bool,
}

/// Record of a review assignment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReviewRecord {
    pub submission_id: String,
    pub review_type: crate::messages::ReviewType,
    pub assigned_validators: Vec<Hotkey>,
    pub results: HashMap<Hotkey, ReviewResultEntry>,
    pub created_at: i64,
}

/// Single review result entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReviewResultEntry {
    pub score: f64,
    pub details: String,
    pub timestamp: i64,
}

/// Registry entry for stored agent code
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentCodeEntry {
    pub agent_hash: String,
    pub code_size: u64,
    pub epoch: u64,
    pub stored_at: i64,
}

impl Default for ChainState {
    fn default() -> Self {
        Self {
            sequence: 0,
            epoch: 0,
            state_hash: [0u8; 32],
            validators: HashMap::new(),
            challenges: HashMap::new(),
            pending_evaluations: HashMap::new(),
            completed_evaluations: HashMap::new(),
            weight_votes: None,
            historical_weights: HashMap::new(),
            sudo_key: Hotkey(platform_core::SUDO_KEY_BYTES),
            netuid: 100,
            last_updated: chrono::Utc::now().timestamp_millis(),
            bittensor_block: 0,
            bittensor_block_hash: [0u8; 32],
            leaderboard: HashMap::new(),
            active_jobs: HashMap::new(),
            task_progress: HashMap::new(),
            challenge_storage_roots: HashMap::new(),
            review_assignments: HashMap::new(),
            agent_log_proposals: HashMap::new(),
            validated_agent_logs: HashMap::new(),
            agent_code_registry: HashMap::new(),
            bootstrap_active: false,
        }
    }
}

impl ChainState {
    /// Create new chain state with production sudo key
    pub fn new(netuid: u16) -> Self {
        let mut state = Self {
            netuid,
            sudo_key: Hotkey(platform_core::SUDO_KEY_BYTES),
            ..Default::default()
        };
        state.update_hash();
        state
    }

    /// Create with custom sudo key (for testing)
    pub fn with_sudo(sudo_key: Hotkey, netuid: u16) -> Self {
        let mut state = Self {
            netuid,
            sudo_key,
            ..Default::default()
        };
        state.update_hash();
        state
    }

    /// Update the state hash after modifications
    pub fn update_hash(&mut self) {
        self.last_updated = chrono::Utc::now().timestamp_millis();

        // Create a deterministic hash input
        #[derive(Serialize)]
        struct HashInput {
            sequence: SequenceNumber,
            epoch: u64,
            validator_count: usize,
            challenge_count: usize,
            pending_count: usize,
            netuid: u16,
        }

        let input = HashInput {
            sequence: self.sequence,
            epoch: self.epoch,
            validator_count: self.validators.len(),
            challenge_count: self.challenges.len(),
            pending_count: self.pending_evaluations.len(),
            netuid: self.netuid,
        };

        self.state_hash = hash_data(&input).unwrap_or([0u8; 32]);
    }

    /// Increment sequence and update hash
    pub fn increment_sequence(&mut self) {
        self.sequence += 1;
        self.update_hash();
    }

    /// Link state to a Bittensor block
    ///
    /// Updates the linked Bittensor block number and hash, and increments
    /// the sequence number to track this state change.
    pub fn link_to_bittensor_block(&mut self, block_number: u64, block_hash: [u8; 32]) {
        self.bittensor_block = block_number;
        self.bittensor_block_hash = block_hash;
        self.increment_sequence();
    }

    /// Get linked Bittensor block number
    pub fn linked_block(&self) -> u64 {
        self.bittensor_block
    }

    /// Check if a hotkey is the sudo key
    pub fn is_sudo(&self, hotkey: &Hotkey) -> bool {
        self.sudo_key == *hotkey
    }

    /// Get state hash as hex string
    pub fn hash_hex(&self) -> String {
        hex::encode(self.state_hash)
    }

    /// Serialize state to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, StateError> {
        bincode::serialize(self).map_err(|e| StateError::Serialization(e.to_string()))
    }

    /// Deserialize state from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StateError> {
        if bytes.len() as u64 > MAX_STATE_DESERIALIZATION_SIZE {
            return Err(StateError::Serialization(format!(
                "state data exceeds maximum size: {} > {}",
                bytes.len(),
                MAX_STATE_DESERIALIZATION_SIZE
            )));
        }
        bincode::DefaultOptions::new()
            .with_limit(MAX_STATE_DESERIALIZATION_SIZE)
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .deserialize(bytes)
            .map_err(|e| StateError::Serialization(e.to_string()))
    }

    /// Add or update a validator
    pub fn update_validator(&mut self, hotkey: Hotkey, stake: u64) {
        self.validators.insert(hotkey, stake);
        self.increment_sequence();
    }

    /// Remove a validator
    pub fn remove_validator(&mut self, hotkey: &Hotkey) -> bool {
        let removed = self.validators.remove(hotkey).is_some();
        if removed {
            self.increment_sequence();
        }
        removed
    }

    /// Add a challenge
    pub fn add_challenge(&mut self, config: ChallengeConfig) {
        info!(challenge_id = %config.id, name = %config.name, "Adding challenge to state");
        self.challenges.insert(config.id, config);
        self.increment_sequence();
    }

    /// Remove a challenge
    pub fn remove_challenge(&mut self, id: &ChallengeId) -> Option<ChallengeConfig> {
        let removed = self.challenges.remove(id);
        if removed.is_some() {
            self.increment_sequence();
        }
        removed
    }

    /// Add an evaluation record
    pub fn add_evaluation(&mut self, record: EvaluationRecord) {
        debug!(submission_id = %record.submission_id, "Adding evaluation record");
        self.pending_evaluations
            .insert(record.submission_id.clone(), record);
        self.increment_sequence();
    }

    /// Add validator evaluation to existing record
    ///
    /// Verifies the provided signature before accepting the evaluation.
    /// The signing data is (submission_id, score) serialized via bincode.
    pub fn add_validator_evaluation(
        &mut self,
        submission_id: &str,
        validator: Hotkey,
        evaluation: ValidatorEvaluation,
        signature: &[u8],
    ) -> Result<(), StateError> {
        // Verify signature over (submission_id, score)
        #[derive(Serialize)]
        struct EvaluationSigningData<'a> {
            submission_id: &'a str,
            score: f64,
        }

        let signing_data = EvaluationSigningData {
            submission_id,
            score: evaluation.score,
        };

        let signing_bytes = bincode::serialize(&signing_data)
            .map_err(|e| StateError::Serialization(e.to_string()))?;

        let signed_msg = SignedMessage {
            message: signing_bytes,
            signature: signature.to_vec(),
            signer: validator.clone(),
        };

        let is_valid = signed_msg
            .verify()
            .map_err(|e| StateError::InvalidSignature(e.to_string()))?;

        if !is_valid {
            return Err(StateError::InvalidSignature(validator.to_hex()));
        }

        if let Some(record) = self.pending_evaluations.get_mut(submission_id) {
            record.evaluations.insert(validator, evaluation);
            self.update_hash();
            Ok(())
        } else {
            Err(StateError::ChallengeNotFound(submission_id.to_string()))
        }
    }

    /// Finalize an evaluation (compute aggregated score)
    ///
    /// Only uses verified stakes from the validators map. Evaluations from
    /// unknown validators are skipped entirely to prevent stake inflation attacks.
    pub fn finalize_evaluation(&mut self, submission_id: &str) -> Result<f64, StateError> {
        if let Some(record) = self.pending_evaluations.get_mut(submission_id) {
            // Stake-weighted average using ONLY verified stakes
            let mut total_stake: u64 = 0;
            let mut weighted_sum: f64 = 0.0;

            for (validator_hotkey, eval) in &record.evaluations {
                // Only use verified stake from validators map - skip unknown validators
                if let Some(stake) = self.validators.get(validator_hotkey).copied() {
                    total_stake += stake;
                    weighted_sum += eval.score * (stake as f64);
                } else {
                    // Skip evaluations from unknown validators to prevent stake inflation
                    warn!(
                        validator = %validator_hotkey.to_hex(),
                        self_reported_stake = eval.stake,
                        "Skipping evaluation from unknown validator - not in verified validators map"
                    );
                }
            }

            if total_stake == 0 {
                return Ok(0.0);
            }

            let aggregated = weighted_sum / (total_stake as f64);
            record.aggregated_score = Some(aggregated);
            record.finalized = true;
            record.finalized_at = Some(chrono::Utc::now().timestamp_millis());

            // Move to completed
            let completed = self
                .pending_evaluations
                .remove(submission_id)
                .ok_or_else(|| {
                    StateError::ChallengeNotFound(format!(
                        "Submission '{}' was removed during finalization",
                        submission_id
                    ))
                })?;
            self.completed_evaluations
                .entry(self.epoch)
                .or_default()
                .push(completed);

            self.increment_sequence();
            Ok(aggregated)
        } else {
            Err(StateError::ChallengeNotFound(submission_id.to_string()))
        }
    }

    /// Add weight vote from validator with signature verification
    ///
    /// Verifies the provided signature before accepting the weight vote.
    /// The signing data is (epoch, netuid, weights) serialized via bincode.
    pub fn add_weight_vote_verified(
        &mut self,
        validator: Hotkey,
        weights: Vec<(u16, u16)>,
        epoch: u64,
        signature: &[u8],
    ) -> Result<(), StateError> {
        // Verify signature over (epoch, netuid, weights)
        #[derive(Serialize)]
        struct WeightVoteSigningData {
            epoch: u64,
            netuid: u16,
            weights: Vec<(u16, u16)>,
        }

        let signing_data = WeightVoteSigningData {
            epoch,
            netuid: self.netuid,
            weights: weights.clone(),
        };

        let signing_bytes = bincode::serialize(&signing_data)
            .map_err(|e| StateError::Serialization(e.to_string()))?;

        let signed_msg = SignedMessage {
            message: signing_bytes,
            signature: signature.to_vec(),
            signer: validator.clone(),
        };

        let is_valid = signed_msg
            .verify()
            .map_err(|e| StateError::InvalidSignature(e.to_string()))?;

        if !is_valid {
            return Err(StateError::InvalidSignature(validator.to_hex()));
        }

        let votes = self.weight_votes.get_or_insert_with(|| WeightVotes {
            epoch,
            netuid: self.netuid,
            votes: HashMap::new(),
            finalized: false,
            final_weights: None,
        });

        if votes.epoch == epoch && !votes.finalized {
            votes.votes.insert(validator, weights);
            self.update_hash();
            Ok(())
        } else {
            warn!(
                epoch,
                votes_epoch = votes.epoch,
                finalized = votes.finalized,
                "Weight vote rejected: epoch mismatch or already finalized"
            );
            Ok(()) // Not an error, just a stale vote
        }
    }

    /// Add weight vote from local validator (no signature verification needed)
    pub fn submit_weight_vote(
        &mut self,
        validator: Hotkey,
        netuid: u16,
        weights: Vec<(u16, u16)>,
    ) -> Result<(), StateError> {
        let epoch = self.epoch;
        let votes = self.weight_votes.get_or_insert_with(|| WeightVotes {
            epoch,
            netuid,
            votes: HashMap::new(),
            finalized: false,
            final_weights: None,
        });

        if votes.epoch == epoch && !votes.finalized {
            votes.votes.insert(validator, weights);
            self.update_hash();
            Ok(())
        } else {
            Ok(())
        }
    }

    /// Check whether the network is currently in the bootstrap period
    pub fn is_in_bootstrap_period(&self) -> bool {
        self.bootstrap_active || self.epoch < platform_core::constants::BOOTSTRAP_PERIOD_EPOCHS
    }

    /// Finalize epoch weights (stake-weighted aggregation)
    pub fn finalize_weights(&mut self) -> Option<Vec<(u16, u16)>> {
        let in_bootstrap = self.is_in_bootstrap_period();
        let votes = self.weight_votes.as_mut()?;
        if votes.finalized {
            return votes.final_weights.clone();
        }

        // Collect all UIDs that received votes
        let mut uid_weights: HashMap<u16, f64> = HashMap::new();
        let mut total_stake: u64 = 0;

        for (validator, weights) in &votes.votes {
            let stake = self.validators.get(validator).copied().unwrap_or(0);
            if stake == 0 {
                continue;
            }
            total_stake += stake;

            for (uid, weight) in weights {
                let weighted = (*weight as f64) * (stake as f64);
                *uid_weights.entry(*uid).or_default() += weighted;
            }
        }

        if total_stake == 0 {
            return None;
        }

        // Normalize and convert to u16
        let max_weight = uid_weights.values().copied().fold(0.0f64, f64::max);

        let final_weights: Vec<(u16, u16)> = if max_weight > 0.0 {
            uid_weights
                .into_iter()
                .map(|(uid, w)| {
                    let normalized = ((w / max_weight) * u16::MAX as f64) as u16;
                    (uid, normalized)
                })
                .collect()
        } else {
            vec![]
        };

        let final_weights = if in_bootstrap {
            let mut weights = final_weights;
            if let Some(entry) = weights.iter_mut().find(|(uid, _)| *uid == 0) {
                entry.1 = platform_core::constants::BOOTSTRAP_UID0_WEIGHT;
            } else {
                weights.push((0, platform_core::constants::BOOTSTRAP_UID0_WEIGHT));
            }
            weights
        } else {
            final_weights
        };

        votes.final_weights = Some(final_weights.clone());
        votes.finalized = true;

        // Store in history
        self.historical_weights
            .insert(votes.epoch, final_weights.clone());

        self.increment_sequence();
        Some(final_weights)
    }

    /// Maximum epochs to keep in historical_weights
    const MAX_HISTORICAL_EPOCHS: usize = 100;

    /// Transition to next epoch
    pub fn next_epoch(&mut self) {
        self.epoch += 1;
        self.weight_votes = None;

        // Prune old historical weights to prevent unbounded growth
        if self.historical_weights.len() > Self::MAX_HISTORICAL_EPOCHS {
            let cutoff_epoch = self
                .epoch
                .saturating_sub(Self::MAX_HISTORICAL_EPOCHS as u64);
            self.historical_weights
                .retain(|epoch, _| *epoch > cutoff_epoch);
            debug!(
                retained_epochs = self.historical_weights.len(),
                cutoff = cutoff_epoch,
                "Pruned historical weights"
            );
        }

        self.increment_sequence();
        info!(epoch = self.epoch, "Transitioned to new epoch");
    }

    /// Get the current block height (sequence number)
    ///
    /// In this P2P consensus system, the sequence number serves as the
    /// logical block height, incrementing with each state change.
    pub fn block_height(&self) -> u64 {
        self.sequence
    }

    /// Get the current state hash as a 32-byte array
    pub fn get_state_hash(&self) -> [u8; 32] {
        self.state_hash
    }

    /// Get aggregated weights for a specific epoch
    ///
    /// Returns a vector of (hotkey_string, weight_as_f64) pairs, where weight
    /// is normalized to a 0.0-1.0 range. Returns empty vector if no weights
    /// exist for the given epoch.
    pub fn get_aggregated_weights(&self, epoch: u64) -> Vec<(String, f64)> {
        self.historical_weights
            .get(&epoch)
            .map(|weights| {
                weights
                    .iter()
                    .map(|(uid, weight)| {
                        // Convert u16 UID to string and normalize weight
                        let normalized_weight = (*weight as f64) / (u16::MAX as f64);
                        (uid.to_string(), normalized_weight)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn assign_job(&mut self, job: JobRecord) {
        info!(submission_id = %job.submission_id, validator = %job.assigned_validator.to_hex(), "Job assigned");
        self.active_jobs.insert(job.submission_id.clone(), job);
        self.increment_sequence();
    }

    pub fn complete_job(&mut self, submission_id: &str) -> Option<JobRecord> {
        let mut job = self.active_jobs.remove(submission_id)?;
        job.status = JobStatus::Completed;
        self.increment_sequence();
        Some(job)
    }

    pub fn update_leaderboard(
        &mut self,
        challenge_id: ChallengeId,
        entries: Vec<LeaderboardEntry>,
    ) {
        self.leaderboard.insert(challenge_id, entries);
        self.increment_sequence();
    }

    pub fn get_leaderboard(&self, challenge_id: &ChallengeId) -> Vec<LeaderboardEntry> {
        self.leaderboard
            .get(challenge_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn update_task_progress(&mut self, record: TaskProgressRecord) {
        let key = format!("{}:{}", record.submission_id, record.validator.to_hex());
        self.task_progress.insert(key, record);
        self.update_hash();
    }

    pub fn update_challenge_storage_root(&mut self, challenge_id: ChallengeId, root: [u8; 32]) {
        self.challenge_storage_roots.insert(challenge_id, root);
        self.increment_sequence();
    }

    pub fn cleanup_stale_jobs(&mut self, now: i64) -> Vec<JobRecord> {
        let stale: Vec<String> = self
            .active_jobs
            .iter()
            .filter(|(_, job)| job.timeout_at < now && job.status != JobStatus::Completed)
            .map(|(id, _)| id.clone())
            .collect();
        let mut removed = Vec::new();
        for id in stale {
            if let Some(mut job) = self.active_jobs.remove(&id) {
                job.status = JobStatus::TimedOut;
                removed.push(job);
            }
        }
        if !removed.is_empty() {
            self.increment_sequence();
        }
        removed
    }

    pub fn assign_review(&mut self, record: ReviewRecord) {
        self.review_assignments
            .entry(record.submission_id.clone())
            .or_default()
            .push(record);
        self.increment_sequence();
    }

    pub fn add_review_result(
        &mut self,
        submission_id: &str,
        validator: &Hotkey,
        score: f64,
        details: String,
    ) -> bool {
        if !score.is_finite() || !(0.0..=1.0).contains(&score) {
            warn!(
                score,
                submission_id,
                "Rejecting review result with invalid score (must be finite and in 0.0..=1.0)"
            );
            return false;
        }
        if let Some(reviews) = self.review_assignments.get_mut(submission_id) {
            for review in reviews.iter_mut() {
                if review.assigned_validators.contains(validator) {
                    review.results.insert(
                        validator.clone(),
                        ReviewResultEntry {
                            score,
                            details,
                            timestamp: chrono::Utc::now().timestamp_millis(),
                        },
                    );
                    self.update_hash();
                    return true;
                }
            }
        }
        false
    }

    pub fn get_review_status(&self, submission_id: &str) -> Option<&Vec<ReviewRecord>> {
        self.review_assignments.get(submission_id)
    }

    /// Propose agent logs from a validator.
    ///
    /// Returns `false` and discards the data if:
    /// - `logs_data` exceeds `MAX_AGENT_LOG_SIZE` (256 KB)
    /// - the total number of proposal entries exceeds `MAX_AGENT_LOG_PROPOSALS`
    pub fn propose_agent_logs(
        &mut self,
        submission_id: &str,
        validator: Hotkey,
        logs_data: Vec<u8>,
    ) -> bool {
        if logs_data.len() > MAX_AGENT_LOG_SIZE {
            warn!(
                submission_id = %submission_id,
                size = logs_data.len(),
                max = MAX_AGENT_LOG_SIZE,
                "Rejecting agent log proposal: data exceeds maximum size"
            );
            return false;
        }

        if self.agent_log_proposals.len() >= MAX_AGENT_LOG_PROPOSALS
            && !self.agent_log_proposals.contains_key(submission_id)
        {
            warn!(
                submission_id = %submission_id,
                count = self.agent_log_proposals.len(),
                max = MAX_AGENT_LOG_PROPOSALS,
                "Rejecting agent log proposal: too many pending proposals"
            );
            return false;
        }

        self.agent_log_proposals
            .entry(submission_id.to_string())
            .or_default()
            .insert(validator, logs_data);
        self.update_hash();
        true
    }

    /// Finalize agent logs by consensus (>50% agreement by hash)
    pub fn finalize_agent_logs(&mut self, submission_id: &str) -> bool {
        let proposals = match self.agent_log_proposals.get(submission_id) {
            Some(p) if !p.is_empty() => p,
            _ => return false,
        };

        let total_proposals = proposals.len();

        let mut hash_counts: HashMap<[u8; 32], usize> = HashMap::new();
        let mut hash_to_data: HashMap<[u8; 32], &Vec<u8>> = HashMap::new();

        for logs_data in proposals.values() {
            let mut hasher = Sha256::new();
            hasher.update(logs_data);
            let hash: [u8; 32] = hasher.finalize().into();

            *hash_counts.entry(hash).or_default() += 1;
            hash_to_data.entry(hash).or_insert(logs_data);
        }

        let (best_hash, best_count) = hash_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(h, c)| (*h, *c))
            .unwrap_or(([0u8; 32], 0));

        if best_count > total_proposals / 2 {
            if let Some(data) = hash_to_data.get(&best_hash) {
                if self.validated_agent_logs.len() >= MAX_VALIDATED_AGENT_LOGS {
                    warn!(
                        count = self.validated_agent_logs.len(),
                        max = MAX_VALIDATED_AGENT_LOGS,
                        "Validated agent logs at capacity; pruning oldest entries"
                    );
                    let keys_to_remove: Vec<String> = self
                        .validated_agent_logs
                        .keys()
                        .take(self.validated_agent_logs.len() / 10)
                        .cloned()
                        .collect();
                    for key in keys_to_remove {
                        self.validated_agent_logs.remove(&key);
                    }
                }
                self.validated_agent_logs
                    .insert(submission_id.to_string(), (*data).clone());
            }
            self.agent_log_proposals.remove(submission_id);
            self.increment_sequence();
            true
        } else {
            false
        }
    }

    /// Register agent code entry
    pub fn register_agent_code(&mut self, miner: Hotkey, entry: AgentCodeEntry) {
        self.agent_code_registry.insert(miner, entry);
        self.increment_sequence();
    }

    /// Get agent code entry for a miner
    pub fn get_agent_code_entry(&self, miner: &Hotkey) -> Option<&AgentCodeEntry> {
        self.agent_code_registry.get(miner)
    }
}

/// Thread-safe state manager
pub struct StateManager {
    state: RwLock<ChainState>,
}

impl StateManager {
    /// Create new state manager
    pub fn new(initial_state: ChainState) -> Self {
        Self {
            state: RwLock::new(initial_state),
        }
    }

    /// Create with default state for netuid
    pub fn for_netuid(netuid: u16) -> Self {
        Self::new(ChainState::new(netuid))
    }

    /// Get current sequence number
    pub fn sequence(&self) -> SequenceNumber {
        self.state.read().sequence
    }

    /// Get current state hash
    pub fn state_hash(&self) -> [u8; 32] {
        self.state.read().state_hash
    }

    /// Get current epoch
    pub fn epoch(&self) -> u64 {
        self.state.read().epoch
    }

    /// Get a snapshot of the state
    pub fn snapshot(&self) -> ChainState {
        self.state.read().clone()
    }

    /// Apply a state update
    pub fn apply<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut ChainState) -> R,
    {
        let mut state = self.state.write();
        f(&mut state)
    }

    /// Read-only access to state
    pub fn read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&ChainState) -> R,
    {
        let state = self.state.read();
        f(&state)
    }

    /// Verify and apply state from sync
    pub fn apply_sync_state(&self, new_state: ChainState) -> Result<(), StateError> {
        let mut state = self.state.write();

        // Only accept state with higher sequence
        if new_state.sequence <= state.sequence {
            return Err(StateError::SequenceTooOld {
                current: state.sequence,
                received: new_state.sequence,
            });
        }

        // Verify hash matches
        let mut verification_state = new_state.clone();
        verification_state.update_hash();
        if verification_state.state_hash != new_state.state_hash {
            return Err(StateError::HashMismatch {
                expected: hex::encode(new_state.state_hash),
                actual: hex::encode(verification_state.state_hash),
            });
        }

        info!(
            old_seq = state.sequence,
            new_seq = new_state.sequence,
            "Applying synced state"
        );
        *state = new_state;
        Ok(())
    }
}

/// Compute merkle root from leaves
pub fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut level: Vec<[u8; 32]> = leaves.to_vec();

    while level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in level.chunks(2) {
            let combined = if chunk.len() == 2 {
                hash_pair(&chunk[0], &chunk[1])
            } else {
                hash_pair(&chunk[0], &chunk[0])
            };
            next_level.push(combined);
        }

        level = next_level;
    }

    level[0]
}

/// Hash two nodes together
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Verify a merkle proof
pub fn verify_merkle_proof(leaf: &[u8; 32], proof: &MerkleProof) -> bool {
    let mut current = *leaf;

    for node in &proof.path {
        current = if node.is_left {
            hash_pair(&node.sibling_hash, &current)
        } else {
            hash_pair(&current, &node.sibling_hash)
        };
    }

    current == proof.root
}

/// Build merkle proof for a leaf
pub fn build_merkle_proof(leaves: &[[u8; 32]], leaf_index: usize) -> Option<MerkleProof> {
    if leaf_index >= leaves.len() || leaves.is_empty() {
        return None;
    }

    let root = compute_merkle_root(leaves);
    let mut path = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut index = leaf_index;

    while level.len() > 1 {
        let sibling_index = if index.is_multiple_of(2) {
            if index + 1 < level.len() {
                index + 1
            } else {
                index
            }
        } else {
            index - 1
        };

        path.push(MerkleNode {
            sibling_hash: level[sibling_index],
            is_left: sibling_index < index,
        });

        // Build next level
        let mut next_level = Vec::new();
        for chunk in level.chunks(2) {
            let combined = if chunk.len() == 2 {
                hash_pair(&chunk[0], &chunk[1])
            } else {
                hash_pair(&chunk[0], &chunk[0])
            };
            next_level.push(combined);
        }

        level = next_level;
        index /= 2;
    }

    Some(MerkleProof { root, path })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_state_creation() {
        let state = ChainState::new(100);
        assert_eq!(state.netuid, 100);
        assert_eq!(state.sequence, 0);
        assert_eq!(state.sudo_key, Hotkey(platform_core::SUDO_KEY_BYTES));
    }

    #[test]
    fn test_state_hash_changes() {
        let mut state = ChainState::new(100);
        let hash1 = state.state_hash;

        state.increment_sequence();
        let hash2 = state.state_hash;

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_validator_updates() {
        let mut state = ChainState::new(100);
        let hotkey = Hotkey([1u8; 32]);

        state.update_validator(hotkey.clone(), 1_000_000);
        assert!(state.validators.contains_key(&hotkey));
        assert_eq!(state.validators.get(&hotkey), Some(&1_000_000));

        state.remove_validator(&hotkey);
        assert!(!state.validators.contains_key(&hotkey));
    }

    #[test]
    fn test_challenge_management() {
        let mut state = ChainState::new(100);
        let config = ChallengeConfig {
            id: ChallengeId::new(),
            name: "Test Challenge".to_string(),
            weight: 50,
            is_active: true,
            creator: Hotkey([0u8; 32]),
            created_at: chrono::Utc::now().timestamp_millis(),
        };

        let id = config.id;
        state.add_challenge(config);
        assert!(state.challenges.contains_key(&id));

        state.remove_challenge(&id);
        assert!(!state.challenges.contains_key(&id));
    }

    #[test]
    fn test_evaluation_flow() {
        use platform_core::Keypair;

        let mut state = ChainState::new(100);

        // Add evaluation record
        let record = EvaluationRecord {
            submission_id: "sub1".to_string(),
            challenge_id: ChallengeId::new(),
            miner: Hotkey([1u8; 32]),
            agent_hash: "abc123".to_string(),
            evaluations: HashMap::new(),
            aggregated_score: None,
            finalized: false,
            created_at: chrono::Utc::now().timestamp_millis(),
            finalized_at: None,
        };
        state.add_evaluation(record);

        // Create a keypair for the validator
        let validator_keypair = Keypair::generate();
        let validator = validator_keypair.hotkey();
        state.validators.insert(validator.clone(), 1000);

        // Create signing data for the evaluation
        #[derive(serde::Serialize)]
        struct EvaluationSigningData<'a> {
            submission_id: &'a str,
            score: f64,
        }
        let signing_data = EvaluationSigningData {
            submission_id: "sub1",
            score: 0.85,
        };
        let signing_bytes = bincode::serialize(&signing_data).unwrap();
        let signature = validator_keypair.sign_bytes(&signing_bytes).unwrap();

        let eval = ValidatorEvaluation {
            score: 0.85,
            stake: 1000,
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: signature.clone(),
        };
        state
            .add_validator_evaluation("sub1", validator, eval, &signature)
            .unwrap();

        // Finalize
        let score = state.finalize_evaluation("sub1").unwrap();
        assert!((score - 0.85).abs() < 0.01);
    }

    #[test]
    fn test_merkle_proof() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();

        let root = compute_merkle_root(&leaves);
        assert_ne!(root, [0u8; 32]);

        // Build and verify proof for each leaf
        for i in 0..leaves.len() {
            let proof = build_merkle_proof(&leaves, i).unwrap();
            assert!(verify_merkle_proof(&leaves[i], &proof));
        }
    }

    #[test]
    fn test_state_manager() {
        let manager = StateManager::for_netuid(100);

        assert_eq!(manager.sequence(), 0);

        manager.apply(|state| {
            state.update_validator(Hotkey([1u8; 32]), 1000);
        });

        assert_eq!(manager.sequence(), 1);
    }

    #[test]
    fn test_state_serialization() {
        let state = ChainState::new(100);
        let bytes = state.to_bytes().unwrap();
        let recovered = ChainState::from_bytes(&bytes).unwrap();

        assert_eq!(state.sequence, recovered.sequence);
        assert_eq!(state.netuid, recovered.netuid);
    }

    #[test]
    fn test_weight_voting() {
        use platform_core::Keypair;

        let mut state = ChainState::new(100);

        // Create keypairs for validators
        let validator1_keypair = Keypair::generate();
        let validator2_keypair = Keypair::generate();
        let validator1 = validator1_keypair.hotkey();
        let validator2 = validator2_keypair.hotkey();

        // Add validators with stakes
        state.validators.insert(validator1.clone(), 1000);
        state.validators.insert(validator2.clone(), 2000);

        // Create signing data structure for weight votes
        #[derive(serde::Serialize)]
        struct WeightVoteSigningData {
            epoch: u64,
            netuid: u16,
            weights: Vec<(u16, u16)>,
        }

        // Create and sign weight vote for validator1
        let weights1 = vec![(0, 100), (1, 200)];
        let signing_data1 = WeightVoteSigningData {
            epoch: 1,
            netuid: state.netuid,
            weights: weights1.clone(),
        };
        let signing_bytes1 = bincode::serialize(&signing_data1).unwrap();
        let signature1 = validator1_keypair.sign_bytes(&signing_bytes1).unwrap();

        // Create and sign weight vote for validator2
        let weights2 = vec![(0, 150), (1, 100)];
        let signing_data2 = WeightVoteSigningData {
            epoch: 1,
            netuid: state.netuid,
            weights: weights2.clone(),
        };
        let signing_bytes2 = bincode::serialize(&signing_data2).unwrap();
        let signature2 = validator2_keypair.sign_bytes(&signing_bytes2).unwrap();

        // Add weight votes with signature verification
        state
            .add_weight_vote_verified(validator1, weights1, 1, &signature1)
            .expect("Failed to add weight vote for validator1");
        state
            .add_weight_vote_verified(validator2, weights2, 1, &signature2)
            .expect("Failed to add weight vote for validator2");

        // Finalize
        let weights = state.finalize_weights().unwrap();
        assert!(!weights.is_empty());
        assert!(state.weight_votes.as_ref().unwrap().finalized);
    }

    #[test]
    fn test_epoch_transition() {
        let mut state = ChainState::new(100);
        assert_eq!(state.epoch, 0);

        state.next_epoch();
        assert_eq!(state.epoch, 1);
    }
}
