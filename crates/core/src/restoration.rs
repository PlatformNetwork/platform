//! State restoration system for crash/update recovery
//!
//! Handles restoring validator state from checkpoints, including:
//! - Automatic restoration on startup
//! - State validation and migration
//! - Partial recovery handling

use crate::checkpoint::{CheckpointData, CheckpointManager, PendingEvaluationState};
use crate::{ChallengeId, MiniChainError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Result of a restoration operation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RestorationResult {
    /// Whether restoration was successful
    pub success: bool,
    /// Sequence number restored from
    pub checkpoint_sequence: u64,
    /// Epoch restored to
    pub epoch: u64,
    /// Number of pending evaluations restored
    pub pending_evaluations_count: usize,
    /// Number of completed evaluations restored
    pub completed_evaluations_count: usize,
    /// Whether weight votes were restored
    pub weight_votes_restored: bool,
    /// Time taken for restoration
    pub duration_ms: u64,
    /// Any warnings during restoration
    pub warnings: Vec<String>,
    /// Error message if failed
    pub error: Option<String>,
}

impl RestorationResult {
    pub fn success(
        checkpoint_sequence: u64,
        epoch: u64,
        pending_count: usize,
        completed_count: usize,
        weight_votes: bool,
        duration_ms: u64,
    ) -> Self {
        Self {
            success: true,
            checkpoint_sequence,
            epoch,
            pending_evaluations_count: pending_count,
            completed_evaluations_count: completed_count,
            weight_votes_restored: weight_votes,
            duration_ms,
            warnings: Vec::new(),
            error: None,
        }
    }

    pub fn failure(error: String) -> Self {
        Self {
            success: false,
            checkpoint_sequence: 0,
            epoch: 0,
            pending_evaluations_count: 0,
            completed_evaluations_count: 0,
            weight_votes_restored: false,
            duration_ms: 0,
            warnings: Vec::new(),
            error: Some(error),
        }
    }

    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }
}

/// Options for restoration
#[derive(Clone, Debug)]
pub struct RestorationOptions {
    /// Maximum age of checkpoint to restore from (None = any age)
    pub max_age: Option<Duration>,
    /// Whether to validate restored state
    pub validate_state: bool,
    /// Whether to skip pending evaluations older than threshold
    pub skip_stale_evaluations: bool,
    /// Threshold for stale evaluations (in epochs)
    pub stale_evaluation_threshold: u64,
    /// Challenge IDs to restore (None = all)
    pub challenge_filter: Option<HashSet<ChallengeId>>,
}

impl Default for RestorationOptions {
    fn default() -> Self {
        Self {
            max_age: Some(Duration::from_secs(24 * 60 * 60)), // 24 hours
            validate_state: true,
            skip_stale_evaluations: true,
            stale_evaluation_threshold: 5, // Skip if > 5 epochs old
            challenge_filter: None,
        }
    }
}

impl RestorationOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_age(mut self, age: Duration) -> Self {
        self.max_age = Some(age);
        self
    }

    pub fn without_max_age(mut self) -> Self {
        self.max_age = None;
        self
    }

    pub fn with_validation(mut self, validate: bool) -> Self {
        self.validate_state = validate;
        self
    }

    pub fn with_challenge_filter(mut self, challenges: HashSet<ChallengeId>) -> Self {
        self.challenge_filter = Some(challenges);
        self
    }
}

/// State restoration manager
pub struct RestorationManager {
    checkpoint_manager: CheckpointManager,
    options: RestorationOptions,
}

impl RestorationManager {
    /// Create a new restoration manager
    pub fn new<P: AsRef<Path>>(checkpoint_dir: P, options: RestorationOptions) -> Result<Self> {
        let checkpoint_manager = CheckpointManager::new(checkpoint_dir, 10)?;
        Ok(Self {
            checkpoint_manager,
            options,
        })
    }

    /// Create with default options
    pub fn with_defaults<P: AsRef<Path>>(checkpoint_dir: P) -> Result<Self> {
        Self::new(checkpoint_dir, RestorationOptions::default())
    }

    /// Attempt to restore from the latest checkpoint
    pub fn restore_latest(&self) -> Result<Option<(RestorationResult, CheckpointData)>> {
        let start = Instant::now();

        // Load latest checkpoint
        let checkpoint = match self.checkpoint_manager.load_latest()? {
            Some(cp) => cp,
            None => {
                info!("No checkpoint found, starting fresh");
                return Ok(None);
            }
        };

        let (header, data) = checkpoint;

        // Check checkpoint age
        if let Some(max_age) = self.options.max_age {
            let checkpoint_age = Duration::from_millis(
                (chrono::Utc::now().timestamp_millis() - header.created_at).max(0) as u64,
            );
            if checkpoint_age > max_age {
                warn!(
                    sequence = header.sequence,
                    age_secs = checkpoint_age.as_secs(),
                    max_age_secs = max_age.as_secs(),
                    "Checkpoint too old, skipping restoration"
                );
                return Ok(None);
            }
        }

        // Filter and validate data
        let filtered_data = self.filter_and_validate(data)?;

        let duration_ms = start.elapsed().as_millis() as u64;

        let mut result = RestorationResult::success(
            header.sequence,
            filtered_data.epoch,
            filtered_data.pending_evaluations.len(),
            filtered_data.completed_evaluations.len(),
            filtered_data.weight_votes.is_some(),
            duration_ms,
        );

        info!(
            sequence = header.sequence,
            epoch = filtered_data.epoch,
            pending = filtered_data.pending_evaluations.len(),
            duration_ms,
            "State restored from checkpoint"
        );

        // Add warnings for filtered items
        if self.options.challenge_filter.is_some() {
            result.add_warning("Some evaluations filtered by challenge".into());
        }

        Ok(Some((result, filtered_data)))
    }

    /// Restore from a specific checkpoint sequence
    pub fn restore_from_sequence(
        &self,
        sequence: u64,
    ) -> Result<Option<(RestorationResult, CheckpointData)>> {
        let start = Instant::now();

        let checkpoint = match self.checkpoint_manager.load_checkpoint(sequence)? {
            Some(cp) => cp,
            None => {
                warn!(sequence, "Checkpoint not found");
                return Ok(None);
            }
        };

        let (header, data) = checkpoint;
        let filtered_data = self.filter_and_validate(data)?;
        let duration_ms = start.elapsed().as_millis() as u64;

        let result = RestorationResult::success(
            header.sequence,
            filtered_data.epoch,
            filtered_data.pending_evaluations.len(),
            filtered_data.completed_evaluations.len(),
            filtered_data.weight_votes.is_some(),
            duration_ms,
        );

        Ok(Some((result, filtered_data)))
    }

    /// Filter and validate checkpoint data
    fn filter_and_validate(&self, mut data: CheckpointData) -> Result<CheckpointData> {
        // Filter by challenge if specified
        if let Some(ref filter) = self.options.challenge_filter {
            data.pending_evaluations
                .retain(|e| filter.contains(&e.challenge_id));
            data.completed_evaluations
                .retain(|e| filter.contains(&e.challenge_id));
        }

        // Skip stale evaluations if enabled
        if self.options.skip_stale_evaluations {
            let _current_epoch = data.epoch;
            let _threshold = self.options.stale_evaluation_threshold;

            let original_count = data.pending_evaluations.len();
            data.pending_evaluations.retain(|_e| {
                // Keep if we can't determine staleness or if within threshold
                // For now, keep all pending (they don't have epoch info)
                true
            });

            let filtered_count = original_count - data.pending_evaluations.len();
            if filtered_count > 0 {
                debug!(
                    filtered = filtered_count,
                    "Skipped stale pending evaluations"
                );
            }
        }

        // Validate state if enabled
        if self.options.validate_state {
            self.validate_data(&data)?;
        }

        Ok(data)
    }

    /// Validate checkpoint data integrity
    fn validate_data(&self, data: &CheckpointData) -> Result<()> {
        // Validate epoch is reasonable
        if data.epoch > 1_000_000 {
            return Err(MiniChainError::Validation(
                "Checkpoint epoch seems unreasonably high".into(),
            ));
        }

        // Validate netuid
        if data.netuid == 0 {
            warn!("Checkpoint has netuid 0, may need reconfiguration");
        }

        // Validate pending evaluations
        for eval in &data.pending_evaluations {
            if eval.submission_id.is_empty() {
                return Err(MiniChainError::Validation(
                    "Found pending evaluation with empty submission_id".into(),
                ));
            }
        }

        // Validate weight votes epoch matches
        if let Some(ref votes) = data.weight_votes {
            if votes.epoch != data.epoch && !votes.finalized {
                warn!(
                    votes_epoch = votes.epoch,
                    data_epoch = data.epoch,
                    "Weight votes epoch mismatch (may be stale)"
                );
            }
        }

        Ok(())
    }

    /// Get list of available checkpoints for restoration
    pub fn list_available(&self) -> Result<Vec<CheckpointInfo>> {
        let checkpoints = self.checkpoint_manager.list_checkpoints()?;

        let mut infos = Vec::new();
        for (sequence, _path, _modified) in checkpoints {
            if let Some(info) = self.get_checkpoint_info(sequence)? {
                infos.push(info);
            }
        }

        Ok(infos)
    }

    /// Get information about a specific checkpoint without full loading
    fn get_checkpoint_info(&self, sequence: u64) -> Result<Option<CheckpointInfo>> {
        match self.checkpoint_manager.load_checkpoint(sequence)? {
            Some((header, data)) => Ok(Some(CheckpointInfo {
                sequence,
                created_at: header.created_at,
                epoch: data.epoch,
                netuid: data.netuid,
                pending_count: data.pending_evaluations.len(),
                completed_count: data.completed_evaluations.len(),
                has_weight_votes: data.weight_votes.is_some(),
                bittensor_block: data.bittensor_block,
            })),
            None => Ok(None),
        }
    }

    /// Get the checkpoint manager
    pub fn checkpoint_manager(&self) -> &CheckpointManager {
        &self.checkpoint_manager
    }
}

/// Information about a checkpoint (lightweight summary)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointInfo {
    pub sequence: u64,
    pub created_at: i64,
    pub epoch: u64,
    pub netuid: u16,
    pub pending_count: usize,
    pub completed_count: usize,
    pub has_weight_votes: bool,
    pub bittensor_block: u64,
}

/// Trait for types that can be restored from checkpoints
pub trait Restorable {
    /// Restore state from checkpoint data
    fn restore_from(&mut self, data: &CheckpointData) -> Result<()>;

    /// Create checkpoint data from current state
    fn create_checkpoint(&self) -> Result<CheckpointData>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hotkey;
    use std::collections::HashMap;
    use tempfile::tempdir;

    fn create_test_checkpoint_data() -> CheckpointData {
        let mut data = CheckpointData::new(1, 5, 100);
        data.pending_evaluations.push(PendingEvaluationState {
            submission_id: "sub1".to_string(),
            challenge_id: ChallengeId::new(),
            miner: Hotkey([1u8; 32]),
            submission_hash: "hash1".to_string(),
            scores: HashMap::new(),
            created_at: chrono::Utc::now().timestamp_millis(),
            finalizing: false,
        });
        data
    }

    #[test]
    fn test_restoration_result() {
        let result = RestorationResult::success(1, 5, 10, 20, true, 100);
        assert!(result.success);
        assert_eq!(result.checkpoint_sequence, 1);
        assert_eq!(result.epoch, 5);

        let failure = RestorationResult::failure("test error".to_string());
        assert!(!failure.success);
        assert!(failure.error.is_some());
    }

    #[test]
    fn test_restoration_options() {
        let opts = RestorationOptions::default();
        assert!(opts.max_age.is_some());
        assert!(opts.validate_state);

        let custom = RestorationOptions::new()
            .without_max_age()
            .with_validation(false);
        assert!(custom.max_age.is_none());
        assert!(!custom.validate_state);
    }

    #[test]
    fn test_restoration_roundtrip() {
        let dir = tempdir().unwrap();

        // Create checkpoint first
        let mut manager = CheckpointManager::new(dir.path(), 5).unwrap();
        let data = create_test_checkpoint_data();
        manager.create_checkpoint(&data).unwrap();

        // Now restore
        let restoration = RestorationManager::with_defaults(dir.path()).unwrap();
        let result = restoration.restore_latest().unwrap();

        assert!(result.is_some());
        let (res, restored_data) = result.unwrap();
        assert!(res.success);
        assert_eq!(restored_data.epoch, data.epoch);
        assert_eq!(restored_data.pending_evaluations.len(), 1);
    }

    #[test]
    fn test_restoration_no_checkpoint() {
        let dir = tempdir().unwrap();
        let restoration = RestorationManager::with_defaults(dir.path()).unwrap();
        let result = restoration.restore_latest().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_checkpoint_info() {
        let dir = tempdir().unwrap();

        let mut manager = CheckpointManager::new(dir.path(), 5).unwrap();
        let data = create_test_checkpoint_data();
        manager.create_checkpoint(&data).unwrap();

        let restoration = RestorationManager::with_defaults(dir.path()).unwrap();
        let infos = restoration.list_available().unwrap();

        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].epoch, 5);
        assert_eq!(infos[0].pending_count, 1);
    }

    #[test]
    fn test_restoration_with_challenge_filter() {
        let dir = tempdir().unwrap();

        let mut manager = CheckpointManager::new(dir.path(), 5).unwrap();
        let challenge1 = ChallengeId::new();
        let challenge2 = ChallengeId::new();

        let mut data = CheckpointData::new(1, 5, 100);
        data.pending_evaluations.push(PendingEvaluationState {
            submission_id: "sub1".to_string(),
            challenge_id: challenge1,
            miner: Hotkey([1u8; 32]),
            submission_hash: "hash1".to_string(),
            scores: HashMap::new(),
            created_at: chrono::Utc::now().timestamp_millis(),
            finalizing: false,
        });
        data.pending_evaluations.push(PendingEvaluationState {
            submission_id: "sub2".to_string(),
            challenge_id: challenge2,
            miner: Hotkey([2u8; 32]),
            submission_hash: "hash2".to_string(),
            scores: HashMap::new(),
            created_at: chrono::Utc::now().timestamp_millis(),
            finalizing: false,
        });
        manager.create_checkpoint(&data).unwrap();

        // Restore with filter for only challenge1
        let mut filter = HashSet::new();
        filter.insert(challenge1);
        let options = RestorationOptions::new().with_challenge_filter(filter);
        let restoration = RestorationManager::new(dir.path(), options).unwrap();
        let result = restoration.restore_latest().unwrap();

        assert!(result.is_some());
        let (_res, restored_data) = result.unwrap();
        assert_eq!(restored_data.pending_evaluations.len(), 1);
        assert_eq!(
            restored_data.pending_evaluations[0].challenge_id,
            challenge1
        );
    }

    #[test]
    fn test_restoration_add_warning() {
        let mut result = RestorationResult::success(1, 5, 10, 20, true, 100);
        assert!(result.warnings.is_empty());

        result.add_warning("Test warning".to_string());
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.warnings[0], "Test warning");
    }

    #[test]
    fn test_restore_from_sequence() {
        let dir = tempdir().unwrap();

        let mut manager = CheckpointManager::new(dir.path(), 5).unwrap();

        // Create multiple checkpoints
        let mut data = create_test_checkpoint_data();
        manager.create_checkpoint(&data).unwrap(); // seq 1

        data.epoch = 10;
        manager.create_checkpoint(&data).unwrap(); // seq 2

        let restoration = RestorationManager::with_defaults(dir.path()).unwrap();

        // Restore from sequence 1
        let result = restoration.restore_from_sequence(1).unwrap();
        assert!(result.is_some());
        let (_res, restored_data) = result.unwrap();
        assert_eq!(restored_data.epoch, 5);

        // Restore from sequence 2
        let result = restoration.restore_from_sequence(2).unwrap();
        assert!(result.is_some());
        let (_res, restored_data) = result.unwrap();
        assert_eq!(restored_data.epoch, 10);

        // Try non-existent sequence
        let result = restoration.restore_from_sequence(999).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_validation_unreasonable_epoch() {
        let dir = tempdir().unwrap();

        let mut manager = CheckpointManager::new(dir.path(), 5).unwrap();
        let mut data = create_test_checkpoint_data();
        data.epoch = 2_000_000; // Unreasonably high
        manager.create_checkpoint(&data).unwrap();

        let restoration = RestorationManager::with_defaults(dir.path()).unwrap();
        let result = restoration.restore_latest();
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_empty_submission_id() {
        let dir = tempdir().unwrap();

        let mut manager = CheckpointManager::new(dir.path(), 5).unwrap();
        let mut data = CheckpointData::new(1, 5, 100);
        data.pending_evaluations.push(PendingEvaluationState {
            submission_id: "".to_string(), // Empty - invalid
            challenge_id: ChallengeId::new(),
            miner: Hotkey([1u8; 32]),
            submission_hash: "hash1".to_string(),
            scores: HashMap::new(),
            created_at: chrono::Utc::now().timestamp_millis(),
            finalizing: false,
        });
        manager.create_checkpoint(&data).unwrap();

        let restoration = RestorationManager::with_defaults(dir.path()).unwrap();
        let result = restoration.restore_latest();
        assert!(result.is_err());
    }

    #[test]
    fn test_options_with_max_age() {
        let opts = RestorationOptions::new().with_max_age(Duration::from_secs(3600));
        assert_eq!(opts.max_age, Some(Duration::from_secs(3600)));
    }

    #[test]
    fn test_checkpoint_info_struct() {
        let info = CheckpointInfo {
            sequence: 1,
            created_at: 12345,
            epoch: 5,
            netuid: 1,
            pending_count: 10,
            completed_count: 20,
            has_weight_votes: true,
            bittensor_block: 100,
        };

        assert_eq!(info.sequence, 1);
        assert_eq!(info.epoch, 5);
        assert!(info.has_weight_votes);
    }
}
