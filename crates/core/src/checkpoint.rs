//! Checkpoint system for state persistence
//!
//! Provides mechanisms to save and restore evaluation state, enabling:
//! - Hot-reload without losing progress
//! - Crash recovery
//! - Rolling updates

use crate::{ChallengeId, Hotkey, MiniChainError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Checkpoint version for format compatibility
pub const CHECKPOINT_VERSION: u32 = 1;

/// Magic bytes for checkpoint file identification
const CHECKPOINT_MAGIC: &[u8; 8] = b"PLATCHKP";

/// Checkpoint file header
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointHeader {
    /// Magic bytes (verified on load)
    pub magic: [u8; 8],
    /// Checkpoint format version
    pub version: u32,
    /// Creation timestamp (Unix millis)
    pub created_at: i64,
    /// Checkpoint sequence number
    pub sequence: u64,
    /// SHA-256 hash of the data section
    pub data_hash: [u8; 32],
    /// Size of the data section in bytes
    pub data_size: u64,
}

impl CheckpointHeader {
    pub fn new(sequence: u64, data_hash: [u8; 32], data_size: u64) -> Self {
        Self {
            magic: *CHECKPOINT_MAGIC,
            version: CHECKPOINT_VERSION,
            created_at: chrono::Utc::now().timestamp_millis(),
            sequence,
            data_hash,
            data_size,
        }
    }

    pub fn verify_magic(&self) -> bool {
        self.magic == *CHECKPOINT_MAGIC
    }
}

/// State of a pending evaluation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingEvaluationState {
    /// Submission ID
    pub submission_id: String,
    /// Challenge ID
    pub challenge_id: ChallengeId,
    /// Miner hotkey
    pub miner: Hotkey,
    /// Submission hash
    pub submission_hash: String,
    /// Evaluation scores received (validator -> score)
    pub scores: HashMap<Hotkey, f64>,
    /// Creation timestamp
    pub created_at: i64,
    /// Whether finalization is in progress
    pub finalizing: bool,
}

/// Completed evaluation record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompletedEvaluationState {
    /// Submission ID
    pub submission_id: String,
    /// Challenge ID
    pub challenge_id: ChallengeId,
    /// Final aggregated score
    pub final_score: f64,
    /// Epoch when completed
    pub epoch: u64,
    /// Completion timestamp
    pub completed_at: i64,
}

/// Weight vote state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightVoteState {
    /// Epoch for these weights
    pub epoch: u64,
    /// Netuid
    pub netuid: u16,
    /// Votes by validator
    pub votes: HashMap<Hotkey, Vec<(u16, u16)>>,
    /// Whether finalized
    pub finalized: bool,
    /// Final weights if finalized
    pub final_weights: Option<Vec<(u16, u16)>>,
}

/// Full checkpoint data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointData {
    /// Current sequence number
    pub sequence: u64,
    /// Current epoch
    pub epoch: u64,
    /// Netuid
    pub netuid: u16,
    /// Pending evaluations
    pub pending_evaluations: Vec<PendingEvaluationState>,
    /// Recent completed evaluations (last N epochs)
    pub completed_evaluations: Vec<CompletedEvaluationState>,
    /// Current weight votes
    pub weight_votes: Option<WeightVoteState>,
    /// Bittensor block number at checkpoint
    pub bittensor_block: u64,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl CheckpointData {
    pub fn new(sequence: u64, epoch: u64, netuid: u16) -> Self {
        Self {
            sequence,
            epoch,
            netuid,
            pending_evaluations: Vec::new(),
            completed_evaluations: Vec::new(),
            weight_votes: None,
            bittensor_block: 0,
            metadata: HashMap::new(),
        }
    }

    /// Add pending evaluation
    pub fn add_pending(&mut self, state: PendingEvaluationState) {
        self.pending_evaluations.push(state);
    }

    /// Add completed evaluation
    pub fn add_completed(&mut self, state: CompletedEvaluationState) {
        self.completed_evaluations.push(state);
    }

    /// Calculate hash of checkpoint data
    pub fn calculate_hash(&self) -> Result<[u8; 32]> {
        let bytes =
            bincode::serialize(self).map_err(|e| MiniChainError::Serialization(e.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(hasher.finalize().into())
    }
}

/// Checkpoint manager for persisting and restoring state
pub struct CheckpointManager {
    /// Directory for checkpoint files
    checkpoint_dir: PathBuf,
    /// Maximum number of checkpoints to keep
    max_checkpoints: usize,
    /// Current checkpoint sequence
    current_sequence: u64,
}

impl CheckpointManager {
    /// Create a new checkpoint manager
    pub fn new<P: AsRef<Path>>(checkpoint_dir: P, max_checkpoints: usize) -> Result<Self> {
        let checkpoint_dir = checkpoint_dir.as_ref().to_path_buf();

        // Create checkpoint directory if it doesn't exist
        fs::create_dir_all(&checkpoint_dir).map_err(|e| {
            MiniChainError::Storage(format!("Failed to create checkpoint dir: {}", e))
        })?;

        // Find the latest checkpoint sequence
        let current_sequence = Self::find_latest_sequence(&checkpoint_dir)?;

        info!(
            dir = %checkpoint_dir.display(),
            max_checkpoints,
            current_sequence,
            "Checkpoint manager initialized"
        );

        Ok(Self {
            checkpoint_dir,
            max_checkpoints,
            current_sequence,
        })
    }

    /// Find the latest checkpoint sequence number
    fn find_latest_sequence(dir: &Path) -> Result<u64> {
        let mut max_seq = 0u64;

        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("checkpoint_") && name.ends_with(".bin") {
                        if let Some(seq_str) = name
                            .strip_prefix("checkpoint_")
                            .and_then(|s| s.strip_suffix(".bin"))
                        {
                            if let Ok(seq) = seq_str.parse::<u64>() {
                                max_seq = max_seq.max(seq);
                            }
                        }
                    }
                }
            }
        }

        Ok(max_seq)
    }

    /// Generate checkpoint filename
    fn checkpoint_filename(&self, sequence: u64) -> PathBuf {
        self.checkpoint_dir
            .join(format!("checkpoint_{:016}.bin", sequence))
    }

    /// Create a new checkpoint
    pub fn create_checkpoint(&mut self, data: &CheckpointData) -> Result<PathBuf> {
        self.current_sequence += 1;
        let sequence = self.current_sequence;
        let filename = self.checkpoint_filename(sequence);

        // Serialize data
        let data_bytes =
            bincode::serialize(data).map_err(|e| MiniChainError::Serialization(e.to_string()))?;

        // Calculate hash
        let mut hasher = Sha256::new();
        hasher.update(&data_bytes);
        let data_hash: [u8; 32] = hasher.finalize().into();

        // Create header
        let header = CheckpointHeader::new(sequence, data_hash, data_bytes.len() as u64);
        let header_bytes = bincode::serialize(&header)
            .map_err(|e| MiniChainError::Serialization(e.to_string()))?;

        // Write to file atomically (write to temp, then rename)
        let temp_filename = filename.with_extension("tmp");
        {
            let file = File::create(&temp_filename).map_err(|e| {
                MiniChainError::Storage(format!("Failed to create checkpoint: {}", e))
            })?;
            let mut writer = BufWriter::new(file);

            // Write header length (4 bytes)
            let header_len = header_bytes.len() as u32;
            writer
                .write_all(&header_len.to_le_bytes())
                .map_err(|e| MiniChainError::Storage(e.to_string()))?;

            // Write header
            writer
                .write_all(&header_bytes)
                .map_err(|e| MiniChainError::Storage(e.to_string()))?;

            // Write data
            writer
                .write_all(&data_bytes)
                .map_err(|e| MiniChainError::Storage(e.to_string()))?;

            writer
                .flush()
                .map_err(|e| MiniChainError::Storage(e.to_string()))?;
        }

        // Atomic rename
        fs::rename(&temp_filename, &filename).map_err(|e| {
            MiniChainError::Storage(format!("Failed to finalize checkpoint: {}", e))
        })?;

        info!(
            sequence,
            path = %filename.display(),
            size = data_bytes.len(),
            "Checkpoint created"
        );

        // Cleanup old checkpoints
        self.cleanup_old_checkpoints()?;

        Ok(filename)
    }

    /// Load the latest checkpoint
    pub fn load_latest(&self) -> Result<Option<(CheckpointHeader, CheckpointData)>> {
        if self.current_sequence == 0 {
            return Ok(None);
        }

        self.load_checkpoint(self.current_sequence)
    }

    /// Load a specific checkpoint
    pub fn load_checkpoint(
        &self,
        sequence: u64,
    ) -> Result<Option<(CheckpointHeader, CheckpointData)>> {
        let filename = self.checkpoint_filename(sequence);

        if !filename.exists() {
            return Ok(None);
        }

        let file = File::open(&filename)
            .map_err(|e| MiniChainError::Storage(format!("Failed to open checkpoint: {}", e)))?;
        let mut reader = BufReader::new(file);

        // Read header length
        let mut header_len_bytes = [0u8; 4];
        reader
            .read_exact(&mut header_len_bytes)
            .map_err(|e| MiniChainError::Storage(format!("Failed to read header length: {}", e)))?;
        let header_len = u32::from_le_bytes(header_len_bytes) as usize;

        // Read header
        let mut header_bytes = vec![0u8; header_len];
        reader
            .read_exact(&mut header_bytes)
            .map_err(|e| MiniChainError::Storage(format!("Failed to read header: {}", e)))?;

        let header: CheckpointHeader = bincode::deserialize(&header_bytes).map_err(|e| {
            MiniChainError::Serialization(format!("Failed to deserialize header: {}", e))
        })?;

        // Verify magic
        if !header.verify_magic() {
            return Err(MiniChainError::Storage(
                "Invalid checkpoint magic bytes".into(),
            ));
        }

        // Verify version compatibility
        if header.version > CHECKPOINT_VERSION {
            return Err(MiniChainError::Storage(format!(
                "Checkpoint version {} is newer than supported version {}",
                header.version, CHECKPOINT_VERSION
            )));
        }

        // Read data
        let mut data_bytes = vec![0u8; header.data_size as usize];
        reader
            .read_exact(&mut data_bytes)
            .map_err(|e| MiniChainError::Storage(format!("Failed to read data: {}", e)))?;

        // Verify hash
        let mut hasher = Sha256::new();
        hasher.update(&data_bytes);
        let actual_hash: [u8; 32] = hasher.finalize().into();

        if actual_hash != header.data_hash {
            return Err(MiniChainError::Storage(
                "Checkpoint data hash mismatch".into(),
            ));
        }

        // Deserialize data
        let data: CheckpointData = bincode::deserialize(&data_bytes).map_err(|e| {
            MiniChainError::Serialization(format!("Failed to deserialize data: {}", e))
        })?;

        info!(
            sequence,
            epoch = data.epoch,
            pending_count = data.pending_evaluations.len(),
            "Checkpoint loaded"
        );

        Ok(Some((header, data)))
    }

    /// List all available checkpoints
    pub fn list_checkpoints(&self) -> Result<Vec<(u64, PathBuf, SystemTime)>> {
        let mut checkpoints = Vec::new();

        if let Ok(entries) = fs::read_dir(&self.checkpoint_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("checkpoint_") && name.ends_with(".bin") {
                        if let Some(seq_str) = name
                            .strip_prefix("checkpoint_")
                            .and_then(|s| s.strip_suffix(".bin"))
                        {
                            if let Ok(seq) = seq_str.parse::<u64>() {
                                if let Ok(meta) = entry.metadata() {
                                    if let Ok(modified) = meta.modified() {
                                        checkpoints.push((seq, path, modified));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        checkpoints.sort_by_key(|(seq, _, _)| *seq);
        Ok(checkpoints)
    }

    /// Clean up old checkpoints
    fn cleanup_old_checkpoints(&self) -> Result<()> {
        let checkpoints = self.list_checkpoints()?;

        if checkpoints.len() <= self.max_checkpoints {
            return Ok(());
        }

        let to_remove = checkpoints.len() - self.max_checkpoints;
        for (seq, path, _) in checkpoints.into_iter().take(to_remove) {
            debug!(sequence = seq, path = %path.display(), "Removing old checkpoint");
            if let Err(e) = fs::remove_file(&path) {
                warn!(path = %path.display(), error = %e, "Failed to remove old checkpoint");
            }
        }

        Ok(())
    }

    /// Get checkpoint directory
    pub fn checkpoint_dir(&self) -> &Path {
        &self.checkpoint_dir
    }

    /// Get current sequence
    pub fn current_sequence(&self) -> u64 {
        self.current_sequence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_checkpoint_header() {
        let header = CheckpointHeader::new(1, [0u8; 32], 100);
        assert!(header.verify_magic());
        assert_eq!(header.version, CHECKPOINT_VERSION);
    }

    #[test]
    fn test_checkpoint_header_invalid_magic() {
        let mut header = CheckpointHeader::new(1, [0u8; 32], 100);
        header.magic = *b"INVALID!";
        assert!(!header.verify_magic());
    }

    #[test]
    fn test_checkpoint_data_hash() {
        let data = CheckpointData::new(1, 0, 100);
        let hash1 = data.calculate_hash().unwrap();

        let mut data2 = data.clone();
        data2.sequence = 2;
        let hash2 = data2.calculate_hash().unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_checkpoint_data_new() {
        let data = CheckpointData::new(5, 10, 200);
        assert_eq!(data.sequence, 5);
        assert_eq!(data.epoch, 10);
        assert_eq!(data.netuid, 200);
        assert!(data.pending_evaluations.is_empty());
        assert!(data.completed_evaluations.is_empty());
        assert!(data.weight_votes.is_none());
        assert_eq!(data.bittensor_block, 0);
        assert!(data.metadata.is_empty());
    }

    #[test]
    fn test_checkpoint_data_add_pending() {
        let mut data = CheckpointData::new(1, 0, 100);
        let pending = PendingEvaluationState {
            submission_id: "sub1".to_string(),
            challenge_id: ChallengeId::new(),
            miner: Hotkey([1u8; 32]),
            submission_hash: "abc123".to_string(),
            scores: HashMap::new(),
            created_at: chrono::Utc::now().timestamp_millis(),
            finalizing: false,
        };
        data.add_pending(pending);
        assert_eq!(data.pending_evaluations.len(), 1);
    }

    #[test]
    fn test_checkpoint_data_add_completed() {
        let mut data = CheckpointData::new(1, 0, 100);
        let completed = CompletedEvaluationState {
            submission_id: "sub1".to_string(),
            challenge_id: ChallengeId::new(),
            final_score: 0.85,
            epoch: 5,
            completed_at: chrono::Utc::now().timestamp_millis(),
        };
        data.add_completed(completed);
        assert_eq!(data.completed_evaluations.len(), 1);
    }

    #[test]
    fn test_checkpoint_manager_roundtrip() {
        let dir = tempdir().unwrap();
        let mut manager = CheckpointManager::new(dir.path(), 5).unwrap();

        let mut data = CheckpointData::new(1, 0, 100);
        data.pending_evaluations.push(PendingEvaluationState {
            submission_id: "sub1".to_string(),
            challenge_id: ChallengeId::new(),
            miner: Hotkey([1u8; 32]),
            submission_hash: "abc123".to_string(),
            scores: HashMap::new(),
            created_at: chrono::Utc::now().timestamp_millis(),
            finalizing: false,
        });

        let path = manager.create_checkpoint(&data).unwrap();
        assert!(path.exists());

        let (header, loaded) = manager.load_latest().unwrap().unwrap();
        assert_eq!(header.sequence, 1);
        assert_eq!(loaded.sequence, data.sequence);
        assert_eq!(loaded.pending_evaluations.len(), 1);
    }

    #[test]
    fn test_checkpoint_manager_no_checkpoints() {
        let dir = tempdir().unwrap();
        let manager = CheckpointManager::new(dir.path(), 5).unwrap();
        assert!(manager.load_latest().unwrap().is_none());
        assert_eq!(manager.current_sequence(), 0);
    }

    #[test]
    fn test_checkpoint_cleanup() {
        let dir = tempdir().unwrap();
        let mut manager = CheckpointManager::new(dir.path(), 3).unwrap();

        for i in 0..5 {
            let data = CheckpointData::new(i, 0, 100);
            manager.create_checkpoint(&data).unwrap();
        }

        let checkpoints = manager.list_checkpoints().unwrap();
        assert_eq!(checkpoints.len(), 3);
    }

    #[test]
    fn test_checkpoint_list() {
        let dir = tempdir().unwrap();
        let mut manager = CheckpointManager::new(dir.path(), 10).unwrap();

        for i in 0..3 {
            let data = CheckpointData::new(i, i, 100);
            manager.create_checkpoint(&data).unwrap();
        }

        let checkpoints = manager.list_checkpoints().unwrap();
        assert_eq!(checkpoints.len(), 3);

        // Verify sorted by sequence
        assert_eq!(checkpoints[0].0, 1);
        assert_eq!(checkpoints[1].0, 2);
        assert_eq!(checkpoints[2].0, 3);
    }

    #[test]
    fn test_checkpoint_load_specific() {
        let dir = tempdir().unwrap();
        let mut manager = CheckpointManager::new(dir.path(), 10).unwrap();

        for i in 0..3 {
            let mut data = CheckpointData::new(i, i * 10, 100);
            data.metadata
                .insert("test_key".to_string(), format!("value_{}", i));
            manager.create_checkpoint(&data).unwrap();
        }

        // Load specific checkpoint
        let (header, data) = manager.load_checkpoint(2).unwrap().unwrap();
        assert_eq!(header.sequence, 2);
        assert_eq!(data.epoch, 10);
        assert_eq!(data.metadata.get("test_key"), Some(&"value_1".to_string()));
    }

    #[test]
    fn test_checkpoint_load_nonexistent() {
        let dir = tempdir().unwrap();
        let manager = CheckpointManager::new(dir.path(), 5).unwrap();
        assert!(manager.load_checkpoint(999).unwrap().is_none());
    }

    #[test]
    fn test_checkpoint_resume_sequence() {
        let dir = tempdir().unwrap();

        // First manager creates some checkpoints
        {
            let mut manager = CheckpointManager::new(dir.path(), 10).unwrap();
            for i in 0..3 {
                let data = CheckpointData::new(i, i, 100);
                manager.create_checkpoint(&data).unwrap();
            }
            assert_eq!(manager.current_sequence(), 3);
        }

        // New manager should resume from the latest sequence
        {
            let manager = CheckpointManager::new(dir.path(), 10).unwrap();
            assert_eq!(manager.current_sequence(), 3);
        }
    }

    #[test]
    fn test_checkpoint_with_scores() {
        let dir = tempdir().unwrap();
        let mut manager = CheckpointManager::new(dir.path(), 5).unwrap();

        let mut scores = HashMap::new();
        scores.insert(Hotkey([1u8; 32]), 0.95);
        scores.insert(Hotkey([2u8; 32]), 0.87);

        let mut data = CheckpointData::new(1, 5, 100);
        data.pending_evaluations.push(PendingEvaluationState {
            submission_id: "sub_with_scores".to_string(),
            challenge_id: ChallengeId::new(),
            miner: Hotkey([3u8; 32]),
            submission_hash: "hash123".to_string(),
            scores,
            created_at: chrono::Utc::now().timestamp_millis(),
            finalizing: true,
        });

        manager.create_checkpoint(&data).unwrap();

        let (_, loaded) = manager.load_latest().unwrap().unwrap();
        let pending = &loaded.pending_evaluations[0];
        assert_eq!(pending.scores.len(), 2);
        assert_eq!(pending.scores.get(&Hotkey([1u8; 32])), Some(&0.95));
        assert!(pending.finalizing);
    }

    #[test]
    fn test_checkpoint_with_weight_votes() {
        let dir = tempdir().unwrap();
        let mut manager = CheckpointManager::new(dir.path(), 5).unwrap();

        let mut votes = HashMap::new();
        votes.insert(Hotkey([1u8; 32]), vec![(0, 100), (1, 200)]);
        votes.insert(Hotkey([2u8; 32]), vec![(0, 150), (1, 150)]);

        let mut data = CheckpointData::new(1, 5, 100);
        data.weight_votes = Some(WeightVoteState {
            epoch: 5,
            netuid: 100,
            votes,
            finalized: true,
            final_weights: Some(vec![(0, 125), (1, 175)]),
        });

        manager.create_checkpoint(&data).unwrap();

        let (_, loaded) = manager.load_latest().unwrap().unwrap();
        let weight_votes = loaded.weight_votes.unwrap();
        assert_eq!(weight_votes.epoch, 5);
        assert!(weight_votes.finalized);
        assert_eq!(weight_votes.final_weights, Some(vec![(0, 125), (1, 175)]));
    }

    #[test]
    fn test_checkpoint_dir_accessor() {
        let dir = tempdir().unwrap();
        let manager = CheckpointManager::new(dir.path(), 5).unwrap();
        assert_eq!(manager.checkpoint_dir(), dir.path());
    }

    #[test]
    fn test_pending_evaluation_state_clone() {
        let state = PendingEvaluationState {
            submission_id: "test".to_string(),
            challenge_id: ChallengeId::new(),
            miner: Hotkey([5u8; 32]),
            submission_hash: "hash".to_string(),
            scores: HashMap::new(),
            created_at: 12345,
            finalizing: false,
        };
        let cloned = state.clone();
        assert_eq!(cloned.submission_id, state.submission_id);
        assert_eq!(cloned.miner, state.miner);
    }

    #[test]
    fn test_completed_evaluation_state_clone() {
        let state = CompletedEvaluationState {
            submission_id: "test".to_string(),
            challenge_id: ChallengeId::new(),
            final_score: 0.75,
            epoch: 10,
            completed_at: 67890,
        };
        let cloned = state.clone();
        assert_eq!(cloned.final_score, state.final_score);
        assert_eq!(cloned.epoch, state.epoch);
    }

    #[test]
    fn test_weight_vote_state_clone() {
        let state = WeightVoteState {
            epoch: 5,
            netuid: 100,
            votes: HashMap::new(),
            finalized: false,
            final_weights: None,
        };
        let cloned = state.clone();
        assert_eq!(cloned.epoch, state.epoch);
        assert_eq!(cloned.finalized, state.finalized);
    }
}
