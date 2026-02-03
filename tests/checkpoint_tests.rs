//! Integration tests for checkpoint and restoration system
//!
//! Tests for verifying the checkpoint/restoration system works correctly end-to-end.

use platform_core::{
    ChallengeId, CheckpointData, CheckpointManager, CompletedEvaluationState, Hotkey,
    PendingEvaluationState, RestorationManager, RestorationOptions, WeightVoteState,
};
use std::collections::HashMap;
use tempfile::tempdir;

// ============================================================================
// TEST HELPERS
// ============================================================================

/// Create test checkpoint data with realistic content
fn create_test_data() -> CheckpointData {
    let mut data = CheckpointData::new(100, 5, 100);

    // Add pending evaluations
    for i in 0..5 {
        data.pending_evaluations.push(PendingEvaluationState {
            submission_id: format!("submission_{}", i),
            challenge_id: ChallengeId::new(),
            miner: Hotkey([i as u8; 32]),
            submission_hash: format!("hash_{}", i),
            scores: {
                let mut scores = HashMap::new();
                scores.insert(Hotkey([1u8; 32]), 0.85);
                scores.insert(Hotkey([2u8; 32]), 0.90);
                scores
            },
            created_at: chrono::Utc::now().timestamp_millis(),
            finalizing: false,
        });
    }

    // Add completed evaluations
    for i in 0..3 {
        data.completed_evaluations.push(CompletedEvaluationState {
            submission_id: format!("completed_{}", i),
            challenge_id: ChallengeId::new(),
            final_score: 0.87 + (i as f64 * 0.01),
            epoch: 5,
            completed_at: chrono::Utc::now().timestamp_millis(),
        });
    }

    // Add weight votes
    data.weight_votes = Some(WeightVoteState {
        epoch: 5,
        netuid: 100,
        votes: {
            let mut votes = HashMap::new();
            votes.insert(Hotkey([1u8; 32]), vec![(0, 1000), (1, 2000)]);
            votes.insert(Hotkey([2u8; 32]), vec![(0, 1500), (1, 1500)]);
            votes
        },
        finalized: false,
        final_weights: None,
    });

    data.bittensor_block = 12345;
    data
}

// ============================================================================
// CHECKPOINT ROUNDTRIP TESTS
// ============================================================================

#[test]
fn test_checkpoint_roundtrip() {
    let dir = tempdir().expect("Failed to create temp dir");
    let mut manager = CheckpointManager::new(dir.path(), 10).expect("Failed to create manager");

    let original_data = create_test_data();

    // Create checkpoint
    let path = manager
        .create_checkpoint(&original_data)
        .expect("Failed to create checkpoint");
    assert!(path.exists());

    // Load checkpoint
    let (header, loaded_data) = manager
        .load_latest()
        .expect("Failed to load")
        .expect("No checkpoint found");

    // Verify data integrity
    assert_eq!(loaded_data.sequence, original_data.sequence);
    assert_eq!(loaded_data.epoch, original_data.epoch);
    assert_eq!(loaded_data.netuid, original_data.netuid);
    assert_eq!(
        loaded_data.pending_evaluations.len(),
        original_data.pending_evaluations.len()
    );
    assert_eq!(
        loaded_data.completed_evaluations.len(),
        original_data.completed_evaluations.len()
    );
    assert!(loaded_data.weight_votes.is_some());
    assert_eq!(loaded_data.bittensor_block, original_data.bittensor_block);

    // Verify header has correct sequence
    assert_eq!(header.sequence, 1);
}

// ============================================================================
// MULTIPLE CHECKPOINTS TESTS
// ============================================================================

#[test]
fn test_multiple_checkpoints() {
    let dir = tempdir().expect("Failed to create temp dir");
    let mut manager = CheckpointManager::new(dir.path(), 5).expect("Failed to create manager");

    // Create multiple checkpoints
    for i in 0..10 {
        let mut data = CheckpointData::new(i, i / 2, 100);
        data.pending_evaluations.push(PendingEvaluationState {
            submission_id: format!("sub_{}", i),
            challenge_id: ChallengeId::new(),
            miner: Hotkey([i as u8; 32]),
            submission_hash: format!("hash_{}", i),
            scores: HashMap::new(),
            created_at: chrono::Utc::now().timestamp_millis(),
            finalizing: false,
        });
        manager
            .create_checkpoint(&data)
            .expect("Failed to create checkpoint");
    }

    // Should only keep 5 checkpoints
    let checkpoints = manager.list_checkpoints().expect("Failed to list");
    assert_eq!(checkpoints.len(), 5);

    // Latest should be sequence 10
    let (header, latest) = manager
        .load_latest()
        .expect("Failed to load")
        .expect("No checkpoint");
    assert_eq!(latest.sequence, 9);
    assert_eq!(header.sequence, 10);
}

// ============================================================================
// RESTORATION TESTS
// ============================================================================

#[test]
fn test_restoration_with_options() {
    let dir = tempdir().expect("Failed to create temp dir");

    // Create checkpoint
    let mut manager = CheckpointManager::new(dir.path(), 5).expect("Failed to create manager");
    let data = create_test_data();
    manager
        .create_checkpoint(&data)
        .expect("Failed to create checkpoint");

    // Restore with options
    let options = RestorationOptions::new()
        .without_max_age()
        .with_validation(true);

    let restoration =
        RestorationManager::new(dir.path(), options).expect("Failed to create restoration manager");

    let result = restoration.restore_latest().expect("Failed to restore");
    assert!(result.is_some());

    let (res, restored_data) = result.unwrap();
    assert!(res.success);
    assert_eq!(restored_data.pending_evaluations.len(), 5);
    assert_eq!(restored_data.completed_evaluations.len(), 3);
}

#[test]
fn test_restoration_empty() {
    let dir = tempdir().expect("Failed to create temp dir");

    let restoration = RestorationManager::with_defaults(dir.path()).expect("Failed to create");
    let result = restoration.restore_latest().expect("Failed to restore");

    assert!(result.is_none());
}

// ============================================================================
// HASH VERIFICATION TESTS
// ============================================================================

#[test]
fn test_checkpoint_hash_verification() {
    let dir = tempdir().expect("Failed to create temp dir");
    let mut manager = CheckpointManager::new(dir.path(), 5).expect("Failed to create manager");

    let data = create_test_data();
    let path = manager.create_checkpoint(&data).expect("Failed to create");

    // Corrupt the file
    let mut content = std::fs::read(&path).expect("Failed to read");
    if content.len() > 100 {
        content[100] ^= 0xFF; // Flip bits
    }
    std::fs::write(&path, content).expect("Failed to write");

    // Loading should fail due to hash mismatch
    let result = manager.load_checkpoint(1);
    assert!(result.is_err());
}

// ============================================================================
// WEIGHT VOTES TESTS
// ============================================================================

#[test]
fn test_weight_votes_persistence() {
    let dir = tempdir().expect("Failed to create temp dir");
    let mut manager = CheckpointManager::new(dir.path(), 5).expect("Failed to create manager");

    let mut data = CheckpointData::new(1, 5, 100);
    data.weight_votes = Some(WeightVoteState {
        epoch: 5,
        netuid: 100,
        votes: {
            let mut v = HashMap::new();
            v.insert(Hotkey([1u8; 32]), vec![(0, 1000), (1, 2000), (2, 3000)]);
            v.insert(Hotkey([2u8; 32]), vec![(0, 1500), (1, 2500), (2, 2000)]);
            v.insert(Hotkey([3u8; 32]), vec![(0, 2000), (1, 2000), (2, 2000)]);
            v
        },
        finalized: true,
        final_weights: Some(vec![(0, 4500), (1, 6500), (2, 7000)]),
    });

    manager.create_checkpoint(&data).expect("Failed to create");

    let (_, loaded) = manager
        .load_latest()
        .expect("Failed to load")
        .expect("No checkpoint");

    let votes = loaded.weight_votes.expect("No weight votes");
    assert!(votes.finalized);
    assert_eq!(votes.votes.len(), 3);
    assert_eq!(votes.final_weights.as_ref().unwrap().len(), 3);
}

// ============================================================================
// CHECKPOINT INFO TESTS
// ============================================================================

#[test]
fn test_checkpoint_info() {
    let dir = tempdir().expect("Failed to create temp dir");

    let mut manager = CheckpointManager::new(dir.path(), 5).expect("Failed to create manager");
    let data = create_test_data();
    manager.create_checkpoint(&data).expect("Failed to create");

    let restoration = RestorationManager::with_defaults(dir.path()).expect("Failed to create");
    let infos = restoration.list_available().expect("Failed to list");

    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].epoch, 5);
    assert_eq!(infos[0].netuid, 100);
    assert_eq!(infos[0].pending_count, 5);
    assert_eq!(infos[0].completed_count, 3);
    assert!(infos[0].has_weight_votes);
    assert_eq!(infos[0].bittensor_block, 12345);
}

// ============================================================================
// SCORING PERSISTENCE TESTS
// ============================================================================

#[test]
fn test_pending_evaluation_scores_persistence() {
    let dir = tempdir().expect("Failed to create temp dir");
    let mut manager = CheckpointManager::new(dir.path(), 5).expect("Failed to create manager");

    let mut data = CheckpointData::new(1, 5, 100);
    let mut scores = HashMap::new();
    scores.insert(Hotkey([10u8; 32]), 0.95);
    scores.insert(Hotkey([20u8; 32]), 0.87);
    scores.insert(Hotkey([30u8; 32]), 0.92);

    data.pending_evaluations.push(PendingEvaluationState {
        submission_id: "scored_submission".to_string(),
        challenge_id: ChallengeId::new(),
        miner: Hotkey([5u8; 32]),
        submission_hash: "hash_scored".to_string(),
        scores,
        created_at: chrono::Utc::now().timestamp_millis(),
        finalizing: true,
    });

    manager.create_checkpoint(&data).expect("Failed to create");

    let (_, loaded) = manager
        .load_latest()
        .expect("Failed to load")
        .expect("No checkpoint");

    let pending = &loaded.pending_evaluations[0];
    assert_eq!(pending.scores.len(), 3);
    assert_eq!(pending.scores.get(&Hotkey([10u8; 32])), Some(&0.95));
    assert_eq!(pending.scores.get(&Hotkey([20u8; 32])), Some(&0.87));
    assert_eq!(pending.scores.get(&Hotkey([30u8; 32])), Some(&0.92));
    assert!(pending.finalizing);
}

// ============================================================================
// SEQUENCE MANAGEMENT TESTS
// ============================================================================

#[test]
fn test_checkpoint_sequence_resume() {
    let dir = tempdir().expect("Failed to create temp dir");

    // First manager creates checkpoints
    {
        let mut manager = CheckpointManager::new(dir.path(), 10).expect("Failed to create manager");
        for i in 0..5 {
            let data = CheckpointData::new(i, i, 100);
            manager.create_checkpoint(&data).expect("Failed to create");
        }
        assert_eq!(manager.current_sequence(), 5);
    }

    // New manager should resume from the latest sequence
    {
        let manager = CheckpointManager::new(dir.path(), 10).expect("Failed to create manager");
        assert_eq!(manager.current_sequence(), 5);
    }
}

#[test]
fn test_load_specific_checkpoint() {
    let dir = tempdir().expect("Failed to create temp dir");
    let mut manager = CheckpointManager::new(dir.path(), 10).expect("Failed to create manager");

    // Create 3 checkpoints with different epochs
    for i in 0..3 {
        let mut data = CheckpointData::new(i, i * 10, 100);
        data.metadata
            .insert("marker".to_string(), format!("checkpoint_{}", i));
        manager.create_checkpoint(&data).expect("Failed to create");
    }

    // Load specific checkpoint (sequence 2)
    let (header, data) = manager
        .load_checkpoint(2)
        .expect("Failed to load")
        .expect("Not found");
    assert_eq!(header.sequence, 2);
    assert_eq!(data.epoch, 10);
    assert_eq!(
        data.metadata.get("marker"),
        Some(&"checkpoint_1".to_string())
    );
}

// ============================================================================
// METADATA TESTS
// ============================================================================

#[test]
fn test_checkpoint_metadata_persistence() {
    let dir = tempdir().expect("Failed to create temp dir");
    let mut manager = CheckpointManager::new(dir.path(), 5).expect("Failed to create manager");

    let mut data = CheckpointData::new(1, 5, 100);
    data.metadata
        .insert("version".to_string(), "1.0.0".to_string());
    data.metadata
        .insert("node_id".to_string(), "validator_1".to_string());
    data.metadata
        .insert("custom_key".to_string(), "custom_value".to_string());

    manager.create_checkpoint(&data).expect("Failed to create");

    let (_, loaded) = manager
        .load_latest()
        .expect("Failed to load")
        .expect("No checkpoint");

    assert_eq!(loaded.metadata.len(), 3);
    assert_eq!(loaded.metadata.get("version"), Some(&"1.0.0".to_string()));
    assert_eq!(
        loaded.metadata.get("node_id"),
        Some(&"validator_1".to_string())
    );
    assert_eq!(
        loaded.metadata.get("custom_key"),
        Some(&"custom_value".to_string())
    );
}

// ============================================================================
// COMPLETED EVALUATION TESTS
// ============================================================================

#[test]
fn test_completed_evaluations_persistence() {
    let dir = tempdir().expect("Failed to create temp dir");
    let mut manager = CheckpointManager::new(dir.path(), 5).expect("Failed to create manager");

    let challenge_id = ChallengeId::new();
    let mut data = CheckpointData::new(1, 5, 100);

    for i in 0..5 {
        data.completed_evaluations.push(CompletedEvaluationState {
            submission_id: format!("completed_{}", i),
            challenge_id,
            final_score: 0.80 + (i as f64 * 0.04),
            epoch: 5,
            completed_at: chrono::Utc::now().timestamp_millis(),
        });
    }

    manager.create_checkpoint(&data).expect("Failed to create");

    let (_, loaded) = manager
        .load_latest()
        .expect("Failed to load")
        .expect("No checkpoint");

    assert_eq!(loaded.completed_evaluations.len(), 5);

    // Verify score ordering is preserved
    for (i, eval) in loaded.completed_evaluations.iter().enumerate() {
        let expected_score = 0.80 + (i as f64 * 0.04);
        assert!((eval.final_score - expected_score).abs() < 0.001);
        assert_eq!(eval.challenge_id, challenge_id);
    }
}

// ============================================================================
// EMPTY STATE TESTS
// ============================================================================

#[test]
fn test_checkpoint_with_empty_state() {
    let dir = tempdir().expect("Failed to create temp dir");
    let mut manager = CheckpointManager::new(dir.path(), 5).expect("Failed to create manager");

    // Empty checkpoint data
    let data = CheckpointData::new(0, 0, 100);

    manager.create_checkpoint(&data).expect("Failed to create");

    let (_, loaded) = manager
        .load_latest()
        .expect("Failed to load")
        .expect("No checkpoint");

    assert_eq!(loaded.sequence, 0);
    assert_eq!(loaded.epoch, 0);
    assert!(loaded.pending_evaluations.is_empty());
    assert!(loaded.completed_evaluations.is_empty());
    assert!(loaded.weight_votes.is_none());
    assert!(loaded.metadata.is_empty());
}

// ============================================================================
// RESTORATION VALIDATION TESTS
// ============================================================================

#[test]
fn test_restoration_validates_epoch() {
    let dir = tempdir().expect("Failed to create temp dir");

    let mut manager = CheckpointManager::new(dir.path(), 5).expect("Failed to create manager");
    let mut data = CheckpointData::new(1, 2_000_000, 100); // Unreasonably high epoch
    data.pending_evaluations.push(PendingEvaluationState {
        submission_id: "test".to_string(),
        challenge_id: ChallengeId::new(),
        miner: Hotkey([1u8; 32]),
        submission_hash: "hash".to_string(),
        scores: HashMap::new(),
        created_at: chrono::Utc::now().timestamp_millis(),
        finalizing: false,
    });
    manager.create_checkpoint(&data).expect("Failed to create");

    // With validation enabled, this should fail
    let options = RestorationOptions::new()
        .without_max_age()
        .with_validation(true);

    let restoration = RestorationManager::new(dir.path(), options).expect("Failed to create");
    let result = restoration.restore_latest();
    assert!(result.is_err());
}

#[test]
fn test_restoration_validates_submission_id() {
    let dir = tempdir().expect("Failed to create temp dir");

    let mut manager = CheckpointManager::new(dir.path(), 5).expect("Failed to create manager");
    let mut data = CheckpointData::new(1, 5, 100);
    data.pending_evaluations.push(PendingEvaluationState {
        submission_id: "".to_string(), // Empty submission_id is invalid
        challenge_id: ChallengeId::new(),
        miner: Hotkey([1u8; 32]),
        submission_hash: "hash".to_string(),
        scores: HashMap::new(),
        created_at: chrono::Utc::now().timestamp_millis(),
        finalizing: false,
    });
    manager.create_checkpoint(&data).expect("Failed to create");

    // With validation enabled, this should fail
    let options = RestorationOptions::new()
        .without_max_age()
        .with_validation(true);

    let restoration = RestorationManager::new(dir.path(), options).expect("Failed to create");
    let result = restoration.restore_latest();
    assert!(result.is_err());
}
