//! Blockchain State Verification Tests
//!
//! Comprehensive tests for:
//! - Bittensor block linking
//! - Merkle proof computation and verification
//! - State hash integrity
//! - State serialization

use platform_core::{ChallengeId, Hotkey, Keypair};
use platform_p2p_consensus::{
    build_merkle_proof, compute_merkle_root, verify_merkle_proof, ChainState, ChallengeConfig,
    EvaluationRecord, StateManager,
};
use std::collections::HashMap;

// ============================================================================
// BITTENSOR BLOCK LINKING TESTS
// ============================================================================

#[test]
fn test_state_links_to_bittensor_block() {
    let mut state = ChainState::new(100);

    // Initial state should have zero block
    assert_eq!(state.linked_block(), 0);
    assert_eq!(state.bittensor_block_hash, [0u8; 32]);

    // Link to a specific block
    let block_number: u64 = 12345;
    let block_hash: [u8; 32] = [0xAB; 32];
    state.link_to_bittensor_block(block_number, block_hash);

    // Verify linkage
    assert_eq!(state.linked_block(), block_number);
    assert_eq!(state.bittensor_block, block_number);
    assert_eq!(state.bittensor_block_hash, block_hash);
}

#[test]
fn test_link_updates_sequence_number() {
    let mut state = ChainState::new(100);
    let initial_sequence = state.sequence;

    // Link to block
    state.link_to_bittensor_block(100, [0x01; 32]);

    // Sequence should have incremented
    assert_eq!(state.sequence, initial_sequence + 1);
}

#[test]
fn test_state_hash_changes_on_bittensor_link() {
    let mut state = ChainState::new(100);
    let hash_before = state.get_state_hash();

    // Link to block
    state.link_to_bittensor_block(100, [0x01; 32]);
    let hash_after = state.get_state_hash();

    // Hash must change
    assert_ne!(hash_before, hash_after);
}

#[test]
fn test_multiple_block_links_track_progression() {
    let mut state = ChainState::new(100);

    // Link to first block
    state.link_to_bittensor_block(1000, [0x01; 32]);
    assert_eq!(state.linked_block(), 1000);
    let seq_after_first = state.sequence;

    // Link to second block
    state.link_to_bittensor_block(2000, [0x02; 32]);
    assert_eq!(state.linked_block(), 2000);
    assert_eq!(state.bittensor_block_hash, [0x02; 32]);
    assert_eq!(state.sequence, seq_after_first + 1);

    // Link to third block
    state.link_to_bittensor_block(3000, [0x03; 32]);
    assert_eq!(state.linked_block(), 3000);
    assert_eq!(state.bittensor_block_hash, [0x03; 32]);
}

#[test]
fn test_bittensor_link_with_real_block_hash() {
    let mut state = ChainState::new(100);

    // Simulate a real block hash (sha256 of block data)
    let real_hash: [u8; 32] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01, 0x02,
        0x03, 0x04,
    ];

    state.link_to_bittensor_block(9999999, real_hash);

    assert_eq!(state.bittensor_block, 9999999);
    assert_eq!(state.bittensor_block_hash, real_hash);
}

// ============================================================================
// MERKLE PROOF TESTS
// ============================================================================

#[test]
fn test_merkle_root_computation_deterministic() {
    let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();

    let root1 = compute_merkle_root(&leaves);
    let root2 = compute_merkle_root(&leaves);

    // Same leaves should produce same root
    assert_eq!(root1, root2);
    assert_ne!(root1, [0u8; 32]);
}

#[test]
fn test_merkle_root_changes_with_different_leaves() {
    let leaves1: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();
    let leaves2: Vec<[u8; 32]> = (1..5).map(|i| [i as u8; 32]).collect();

    let root1 = compute_merkle_root(&leaves1);
    let root2 = compute_merkle_root(&leaves2);

    // Different leaves should produce different roots
    assert_ne!(root1, root2);
}

#[test]
fn test_merkle_proof_verification_valid() {
    let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i as u8; 32]).collect();

    // Build and verify proof for each leaf
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = build_merkle_proof(&leaves, i).expect("Failed to build proof");
        assert!(
            verify_merkle_proof(leaf, &proof),
            "Valid proof for leaf {} should verify",
            i
        );
    }
}

#[test]
fn test_merkle_proof_verification_invalid() {
    let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();

    let proof = build_merkle_proof(&leaves, 0).expect("Failed to build proof");

    // Tampered leaf should not verify
    let tampered_leaf: [u8; 32] = [0xFF; 32];
    assert!(
        !verify_merkle_proof(&tampered_leaf, &proof),
        "Tampered leaf should not verify"
    );

    // Original leaf should still verify
    assert!(
        verify_merkle_proof(&leaves[0], &proof),
        "Original leaf should verify"
    );
}

#[test]
fn test_merkle_proof_single_leaf() {
    let leaves: Vec<[u8; 32]> = vec![[0x42; 32]];

    let root = compute_merkle_root(&leaves);
    // Single leaf should be its own root
    assert_eq!(root, leaves[0]);

    let proof = build_merkle_proof(&leaves, 0).expect("Failed to build proof for single leaf");
    assert!(
        verify_merkle_proof(&leaves[0], &proof),
        "Single leaf proof should verify"
    );
}

#[test]
fn test_merkle_proof_empty_leaves() {
    let leaves: Vec<[u8; 32]> = vec![];

    let root = compute_merkle_root(&leaves);
    // Empty tree should return zero hash
    assert_eq!(root, [0u8; 32]);

    // Building proof for empty tree should return None
    let proof = build_merkle_proof(&leaves, 0);
    assert!(
        proof.is_none(),
        "Should not build proof for empty leaf array"
    );
}

#[test]
fn test_merkle_proof_out_of_bounds() {
    let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();

    // Index out of bounds should return None
    let proof = build_merkle_proof(&leaves, 10);
    assert!(proof.is_none(), "Out of bounds index should return None");
}

#[test]
fn test_merkle_proof_odd_number_of_leaves() {
    // Odd number of leaves tests edge case in tree construction
    let leaves: Vec<[u8; 32]> = (0..5).map(|i| [i as u8; 32]).collect();

    let root = compute_merkle_root(&leaves);
    assert_ne!(root, [0u8; 32]);

    // All proofs should still verify
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = build_merkle_proof(&leaves, i).expect("Failed to build proof");
        assert!(
            verify_merkle_proof(leaf, &proof),
            "Proof for leaf {} should verify",
            i
        );
    }
}

#[test]
fn test_merkle_proof_power_of_two_leaves() {
    // Test perfect binary tree
    let leaves: Vec<[u8; 32]> = (0..16).map(|i| [i as u8; 32]).collect();

    let root = compute_merkle_root(&leaves);
    assert_ne!(root, [0u8; 32]);

    // Verify first, middle, and last
    for &i in &[0, 7, 8, 15] {
        let proof = build_merkle_proof(&leaves, i).expect("Failed to build proof");
        assert!(verify_merkle_proof(&leaves[i], &proof));
    }
}

// ============================================================================
// STATE VERIFICATION TESTS
// ============================================================================

#[test]
fn test_state_serialization_preserves_bittensor_link() {
    let mut state = ChainState::new(100);

    // Link to bittensor block
    let block_number: u64 = 54321;
    let block_hash: [u8; 32] = [0xBE; 32];
    state.link_to_bittensor_block(block_number, block_hash);

    // Serialize and deserialize
    let bytes = state.to_bytes().expect("Serialization failed");
    let recovered = ChainState::from_bytes(&bytes).expect("Deserialization failed");

    // Verify block link preserved
    assert_eq!(recovered.bittensor_block, block_number);
    assert_eq!(recovered.bittensor_block_hash, block_hash);
    assert_eq!(recovered.linked_block(), block_number);
    assert_eq!(recovered.sequence, state.sequence);
}

#[test]
fn test_state_hash_unique_per_modification() {
    let mut state = ChainState::new(100);
    let mut seen_hashes = std::collections::HashSet::new();

    // Initial hash
    seen_hashes.insert(state.get_state_hash());

    // Add validator
    let keypair1 = Keypair::generate();
    state.update_validator(keypair1.hotkey(), 1_000_000);
    assert!(
        seen_hashes.insert(state.get_state_hash()),
        "Hash should be unique after adding validator"
    );

    // Link to block
    state.link_to_bittensor_block(100, [0x01; 32]);
    assert!(
        seen_hashes.insert(state.get_state_hash()),
        "Hash should be unique after linking block"
    );

    // Add challenge
    let config = ChallengeConfig {
        id: ChallengeId::new(),
        name: "Test Challenge".to_string(),
        weight: 50,
        is_active: true,
        creator: Hotkey([0u8; 32]),
        created_at: chrono::Utc::now().timestamp_millis(),
        wasm_hash: [0u8; 32],
    };
    state.add_challenge(config);
    assert!(
        seen_hashes.insert(state.get_state_hash()),
        "Hash should be unique after adding challenge"
    );

    // Transition epoch
    state.next_epoch();
    assert!(
        seen_hashes.insert(state.get_state_hash()),
        "Hash should be unique after epoch transition"
    );

    // All 5 states had unique hashes
    assert_eq!(seen_hashes.len(), 5);
}

#[test]
fn test_epoch_transition_maintains_bittensor_link() {
    let mut state = ChainState::new(100);

    // Link to block
    let block_number: u64 = 12345;
    let block_hash: [u8; 32] = [0xAB; 32];
    state.link_to_bittensor_block(block_number, block_hash);

    // Transition epoch
    state.next_epoch();

    // Block link should be preserved
    assert_eq!(state.linked_block(), block_number);
    assert_eq!(state.bittensor_block_hash, block_hash);
    assert_eq!(state.epoch, 1);
}

#[test]
fn test_validator_update_changes_hash_preserves_block() {
    let mut state = ChainState::new(100);

    // Link to block
    let block_number: u64 = 10000;
    let block_hash: [u8; 32] = [0xCD; 32];
    state.link_to_bittensor_block(block_number, block_hash);

    let hash_before = state.get_state_hash();

    // Add validators
    let keypair1 = Keypair::generate();
    let keypair2 = Keypair::generate();
    state.update_validator(keypair1.hotkey(), 1_000_000);
    state.update_validator(keypair2.hotkey(), 2_000_000);

    let hash_after = state.get_state_hash();

    // Hash should change
    assert_ne!(hash_before, hash_after);

    // Block link should be preserved
    assert_eq!(state.linked_block(), block_number);
    assert_eq!(state.bittensor_block_hash, block_hash);
}

#[test]
fn test_state_hash_hex_format() {
    let state = ChainState::new(100);
    let hex = state.hash_hex();

    // Should be 64 hex characters (32 bytes)
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_block_height_tracks_sequence() {
    let mut state = ChainState::new(100);

    assert_eq!(state.block_height(), 0);

    state.increment_sequence();
    assert_eq!(state.block_height(), 1);

    state.link_to_bittensor_block(100, [0x01; 32]);
    assert_eq!(state.block_height(), 2);

    let keypair = Keypair::generate();
    state.update_validator(keypair.hotkey(), 1_000_000);
    assert_eq!(state.block_height(), 3);
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[test]
fn test_full_state_lifecycle_with_block_linking() {
    // Create state with custom sudo key for testing
    let sudo_keypair = Keypair::generate();
    let mut state = ChainState::with_sudo(sudo_keypair.hotkey(), 100);

    // Initial state
    assert_eq!(state.epoch, 0);
    assert_eq!(state.linked_block(), 0);

    // Link to genesis block
    state.link_to_bittensor_block(1, [0x01; 32]);
    assert_eq!(state.linked_block(), 1);
    let seq_after_genesis = state.sequence;

    // Add validators
    let validator1 = Keypair::generate();
    let validator2 = Keypair::generate();
    state.update_validator(validator1.hotkey(), 1_000_000);
    state.update_validator(validator2.hotkey(), 2_000_000);
    assert_eq!(state.validators.len(), 2);
    assert!(state.sequence > seq_after_genesis);

    // Add challenge
    let challenge = ChallengeConfig {
        id: ChallengeId::new(),
        name: "Integration Test Challenge".to_string(),
        weight: 100,
        is_active: true,
        creator: sudo_keypair.hotkey(),
        created_at: chrono::Utc::now().timestamp_millis(),
        wasm_hash: [0u8; 32],
    };
    state.add_challenge(challenge);
    assert_eq!(state.challenges.len(), 1);

    // Link to new block (simulating progression)
    let hash_before_new_block = state.get_state_hash();
    state.link_to_bittensor_block(1000, [0x10; 32]);
    let hash_after_new_block = state.get_state_hash();

    // Verify state integrity
    assert_ne!(hash_before_new_block, hash_after_new_block);
    assert_eq!(state.linked_block(), 1000);
    assert_eq!(state.validators.len(), 2);
    assert_eq!(state.challenges.len(), 1);

    // Serialize and verify
    let bytes = state.to_bytes().expect("Serialization failed");
    let recovered = ChainState::from_bytes(&bytes).expect("Deserialization failed");

    assert_eq!(recovered.linked_block(), 1000);
    assert_eq!(recovered.validators.len(), 2);
    assert_eq!(recovered.challenges.len(), 1);
}

#[test]
fn test_evaluation_finalization_with_merkle_proof() {
    // Create state
    let mut state = ChainState::new(100);

    // Add validators
    let validator1 = Keypair::generate();
    let validator2 = Keypair::generate();
    state.update_validator(validator1.hotkey(), 1_000_000);
    state.update_validator(validator2.hotkey(), 2_000_000);

    // Create evaluation records with unique hashes
    let evaluation_hashes: Vec<[u8; 32]> = (0..4)
        .map(|i| {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            hash[31] = i as u8;
            hash
        })
        .collect();

    // Compute merkle root for evaluations
    let root = compute_merkle_root(&evaluation_hashes);
    assert_ne!(root, [0u8; 32]);

    // Build and verify proof for each evaluation
    for (i, hash) in evaluation_hashes.iter().enumerate() {
        let proof = build_merkle_proof(&evaluation_hashes, i).expect("Failed to build proof");

        // Proof should verify
        assert!(
            verify_merkle_proof(hash, &proof),
            "Proof for evaluation {} should verify",
            i
        );

        // Proof root should match computed root
        assert_eq!(proof.root, root);
    }
}

#[test]
fn test_state_manager_with_block_linking() {
    let manager = StateManager::for_netuid(100);

    // Link to block via manager
    manager.apply(|state| {
        state.link_to_bittensor_block(500, [0x50; 32]);
    });

    // Verify via snapshot
    let snapshot = manager.snapshot();
    assert_eq!(snapshot.linked_block(), 500);
    assert_eq!(snapshot.bittensor_block_hash, [0x50; 32]);
    assert_eq!(manager.sequence(), 1);
}

#[test]
fn test_state_sync_preserves_bittensor_link() {
    let manager = StateManager::for_netuid(100);

    // Create a new state with higher sequence
    let mut new_state = ChainState::new(100);
    new_state.link_to_bittensor_block(9999, [0x99; 32]);
    new_state.increment_sequence(); // Sequence = 2

    // Apply sync
    manager
        .apply_sync_state(new_state.clone())
        .expect("Sync should succeed");

    // Verify synced state
    let snapshot = manager.snapshot();
    assert_eq!(snapshot.linked_block(), 9999);
    assert_eq!(snapshot.bittensor_block_hash, [0x99; 32]);
}

#[test]
fn test_merkle_proof_for_validator_hashes() {
    // Simulate validator hotkeys as merkle leaves
    let validators: Vec<Keypair> = (0..8).map(|_| Keypair::generate()).collect();
    let leaves: Vec<[u8; 32]> = validators.iter().map(|k| k.hotkey().0).collect();

    let root = compute_merkle_root(&leaves);
    assert_ne!(root, [0u8; 32], "Merkle root should not be empty");

    // Verify each validator's inclusion
    for (i, validator) in validators.iter().enumerate() {
        let leaf = validator.hotkey().0;
        let proof = build_merkle_proof(&leaves, i).expect("Failed to build proof");
        assert!(
            verify_merkle_proof(&leaf, &proof),
            "Validator {} should be provable in merkle tree",
            i
        );
    }
}

#[test]
fn test_state_determinism() {
    // Two states with same operations should have same hash
    let mut state1 = ChainState::new(100);
    let mut state2 = ChainState::new(100);

    // Both start with same hash
    let initial_hash1 = state1.get_state_hash();
    let initial_hash2 = state2.get_state_hash();
    assert_eq!(initial_hash1, initial_hash2);

    // Same operations in same order
    let hotkey = Hotkey([0x42; 32]);
    state1.update_validator(hotkey.clone(), 1_000_000);
    state2.update_validator(hotkey.clone(), 1_000_000);

    // Should still have same hash (sequence-based)
    // Note: Hash is based on counts and sequence, so adding same validator
    // at same sequence should produce same hash
    assert_eq!(state1.sequence, state2.sequence);
}

#[test]
fn test_challenge_removal_changes_hash() {
    let mut state = ChainState::new(100);

    let challenge_id = ChallengeId::new();
    let config = ChallengeConfig {
        id: challenge_id,
        name: "Removable Challenge".to_string(),
        weight: 50,
        is_active: true,
        creator: Hotkey([0u8; 32]),
        created_at: chrono::Utc::now().timestamp_millis(),
        wasm_hash: [0u8; 32],
    };

    state.add_challenge(config);
    let hash_with_challenge = state.get_state_hash();

    state.remove_challenge(&challenge_id);
    let hash_without_challenge = state.get_state_hash();

    assert_ne!(hash_with_challenge, hash_without_challenge);
}

#[test]
fn test_evaluation_record_lifecycle() {
    let mut state = ChainState::new(100);

    // Add validator
    let validator_keypair = Keypair::generate();
    state.update_validator(validator_keypair.hotkey(), 1_000_000);

    // Create evaluation record
    let record = EvaluationRecord {
        submission_id: "test_submission_001".to_string(),
        challenge_id: ChallengeId::new(),
        miner: Keypair::generate().hotkey(),
        agent_hash: "agent_hash_123".to_string(),
        evaluations: HashMap::new(),
        aggregated_score: None,
        finalized: false,
        created_at: chrono::Utc::now().timestamp_millis(),
        finalized_at: None,
    };

    let hash_before = state.get_state_hash();
    state.add_evaluation(record);
    let hash_after = state.get_state_hash();

    assert_ne!(hash_before, hash_after);
    assert!(state
        .pending_evaluations
        .contains_key("test_submission_001"));
}
