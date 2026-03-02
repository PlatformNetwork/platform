//! End-to-End Integration Tests for Platform
//!
//! These tests verify the complete flow of the validator system.

use parking_lot::RwLock;
use platform_core::*;
use platform_storage::*;
use std::sync::Arc;
use tempfile::tempdir;

// ============================================================================
// E2E: STORAGE FLOW
// ============================================================================

#[test]
fn test_e2e_storage_state_persistence() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path()).unwrap();

    let sudo = Keypair::generate();
    let mut state = ChainState::new(sudo.hotkey(), NetworkConfig::default());

    // Add validators
    for _ in 0..4 {
        let kp = Keypair::generate();
        let info = ValidatorInfo::new(kp.hotkey(), Stake::new(10_000_000_000));
        state.add_validator(info).unwrap();
    }

    state.increment_block();
    state.increment_block();

    // Save
    storage.save_state(&state).unwrap();

    // Load and verify
    let loaded = storage.load_state().unwrap().unwrap();
    assert_eq!(loaded.block_height, 2);
    assert_eq!(loaded.validators.len(), 4);
}

#[test]
fn test_e2e_storage_challenge_lifecycle() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path()).unwrap();

    let sudo = Keypair::generate();
    let mut state = ChainState::new(sudo.hotkey(), NetworkConfig::default());

    // Create challenge
    let challenge = Challenge::new(
        "Test Challenge".into(),
        "A test challenge".into(),
        b"print('hello')".to_vec(),
        sudo.hotkey(),
        ChallengeConfig::default(),
    );

    let challenge_id = challenge.id.clone();

    // Add to state
    state.add_challenge(challenge.clone());
    assert!(state.get_challenge(&challenge_id).is_some());

    // Save to storage
    storage.save_challenge(&challenge).unwrap();

    // Load
    let loaded = storage.load_challenge(&challenge_id).unwrap().unwrap();
    assert_eq!(loaded.name, "Test Challenge");

    // Remove
    state.remove_challenge(&challenge_id);
    assert!(state.get_challenge(&challenge_id).is_none());
}

#[test]
fn test_e2e_validator_registration() {
    let sudo = Keypair::generate();
    let mut state = ChainState::new(sudo.hotkey(), NetworkConfig::default());

    let validators: Vec<_> = (0..8)
        .map(|i| {
            let kp = Keypair::generate();
            let stake = Stake::new((i + 1) as u64 * 1_000_000_000);
            (kp, stake)
        })
        .collect();

    for (kp, stake) in &validators {
        let info = ValidatorInfo::new(kp.hotkey(), *stake);
        state.add_validator(info).unwrap();
    }

    assert_eq!(state.validators.len(), 8);
    assert_eq!(state.active_validators().len(), 8);

    let expected_stake: u64 = (1..=8).map(|i| i * 1_000_000_000).sum();
    assert_eq!(state.total_stake().0, expected_stake);

    // Consensus threshold (50% of 8 = 4)
    assert_eq!(state.consensus_threshold(), 4);
}

#[test]
fn test_e2e_job_queue() {
    let sudo = Keypair::generate();
    let mut state = ChainState::new(sudo.hotkey(), NetworkConfig::default());

    let challenge_id = ChallengeId::new("test-challenge");

    // Add jobs
    for i in 0..5 {
        let job = Job::new(challenge_id.clone(), format!("agent_{}", i));
        state.add_job(job);
    }

    assert_eq!(state.pending_jobs.len(), 5);

    // Claim jobs
    let validator = Keypair::generate();
    for i in 0..5 {
        let job = state.claim_job(&validator.hotkey());
        assert!(job.is_some());
        assert_eq!(job.unwrap().agent_hash, format!("agent_{}", i));
    }

    assert!(state.claim_job(&validator.hotkey()).is_none());
}

// ============================================================================
// E2E: CRYPTO VERIFICATION
// ============================================================================

#[test]
fn test_e2e_signed_message_chain() {
    let validators: Vec<_> = (0..4).map(|_| Keypair::generate()).collect();

    let original_message = b"Important network message";

    let signed_messages: Vec<_> = validators
        .iter()
        .map(|v| v.sign(original_message))
        .collect();

    for signed in &signed_messages {
        assert!(signed.verify().unwrap());
    }

    // Tampering should fail
    let mut tampered = signed_messages[0].clone();
    tampered.message.push(0);
    assert!(!tampered.verify().unwrap());
}

#[test]
fn test_e2e_state_hash_consistency() {
    let sudo = Keypair::generate();
    let mut state = ChainState::new(sudo.hotkey(), NetworkConfig::default());

    let mut hashes = Vec::new();

    hashes.push(state.state_hash);

    state.increment_block();
    hashes.push(state.state_hash);

    let kp = Keypair::generate();
    state
        .add_validator(ValidatorInfo::new(kp.hotkey(), Stake::new(10_000_000_000)))
        .unwrap();
    hashes.push(state.state_hash);

    let challenge = Challenge::new(
        "Test".into(),
        "Desc".into(),
        vec![],
        sudo.hotkey(),
        ChallengeConfig::default(),
    );
    state.add_challenge(challenge);
    hashes.push(state.state_hash);

    // All hashes should be unique
    for i in 0..hashes.len() {
        for j in i + 1..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "Hash collision at {} and {}", i, j);
        }
    }
}

// ============================================================================
// E2E: FULL VALIDATOR FLOW
// ============================================================================

#[test]
fn test_e2e_full_validator_flow() {
    let sudo = Keypair::generate();
    let dir = tempdir().unwrap();

    let state = Arc::new(RwLock::new(ChainState::new(
        sudo.hotkey(),
        NetworkConfig::default(),
    )));

    let storage = Storage::open(dir.path()).unwrap();

    // Add validators
    let validators: Vec<_> = (0..4).map(|_| Keypair::generate()).collect();
    for v in &validators {
        let info = ValidatorInfo::new(v.hotkey(), Stake::new(10_000_000_000));
        state.write().add_validator(info.clone()).unwrap();
        storage.save_validator(&info).unwrap();
    }

    // 1. Add a challenge
    let challenge = Challenge::new(
        "Terminal Benchmark".into(),
        "Terminal AI benchmark challenge".into(),
        b"challenge code".to_vec(),
        sudo.hotkey(),
        ChallengeConfig::default(),
    );

    state.write().add_challenge(challenge.clone());
    storage.save_challenge(&challenge).unwrap();

    // 2. Add jobs
    let job = Job::new(challenge.id, "agent_abc123".into());
    state.write().add_job(job);

    // 3. Claim job
    let claimed = state.write().claim_job(&validators[0].hotkey());
    assert!(claimed.is_some());

    // 4. Save state
    storage.save_state(&state.read().clone()).unwrap();

    // 5. Load and verify
    let loaded_state = storage.load_state().unwrap().unwrap();
    assert_eq!(loaded_state.validators.len(), 4);
    assert_eq!(loaded_state.challenges.len(), 1);
}

// ============================================================================
// E2E: EPOCH SIMULATION
// ============================================================================

#[test]
fn test_e2e_epoch_simulation() {
    let sudo = Keypair::generate();
    let mut state = ChainState::new(sudo.hotkey(), NetworkConfig::default());

    for epoch in 0..10 {
        state.epoch = epoch;

        for _ in 0..100 {
            state.increment_block();
        }

        assert_eq!(state.block_height, (epoch + 1) * 100);
    }

    assert_eq!(state.epoch, 9);
    assert_eq!(state.block_height, 1000);
}
