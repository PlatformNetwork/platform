//! Integration tests for the WASM + Storage + P2P + Epoch pipeline.
//!
//! These tests verify that the key integration points between crates work
//! correctly when wired together, without requiring a live P2P network.

use std::sync::Arc;

use parking_lot::RwLock;
use platform_core::{ChallengeId, Hotkey, Keypair, NetworkConfig};
use platform_distributed_storage::local::LocalStorage;
use platform_distributed_storage::store::{DistributedStore, GetOptions, PutOptions, StorageKey};
use platform_epoch::{
    CommitRevealState, EpochConfig, EpochManager, EpochPhase, WeightCommitment, WeightReveal,
};
use platform_p2p_consensus::state::{ChainState as ConsensusChainState, StorageProposal};
use platform_p2p_consensus::validator::{ValidatorRecord, ValidatorSet};
use platform_rpc::{JsonRpcRequest, RpcHandler};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Test 1: Local storage write and read round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_local_storage_write_and_read() {
    let storage = LocalStorage::in_memory("test-node".to_string()).unwrap();

    let key = StorageKey::new("challenge-abc", "submission-1");
    let data = b"hello world".to_vec();

    // Write
    storage
        .put(key.clone(), data.clone(), PutOptions::default())
        .await
        .unwrap();

    // Read back
    let result = storage
        .get(&key, GetOptions::default())
        .await
        .unwrap()
        .expect("value should exist");

    assert_eq!(result.data, data);
}

// ---------------------------------------------------------------------------
// Test 2: Storage proposal consensus flow via ConsensusChainState
// ---------------------------------------------------------------------------

#[test]
fn test_storage_proposal_consensus_flow() {
    let mut state = ConsensusChainState::new(1);

    let proposer = Keypair::generate();
    let voter1 = Keypair::generate();
    let voter2 = Keypair::generate();

    // Register validators so votes are meaningful
    state.update_validator(proposer.hotkey(), 1000);
    state.update_validator(voter1.hotkey(), 1000);
    state.update_validator(voter2.hotkey(), 1000);

    // Create a storage proposal
    let proposal_id = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"test-proposal");
        let hash: [u8; 32] = hasher.finalize().into();
        hash
    };

    let proposal = StorageProposal {
        proposal_id,
        challenge_id: ChallengeId::new("test-challenge"),
        proposer: proposer.hotkey(),
        key: b"some-key".to_vec(),
        value: b"some-value".to_vec(),
        timestamp: chrono::Utc::now().timestamp_millis(),
        votes: std::collections::HashMap::new(),
        finalized: false,
    };

    state.add_storage_proposal(proposal);

    // Verify proposal exists
    let fetched = state.get_storage_proposal(&proposal_id);
    assert!(fetched.is_some());
    assert!(!fetched.unwrap().finalized);

    // Vote on proposal — threshold is 35% of stake (1050 out of 3000)
    // First vote (1000 stake) doesn't reach threshold
    let result1 = state.vote_storage_proposal(&proposal_id, proposer.hotkey(), true);
    assert_eq!(result1, None);
    // Second vote (2000 stake total) reaches 35% threshold
    let result2 = state.vote_storage_proposal(&proposal_id, voter1.hotkey(), true);
    assert_eq!(result2, Some(true));

    // Proposal should now be finalized
    let fetched = state.get_storage_proposal(&proposal_id);
    assert!(fetched.is_some());
    assert!(fetched.unwrap().finalized);
}

// ---------------------------------------------------------------------------
// Test 3: Epoch commit-reveal with phase validation
// ---------------------------------------------------------------------------

#[test]
fn test_epoch_commit_reveal_with_phases() {
    let challenge_id = platform_challenge_sdk::ChallengeId::new("test-challenge");
    let mut cr_state = CommitRevealState::new(0, challenge_id.clone());

    let v1 = Keypair::generate();
    let v2 = Keypair::generate();

    // Helper to create commitment + reveal pair
    let challenge_id_clone = challenge_id.clone();
    let make_pair = move |kp: &Keypair| {
        let weights = vec![
            platform_challenge_sdk::WeightAssignment::new("agent1".to_string(), 0.7),
            platform_challenge_sdk::WeightAssignment::new("agent2".to_string(), 0.3),
        ];
        let secret = b"secret123".to_vec();
        let hash = platform_challenge_sdk::weights::create_commitment(&weights, &secret);
        let commitment = WeightCommitment {
            validator: kp.hotkey(),
            challenge_id: challenge_id_clone.clone(),
            epoch: 0,
            commitment_hash: hash,
            timestamp: chrono::Utc::now(),
        };
        let reveal = WeightReveal {
            validator: kp.hotkey(),
            challenge_id: challenge_id_clone.clone(),
            epoch: 0,
            weights,
            secret,
            timestamp: chrono::Utc::now(),
        };
        (commitment, reveal)
    };

    let (c1, r1) = make_pair(&v1);
    let (c2, r2) = make_pair(&v2);

    // Committing during Commit phase should succeed
    cr_state.submit_commitment(EpochPhase::Commit, c1).unwrap();
    cr_state.submit_commitment(EpochPhase::Commit, c2).unwrap();
    assert_eq!(cr_state.commitment_count(), 2);

    // Revealing during Commit phase should fail
    let bad = cr_state.submit_reveal(EpochPhase::Commit, r1.clone());
    assert!(bad.is_err());

    // Revealing during Reveal phase should succeed
    cr_state.submit_reveal(EpochPhase::Reveal, r1).unwrap();
    cr_state.submit_reveal(EpochPhase::Reveal, r2).unwrap();
    assert_eq!(cr_state.reveal_count(), 2);

    // Finalize
    let finalized = cr_state.finalize(0.3, 2).unwrap();
    assert_eq!(finalized.participating_validators.len(), 2);
    assert!(!finalized.weights.is_empty());
}

// ---------------------------------------------------------------------------
// Test 4: EpochManager phase transitions
// ---------------------------------------------------------------------------

#[test]
fn test_epoch_manager_phase_transitions() {
    let config = EpochConfig::default();
    // blocks_per_epoch=360, evaluation=270, commit=45, reveal=45
    let mgr = EpochManager::new(config.clone(), 0);

    assert_eq!(mgr.current_epoch(), 0);
    assert_eq!(mgr.current_phase(), EpochPhase::Evaluation);

    // Advance past evaluation phase (270 blocks)
    for block in 1..=270 {
        mgr.on_new_block(block);
    }
    assert_eq!(mgr.current_phase(), EpochPhase::Commit);

    // Advance past commit phase (45 blocks)
    for block in 271..=315 {
        mgr.on_new_block(block);
    }
    assert_eq!(mgr.current_phase(), EpochPhase::Reveal);

    // Advance past reveal phase triggers new epoch
    for block in 316..=360 {
        mgr.on_new_block(block);
    }
    assert_eq!(mgr.current_epoch(), 1);
}

// ---------------------------------------------------------------------------
// Test 5: RPC handler serves challenge routes
// ---------------------------------------------------------------------------

#[test]
fn test_rpc_challenge_route_resolution() {
    let kp = Keypair::generate();
    let state = Arc::new(RwLock::new(platform_core::ChainState::new(
        kp.hotkey(),
        NetworkConfig::default(),
    )));

    // Register a WASM challenge (challenge_list reads from wasm_challenge_configs)
    {
        let mut s = state.write();
        let mut wasm_config = platform_core::WasmChallengeConfig::default();
        wasm_config.name = "test-challenge".to_string();
        wasm_config.description = "A test challenge".to_string();
        wasm_config.is_active = true;
        s.register_wasm_challenge(wasm_config);
    }

    let handler = RpcHandler::new(state, 1);

    // List challenges via RPC
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "challenge_list".to_string(),
        params: Value::Null,
        id: json!(1),
    };
    let resp = handler.handle(req);
    assert!(resp.result.is_some());
    let result = resp.result.unwrap();
    let challenges = result["challenges"].as_array().unwrap();
    assert!(!challenges.is_empty());
}

// ---------------------------------------------------------------------------
// Test 6: Validator set management
// ---------------------------------------------------------------------------

#[test]
fn test_validator_set_registration_and_quorum() {
    let local_kp = Keypair::generate();
    let vset = ValidatorSet::new(local_kp.clone(), 100);

    let v1 = Keypair::generate();
    let v2 = Keypair::generate();
    let v3 = Keypair::generate();

    // Register validators
    vset.register_validator(ValidatorRecord::new(v1.hotkey(), 500))
        .unwrap();
    vset.register_validator(ValidatorRecord::new(v2.hotkey(), 500))
        .unwrap();
    vset.register_validator(ValidatorRecord::new(v3.hotkey(), 500))
        .unwrap();

    assert_eq!(vset.active_count(), 3);

    // fault_tolerance = (3-1)/3 = 0, quorum = 2*0+1 = 1
    // With 4+ validators: fault_tolerance = (4-1)/3 = 1, quorum = 3
    let quorum = vset.quorum_size();
    assert_eq!(quorum, 1);

    // Add a 4th validator to get meaningful BFT quorum
    let v4 = Keypair::generate();
    vset.register_validator(ValidatorRecord::new(v4.hotkey(), 500))
        .unwrap();
    assert_eq!(vset.active_count(), 4);
    // fault_tolerance = (4-1)/3 = 1, quorum = 2*1+1 = 3
    assert_eq!(vset.quorum_size(), 3);

    // Verify stake
    assert_eq!(vset.stake_for(&v1.hotkey()), 500);
    assert!(vset.is_validator(&v1.hotkey()));
    assert!(!vset.is_validator(&Hotkey([0xff; 32])));
}

// ---------------------------------------------------------------------------
// Test 7: End-to-end storage + consensus state integration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_storage_write_feeds_consensus_state() {
    // 1. Write data to local storage
    let storage = LocalStorage::in_memory("node-1".to_string()).unwrap();
    let key = StorageKey::new("challenge-x", "result-42");
    let value = b"{\"score\": 0.95}".to_vec();

    storage
        .put(key.clone(), value.clone(), PutOptions::default())
        .await
        .unwrap();

    // 2. Simulate creating a storage proposal from the write
    let mut consensus_state = ConsensusChainState::new(1);
    let proposer = Keypair::generate();
    consensus_state.update_validator(proposer.hotkey(), 1000);

    let proposal_id = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&key.to_bytes());
        hasher.update(&value);
        let hash: [u8; 32] = hasher.finalize().into();
        hash
    };

    let proposal = StorageProposal {
        proposal_id,
        challenge_id: ChallengeId::new("test-challenge"),
        proposer: proposer.hotkey(),
        key: key.to_bytes(),
        value: value.clone(),
        timestamp: chrono::Utc::now().timestamp_millis(),
        votes: std::collections::HashMap::new(),
        finalized: false,
    };

    consensus_state.add_storage_proposal(proposal);

    // 3. Verify the data is consistent across both layers
    let stored = storage
        .get(&key, GetOptions::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.data, value);

    let proposal_ref = consensus_state.get_storage_proposal(&proposal_id).unwrap();
    assert_eq!(proposal_ref.value, value);
}
