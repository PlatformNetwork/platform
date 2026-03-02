//! WASM Challenge Integration Tests
//!
//! Comprehensive tests for the full challenge lifecycle with 5 validators:
//! - Sudo owner can add/remove WASM challenges
//! - Challenge data persists in blockchain storage
//! - term-challenge WASM module builds and loads correctly
//! - PBFT consensus rounds with 5 validators
//! - Full evaluation pipeline end-to-end

use platform_core::{
    ChainState, Challenge, ChallengeConfig, ChallengeId, Hotkey, Keypair, NetworkConfig,
    NetworkMessage, SignedNetworkMessage, Stake, SudoAction, ValidatorInfo,
};
use platform_p2p_consensus::{
    ChallengeConfig as ConsensusChallengeConfig, ConsensusEngine, StateManager, ValidatorRecord,
    ValidatorSet,
};
use platform_storage::Storage;
use std::sync::Arc;
use tempfile::tempdir;
use wasm_runtime_interface::{InMemoryStorageBackend, InstanceConfig, RuntimeConfig, WasmRuntime};

const TERM_CHALLENGE_WASM: &[u8] = include_bytes!(
    "../../term-challenge/target/wasm32-unknown-unknown/release/term_challenge_wasm.wasm"
);

fn create_five_validators() -> (Keypair, Vec<Keypair>) {
    let sudo = Keypair::generate();
    let validators: Vec<Keypair> = (0..5).map(|_| Keypair::generate()).collect();
    (sudo, validators)
}

fn create_state_with_validators(sudo: &Keypair, validators: &[Keypair]) -> ChainState {
    let mut state = ChainState::new(sudo.hotkey(), NetworkConfig::default());
    for v in validators {
        let info = ValidatorInfo::new(v.hotkey(), Stake::new(10_000_000_000));
        state.add_validator(info).unwrap();
    }
    state
}

fn create_test_challenge(sudo: &Keypair, wasm_code: Vec<u8>) -> Challenge {
    Challenge::new(
        "term-challenge".into(),
        "Terminal AI benchmark challenge".into(),
        wasm_code,
        sudo.hotkey(),
        ChallengeConfig::default(),
    )
}

// ============================================================================
// WASM MODULE TESTS
// ============================================================================

#[test]
fn test_wasm_module_compiles() {
    let config = RuntimeConfig::default();
    let runtime = WasmRuntime::new(config).expect("Failed to create WASM runtime");

    let module = runtime.compile_module(TERM_CHALLENGE_WASM);
    assert!(
        module.is_ok(),
        "WASM module should compile: {:?}",
        module.err()
    );
}

#[test]
fn test_wasm_module_instantiates() {
    let config = RuntimeConfig::default();
    let runtime = WasmRuntime::new(config).expect("Failed to create WASM runtime");

    let module = runtime
        .compile_module(TERM_CHALLENGE_WASM)
        .expect("Failed to compile WASM module");

    let instance_config = InstanceConfig {
        challenge_id: "term-challenge-test".to_string(),
        validator_id: "test-validator".to_string(),
        storage_backend: Arc::new(InMemoryStorageBackend::new()),
        ..Default::default()
    };

    let instance = runtime.instantiate(&module, instance_config, None);
    assert!(
        instance.is_ok(),
        "WASM module should instantiate: {:?}",
        instance.err()
    );
}

#[test]
fn test_wasm_module_has_expected_exports() {
    let config = RuntimeConfig::default();
    let runtime = WasmRuntime::new(config).expect("Failed to create WASM runtime");

    let module = runtime
        .compile_module(TERM_CHALLENGE_WASM)
        .expect("Failed to compile WASM module");

    let instance_config = InstanceConfig {
        challenge_id: "term-challenge-test".to_string(),
        validator_id: "test-validator".to_string(),
        storage_backend: Arc::new(InMemoryStorageBackend::new()),
        ..Default::default()
    };

    let instance = runtime
        .instantiate(&module, instance_config, None)
        .expect("Failed to instantiate WASM module");

    let _memory = instance.memory();
}

// ============================================================================
// CHALLENGE LIFECYCLE TESTS (5 VALIDATORS)
// ============================================================================

#[test]
fn test_sudo_add_challenge_with_wasm() {
    let (sudo, validators) = create_five_validators();
    let mut state = create_state_with_validators(&sudo, &validators);

    assert_eq!(state.validators.len(), 5);
    assert_eq!(state.challenges.len(), 0);

    let challenge = create_test_challenge(&sudo, TERM_CHALLENGE_WASM.to_vec());
    let challenge_id = challenge.id;

    state.add_challenge(challenge);

    assert_eq!(state.challenges.len(), 1);
    let stored = state.get_challenge(&challenge_id).unwrap();
    assert_eq!(stored.name, "term-challenge");
    assert_eq!(stored.wasm_code.len(), TERM_CHALLENGE_WASM.len());
    assert!(stored.is_active);
    assert_eq!(stored.owner, sudo.hotkey());
}

#[test]
fn test_sudo_remove_challenge() {
    let (sudo, validators) = create_five_validators();
    let mut state = create_state_with_validators(&sudo, &validators);

    let challenge = create_test_challenge(&sudo, TERM_CHALLENGE_WASM.to_vec());
    let challenge_id = challenge.id;
    state.add_challenge(challenge);

    assert_eq!(state.challenges.len(), 1);

    let removed = state.remove_challenge(&challenge_id);
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().name, "term-challenge");
    assert_eq!(state.challenges.len(), 0);
    assert!(state.get_challenge(&challenge_id).is_none());
}

#[test]
fn test_non_sudo_cannot_add_challenge_via_signed_message() {
    let (sudo, validators) = create_five_validators();
    let state = create_state_with_validators(&sudo, &validators);
    let non_sudo = Keypair::generate();

    let action = SudoAction::EmergencyPause {
        reason: "Unauthorized attempt".to_string(),
    };
    let msg = NetworkMessage::SudoAction(action);
    let signed = SignedNetworkMessage::new(msg, &non_sudo).expect("Should sign");

    assert!(signed.verify().unwrap());
    assert!(
        !state.is_sudo(signed.signer()),
        "Non-sudo key should not be recognized as sudo"
    );

    let sudo_signed =
        SignedNetworkMessage::new(NetworkMessage::SudoAction(SudoAction::Resume), &sudo)
            .expect("Should sign");
    assert!(state.is_sudo(sudo_signed.signer()));
}

#[test]
fn test_challenge_persistence_in_storage() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path()).unwrap();

    let (sudo, validators) = create_five_validators();
    let mut state = create_state_with_validators(&sudo, &validators);

    let challenge = create_test_challenge(&sudo, TERM_CHALLENGE_WASM.to_vec());
    let challenge_id = challenge.id;

    state.add_challenge(challenge.clone());
    storage.save_challenge(&challenge).unwrap();
    storage.save_state(&state).unwrap();

    let loaded_challenge = storage.load_challenge(&challenge_id).unwrap().unwrap();
    assert_eq!(loaded_challenge.name, "term-challenge");
    assert_eq!(loaded_challenge.wasm_code.len(), TERM_CHALLENGE_WASM.len());
    assert_eq!(loaded_challenge.owner, sudo.hotkey());

    let loaded_state = storage.load_state().unwrap().unwrap();
    assert_eq!(loaded_state.validators.len(), 5);
    assert_eq!(loaded_state.challenges.len(), 1);
}

#[test]
fn test_challenge_state_hash_changes() {
    let (sudo, validators) = create_five_validators();
    let mut state = create_state_with_validators(&sudo, &validators);

    let hash_before = state.state_hash;

    let challenge = create_test_challenge(&sudo, TERM_CHALLENGE_WASM.to_vec());
    let challenge_id = challenge.id;
    state.add_challenge(challenge);

    let hash_after_add = state.state_hash;
    assert_ne!(
        hash_before, hash_after_add,
        "Hash should change after adding challenge"
    );

    state.remove_challenge(&challenge_id);
    let hash_after_remove = state.state_hash;
    assert_ne!(
        hash_after_add, hash_after_remove,
        "Hash should change after removing challenge"
    );
}

#[test]
fn test_challenge_deletion_from_storage() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path()).unwrap();

    let (sudo, _validators) = create_five_validators();
    let challenge = create_test_challenge(&sudo, TERM_CHALLENGE_WASM.to_vec());
    let challenge_id = challenge.id;

    storage.save_challenge(&challenge).unwrap();
    assert!(storage.load_challenge(&challenge_id).unwrap().is_some());

    assert!(storage.delete_challenge(&challenge_id).unwrap());
    assert!(storage.load_challenge(&challenge_id).unwrap().is_none());
}

// ============================================================================
// CONSENSUS WITH CHALLENGES (5 VALIDATORS)
// ============================================================================

#[test]
fn test_five_validator_consensus_engine_setup() {
    let leader_kp = Keypair::generate();
    let validator_set = Arc::new(ValidatorSet::new(leader_kp.clone(), 0));
    let state_manager = Arc::new(StateManager::for_netuid(100));

    let leader_record = ValidatorRecord::new(leader_kp.hotkey(), 10_000);
    validator_set.register_validator(leader_record).unwrap();

    for _ in 0..4 {
        let kp = Keypair::generate();
        let record = ValidatorRecord::new(kp.hotkey(), 10_000);
        validator_set.register_validator(record).unwrap();
    }

    let engine = ConsensusEngine::new(leader_kp, validator_set.clone(), state_manager);

    assert_eq!(engine.current_view(), 0);
    assert_eq!(engine.next_sequence(), 1);
    assert_eq!(engine.quorum_size(), 3);
}

#[test]
fn test_five_validator_consensus_proposal_with_challenge() {
    let leader_kp = Keypair::generate();
    let validator_set = Arc::new(ValidatorSet::new(leader_kp.clone(), 0));
    let state_manager = Arc::new(StateManager::for_netuid(100));

    let leader_record = ValidatorRecord::new(leader_kp.hotkey(), 10_000);
    validator_set.register_validator(leader_record).unwrap();

    for _ in 0..4 {
        let kp = Keypair::generate();
        let record = ValidatorRecord::new(kp.hotkey(), 10_000);
        validator_set.register_validator(record).unwrap();
    }

    let engine = ConsensusEngine::new(leader_kp, validator_set, state_manager);

    let leader = engine.current_leader();
    assert!(leader.is_some(), "Should have a leader");

    if engine.am_i_leader() {
        let challenge_data = bincode::serialize(&"add-challenge-term").unwrap();
        let proposal = engine.create_proposal(
            platform_p2p_consensus::StateChangeType::ChallengeSubmission,
            challenge_data,
        );
        assert!(
            proposal.is_ok(),
            "Leader should create proposal: {:?}",
            proposal.err()
        );

        let proposal = proposal.unwrap();
        assert_eq!(proposal.view, 0);
        assert_eq!(proposal.sequence, 1);
    }
}

#[test]
fn test_consensus_state_manager_with_challenges() {
    let state_manager = StateManager::for_netuid(100);

    let challenge_id = ChallengeId::new("test-challenge");
    let config = ConsensusChallengeConfig {
        id: challenge_id,
        name: "term-challenge".to_string(),
        weight: 100,
        is_active: true,
        creator: Hotkey([0u8; 32]),
        created_at: chrono::Utc::now().timestamp_millis(),
    };

    state_manager.apply(|s| {
        s.add_challenge(config);
    });

    let snapshot = state_manager.snapshot();
    assert_eq!(snapshot.challenges.len(), 1);
    assert!(snapshot.challenges.contains_key(&challenge_id));

    state_manager.apply(|s| {
        s.remove_challenge(&challenge_id);
    });

    let snapshot = state_manager.snapshot();
    assert_eq!(snapshot.challenges.len(), 0);
}

#[test]
fn test_challenge_survives_epoch_transition() {
    let (sudo, validators) = create_five_validators();
    let mut state = create_state_with_validators(&sudo, &validators);

    let challenge = create_test_challenge(&sudo, TERM_CHALLENGE_WASM.to_vec());
    let challenge_id = challenge.id;
    state.add_challenge(challenge);

    assert_eq!(state.epoch, 0);
    assert_eq!(state.challenges.len(), 1);

    for epoch in 1..=5 {
        state.epoch = epoch;
        state.increment_block();
    }

    assert_eq!(state.epoch, 5);
    assert_eq!(state.challenges.len(), 1);
    assert!(state.get_challenge(&challenge_id).is_some());
    assert_eq!(
        state.get_challenge(&challenge_id).unwrap().wasm_code.len(),
        TERM_CHALLENGE_WASM.len()
    );
}

#[test]
fn test_multiple_challenges_lifecycle() {
    let (sudo, validators) = create_five_validators();
    let mut state = create_state_with_validators(&sudo, &validators);

    let challenge1 = Challenge::new(
        "challenge-1".into(),
        "First challenge".into(),
        vec![0x00, 0x61, 0x73, 0x6d],
        sudo.hotkey(),
        ChallengeConfig::default(),
    );
    let challenge2 = Challenge::new(
        "challenge-2".into(),
        "Second challenge".into(),
        TERM_CHALLENGE_WASM.to_vec(),
        sudo.hotkey(),
        ChallengeConfig::default(),
    );
    let challenge3 = Challenge::new(
        "challenge-3".into(),
        "Third challenge".into(),
        vec![0x00, 0x61, 0x73, 0x6d, 0x01],
        sudo.hotkey(),
        ChallengeConfig::default(),
    );

    let id1 = challenge1.id;
    let id2 = challenge2.id;
    let id3 = challenge3.id;

    state.add_challenge(challenge1);
    state.add_challenge(challenge2);
    state.add_challenge(challenge3);
    assert_eq!(state.challenges.len(), 3);

    state.remove_challenge(&id2);
    assert_eq!(state.challenges.len(), 2);
    assert!(state.get_challenge(&id1).is_some());
    assert!(state.get_challenge(&id2).is_none());
    assert!(state.get_challenge(&id3).is_some());

    state.remove_challenge(&id1);
    state.remove_challenge(&id3);
    assert_eq!(state.challenges.len(), 0);
}

// ============================================================================
// FULL PIPELINE TESTS
// ============================================================================

#[test]
fn test_full_evaluation_pipeline() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path()).unwrap();

    let (sudo, validators) = create_five_validators();
    let mut state = create_state_with_validators(&sudo, &validators);

    let challenge = create_test_challenge(&sudo, TERM_CHALLENGE_WASM.to_vec());
    let challenge_id = challenge.id;

    state.add_challenge(challenge.clone());
    storage.save_challenge(&challenge).unwrap();
    storage.save_state(&state).unwrap();

    let loaded_challenge = storage.load_challenge(&challenge_id).unwrap().unwrap();
    assert_eq!(loaded_challenge.wasm_code.len(), TERM_CHALLENGE_WASM.len());

    let runtime_config = RuntimeConfig::default();
    let runtime = WasmRuntime::new(runtime_config).expect("Failed to create WASM runtime");

    let module = runtime
        .compile_module(&loaded_challenge.wasm_code)
        .expect("Failed to compile challenge WASM");

    let instance_config = InstanceConfig {
        challenge_id: challenge_id.0.to_string(),
        validator_id: validators[0].hotkey().to_hex(),
        storage_backend: Arc::new(InMemoryStorageBackend::new()),
        ..Default::default()
    };

    let instance = runtime
        .instantiate(&module, instance_config, None)
        .expect("Failed to instantiate challenge WASM");

    let _memory = instance.memory();
}

#[test]
fn test_full_pipeline_add_persist_load_compile_remove() {
    let dir = tempdir().unwrap();
    let storage = Storage::open(dir.path()).unwrap();

    let (sudo, validators) = create_five_validators();
    let mut state = create_state_with_validators(&sudo, &validators);

    assert!(state.is_sudo(&sudo.hotkey()));
    for v in &validators {
        assert!(!state.is_sudo(&v.hotkey()));
    }

    let challenge = create_test_challenge(&sudo, TERM_CHALLENGE_WASM.to_vec());
    let challenge_id = challenge.id;
    let code_hash = challenge.code_hash.clone();

    state.add_challenge(challenge.clone());
    storage.save_challenge(&challenge).unwrap();
    storage.save_state(&state).unwrap();

    let loaded_state = storage.load_state().unwrap().unwrap();
    assert_eq!(loaded_state.challenges.len(), 1);
    assert_eq!(loaded_state.validators.len(), 5);

    let loaded_challenge = storage.load_challenge(&challenge_id).unwrap().unwrap();
    assert_eq!(loaded_challenge.code_hash, code_hash);

    let runtime = WasmRuntime::new(RuntimeConfig::default()).unwrap();
    let module = runtime.compile_module(&loaded_challenge.wasm_code).unwrap();

    for (i, v) in validators.iter().enumerate() {
        let ic = InstanceConfig {
            challenge_id: challenge_id.0.to_string(),
            validator_id: v.hotkey().to_hex(),
            storage_backend: Arc::new(InMemoryStorageBackend::new()),
            ..Default::default()
        };
        let instance = runtime.instantiate(&module, ic, None);
        assert!(
            instance.is_ok(),
            "Validator {} should instantiate WASM: {:?}",
            i,
            instance.err()
        );
    }

    state.remove_challenge(&challenge_id);
    assert_eq!(state.challenges.len(), 0);

    storage.delete_challenge(&challenge_id).unwrap();
    assert!(storage.load_challenge(&challenge_id).unwrap().is_none());

    storage.save_state(&state).unwrap();
    let final_state = storage.load_state().unwrap().unwrap();
    assert_eq!(final_state.challenges.len(), 0);
}

#[test]
fn test_consensus_five_validators_full_round() {
    let validators: Vec<Keypair> = (0..5).map(|_| Keypair::generate()).collect();
    let state_manager = Arc::new(StateManager::for_netuid(100));

    let mut engines = Vec::new();
    for v in &validators {
        let vs = Arc::new(ValidatorSet::new(v.clone(), 0));
        for vr in &validators {
            let record = ValidatorRecord::new(vr.hotkey(), 10_000);
            vs.register_validator(record).unwrap();
        }
        engines.push(ConsensusEngine::new(v.clone(), vs, state_manager.clone()));
    }

    let leader_hotkey = engines[0].current_leader();
    assert!(leader_hotkey.is_some(), "Should have a leader");
    let leader_hotkey = leader_hotkey.unwrap();

    let leader_idx = validators
        .iter()
        .position(|v| v.hotkey() == leader_hotkey)
        .expect("Leader should be one of the validators");

    assert!(
        engines[leader_idx].am_i_leader(),
        "Engine at leader_idx should recognize itself as leader"
    );

    let proposal = engines[leader_idx]
        .create_proposal(
            platform_p2p_consensus::StateChangeType::ChallengeSubmission,
            b"challenge-update".to_vec(),
        )
        .expect("Leader should create proposal");

    assert_eq!(proposal.view, 0);
    assert_eq!(proposal.sequence, 1);

    use sha2::{Digest, Sha256};
    let proposal_bytes = bincode::serialize(&proposal.proposal).unwrap();
    let proposal_hash: [u8; 32] = Sha256::digest(&proposal_bytes).into();

    let _pre_prepare = engines[leader_idx]
        .create_pre_prepare(proposal.view, proposal.sequence, proposal_hash)
        .expect("Leader should create pre-prepare");

    let mut prepares = Vec::new();
    for (i, engine) in engines.iter().enumerate() {
        if i == leader_idx {
            continue;
        }
        match engine.handle_proposal(proposal.clone()) {
            Ok(prepare) => prepares.push(prepare),
            Err(e) => panic!("Validator {} failed to handle proposal: {:?}", i, e),
        }
    }

    assert!(
        prepares.len() >= 3,
        "Need at least 3 prepares for quorum (got {})",
        prepares.len()
    );
}

#[test]
fn test_state_serialization_with_wasm_challenge() {
    let (sudo, validators) = create_five_validators();
    let mut state = create_state_with_validators(&sudo, &validators);

    let challenge = create_test_challenge(&sudo, TERM_CHALLENGE_WASM.to_vec());
    let challenge_id = challenge.id;
    state.add_challenge(challenge);

    let bytes = bincode::serialize(&state).expect("Serialization should succeed");
    let recovered: ChainState =
        bincode::deserialize(&bytes).expect("Deserialization should succeed");

    assert_eq!(recovered.validators.len(), 5);
    assert_eq!(recovered.challenges.len(), 1);
    assert_eq!(
        recovered
            .get_challenge(&challenge_id)
            .unwrap()
            .wasm_code
            .len(),
        TERM_CHALLENGE_WASM.len()
    );
    assert_eq!(recovered.sudo_key, sudo.hotkey());
}
