//! Exhaustive Error Case Tests
//!
//! These tests verify that all error conditions are properly handled.

#![allow(clippy::field_reassign_with_default)]

use parking_lot::RwLock;
use platform_consensus::*;
use platform_core::*;
use platform_storage::*;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::mpsc;

// ============================================================================
// CORE ERROR CASES
// ============================================================================

mod core_errors {
    use super::*;

    #[test]
    fn test_hotkey_from_bytes_too_short() {
        let short = vec![1u8; 16];
        assert!(Hotkey::from_bytes(&short).is_none());
    }

    #[test]
    fn test_hotkey_from_bytes_too_long() {
        let long = vec![1u8; 64];
        assert!(Hotkey::from_bytes(&long).is_none());
    }

    #[test]
    fn test_hotkey_from_bytes_empty() {
        assert!(Hotkey::from_bytes(&[]).is_none());
    }

    #[test]
    fn test_hotkey_from_hex_invalid() {
        assert!(Hotkey::from_hex("not_valid_hex").is_none());
        assert!(Hotkey::from_hex("").is_none());
        assert!(Hotkey::from_hex("zzzz").is_none());
    }

    #[test]
    fn test_hotkey_from_hex_wrong_length() {
        assert!(Hotkey::from_hex("0102030405").is_none());
    }

    #[test]
    fn test_signature_invalid_length() {
        let signed = SignedMessage {
            message: b"test".to_vec(),
            signature: vec![0u8; 32], // Wrong length
            signer: Hotkey([0u8; 32]),
        };
        assert!(signed.verify().is_err());
    }

    #[test]
    fn test_signature_corrupted() {
        let kp = Keypair::generate();
        let mut signed = kp.sign(b"test message");
        signed.signature[0] ^= 0xFF;
        signed.signature[32] ^= 0xFF;
        assert!(!signed.verify().unwrap());
    }

    #[test]
    fn test_signature_wrong_message() {
        let kp = Keypair::generate();
        let mut signed = kp.sign(b"original message");
        signed.message = b"different message".to_vec();
        assert!(!signed.verify().unwrap());
    }

    #[test]
    fn test_score_negative_values() {
        let score = Score::new(-1.0, -1.0);
        assert_eq!(score.value, 0.0);
        assert_eq!(score.weight, 0.0);
    }

    #[test]
    fn test_score_overflow_values() {
        let score = Score::new(1000.0, 1000.0);
        assert_eq!(score.value, 1.0);
        assert_eq!(score.weight, 1.0);
    }

    #[test]
    fn test_challenge_id_from_invalid_uuid() {
        let id1 = ChallengeId::from_string("not-a-uuid");
        let id2 = ChallengeId::from_string("not-a-uuid");
        assert_eq!(id1, id2);
    }
}

// ============================================================================
// STATE ERROR CASES
// ============================================================================

mod state_errors {
    use super::*;

    #[test]
    fn test_add_validator_max_reached() {
        let sudo = Keypair::generate();
        let mut config = NetworkConfig::default();
        config.max_validators = 2;

        let mut state = ChainState::new(sudo.hotkey(), config);

        for _ in 0..2 {
            let kp = Keypair::generate();
            let info = ValidatorInfo::new(kp.hotkey(), Stake::new(10_000_000_000));
            assert!(state.add_validator(info).is_ok());
        }

        let kp = Keypair::generate();
        let info = ValidatorInfo::new(kp.hotkey(), Stake::new(10_000_000_000));
        assert!(state.add_validator(info).is_err());
    }

    #[test]
    fn test_add_validator_insufficient_stake() {
        let sudo = Keypair::generate();
        let mut config = NetworkConfig::default();
        config.min_stake = Stake::new(1_000_000_000_000);

        let mut state = ChainState::new(sudo.hotkey(), config);

        let kp = Keypair::generate();
        let info = ValidatorInfo::new(kp.hotkey(), Stake::new(100));
        assert!(state.add_validator(info).is_err());
    }

    #[test]
    fn test_remove_nonexistent_validator() {
        let sudo = Keypair::generate();
        let mut state = ChainState::new(sudo.hotkey(), NetworkConfig::default());

        let kp = Keypair::generate();
        let removed = state.remove_validator(&kp.hotkey());
        assert!(removed.is_none());
    }

    #[test]
    fn test_get_nonexistent_validator() {
        let sudo = Keypair::generate();
        let state = ChainState::new(sudo.hotkey(), NetworkConfig::default());

        let kp = Keypair::generate();
        assert!(state.get_validator(&kp.hotkey()).is_none());
    }

    #[test]
    fn test_get_nonexistent_challenge() {
        let sudo = Keypair::generate();
        let state = ChainState::new(sudo.hotkey(), NetworkConfig::default());
        assert!(state.get_challenge(&ChallengeId::new()).is_none());
    }

    #[test]
    fn test_remove_nonexistent_challenge() {
        let sudo = Keypair::generate();
        let mut state = ChainState::new(sudo.hotkey(), NetworkConfig::default());
        let removed = state.remove_challenge(&ChallengeId::new());
        assert!(removed.is_none());
    }

    #[test]
    fn test_claim_job_empty_queue() {
        let sudo = Keypair::generate();
        let mut state = ChainState::new(sudo.hotkey(), NetworkConfig::default());

        let validator = Keypair::generate();
        assert!(state.claim_job(&validator.hotkey()).is_none());
    }

    #[test]
    fn test_is_sudo_wrong_key() {
        let sudo = Keypair::generate();
        let state = ChainState::new(sudo.hotkey(), NetworkConfig::default());

        let not_sudo = Keypair::generate();
        assert!(!state.is_sudo(&not_sudo.hotkey()));
    }

    #[test]
    fn test_consensus_threshold_zero_validators() {
        let sudo = Keypair::generate();
        let state = ChainState::new(sudo.hotkey(), NetworkConfig::default());
        assert_eq!(state.consensus_threshold(), 0);
    }

    #[test]
    fn test_total_stake_empty() {
        let sudo = Keypair::generate();
        let state = ChainState::new(sudo.hotkey(), NetworkConfig::default());
        assert_eq!(state.total_stake().0, 0);
    }
}

// ============================================================================
// CONSENSUS ERROR CASES
// ============================================================================

mod consensus_errors {
    use super::*;

    #[tokio::test]
    async fn test_propose_sudo_not_authorized() {
        let sudo = Keypair::generate();
        let not_sudo = Keypair::generate();

        let state = Arc::new(RwLock::new(ChainState::new(
            sudo.hotkey(),
            NetworkConfig::default(),
        )));

        let (tx, _rx) = mpsc::channel(100);
        let engine = PBFTEngine::new(not_sudo, Arc::clone(&state), tx);

        let action = SudoAction::UpdateConfig {
            config: NetworkConfig::default(),
        };

        let result = engine.propose_sudo(action).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_proposal_wrong_signer() {
        let sudo = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            sudo.hotkey(),
            NetworkConfig::default(),
        )));

        let (tx, _rx) = mpsc::channel(100);
        let engine = PBFTEngine::new(sudo.clone(), Arc::clone(&state), tx);

        let other = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            other.hotkey(),
            0,
        );

        let result = engine.handle_proposal(proposal, &sudo.hotkey()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_vote_wrong_signer() {
        let sudo = Keypair::generate();
        let voter = Keypair::generate();
        let wrong_signer = Keypair::generate();

        let state = Arc::new(RwLock::new(ChainState::new(
            sudo.hotkey(),
            NetworkConfig::default(),
        )));

        state
            .write()
            .add_validator(ValidatorInfo::new(
                voter.hotkey(),
                Stake::new(10_000_000_000),
            ))
            .unwrap();

        let (tx, _rx) = mpsc::channel(100);
        let engine = PBFTEngine::new(sudo, Arc::clone(&state), tx);
        engine.sync_validators();

        let vote = Vote::approve(uuid::Uuid::new_v4(), voter.hotkey());
        let result = engine.handle_vote(vote, &wrong_signer.hotkey()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_vote_non_validator() {
        let sudo = Keypair::generate();
        let non_validator = Keypair::generate();

        let state = Arc::new(RwLock::new(ChainState::new(
            sudo.hotkey(),
            NetworkConfig::default(),
        )));

        let (tx, _rx) = mpsc::channel(100);
        let engine = PBFTEngine::new(sudo, Arc::clone(&state), tx);

        let vote = Vote::approve(uuid::Uuid::new_v4(), non_validator.hotkey());
        let result = engine.handle_vote(vote, &non_validator.hotkey()).await;
        assert!(result.is_ok()); // Silently ignored
    }

    #[test]
    fn test_round_timeout() {
        let config = ConsensusConfig {
            threshold: 0.5,
            round_timeout_secs: 0,
            max_rounds: 10,
        };

        let state = ConsensusState::new(config);
        state.set_validator_count(4);

        let proposer = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            proposer.hotkey(),
            0,
        );

        let id = state.start_round(proposal);
        std::thread::sleep(std::time::Duration::from_millis(10));

        let timeouts = state.check_timeouts();
        assert_eq!(timeouts.len(), 1);
        assert!(!state.is_pending(&id));
    }

    #[test]
    fn test_votes_per_validator() {
        let config = ConsensusConfig::default();
        let state = ConsensusState::new(config);
        state.set_validator_count(10);

        let proposer = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            proposer.hotkey(),
            0,
        );

        let id = state.start_round(proposal);

        // First voter approves
        let voter1 = Keypair::generate();
        state.add_vote(Vote::approve(id, voter1.hotkey()));

        // Second voter rejects
        let voter2 = Keypair::generate();
        state.add_vote(Vote::reject(id, voter2.hotkey()));

        // Check the round state
        if let Some(round) = state.get_round(&id) {
            // Should have 2 total votes
            assert_eq!(round.approve_count(), 1);
            assert_eq!(round.reject_count(), 1);
            assert_eq!(round.votes.len(), 2);
        }
    }
}

// ============================================================================
// STORAGE ERROR CASES
// ============================================================================

mod storage_errors {
    use super::*;

    #[test]
    fn test_load_nonexistent_state() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let loaded = storage.load_state().unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_load_nonexistent_challenge() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let loaded = storage.load_challenge(&ChallengeId::new()).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_load_nonexistent_validator() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let kp = Keypair::generate();
        let loaded = storage.load_validator(&kp.hotkey()).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_delete_nonexistent_challenge() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let deleted = storage.delete_challenge(&ChallengeId::new()).unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_list_challenges_empty() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let challenges = storage.list_challenges().unwrap();
        assert!(challenges.is_empty());
    }
}

// ============================================================================
// MESSAGE ERROR CASES
// ============================================================================

mod message_errors {
    use super::*;

    #[test]
    fn test_signed_message_tampering() {
        let kp = Keypair::generate();
        let mut signed = kp.sign(b"original message");
        signed.message = b"tampered message".to_vec();
        assert!(!signed.verify().unwrap());
    }

    #[test]
    fn test_signed_message_signature_tampering() {
        let kp = Keypair::generate();
        let mut signed = kp.sign(b"test message");
        // SignedMessage has signature as Vec<u8>
        if !signed.signature.is_empty() {
            signed.signature[0] ^= 0xFF;
        }
        assert!(!signed.verify().unwrap());
    }

    #[test]
    fn test_signed_message_signer_tampering() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let mut signed = kp1.sign(b"test");
        signed.signer = kp2.hotkey();
        assert!(!signed.verify().unwrap());
    }
}

// ============================================================================
// CRYPTO ERROR CASES
// ============================================================================

mod crypto_errors {
    use super::*;

    #[test]
    fn test_hash_empty_data() {
        let h1 = hash(b"");
        let h2 = hash(b"");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn test_signature_empty_message() {
        let kp = Keypair::generate();
        let signed = kp.sign(b"");
        assert!(signed.verify().unwrap());
    }

    #[test]
    fn test_signature_large_message() {
        let kp = Keypair::generate();
        let large = vec![0xAB; 1024 * 1024];
        let signed = kp.sign(&large);
        assert!(signed.verify().unwrap());
    }
}

// ============================================================================
// EDGE CASES
// ============================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn test_stake_zero() {
        let stake = Stake::new(0);
        assert_eq!(stake.as_tao(), 0.0);
    }

    #[test]
    fn test_stake_max() {
        let stake = Stake::new(u64::MAX);
        assert!(stake.as_tao() > 0.0);
    }

    #[test]
    fn test_block_height_max() {
        let sudo = Keypair::generate();
        let mut state = ChainState::new(sudo.hotkey(), NetworkConfig::default());
        state.block_height = u64::MAX - 1;
        state.increment_block();
        assert_eq!(state.block_height, u64::MAX);
    }

    #[test]
    fn test_epoch_max() {
        let sudo = Keypair::generate();
        let mut state = ChainState::new(sudo.hotkey(), NetworkConfig::default());
        state.epoch = u64::MAX;
        let _ = state.snapshot(); // Should not panic
    }

    #[test]
    fn test_empty_validators_consensus() {
        let config = ConsensusConfig::default();
        let state = ConsensusState::new(config);
        state.set_validator_count(0);
        assert_eq!(state.threshold(), 0);
    }

    #[test]
    fn test_single_validator_consensus() {
        let config = ConsensusConfig::default();
        let state = ConsensusState::new(config);
        state.set_validator_count(1);
        assert_eq!(state.threshold(), 1);

        let proposer = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            proposer.hotkey(),
            0,
        );

        let id = state.start_round(proposal);
        let result = state.add_vote(Vote::approve(id, proposer.hotkey()));
        assert!(matches!(result, Some(ConsensusResult::Approved(_))));
    }

    #[test]
    fn test_challenge_empty_code() {
        let kp = Keypair::generate();
        let challenge = Challenge::new(
            "Empty".into(),
            "Description".into(),
            vec![],
            kp.hotkey(),
            ChallengeConfig::default(),
        );
        assert!(!challenge.code_hash.is_empty());
    }

    #[test]
    fn test_job_status_transitions() {
        let challenge_id = ChallengeId::new();
        let mut job = Job::new(challenge_id, "agent1".into());

        assert_eq!(job.status, JobStatus::Pending);

        job.status = JobStatus::Running;
        assert_eq!(job.status, JobStatus::Running);

        job.status = JobStatus::Completed;
        job.result = Some(Score::new(0.95, 1.0));
        assert_eq!(job.status, JobStatus::Completed);

        let mut failed_job = Job::new(challenge_id, "agent2".into());
        failed_job.status = JobStatus::Failed;
        assert_eq!(failed_job.status, JobStatus::Failed);

        let mut timeout_job = Job::new(challenge_id, "agent3".into());
        timeout_job.status = JobStatus::Timeout;
        assert_eq!(timeout_job.status, JobStatus::Timeout);
    }

    #[test]
    fn test_validator_inactive_not_counted() {
        let sudo = Keypair::generate();
        let mut state = ChainState::new(sudo.hotkey(), NetworkConfig::default());

        // Add active validator
        let kp1 = Keypair::generate();
        state
            .add_validator(ValidatorInfo::new(kp1.hotkey(), Stake::new(10_000_000_000)))
            .unwrap();

        // Add inactive validator
        let kp2 = Keypair::generate();
        let mut info2 = ValidatorInfo::new(kp2.hotkey(), Stake::new(10_000_000_000));
        info2.is_active = false;
        state.validators.insert(kp2.hotkey(), info2);

        assert_eq!(state.validators.len(), 2);
        assert_eq!(state.active_validators().len(), 1);
    }
}
