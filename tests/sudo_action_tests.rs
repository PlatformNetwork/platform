//! Tests for SudoAction operations and blockchain halt functionality.
//!
//! These tests verify:
//! - Emergency controls (EmergencyPause, Resume)
//! - Signature verification for sudo operations
//! - Version management
//! - Weight and validator management

use platform_core::{
    is_production_sudo, production_sudo_key, ChainState, ChallengeId, Hotkey, Keypair,
    NetworkConfig, NetworkMessage, ProposalAction, SignedNetworkMessage, Stake, SudoAction,
    ValidatorInfo, SUDO_KEY_BYTES,
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Create a test ChainState with a custom sudo key
fn create_test_state_with_sudo(sudo_keypair: &Keypair) -> ChainState {
    ChainState::new(sudo_keypair.hotkey(), NetworkConfig::default())
}

/// Create a test ChainState with production sudo key
fn create_production_state() -> ChainState {
    ChainState::new_production(NetworkConfig::default())
}

// ============================================================================
// SUDO KEY AUTHORIZATION TESTS
// ============================================================================

#[test]
fn test_only_sudo_can_perform_actions() {
    let sudo_kp = Keypair::generate();
    let non_sudo_kp = Keypair::generate();
    let state = create_test_state_with_sudo(&sudo_kp);

    // Verify sudo key is recognized
    assert!(
        state.is_sudo(&sudo_kp.hotkey()),
        "Sudo keypair should be recognized as sudo"
    );

    // Verify non-sudo key is rejected
    assert!(
        !state.is_sudo(&non_sudo_kp.hotkey()),
        "Non-sudo keypair should not be recognized as sudo"
    );

    // The actual authorization check is done at the network layer
    // where SignedNetworkMessage.signer() is checked against state.sudo_key
}

// ============================================================================
// EMERGENCY CONTROLS TESTS
// ============================================================================

/// Simulated pause state for testing
struct PausedState {
    is_paused: bool,
    pause_reason: Option<String>,
}

impl PausedState {
    fn new() -> Self {
        Self {
            is_paused: false,
            pause_reason: None,
        }
    }

    fn pause(&mut self, reason: String) {
        self.is_paused = true;
        self.pause_reason = Some(reason);
    }

    fn resume(&mut self) {
        self.is_paused = false;
        self.pause_reason = None;
    }
}

#[test]
fn test_emergency_pause_halts_operations() {
    let mut paused_state = PausedState::new();

    // Initially not paused
    assert!(!paused_state.is_paused);

    // Create EmergencyPause action
    let action = SudoAction::EmergencyPause {
        reason: "Security vulnerability detected".to_string(),
    };

    // Apply pause
    if let SudoAction::EmergencyPause { reason } = action {
        paused_state.pause(reason);
    }

    // Verify paused
    assert!(paused_state.is_paused);
    assert_eq!(
        paused_state.pause_reason,
        Some("Security vulnerability detected".to_string())
    );
}

#[test]
fn test_resume_restores_operations() {
    let mut paused_state = PausedState::new();

    // First pause
    paused_state.pause("Test pause".to_string());
    assert!(paused_state.is_paused);

    // Create Resume action
    let action = SudoAction::Resume;

    // Apply resume
    if let SudoAction::Resume = action {
        paused_state.resume();
    }

    // Verify resumed
    assert!(!paused_state.is_paused);
    assert!(paused_state.pause_reason.is_none());
}

#[test]
fn test_emergency_pause_requires_sudo() {
    let sudo_kp = Keypair::generate();
    let non_sudo_kp = Keypair::generate();
    let state = create_test_state_with_sudo(&sudo_kp);

    // Create signed EmergencyPause message from sudo key
    let pause_action = SudoAction::EmergencyPause {
        reason: "Test".to_string(),
    };
    let msg = NetworkMessage::SudoAction(pause_action);
    let signed_sudo =
        SignedNetworkMessage::new(msg.clone(), &sudo_kp).expect("Should sign message");

    // Verify signature is valid
    assert!(signed_sudo.verify().unwrap());

    // Verify signer is sudo
    assert!(state.is_sudo(signed_sudo.signer()));

    // Create signed message from non-sudo key
    let non_sudo_msg = NetworkMessage::SudoAction(SudoAction::EmergencyPause {
        reason: "Unauthorized".to_string(),
    });
    let signed_non_sudo =
        SignedNetworkMessage::new(non_sudo_msg, &non_sudo_kp).expect("Should sign message");

    // Signature is valid but signer is not sudo
    assert!(signed_non_sudo.verify().unwrap());
    assert!(!state.is_sudo(signed_non_sudo.signer()));
}

#[test]
fn test_pause_reason_is_recorded() {
    let action = SudoAction::EmergencyPause {
        reason: "Critical bug in scoring algorithm".to_string(),
    };

    match action {
        SudoAction::EmergencyPause { reason } => {
            assert_eq!(reason, "Critical bug in scoring algorithm");
            assert!(!reason.is_empty());
        }
        _ => panic!("Expected EmergencyPause action"),
    }
}

// ============================================================================
// SIGNATURE VERIFICATION TESTS
// ============================================================================

#[test]
fn test_sudo_action_signed_by_sudo_key_accepted() {
    let sudo_kp = Keypair::generate();
    let state = create_test_state_with_sudo(&sudo_kp);

    // Create sudo action
    let action = SudoAction::UpdateConfig {
        config: NetworkConfig::default(),
    };
    let msg = NetworkMessage::SudoAction(action);

    // Sign with sudo key
    let signed = SignedNetworkMessage::new(msg, &sudo_kp).expect("Should sign");

    // Verify signature
    assert!(signed.verify().unwrap(), "Signature should be valid");

    // Verify signer is sudo
    assert!(
        state.is_sudo(signed.signer()),
        "Signer should be recognized as sudo"
    );
}

#[test]
fn test_sudo_action_signed_by_non_sudo_rejected() {
    let sudo_kp = Keypair::generate();
    let non_sudo_kp = Keypair::generate();
    let state = create_test_state_with_sudo(&sudo_kp);

    // Create sudo action
    let action = SudoAction::AddValidator {
        info: ValidatorInfo::new(non_sudo_kp.hotkey(), Stake::new(10_000_000_000)),
    };
    let msg = NetworkMessage::SudoAction(action);

    // Sign with non-sudo key
    let signed = SignedNetworkMessage::new(msg, &non_sudo_kp).expect("Should sign");

    // Signature is technically valid
    assert!(signed.verify().unwrap(), "Signature should be valid");

    // But signer is NOT sudo
    assert!(
        !state.is_sudo(signed.signer()),
        "Non-sudo signer should be rejected"
    );
}

#[test]
fn test_sudo_action_invalid_signature_rejected() {
    let sudo_kp = Keypair::generate();

    // Create sudo action and sign it
    let action = SudoAction::Resume;
    let msg = NetworkMessage::SudoAction(action);
    let mut signed = SignedNetworkMessage::new(msg, &sudo_kp).expect("Should sign");

    // Tamper with the signature
    if !signed.signature.signature.is_empty() {
        signed.signature.signature[0] ^= 0xFF; // Flip bits
    }

    // Verification should fail
    let result = signed.verify();
    // After tampering, verify should return false or error
    if let Ok(valid) = result {
        assert!(!valid, "Tampered signature should not verify");
    }
}

#[test]
fn test_production_sudo_key_recognized() {
    let state = create_production_state();

    // Get production sudo key
    let prod_sudo = production_sudo_key();

    // Verify it's recognized
    assert!(state.is_sudo(&prod_sudo));
    assert!(is_production_sudo(&prod_sudo));

    // Verify raw bytes match
    assert_eq!(prod_sudo.0, SUDO_KEY_BYTES);
}

#[test]
fn test_proposal_action_sudo_variant() {
    let sudo_action = SudoAction::EmergencyPause {
        reason: "Testing proposal".to_string(),
    };

    let proposal = ProposalAction::Sudo(sudo_action);

    match proposal {
        ProposalAction::Sudo(SudoAction::EmergencyPause { reason }) => {
            assert_eq!(reason, "Testing proposal");
        }
        _ => panic!("Expected Sudo(EmergencyPause)"),
    }
}

// ============================================================================
// SUDO ACTION SERIALIZATION TESTS
// ============================================================================

#[test]
fn test_sudo_action_serialization_roundtrip() {
    let actions = vec![
        SudoAction::EmergencyPause {
            reason: "Test pause".to_string(),
        },
        SudoAction::Resume,
        SudoAction::SetEmission {
            challenge_id: ChallengeId::new("test-challenge"),
            emission_weight: 0.5,
        },
    ];

    for action in actions {
        // Serialize
        let bytes = bincode::serialize(&action).expect("Should serialize");

        // Deserialize
        let recovered: SudoAction = bincode::deserialize(&bytes).expect("Should deserialize");

        // Verify match
        match (&action, &recovered) {
            (
                SudoAction::EmergencyPause { reason: r1 },
                SudoAction::EmergencyPause { reason: r2 },
            ) => assert_eq!(r1, r2),
            (SudoAction::Resume, SudoAction::Resume) => {}
            (
                SudoAction::SetEmission {
                    challenge_id: c1,
                    emission_weight: w1,
                },
                SudoAction::SetEmission {
                    challenge_id: c2,
                    emission_weight: w2,
                },
            ) => {
                assert_eq!(c1, c2);
                assert_eq!(w1, w2);
            }
            _ => panic!("Serialization roundtrip produced different variant"),
        }
    }
}

// ============================================================================
// SIGNED NETWORK MESSAGE TESTS FOR SUDO
// ============================================================================

#[test]
fn test_signed_sudo_message_contains_signer_info() {
    let sudo_kp = Keypair::generate();

    let action = SudoAction::EmergencyPause {
        reason: "Signed Challenge".to_string(),
    };
    let msg = NetworkMessage::SudoAction(action);
    let signed = SignedNetworkMessage::new(msg, &sudo_kp).expect("Should sign");

    // Verify signer is captured
    assert_eq!(signed.signer(), &sudo_kp.hotkey());

    // Verify message is accessible
    match &signed.message {
        NetworkMessage::SudoAction(SudoAction::EmergencyPause { reason }) => {
            assert_eq!(reason, "Signed Challenge");
        }
        _ => panic!("Expected SudoAction(EmergencyPause)"),
    }
}

#[test]
fn test_all_sudo_action_variants_can_be_signed() {
    let kp = Keypair::generate();

    let actions: Vec<SudoAction> = vec![
        SudoAction::UpdateConfig {
            config: NetworkConfig::default(),
        },
        SudoAction::SetEmission {
            challenge_id: ChallengeId::new("test-challenge"),
            emission_weight: 0.5,
        },
        SudoAction::SetRequiredVersion {
            min_version: "0.1.0".to_string(),
            recommended_version: "0.2.0".to_string(),
            mandatory: false,
            deadline_block: None,
            release_notes: None,
        },
        SudoAction::AddValidator {
            info: ValidatorInfo::new(kp.hotkey(), Stake::new(10_000_000_000)),
        },
        SudoAction::RemoveValidator {
            hotkey: kp.hotkey(),
        },
        SudoAction::EmergencyPause {
            reason: "Test".to_string(),
        },
        SudoAction::Resume,
        SudoAction::ForceStateUpdate {
            state: ChainState::default(),
        },
    ];

    for action in actions {
        let msg = NetworkMessage::SudoAction(action);
        let signed = SignedNetworkMessage::new(msg, &kp);
        assert!(signed.is_ok(), "Failed to sign SudoAction variant");

        let signed = signed.unwrap();
        assert!(signed.verify().unwrap(), "Signature verification failed");
    }
}

// ============================================================================
// CHAIN STATE SUDO KEY TESTS
// ============================================================================

#[test]
fn test_chain_state_is_sudo_method() {
    let sudo_kp = Keypair::generate();
    let other_kp = Keypair::generate();
    let state = create_test_state_with_sudo(&sudo_kp);

    assert!(state.is_sudo(&sudo_kp.hotkey()));
    assert!(!state.is_sudo(&other_kp.hotkey()));
    assert!(!state.is_sudo(&Hotkey([0u8; 32])));
}

#[test]
fn test_chain_state_sudo_key_immutable() {
    let sudo_kp = Keypair::generate();
    let state = create_test_state_with_sudo(&sudo_kp);

    // Sudo key should remain constant
    let original_sudo = state.sudo_key.clone();

    // After various operations
    let mut state = state;
    state.increment_block();
    state.update_hash();

    // Sudo key unchanged
    assert_eq!(state.sudo_key, original_sudo);
}

// ============================================================================
// FORCE STATE UPDATE TESTS
// ============================================================================

#[test]
fn test_force_state_update_action() {
    let sudo_kp = Keypair::generate();
    let mut recovery_state = ChainState::new(sudo_kp.hotkey(), NetworkConfig::default());
    recovery_state.block_height = 1000;

    let action = SudoAction::ForceStateUpdate {
        state: recovery_state.clone(),
    };

    match action {
        SudoAction::ForceStateUpdate { state } => {
            assert_eq!(state.block_height, 1000);
            assert!(state.is_sudo(&sudo_kp.hotkey()));
        }
        _ => panic!("Expected ForceStateUpdate"),
    }
}

// ============================================================================
// CHALLENGE WEIGHT ALLOCATION TESTS
// ============================================================================

#[test]
fn test_set_emission_action() {
    let challenge_id = ChallengeId::new("test-challenge");

    let action = SudoAction::SetEmission {
        challenge_id: challenge_id.clone(),
        emission_weight: 0.75,
    };

    match action {
        SudoAction::SetEmission {
            challenge_id: cid,
            emission_weight,
        } => {
            assert_eq!(cid, challenge_id);
            assert_eq!(emission_weight, 0.75);
        }
        _ => panic!("Expected SetEmission"),
    }
}

// ============================================================================
// VERSION MANAGEMENT TESTS
// ============================================================================

#[test]
fn test_set_required_version_action() {
    let action = SudoAction::SetRequiredVersion {
        min_version: "0.2.0".to_string(),
        recommended_version: "0.3.0".to_string(),
        mandatory: true,
        deadline_block: Some(50000),
        release_notes: Some("Security patches and performance improvements".to_string()),
    };

    match action {
        SudoAction::SetRequiredVersion {
            min_version,
            recommended_version,
            mandatory,
            deadline_block,
            release_notes,
        } => {
            assert_eq!(min_version, "0.2.0");
            assert_eq!(recommended_version, "0.3.0");
            assert!(mandatory);
            assert_eq!(deadline_block, Some(50000));
            assert!(release_notes.is_some());
        }
        _ => panic!("Expected SetRequiredVersion"),
    }
}

#[test]
fn test_sudo_remove_validator_action() {
    let validator_kp = Keypair::generate();

    let action = SudoAction::RemoveValidator {
        hotkey: validator_kp.hotkey(),
    };

    match action {
        SudoAction::RemoveValidator { hotkey } => {
            assert_eq!(hotkey, validator_kp.hotkey());
        }
        _ => panic!("Expected RemoveValidator"),
    }
}

// ============================================================================
// CONFIG UPDATE TESTS
// ============================================================================

#[test]
fn test_sudo_update_config_action() {
    let config = NetworkConfig {
        max_validators: 64,
        consensus_threshold: 0.67,
        ..Default::default()
    };

    let action = SudoAction::UpdateConfig {
        config: config.clone(),
    };

    match action {
        SudoAction::UpdateConfig { config: updated } => {
            assert_eq!(updated.max_validators, 64);
            assert_eq!(updated.consensus_threshold, 0.67);
        }
        _ => panic!("Expected UpdateConfig"),
    }
}
