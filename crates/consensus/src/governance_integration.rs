//! Integration Layer for Stake-Based Governance
//!
//! This module provides the integration between the stake-based governance system
//! and the existing PBFT consensus and validator sync mechanisms.
//!
//! # Usage Flow
//! 1. Validator sync updates metagraph data (stakes)
//! 2. Governance engine receives updated stakes
//! 3. When a SudoAction is received:
//!    a. Check if in bootstrap period -> execute directly if owner
//!    b. Otherwise, create/vote on proposal requiring 50%+ stake
//! 4. Approved proposals trigger actual state changes

use crate::{
    stake_governance::{
        GovernanceActionType, GovernanceProposal, GovernanceStatus, HybridGovernance,
        StakeConsensusResult, StakeGovernance, ValidatorStake, BOOTSTRAP_END_BLOCK,
        STAKE_THRESHOLD_PERCENT,
    },
    PBFTEngine,
};
use parking_lot::RwLock;
use platform_core::{
    ChainState, Hotkey, Keypair, MiniChainError, Result, Stake, SudoAction, ValidatorInfo,
};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Governance-aware PBFT engine that enforces stake consensus for chain modifications
pub struct GovernancePBFT {
    /// Standard PBFT engine
    pbft: Arc<PBFTEngine>,
    /// Hybrid governance (bootstrap + stake consensus)
    governance: Arc<HybridGovernance>,
    /// Chain state reference
    chain_state: Arc<RwLock<ChainState>>,
    /// Local keypair
    keypair: Keypair,
}

impl GovernancePBFT {
    /// Create a new governance-aware PBFT engine
    pub fn new(
        pbft: Arc<PBFTEngine>,
        chain_state: Arc<RwLock<ChainState>>,
        keypair: Keypair,
    ) -> Self {
        let stake_gov = Arc::new(StakeGovernance::new());
        let hybrid = Arc::new(HybridGovernance::new(stake_gov));

        Self {
            pbft,
            governance: hybrid,
            chain_state,
            keypair,
        }
    }

    /// Update block height in governance engine
    pub fn set_block_height(&self, block: u64) {
        self.governance.stake_governance().set_block_height(block);
    }

    /// Update validator stakes from metagraph sync
    pub fn update_stakes_from_metagraph(&self, validators: &[ValidatorInfo]) {
        let stakes: Vec<ValidatorStake> = validators
            .iter()
            .map(|v| ValidatorStake {
                hotkey: v.hotkey.clone(),
                stake: v.stake,
                is_active: v.is_active,
                last_updated: chrono::Utc::now(),
            })
            .collect();

        self.governance
            .stake_governance()
            .update_validator_stakes(stakes);

        info!(
            "Updated governance with {} validator stakes",
            validators.len()
        );
    }

    /// Execute a sudo action with governance authorization
    /// During bootstrap: owner can execute directly
    /// After bootstrap: requires creating a proposal for stake consensus
    pub async fn execute_sudo_action(&self, action: SudoAction) -> Result<SudoExecutionResult> {
        let requester = self.keypair.hotkey();
        let action_type = sudo_action_to_governance_type(&action);

        // Check bootstrap authority first
        if self.governance.stake_governance().is_bootstrap_period() {
            if crate::stake_governance::is_subnet_owner(&requester) {
                info!(
                    "Bootstrap mode: Executing {:?} directly from owner",
                    action_type
                );
                // Execute via normal PBFT
                let proposal_id = self.pbft.propose_sudo(action).await?;
                return Ok(SudoExecutionResult::ExecutedBootstrap { proposal_id });
            } else {
                return Err(MiniChainError::Unauthorized(format!(
                    "During bootstrap (until block {}), only subnet owner can execute sudo actions",
                    BOOTSTRAP_END_BLOCK
                )));
            }
        }

        // After bootstrap, need stake consensus
        self.create_governance_proposal(action).await
    }

    /// Create a governance proposal for stake-based voting
    async fn create_governance_proposal(&self, action: SudoAction) -> Result<SudoExecutionResult> {
        let action_type = sudo_action_to_governance_type(&action);
        let title = generate_proposal_title(&action);
        let description = generate_proposal_description(&action);
        let action_data = bincode::serialize(&action)?;

        let proposal = self.governance.stake_governance().create_proposal(
            action_type.clone(),
            title,
            description,
            action_data,
            &self.keypair.hotkey(),
            &self.keypair,
        )?;

        info!(
            "Created governance proposal {} for {:?}",
            proposal.id, action_type
        );

        // Automatically vote YES from proposer
        let result = self.governance.stake_governance().vote(
            proposal.id,
            &self.keypair.hotkey(),
            true,
            &self.keypair,
        )?;

        Ok(SudoExecutionResult::ProposalCreated {
            proposal_id: proposal.id,
            initial_result: result,
        })
    }

    /// Vote on a pending governance proposal
    pub fn vote_on_proposal(
        &self,
        proposal_id: uuid::Uuid,
        approve: bool,
    ) -> Result<StakeConsensusResult> {
        let result = self.governance.stake_governance().vote(
            proposal_id,
            &self.keypair.hotkey(),
            approve,
            &self.keypair,
        )?;

        // If approved, execute the proposal
        if let StakeConsensusResult::Approved { ref proposal, .. } = result {
            self.execute_approved_proposal(proposal)?;
        }

        Ok(result)
    }

    /// Execute an approved proposal
    fn execute_approved_proposal(&self, proposal: &GovernanceProposal) -> Result<()> {
        // Deserialize the action
        let action: SudoAction = bincode::deserialize(&proposal.action_data)?;

        info!(
            "Executing approved proposal {} ({:?})",
            proposal.id, proposal.action_type
        );

        // Apply the action to chain state
        let mut state = self.chain_state.write();
        apply_sudo_action(&mut state, &action)?;

        // Mark as executed
        self.governance
            .stake_governance()
            .mark_executed(proposal.id)?;

        Ok(())
    }

    /// Get current governance status
    pub fn governance_status(&self) -> GovernanceStatus {
        self.governance.stake_governance().status()
    }

    /// Get all active proposals
    pub fn active_proposals(&self) -> Vec<GovernanceProposal> {
        self.governance.stake_governance().active_proposals()
    }

    /// Check if current validator can use bootstrap authority
    pub fn can_use_bootstrap(&self) -> bool {
        self.governance
            .stake_governance()
            .can_use_bootstrap(&self.keypair.hotkey())
    }

    /// Get stake required for consensus
    pub fn stake_for_consensus(&self) -> (Stake, f64) {
        let total = self.governance.stake_governance().total_stake();
        let threshold = STAKE_THRESHOLD_PERCENT;
        let required = Stake(((total.0 as f64 * threshold) / 100.0) as u64);
        (required, threshold)
    }
}

/// Result of sudo action execution
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SudoExecutionResult {
    /// Executed directly during bootstrap period
    ExecutedBootstrap { proposal_id: uuid::Uuid },
    /// Proposal created, awaiting stake consensus
    ProposalCreated {
        proposal_id: uuid::Uuid,
        initial_result: StakeConsensusResult,
    },
}

/// Convert SudoAction to GovernanceActionType
///
/// Note: Some SudoActions are intentionally mapped to the same GovernanceActionType
/// for governance classification and rate-limiting purposes:
/// - `SetMechanismConfig` → `SetMechanismBurnRate` (both are mechanism parameter changes)
/// - `RefreshChallenges` → `UpdateChallenge` (both affect challenge state)
///
/// This aliasing is intentional to group related actions. If per-action visibility
/// or separate rate limits are needed in the future, add new GovernanceActionType variants.
fn sudo_action_to_governance_type(action: &SudoAction) -> GovernanceActionType {
    match action {
        SudoAction::UpdateConfig { .. } => GovernanceActionType::UpdateConfig,
        SudoAction::AddChallenge { .. } => GovernanceActionType::AddChallenge,
        SudoAction::UpdateChallenge { .. } => GovernanceActionType::UpdateChallenge,
        SudoAction::RemoveChallenge { .. } => GovernanceActionType::RemoveChallenge,
        SudoAction::SetChallengeWeight { .. } => GovernanceActionType::SetChallengeWeight,
        SudoAction::SetMechanismBurnRate { .. } => GovernanceActionType::SetMechanismBurnRate,
        // Intentional aliasing: mechanism config changes grouped with burn rate changes
        SudoAction::SetMechanismConfig { .. } => GovernanceActionType::SetMechanismBurnRate,
        SudoAction::SetRequiredVersion { .. } => GovernanceActionType::SetRequiredVersion,
        SudoAction::AddValidator { .. } => GovernanceActionType::AddValidator,
        SudoAction::RemoveValidator { .. } => GovernanceActionType::RemoveValidator,
        SudoAction::EmergencyPause { .. } => GovernanceActionType::EmergencyPause,
        SudoAction::Resume => GovernanceActionType::Resume,
        SudoAction::ForceStateUpdate { .. } => GovernanceActionType::ForceStateUpdate,
        // Intentional aliasing: refresh operations grouped with update operations
        SudoAction::RefreshChallenges { .. } => GovernanceActionType::UpdateChallenge,
    }
}

/// Generate a human-readable title for a proposal
fn generate_proposal_title(action: &SudoAction) -> String {
    match action {
        SudoAction::UpdateConfig { .. } => "Update Network Configuration".to_string(),
        SudoAction::AddChallenge { config } => format!("Add Challenge: {}", config.name),
        SudoAction::UpdateChallenge { config } => format!("Update Challenge: {}", config.name),
        SudoAction::RemoveChallenge { id } => format!("Remove Challenge: {:?}", id),
        SudoAction::RefreshChallenges { challenge_id } => match challenge_id {
            Some(id) => format!("Refresh Challenge: {:?}", id),
            None => "Refresh All Challenges".to_string(),
        },
        SudoAction::SetChallengeWeight { challenge_id, .. } => {
            format!("Set Weight for Challenge: {:?}", challenge_id)
        }
        SudoAction::SetMechanismBurnRate { mechanism_id, .. } => {
            format!("Set Burn Rate for Mechanism: {}", mechanism_id)
        }
        SudoAction::SetMechanismConfig { mechanism_id, .. } => {
            format!("Configure Mechanism: {}", mechanism_id)
        }
        SudoAction::SetRequiredVersion { min_version, .. } => {
            format!("Set Required Version: {}", min_version)
        }
        SudoAction::AddValidator { info } => {
            format!("Add Validator: {}", info.hotkey.to_ss58())
        }
        SudoAction::RemoveValidator { hotkey } => {
            format!("Remove Validator: {}", hotkey.to_ss58())
        }
        SudoAction::EmergencyPause { reason } => format!("Emergency Pause: {}", reason),
        SudoAction::Resume => "Resume Network".to_string(),
        SudoAction::ForceStateUpdate { .. } => "Force State Update (Emergency)".to_string(),
    }
}

/// Generate a description for a proposal
fn generate_proposal_description(action: &SudoAction) -> String {
    match action {
        SudoAction::AddChallenge { config } => format!(
            "Add new challenge '{}' using Docker image '{}' with {}% emission weight",
            config.name,
            config.docker_image,
            config.emission_weight * 100.0
        ),
        SudoAction::UpdateChallenge { config } => format!(
            "Update challenge '{}' to Docker image '{}'",
            config.name, config.docker_image
        ),
        SudoAction::SetRequiredVersion {
            min_version,
            mandatory,
            ..
        } => format!(
            "Set minimum validator version to {} (mandatory: {})",
            min_version, mandatory
        ),
        SudoAction::EmergencyPause { reason } => {
            format!("Emergency pause requested: {}", reason)
        }
        _ => "No additional description available.".to_string(),
    }
}

/// Apply a sudo action to chain state
fn apply_sudo_action(state: &mut ChainState, action: &SudoAction) -> Result<()> {
    match action {
        SudoAction::UpdateConfig { config } => {
            state.config = config.clone();
            info!("Network configuration updated");
        }
        SudoAction::AddChallenge { config } => {
            state
                .challenge_configs
                .insert(config.challenge_id, config.clone());
            info!(
                "Challenge added: {} ({:?})",
                config.name, config.challenge_id
            );
        }
        SudoAction::UpdateChallenge { config } => {
            state
                .challenge_configs
                .insert(config.challenge_id, config.clone());
            info!(
                "Challenge updated: {} ({:?})",
                config.name, config.challenge_id
            );
        }
        SudoAction::RemoveChallenge { id } => {
            state.challenge_configs.remove(id);
            state.remove_challenge(id);
            info!("Challenge removed: {:?}", id);
        }
        SudoAction::SetChallengeWeight {
            challenge_id,
            mechanism_id,
            weight_ratio,
        } => {
            let allocation = platform_core::ChallengeWeightAllocation::new(
                *challenge_id,
                *mechanism_id,
                *weight_ratio,
            );
            state.challenge_weights.insert(*challenge_id, allocation);
            info!(
                "Challenge weight set: {:?} on mechanism {} = {:.2}%",
                challenge_id,
                mechanism_id,
                weight_ratio * 100.0
            );
        }
        SudoAction::SetMechanismBurnRate {
            mechanism_id,
            burn_rate,
        } => {
            let config = state
                .mechanism_configs
                .entry(*mechanism_id)
                .or_insert_with(|| platform_core::MechanismWeightConfig::new(*mechanism_id));
            config.base_burn_rate = burn_rate.clamp(0.0, 1.0);
            info!(
                "Mechanism {} burn rate set to {:.2}%",
                mechanism_id,
                burn_rate * 100.0
            );
        }
        SudoAction::SetMechanismConfig {
            mechanism_id,
            config,
        } => {
            state
                .mechanism_configs
                .insert(*mechanism_id, config.clone());
            info!(
                "Mechanism {} config updated: burn={:.2}%, cap={:.2}%",
                mechanism_id,
                config.base_burn_rate * 100.0,
                config.max_weight_cap * 100.0
            );
        }
        SudoAction::SetRequiredVersion {
            min_version,
            recommended_version,
            docker_image,
            mandatory,
            deadline_block,
            ..
        } => {
            state.required_version = Some(platform_core::RequiredVersion {
                min_version: min_version.clone(),
                recommended_version: recommended_version.clone(),
                docker_image: docker_image.clone(),
                mandatory: *mandatory,
                deadline_block: *deadline_block,
            });
            info!(
                "Required version set: {} (mandatory: {})",
                min_version, mandatory
            );
        }
        SudoAction::AddValidator { info } => {
            state.add_validator(info.clone())?;
            info!("Validator added: {}", info.hotkey.to_ss58());
        }
        SudoAction::RemoveValidator { hotkey } => {
            state.remove_validator(hotkey);
            info!("Validator removed: {}", hotkey.to_ss58());
        }
        SudoAction::EmergencyPause { reason } => {
            warn!("EMERGENCY PAUSE: {}", reason);
            // Could add a paused flag to state
        }
        SudoAction::Resume => {
            info!("Network resumed");
        }
        SudoAction::ForceStateUpdate { state: new_state } => {
            *state = new_state.clone();
            warn!("Force state update applied");
        }
        SudoAction::RefreshChallenges { challenge_id } => {
            // RefreshChallenges doesn't modify state - handled by orchestrator
            match challenge_id {
                Some(id) => info!("Challenge refresh requested: {:?}", id),
                None => info!("All challenges refresh requested"),
            }
        }
    }

    state.update_hash();
    Ok(())
}

// ============================================================================
// METAGRAPH INTEGRATION
// ============================================================================

/// Utility to sync governance stakes from Bittensor metagraph
pub struct MetagraphGovernanceSync {
    governance: Arc<StakeGovernance>,
}

impl MetagraphGovernanceSync {
    pub fn new(governance: Arc<StakeGovernance>) -> Self {
        Self { governance }
    }

    /// Update governance from metagraph neurons
    pub fn sync_from_metagraph(&self, validators: &[ValidatorInfo], current_block: u64) {
        // Update block height
        self.governance.set_block_height(current_block);

        // Convert to governance validator stakes
        let stakes: Vec<ValidatorStake> = validators
            .iter()
            .filter(|v| v.is_active && v.stake.0 > 0)
            .map(|v| ValidatorStake {
                hotkey: v.hotkey.clone(),
                stake: v.stake,
                is_active: v.is_active,
                last_updated: chrono::Utc::now(),
            })
            .collect();

        self.governance.update_validator_stakes(stakes.clone());

        debug!(
            "Synced {} active validators to governance at block {}",
            stakes.len(),
            current_block
        );
    }

    /// Get governance engine
    pub fn governance(&self) -> &Arc<StakeGovernance> {
        &self.governance
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sudo_action_conversion() {
        let action = SudoAction::EmergencyPause {
            reason: "test".to_string(),
        };
        let gtype = sudo_action_to_governance_type(&action);
        assert_eq!(gtype, GovernanceActionType::EmergencyPause);

        let action2 = SudoAction::Resume;
        let gtype2 = sudo_action_to_governance_type(&action2);
        assert_eq!(gtype2, GovernanceActionType::Resume);
    }

    #[test]
    fn test_sudo_action_conversion_all_variants() {
        // Test UpdateConfig
        let action = SudoAction::UpdateConfig {
            config: platform_core::NetworkConfig::default(),
        };
        assert_eq!(
            sudo_action_to_governance_type(&action),
            GovernanceActionType::UpdateConfig
        );

        // Test AddChallenge
        let challenge_id = platform_core::ChallengeId::new();
        let config = platform_core::ChallengeContainerConfig::new("test", "test:latest", 1, 0.5);
        let action = SudoAction::AddChallenge { config };
        assert_eq!(
            sudo_action_to_governance_type(&action),
            GovernanceActionType::AddChallenge
        );

        // Test UpdateChallenge
        let config = platform_core::ChallengeContainerConfig::new("test", "test:latest", 1, 0.5);
        let action = SudoAction::UpdateChallenge { config };
        assert_eq!(
            sudo_action_to_governance_type(&action),
            GovernanceActionType::UpdateChallenge
        );

        // Test RemoveChallenge
        let action = SudoAction::RemoveChallenge { id: challenge_id };
        assert_eq!(
            sudo_action_to_governance_type(&action),
            GovernanceActionType::RemoveChallenge
        );

        // Test SetChallengeWeight
        let action = SudoAction::SetChallengeWeight {
            challenge_id,
            mechanism_id: 1,
            weight_ratio: 0.5,
        };
        assert_eq!(
            sudo_action_to_governance_type(&action),
            GovernanceActionType::SetChallengeWeight
        );

        // Test SetMechanismBurnRate
        let action = SudoAction::SetMechanismBurnRate {
            mechanism_id: 1,
            burn_rate: 0.1,
        };
        assert_eq!(
            sudo_action_to_governance_type(&action),
            GovernanceActionType::SetMechanismBurnRate
        );

        // Test SetMechanismConfig
        let action = SudoAction::SetMechanismConfig {
            mechanism_id: 1,
            config: platform_core::MechanismWeightConfig::new(1),
        };
        assert_eq!(
            sudo_action_to_governance_type(&action),
            GovernanceActionType::SetMechanismBurnRate
        );

        // Test SetRequiredVersion
        let action = SudoAction::SetRequiredVersion {
            min_version: "1.0.0".to_string(),
            recommended_version: "1.1.0".to_string(),
            docker_image: "image".to_string(),
            mandatory: false,
            deadline_block: Some(1000),
            release_notes: None,
        };
        assert_eq!(
            sudo_action_to_governance_type(&action),
            GovernanceActionType::SetRequiredVersion
        );

        // Test AddValidator
        let info = ValidatorInfo::new(Hotkey([1u8; 32]), Stake(1000));
        let action = SudoAction::AddValidator { info };
        assert_eq!(
            sudo_action_to_governance_type(&action),
            GovernanceActionType::AddValidator
        );

        // Test RemoveValidator
        let action = SudoAction::RemoveValidator {
            hotkey: Hotkey([1u8; 32]),
        };
        assert_eq!(
            sudo_action_to_governance_type(&action),
            GovernanceActionType::RemoveValidator
        );

        // Test ForceStateUpdate
        let state = ChainState::new(Hotkey([1u8; 32]), platform_core::NetworkConfig::default());
        let action = SudoAction::ForceStateUpdate { state };
        assert_eq!(
            sudo_action_to_governance_type(&action),
            GovernanceActionType::ForceStateUpdate
        );

        // Test RefreshChallenges
        let action = SudoAction::RefreshChallenges {
            challenge_id: Some(challenge_id),
        };
        assert_eq!(
            sudo_action_to_governance_type(&action),
            GovernanceActionType::UpdateChallenge
        );
    }

    #[test]
    fn test_generate_proposal_title_all_variants() {
        let challenge_id = platform_core::ChallengeId::new();

        // UpdateConfig
        let action = SudoAction::UpdateConfig {
            config: platform_core::NetworkConfig::default(),
        };
        assert_eq!(
            generate_proposal_title(&action),
            "Update Network Configuration"
        );

        // AddChallenge
        let config =
            platform_core::ChallengeContainerConfig::new("TestChallenge", "test:latest", 1, 0.5);
        let action = SudoAction::AddChallenge {
            config: config.clone(),
        };
        assert_eq!(
            generate_proposal_title(&action),
            "Add Challenge: TestChallenge"
        );

        // UpdateChallenge
        let action = SudoAction::UpdateChallenge { config };
        assert_eq!(
            generate_proposal_title(&action),
            "Update Challenge: TestChallenge"
        );

        // RemoveChallenge
        let action = SudoAction::RemoveChallenge { id: challenge_id };
        let title = generate_proposal_title(&action);
        assert!(title.starts_with("Remove Challenge:"));

        // RefreshChallenges with ID
        let action = SudoAction::RefreshChallenges {
            challenge_id: Some(challenge_id),
        };
        let title = generate_proposal_title(&action);
        assert!(title.starts_with("Refresh Challenge:"));

        // RefreshChallenges without ID
        let action = SudoAction::RefreshChallenges { challenge_id: None };
        assert_eq!(generate_proposal_title(&action), "Refresh All Challenges");

        // SetChallengeWeight
        let action = SudoAction::SetChallengeWeight {
            challenge_id,
            mechanism_id: 1,
            weight_ratio: 0.5,
        };
        let title = generate_proposal_title(&action);
        assert!(title.starts_with("Set Weight for Challenge:"));

        // SetMechanismBurnRate
        let action = SudoAction::SetMechanismBurnRate {
            mechanism_id: 42,
            burn_rate: 0.1,
        };
        assert_eq!(
            generate_proposal_title(&action),
            "Set Burn Rate for Mechanism: 42"
        );

        // SetMechanismConfig
        let action = SudoAction::SetMechanismConfig {
            mechanism_id: 99,
            config: platform_core::MechanismWeightConfig::new(99),
        };
        assert_eq!(generate_proposal_title(&action), "Configure Mechanism: 99");

        // SetRequiredVersion
        let action = SudoAction::SetRequiredVersion {
            min_version: "2.0.0".to_string(),
            recommended_version: "2.1.0".to_string(),
            docker_image: "image".to_string(),
            mandatory: true,
            deadline_block: Some(1000),
            release_notes: None,
        };
        assert_eq!(
            generate_proposal_title(&action),
            "Set Required Version: 2.0.0"
        );

        // AddValidator
        let hotkey = Hotkey([42u8; 32]);
        let info = ValidatorInfo::new(hotkey.clone(), Stake(1000));
        let action = SudoAction::AddValidator { info };
        let title = generate_proposal_title(&action);
        assert!(title.starts_with("Add Validator:"));

        // RemoveValidator
        let action = SudoAction::RemoveValidator { hotkey };
        let title = generate_proposal_title(&action);
        assert!(title.starts_with("Remove Validator:"));

        // EmergencyPause
        let action = SudoAction::EmergencyPause {
            reason: "Critical bug".to_string(),
        };
        assert_eq!(
            generate_proposal_title(&action),
            "Emergency Pause: Critical bug"
        );

        // Resume
        let action = SudoAction::Resume;
        assert_eq!(generate_proposal_title(&action), "Resume Network");

        // ForceStateUpdate
        let state = ChainState::new(Hotkey([1u8; 32]), platform_core::NetworkConfig::default());
        let action = SudoAction::ForceStateUpdate { state };
        assert_eq!(
            generate_proposal_title(&action),
            "Force State Update (Emergency)"
        );
    }

    #[test]
    fn test_generate_proposal_description() {
        let challenge_id = platform_core::ChallengeId::new();

        // AddChallenge
        let config = platform_core::ChallengeContainerConfig::new(
            "TestChallenge",
            "test/image:latest",
            1,
            0.25,
        );
        let action = SudoAction::AddChallenge {
            config: config.clone(),
        };
        let desc = generate_proposal_description(&action);
        assert!(desc.contains("TestChallenge"));
        assert!(desc.contains("test/image:latest"));
        assert!(desc.contains("25%"));

        // UpdateChallenge
        let action = SudoAction::UpdateChallenge { config };
        let desc = generate_proposal_description(&action);
        assert!(desc.contains("TestChallenge"));
        assert!(desc.contains("test/image:latest"));

        // SetRequiredVersion
        let action = SudoAction::SetRequiredVersion {
            min_version: "1.5.0".to_string(),
            recommended_version: "1.6.0".to_string(),
            docker_image: "image".to_string(),
            mandatory: true,
            deadline_block: Some(1000),
            release_notes: None,
        };
        let desc = generate_proposal_description(&action);
        assert!(desc.contains("1.5.0"));
        assert!(desc.contains("true"));

        // EmergencyPause
        let action = SudoAction::EmergencyPause {
            reason: "Security vulnerability".to_string(),
        };
        let desc = generate_proposal_description(&action);
        assert!(desc.contains("Security vulnerability"));

        // Other actions return default description
        let action = SudoAction::Resume;
        let desc = generate_proposal_description(&action);
        assert_eq!(desc, "No additional description available.");
    }

    #[test]
    fn test_apply_sudo_action_all_variants() {
        let keypair = Keypair::generate();
        let mut state = ChainState::new(keypair.hotkey(), platform_core::NetworkConfig::default());

        // Test UpdateConfig
        let new_config = platform_core::NetworkConfig::default();
        let action = SudoAction::UpdateConfig {
            config: new_config.clone(),
        };
        assert!(apply_sudo_action(&mut state, &action).is_ok());
        assert_eq!(state.config.subnet_id, new_config.subnet_id);

        // Test AddChallenge
        let config = platform_core::ChallengeContainerConfig::new(
            "test",
            "ghcr.io/platformnetwork/test:latest",
            1,
            0.5,
        );
        let challenge_id = config.challenge_id;
        let action = SudoAction::AddChallenge {
            config: config.clone(),
        };
        assert!(apply_sudo_action(&mut state, &action).is_ok());
        assert!(state.challenge_configs.contains_key(&challenge_id));

        // Test UpdateChallenge
        let mut updated_config = platform_core::ChallengeContainerConfig::new(
            "test",
            "ghcr.io/platformnetwork/updated:latest",
            1,
            0.5,
        );
        updated_config.challenge_id = challenge_id; // Use same ID for update
        let action = SudoAction::UpdateChallenge {
            config: updated_config.clone(),
        };
        assert!(apply_sudo_action(&mut state, &action).is_ok());
        assert_eq!(
            state.challenge_configs[&challenge_id].docker_image,
            "ghcr.io/platformnetwork/updated:latest"
        );

        // Test RemoveChallenge
        let action = SudoAction::RemoveChallenge { id: challenge_id };
        assert!(apply_sudo_action(&mut state, &action).is_ok());
        assert!(!state.challenge_configs.contains_key(&challenge_id));

        // Test SetChallengeWeight
        let action = SudoAction::SetChallengeWeight {
            challenge_id,
            mechanism_id: 1,
            weight_ratio: 0.75,
        };
        assert!(apply_sudo_action(&mut state, &action).is_ok());
        assert!(state.challenge_weights.contains_key(&challenge_id));

        // Test SetMechanismBurnRate
        let action = SudoAction::SetMechanismBurnRate {
            mechanism_id: 1,
            burn_rate: 0.15,
        };
        assert!(apply_sudo_action(&mut state, &action).is_ok());
        assert_eq!(state.mechanism_configs[&1].base_burn_rate, 0.15);

        // Test SetMechanismConfig
        let mut mechanism_config = platform_core::MechanismWeightConfig::new(2);
        mechanism_config.base_burn_rate = 0.2;
        mechanism_config.max_weight_cap = 0.5;
        let action = SudoAction::SetMechanismConfig {
            mechanism_id: 2,
            config: mechanism_config.clone(),
        };
        assert!(apply_sudo_action(&mut state, &action).is_ok());
        assert_eq!(state.mechanism_configs[&2].base_burn_rate, 0.2);
        assert_eq!(state.mechanism_configs[&2].max_weight_cap, 0.5);

        // Test SetRequiredVersion
        let action = SudoAction::SetRequiredVersion {
            min_version: "1.0.0".to_string(),
            recommended_version: "1.1.0".to_string(),
            docker_image: "validator:1.1.0".to_string(),
            mandatory: true,
            deadline_block: Some(10000),
            release_notes: Some("Important update".to_string()),
        };
        assert!(apply_sudo_action(&mut state, &action).is_ok());
        assert!(state.required_version.is_some());
        let req_ver = state.required_version.as_ref().unwrap();
        assert_eq!(req_ver.min_version, "1.0.0");
        assert!(req_ver.mandatory);

        // Test AddValidator
        let new_validator = ValidatorInfo::new(Hotkey([99u8; 32]), Stake(500_000_000_000));
        let action = SudoAction::AddValidator {
            info: new_validator.clone(),
        };
        assert!(apply_sudo_action(&mut state, &action).is_ok());
        assert!(state.get_validator(&new_validator.hotkey).is_some());

        // Test RemoveValidator
        let action = SudoAction::RemoveValidator {
            hotkey: new_validator.hotkey.clone(),
        };
        assert!(apply_sudo_action(&mut state, &action).is_ok());
        assert!(state.get_validator(&new_validator.hotkey).is_none());

        // Test EmergencyPause
        let action = SudoAction::EmergencyPause {
            reason: "Test pause".to_string(),
        };
        assert!(apply_sudo_action(&mut state, &action).is_ok());

        // Test Resume
        let action = SudoAction::Resume;
        assert!(apply_sudo_action(&mut state, &action).is_ok());

        // Test ForceStateUpdate
        let new_state =
            ChainState::new(Hotkey([88u8; 32]), platform_core::NetworkConfig::default());
        let action = SudoAction::ForceStateUpdate {
            state: new_state.clone(),
        };
        assert!(apply_sudo_action(&mut state, &action).is_ok());
        assert_eq!(state.sudo_key, Hotkey([88u8; 32]));

        // Test RefreshChallenges with ID
        let action = SudoAction::RefreshChallenges {
            challenge_id: Some(challenge_id),
        };
        assert!(apply_sudo_action(&mut state, &action).is_ok());

        // Test RefreshChallenges without ID
        let action = SudoAction::RefreshChallenges { challenge_id: None };
        assert!(apply_sudo_action(&mut state, &action).is_ok());
    }

    #[test]
    fn test_proposal_title_generation() {
        let action = SudoAction::EmergencyPause {
            reason: "Security issue".to_string(),
        };
        let title = generate_proposal_title(&action);
        assert!(title.contains("Emergency Pause"));
        assert!(title.contains("Security issue"));
    }

    #[test]
    fn test_metagraph_sync() {
        let gov = Arc::new(StakeGovernance::new());
        let sync = MetagraphGovernanceSync::new(gov.clone());

        let validators = vec![
            ValidatorInfo::new(Hotkey([1u8; 32]), Stake(100_000_000_000)),
            ValidatorInfo::new(Hotkey([2u8; 32]), Stake(200_000_000_000)),
        ];

        sync.sync_from_metagraph(&validators, 1_000_000);

        assert_eq!(sync.governance().block_height(), 1_000_000);
        assert_eq!(sync.governance().total_stake().0, 300_000_000_000);
    }

    #[tokio::test]
    async fn test_governance_pbft_new() {
        let keypair = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            keypair.hotkey(),
            platform_core::NetworkConfig::default(),
        )));
        let (tx, _rx) = tokio::sync::mpsc::channel(100);
        let pbft = Arc::new(PBFTEngine::new(keypair.clone(), state.clone(), tx));

        let gov_pbft = GovernancePBFT::new(pbft, state, keypair);

        // Verify initialization - governance status
        let status = gov_pbft.governance_status();
        assert!(status.is_bootstrap_period);
    }

    #[tokio::test]
    async fn test_set_block_height() {
        let keypair = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            keypair.hotkey(),
            platform_core::NetworkConfig::default(),
        )));
        let (tx, _rx) = tokio::sync::mpsc::channel(100);
        let pbft = Arc::new(PBFTEngine::new(keypair.clone(), state.clone(), tx));

        let gov_pbft = GovernancePBFT::new(pbft, state, keypair);

        gov_pbft.set_block_height(5000);
        assert_eq!(gov_pbft.governance.stake_governance().block_height(), 5000);
    }

    #[tokio::test]
    async fn test_update_stakes_from_metagraph() {
        let keypair = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            keypair.hotkey(),
            platform_core::NetworkConfig::default(),
        )));
        let (tx, _rx) = tokio::sync::mpsc::channel(100);
        let pbft = Arc::new(PBFTEngine::new(keypair.clone(), state.clone(), tx));

        let gov_pbft = GovernancePBFT::new(pbft, state, keypair);

        let validators = vec![
            ValidatorInfo::new(Hotkey([1u8; 32]), Stake(100_000_000_000)),
            ValidatorInfo::new(Hotkey([2u8; 32]), Stake(200_000_000_000)),
        ];

        gov_pbft.update_stakes_from_metagraph(&validators);

        assert_eq!(
            gov_pbft.governance.stake_governance().total_stake().0,
            300_000_000_000
        );
    }

    #[tokio::test]
    async fn test_execute_sudo_action_bootstrap_non_owner() {
        let keypair = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            keypair.hotkey(),
            platform_core::NetworkConfig::default(),
        )));
        let (tx, _rx) = tokio::sync::mpsc::channel(100);
        let pbft = Arc::new(PBFTEngine::new(keypair.clone(), state.clone(), tx));

        let gov_pbft = GovernancePBFT::new(pbft, state, keypair);

        gov_pbft.set_block_height(1000); // In bootstrap period

        let action = SudoAction::UpdateConfig {
            config: platform_core::NetworkConfig::default(),
        };

        let result = gov_pbft.execute_sudo_action(action).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_governance_status() {
        let keypair = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            keypair.hotkey(),
            platform_core::NetworkConfig::default(),
        )));
        let (tx, _rx) = tokio::sync::mpsc::channel(100);
        let pbft = Arc::new(PBFTEngine::new(keypair.clone(), state.clone(), tx));

        let gov_pbft = GovernancePBFT::new(pbft, state, keypair);

        let status = gov_pbft.governance_status();
        assert_eq!(status.current_block, 0);
        assert!(status.is_bootstrap_period);
    }

    #[tokio::test]
    async fn test_active_proposals() {
        let keypair = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            keypair.hotkey(),
            platform_core::NetworkConfig::default(),
        )));
        let (tx, _rx) = tokio::sync::mpsc::channel(100);
        let pbft = Arc::new(PBFTEngine::new(keypair.clone(), state.clone(), tx));

        let gov_pbft = GovernancePBFT::new(pbft, state, keypair);

        let proposals = gov_pbft.active_proposals();
        assert_eq!(proposals.len(), 0);
    }

    #[tokio::test]
    async fn test_stake_for_consensus() {
        let keypair = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            keypair.hotkey(),
            platform_core::NetworkConfig::default(),
        )));
        let (tx, _rx) = tokio::sync::mpsc::channel(100);
        let pbft = Arc::new(PBFTEngine::new(keypair.clone(), state.clone(), tx));

        let gov_pbft = GovernancePBFT::new(pbft, state, keypair);

        let (required, threshold) = gov_pbft.stake_for_consensus();
        assert_eq!(threshold, crate::stake_governance::STAKE_THRESHOLD_PERCENT);
        // With zero stake, required should be 0
        assert_eq!(required.0, 0);
    }

    #[tokio::test]
    async fn test_execute_sudo_action_post_bootstrap() {
        let keypair = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            keypair.hotkey(),
            platform_core::NetworkConfig::default(),
        )));
        let (tx, _rx) = tokio::sync::mpsc::channel(100);
        let pbft = Arc::new(PBFTEngine::new(keypair.clone(), state.clone(), tx));

        let gov_pbft = GovernancePBFT::new(pbft, state, keypair);
        gov_pbft.set_block_height(crate::stake_governance::BOOTSTRAP_END_BLOCK + 1);

        // Add stake for the validator
        let validators = vec![ValidatorInfo::new(
            gov_pbft.keypair.hotkey(),
            Stake(100_000_000_000),
        )];
        gov_pbft.update_stakes_from_metagraph(&validators);

        let action = SudoAction::UpdateConfig {
            config: platform_core::NetworkConfig::default(),
        };

        let result = gov_pbft.execute_sudo_action(action).await;
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            SudoExecutionResult::ProposalCreated { .. }
        ));
    }

    #[tokio::test]
    async fn test_can_use_bootstrap_false() {
        let keypair = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            keypair.hotkey(),
            platform_core::NetworkConfig::default(),
        )));
        let (tx, _rx) = tokio::sync::mpsc::channel(100);
        let pbft = Arc::new(PBFTEngine::new(keypair.clone(), state.clone(), tx));

        let gov_pbft = GovernancePBFT::new(pbft, state, keypair);
        gov_pbft.set_block_height(1000);

        assert!(!gov_pbft.can_use_bootstrap());
    }
}
