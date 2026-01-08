//! Stake-Weighted PBFT Consensus Engine
//!
//! Enhanced PBFT that weights votes by validator stake instead of simple vote count.
//! This prevents low-stake validators from having equal influence as high-stake ones.
//!
//! # Security Improvements
//! - Votes are weighted by stake (50%+ of STAKE required, not 50% of validators)
//! - Double-voting is prevented (first vote wins)
//! - Integration with StakeGovernance for bootstrap period handling

use crate::{ConsensusConfig, ConsensusPhase};
use parking_lot::RwLock;
use platform_core::{
    ChainState, Hotkey, Keypair, MiniChainError, NetworkMessage, Proposal, ProposalAction, Result,
    SignedNetworkMessage, Stake, SudoAction, Vote,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

// ============================================================================
// STAKE-WEIGHTED ROUND STATE
// ============================================================================

/// Round state with stake-weighted voting
#[derive(Clone, Debug)]
pub struct StakeWeightedRoundState {
    /// Proposal being voted on
    pub proposal: Proposal,
    /// Current phase
    pub phase: ConsensusPhase,
    /// Votes received (hotkey -> vote)
    votes: HashMap<Hotkey, StakeWeightedVote>,
    /// Set of hotkeys that have voted (for double-vote prevention)
    voted_hotkeys: HashSet<Hotkey>,
    /// Start time
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Timeout
    pub timeout: chrono::Duration,
}

/// Vote with stake weight
#[derive(Clone, Debug)]
pub struct StakeWeightedVote {
    pub vote: Vote,
    pub stake: Stake,
    pub received_at: chrono::DateTime<chrono::Utc>,
}

impl StakeWeightedRoundState {
    pub fn new(proposal: Proposal, timeout_secs: i64) -> Self {
        Self {
            proposal,
            phase: ConsensusPhase::PrePrepare,
            votes: HashMap::new(),
            voted_hotkeys: HashSet::new(),
            started_at: chrono::Utc::now(),
            timeout: chrono::Duration::seconds(timeout_secs),
        }
    }

    /// Check if round has timed out
    pub fn is_timed_out(&self) -> bool {
        chrono::Utc::now() > self.started_at + self.timeout
    }

    /// Add a vote with stake weight
    /// Returns false if this is a double-vote (rejected)
    pub fn add_vote(&mut self, vote: Vote, stake: Stake) -> bool {
        // SECURITY: Prevent double-voting - first vote wins
        if self.voted_hotkeys.contains(&vote.voter) {
            warn!(
                "SECURITY: Rejected double-vote from {} on proposal {}",
                vote.voter.to_hex()[..16].to_string(),
                self.proposal.id
            );
            return false;
        }

        // Record that this hotkey has voted
        self.voted_hotkeys.insert(vote.voter.clone());

        // Store vote with stake
        let weighted_vote = StakeWeightedVote {
            vote: vote.clone(),
            stake,
            received_at: chrono::Utc::now(),
        };
        self.votes.insert(vote.voter.clone(), weighted_vote);

        true
    }

    /// Get total approve stake
    pub fn approve_stake(&self) -> u64 {
        self.votes
            .values()
            .filter(|v| v.vote.approve)
            .map(|v| v.stake.0)
            .sum()
    }

    /// Get total reject stake
    pub fn reject_stake(&self) -> u64 {
        self.votes
            .values()
            .filter(|v| !v.vote.approve)
            .map(|v| v.stake.0)
            .sum()
    }

    /// Check if we have enough stake for consensus (50%+ of total)
    pub fn has_stake_consensus(&self, total_stake: u64) -> bool {
        if total_stake == 0 {
            return false;
        }
        let approve_stake = self.approve_stake();
        // Require strictly more than 50% to prevent ties
        approve_stake * 2 > total_stake
    }

    /// Check if rejection is certain (>50% reject stake)
    pub fn is_stake_rejected(&self, total_stake: u64) -> bool {
        if total_stake == 0 {
            return false;
        }
        let reject_stake = self.reject_stake();
        reject_stake * 2 > total_stake
    }

    /// Get vote count (for logging)
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    /// Check if a hotkey has already voted
    pub fn has_voted(&self, hotkey: &Hotkey) -> bool {
        self.voted_hotkeys.contains(hotkey)
    }
}

// ============================================================================
// STAKE-WEIGHTED CONSENSUS RESULT
// ============================================================================

/// Result of stake-weighted consensus check
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum StakeWeightedResult {
    /// Proposal approved with required stake
    Approved {
        proposal: Proposal,
        approve_stake: u64,
        total_stake: u64,
        vote_count: usize,
    },
    /// Proposal rejected (>50% stake voted against)
    Rejected {
        proposal_id: Uuid,
        reject_stake: u64,
        total_stake: u64,
        reason: String,
    },
    /// Still pending
    Pending {
        approve_stake: u64,
        reject_stake: u64,
        total_stake: u64,
    },
    /// Timeout
    Timeout { proposal_id: Uuid },
}

// ============================================================================
// STAKE-WEIGHTED PBFT ENGINE
// ============================================================================

/// Stake-Weighted PBFT Consensus Engine
pub struct StakeWeightedPBFT {
    /// Local keypair
    keypair: Keypair,
    /// Active rounds by proposal ID
    rounds: Arc<RwLock<HashMap<Uuid, StakeWeightedRoundState>>>,
    /// Chain state reference (for stake lookup)
    chain_state: Arc<RwLock<ChainState>>,
    /// Configuration
    config: ConsensusConfig,
    /// Outgoing message sender
    message_tx: mpsc::Sender<SignedNetworkMessage>,
}

impl StakeWeightedPBFT {
    pub fn new(
        keypair: Keypair,
        chain_state: Arc<RwLock<ChainState>>,
        message_tx: mpsc::Sender<SignedNetworkMessage>,
    ) -> Self {
        Self {
            keypair,
            rounds: Arc::new(RwLock::new(HashMap::new())),
            chain_state,
            config: ConsensusConfig::default(),
            message_tx,
        }
    }

    /// Get total active stake from chain state
    fn total_stake(&self) -> u64 {
        self.chain_state.read().total_stake().0
    }

    /// Get stake for a specific validator
    fn get_validator_stake(&self, hotkey: &Hotkey) -> Option<Stake> {
        self.chain_state
            .read()
            .get_validator(hotkey)
            .map(|v| v.stake)
    }

    /// Check if we are the sudo key
    pub fn is_sudo(&self) -> bool {
        self.chain_state.read().is_sudo(&self.keypair.hotkey())
    }

    /// Start a new round for a proposal
    pub fn start_round(&self, proposal: Proposal) -> Uuid {
        let id = proposal.id;
        let round = StakeWeightedRoundState::new(proposal, self.config.round_timeout_secs);
        self.rounds.write().insert(id, round);
        id
    }

    /// Propose a sudo action (only subnet owner)
    pub async fn propose_sudo(&self, action: SudoAction) -> Result<Uuid> {
        if !self.is_sudo() {
            return Err(MiniChainError::Unauthorized("Not the subnet owner".into()));
        }

        let block_height = self.chain_state.read().block_height;
        let proposal = Proposal::new(
            ProposalAction::Sudo(action),
            self.keypair.hotkey(),
            block_height,
        );

        let proposal_id = self.start_round(proposal.clone());

        // Broadcast proposal
        let msg = NetworkMessage::Proposal(proposal);
        let signed = SignedNetworkMessage::new(msg, &self.keypair)?;
        self.message_tx
            .send(signed)
            .await
            .map_err(|e| MiniChainError::Network(e.to_string()))?;

        // Self-vote approve
        self.vote_internal(proposal_id, true).await?;

        info!("Proposed sudo action: {:?}", proposal_id);
        Ok(proposal_id)
    }

    /// Propose a new block
    #[allow(clippy::await_holding_lock)]
    pub async fn propose_block(&self) -> Result<Uuid> {
        let state = self.chain_state.read();
        let block_height = state.block_height;
        let state_hash = state.state_hash;
        drop(state);

        let proposal = Proposal::new(
            ProposalAction::NewBlock { state_hash },
            self.keypair.hotkey(),
            block_height,
        );

        let proposal_id = self.start_round(proposal.clone());

        // Broadcast proposal
        let msg = NetworkMessage::Proposal(proposal);
        let signed = SignedNetworkMessage::new(msg, &self.keypair)?;
        self.message_tx
            .send(signed)
            .await
            .map_err(|e| MiniChainError::Network(e.to_string()))?;

        // Self-vote approve
        self.vote_internal(proposal_id, true).await?;

        debug!("Proposed new block: {:?}", proposal_id);
        Ok(proposal_id)
    }

    /// Handle incoming proposal
    pub async fn handle_proposal(&self, proposal: Proposal, signer: &Hotkey) -> Result<()> {
        // Verify proposer signature matches
        if proposal.proposer != *signer {
            return Err(MiniChainError::InvalidSignature);
        }

        // For sudo actions, verify sender is the sudo key
        if let ProposalAction::Sudo(_) = &proposal.action {
            if !self.chain_state.read().is_sudo(signer) {
                warn!("Non-sudo tried to propose sudo action: {:?}", signer);
                return Err(MiniChainError::Unauthorized("Not sudo".into()));
            }
        }

        // Validate proposal
        if !self.validate_proposal(&proposal) {
            warn!("Invalid proposal: {:?}", proposal.id);
            self.vote_internal(proposal.id, false).await?;
            return Ok(());
        }

        // Start round and vote approve
        self.start_round(proposal.clone());
        self.vote_internal(proposal.id, true).await?;

        Ok(())
    }

    /// Internal vote function
    async fn vote_internal(&self, proposal_id: Uuid, approve: bool) -> Result<()> {
        let vote = if approve {
            Vote::approve(proposal_id, self.keypair.hotkey())
        } else {
            Vote::reject(proposal_id, self.keypair.hotkey())
        };

        // Get our stake
        let stake = self
            .get_validator_stake(&self.keypair.hotkey())
            .unwrap_or(Stake::new(0));

        // Add local vote
        let result = self.add_vote_with_stake(vote.clone(), stake);
        if let Some(result) = result {
            self.handle_result(result).await?;
        }

        // Broadcast vote
        let msg = NetworkMessage::Vote(vote);
        let signed = SignedNetworkMessage::new(msg, &self.keypair)?;
        self.message_tx
            .send(signed)
            .await
            .map_err(|e| MiniChainError::Network(e.to_string()))?;

        Ok(())
    }

    /// Handle incoming vote from network
    pub async fn handle_vote(&self, vote: Vote, signer: &Hotkey) -> Result<()> {
        // Verify voter signature
        if vote.voter != *signer {
            return Err(MiniChainError::InvalidSignature);
        }

        // Get validator stake (must be a validator with stake)
        let stake = match self.get_validator_stake(signer) {
            Some(s) if s.0 > 0 => s,
            _ => {
                warn!(
                    "Vote rejected: {} is not a validator or has no stake",
                    signer.to_hex()[..16].to_string()
                );
                return Ok(());
            }
        };

        // Add vote with stake weight
        let result = self.add_vote_with_stake(vote, stake);
        if let Some(result) = result {
            self.handle_result(result).await?;
        }

        Ok(())
    }

    /// Add a vote with stake weight and check consensus
    fn add_vote_with_stake(&self, vote: Vote, stake: Stake) -> Option<StakeWeightedResult> {
        let proposal_id = vote.proposal_id;
        let mut rounds = self.rounds.write();

        let total_stake = self.total_stake();

        if let Some(round) = rounds.get_mut(&proposal_id) {
            // Try to add vote (returns false if double-vote)
            if !round.add_vote(vote.clone(), stake) {
                // Double vote rejected
                return None;
            }

            let approve_stake = round.approve_stake();
            let reject_stake = round.reject_stake();

            debug!(
                "Vote recorded: {} voted {} with {} stake (approve: {}/{}, reject: {}/{})",
                vote.voter.to_hex()[..16].to_string(),
                if vote.approve { "YES" } else { "NO" },
                stake.0,
                approve_stake,
                total_stake,
                reject_stake,
                total_stake
            );

            // Check for consensus
            if round.has_stake_consensus(total_stake) {
                let proposal = round.proposal.clone();
                let vote_count = round.vote_count();
                round.phase = ConsensusPhase::Completed;

                info!(
                    "CONSENSUS REACHED: Proposal {} approved with {}/{} stake ({} votes)",
                    proposal_id, approve_stake, total_stake, vote_count
                );

                // Remove completed round
                rounds.remove(&proposal_id);

                return Some(StakeWeightedResult::Approved {
                    proposal,
                    approve_stake,
                    total_stake,
                    vote_count,
                });
            }

            // Check for certain rejection
            if round.is_stake_rejected(total_stake) {
                round.phase = ConsensusPhase::Failed;

                info!(
                    "REJECTED: Proposal {} with {}/{} stake against",
                    proposal_id, reject_stake, total_stake
                );

                rounds.remove(&proposal_id);

                return Some(StakeWeightedResult::Rejected {
                    proposal_id,
                    reject_stake,
                    total_stake,
                    reason: format!(
                        "Rejected by {:.1}% of stake",
                        (reject_stake as f64 / total_stake as f64) * 100.0
                    ),
                });
            }

            // Update phase
            if round.vote_count() > 0 {
                round.phase = ConsensusPhase::Prepare;
            }

            None
        } else {
            // Round not found (proposal may have already completed)
            None
        }
    }

    /// Handle consensus result
    async fn handle_result(&self, result: StakeWeightedResult) -> Result<()> {
        match result {
            StakeWeightedResult::Approved { proposal, .. } => {
                self.apply_proposal(proposal).await?;
            }
            StakeWeightedResult::Rejected {
                proposal_id,
                reason,
                ..
            } => {
                warn!("Proposal {} rejected: {}", proposal_id, reason);
            }
            StakeWeightedResult::Pending { .. } => {}
            StakeWeightedResult::Timeout { proposal_id } => {
                warn!("Proposal {} timed out", proposal_id);
            }
        }
        Ok(())
    }

    /// Apply an approved proposal
    async fn apply_proposal(&self, proposal: Proposal) -> Result<()> {
        let mut state = self.chain_state.write();

        match proposal.action {
            ProposalAction::Sudo(action) => {
                self.apply_sudo_action(&mut state, action)?;
            }
            ProposalAction::NewBlock { state_hash } => {
                if state.state_hash == state_hash {
                    state.increment_block();
                    info!("New block: {}", state.block_height);
                }
            }
            ProposalAction::JobCompletion {
                job_id,
                result,
                validator,
            } => {
                info!(
                    "Job {} completed by {:?} with score {:?}",
                    job_id, validator, result
                );
            }
        }

        Ok(())
    }

    /// Apply a sudo action
    fn apply_sudo_action(&self, state: &mut ChainState, action: SudoAction) -> Result<()> {
        match action {
            SudoAction::UpdateConfig { config } => {
                state.config = config;
                info!("Config updated via stake-weighted consensus");
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
                state.challenge_configs.remove(&id);
                state.remove_challenge(&id);
                info!("Challenge removed: {:?}", id);
            }
            SudoAction::RefreshChallenges { challenge_id } => {
                // RefreshChallenges is handled by the orchestrator, not state
                // Just log it here
                match challenge_id {
                    Some(id) => info!("Challenge refresh requested: {:?}", id),
                    None => info!("All challenges refresh requested"),
                }
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
                    mandatory,
                    deadline_block,
                });
                info!(
                    "Required version set: {} (mandatory: {})",
                    min_version, mandatory
                );
            }
            SudoAction::AddValidator { info } => {
                state.add_validator(info)?;
                info!("Validator added via consensus");
            }
            SudoAction::RemoveValidator { hotkey } => {
                state.remove_validator(&hotkey);
                info!("Validator removed: {:?}", hotkey);
            }
            SudoAction::EmergencyPause { reason } => {
                warn!("EMERGENCY PAUSE: {}", reason);
            }
            SudoAction::Resume => {
                info!("Network resumed");
            }
            SudoAction::ForceStateUpdate { state: new_state } => {
                *state = new_state;
                warn!("Force state update applied");
            }
            SudoAction::SetChallengeWeight {
                challenge_id,
                mechanism_id,
                weight_ratio,
            } => {
                let allocation = platform_core::ChallengeWeightAllocation::new(
                    challenge_id,
                    mechanism_id,
                    weight_ratio,
                );
                state.challenge_weights.insert(challenge_id, allocation);
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
                    .entry(mechanism_id)
                    .or_insert_with(|| platform_core::MechanismWeightConfig::new(mechanism_id));
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
                state.mechanism_configs.insert(mechanism_id, config.clone());
                info!(
                    "Mechanism {} config updated: burn={:.2}%, cap={:.2}%",
                    mechanism_id,
                    config.base_burn_rate * 100.0,
                    config.max_weight_cap * 100.0
                );
            }
        }

        state.update_hash();
        Ok(())
    }

    /// Validate a proposal
    fn validate_proposal(&self, proposal: &Proposal) -> bool {
        let state = self.chain_state.read();

        if proposal.block_height > state.block_height + 1 {
            return false;
        }

        match &proposal.action {
            ProposalAction::Sudo(action) => {
                if !state.is_sudo(&proposal.proposer) {
                    return false;
                }
                self.validate_sudo_action(&state, action)
            }
            ProposalAction::NewBlock { .. } => true,
            ProposalAction::JobCompletion { .. } => true,
        }
    }

    fn validate_sudo_action(&self, _state: &ChainState, action: &SudoAction) -> bool {
        match action {
            SudoAction::AddChallenge { config } | SudoAction::UpdateChallenge { config } => {
                config.validate().is_ok()
            }
            _ => true,
        }
    }

    /// Check for timeouts
    pub fn check_timeouts(&self) -> Vec<StakeWeightedResult> {
        let mut results = Vec::new();
        let mut rounds = self.rounds.write();

        let timed_out: Vec<Uuid> = rounds
            .iter()
            .filter(|(_, r)| r.is_timed_out())
            .map(|(id, _)| *id)
            .collect();

        for id in timed_out {
            rounds.remove(&id);
            results.push(StakeWeightedResult::Timeout { proposal_id: id });
        }

        results
    }

    /// Get active rounds count
    pub fn active_rounds(&self) -> usize {
        self.rounds.read().len()
    }

    /// Get consensus status
    pub fn status(&self) -> StakeWeightedConsensusStatus {
        let total_stake = self.total_stake();
        let validator_count = self.chain_state.read().validators.len();

        StakeWeightedConsensusStatus {
            active_rounds: self.active_rounds(),
            total_stake,
            validator_count,
            threshold_stake: total_stake / 2 + 1,
        }
    }
}

/// Status for stake-weighted consensus
#[derive(Debug, Clone)]
pub struct StakeWeightedConsensusStatus {
    pub active_rounds: usize,
    pub total_stake: u64,
    pub validator_count: usize,
    pub threshold_stake: u64,
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use platform_core::{NetworkConfig, ValidatorInfo};
    use tokio::sync::mpsc;

    fn create_test_engine() -> (StakeWeightedPBFT, mpsc::Receiver<SignedNetworkMessage>) {
        let keypair = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            keypair.hotkey(),
            NetworkConfig::default(),
        )));
        let (tx, rx) = mpsc::channel(100);

        let engine = StakeWeightedPBFT::new(keypair, state, tx);
        (engine, rx)
    }

    #[test]
    fn test_stake_weighted_round() {
        let kp = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            kp.hotkey(),
            0,
        );

        let mut round = StakeWeightedRoundState::new(proposal, 30);

        // Add votes with different stakes
        let v1 = Keypair::generate();
        let v2 = Keypair::generate();
        let v3 = Keypair::generate();

        // v1: 60% stake, approves
        assert!(round.add_vote(
            Vote::approve(round.proposal.id, v1.hotkey()),
            Stake::new(600)
        ));
        // v2: 30% stake, approves
        assert!(round.add_vote(
            Vote::approve(round.proposal.id, v2.hotkey()),
            Stake::new(300)
        ));
        // v3: 10% stake, rejects
        assert!(round.add_vote(
            Vote::reject(round.proposal.id, v3.hotkey()),
            Stake::new(100)
        ));

        assert_eq!(round.approve_stake(), 900);
        assert_eq!(round.reject_stake(), 100);
        assert!(round.has_stake_consensus(1000)); // 90% > 50%
    }

    #[test]
    fn test_double_vote_prevention() {
        let kp = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            kp.hotkey(),
            0,
        );

        let mut round = StakeWeightedRoundState::new(proposal, 30);

        let voter = Keypair::generate();

        // First vote should succeed
        assert!(round.add_vote(
            Vote::approve(round.proposal.id, voter.hotkey()),
            Stake::new(100)
        ));

        // Second vote should be rejected
        assert!(!round.add_vote(
            Vote::reject(round.proposal.id, voter.hotkey()),
            Stake::new(100)
        ));

        // Stake should still be 100 (first vote only)
        assert_eq!(round.approve_stake(), 100);
        assert_eq!(round.reject_stake(), 0);
    }

    #[test]
    fn test_has_voted_check() {
        let kp = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            kp.hotkey(),
            0,
        );

        let mut round = StakeWeightedRoundState::new(proposal, 30);

        let voter = Keypair::generate();

        assert!(!round.has_voted(&voter.hotkey()));
        round.add_vote(
            Vote::approve(round.proposal.id, voter.hotkey()),
            Stake::new(100),
        );
        assert!(round.has_voted(&voter.hotkey()));
    }

    #[test]
    fn test_stake_rejection() {
        let kp = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            kp.hotkey(),
            0,
        );

        let mut round = StakeWeightedRoundState::new(proposal, 30);

        // 60% stake rejects
        let v1 = Keypair::generate();
        round.add_vote(
            Vote::reject(round.proposal.id, v1.hotkey()),
            Stake::new(600),
        );

        assert!(round.is_stake_rejected(1000)); // 60% > 50%
        assert!(!round.has_stake_consensus(1000));
    }

    #[tokio::test]
    async fn test_stake_weighted_engine() {
        let (engine, _rx) = create_test_engine();

        // Add validators with different stakes
        {
            let mut state = engine.chain_state.write();
            let v1 = Keypair::generate();
            let v2 = Keypair::generate();

            state
                .add_validator(ValidatorInfo::new(v1.hotkey(), Stake::new(600_000_000_000)))
                .unwrap();
            state
                .add_validator(ValidatorInfo::new(v2.hotkey(), Stake::new(400_000_000_000)))
                .unwrap();
        }

        let total = engine.total_stake();
        assert_eq!(total, 1_000_000_000_000);

        let status = engine.status();
        assert_eq!(status.validator_count, 2);
        assert_eq!(status.threshold_stake, 500_000_000_001);
    }

    #[tokio::test]
    async fn test_sudo_proposal_stake_weighted() {
        let (engine, mut rx) = create_test_engine();

        // Add validators
        {
            let mut state = engine.chain_state.write();
            for _ in 0..3 {
                let kp = Keypair::generate();
                state
                    .add_validator(ValidatorInfo::new(kp.hotkey(), Stake::new(100_000_000_000)))
                    .unwrap();
            }
        }

        // Propose sudo action
        let action = SudoAction::UpdateConfig {
            config: NetworkConfig::default(),
        };
        let result = engine.propose_sudo(action).await;
        assert!(result.is_ok());

        // Should broadcast proposal and vote
        let msg1 = rx.recv().await.unwrap();
        let msg2 = rx.recv().await.unwrap();

        assert!(matches!(msg1.message, NetworkMessage::Proposal(_)));
        assert!(matches!(msg2.message, NetworkMessage::Vote(_)));
    }

    #[tokio::test]
    async fn test_handle_proposal_wrong_signer() {
        let (engine, _rx) = create_test_engine();
        let other_key = Keypair::generate().hotkey();

        let action = SudoAction::UpdateConfig {
            config: NetworkConfig::default(),
        };
        let proposal = Proposal::new(ProposalAction::Sudo(action), other_key.clone(), 0);

        let result = engine
            .handle_proposal(proposal, &engine.keypair.hotkey())
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_proposal_non_sudo() {
        let (engine, _rx) = create_test_engine();
        let non_sudo = Keypair::generate();

        let action = SudoAction::UpdateConfig {
            config: NetworkConfig::default(),
        };
        let proposal = Proposal::new(ProposalAction::Sudo(action), non_sudo.hotkey(), 0);

        let result = engine.handle_proposal(proposal, &non_sudo.hotkey()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_proposal_invalid_config() {
        let (engine, _rx) = create_test_engine();
        let sudo_key = engine.keypair.hotkey();

        let config = platform_core::ChallengeContainerConfig::new("", "", 1, 0.5);
        let challenge_id = config.challenge_id;

        let action = SudoAction::AddChallenge { config };
        let proposal = Proposal::new(ProposalAction::Sudo(action), sudo_key.clone(), 0);

        let result = engine.handle_proposal(proposal, &sudo_key).await;
        // Invalid config is accepted (doesn't error) but internally voted NO
        assert!(result.is_ok());

        // Verify the invalid config was NOT added to chain state
        assert!(!engine
            .chain_state
            .read()
            .challenge_configs
            .contains_key(&challenge_id));
    }

    #[tokio::test]
    async fn test_handle_vote_non_validator() {
        let (engine, _rx) = create_test_engine();
        let non_validator = Keypair::generate();

        let proposal_id = uuid::Uuid::new_v4();
        let vote = Vote::approve(proposal_id, non_validator.hotkey());

        let result = engine.handle_vote(vote, &non_validator.hotkey()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_apply_proposal_new_block() {
        let (engine, _rx) = create_test_engine();

        let state_hash = {
            let state = engine.chain_state.read();
            state.state_hash
        };

        let proposal = Proposal::new(
            ProposalAction::NewBlock { state_hash },
            engine.keypair.hotkey(),
            0,
        );

        let result = engine.apply_proposal(proposal).await;
        assert!(result.is_ok());

        let block = engine.chain_state.read().block_height;
        assert_eq!(block, 1);
    }

    #[tokio::test]
    async fn test_apply_proposal_job_completion() {
        let (engine, _rx) = create_test_engine();

        let proposal = Proposal::new(
            ProposalAction::JobCompletion {
                job_id: uuid::Uuid::new_v4(),
                result: platform_core::Score::new(0.75, 1.0),
                validator: engine.keypair.hotkey(),
            },
            engine.keypair.hotkey(),
            0,
        );

        let result = engine.apply_proposal(proposal).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_apply_sudo_action_all_variants() {
        let (engine, _rx) = create_test_engine();
        let challenge_id = platform_core::ChallengeId::new();

        // Test SetChallengeWeight
        let action = SudoAction::SetChallengeWeight {
            challenge_id,
            mechanism_id: 1,
            weight_ratio: 0.5,
        };
        let mut state = engine.chain_state.write();
        assert!(engine.apply_sudo_action(&mut state, action).is_ok());
        drop(state);

        // Test SetMechanismBurnRate
        let action = SudoAction::SetMechanismBurnRate {
            mechanism_id: 1,
            burn_rate: 0.2,
        };
        let mut state = engine.chain_state.write();
        assert!(engine.apply_sudo_action(&mut state, action).is_ok());
        drop(state);

        // Test SetMechanismConfig
        let action = SudoAction::SetMechanismConfig {
            mechanism_id: 2,
            config: platform_core::MechanismWeightConfig::new(2),
        };
        let mut state = engine.chain_state.write();
        assert!(engine.apply_sudo_action(&mut state, action).is_ok());
        drop(state);

        // Test EmergencyPause
        let action = SudoAction::EmergencyPause {
            reason: "Test".to_string(),
        };
        let mut state = engine.chain_state.write();
        assert!(engine.apply_sudo_action(&mut state, action).is_ok());
        drop(state);

        // Test Resume
        let action = SudoAction::Resume;
        let mut state = engine.chain_state.write();
        assert!(engine.apply_sudo_action(&mut state, action).is_ok());
        drop(state);

        // Test ForceStateUpdate
        let new_state = ChainState::new(Hotkey([99u8; 32]), NetworkConfig::default());
        let action = SudoAction::ForceStateUpdate {
            state: new_state.clone(),
        };
        let mut state = engine.chain_state.write();
        assert!(engine.apply_sudo_action(&mut state, action).is_ok());
    }

    #[tokio::test]
    async fn test_validate_sudo_action() {
        let (engine, _rx) = create_test_engine();
        let state = engine.chain_state.read();

        // Valid challenge
        let config = platform_core::ChallengeContainerConfig::new(
            "Valid",
            "ghcr.io/platformnetwork/valid:latest",
            1,
            0.5,
        );
        let action = SudoAction::AddChallenge { config };
        assert!(engine.validate_sudo_action(&state, &action));

        // Invalid challenge (empty name)
        let invalid_config = platform_core::ChallengeContainerConfig::new("", "", 1, 0.5);
        let action = SudoAction::AddChallenge {
            config: invalid_config,
        };
        assert!(!engine.validate_sudo_action(&state, &action));

        // Other actions validate true
        let action = SudoAction::Resume;
        assert!(engine.validate_sudo_action(&state, &action));
    }

    #[tokio::test]
    async fn test_validate_proposal() {
        let (engine, _rx) = create_test_engine();

        // Valid proposal
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            engine.keypair.hotkey(),
            0,
        );
        assert!(engine.validate_proposal(&proposal));

        // Invalid block height
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            engine.keypair.hotkey(),
            100,
        );
        assert!(!engine.validate_proposal(&proposal));

        // Non-sudo proposing sudo action
        let non_sudo = Keypair::generate();
        let action = SudoAction::UpdateConfig {
            config: NetworkConfig::default(),
        };
        let proposal = Proposal::new(ProposalAction::Sudo(action), non_sudo.hotkey(), 0);
        assert!(!engine.validate_proposal(&proposal));
    }

    #[tokio::test]
    async fn test_check_timeouts() {
        let (engine, _rx) = create_test_engine();

        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            engine.keypair.hotkey(),
            0,
        );
        engine.start_round(proposal);

        let timeouts = engine.check_timeouts();
        // Just verify it doesn't panic
        assert_eq!(timeouts.len(), 0);
    }

    #[tokio::test]
    async fn test_consensus_threshold() {
        let (engine, _rx) = create_test_engine();

        // Add validators with specific stakes
        {
            let mut state = engine.chain_state.write();
            let v1 = Keypair::generate();
            let v2 = Keypair::generate();
            state
                .add_validator(ValidatorInfo::new(v1.hotkey(), Stake::new(300_000_000_000)))
                .unwrap();
            state
                .add_validator(ValidatorInfo::new(v2.hotkey(), Stake::new(700_000_000_000)))
                .unwrap();
        }

        let total = engine.total_stake();
        assert_eq!(total, 1_000_000_000_000);

        let status = engine.status();
        // Threshold is total/2 + 1 = 500_000_000_001
        assert_eq!(status.threshold_stake, 500_000_000_001);
    }

    #[tokio::test]
    async fn test_propose_block_flow() {
        let (engine, mut rx) = create_test_engine();

        // Add validators
        {
            let mut state = engine.chain_state.write();
            for _ in 0..3 {
                let kp = Keypair::generate();
                let info = ValidatorInfo::new(kp.hotkey(), Stake::new(10_000_000_000));
                state.add_validator(info).unwrap();
            }
        }

        let result = engine.propose_block().await;
        assert!(result.is_ok());

        // Should broadcast proposal and vote
        let _proposal_msg = rx.recv().await;
        let _vote_msg = rx.recv().await;
    }

    #[tokio::test]
    async fn test_handle_result_pending() {
        let (engine, _rx) = create_test_engine();

        let result = StakeWeightedResult::Pending {
            approve_stake: 100,
            reject_stake: 50,
            total_stake: 1000,
        };

        // Should not panic
        let res = engine.handle_result(result).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_handle_result_timeout() {
        let (engine, _rx) = create_test_engine();

        let result = StakeWeightedResult::Timeout {
            proposal_id: uuid::Uuid::new_v4(),
        };

        // Should not panic
        let res = engine.handle_result(result).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_handle_result_rejected() {
        let (engine, _rx) = create_test_engine();

        let result = StakeWeightedResult::Rejected {
            proposal_id: uuid::Uuid::new_v4(),
            reject_stake: 600,
            total_stake: 1000,
            reason: "Test rejection".to_string(),
        };

        let res = engine.handle_result(result).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_apply_proposal_job_completion_details() {
        let (engine, _rx) = create_test_engine();

        let job_id = uuid::Uuid::new_v4();
        let proposal = Proposal::new(
            ProposalAction::JobCompletion {
                job_id,
                result: platform_core::Score::new(0.95, 1.0),
                validator: engine.keypair.hotkey(),
            },
            engine.keypair.hotkey(),
            0,
        );

        let result = engine.apply_proposal(proposal).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_apply_sudo_action_update_config() {
        let (engine, _rx) = create_test_engine();

        let action = SudoAction::UpdateConfig {
            config: NetworkConfig::default(),
        };

        let mut state = engine.chain_state.write();
        let result = engine.apply_sudo_action(&mut state, action);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_apply_sudo_action_add_challenge() {
        let (engine, _rx) = create_test_engine();

        let config = platform_core::ChallengeContainerConfig::new(
            "TestChallenge",
            "ghcr.io/platformnetwork/test:latest",
            1,
            0.5,
        );
        let action = SudoAction::AddChallenge {
            config: config.clone(),
        };

        let mut state = engine.chain_state.write();
        let result = engine.apply_sudo_action(&mut state, action);
        assert!(result.is_ok());
        assert!(state.challenge_configs.contains_key(&config.challenge_id));
    }

    #[tokio::test]
    async fn test_apply_sudo_action_update_challenge() {
        let (engine, _rx) = create_test_engine();

        let config = platform_core::ChallengeContainerConfig::new(
            "TestChallenge",
            "ghcr.io/platformnetwork/updated:latest",
            1,
            0.6,
        );
        let action = SudoAction::UpdateChallenge {
            config: config.clone(),
        };

        let mut state = engine.chain_state.write();
        let result = engine.apply_sudo_action(&mut state, action);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_apply_sudo_action_remove_challenge() {
        let (engine, _rx) = create_test_engine();

        let challenge_id = platform_core::ChallengeId::new();
        let action = SudoAction::RemoveChallenge { id: challenge_id };

        let mut state = engine.chain_state.write();
        let result = engine.apply_sudo_action(&mut state, action);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_apply_sudo_action_refresh_challenges() {
        let (engine, _rx) = create_test_engine();

        let action = SudoAction::RefreshChallenges {
            challenge_id: Some(platform_core::ChallengeId::new()),
        };

        let mut state = engine.chain_state.write();
        let result = engine.apply_sudo_action(&mut state, action);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_apply_sudo_action_set_required_version() {
        let (engine, _rx) = create_test_engine();

        let action = SudoAction::SetRequiredVersion {
            min_version: "1.5.0".to_string(),
            recommended_version: "1.6.0".to_string(),
            docker_image: "validator:1.5.0".to_string(),
            mandatory: false,
            deadline_block: None,
            release_notes: None,
        };

        let mut state = engine.chain_state.write();
        let result = engine.apply_sudo_action(&mut state, action);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_apply_sudo_action_add_validator() {
        let (engine, _rx) = create_test_engine();

        let new_val = ValidatorInfo::new(Hotkey([77u8; 32]), Stake::new(150_000_000_000));
        let action = SudoAction::AddValidator {
            info: new_val.clone(),
        };

        let mut state = engine.chain_state.write();
        let result = engine.apply_sudo_action(&mut state, action);
        assert!(result.is_ok());
        assert!(state.get_validator(&new_val.hotkey).is_some());
    }

    #[tokio::test]
    async fn test_apply_sudo_action_remove_validator() {
        let (engine, _rx) = create_test_engine();

        let hotkey = Hotkey([88u8; 32]);

        // Add validator first
        {
            let mut state = engine.chain_state.write();
            let val = ValidatorInfo::new(hotkey.clone(), Stake::new(100_000_000_000));
            state.add_validator(val).unwrap();
        }

        let action = SudoAction::RemoveValidator {
            hotkey: hotkey.clone(),
        };

        let mut state = engine.chain_state.write();
        let result = engine.apply_sudo_action(&mut state, action);
        assert!(result.is_ok());
        assert!(state.get_validator(&hotkey).is_none());
    }

    #[tokio::test]
    async fn test_validate_proposal_sudo_action() {
        let (engine, _rx) = create_test_engine();

        // Valid sudo action from sudo key
        let action = SudoAction::Resume;
        let proposal = Proposal::new(ProposalAction::Sudo(action), engine.keypair.hotkey(), 0);

        assert!(engine.validate_proposal(&proposal));
    }

    #[tokio::test]
    async fn test_check_timeouts_with_actual_timeout() {
        let (engine, _rx) = create_test_engine();

        // Create a proposal
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            engine.keypair.hotkey(),
            0,
        );
        engine.start_round(proposal);

        // Check timeouts (won't actually timeout immediately)
        let timeouts = engine.check_timeouts();
        assert_eq!(timeouts.len(), 0);
    }

    #[tokio::test]
    async fn test_active_rounds_tracking() {
        let (engine, _rx) = create_test_engine();

        assert_eq!(engine.active_rounds(), 0);

        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            engine.keypair.hotkey(),
            0,
        );
        engine.start_round(proposal);

        assert_eq!(engine.active_rounds(), 1);
    }

    #[test]
    fn test_round_state_total_stake_zero() {
        let kp = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            kp.hotkey(),
            0,
        );

        let round = StakeWeightedRoundState::new(proposal, 30);

        // With total_stake = 0, should return false
        assert!(!round.has_stake_consensus(0));
        assert!(!round.is_stake_rejected(0));
    }

    #[test]
    fn test_round_state_timeout() {
        let kp = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            kp.hotkey(),
            0,
        );

        let round = StakeWeightedRoundState::new(proposal, -1); // Negative timeout for immediate timeout
        assert!(round.is_timed_out());
    }

    #[tokio::test]
    async fn test_vote_internal_with_zero_stake() {
        let (engine, _rx) = create_test_engine();

        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            engine.keypair.hotkey(),
            0,
        );
        let proposal_id = engine.start_round(proposal);

        // Vote should work even with zero stake (for the engine itself)
        let result = engine.vote_internal(proposal_id, true).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_vote_wrong_voter_signature() {
        let (engine, _rx) = create_test_engine();

        let proposal_id = uuid::Uuid::new_v4();
        let wrong_voter = Keypair::generate().hotkey();
        let vote = Vote::approve(proposal_id, wrong_voter);

        let different_signer = Keypair::generate().hotkey();
        let result = engine.handle_vote(vote, &different_signer).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_vote_non_validator_no_stake() {
        let (engine, _rx) = create_test_engine();

        let non_validator = Keypair::generate();
        let proposal_id = uuid::Uuid::new_v4();
        let vote = Vote::approve(proposal_id, non_validator.hotkey());

        // Non-validator has no stake, should succeed but have no effect
        let result = engine.handle_vote(vote, &non_validator.hotkey()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_add_vote_with_stake_round_not_found() {
        let (engine, _rx) = create_test_engine();

        let fake_proposal_id = uuid::Uuid::new_v4();
        let vote = Vote::approve(fake_proposal_id, engine.keypair.hotkey());

        let result = engine.add_vote_with_stake(vote, Stake::new(100));
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_apply_proposal_new_block_hash_mismatch() {
        let (engine, _rx) = create_test_engine();

        let wrong_hash = [99u8; 32];
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: wrong_hash,
            },
            engine.keypair.hotkey(),
            0,
        );

        // Should succeed but not increment block due to hash mismatch
        let result = engine.apply_proposal(proposal).await;
        assert!(result.is_ok());

        let block = engine.chain_state.read().block_height;
        assert_eq!(block, 0); // Block not incremented
    }

    #[tokio::test]
    async fn test_validate_proposal_invalid_block_height() {
        let (engine, _rx) = create_test_engine();

        // Proposal with future block height
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            engine.keypair.hotkey(),
            1000,
        );

        assert!(!engine.validate_proposal(&proposal));
    }

    #[tokio::test]
    async fn test_validate_proposal_non_sudo_proposer() {
        let (engine, _rx) = create_test_engine();
        let non_sudo = Keypair::generate();

        let action = SudoAction::Resume;
        let proposal = Proposal::new(ProposalAction::Sudo(action), non_sudo.hotkey(), 0);

        assert!(!engine.validate_proposal(&proposal));
    }

    #[tokio::test]
    async fn test_check_timeouts_removes_timed_out() {
        let (engine, _rx) = create_test_engine();

        // Create a round with very short timeout
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            engine.keypair.hotkey(),
            0,
        );
        let proposal_id = proposal.id;

        // Manually insert a timed out round
        let round = StakeWeightedRoundState::new(proposal, -1);
        engine.rounds.write().insert(proposal_id, round);

        // Check timeouts should find and remove it
        let timeouts = engine.check_timeouts();
        assert!(!timeouts.is_empty());
        assert!(!engine.rounds.read().contains_key(&proposal_id));
    }
}
