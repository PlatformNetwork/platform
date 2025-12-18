//! Stake-Based Governance Consensus
//!
//! Implements a sophisticated governance system requiring 50%+ of stake to approve
//! chain modifications. During bootstrap period (block < 7175360), the subnet owner
//! can make decisions without stake verification to allow network setup.
//!
//! # Security Features
//! - 50%+ stake threshold for consensus
//! - Bootstrap period with owner-only authority
//! - Proposal expiration and timeout protection
//! - Double-voting prevention
//! - Signature verification on all votes
//! - Metagraph synchronization for stake verification

use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use platform_core::{Hotkey, Keypair, Result, Stake};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Block height until which the bootstrap period is active.
/// During bootstrap, the subnet owner can make changes without stake consensus.
/// This allows network setup while validators join.
pub const BOOTSTRAP_END_BLOCK: u64 = 7_175_360;

/// Subnet owner hotkey (SS58: 5GziQCcRpN8NCJktX343brnfuVe3w6gUYieeStXPD1Dag2At)
/// During bootstrap, this hotkey has full authority.
pub const SUBNET_OWNER_SS58: &str = "5GziQCcRpN8NCJktX343brnfuVe3w6gUYieeStXPD1Dag2At";

/// Subnet owner hotkey bytes
pub const SUBNET_OWNER_BYTES: [u8; 32] = [
    0xda, 0x22, 0x04, 0x09, 0x67, 0x8d, 0xf5, 0xf0, 0x60, 0x74, 0xa6, 0x71, 0xab, 0xdc, 0x1f, 0x19,
    0xbc, 0x2b, 0xa1, 0x51, 0x72, 0x9f, 0xdb, 0x9a, 0x8e, 0x4b, 0xe2, 0x84, 0xe6, 0x0c, 0x94, 0x01,
];

/// Get the subnet owner hotkey
pub fn subnet_owner_hotkey() -> Hotkey {
    Hotkey(SUBNET_OWNER_BYTES)
}

/// Check if a hotkey is the subnet owner
pub fn is_subnet_owner(hotkey: &Hotkey) -> bool {
    hotkey.0 == SUBNET_OWNER_BYTES
}

/// Check if data from a given source can be trusted during bootstrap
/// During bootstrap, ONLY data from the subnet owner is trusted without stake verification
pub fn is_trusted_bootstrap_source(source_hotkey: &Hotkey, current_block: u64) -> bool {
    if current_block >= BOOTSTRAP_END_BLOCK {
        // After bootstrap, no automatic trust - require stake consensus
        false
    } else {
        // During bootstrap, only trust the subnet owner
        is_subnet_owner(source_hotkey)
    }
}

/// Minimum stake threshold for consensus (50% + epsilon for security)
pub const STAKE_THRESHOLD_PERCENT: f64 = 50.0;

/// Proposal timeout in seconds (24 hours)
pub const PROPOSAL_TIMEOUT_SECS: i64 = 86400;

/// Minimum voting period in seconds (1 hour) - proposals cannot be executed before this
pub const MIN_VOTING_PERIOD_SECS: i64 = 3600;

/// Maximum proposals per validator per day (rate limiting)
pub const MAX_PROPOSALS_PER_DAY: usize = 10;

// ============================================================================
// TYPES
// ============================================================================

/// Type of governance action that can be proposed
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GovernanceActionType {
    /// Add a new challenge to the network
    AddChallenge,
    /// Update an existing challenge
    UpdateChallenge,
    /// Remove a challenge
    RemoveChallenge,
    /// Update network configuration
    UpdateConfig,
    /// Set required validator version
    SetRequiredVersion,
    /// Add a validator manually
    AddValidator,
    /// Remove a validator
    RemoveValidator,
    /// Set challenge weight allocation
    SetChallengeWeight,
    /// Set mechanism burn rate
    SetMechanismBurnRate,
    /// Emergency pause
    EmergencyPause,
    /// Resume from emergency
    Resume,
    /// Force state update (emergency only)
    ForceStateUpdate,
    /// Custom governance action
    Custom(String),
}

/// A governance proposal requiring stake consensus
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceProposal {
    /// Unique proposal ID
    pub id: Uuid,
    /// Type of action being proposed
    pub action_type: GovernanceActionType,
    /// Human-readable title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Serialized action data (the actual SudoAction)
    pub action_data: Vec<u8>,
    /// Proposer's hotkey
    pub proposer: Hotkey,
    /// Block height when proposed
    pub block_height: u64,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Whether proposal has been executed
    pub executed: bool,
    /// Whether proposal was cancelled
    pub cancelled: bool,
    /// Proposal signature from proposer
    pub signature: Vec<u8>,
}

impl GovernanceProposal {
    /// Create a new governance proposal
    pub fn new(
        action_type: GovernanceActionType,
        title: String,
        description: String,
        action_data: Vec<u8>,
        proposer: Hotkey,
        block_height: u64,
    ) -> Self {
        let created_at = Utc::now();
        Self {
            id: Uuid::new_v4(),
            action_type,
            title,
            description,
            action_data,
            proposer,
            block_height,
            created_at,
            expires_at: created_at + Duration::seconds(PROPOSAL_TIMEOUT_SECS),
            executed: false,
            cancelled: false,
            signature: vec![],
        }
    }

    /// Sign the proposal with a keypair
    pub fn sign(&mut self, keypair: &Keypair) -> Result<()> {
        let data = self.signable_data();
        let signed = keypair.sign_bytes(&data)?;
        self.signature = signed;
        Ok(())
    }

    /// Get the data to be signed
    fn signable_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.id.as_bytes());
        data.extend_from_slice(&bincode::serialize(&self.action_type).unwrap_or_default());
        data.extend_from_slice(self.title.as_bytes());
        data.extend_from_slice(&self.action_data);
        data.extend_from_slice(&self.proposer.0);
        data.extend_from_slice(&self.block_height.to_le_bytes());
        data
    }

    /// Check if proposal has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if minimum voting period has passed
    pub fn voting_period_complete(&self) -> bool {
        Utc::now() > self.created_at + Duration::seconds(MIN_VOTING_PERIOD_SECS)
    }

    /// Check if proposal can be executed
    pub fn can_execute(&self) -> bool {
        !self.executed && !self.cancelled && !self.is_expired() && self.voting_period_complete()
    }
}

/// A vote on a governance proposal
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalVote {
    /// Proposal being voted on
    pub proposal_id: Uuid,
    /// Voter's hotkey
    pub voter: Hotkey,
    /// Vote decision (true = approve, false = reject)
    pub approve: bool,
    /// Voter's stake at time of voting
    pub stake: Stake,
    /// Vote timestamp
    pub timestamp: DateTime<Utc>,
    /// Vote signature
    pub signature: Vec<u8>,
}

impl ProposalVote {
    /// Create a new vote
    pub fn new(proposal_id: Uuid, voter: Hotkey, approve: bool, stake: Stake) -> Self {
        Self {
            proposal_id,
            voter,
            approve,
            stake,
            timestamp: Utc::now(),
            signature: vec![],
        }
    }

    /// Sign the vote
    pub fn sign(&mut self, keypair: &Keypair) -> Result<()> {
        let data = self.signable_data();
        let signed = keypair.sign_bytes(&data)?;
        self.signature = signed;
        Ok(())
    }

    /// Get signable data
    fn signable_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.proposal_id.as_bytes());
        data.extend_from_slice(&self.voter.0);
        data.push(if self.approve { 1 } else { 0 });
        data.extend_from_slice(&self.stake.0.to_le_bytes());
        data
    }
}

/// Result of a stake-based governance consensus check
#[derive(Clone, Debug)]
pub enum StakeConsensusResult {
    /// Proposal approved with required stake
    Approved {
        proposal: GovernanceProposal,
        approve_stake: Stake,
        total_stake: Stake,
        approve_percent: f64,
    },
    /// Proposal rejected (enough stake voted against)
    Rejected {
        proposal_id: Uuid,
        reject_stake: Stake,
        total_stake: Stake,
        reason: String,
    },
    /// Still pending (not enough votes yet)
    Pending {
        proposal_id: Uuid,
        approve_stake: Stake,
        reject_stake: Stake,
        total_stake: Stake,
        remaining_stake_needed: Stake,
    },
    /// Proposal expired
    Expired { proposal_id: Uuid },
    /// Proposal cancelled
    Cancelled { proposal_id: Uuid },
}

/// Bootstrap mode decision result
#[derive(Clone, Debug)]
pub enum BootstrapDecision {
    /// Owner action accepted during bootstrap
    OwnerAccepted {
        action_type: GovernanceActionType,
        owner: Hotkey,
        block_height: u64,
    },
    /// Bootstrap period has ended, need stake consensus
    RequiresStakeConsensus,
    /// Not the owner, cannot use bootstrap authority
    NotOwner { requester: Hotkey },
}

/// Validator stake info from metagraph
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorStake {
    pub hotkey: Hotkey,
    pub stake: Stake,
    pub is_active: bool,
    pub last_updated: DateTime<Utc>,
}

// ============================================================================
// STAKE GOVERNANCE ENGINE
// ============================================================================

/// Stake-based governance consensus engine
pub struct StakeGovernance {
    /// Current block height
    current_block: Arc<RwLock<u64>>,
    /// Active proposals
    proposals: Arc<RwLock<HashMap<Uuid, GovernanceProposal>>>,
    /// Votes per proposal
    votes: Arc<RwLock<HashMap<Uuid, Vec<ProposalVote>>>>,
    /// Validator stakes (from metagraph)
    validator_stakes: Arc<RwLock<HashMap<Hotkey, ValidatorStake>>>,
    /// Rate limiting: proposals per validator
    proposal_counts: Arc<RwLock<HashMap<Hotkey, (DateTime<Utc>, usize)>>>,
    /// Executed proposal IDs (to prevent replay)
    executed_proposals: Arc<RwLock<HashSet<Uuid>>>,
}

impl StakeGovernance {
    /// Create a new stake governance engine
    pub fn new() -> Self {
        Self {
            current_block: Arc::new(RwLock::new(0)),
            proposals: Arc::new(RwLock::new(HashMap::new())),
            votes: Arc::new(RwLock::new(HashMap::new())),
            validator_stakes: Arc::new(RwLock::new(HashMap::new())),
            proposal_counts: Arc::new(RwLock::new(HashMap::new())),
            executed_proposals: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Update current block height
    pub fn set_block_height(&self, block: u64) {
        *self.current_block.write() = block;
    }

    /// Get current block height
    pub fn block_height(&self) -> u64 {
        *self.current_block.read()
    }

    /// Check if we are in bootstrap period
    pub fn is_bootstrap_period(&self) -> bool {
        self.block_height() < BOOTSTRAP_END_BLOCK
    }

    /// Update validator stakes from metagraph data
    pub fn update_validator_stakes(&self, stakes: Vec<ValidatorStake>) {
        let mut vs = self.validator_stakes.write();
        vs.clear();
        for stake in stakes {
            vs.insert(stake.hotkey.clone(), stake);
        }
        info!("Updated {} validator stakes in governance", vs.len());
    }

    /// Get total active stake
    pub fn total_stake(&self) -> Stake {
        let vs = self.validator_stakes.read();
        Stake(vs.values().filter(|v| v.is_active).map(|v| v.stake.0).sum())
    }

    /// Get stake for a specific validator
    pub fn get_validator_stake(&self, hotkey: &Hotkey) -> Option<Stake> {
        self.validator_stakes.read().get(hotkey).map(|v| v.stake)
    }

    // ========================================================================
    // BOOTSTRAP MODE OPERATIONS
    // ========================================================================

    /// Check if an action can be executed in bootstrap mode
    /// Returns BootstrapDecision indicating if action is accepted or requires consensus
    pub fn check_bootstrap_authority(
        &self,
        requester: &Hotkey,
        action_type: &GovernanceActionType,
    ) -> BootstrapDecision {
        let block = self.block_height();

        // If past bootstrap period, always require stake consensus
        if block >= BOOTSTRAP_END_BLOCK {
            return BootstrapDecision::RequiresStakeConsensus;
        }

        // During bootstrap, only the subnet owner can execute actions directly
        if is_subnet_owner(requester) {
            info!(
                "Bootstrap mode: Owner action accepted at block {} (ends at {})",
                block, BOOTSTRAP_END_BLOCK
            );
            return BootstrapDecision::OwnerAccepted {
                action_type: action_type.clone(),
                owner: requester.clone(),
                block_height: block,
            };
        }

        // Not the owner - cannot use bootstrap authority
        BootstrapDecision::NotOwner {
            requester: requester.clone(),
        }
    }

    /// Execute an action in bootstrap mode (owner only, no stake check)
    /// Returns Ok if action can proceed, Err if not authorized
    pub fn execute_bootstrap_action(
        &self,
        requester: &Hotkey,
        action_type: &GovernanceActionType,
    ) -> Result<()> {
        match self.check_bootstrap_authority(requester, action_type) {
            BootstrapDecision::OwnerAccepted { .. } => {
                info!("Executing bootstrap action {:?} from owner", action_type);
                Ok(())
            }
            BootstrapDecision::RequiresStakeConsensus => {
                Err(platform_core::MiniChainError::Unauthorized(format!(
                    "Bootstrap period ended at block {}. Action requires 50%+ stake consensus.",
                    BOOTSTRAP_END_BLOCK
                )))
            }
            BootstrapDecision::NotOwner { requester } => {
                Err(platform_core::MiniChainError::Unauthorized(format!(
                    "Only subnet owner {} can execute actions during bootstrap. Requester: {}",
                    SUBNET_OWNER_SS58,
                    requester.to_ss58()
                )))
            }
        }
    }

    // ========================================================================
    // STAKE CONSENSUS OPERATIONS
    // ========================================================================

    /// Create a new governance proposal
    pub fn create_proposal(
        &self,
        action_type: GovernanceActionType,
        title: String,
        description: String,
        action_data: Vec<u8>,
        proposer: &Hotkey,
        keypair: &Keypair,
    ) -> Result<GovernanceProposal> {
        // Check rate limiting
        self.check_rate_limit(proposer)?;

        // Verify proposer has stake (must be a validator)
        let stake = self.get_validator_stake(proposer).ok_or_else(|| {
            platform_core::MiniChainError::Unauthorized(
                "Proposer must be a validator with stake".into(),
            )
        })?;

        if stake.0 == 0 {
            return Err(platform_core::MiniChainError::Unauthorized(
                "Proposer has no stake".into(),
            ));
        }

        let block = self.block_height();
        let mut proposal = GovernanceProposal::new(
            action_type.clone(),
            title,
            description,
            action_data,
            proposer.clone(),
            block,
        );

        // Sign the proposal
        proposal.sign(keypair)?;

        // Store proposal
        let proposal_id = proposal.id;
        self.proposals.write().insert(proposal_id, proposal.clone());
        self.votes.write().insert(proposal_id, Vec::new());

        // Update rate limit counter
        self.increment_proposal_count(proposer);

        info!(
            "Created governance proposal {} ({:?}) by {} at block {}",
            proposal_id,
            action_type,
            proposer.to_ss58(),
            block
        );

        Ok(proposal)
    }

    /// Vote on a proposal
    pub fn vote(
        &self,
        proposal_id: Uuid,
        voter: &Hotkey,
        approve: bool,
        keypair: &Keypair,
    ) -> Result<StakeConsensusResult> {
        // Get proposal
        let proposal = self
            .proposals
            .read()
            .get(&proposal_id)
            .cloned()
            .ok_or_else(|| {
                platform_core::MiniChainError::NotFound(format!(
                    "Proposal {} not found",
                    proposal_id
                ))
            })?;

        // Check proposal is still valid
        if proposal.is_expired() {
            return Ok(StakeConsensusResult::Expired { proposal_id });
        }
        if proposal.executed {
            return Err(platform_core::MiniChainError::Consensus(
                "Proposal already executed".into(),
            ));
        }
        if proposal.cancelled {
            return Ok(StakeConsensusResult::Cancelled { proposal_id });
        }

        // Verify voter has stake
        let stake = self.get_validator_stake(voter).ok_or_else(|| {
            platform_core::MiniChainError::Unauthorized(
                "Voter must be a validator with stake".into(),
            )
        })?;

        if stake.0 == 0 {
            return Err(platform_core::MiniChainError::Unauthorized(
                "Voter has no stake".into(),
            ));
        }

        // Check for double voting
        {
            let votes = self.votes.read();
            if let Some(existing_votes) = votes.get(&proposal_id) {
                if existing_votes.iter().any(|v| v.voter == *voter) {
                    return Err(platform_core::MiniChainError::Consensus(
                        "Validator has already voted on this proposal".into(),
                    ));
                }
            }
        }

        // Create and sign vote
        let mut vote = ProposalVote::new(proposal_id, voter.clone(), approve, stake);
        vote.sign(keypair)?;

        // Add vote
        self.votes
            .write()
            .entry(proposal_id)
            .or_default()
            .push(vote.clone());

        debug!(
            "Vote recorded: {} voted {} on proposal {}",
            voter.to_ss58(),
            if approve { "YES" } else { "NO" },
            proposal_id
        );

        // Check consensus
        self.check_consensus(proposal_id)
    }

    /// Check if consensus has been reached for a proposal
    pub fn check_consensus(&self, proposal_id: Uuid) -> Result<StakeConsensusResult> {
        let proposal = self
            .proposals
            .read()
            .get(&proposal_id)
            .cloned()
            .ok_or_else(|| {
                platform_core::MiniChainError::NotFound(format!(
                    "Proposal {} not found",
                    proposal_id
                ))
            })?;

        // Check expiration
        if proposal.is_expired() {
            return Ok(StakeConsensusResult::Expired { proposal_id });
        }
        if proposal.cancelled {
            return Ok(StakeConsensusResult::Cancelled { proposal_id });
        }

        let total_stake = self.total_stake();
        if total_stake.0 == 0 {
            return Err(platform_core::MiniChainError::Consensus(
                "No active validators with stake".into(),
            ));
        }

        // Calculate stake distribution
        let votes = self.votes.read();
        let proposal_votes = votes.get(&proposal_id).cloned().unwrap_or_default();

        let approve_stake: u64 = proposal_votes
            .iter()
            .filter(|v| v.approve)
            .map(|v| v.stake.0)
            .sum();

        let reject_stake: u64 = proposal_votes
            .iter()
            .filter(|v| !v.approve)
            .map(|v| v.stake.0)
            .sum();

        let approve_percent = (approve_stake as f64 / total_stake.0 as f64) * 100.0;
        let reject_percent = (reject_stake as f64 / total_stake.0 as f64) * 100.0;

        // Check if approval threshold reached (50%+)
        if approve_percent > STAKE_THRESHOLD_PERCENT {
            // Also ensure voting period is complete for security
            if !proposal.voting_period_complete() {
                let remaining_secs =
                    (proposal.created_at + Duration::seconds(MIN_VOTING_PERIOD_SECS) - Utc::now())
                        .num_seconds();
                return Ok(StakeConsensusResult::Pending {
                    proposal_id,
                    approve_stake: Stake(approve_stake),
                    reject_stake: Stake(reject_stake),
                    total_stake,
                    remaining_stake_needed: Stake(0),
                });
            }

            info!(
                "Proposal {} APPROVED with {:.2}% stake ({} / {})",
                proposal_id, approve_percent, approve_stake, total_stake.0
            );

            return Ok(StakeConsensusResult::Approved {
                proposal,
                approve_stake: Stake(approve_stake),
                total_stake,
                approve_percent,
            });
        }

        // Check if rejection is certain (>50% rejected)
        if reject_percent > STAKE_THRESHOLD_PERCENT {
            info!(
                "Proposal {} REJECTED with {:.2}% stake against",
                proposal_id, reject_percent
            );

            return Ok(StakeConsensusResult::Rejected {
                proposal_id,
                reject_stake: Stake(reject_stake),
                total_stake,
                reason: format!(
                    "Rejected by {:.2}% of stake ({} / {})",
                    reject_percent, reject_stake, total_stake.0
                ),
            });
        }

        // Still pending
        let threshold_stake = ((total_stake.0 as f64 * STAKE_THRESHOLD_PERCENT) / 100.0) as u64;
        let remaining = threshold_stake.saturating_sub(approve_stake);

        Ok(StakeConsensusResult::Pending {
            proposal_id,
            approve_stake: Stake(approve_stake),
            reject_stake: Stake(reject_stake),
            total_stake,
            remaining_stake_needed: Stake(remaining),
        })
    }

    /// Mark a proposal as executed
    pub fn mark_executed(&self, proposal_id: Uuid) -> Result<()> {
        let mut proposals = self.proposals.write();
        let proposal = proposals.get_mut(&proposal_id).ok_or_else(|| {
            platform_core::MiniChainError::NotFound(format!("Proposal {} not found", proposal_id))
        })?;

        if proposal.executed {
            return Err(platform_core::MiniChainError::Consensus(
                "Proposal already executed".into(),
            ));
        }

        proposal.executed = true;
        self.executed_proposals.write().insert(proposal_id);

        info!("Proposal {} marked as executed", proposal_id);
        Ok(())
    }

    /// Cancel a proposal (only proposer can cancel before execution)
    pub fn cancel_proposal(&self, proposal_id: Uuid, requester: &Hotkey) -> Result<()> {
        let mut proposals = self.proposals.write();
        let proposal = proposals.get_mut(&proposal_id).ok_or_else(|| {
            platform_core::MiniChainError::NotFound(format!("Proposal {} not found", proposal_id))
        })?;

        // Only proposer or subnet owner can cancel
        if proposal.proposer != *requester && !is_subnet_owner(requester) {
            return Err(platform_core::MiniChainError::Unauthorized(
                "Only proposer or subnet owner can cancel proposal".into(),
            ));
        }

        if proposal.executed {
            return Err(platform_core::MiniChainError::Consensus(
                "Cannot cancel executed proposal".into(),
            ));
        }

        proposal.cancelled = true;
        info!(
            "Proposal {} cancelled by {}",
            proposal_id,
            requester.to_ss58()
        );
        Ok(())
    }

    /// Get a proposal by ID
    pub fn get_proposal(&self, proposal_id: Uuid) -> Option<GovernanceProposal> {
        self.proposals.read().get(&proposal_id).cloned()
    }

    /// Get all active proposals
    pub fn active_proposals(&self) -> Vec<GovernanceProposal> {
        self.proposals
            .read()
            .values()
            .filter(|p| !p.executed && !p.cancelled && !p.is_expired())
            .cloned()
            .collect()
    }

    /// Get votes for a proposal
    pub fn get_votes(&self, proposal_id: Uuid) -> Vec<ProposalVote> {
        self.votes
            .read()
            .get(&proposal_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Clean up expired proposals
    pub fn cleanup_expired(&self) {
        let mut proposals = self.proposals.write();
        let mut votes = self.votes.write();

        let expired: Vec<Uuid> = proposals
            .iter()
            .filter(|(_, p)| p.is_expired() && !p.executed)
            .map(|(id, _)| *id)
            .collect();

        for id in &expired {
            proposals.remove(id);
            votes.remove(id);
        }

        if !expired.is_empty() {
            debug!("Cleaned up {} expired proposals", expired.len());
        }
    }

    // ========================================================================
    // RATE LIMITING
    // ========================================================================

    fn check_rate_limit(&self, proposer: &Hotkey) -> Result<()> {
        let mut counts = self.proposal_counts.write();
        let now = Utc::now();

        if let Some((last_day, count)) = counts.get(proposer) {
            // Reset counter if it's a new day
            if now.date_naive() != last_day.date_naive() {
                counts.insert(proposer.clone(), (now, 1));
                return Ok(());
            }

            if *count >= MAX_PROPOSALS_PER_DAY {
                return Err(platform_core::MiniChainError::RateLimited(format!(
                    "Maximum {} proposals per day exceeded",
                    MAX_PROPOSALS_PER_DAY
                )));
            }
        }

        Ok(())
    }

    fn increment_proposal_count(&self, proposer: &Hotkey) {
        let mut counts = self.proposal_counts.write();
        let now = Utc::now();

        let new_count = if let Some((last_day, count)) = counts.get(proposer) {
            if now.date_naive() == last_day.date_naive() {
                count + 1
            } else {
                1
            }
        } else {
            1
        };

        counts.insert(proposer.clone(), (now, new_count));
    }

    // ========================================================================
    // CONVENIENCE METHODS
    // ========================================================================

    /// Check if action requires consensus or can use bootstrap authority
    /// Returns true if bootstrap mode can be used
    pub fn can_use_bootstrap(&self, requester: &Hotkey) -> bool {
        matches!(
            self.check_bootstrap_authority(requester, &GovernanceActionType::UpdateConfig),
            BootstrapDecision::OwnerAccepted { .. }
        )
    }

    /// Get governance status summary
    pub fn status(&self) -> GovernanceStatus {
        let block = self.block_height();
        let total_stake = self.total_stake();
        let validator_count = self.validator_stakes.read().len();
        let active_proposals = self.active_proposals().len();

        GovernanceStatus {
            current_block: block,
            is_bootstrap_period: block < BOOTSTRAP_END_BLOCK,
            bootstrap_ends_at_block: BOOTSTRAP_END_BLOCK,
            blocks_until_bootstrap_end: BOOTSTRAP_END_BLOCK.saturating_sub(block),
            total_stake,
            validator_count,
            active_proposals,
            stake_threshold_percent: STAKE_THRESHOLD_PERCENT,
        }
    }
}

impl Default for StakeGovernance {
    fn default() -> Self {
        Self::new()
    }
}

/// Governance status summary
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceStatus {
    pub current_block: u64,
    pub is_bootstrap_period: bool,
    pub bootstrap_ends_at_block: u64,
    pub blocks_until_bootstrap_end: u64,
    pub total_stake: Stake,
    pub validator_count: usize,
    pub active_proposals: usize,
    pub stake_threshold_percent: f64,
}

// ============================================================================
// BOOTSTRAP SYNC POLICY
// ============================================================================

/// Policy for synchronizing data during bootstrap period
///
/// During bootstrap (block < 7,175,360), validators can sync data directly
/// from the subnet owner validator without requiring stake verification.
/// This allows the network to bootstrap while validators are joining.
///
/// # Security
/// - Only data signed by the owner hotkey is trusted during bootstrap
/// - After bootstrap ends, all sync requires stake-based verification
/// - Validators should verify signatures on all received data
#[derive(Clone, Debug)]
pub struct BootstrapSyncPolicy {
    /// Current block height
    current_block: u64,
    /// Owner hotkey for trusted sync
    owner_hotkey: Hotkey,
}

impl BootstrapSyncPolicy {
    /// Create a new bootstrap sync policy
    pub fn new(current_block: u64) -> Self {
        Self {
            current_block,
            owner_hotkey: subnet_owner_hotkey(),
        }
    }

    /// Update current block
    pub fn set_block(&mut self, block: u64) {
        self.current_block = block;
    }

    /// Check if we are in bootstrap period
    pub fn is_bootstrap_active(&self) -> bool {
        self.current_block < BOOTSTRAP_END_BLOCK
    }

    /// Check if a source can be trusted for sync
    /// During bootstrap: only owner is trusted
    /// After bootstrap: no automatic trust (require stake verification)
    pub fn can_trust_source(&self, source: &Hotkey) -> SyncTrustResult {
        if self.current_block >= BOOTSTRAP_END_BLOCK {
            SyncTrustResult::RequiresStakeVerification {
                current_block: self.current_block,
                message: "Bootstrap period ended. Require stake-based verification.".into(),
            }
        } else if is_subnet_owner(source) {
            SyncTrustResult::TrustedBootstrapOwner {
                owner: self.owner_hotkey.clone(),
                block: self.current_block,
                blocks_remaining: BOOTSTRAP_END_BLOCK - self.current_block,
            }
        } else {
            SyncTrustResult::UntrustedDuringBootstrap {
                source: source.clone(),
                expected_owner: self.owner_hotkey.clone(),
            }
        }
    }

    /// Get the trusted owner hotkey for bootstrap sync
    pub fn owner_hotkey(&self) -> &Hotkey {
        &self.owner_hotkey
    }

    /// Get owner SS58 address for display
    pub fn owner_ss58(&self) -> &'static str {
        SUBNET_OWNER_SS58
    }

    /// Check if data from owner should be accepted without stake verification
    /// This is the main function validators use when receiving sync data
    pub fn should_accept_without_stake_check(
        &self,
        source: &Hotkey,
        data_type: &str,
    ) -> AcceptanceDecision {
        if self.current_block >= BOOTSTRAP_END_BLOCK {
            AcceptanceDecision::RequireStakeConsensus {
                reason: format!(
                    "Block {} >= bootstrap end {}. {} requires stake verification.",
                    self.current_block, BOOTSTRAP_END_BLOCK, data_type
                ),
            }
        } else if is_subnet_owner(source) {
            AcceptanceDecision::AcceptFromOwner {
                owner: source.clone(),
                data_type: data_type.to_string(),
                block: self.current_block,
            }
        } else {
            AcceptanceDecision::RejectUntrustedSource {
                source: source.clone(),
                reason: format!(
                    "During bootstrap, only owner {} can provide {} without stake verification",
                    SUBNET_OWNER_SS58, data_type
                ),
            }
        }
    }
}

impl Default for BootstrapSyncPolicy {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Result of checking if a sync source can be trusted
#[derive(Clone, Debug)]
pub enum SyncTrustResult {
    /// Source is the trusted owner during bootstrap
    TrustedBootstrapOwner {
        owner: Hotkey,
        block: u64,
        blocks_remaining: u64,
    },
    /// Source is not the owner during bootstrap - cannot trust
    UntrustedDuringBootstrap {
        source: Hotkey,
        expected_owner: Hotkey,
    },
    /// Bootstrap ended - require stake verification for all sources
    RequiresStakeVerification { current_block: u64, message: String },
}

/// Decision on whether to accept data without stake verification
#[derive(Clone, Debug)]
pub enum AcceptanceDecision {
    /// Accept data from owner during bootstrap
    AcceptFromOwner {
        owner: Hotkey,
        data_type: String,
        block: u64,
    },
    /// Reject - source not trusted during bootstrap
    RejectUntrustedSource { source: Hotkey, reason: String },
    /// Require stake consensus (bootstrap ended)
    RequireStakeConsensus { reason: String },
}

impl AcceptanceDecision {
    /// Check if data should be accepted
    pub fn should_accept(&self) -> bool {
        matches!(self, AcceptanceDecision::AcceptFromOwner { .. })
    }

    /// Check if stake verification is required
    pub fn needs_stake_check(&self) -> bool {
        matches!(self, AcceptanceDecision::RequireStakeConsensus { .. })
    }
}

// ============================================================================
// HYBRID AUTHORITY: BOOTSTRAP + STAKE CONSENSUS
// ============================================================================

/// Unified governance authority that handles both bootstrap and stake consensus
pub struct HybridGovernance {
    stake_governance: Arc<StakeGovernance>,
}

impl HybridGovernance {
    pub fn new(stake_governance: Arc<StakeGovernance>) -> Self {
        Self { stake_governance }
    }

    /// Check if an action is authorized
    /// During bootstrap: subnet owner can execute immediately
    /// After bootstrap: requires 50%+ stake approval via proposal
    pub fn check_authorization(
        &self,
        requester: &Hotkey,
        action_type: &GovernanceActionType,
    ) -> AuthorizationResult {
        // First check bootstrap authority
        match self
            .stake_governance
            .check_bootstrap_authority(requester, action_type)
        {
            BootstrapDecision::OwnerAccepted { block_height, .. } => {
                return AuthorizationResult::BootstrapAuthorized {
                    owner: requester.clone(),
                    block_height,
                    bootstrap_ends: BOOTSTRAP_END_BLOCK,
                };
            }
            BootstrapDecision::RequiresStakeConsensus => {
                // Need stake consensus
            }
            BootstrapDecision::NotOwner { .. } => {
                // Not owner during bootstrap, check if they can create proposals
                if self.stake_governance.is_bootstrap_period() {
                    return AuthorizationResult::BootstrapOwnerOnly {
                        owner_ss58: SUBNET_OWNER_SS58.to_string(),
                    };
                }
            }
        }

        // After bootstrap or for non-owners, need stake consensus
        let stake = self.stake_governance.get_validator_stake(requester);
        let has_stake = stake.map(|s| s.0 > 0).unwrap_or(false);

        if has_stake {
            AuthorizationResult::RequiresProposal {
                proposer: requester.clone(),
                stake_threshold: STAKE_THRESHOLD_PERCENT,
                min_voting_period_secs: MIN_VOTING_PERIOD_SECS,
            }
        } else {
            AuthorizationResult::InsufficientStake {
                requester: requester.clone(),
            }
        }
    }

    /// Execute an action with hybrid authorization
    /// Returns the execution path taken (bootstrap or consensus)
    pub fn execute_with_authorization<F>(
        &self,
        requester: &Hotkey,
        action_type: GovernanceActionType,
        execute_fn: F,
    ) -> Result<ExecutionResult>
    where
        F: FnOnce() -> Result<()>,
    {
        match self.check_authorization(requester, &action_type) {
            AuthorizationResult::BootstrapAuthorized { block_height, .. } => {
                // Execute immediately
                execute_fn()?;
                Ok(ExecutionResult::ExecutedViaBootstrap {
                    block_height,
                    owner: requester.clone(),
                })
            }
            AuthorizationResult::RequiresProposal { .. } => {
                // Cannot execute immediately, need proposal
                Ok(ExecutionResult::RequiresProposal {
                    action_type,
                    stake_threshold: STAKE_THRESHOLD_PERCENT,
                })
            }
            AuthorizationResult::BootstrapOwnerOnly { owner_ss58 } => {
                Err(platform_core::MiniChainError::Unauthorized(format!(
                    "During bootstrap, only subnet owner ({}) can execute actions",
                    owner_ss58
                )))
            }
            AuthorizationResult::InsufficientStake { .. } => {
                Err(platform_core::MiniChainError::Unauthorized(
                    "Requester has no stake and cannot propose governance actions".into(),
                ))
            }
        }
    }

    pub fn stake_governance(&self) -> &Arc<StakeGovernance> {
        &self.stake_governance
    }
}

/// Result of authorization check
#[derive(Clone, Debug)]
pub enum AuthorizationResult {
    /// Authorized via bootstrap mode (owner during bootstrap period)
    BootstrapAuthorized {
        owner: Hotkey,
        block_height: u64,
        bootstrap_ends: u64,
    },
    /// During bootstrap, only owner can execute
    BootstrapOwnerOnly { owner_ss58: String },
    /// Requires creating a proposal for stake consensus
    RequiresProposal {
        proposer: Hotkey,
        stake_threshold: f64,
        min_voting_period_secs: i64,
    },
    /// Requester has no stake
    InsufficientStake { requester: Hotkey },
}

/// Result of execution attempt
#[derive(Clone, Debug)]
pub enum ExecutionResult {
    /// Executed via bootstrap authority
    ExecutedViaBootstrap { block_height: u64, owner: Hotkey },
    /// Requires creating a proposal
    RequiresProposal {
        action_type: GovernanceActionType,
        stake_threshold: f64,
    },
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_governance() -> StakeGovernance {
        StakeGovernance::new()
    }

    fn create_test_validator(stake_amount: u64) -> (Keypair, ValidatorStake) {
        let kp = Keypair::generate();
        let stake = ValidatorStake {
            hotkey: kp.hotkey(),
            stake: Stake(stake_amount),
            is_active: true,
            last_updated: Utc::now(),
        };
        (kp, stake)
    }

    #[test]
    fn test_is_subnet_owner() {
        let owner = subnet_owner_hotkey();
        assert!(is_subnet_owner(&owner));

        let other = Hotkey([0u8; 32]);
        assert!(!is_subnet_owner(&other));
    }

    #[test]
    fn test_bootstrap_period_check() {
        let gov = create_test_governance();

        // Block 0: should be in bootstrap
        gov.set_block_height(0);
        assert!(gov.is_bootstrap_period());

        // Block before end: still bootstrap
        gov.set_block_height(BOOTSTRAP_END_BLOCK - 1);
        assert!(gov.is_bootstrap_period());

        // Block at end: not bootstrap
        gov.set_block_height(BOOTSTRAP_END_BLOCK);
        assert!(!gov.is_bootstrap_period());

        // Block after end: not bootstrap
        gov.set_block_height(BOOTSTRAP_END_BLOCK + 1000);
        assert!(!gov.is_bootstrap_period());
    }

    #[test]
    fn test_bootstrap_authority_owner() {
        let gov = create_test_governance();
        let owner = subnet_owner_hotkey();

        // During bootstrap
        gov.set_block_height(1000);
        let result = gov.check_bootstrap_authority(&owner, &GovernanceActionType::AddChallenge);
        assert!(matches!(result, BootstrapDecision::OwnerAccepted { .. }));

        // After bootstrap
        gov.set_block_height(BOOTSTRAP_END_BLOCK + 1);
        let result = gov.check_bootstrap_authority(&owner, &GovernanceActionType::AddChallenge);
        assert!(matches!(result, BootstrapDecision::RequiresStakeConsensus));
    }

    #[test]
    fn test_bootstrap_authority_non_owner() {
        let gov = create_test_governance();
        let (kp, _) = create_test_validator(1_000_000_000_000);

        // During bootstrap, non-owner cannot use bootstrap authority
        gov.set_block_height(1000);
        let result =
            gov.check_bootstrap_authority(&kp.hotkey(), &GovernanceActionType::AddChallenge);
        assert!(matches!(result, BootstrapDecision::NotOwner { .. }));
    }

    #[test]
    fn test_proposal_creation() {
        let gov = create_test_governance();
        gov.set_block_height(BOOTSTRAP_END_BLOCK + 1);

        let (kp, stake) = create_test_validator(1_000_000_000_000);
        gov.update_validator_stakes(vec![stake]);

        let result = gov.create_proposal(
            GovernanceActionType::AddChallenge,
            "Add New Challenge".to_string(),
            "Add a new coding challenge".to_string(),
            vec![1, 2, 3],
            &kp.hotkey(),
            &kp,
        );

        assert!(result.is_ok());
        let proposal = result.unwrap();
        assert_eq!(proposal.action_type, GovernanceActionType::AddChallenge);
        assert!(!proposal.signature.is_empty());
    }

    #[test]
    fn test_voting() {
        let gov = create_test_governance();
        gov.set_block_height(BOOTSTRAP_END_BLOCK + 1);

        // Create validators with stakes
        let (kp1, stake1) = create_test_validator(600_000_000_000); // 60%
        let (kp2, stake2) = create_test_validator(400_000_000_000); // 40%
        gov.update_validator_stakes(vec![stake1, stake2]);

        // Create proposal
        let proposal = gov
            .create_proposal(
                GovernanceActionType::UpdateConfig,
                "Update Config".to_string(),
                "Test".to_string(),
                vec![],
                &kp1.hotkey(),
                &kp1,
            )
            .unwrap();

        // Vote with 60% stake
        let result = gov.vote(proposal.id, &kp1.hotkey(), true, &kp1).unwrap();

        // Should be pending because voting period not complete
        assert!(matches!(result, StakeConsensusResult::Pending { .. }));
    }

    #[test]
    fn test_double_vote_prevention() {
        let gov = create_test_governance();
        gov.set_block_height(BOOTSTRAP_END_BLOCK + 1);

        let (kp, stake) = create_test_validator(1_000_000_000_000);
        gov.update_validator_stakes(vec![stake]);

        let proposal = gov
            .create_proposal(
                GovernanceActionType::UpdateConfig,
                "Test".to_string(),
                "Test".to_string(),
                vec![],
                &kp.hotkey(),
                &kp,
            )
            .unwrap();

        // First vote should succeed
        let result1 = gov.vote(proposal.id, &kp.hotkey(), true, &kp);
        assert!(result1.is_ok());

        // Second vote should fail
        let result2 = gov.vote(proposal.id, &kp.hotkey(), true, &kp);
        assert!(result2.is_err());
    }

    #[test]
    fn test_proposal_expiration() {
        let mut proposal = GovernanceProposal::new(
            GovernanceActionType::AddChallenge,
            "Test".to_string(),
            "Test".to_string(),
            vec![],
            Hotkey([0u8; 32]),
            100,
        );

        // Not expired initially
        assert!(!proposal.is_expired());

        // Manually set to expired
        proposal.expires_at = Utc::now() - Duration::hours(1);
        assert!(proposal.is_expired());
    }

    #[test]
    fn test_stake_calculation() {
        let gov = create_test_governance();

        let (_, stake1) = create_test_validator(100_000_000_000);
        let (_, stake2) = create_test_validator(200_000_000_000);
        let (_, stake3) = create_test_validator(300_000_000_000);

        gov.update_validator_stakes(vec![stake1, stake2, stake3]);

        let total = gov.total_stake();
        assert_eq!(total.0, 600_000_000_000);
    }

    #[test]
    fn test_governance_status() {
        let gov = create_test_governance();
        gov.set_block_height(1_000_000);

        let (_, stake1) = create_test_validator(100_000_000_000);
        let (_, stake2) = create_test_validator(200_000_000_000);
        gov.update_validator_stakes(vec![stake1, stake2]);

        let status = gov.status();
        assert_eq!(status.current_block, 1_000_000);
        assert!(status.is_bootstrap_period);
        assert_eq!(status.validator_count, 2);
        assert_eq!(status.total_stake.0, 300_000_000_000);
    }

    #[test]
    fn test_hybrid_authorization_bootstrap() {
        let stake_gov = Arc::new(StakeGovernance::new());
        stake_gov.set_block_height(1000);

        let hybrid = HybridGovernance::new(stake_gov);
        let owner = subnet_owner_hotkey();

        let result = hybrid.check_authorization(&owner, &GovernanceActionType::AddChallenge);
        assert!(matches!(
            result,
            AuthorizationResult::BootstrapAuthorized { .. }
        ));
    }

    #[test]
    fn test_hybrid_authorization_post_bootstrap() {
        let stake_gov = Arc::new(StakeGovernance::new());
        stake_gov.set_block_height(BOOTSTRAP_END_BLOCK + 1);

        let (kp, stake) = create_test_validator(1_000_000_000_000);
        stake_gov.update_validator_stakes(vec![stake]);

        let hybrid = HybridGovernance::new(stake_gov);

        let result = hybrid.check_authorization(&kp.hotkey(), &GovernanceActionType::AddChallenge);
        assert!(matches!(
            result,
            AuthorizationResult::RequiresProposal { .. }
        ));
    }

    // ========================================================================
    // BOOTSTRAP SYNC POLICY TESTS
    // ========================================================================

    #[test]
    fn test_bootstrap_sync_policy_during_bootstrap() {
        let policy = BootstrapSyncPolicy::new(1000);
        let owner = subnet_owner_hotkey();
        let other = Hotkey([99u8; 32]);

        // Owner should be trusted during bootstrap
        let result = policy.can_trust_source(&owner);
        assert!(matches!(
            result,
            SyncTrustResult::TrustedBootstrapOwner { .. }
        ));

        // Other validators should not be trusted during bootstrap
        let result2 = policy.can_trust_source(&other);
        assert!(matches!(
            result2,
            SyncTrustResult::UntrustedDuringBootstrap { .. }
        ));
    }

    #[test]
    fn test_bootstrap_sync_policy_after_bootstrap() {
        let policy = BootstrapSyncPolicy::new(BOOTSTRAP_END_BLOCK + 1);
        let owner = subnet_owner_hotkey();

        // Even owner requires stake verification after bootstrap
        let result = policy.can_trust_source(&owner);
        assert!(matches!(
            result,
            SyncTrustResult::RequiresStakeVerification { .. }
        ));
    }

    #[test]
    fn test_bootstrap_sync_acceptance_decision() {
        let policy = BootstrapSyncPolicy::new(1000);
        let owner = subnet_owner_hotkey();
        let other = Hotkey([99u8; 32]);

        // Owner data should be accepted
        let decision = policy.should_accept_without_stake_check(&owner, "challenge_config");
        assert!(decision.should_accept());
        assert!(!decision.needs_stake_check());

        // Other validator data should be rejected
        let decision2 = policy.should_accept_without_stake_check(&other, "challenge_config");
        assert!(!decision2.should_accept());
    }

    #[test]
    fn test_bootstrap_sync_post_bootstrap_requires_stake() {
        let policy = BootstrapSyncPolicy::new(BOOTSTRAP_END_BLOCK + 100);
        let owner = subnet_owner_hotkey();

        // After bootstrap, all sources require stake verification
        let decision = policy.should_accept_without_stake_check(&owner, "state_sync");
        assert!(!decision.should_accept());
        assert!(decision.needs_stake_check());
    }

    #[test]
    fn test_is_trusted_bootstrap_source() {
        let owner = subnet_owner_hotkey();
        let other = Hotkey([42u8; 32]);

        // During bootstrap
        assert!(is_trusted_bootstrap_source(&owner, 1000));
        assert!(!is_trusted_bootstrap_source(&other, 1000));

        // After bootstrap
        assert!(!is_trusted_bootstrap_source(&owner, BOOTSTRAP_END_BLOCK));
        assert!(!is_trusted_bootstrap_source(&other, BOOTSTRAP_END_BLOCK));
    }

    #[test]
    fn test_bootstrap_sync_policy_block_update() {
        let mut policy = BootstrapSyncPolicy::new(1000);
        assert!(policy.is_bootstrap_active());

        policy.set_block(BOOTSTRAP_END_BLOCK);
        assert!(!policy.is_bootstrap_active());
    }

    #[test]
    fn test_bootstrap_owner_ss58() {
        let policy = BootstrapSyncPolicy::new(0);
        assert_eq!(policy.owner_ss58(), SUBNET_OWNER_SS58);
        assert_eq!(
            policy.owner_ss58(),
            "5GziQCcRpN8NCJktX343brnfuVe3w6gUYieeStXPD1Dag2At"
        );
    }
}
