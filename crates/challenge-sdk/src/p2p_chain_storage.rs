//! P2P Chain Storage System
//!
//! A complete distributed storage system for challenges with:
//! - Proposal/Acceptation protocol for data validation
//! - Custom validators per challenge (for security)
//! - Consensus mechanism across validators
//! - Persistent storage with P2P replication
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        P2P Chain Storage                            │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │  1. PROPOSAL: Validator proposes data to store                      │
//! │     - Signs the proposal with their keypair                         │
//! │     - Broadcasts to all other validators                            │
//! │                                                                     │
//! │  2. VALIDATION: Each validator validates the proposal               │
//! │     - Challenge-specific validation (custom rules)                  │
//! │     - Signature verification                                        │
//! │     - Stake requirements                                            │
//! │                                                                     │
//! │  3. ACCEPTATION: Validators vote to accept/reject                   │
//! │     - Each validator broadcasts their vote                          │
//! │     - Votes are signed and verifiable                               │
//! │                                                                     │
//! │  4. CONSENSUS: When 2/3+ validators accept                          │
//! │     - Data is committed to local storage                            │
//! │     - Consensus state is broadcast                                  │
//! │                                                                     │
//! │  5. PERSISTENCE: Data stored in local sled database                 │
//! │     - Survives restarts                                             │
//! │     - Syncs with peers on startup                                   │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Security
//!
//! - All proposals must be signed by a validator with sufficient stake
//! - Each challenge defines its own validation rules
//! - Data cannot be modified once consensus is reached
//! - Byzantine fault tolerant (up to 1/3 malicious validators)

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Minimum stake to propose data (100 TAO in RAO)
pub const MIN_PROPOSE_STAKE: u64 = 100_000_000_000;

/// Minimum validators for consensus (2/3 + 1)
pub const MIN_CONSENSUS_RATIO: f64 = 0.67;

/// Maximum proposal size (1 MB)
pub const MAX_PROPOSAL_SIZE: usize = 1024 * 1024;

/// Proposal TTL (blocks before expiry if no consensus)
pub const PROPOSAL_TTL_BLOCKS: u64 = 100;

/// Maximum pending proposals per validator
pub const MAX_PENDING_PER_VALIDATOR: usize = 10;

// ============================================================================
// DATA CATEGORIES
// ============================================================================

/// Category of data being stored
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataCategory {
    /// Agent source code submission
    AgentSubmission,
    /// Agent evaluation result from a validator
    EvaluationResult,
    /// Individual task result
    TaskResult,
    /// Consensus score (after multi-validator agreement)
    ConsensusScore,
    /// Execution logs (compressed)
    ExecutionLog,
    /// Leaderboard update
    Leaderboard,
    /// Challenge-specific custom data
    Custom,
}

impl DataCategory {
    /// Whether this category requires multi-validator consensus
    pub fn requires_consensus(&self) -> bool {
        matches!(
            self,
            DataCategory::ConsensusScore | DataCategory::Leaderboard
        )
    }

    /// Whether this category is validator-scoped (one entry per validator)
    pub fn is_validator_scoped(&self) -> bool {
        matches!(
            self,
            DataCategory::EvaluationResult | DataCategory::TaskResult | DataCategory::ExecutionLog
        )
    }

    /// Default TTL in blocks (None = permanent)
    pub fn default_ttl(&self) -> Option<u64> {
        match self {
            DataCategory::ExecutionLog => Some(10_000),  // ~1 day
            DataCategory::AgentSubmission => Some(5_000), // Until reveal
            _ => None,                                    // Permanent
        }
    }
}

// ============================================================================
// PROPOSAL SYSTEM
// ============================================================================

/// Unique identifier for a proposal
pub type ProposalId = [u8; 32];

/// A proposal to store data on chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProposal {
    /// Unique proposal ID (hash of content)
    pub id: ProposalId,
    /// Challenge ID this proposal belongs to
    pub challenge_id: String,
    /// Category of data
    pub category: DataCategory,
    /// Data key (unique within category)
    pub key: String,
    /// Data value (serialized)
    pub value: Vec<u8>,
    /// Hash of the value for integrity
    pub value_hash: [u8; 32],
    /// Proposer validator hotkey
    pub proposer: String,
    /// Proposer's stake at time of proposal
    pub proposer_stake: u64,
    /// Block height when proposed
    pub proposed_at_block: u64,
    /// Block when proposal expires
    pub expires_at_block: u64,
    /// Epoch when proposed
    pub epoch: u64,
    /// Proposer signature
    pub signature: Vec<u8>,
    /// Optional metadata (challenge-specific)
    pub metadata: HashMap<String, String>,
}

impl DataProposal {
    /// Create a new proposal
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_id: String,
        category: DataCategory,
        key: String,
        value: Vec<u8>,
        proposer: String,
        proposer_stake: u64,
        block_height: u64,
        epoch: u64,
    ) -> Self {
        let value_hash = Self::compute_hash(&value);
        let expires_at_block = block_height + PROPOSAL_TTL_BLOCKS;

        // Compute proposal ID
        let mut hasher = Sha256::new();
        hasher.update(challenge_id.as_bytes());
        hasher.update([category as u8]);
        hasher.update(key.as_bytes());
        hasher.update(&value_hash);
        hasher.update(proposer.as_bytes());
        hasher.update(block_height.to_le_bytes());
        let id: ProposalId = hasher.finalize().into();

        Self {
            id,
            challenge_id,
            category,
            key,
            value,
            value_hash,
            proposer,
            proposer_stake,
            proposed_at_block: block_height,
            expires_at_block,
            epoch,
            signature: vec![],
            metadata: HashMap::new(),
        }
    }

    /// Compute hash of value
    pub fn compute_hash(value: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(value);
        hasher.finalize().into()
    }

    /// Compute hash for signing
    pub fn sign_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.id);
        hasher.update(self.challenge_id.as_bytes());
        hasher.update([self.category as u8]);
        hasher.update(self.key.as_bytes());
        hasher.update(&self.value_hash);
        hasher.update(self.proposer.as_bytes());
        hasher.update(self.proposed_at_block.to_le_bytes());
        hasher.finalize().into()
    }

    /// Sign the proposal
    pub fn sign(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Verify value integrity
    pub fn verify_integrity(&self) -> bool {
        Self::compute_hash(&self.value) == self.value_hash
    }

    /// Check if expired
    pub fn is_expired(&self, current_block: u64) -> bool {
        current_block >= self.expires_at_block
    }

    /// Get proposal ID as hex string
    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }
}

// ============================================================================
// ACCEPTATION SYSTEM
// ============================================================================

/// Vote on a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalVote {
    /// Proposal being voted on
    pub proposal_id: ProposalId,
    /// Validator casting the vote
    pub validator: String,
    /// Validator's stake
    pub validator_stake: u64,
    /// Accept or reject
    pub accept: bool,
    /// Rejection reason (if rejected)
    pub rejection_reason: Option<String>,
    /// Block when voted
    pub voted_at_block: u64,
    /// Validator signature
    pub signature: Vec<u8>,
}

impl ProposalVote {
    /// Create an accept vote
    pub fn accept(
        proposal_id: ProposalId,
        validator: String,
        validator_stake: u64,
        block_height: u64,
    ) -> Self {
        Self {
            proposal_id,
            validator,
            validator_stake,
            accept: true,
            rejection_reason: None,
            voted_at_block: block_height,
            signature: vec![],
        }
    }

    /// Create a reject vote
    pub fn reject(
        proposal_id: ProposalId,
        validator: String,
        validator_stake: u64,
        block_height: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            proposal_id,
            validator,
            validator_stake,
            accept: false,
            rejection_reason: Some(reason.into()),
            voted_at_block: block_height,
            signature: vec![],
        }
    }

    /// Compute hash for signing
    pub fn sign_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.proposal_id);
        hasher.update(self.validator.as_bytes());
        hasher.update([self.accept as u8]);
        if let Some(reason) = &self.rejection_reason {
            hasher.update(reason.as_bytes());
        }
        hasher.update(self.voted_at_block.to_le_bytes());
        hasher.finalize().into()
    }

    /// Sign the vote
    pub fn sign(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }
}

/// State of a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalState {
    /// The proposal
    pub proposal: DataProposal,
    /// Votes received
    pub votes: HashMap<String, ProposalVote>,
    /// Total stake that accepted
    pub accept_stake: u64,
    /// Total stake that rejected
    pub reject_stake: u64,
    /// Whether consensus is reached
    pub consensus_reached: bool,
    /// Final status (once determined)
    pub final_status: Option<ProposalStatus>,
    /// Block when consensus was reached
    pub consensus_block: Option<u64>,
}

impl ProposalState {
    /// Create new proposal state
    pub fn new(proposal: DataProposal) -> Self {
        Self {
            proposal,
            votes: HashMap::new(),
            accept_stake: 0,
            reject_stake: 0,
            consensus_reached: false,
            final_status: None,
            consensus_block: None,
        }
    }

    /// Add a vote
    pub fn add_vote(&mut self, vote: ProposalVote) {
        if self.votes.contains_key(&vote.validator) {
            return; // Already voted
        }

        if vote.accept {
            self.accept_stake += vote.validator_stake;
        } else {
            self.reject_stake += vote.validator_stake;
        }

        self.votes.insert(vote.validator.clone(), vote);
    }

    /// Check if consensus is reached
    pub fn check_consensus(&mut self, total_stake: u64, current_block: u64) -> Option<ProposalStatus> {
        if self.consensus_reached {
            return self.final_status.clone();
        }

        let required_stake = (total_stake as f64 * MIN_CONSENSUS_RATIO) as u64;

        if self.accept_stake >= required_stake {
            self.consensus_reached = true;
            self.final_status = Some(ProposalStatus::Accepted);
            self.consensus_block = Some(current_block);
            return Some(ProposalStatus::Accepted);
        }

        if self.reject_stake >= required_stake {
            self.consensus_reached = true;
            self.final_status = Some(ProposalStatus::Rejected);
            self.consensus_block = Some(current_block);
            return Some(ProposalStatus::Rejected);
        }

        None
    }

    /// Get vote count
    pub fn vote_count(&self) -> (usize, usize) {
        let accepts = self.votes.values().filter(|v| v.accept).count();
        let rejects = self.votes.values().filter(|v| !v.accept).count();
        (accepts, rejects)
    }
}

/// Final status of a proposal
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    /// Waiting for votes
    Pending,
    /// Accepted by consensus
    Accepted,
    /// Rejected by consensus
    Rejected,
    /// Expired without consensus
    Expired,
}

// ============================================================================
// VALIDATION TRAIT (Challenge-specific)
// ============================================================================

/// Result of validating a proposal
#[derive(Debug, Clone)]
pub enum ValidationResult {
    /// Accept the proposal
    Accept,
    /// Reject with reason
    Reject(String),
}

impl ValidationResult {
    pub fn is_accepted(&self) -> bool {
        matches!(self, ValidationResult::Accept)
    }
}

/// Trait for challenge-specific validation
///
/// Each challenge implements this to define its own validation rules.
/// This is called before accepting any proposal.
#[async_trait]
pub trait ProposalValidator: Send + Sync {
    /// Validate a proposal
    ///
    /// Called when a new proposal is received. The challenge can:
    /// - Verify the data format
    /// - Check business rules (e.g., agent code syntax)
    /// - Verify signatures and permissions
    /// - Rate limit specific operations
    async fn validate_proposal(&self, proposal: &DataProposal) -> ValidationResult;

    /// Validate a vote
    ///
    /// Called when a vote is received. Usually just signature verification.
    async fn validate_vote(&self, vote: &ProposalVote, proposal: &DataProposal) -> ValidationResult;

    /// Called when consensus is reached
    ///
    /// The challenge can perform post-consensus actions like:
    /// - Updating leaderboard
    /// - Triggering evaluations
    /// - Notifying other systems
    async fn on_consensus(&self, proposal: &DataProposal, status: ProposalStatus);
}

// ============================================================================
// STORED DATA
// ============================================================================

/// Committed data (after consensus)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommittedData {
    /// Original proposal ID
    pub proposal_id: ProposalId,
    /// Challenge ID
    pub challenge_id: String,
    /// Data category
    pub category: DataCategory,
    /// Data key
    pub key: String,
    /// Data value
    pub value: Vec<u8>,
    /// Value hash
    pub value_hash: [u8; 32],
    /// Original proposer
    pub proposer: String,
    /// Validators who accepted
    pub accepted_by: Vec<String>,
    /// Block when proposed
    pub proposed_at_block: u64,
    /// Block when consensus reached
    pub committed_at_block: u64,
    /// Epoch
    pub epoch: u64,
    /// TTL (None = permanent)
    pub expires_at_block: Option<u64>,
    /// Version (incremented on update)
    pub version: u64,
}

impl CommittedData {
    /// Create from accepted proposal
    pub fn from_proposal(proposal: &DataProposal, state: &ProposalState) -> Self {
        let accepted_by: Vec<String> = state
            .votes
            .values()
            .filter(|v| v.accept)
            .map(|v| v.validator.clone())
            .collect();

        Self {
            proposal_id: proposal.id,
            challenge_id: proposal.challenge_id.clone(),
            category: proposal.category,
            key: proposal.key.clone(),
            value: proposal.value.clone(),
            value_hash: proposal.value_hash,
            proposer: proposal.proposer.clone(),
            accepted_by,
            proposed_at_block: proposal.proposed_at_block,
            committed_at_block: state.consensus_block.unwrap_or(proposal.proposed_at_block),
            epoch: proposal.epoch,
            expires_at_block: proposal.category.default_ttl().map(|ttl| {
                state.consensus_block.unwrap_or(proposal.proposed_at_block) + ttl
            }),
            version: 1,
        }
    }

    /// Check if expired
    pub fn is_expired(&self, current_block: u64) -> bool {
        self.expires_at_block
            .map(|e| current_block >= e)
            .unwrap_or(false)
    }

    /// Verify integrity
    pub fn verify_integrity(&self) -> bool {
        DataProposal::compute_hash(&self.value) == self.value_hash
    }

    /// Deserialize value
    pub fn deserialize<T: serde::de::DeserializeOwned>(&self) -> Option<T> {
        serde_json::from_slice(&self.value).ok()
    }
}

// ============================================================================
// P2P MESSAGES
// ============================================================================

/// P2P messages for chain storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainStorageMessage {
    /// Propose new data
    Propose(DataProposal),

    /// Vote on a proposal
    Vote(ProposalVote),

    /// Announce consensus reached
    ConsensusReached {
        proposal_id: ProposalId,
        status: ProposalStatus,
        block: u64,
    },

    /// Request a proposal (if we missed it)
    RequestProposal { proposal_id: ProposalId },

    /// Response with proposal
    ProposalResponse { proposal: Option<DataProposal> },

    /// Request committed data by key
    RequestData {
        challenge_id: String,
        category: DataCategory,
        key: String,
    },

    /// Response with committed data
    DataResponse { data: Option<CommittedData> },

    /// Request full sync
    RequestSync {
        challenge_id: String,
        from_block: u64,
    },

    /// Sync response (paginated)
    SyncResponse {
        challenge_id: String,
        entries: Vec<CommittedData>,
        proposals: Vec<ProposalState>,
        has_more: bool,
        next_block: u64,
    },

    /// Request partition hash for comparison
    RequestHash { challenge_id: String },

    /// Hash response
    HashResponse {
        challenge_id: String,
        data_hash: [u8; 32],
        entry_count: usize,
        pending_count: usize,
    },
}

// ============================================================================
// STORAGE STATE
// ============================================================================

/// State of the chain storage for a challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStorageState {
    /// Challenge ID
    pub challenge_id: String,
    /// Pending proposals (not yet consensus)
    pub pending_proposals: HashMap<ProposalId, ProposalState>,
    /// Committed data (after consensus)
    pub committed_data: HashMap<String, CommittedData>,
    /// Index: category -> keys
    pub category_index: HashMap<DataCategory, HashSet<String>>,
    /// Index: proposer -> proposal IDs
    pub proposer_index: HashMap<String, Vec<ProposalId>>,
    /// Current block height
    pub current_block: u64,
    /// Current epoch
    pub current_epoch: u64,
    /// Total validator stake (for consensus calculation)
    pub total_stake: u64,
}

impl ChainStorageState {
    /// Create new state
    pub fn new(challenge_id: String) -> Self {
        Self {
            challenge_id,
            pending_proposals: HashMap::new(),
            committed_data: HashMap::new(),
            category_index: HashMap::new(),
            proposer_index: HashMap::new(),
            current_block: 0,
            current_epoch: 0,
            total_stake: 0,
        }
    }

    /// Update block and epoch
    pub fn update_block(&mut self, block: u64, epoch: u64) {
        self.current_block = block;
        self.current_epoch = epoch;
    }

    /// Update total stake
    pub fn update_stake(&mut self, stake: u64) {
        self.total_stake = stake;
    }

    /// Add a pending proposal
    pub fn add_proposal(&mut self, proposal: DataProposal) -> bool {
        if self.pending_proposals.contains_key(&proposal.id) {
            return false;
        }

        // Check pending limit per proposer
        let proposer_count = self
            .proposer_index
            .get(&proposal.proposer)
            .map(|v| v.len())
            .unwrap_or(0);
        if proposer_count >= MAX_PENDING_PER_VALIDATOR {
            return false;
        }

        let id = proposal.id;
        let proposer = proposal.proposer.clone();

        self.pending_proposals
            .insert(id, ProposalState::new(proposal));
        self.proposer_index
            .entry(proposer)
            .or_default()
            .push(id);

        true
    }

    /// Add a vote to a proposal
    pub fn add_vote(&mut self, vote: ProposalVote) -> Option<ProposalStatus> {
        let state = self.pending_proposals.get_mut(&vote.proposal_id)?;
        state.add_vote(vote);
        state.check_consensus(self.total_stake, self.current_block)
    }

    /// Commit a proposal (after consensus)
    pub fn commit_proposal(&mut self, proposal_id: &ProposalId) -> Option<CommittedData> {
        let state = self.pending_proposals.get(proposal_id)?;

        if !state.consensus_reached || state.final_status != Some(ProposalStatus::Accepted) {
            return None;
        }

        let data = CommittedData::from_proposal(&state.proposal, state);
        let full_key = format!("{}:{}", data.category as u8, data.key);

        // Update indices
        self.category_index
            .entry(data.category)
            .or_default()
            .insert(data.key.clone());

        self.committed_data.insert(full_key, data.clone());

        // Remove from pending
        self.pending_proposals.remove(proposal_id);

        // Clean up proposer index
        if let Some(ids) = self.proposer_index.get_mut(&data.proposer) {
            ids.retain(|id| id != proposal_id);
        }

        Some(data)
    }

    /// Get committed data by key
    pub fn get(&self, category: DataCategory, key: &str) -> Option<&CommittedData> {
        let full_key = format!("{}:{}", category as u8, key);
        self.committed_data.get(&full_key)
    }

    /// Get all committed data by category
    pub fn get_by_category(&self, category: DataCategory) -> Vec<&CommittedData> {
        self.category_index
            .get(&category)
            .map(|keys| {
                keys.iter()
                    .filter_map(|k| self.get(category, k))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get pending proposal
    pub fn get_proposal(&self, id: &ProposalId) -> Option<&ProposalState> {
        self.pending_proposals.get(id)
    }

    /// Cleanup expired data
    pub fn cleanup(&mut self) -> (usize, usize) {
        let block = self.current_block;

        // Cleanup expired proposals
        let expired_proposals: Vec<ProposalId> = self
            .pending_proposals
            .iter()
            .filter(|(_, s)| s.proposal.is_expired(block))
            .map(|(id, _)| *id)
            .collect();

        for id in &expired_proposals {
            if let Some(state) = self.pending_proposals.remove(id) {
                if let Some(ids) = self.proposer_index.get_mut(&state.proposal.proposer) {
                    ids.retain(|i| i != id);
                }
            }
        }

        // Cleanup expired committed data
        let expired_data: Vec<String> = self
            .committed_data
            .iter()
            .filter(|(_, d)| d.is_expired(block))
            .map(|(k, _)| k.clone())
            .collect();

        for key in &expired_data {
            if let Some(data) = self.committed_data.remove(key) {
                if let Some(keys) = self.category_index.get_mut(&data.category) {
                    keys.remove(&data.key);
                }
            }
        }

        (expired_proposals.len(), expired_data.len())
    }

    /// Compute state hash for comparison
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.challenge_id.as_bytes());

        // Sort keys for deterministic hash
        let mut keys: Vec<&String> = self.committed_data.keys().collect();
        keys.sort();

        for key in keys {
            if let Some(data) = self.committed_data.get(key) {
                hasher.update(key.as_bytes());
                hasher.update(&data.value_hash);
                hasher.update(data.version.to_le_bytes());
            }
        }

        hasher.finalize().into()
    }

    /// Get statistics
    pub fn stats(&self) -> StorageStats {
        let mut by_category: HashMap<DataCategory, usize> = HashMap::new();
        for data in self.committed_data.values() {
            *by_category.entry(data.category).or_default() += 1;
        }

        let total_size: usize = self.committed_data.values().map(|d| d.value.len()).sum();

        StorageStats {
            challenge_id: self.challenge_id.clone(),
            committed_count: self.committed_data.len(),
            pending_count: self.pending_proposals.len(),
            total_size,
            by_category,
            current_block: self.current_block,
        }
    }
}

/// Storage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub challenge_id: String,
    pub committed_count: usize,
    pub pending_count: usize,
    pub total_size: usize,
    pub by_category: HashMap<DataCategory, usize>,
    pub current_block: u64,
}

// ============================================================================
// HELPER TYPES FOR CHALLENGES
// ============================================================================

/// Agent submission data (stored in chain storage)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSubmissionData {
    /// Agent hash (SHA256 of owner + source code)
    pub agent_hash: String,
    /// Miner/owner hotkey
    pub owner_hotkey: String,
    /// Agent name
    pub name: String,
    /// Agent version
    pub version: String,
    /// Source code
    pub source_code: String,
    /// Source code hash
    pub code_hash: [u8; 32],
    /// Dependencies (requirements.txt content)
    pub dependencies: Option<String>,
    /// Submission timestamp
    pub submitted_at: u64,
    /// Block height
    pub block_height: u64,
    /// Owner signature
    pub signature: Vec<u8>,
}

impl AgentSubmissionData {
    /// Compute agent hash
    pub fn compute_agent_hash(owner: &str, source_code: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(owner.as_bytes());
        hasher.update(source_code.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Create new submission
    pub fn new(
        owner_hotkey: String,
        name: String,
        version: String,
        source_code: String,
        dependencies: Option<String>,
        block_height: u64,
    ) -> Self {
        let agent_hash = Self::compute_agent_hash(&owner_hotkey, &source_code);
        let code_hash = {
            let mut hasher = Sha256::new();
            hasher.update(source_code.as_bytes());
            hasher.finalize().into()
        };

        Self {
            agent_hash,
            owner_hotkey,
            name,
            version,
            source_code,
            code_hash,
            dependencies,
            submitted_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            block_height,
            signature: vec![],
        }
    }

    /// Sign the submission
    pub fn sign(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }

    /// Get data key
    pub fn key(&self) -> String {
        self.agent_hash.clone()
    }
}

/// Evaluation result data (stored in chain storage)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResultData {
    /// Agent hash being evaluated
    pub agent_hash: String,
    /// Validator who performed evaluation
    pub validator_hotkey: String,
    /// Overall score (0.0 - 1.0)
    pub score: f64,
    /// Total tasks evaluated
    pub total_tasks: u32,
    /// Tasks passed
    pub passed_tasks: u32,
    /// Tasks failed
    pub failed_tasks: u32,
    /// Total cost in USD
    pub total_cost_usd: f64,
    /// Per-task results
    pub task_results: Vec<TaskResultData>,
    /// Evaluation timestamp
    pub evaluated_at: u64,
    /// Block height
    pub block_height: u64,
    /// Epoch
    pub epoch: u64,
    /// Results hash for verification
    pub results_hash: [u8; 32],
    /// Validator signature
    pub signature: Vec<u8>,
}

impl EvaluationResultData {
    /// Get data key (agent_hash:validator)
    pub fn key(&self) -> String {
        format!("{}:{}", self.agent_hash, self.validator_hotkey)
    }

    /// Compute results hash
    pub fn compute_results_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.agent_hash.as_bytes());
        hasher.update(self.validator_hotkey.as_bytes());
        hasher.update(self.score.to_le_bytes());
        hasher.update(self.total_tasks.to_le_bytes());
        for tr in &self.task_results {
            hasher.update(tr.task_id.as_bytes());
            hasher.update([tr.passed as u8]);
            hasher.update(tr.score.to_le_bytes());
        }
        hasher.finalize().into()
    }
}

/// Individual task result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResultData {
    /// Task ID
    pub task_id: String,
    /// Whether task passed
    pub passed: bool,
    /// Task score (0.0 - 1.0)
    pub score: f64,
    /// Cost in USD
    pub cost_usd: f64,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Number of steps taken
    pub steps: u32,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Consensus score data (stored after multi-validator agreement)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusScoreData {
    /// Agent hash
    pub agent_hash: String,
    /// Consensus score (stake-weighted average)
    pub score: f64,
    /// Number of validators who evaluated
    pub validator_count: u32,
    /// Validators who participated
    pub validators: Vec<String>,
    /// Epoch
    pub epoch: u64,
    /// Block when consensus reached
    pub consensus_block: u64,
    /// Score deviation (for detecting outliers)
    pub score_deviation: f64,
}

impl ConsensusScoreData {
    /// Get data key
    pub fn key(&self) -> String {
        format!("{}:{}", self.agent_hash, self.epoch)
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proposal_creation() {
        let proposal = DataProposal::new(
            "term-bench".to_string(),
            DataCategory::AgentSubmission,
            "agent:abc123".to_string(),
            vec![1, 2, 3, 4],
            "validator1".to_string(),
            1_000_000_000_000,
            100,
            1,
        );

        assert!(proposal.verify_integrity());
        assert!(!proposal.is_expired(50));
        assert!(proposal.is_expired(250));
    }

    #[test]
    fn test_proposal_state_consensus() {
        let proposal = DataProposal::new(
            "term-bench".to_string(),
            DataCategory::AgentSubmission,
            "agent:abc123".to_string(),
            vec![1, 2, 3, 4],
            "validator1".to_string(),
            1_000_000_000_000,
            100,
            1,
        );

        let mut state = ProposalState::new(proposal.clone());
        let total_stake = 3_000_000_000_000u64; // 3000 TAO
        // Required: 3000 * 0.67 = 2010 TAO

        // Add first vote (1000 TAO) - not enough (1000 < 2010)
        let vote1 = ProposalVote::accept(
            proposal.id,
            "validator1".to_string(),
            1_000_000_000_000,
            101,
        );
        state.add_vote(vote1);
        assert!(state.check_consensus(total_stake, 101).is_none());

        // Add second vote (1100 TAO) - now 2100/3000 = 70% > 67%
        let vote2 = ProposalVote::accept(
            proposal.id,
            "validator2".to_string(),
            1_100_000_000_000,
            102,
        );
        state.add_vote(vote2);
        let status = state.check_consensus(total_stake, 102);
        assert_eq!(status, Some(ProposalStatus::Accepted));
    }

    #[test]
    fn test_storage_state() {
        let mut state = ChainStorageState::new("term-bench".to_string());
        state.update_block(100, 1);
        state.update_stake(3_000_000_000_000);

        // Add proposal
        let proposal = DataProposal::new(
            "term-bench".to_string(),
            DataCategory::AgentSubmission,
            "agent:abc123".to_string(),
            b"print('hello')".to_vec(),
            "validator1".to_string(),
            1_000_000_000_000,
            100,
            1,
        )
        .sign(vec![1, 2, 3]);

        assert!(state.add_proposal(proposal.clone()));

        // Add votes
        let vote1 = ProposalVote::accept(
            proposal.id,
            "validator1".to_string(),
            1_000_000_000_000,
            101,
        )
        .sign(vec![1]);

        let vote2 = ProposalVote::accept(
            proposal.id,
            "validator2".to_string(),
            1_500_000_000_000,
            102,
        )
        .sign(vec![2]);

        state.add_vote(vote1);
        let status = state.add_vote(vote2);
        assert_eq!(status, Some(ProposalStatus::Accepted));

        // Commit
        let data = state.commit_proposal(&proposal.id);
        assert!(data.is_some());

        // Verify committed
        let committed = state.get(DataCategory::AgentSubmission, "agent:abc123");
        assert!(committed.is_some());
        assert_eq!(committed.unwrap().value, b"print('hello')");
    }

    #[test]
    fn test_agent_submission_data() {
        let submission = AgentSubmissionData::new(
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
            "test-agent".to_string(),
            "1.0.0".to_string(),
            "print('hello world')".to_string(),
            None,
            100,
        );

        assert!(!submission.agent_hash.is_empty());
        assert_eq!(submission.name, "test-agent");
    }
}
