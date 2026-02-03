//! State Root Consensus Protocol
//!
//! This module provides cross-validator state verification with fraud proofs.
//! Validators coordinate to agree on global state roots using 2f+1 consensus,
//! enabling detection and proof of Byzantine behavior.
//!
//! # Overview
//!
//! The state consensus protocol allows validators to:
//! - Propose state roots for specific block numbers
//! - Vote on proposals by comparing against locally computed state
//! - Reach consensus when 2f+1 validators agree
//! - Generate fraud proofs when conflicting roots are detected
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    GlobalStateLinker                            │
//! │         (aggregates per-challenge roots into global root)       │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                   StateRootConsensus                            │
//! │    (manages proposals, votes, and consensus achievement)        │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!               ┌──────────────┴──────────────┐
//!               ▼                             ▼
//! ┌─────────────────────────┐   ┌─────────────────────────────────┐
//! │   StateRootProposal     │   │        StateRootVote            │
//! │   (proposer submits)    │   │   (validators vote yes/no)      │
//! └─────────────────────────┘   └─────────────────────────────────┘
//!                              │
//!                              ▼
//!               ┌──────────────────────────────┐
//!               │         FraudProof           │
//!               │  (evidence of misbehavior)   │
//!               └──────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use platform_distributed_storage::state_consensus::{
//!     StateRootConsensus, GlobalStateLinker, StateRootProposal,
//! };
//! use platform_core::Hotkey;
//!
//! // Create a consensus manager
//! let my_hotkey = Hotkey([0u8; 32]);
//! let mut consensus = StateRootConsensus::new(my_hotkey, 3); // quorum of 3
//!
//! // Create a global state linker
//! let mut linker = GlobalStateLinker::new();
//! linker.add_challenge_root("challenge-1", [1u8; 32]);
//! linker.add_challenge_root("challenge-2", [2u8; 32]);
//!
//! // Compute global root
//! let global_root = linker.compute_global_root();
//!
//! // Propose a state root
//! let proposal = consensus.propose_state_root(
//!     100, // block number
//!     global_root,
//!     linker.get_challenge_roots().clone(),
//! );
//! ```

#![allow(dead_code, unused_variables, unused_imports)]

use platform_core::Hotkey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info, warn};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during state root consensus.
#[derive(Error, Debug, Clone)]
pub enum StateRootConsensusError {
    /// Not enough votes to reach consensus.
    #[error("Not enough votes: need {needed}, have {have}")]
    NotEnoughVotes {
        /// Number of votes needed for consensus
        needed: usize,
        /// Number of votes currently received
        have: usize,
    },

    /// Conflicting state roots detected.
    #[error("Conflicting roots: expected {expected}, got {got}")]
    ConflictingRoots {
        /// Expected root (hex encoded)
        expected: String,
        /// Actual root received (hex encoded)
        got: String,
    },

    /// Invalid signature on message.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Proposal timed out before reaching consensus.
    #[error("Proposal timeout")]
    ProposalTimeout,

    /// Fraud was detected during consensus.
    #[error("Fraud detected: {0}")]
    FraudDetected(String),

    /// Internal error occurred.
    #[error("Internal error: {0}")]
    InternalError(String),
}

// ============================================================================
// Core Data Structures
// ============================================================================

/// A proposal for a state root at a specific block number.
///
/// The proposer computes the global state root from all challenge roots
/// and broadcasts this to other validators for verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateRootProposal {
    /// Block number this proposal is for
    pub block_number: u64,

    /// Hotkey of the validator proposing this root
    pub proposer: Hotkey,

    /// The global state root (hash of all challenge roots)
    pub global_state_root: [u8; 32],

    /// Individual challenge roots that make up the global root
    /// Maps challenge_id -> merkle root of that challenge's data
    pub challenge_roots: HashMap<String, [u8; 32]>,

    /// Unix timestamp (milliseconds) when proposal was created
    pub timestamp: i64,

    /// Cryptographic signature over the proposal content
    pub signature: Vec<u8>,
}

impl StateRootProposal {
    /// Compute the hash of the proposal for signing/verification.
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.block_number.to_le_bytes());
        hasher.update(self.proposer.as_bytes());
        hasher.update(&self.global_state_root);

        // Sort challenge roots for deterministic hashing
        let mut sorted_roots: Vec<_> = self.challenge_roots.iter().collect();
        sorted_roots.sort_by_key(|(k, _)| *k);
        for (challenge_id, root) in sorted_roots {
            hasher.update(challenge_id.as_bytes());
            hasher.update(root);
        }

        hasher.update(self.timestamp.to_le_bytes());
        hasher.finalize().into()
    }

    /// Verify the global root matches the challenge roots.
    pub fn verify_global_root(&self) -> bool {
        let computed = compute_global_root_from_challenges(&self.challenge_roots);
        computed == self.global_state_root
    }
}

/// A vote on a state root proposal.
///
/// Validators compare the proposed root against their locally computed state
/// and vote accordingly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateRootVote {
    /// Block number this vote is for
    pub block_number: u64,

    /// Hotkey of the voting validator
    pub voter: Hotkey,

    /// The state root the voter computed locally
    pub state_root: [u8; 32],

    /// Whether this voter agrees with the proposal
    pub agrees_with_proposal: bool,

    /// Unix timestamp (milliseconds) when vote was cast
    pub timestamp: i64,

    /// Cryptographic signature over the vote content
    pub signature: Vec<u8>,
}

impl StateRootVote {
    /// Compute the hash of the vote for signing/verification.
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.block_number.to_le_bytes());
        hasher.update(self.voter.as_bytes());
        hasher.update(&self.state_root);
        hasher.update(&[self.agrees_with_proposal as u8]);
        hasher.update(self.timestamp.to_le_bytes());
        hasher.finalize().into()
    }
}

/// Proof of fraudulent behavior by a validator.
///
/// Generated when a validator is caught submitting conflicting state roots
/// or when their claimed root doesn't match the actual computed state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FraudProof {
    /// Hotkey of the validator creating this proof
    pub accuser: Hotkey,

    /// Hotkey of the validator being accused
    pub accused: Hotkey,

    /// Block number where fraud occurred
    pub block_number: u64,

    /// The root the accused validator claimed
    pub claimed_root: [u8; 32],

    /// The actual root as computed from the data
    pub actual_root: [u8; 32],

    /// Optional merkle proof showing the incorrect data
    pub merkle_proof: Option<Vec<[u8; 32]>>,

    /// Unix timestamp (milliseconds) when proof was created
    pub timestamp: i64,

    /// Cryptographic signature over the proof content
    pub signature: Vec<u8>,
}

impl FraudProof {
    /// Compute the hash of the fraud proof for signing/verification.
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.accuser.as_bytes());
        hasher.update(self.accused.as_bytes());
        hasher.update(self.block_number.to_le_bytes());
        hasher.update(&self.claimed_root);
        hasher.update(&self.actual_root);
        hasher.update(self.timestamp.to_le_bytes());
        hasher.finalize().into()
    }

    /// Check if the claimed and actual roots differ.
    pub fn roots_differ(&self) -> bool {
        self.claimed_root != self.actual_root
    }
}

/// Result of successful consensus.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusResult {
    /// Block number consensus was achieved for
    pub block_number: u64,

    /// The agreed-upon state root
    pub agreed_root: [u8; 32],

    /// All votes that contributed to consensus
    pub votes: Vec<StateRootVote>,

    /// Unix timestamp (milliseconds) when consensus was achieved
    pub timestamp: i64,
}

impl ConsensusResult {
    /// Get the number of agreeing votes.
    pub fn agreeing_votes(&self) -> usize {
        self.votes.iter().filter(|v| v.agrees_with_proposal).count()
    }

    /// Get the number of disagreeing votes.
    pub fn disagreeing_votes(&self) -> usize {
        self.votes
            .iter()
            .filter(|v| !v.agrees_with_proposal)
            .count()
    }
}

// ============================================================================
// Inclusion Proof
// ============================================================================

/// A step in the inclusion proof path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofStep {
    /// Hash of the sibling node
    pub sibling_hash: [u8; 32],
    /// Whether the current node is on the left (true) or right (false)
    pub is_left: bool,
}

/// Proof that a challenge's state is included in the global state root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InclusionProof {
    /// The challenge this proof is for
    pub challenge_id: String,

    /// The challenge's state root
    pub challenge_root: [u8; 32],

    /// The global state root containing this challenge
    pub global_root: [u8; 32],

    /// Merkle path from challenge leaf to global root
    pub proof_path: Vec<ProofStep>,
}

impl InclusionProof {
    /// Verify this inclusion proof is valid.
    pub fn verify(&self) -> bool {
        // Start with the leaf hash (challenge_id + challenge_root)
        let mut hasher = Sha256::new();
        hasher.update(self.challenge_id.as_bytes());
        hasher.update(&self.challenge_root);
        let mut current: [u8; 32] = hasher.finalize().into();

        // Walk up the proof path
        for step in &self.proof_path {
            // Combine based on position
            current = if step.is_left {
                // We are left child, sibling is on right
                hash_pair(&current, &step.sibling_hash)
            } else {
                // We are right child, sibling is on left
                hash_pair(&step.sibling_hash, &current)
            };
        }

        // Check if we reached the global root
        current == self.global_root
    }
}

// ============================================================================
// Global State Linker
// ============================================================================

/// Links per-challenge storage roots into a global state root.
///
/// This struct maintains the mapping between individual challenge state roots
/// and computes the aggregate global root that validators agree upon.
#[derive(Clone, Debug, Default)]
pub struct GlobalStateLinker {
    /// Maps challenge_id -> state root for that challenge
    challenge_roots: HashMap<String, [u8; 32]>,

    /// Cached global root (invalidated on changes)
    cached_global_root: Option<[u8; 32]>,
}

impl GlobalStateLinker {
    /// Create a new empty state linker.
    pub fn new() -> Self {
        Self {
            challenge_roots: HashMap::new(),
            cached_global_root: None,
        }
    }

    /// Add or update a challenge root.
    pub fn add_challenge_root(&mut self, challenge_id: &str, root: [u8; 32]) {
        self.challenge_roots.insert(challenge_id.to_string(), root);
        self.cached_global_root = None; // Invalidate cache
        debug!(
            challenge_id,
            root = hex::encode(root),
            "Added challenge root"
        );
    }

    /// Remove a challenge root.
    pub fn remove_challenge_root(&mut self, challenge_id: &str) {
        self.challenge_roots.remove(challenge_id);
        self.cached_global_root = None; // Invalidate cache
        debug!(challenge_id, "Removed challenge root");
    }

    /// Compute the global state root from all challenge roots.
    ///
    /// The global root is computed as a merkle tree of all challenge roots,
    /// sorted by challenge ID for determinism.
    pub fn compute_global_root(&self) -> [u8; 32] {
        if let Some(cached) = self.cached_global_root {
            return cached;
        }

        compute_global_root_from_challenges(&self.challenge_roots)
    }

    /// Get a reference to all challenge roots.
    pub fn get_challenge_roots(&self) -> &HashMap<String, [u8; 32]> {
        &self.challenge_roots
    }

    /// Verify that a specific challenge root is included in the global state.
    pub fn verify_inclusion(&self, challenge_id: &str, claimed_root: [u8; 32]) -> bool {
        match self.challenge_roots.get(challenge_id) {
            Some(root) => *root == claimed_root,
            None => false,
        }
    }

    /// Build an inclusion proof for a challenge.
    pub fn build_inclusion_proof(&self, challenge_id: &str) -> Option<InclusionProof> {
        let challenge_root = *self.challenge_roots.get(challenge_id)?;
        let global_root = self.compute_global_root();

        // Build merkle proof path
        let proof_path = build_merkle_proof_path(&self.challenge_roots, challenge_id);

        Some(InclusionProof {
            challenge_id: challenge_id.to_string(),
            challenge_root,
            global_root,
            proof_path,
        })
    }

    /// Get the number of challenges tracked.
    pub fn challenge_count(&self) -> usize {
        self.challenge_roots.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.challenge_roots.is_empty()
    }
}

// ============================================================================
// State Root Consensus Manager
// ============================================================================

/// Manages the state root consensus protocol.
///
/// This struct coordinates proposals, votes, and consensus detection,
/// maintaining the state needed to achieve 2f+1 agreement.
pub struct StateRootConsensus {
    /// Our local hotkey for signing
    local_hotkey: Hotkey,

    /// Number of votes required for consensus (2f+1)
    quorum_size: usize,

    /// Current proposal being voted on
    current_proposal: Option<StateRootProposal>,

    /// Votes received for the current proposal
    votes: HashMap<Hotkey, StateRootVote>,

    /// Detected fraud proofs
    fraud_proofs: Vec<FraudProof>,

    /// Completed consensus results (block_number -> result)
    completed: HashMap<u64, ConsensusResult>,
}

impl StateRootConsensus {
    /// Create a new consensus manager.
    ///
    /// # Arguments
    ///
    /// * `local_hotkey` - Our hotkey for signing proposals and votes
    /// * `quorum_size` - Number of votes needed for consensus (typically 2f+1)
    pub fn new(local_hotkey: Hotkey, quorum_size: usize) -> Self {
        info!(
            hotkey = local_hotkey.to_hex(),
            quorum_size, "Created state root consensus manager"
        );

        Self {
            local_hotkey,
            quorum_size,
            current_proposal: None,
            votes: HashMap::new(),
            fraud_proofs: Vec::new(),
            completed: HashMap::new(),
        }
    }

    /// Propose a new state root for consensus.
    ///
    /// Creates a proposal that other validators will vote on.
    pub fn propose_state_root(
        &mut self,
        block_number: u64,
        global_root: [u8; 32],
        challenge_roots: HashMap<String, [u8; 32]>,
    ) -> StateRootProposal {
        let timestamp = chrono::Utc::now().timestamp_millis();

        let proposal = StateRootProposal {
            block_number,
            proposer: self.local_hotkey.clone(),
            global_state_root: global_root,
            challenge_roots,
            timestamp,
            signature: Vec::new(), // Signature would be added by caller with keypair
        };

        info!(
            block_number,
            root = hex::encode(global_root),
            "Created state root proposal"
        );

        // Clear previous state and set new proposal
        self.current_proposal = Some(proposal.clone());
        self.votes.clear();

        proposal
    }

    /// Receive and process an incoming proposal.
    ///
    /// Validates the proposal structure and stores it for voting.
    pub fn receive_proposal(
        &mut self,
        proposal: StateRootProposal,
    ) -> Result<(), StateRootConsensusError> {
        // Verify the proposal's internal consistency
        if !proposal.verify_global_root() {
            return Err(StateRootConsensusError::ConflictingRoots {
                expected: hex::encode(compute_global_root_from_challenges(
                    &proposal.challenge_roots,
                )),
                got: hex::encode(proposal.global_state_root),
            });
        }

        debug!(
            block_number = proposal.block_number,
            proposer = proposal.proposer.to_hex(),
            "Received state root proposal"
        );

        // Clear any previous proposal and votes
        self.current_proposal = Some(proposal);
        self.votes.clear();

        Ok(())
    }

    /// Vote on the current proposal.
    ///
    /// Compares the proposal against the locally computed state root.
    pub fn vote_on_proposal(
        &mut self,
        proposal: &StateRootProposal,
        local_root: [u8; 32],
    ) -> StateRootVote {
        let agrees = local_root == proposal.global_state_root;
        let timestamp = chrono::Utc::now().timestamp_millis();

        let vote = StateRootVote {
            block_number: proposal.block_number,
            voter: self.local_hotkey.clone(),
            state_root: local_root,
            agrees_with_proposal: agrees,
            timestamp,
            signature: Vec::new(), // Signature would be added by caller with keypair
        };

        if !agrees {
            warn!(
                block_number = proposal.block_number,
                expected = hex::encode(proposal.global_state_root),
                local = hex::encode(local_root),
                "Local state differs from proposal"
            );
        } else {
            debug!(
                block_number = proposal.block_number,
                "Voting in agreement with proposal"
            );
        }

        // Record our own vote
        self.votes.insert(self.local_hotkey.clone(), vote.clone());

        vote
    }

    /// Receive and process an incoming vote.
    ///
    /// Returns `Some(ConsensusResult)` if consensus is reached with this vote.
    pub fn receive_vote(
        &mut self,
        vote: StateRootVote,
    ) -> Result<Option<ConsensusResult>, StateRootConsensusError> {
        let proposal = self.current_proposal.as_ref().ok_or_else(|| {
            StateRootConsensusError::InternalError("No active proposal".to_string())
        })?;

        // Verify vote is for current proposal
        if vote.block_number != proposal.block_number {
            return Err(StateRootConsensusError::InternalError(format!(
                "Vote block {} doesn't match proposal block {}",
                vote.block_number, proposal.block_number
            )));
        }

        // Check for conflicting votes from same voter
        if let Some(existing) = self.votes.get(&vote.voter) {
            if existing.state_root != vote.state_root {
                // This is potential fraud - voter sending different roots
                warn!(
                    voter = vote.voter.to_hex(),
                    first_root = hex::encode(existing.state_root),
                    second_root = hex::encode(vote.state_root),
                    "Detected conflicting votes from same validator"
                );
                return Err(StateRootConsensusError::FraudDetected(format!(
                    "Validator {} sent conflicting votes",
                    vote.voter.to_hex()
                )));
            }
        }

        debug!(
            voter = vote.voter.to_hex(),
            agrees = vote.agrees_with_proposal,
            "Received vote"
        );

        self.votes.insert(vote.voter.clone(), vote);

        // Check if we've reached consensus
        Ok(self.check_consensus())
    }

    /// Check if consensus has been reached.
    ///
    /// Returns `Some(ConsensusResult)` if 2f+1 validators agree on the state root.
    pub fn check_consensus(&self) -> Option<ConsensusResult> {
        let proposal = self.current_proposal.as_ref()?;

        // Count agreeing votes
        let agreeing_votes: Vec<_> = self
            .votes
            .values()
            .filter(|v| v.agrees_with_proposal)
            .cloned()
            .collect();

        if agreeing_votes.len() >= self.quorum_size {
            info!(
                block_number = proposal.block_number,
                votes = agreeing_votes.len(),
                quorum = self.quorum_size,
                "Consensus reached!"
            );

            Some(ConsensusResult {
                block_number: proposal.block_number,
                agreed_root: proposal.global_state_root,
                votes: agreeing_votes,
                timestamp: chrono::Utc::now().timestamp_millis(),
            })
        } else {
            None
        }
    }

    /// Create a fraud proof against a validator.
    pub fn create_fraud_proof(
        &self,
        accused: &Hotkey,
        claimed: [u8; 32],
        actual: [u8; 32],
    ) -> FraudProof {
        let current_block = self
            .current_proposal
            .as_ref()
            .map(|p| p.block_number)
            .unwrap_or(0);

        let proof = FraudProof {
            accuser: self.local_hotkey.clone(),
            accused: accused.clone(),
            block_number: current_block,
            claimed_root: claimed,
            actual_root: actual,
            merkle_proof: None,
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: Vec::new(), // Signature would be added by caller with keypair
        };

        warn!(
            accused = accused.to_hex(),
            block_number = current_block,
            claimed = hex::encode(claimed),
            actual = hex::encode(actual),
            "Created fraud proof"
        );

        proof
    }

    /// Verify a fraud proof.
    pub fn verify_fraud_proof(&self, proof: &FraudProof) -> bool {
        // Basic validation: roots must actually differ
        if !proof.roots_differ() {
            debug!("Fraud proof invalid: roots are identical");
            return false;
        }

        // If merkle proof is provided, verify it
        if let Some(ref merkle_path) = proof.merkle_proof {
            // Verify the merkle path leads to actual_root
            let mut current = proof.claimed_root;
            for sibling in merkle_path {
                current = if current <= *sibling {
                    hash_pair(&current, sibling)
                } else {
                    hash_pair(sibling, &current)
                };
            }

            // The merkle path should NOT lead to actual_root if fraud is genuine
            // (the accused claimed a wrong root)
            if current == proof.actual_root {
                debug!("Fraud proof invalid: merkle path verifies to actual root");
                return false;
            }
        }

        debug!(accused = proof.accused.to_hex(), "Fraud proof verified");

        true
    }

    /// Get the current proposal if any.
    pub fn current_proposal(&self) -> Option<&StateRootProposal> {
        self.current_proposal.as_ref()
    }

    /// Get all votes for the current proposal.
    pub fn current_votes(&self) -> &HashMap<Hotkey, StateRootVote> {
        &self.votes
    }

    /// Get the number of votes received.
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    /// Get completed consensus results.
    pub fn get_completed(&self, block_number: u64) -> Option<&ConsensusResult> {
        self.completed.get(&block_number)
    }

    /// Store a completed consensus result.
    pub fn store_completed(&mut self, result: ConsensusResult) {
        let block = result.block_number;
        self.completed.insert(block, result);
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Compute global state root from challenge roots.
fn compute_global_root_from_challenges(challenge_roots: &HashMap<String, [u8; 32]>) -> [u8; 32] {
    if challenge_roots.is_empty() {
        return [0u8; 32];
    }

    // Sort by challenge ID for determinism
    let mut sorted_entries: Vec<_> = challenge_roots.iter().collect();
    sorted_entries.sort_by_key(|(k, _)| *k);

    // Build leaf hashes (challenge_id + root)
    let leaves: Vec<[u8; 32]> = sorted_entries
        .iter()
        .map(|(id, root)| {
            let mut hasher = Sha256::new();
            hasher.update(id.as_bytes());
            hasher.update(*root);
            hasher.finalize().into()
        })
        .collect();

    // Compute merkle root of leaves
    compute_merkle_root(&leaves)
}

/// Compute merkle root from a list of leaf hashes.
fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut level = leaves.to_vec();

    while level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in level.chunks(2) {
            let combined = if chunk.len() == 2 {
                hash_pair(&chunk[0], &chunk[1])
            } else {
                // Odd number - duplicate last element
                hash_pair(&chunk[0], &chunk[0])
            };
            next_level.push(combined);
        }

        level = next_level;
    }

    level[0]
}

/// Hash two 32-byte values together.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Build merkle proof path for a specific challenge.
fn build_merkle_proof_path(
    challenge_roots: &HashMap<String, [u8; 32]>,
    target_challenge: &str,
) -> Vec<ProofStep> {
    if challenge_roots.is_empty() {
        return Vec::new();
    }

    // Sort by challenge ID for determinism
    let mut sorted_entries: Vec<_> = challenge_roots.iter().collect();
    sorted_entries.sort_by_key(|(k, _)| *k);

    // Find target index
    let target_index = sorted_entries
        .iter()
        .position(|(k, _)| *k == target_challenge);

    let target_index = match target_index {
        Some(idx) => idx,
        None => return Vec::new(),
    };

    // Build leaf hashes
    let leaves: Vec<[u8; 32]> = sorted_entries
        .iter()
        .map(|(id, root)| {
            let mut hasher = Sha256::new();
            hasher.update(id.as_bytes());
            hasher.update(*root);
            hasher.finalize().into()
        })
        .collect();

    // Build proof path
    let mut proof_path = Vec::new();
    let mut level = leaves;
    let mut index = target_index;

    while level.len() > 1 {
        // Determine if we are left (even index) or right (odd index) child
        let is_left = index % 2 == 0;

        // Get sibling index
        let sibling_index = if is_left {
            if index + 1 < level.len() {
                index + 1
            } else {
                index // duplicate self for odd case
            }
        } else {
            index - 1
        };

        proof_path.push(ProofStep {
            sibling_hash: level[sibling_index],
            is_left,
        });

        // Build next level
        let mut next_level = Vec::new();
        for chunk in level.chunks(2) {
            let combined = if chunk.len() == 2 {
                hash_pair(&chunk[0], &chunk[1])
            } else {
                hash_pair(&chunk[0], &chunk[0])
            };
            next_level.push(combined);
        }

        level = next_level;
        index /= 2;
    }

    proof_path
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_hotkey(seed: u8) -> Hotkey {
        Hotkey([seed; 32])
    }

    #[test]
    fn test_global_state_linker_basic() {
        let mut linker = GlobalStateLinker::new();

        assert!(linker.is_empty());
        assert_eq!(linker.challenge_count(), 0);

        // Add some challenge roots
        linker.add_challenge_root("challenge-1", [1u8; 32]);
        linker.add_challenge_root("challenge-2", [2u8; 32]);

        assert!(!linker.is_empty());
        assert_eq!(linker.challenge_count(), 2);

        // Compute global root
        let root = linker.compute_global_root();
        assert_ne!(root, [0u8; 32]);

        // Verify inclusion
        assert!(linker.verify_inclusion("challenge-1", [1u8; 32]));
        assert!(!linker.verify_inclusion("challenge-1", [2u8; 32]));
        assert!(!linker.verify_inclusion("challenge-3", [1u8; 32]));
    }

    #[test]
    fn test_global_state_linker_remove() {
        let mut linker = GlobalStateLinker::new();

        linker.add_challenge_root("challenge-1", [1u8; 32]);
        linker.add_challenge_root("challenge-2", [2u8; 32]);

        let root_before = linker.compute_global_root();

        linker.remove_challenge_root("challenge-1");

        let root_after = linker.compute_global_root();
        assert_ne!(root_before, root_after);
        assert_eq!(linker.challenge_count(), 1);
    }

    #[test]
    fn test_global_state_linker_deterministic() {
        let mut linker1 = GlobalStateLinker::new();
        let mut linker2 = GlobalStateLinker::new();

        // Add in different orders
        linker1.add_challenge_root("b-challenge", [2u8; 32]);
        linker1.add_challenge_root("a-challenge", [1u8; 32]);

        linker2.add_challenge_root("a-challenge", [1u8; 32]);
        linker2.add_challenge_root("b-challenge", [2u8; 32]);

        // Should produce same root regardless of insertion order
        assert_eq!(linker1.compute_global_root(), linker2.compute_global_root());
    }

    #[test]
    fn test_inclusion_proof() {
        let mut linker = GlobalStateLinker::new();

        linker.add_challenge_root("challenge-1", [1u8; 32]);
        linker.add_challenge_root("challenge-2", [2u8; 32]);
        linker.add_challenge_root("challenge-3", [3u8; 32]);

        // Build and verify inclusion proof
        let proof = linker
            .build_inclusion_proof("challenge-2")
            .expect("Should build proof");

        assert_eq!(proof.challenge_id, "challenge-2");
        assert_eq!(proof.challenge_root, [2u8; 32]);
        assert_eq!(proof.global_root, linker.compute_global_root());
        assert!(proof.verify());
    }

    #[test]
    fn test_inclusion_proof_nonexistent() {
        let mut linker = GlobalStateLinker::new();
        linker.add_challenge_root("challenge-1", [1u8; 32]);

        let proof = linker.build_inclusion_proof("nonexistent");
        assert!(proof.is_none());
    }

    #[test]
    fn test_state_root_proposal() {
        let hotkey = create_test_hotkey(1);
        let mut challenge_roots = HashMap::new();
        challenge_roots.insert("challenge-1".to_string(), [1u8; 32]);
        challenge_roots.insert("challenge-2".to_string(), [2u8; 32]);

        let global_root = compute_global_root_from_challenges(&challenge_roots);

        let proposal = StateRootProposal {
            block_number: 100,
            proposer: hotkey,
            global_state_root: global_root,
            challenge_roots,
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: Vec::new(),
        };

        // Verify global root consistency
        assert!(proposal.verify_global_root());

        // Compute hash
        let hash = proposal.compute_hash();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_state_root_proposal_invalid_global_root() {
        let hotkey = create_test_hotkey(1);
        let mut challenge_roots = HashMap::new();
        challenge_roots.insert("challenge-1".to_string(), [1u8; 32]);

        let proposal = StateRootProposal {
            block_number: 100,
            proposer: hotkey,
            global_state_root: [0u8; 32], // Wrong root
            challenge_roots,
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: Vec::new(),
        };

        // Should fail verification
        assert!(!proposal.verify_global_root());
    }

    #[test]
    fn test_state_root_vote() {
        let hotkey = create_test_hotkey(1);
        let state_root = [42u8; 32];

        let vote = StateRootVote {
            block_number: 100,
            voter: hotkey,
            state_root,
            agrees_with_proposal: true,
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: Vec::new(),
        };

        let hash = vote.compute_hash();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_fraud_proof() {
        let accuser = create_test_hotkey(1);
        let accused = create_test_hotkey(2);

        let proof = FraudProof {
            accuser,
            accused,
            block_number: 100,
            claimed_root: [1u8; 32],
            actual_root: [2u8; 32],
            merkle_proof: None,
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: Vec::new(),
        };

        assert!(proof.roots_differ());

        let hash = proof.compute_hash();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_fraud_proof_same_roots() {
        let accuser = create_test_hotkey(1);
        let accused = create_test_hotkey(2);

        let proof = FraudProof {
            accuser,
            accused,
            block_number: 100,
            claimed_root: [1u8; 32],
            actual_root: [1u8; 32], // Same as claimed
            merkle_proof: None,
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: Vec::new(),
        };

        assert!(!proof.roots_differ());
    }

    #[test]
    fn test_state_root_consensus_creation() {
        let hotkey = create_test_hotkey(1);
        let consensus = StateRootConsensus::new(hotkey, 3);

        assert_eq!(consensus.quorum_size, 3);
        assert!(consensus.current_proposal().is_none());
        assert_eq!(consensus.vote_count(), 0);
    }

    #[test]
    fn test_state_root_consensus_propose() {
        let hotkey = create_test_hotkey(1);
        let mut consensus = StateRootConsensus::new(hotkey, 3);

        let mut challenge_roots = HashMap::new();
        challenge_roots.insert("challenge-1".to_string(), [1u8; 32]);

        let global_root = compute_global_root_from_challenges(&challenge_roots);
        let proposal = consensus.propose_state_root(100, global_root, challenge_roots);

        assert_eq!(proposal.block_number, 100);
        assert!(consensus.current_proposal().is_some());
    }

    #[test]
    fn test_state_root_consensus_receive_proposal() {
        let hotkey = create_test_hotkey(1);
        let mut consensus = StateRootConsensus::new(hotkey, 3);

        let mut challenge_roots = HashMap::new();
        challenge_roots.insert("challenge-1".to_string(), [1u8; 32]);
        let global_root = compute_global_root_from_challenges(&challenge_roots);

        let proposal = StateRootProposal {
            block_number: 100,
            proposer: create_test_hotkey(2),
            global_state_root: global_root,
            challenge_roots,
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: Vec::new(),
        };

        let result = consensus.receive_proposal(proposal);
        assert!(result.is_ok());
        assert!(consensus.current_proposal().is_some());
    }

    #[test]
    fn test_state_root_consensus_receive_invalid_proposal() {
        let hotkey = create_test_hotkey(1);
        let mut consensus = StateRootConsensus::new(hotkey, 3);

        let mut challenge_roots = HashMap::new();
        challenge_roots.insert("challenge-1".to_string(), [1u8; 32]);

        let proposal = StateRootProposal {
            block_number: 100,
            proposer: create_test_hotkey(2),
            global_state_root: [0u8; 32], // Invalid root
            challenge_roots,
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: Vec::new(),
        };

        let result = consensus.receive_proposal(proposal);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StateRootConsensusError::ConflictingRoots { .. }
        ));
    }

    #[test]
    fn test_state_root_consensus_voting() {
        let hotkey = create_test_hotkey(1);
        let mut consensus = StateRootConsensus::new(hotkey.clone(), 3);

        let mut challenge_roots = HashMap::new();
        challenge_roots.insert("challenge-1".to_string(), [1u8; 32]);
        let global_root = compute_global_root_from_challenges(&challenge_roots);

        let proposal = consensus.propose_state_root(100, global_root, challenge_roots);

        // Vote in agreement
        let vote = consensus.vote_on_proposal(&proposal, global_root);
        assert!(vote.agrees_with_proposal);
        assert_eq!(vote.state_root, global_root);
    }

    #[test]
    fn test_state_root_consensus_voting_disagreement() {
        let hotkey = create_test_hotkey(1);
        let mut consensus = StateRootConsensus::new(hotkey, 3);

        let mut challenge_roots = HashMap::new();
        challenge_roots.insert("challenge-1".to_string(), [1u8; 32]);
        let global_root = compute_global_root_from_challenges(&challenge_roots);

        let proposal = consensus.propose_state_root(100, global_root, challenge_roots);

        // Vote with different local state
        let different_root = [99u8; 32];
        let vote = consensus.vote_on_proposal(&proposal, different_root);
        assert!(!vote.agrees_with_proposal);
    }

    #[test]
    fn test_state_root_consensus_quorum() {
        let hotkey = create_test_hotkey(1);
        let mut consensus = StateRootConsensus::new(hotkey.clone(), 2); // Quorum of 2

        let mut challenge_roots = HashMap::new();
        challenge_roots.insert("challenge-1".to_string(), [1u8; 32]);
        let global_root = compute_global_root_from_challenges(&challenge_roots);

        let proposal = consensus.propose_state_root(100, global_root, challenge_roots);

        // First vote (our own)
        let vote1 = consensus.vote_on_proposal(&proposal, global_root);
        assert!(consensus.check_consensus().is_none()); // Not enough yet

        // Second vote from another validator
        let vote2 = StateRootVote {
            block_number: 100,
            voter: create_test_hotkey(2),
            state_root: global_root,
            agrees_with_proposal: true,
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: Vec::new(),
        };

        let result = consensus.receive_vote(vote2).expect("Should accept vote");
        assert!(result.is_some()); // Should have consensus now

        let consensus_result = result.unwrap();
        assert_eq!(consensus_result.block_number, 100);
        assert_eq!(consensus_result.agreed_root, global_root);
        assert_eq!(consensus_result.agreeing_votes(), 2);
    }

    #[test]
    fn test_state_root_consensus_conflicting_votes() {
        let hotkey = create_test_hotkey(1);
        let mut consensus = StateRootConsensus::new(hotkey, 3);

        let mut challenge_roots = HashMap::new();
        challenge_roots.insert("challenge-1".to_string(), [1u8; 32]);
        let global_root = compute_global_root_from_challenges(&challenge_roots);

        let _proposal = consensus.propose_state_root(100, global_root, challenge_roots);

        // First vote from validator 2
        let vote1 = StateRootVote {
            block_number: 100,
            voter: create_test_hotkey(2),
            state_root: global_root,
            agrees_with_proposal: true,
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: Vec::new(),
        };
        consensus.receive_vote(vote1).expect("Should accept vote");

        // Conflicting vote from same validator
        let vote2 = StateRootVote {
            block_number: 100,
            voter: create_test_hotkey(2),
            state_root: [99u8; 32], // Different root!
            agrees_with_proposal: false,
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: Vec::new(),
        };

        let result = consensus.receive_vote(vote2);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StateRootConsensusError::FraudDetected(_)
        ));
    }

    #[test]
    fn test_create_and_verify_fraud_proof() {
        let hotkey = create_test_hotkey(1);
        let consensus = StateRootConsensus::new(hotkey, 3);

        let accused = create_test_hotkey(2);
        let claimed = [1u8; 32];
        let actual = [2u8; 32];

        let proof = consensus.create_fraud_proof(&accused, claimed, actual);

        assert!(proof.roots_differ());
        assert!(consensus.verify_fraud_proof(&proof));
    }

    #[test]
    fn test_verify_invalid_fraud_proof() {
        let hotkey = create_test_hotkey(1);
        let consensus = StateRootConsensus::new(hotkey, 3);

        // Proof with same roots (not fraud)
        let proof = FraudProof {
            accuser: create_test_hotkey(1),
            accused: create_test_hotkey(2),
            block_number: 100,
            claimed_root: [1u8; 32],
            actual_root: [1u8; 32], // Same!
            merkle_proof: None,
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: Vec::new(),
        };

        assert!(!consensus.verify_fraud_proof(&proof));
    }

    #[test]
    fn test_consensus_result_methods() {
        let result = ConsensusResult {
            block_number: 100,
            agreed_root: [42u8; 32],
            votes: vec![
                StateRootVote {
                    block_number: 100,
                    voter: create_test_hotkey(1),
                    state_root: [42u8; 32],
                    agrees_with_proposal: true,
                    timestamp: 0,
                    signature: Vec::new(),
                },
                StateRootVote {
                    block_number: 100,
                    voter: create_test_hotkey(2),
                    state_root: [42u8; 32],
                    agrees_with_proposal: true,
                    timestamp: 0,
                    signature: Vec::new(),
                },
                StateRootVote {
                    block_number: 100,
                    voter: create_test_hotkey(3),
                    state_root: [99u8; 32],
                    agrees_with_proposal: false,
                    timestamp: 0,
                    signature: Vec::new(),
                },
            ],
            timestamp: 0,
        };

        assert_eq!(result.agreeing_votes(), 2);
        assert_eq!(result.disagreeing_votes(), 1);
    }

    #[test]
    fn test_store_and_get_completed() {
        let hotkey = create_test_hotkey(1);
        let mut consensus = StateRootConsensus::new(hotkey, 3);

        let result = ConsensusResult {
            block_number: 100,
            agreed_root: [42u8; 32],
            votes: Vec::new(),
            timestamp: chrono::Utc::now().timestamp_millis(),
        };

        consensus.store_completed(result.clone());

        let retrieved = consensus.get_completed(100);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().block_number, 100);

        assert!(consensus.get_completed(101).is_none());
    }

    #[test]
    fn test_merkle_root_computation() {
        // Empty case
        let empty: Vec<[u8; 32]> = Vec::new();
        assert_eq!(compute_merkle_root(&empty), [0u8; 32]);

        // Single leaf
        let single = vec![[1u8; 32]];
        assert_eq!(compute_merkle_root(&single), [1u8; 32]);

        // Two leaves
        let two = vec![[1u8; 32], [2u8; 32]];
        let root_two = compute_merkle_root(&two);
        assert_ne!(root_two, [0u8; 32]);
        assert_ne!(root_two, [1u8; 32]);
        assert_ne!(root_two, [2u8; 32]);

        // Three leaves (odd number)
        let three = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let root_three = compute_merkle_root(&three);
        assert_ne!(root_three, root_two);
    }

    #[test]
    fn test_hash_pair() {
        let a = [1u8; 32];
        let b = [2u8; 32];

        let hash1 = hash_pair(&a, &b);
        let hash2 = hash_pair(&b, &a);

        // Order matters
        assert_ne!(hash1, hash2);

        // Deterministic
        assert_eq!(hash_pair(&a, &b), hash_pair(&a, &b));
    }

    #[test]
    fn test_empty_global_state_linker() {
        let linker = GlobalStateLinker::new();

        assert!(linker.is_empty());
        assert_eq!(linker.compute_global_root(), [0u8; 32]);
        assert!(linker.build_inclusion_proof("anything").is_none());
    }

    #[test]
    fn test_single_challenge_inclusion_proof() {
        let mut linker = GlobalStateLinker::new();
        linker.add_challenge_root("challenge-1", [42u8; 32]);

        let proof = linker
            .build_inclusion_proof("challenge-1")
            .expect("Should build proof");
        assert!(proof.verify());
    }

    #[test]
    fn test_receive_vote_no_proposal() {
        let hotkey = create_test_hotkey(1);
        let mut consensus = StateRootConsensus::new(hotkey, 3);

        let vote = StateRootVote {
            block_number: 100,
            voter: create_test_hotkey(2),
            state_root: [42u8; 32],
            agrees_with_proposal: true,
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: Vec::new(),
        };

        let result = consensus.receive_vote(vote);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StateRootConsensusError::InternalError(_)
        ));
    }

    #[test]
    fn test_receive_vote_wrong_block() {
        let hotkey = create_test_hotkey(1);
        let mut consensus = StateRootConsensus::new(hotkey, 3);

        let mut challenge_roots = HashMap::new();
        challenge_roots.insert("challenge-1".to_string(), [1u8; 32]);
        let global_root = compute_global_root_from_challenges(&challenge_roots);

        let _proposal = consensus.propose_state_root(100, global_root, challenge_roots);

        let vote = StateRootVote {
            block_number: 999, // Wrong block!
            voter: create_test_hotkey(2),
            state_root: global_root,
            agrees_with_proposal: true,
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: Vec::new(),
        };

        let result = consensus.receive_vote(vote);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_display() {
        let err1 = StateRootConsensusError::NotEnoughVotes { needed: 5, have: 2 };
        assert!(err1.to_string().contains("5"));
        assert!(err1.to_string().contains("2"));

        let err2 = StateRootConsensusError::ConflictingRoots {
            expected: "abc".to_string(),
            got: "def".to_string(),
        };
        assert!(err2.to_string().contains("abc"));
        assert!(err2.to_string().contains("def"));

        let err3 = StateRootConsensusError::InvalidSignature("bad sig".to_string());
        assert!(err3.to_string().contains("bad sig"));

        let err4 = StateRootConsensusError::ProposalTimeout;
        assert!(err4.to_string().contains("timeout"));

        let err5 = StateRootConsensusError::FraudDetected("fraud!".to_string());
        assert!(err5.to_string().contains("fraud"));

        let err6 = StateRootConsensusError::InternalError("internal".to_string());
        assert!(err6.to_string().contains("internal"));
    }

    #[test]
    fn test_global_root_update_invalidates_cache() {
        let mut linker = GlobalStateLinker::new();

        linker.add_challenge_root("challenge-1", [1u8; 32]);
        let root1 = linker.compute_global_root();

        linker.add_challenge_root("challenge-1", [2u8; 32]); // Update
        let root2 = linker.compute_global_root();

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_many_challenges_inclusion_proof() {
        let mut linker = GlobalStateLinker::new();

        // Add many challenges
        for i in 0..10 {
            linker.add_challenge_root(&format!("challenge-{}", i), [i as u8; 32]);
        }

        // Build and verify proofs for each
        for i in 0..10 {
            let proof = linker
                .build_inclusion_proof(&format!("challenge-{}", i))
                .expect("Should build proof");
            assert!(proof.verify(), "Proof for challenge-{} failed", i);
        }
    }
}
