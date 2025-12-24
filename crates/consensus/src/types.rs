//! Consensus types

use platform_core::{Hotkey, Proposal, Vote};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Consensus phase
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusPhase {
    /// Waiting for proposal
    Idle,

    /// Pre-prepare phase (leader broadcasts proposal)
    PrePrepare,

    /// Prepare phase (validators vote)
    Prepare,

    /// Commit phase (enough votes received)
    Commit,

    /// Completed
    Completed,

    /// Failed (timeout or not enough votes)
    Failed,
}

/// Round state for a proposal
#[derive(Clone, Debug)]
pub struct RoundState {
    /// Proposal being voted on
    pub proposal: Proposal,

    /// Current phase
    pub phase: ConsensusPhase,

    /// Votes received
    pub votes: HashMap<Hotkey, Vote>,

    /// Start time
    pub started_at: chrono::DateTime<chrono::Utc>,

    /// Timeout
    pub timeout: chrono::Duration,
}

impl RoundState {
    pub fn new(proposal: Proposal, timeout_secs: i64) -> Self {
        Self {
            proposal,
            phase: ConsensusPhase::PrePrepare,
            votes: HashMap::new(),
            started_at: chrono::Utc::now(),
            timeout: chrono::Duration::seconds(timeout_secs),
        }
    }

    /// Check if round has timed out
    pub fn is_timed_out(&self) -> bool {
        chrono::Utc::now() > self.started_at + self.timeout
    }

    /// Add a vote
    pub fn add_vote(&mut self, vote: Vote) {
        self.votes.insert(vote.voter.clone(), vote);
    }

    /// Count approve votes
    pub fn approve_count(&self) -> usize {
        self.votes.values().filter(|v| v.approve).count()
    }

    /// Count reject votes
    pub fn reject_count(&self) -> usize {
        self.votes.values().filter(|v| !v.approve).count()
    }

    /// Check if we have enough votes for consensus
    pub fn has_consensus(&self, threshold: usize) -> bool {
        self.approve_count() >= threshold
    }

    /// Check if consensus is impossible (too many rejects)
    pub fn is_rejected(&self, total_validators: usize, threshold: usize) -> bool {
        let max_possible_approves = total_validators - self.reject_count();
        max_possible_approves < threshold
    }
}

/// Consensus result
#[derive(Clone, Debug)]
pub enum ConsensusResult {
    /// Consensus reached
    Approved(Box<Proposal>),

    /// Consensus failed (rejected or timeout)
    Rejected {
        proposal_id: uuid::Uuid,
        reason: String,
    },

    /// Still in progress
    Pending,
}

/// Consensus configuration
#[derive(Clone, Debug)]
pub struct ConsensusConfig {
    /// Threshold fraction (e.g., 0.67 for 2/3)
    pub threshold: f64,

    /// Round timeout in seconds
    pub round_timeout_secs: i64,

    /// Maximum rounds before giving up
    pub max_rounds: usize,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            threshold: 0.33, // 33% for partial network tolerance
            round_timeout_secs: 30,
            max_rounds: 3,
        }
    }
}
