//! Decentralized P2P consensus for Platform Network validators
//!
//! This crate provides the networking and consensus layer for validators
//! to communicate directly without a centralized server.
//!
//! # Architecture
//!
//! - **Network Layer** (`network.rs`): libp2p-based P2P networking with gossipsub
//!   for message broadcasting and Kademlia DHT for peer discovery.
//!
//! - **Consensus** (`consensus.rs`): PBFT-style Byzantine fault tolerant consensus
//!   with view changes and leader election.
//!
//! - **State Management** (`state.rs`): Decentralized state synchronization with
//!   merkle proofs for verification.
//!
//! - **Validator Management** (`validator.rs`): Tracks active validators, their
//!   stakes, and handles leader election.
//!
//! # Usage
//!
//! ```text
//! use platform_p2p_consensus::{P2PConfig, P2PNetwork, ConsensusEngine, StateManager};
//!
//! // Create configuration
//! let config = P2PConfig::production();
//!
//! // Create network and consensus
//! let network = P2PNetwork::new(keypair, config, validator_set, event_tx)?;
//! let consensus = ConsensusEngine::new(keypair, validator_set, state_manager);
//! ```
//!
//! # SudoOwner
//!
//! The network sudo key is hardcoded to: `5GziQCcRpN8NCJktX343brnfuVe3w6gUYieeStXPD1Dag2At`

pub mod config;
pub mod consensus;
pub mod messages;
pub mod network;
pub mod state;
pub mod validator;

// Re-export main types
pub use config::{P2PConfig, DEFAULT_BOOTSTRAP_NODES};
pub use consensus::{ConsensusDecision, ConsensusEngine, ConsensusError, ConsensusPhase};
pub use messages::{
    ChallengeUpdateMessage, CommitMessage, ConsensusProposal, DataRequestMessage,
    DataResponseMessage, EvaluationMessage, EvaluationMetrics, HeartbeatMessage,
    JobAssignmentMessage, JobClaimMessage, LeaderboardRequestMessage, LeaderboardResponseMessage,
    MerkleNode, MerkleProof, NewViewMessage, P2PMessage, PeerAnnounceMessage, PrePrepare,
    PrepareMessage, PreparedProof, ProposalContent, RoundId, SequenceNumber, SignedP2PMessage,
    StateChangeType, StateRequest, StateResponse, StorageProposalMessage, StorageVoteMessage,
    SubmissionMessage, TaskProgressMessage, TaskResultMessage, ViewChangeMessage, ViewNumber,
    WeightVoteMessage,
};
pub use network::{
    NetworkBehaviour, NetworkError, NetworkEvent, NetworkRunner, P2PCommand, P2PEvent, P2PNetwork,
    PeerMapping,
};
pub use state::{
    build_merkle_proof, compute_merkle_root, verify_merkle_proof, ChainState, ChallengeConfig,
    EvaluationRecord, JobRecord, JobStatus, LeaderboardEntry, StateError, StateManager,
    TaskProgressRecord, ValidatorEvaluation, WeightVotes,
};
pub use validator::{
    LeaderElection, StakeWeightedVoting, ValidatorError, ValidatorRecord, ValidatorSet,
};

/// Protocol version string
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// Hardcoded SudoOwner hotkey (SS58 format)
/// This is the only key allowed to perform sudo operations
pub const SUDO_HOTKEY: &str = "5GziQCcRpN8NCJktX343brnfuVe3w6gUYieeStXPD1Dag2At";

/// Default consensus topic
pub const CONSENSUS_TOPIC: &str = "platform/consensus/1.0.0";

/// Default challenge topic
pub const CHALLENGE_TOPIC: &str = "platform/challenge/1.0.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version() {
        assert_eq!(PROTOCOL_VERSION, "1.0.0");
    }

    #[test]
    fn test_default_topics() {
        assert!(CONSENSUS_TOPIC.contains("consensus"));
        assert!(CHALLENGE_TOPIC.contains("challenge"));
    }
}
