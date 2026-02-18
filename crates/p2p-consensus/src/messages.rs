//! P2P message types for consensus and state synchronization
//!
//! Defines all message types used for inter-validator communication
//! over the libp2p gossipsub network.

use platform_core::{ChallengeId, Hotkey};
use serde::{Deserialize, Serialize};

/// Unique identifier for a consensus round
pub type RoundId = u64;

/// View number for PBFT consensus
pub type ViewNumber = u64;

/// Sequence number for ordering
pub type SequenceNumber = u64;

/// All P2P message types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum P2PMessage {
    // Consensus messages
    Proposal(ConsensusProposal),
    PrePrepare(PrePrepare),
    Prepare(PrepareMessage),
    Commit(CommitMessage),
    ViewChange(ViewChangeMessage),
    NewView(NewViewMessage),

    // State sync
    StateRequest(StateRequest),
    StateResponse(StateResponse),

    // Challenge evaluation
    Submission(SubmissionMessage),
    Evaluation(EvaluationMessage),
    WeightVote(WeightVoteMessage),

    // Network maintenance
    Heartbeat(HeartbeatMessage),
    PeerAnnounce(PeerAnnounceMessage),

    // Challenge lifecycle
    JobClaim(JobClaimMessage),
    JobAssignment(JobAssignmentMessage),
    DataRequest(DataRequestMessage),
    DataResponse(DataResponseMessage),
    TaskProgress(TaskProgressMessage),
    TaskResult(TaskResultMessage),
    LeaderboardRequest(LeaderboardRequestMessage),
    LeaderboardResponse(LeaderboardResponseMessage),
    ChallengeUpdate(ChallengeUpdateMessage),
    StorageProposal(StorageProposalMessage),
    StorageVote(StorageVoteMessage),
}

impl P2PMessage {
    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Get the message type name for logging
    pub fn type_name(&self) -> &'static str {
        match self {
            P2PMessage::Proposal(_) => "Proposal",
            P2PMessage::PrePrepare(_) => "PrePrepare",
            P2PMessage::Prepare(_) => "Prepare",
            P2PMessage::Commit(_) => "Commit",
            P2PMessage::ViewChange(_) => "ViewChange",
            P2PMessage::NewView(_) => "NewView",
            P2PMessage::StateRequest(_) => "StateRequest",
            P2PMessage::StateResponse(_) => "StateResponse",
            P2PMessage::Submission(_) => "Submission",
            P2PMessage::Evaluation(_) => "Evaluation",
            P2PMessage::WeightVote(_) => "WeightVote",
            P2PMessage::Heartbeat(_) => "Heartbeat",
            P2PMessage::PeerAnnounce(_) => "PeerAnnounce",
            P2PMessage::JobClaim(_) => "JobClaim",
            P2PMessage::JobAssignment(_) => "JobAssignment",
            P2PMessage::DataRequest(_) => "DataRequest",
            P2PMessage::DataResponse(_) => "DataResponse",
            P2PMessage::TaskProgress(_) => "TaskProgress",
            P2PMessage::TaskResult(_) => "TaskResult",
            P2PMessage::LeaderboardRequest(_) => "LeaderboardRequest",
            P2PMessage::LeaderboardResponse(_) => "LeaderboardResponse",
            P2PMessage::ChallengeUpdate(_) => "ChallengeUpdate",
            P2PMessage::StorageProposal(_) => "StorageProposal",
            P2PMessage::StorageVote(_) => "StorageVote",
        }
    }
}

// ============================================================================
// Consensus Messages (PBFT-style)
// ============================================================================

/// Proposal from the leader to initiate consensus
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusProposal {
    /// View number (leader term)
    pub view: ViewNumber,
    /// Sequence number for this proposal
    pub sequence: SequenceNumber,
    /// The proposed state transition
    pub proposal: ProposalContent,
    /// Proposer's hotkey
    pub proposer: Hotkey,
    /// Proposer's signature over (view, sequence, proposal_hash)
    pub signature: Vec<u8>,
    /// Timestamp when proposal was created
    pub timestamp: i64,
}

/// Content of a consensus proposal
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalContent {
    /// Type of state change
    pub change_type: StateChangeType,
    /// Serialized change data
    pub data: Vec<u8>,
    /// Hash of the change for verification
    pub data_hash: [u8; 32],
}

/// Types of state changes that can be proposed
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum StateChangeType {
    /// New challenge submission
    ChallengeSubmission,
    /// Evaluation result
    EvaluationResult,
    /// Weight update
    WeightUpdate,
    /// Validator set change
    ValidatorChange,
    /// Configuration update (sudo only)
    ConfigUpdate,
    /// Epoch transition
    EpochTransition,
}

/// Pre-prepare message (leader broadcasts after receiving proposal)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrePrepare {
    /// View number
    pub view: ViewNumber,
    /// Sequence number
    pub sequence: SequenceNumber,
    /// Hash of the proposal
    pub proposal_hash: [u8; 32],
    /// Leader's hotkey
    pub leader: Hotkey,
    /// Leader's signature
    pub signature: Vec<u8>,
}

/// Prepare message (validators acknowledge pre-prepare)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrepareMessage {
    /// View number
    pub view: ViewNumber,
    /// Sequence number
    pub sequence: SequenceNumber,
    /// Hash of the proposal
    pub proposal_hash: [u8; 32],
    /// Validator's hotkey
    pub validator: Hotkey,
    /// Validator's signature
    pub signature: Vec<u8>,
}

/// Commit message (validators commit to the proposal)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitMessage {
    /// View number
    pub view: ViewNumber,
    /// Sequence number
    pub sequence: SequenceNumber,
    /// Hash of the proposal
    pub proposal_hash: [u8; 32],
    /// Validator's hotkey
    pub validator: Hotkey,
    /// Validator's signature
    pub signature: Vec<u8>,
}

/// View change message (request new leader)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewChangeMessage {
    /// New view number being proposed
    pub new_view: ViewNumber,
    /// Last prepared sequence number
    pub last_prepared_sequence: Option<SequenceNumber>,
    /// Proof of last prepared (signatures)
    pub prepared_proof: Option<PreparedProof>,
    /// Validator requesting change
    pub validator: Hotkey,
    /// Validator's signature
    pub signature: Vec<u8>,
}

/// Proof that a proposal was prepared
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedProof {
    /// The pre-prepare message
    pub pre_prepare: PrePrepare,
    /// Prepare messages (2f+1 required)
    pub prepares: Vec<PrepareMessage>,
}

/// New view message (new leader announces)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewViewMessage {
    /// The new view number
    pub view: ViewNumber,
    /// View change messages collected (2f+1)
    pub view_changes: Vec<ViewChangeMessage>,
    /// New leader's hotkey
    pub leader: Hotkey,
    /// New leader's signature
    pub signature: Vec<u8>,
}

// ============================================================================
// State Sync Messages
// ============================================================================

/// Request for state synchronization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateRequest {
    /// Requesting validator
    pub requester: Hotkey,
    /// Current state hash of requester
    pub current_hash: [u8; 32],
    /// Current sequence number
    pub current_sequence: SequenceNumber,
    /// Request timestamp
    pub timestamp: i64,
}

/// Response with state data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateResponse {
    /// Responding validator
    pub responder: Hotkey,
    /// State hash being sent
    pub state_hash: [u8; 32],
    /// Sequence number of this state
    pub sequence: SequenceNumber,
    /// Serialized state data
    pub state_data: Vec<u8>,
    /// Merkle proof for verification
    pub merkle_proof: Option<MerkleProof>,
    /// Responder's signature
    pub signature: Vec<u8>,
}

/// Merkle proof for state verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Root hash
    pub root: [u8; 32],
    /// Path from leaf to root
    pub path: Vec<MerkleNode>,
}

/// Node in merkle proof path
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleNode {
    /// Hash of sibling
    pub sibling_hash: [u8; 32],
    /// Whether sibling is on the left
    pub is_left: bool,
}

// ============================================================================
// Challenge Messages
// ============================================================================

/// Submission of agent code for evaluation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmissionMessage {
    /// Unique submission ID
    pub submission_id: String,
    /// Challenge being submitted to
    pub challenge_id: ChallengeId,
    /// Miner's hotkey
    pub miner: Hotkey,
    /// Hash of the agent code
    pub agent_hash: String,
    /// Signature from miner
    pub signature: Vec<u8>,
    /// Submission timestamp
    pub timestamp: i64,
}

/// Evaluation result from a validator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationMessage {
    /// Submission being evaluated
    pub submission_id: String,
    /// Challenge ID
    pub challenge_id: ChallengeId,
    /// Evaluating validator
    pub validator: Hotkey,
    /// Evaluation score (0.0 to 1.0)
    pub score: f64,
    /// Evaluation metrics
    pub metrics: EvaluationMetrics,
    /// Validator's signature
    pub signature: Vec<u8>,
    /// Evaluation timestamp
    pub timestamp: i64,
}

/// Detailed evaluation metrics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationMetrics {
    /// Primary score
    pub primary_score: f64,
    /// Secondary metrics (challenge-specific)
    pub secondary_metrics: Vec<(String, f64)>,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Memory usage in bytes
    pub memory_usage_bytes: Option<u64>,
    /// Whether evaluation timed out
    pub timed_out: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Weight vote for epoch finalization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightVoteMessage {
    /// Epoch number
    pub epoch: u64,
    /// Netuid
    pub netuid: u16,
    /// Validator casting the vote
    pub validator: Hotkey,
    /// Weight vector (uid -> weight)
    pub weights: Vec<(u16, u16)>,
    /// Hash of the weight vector
    pub weights_hash: [u8; 32],
    /// Validator's signature
    pub signature: Vec<u8>,
    /// Vote timestamp
    pub timestamp: i64,
}

// ============================================================================
// Network Maintenance Messages
// ============================================================================

/// Heartbeat message to maintain presence
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    /// Validator's hotkey
    pub validator: Hotkey,
    /// Current state hash
    pub state_hash: [u8; 32],
    /// Current sequence number
    pub sequence: SequenceNumber,
    /// Validator's stake (self-reported, verify against chain)
    pub stake: u64,
    /// Timestamp
    pub timestamp: i64,
    /// Signature
    pub signature: Vec<u8>,
}

/// Peer announcement for discovery
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerAnnounceMessage {
    /// Validator's hotkey
    pub validator: Hotkey,
    /// Multiaddresses where this peer can be reached
    pub addresses: Vec<String>,
    /// Peer ID (libp2p)
    pub peer_id: String,
    /// Protocol version
    pub protocol_version: String,
    /// Timestamp
    pub timestamp: i64,
    /// Signature
    pub signature: Vec<u8>,
}

// ============================================================================
// Challenge Lifecycle Messages
// ============================================================================

/// Job claim from a validator for challenge evaluation work
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobClaimMessage {
    /// Validator claiming the job
    pub validator: Hotkey,
    /// Challenge to claim work for
    pub challenge_id: ChallengeId,
    /// Maximum number of jobs the validator can handle
    pub max_jobs: u32,
    /// Claim timestamp
    pub timestamp: i64,
    /// Validator's signature
    pub signature: Vec<u8>,
}

/// Assignment of a submission evaluation job to a validator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobAssignmentMessage {
    /// Submission being assigned
    pub submission_id: String,
    /// Challenge the submission belongs to
    pub challenge_id: ChallengeId,
    /// Validator assigned to evaluate
    pub assigned_validator: Hotkey,
    /// Validator that made the assignment
    pub assigner: Hotkey,
    /// Hash of the agent code to evaluate
    pub agent_hash: String,
    /// Assignment timestamp
    pub timestamp: i64,
    /// Assigner's signature
    pub signature: Vec<u8>,
}

/// Request for challenge-related data from peers
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataRequestMessage {
    /// Unique request identifier
    pub request_id: String,
    /// Validator making the request
    pub requester: Hotkey,
    /// Challenge the data belongs to
    pub challenge_id: ChallengeId,
    /// Type of data being requested
    pub data_type: String,
    /// Key identifying the specific data
    pub data_key: String,
    /// Request timestamp
    pub timestamp: i64,
    /// Requester's signature
    pub signature: Vec<u8>,
}

/// Response containing requested challenge data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataResponseMessage {
    /// Request identifier this responds to
    pub request_id: String,
    /// Validator providing the data
    pub responder: Hotkey,
    /// Challenge the data belongs to
    pub challenge_id: ChallengeId,
    /// Type of data being returned
    pub data_type: String,
    /// Serialized data payload
    pub data: Vec<u8>,
    /// Response timestamp
    pub timestamp: i64,
    /// Responder's signature
    pub signature: Vec<u8>,
}

/// Progress update for a task within a submission evaluation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskProgressMessage {
    /// Submission being evaluated
    pub submission_id: String,
    /// Challenge the submission belongs to
    pub challenge_id: ChallengeId,
    /// Validator performing the evaluation
    pub validator: Hotkey,
    /// Index of the current task
    pub task_index: u32,
    /// Total number of tasks
    pub total_tasks: u32,
    /// Current status description
    pub status: String,
    /// Progress percentage (0.0 to 100.0)
    pub progress_pct: f64,
    /// Progress timestamp
    pub timestamp: i64,
    /// Validator's signature
    pub signature: Vec<u8>,
}

/// Result of a single task within a submission evaluation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskResultMessage {
    /// Submission being evaluated
    pub submission_id: String,
    /// Challenge the submission belongs to
    pub challenge_id: ChallengeId,
    /// Validator that performed the evaluation
    pub validator: Hotkey,
    /// Unique task identifier
    pub task_id: String,
    /// Whether the task passed
    pub passed: bool,
    /// Task score
    pub score: f64,
    /// Serialized task output
    pub output: Vec<u8>,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Result timestamp
    pub timestamp: i64,
    /// Validator's signature
    pub signature: Vec<u8>,
}

/// Request for challenge leaderboard data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaderboardRequestMessage {
    /// Validator making the request
    pub requester: Hotkey,
    /// Challenge to get leaderboard for
    pub challenge_id: ChallengeId,
    /// Maximum number of entries to return
    pub limit: u32,
    /// Offset for pagination
    pub offset: u32,
    /// Request timestamp
    pub timestamp: i64,
    /// Requester's signature
    pub signature: Vec<u8>,
}

/// Response containing leaderboard data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaderboardResponseMessage {
    /// Validator providing the data
    pub responder: Hotkey,
    /// Challenge the leaderboard belongs to
    pub challenge_id: ChallengeId,
    /// Serialized leaderboard entries
    pub entries: Vec<u8>,
    /// Total number of entries in the leaderboard
    pub total_count: u32,
    /// Response timestamp
    pub timestamp: i64,
    /// Responder's signature
    pub signature: Vec<u8>,
}

/// Update notification for a challenge
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeUpdateMessage {
    /// Challenge being updated
    pub challenge_id: ChallengeId,
    /// Validator publishing the update
    pub updater: Hotkey,
    /// Type of update
    pub update_type: String,
    /// Serialized update data
    pub data: Vec<u8>,
    /// Update timestamp
    pub timestamp: i64,
    /// Updater's signature
    pub signature: Vec<u8>,
}

/// Proposal to store a key-value pair in consensus storage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageProposalMessage {
    /// Unique proposal identifier
    pub proposal_id: [u8; 32],
    /// Challenge the storage belongs to
    pub challenge_id: ChallengeId,
    /// Validator proposing the storage
    pub proposer: Hotkey,
    /// Storage key
    pub key: Vec<u8>,
    /// Storage value
    pub value: Vec<u8>,
    /// Proposal timestamp
    pub timestamp: i64,
    /// Proposer's signature
    pub signature: Vec<u8>,
}

/// Vote on a storage proposal
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageVoteMessage {
    /// Proposal being voted on
    pub proposal_id: [u8; 32],
    /// Validator casting the vote
    pub voter: Hotkey,
    /// Whether the voter approves
    pub approve: bool,
    /// Vote timestamp
    pub timestamp: i64,
    /// Voter's signature
    pub signature: Vec<u8>,
}

// ============================================================================
// Signed Message Wrapper
// ============================================================================

/// Wrapper for signed P2P messages with validation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedP2PMessage {
    /// The inner message
    pub message: P2PMessage,
    /// Signer's hotkey
    pub signer: Hotkey,
    /// Signature over the serialized message
    pub signature: Vec<u8>,
    /// Message nonce for replay protection
    pub nonce: u64,
}

impl SignedP2PMessage {
    /// Get the bytes that were signed
    pub fn signing_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        #[derive(Serialize)]
        struct SigningData<'a> {
            message: &'a P2PMessage,
            nonce: u64,
        }
        bincode::serialize(&SigningData {
            message: &self.message,
            nonce: self.nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2p_message_serialization() {
        let msg = P2PMessage::Heartbeat(HeartbeatMessage {
            validator: Hotkey([1u8; 32]),
            state_hash: [2u8; 32],
            sequence: 100,
            stake: 1_000_000_000_000,
            timestamp: 1234567890,
            signature: vec![0u8; 64],
        });

        let bytes = msg.to_bytes().expect("serialization should work");
        let recovered = P2PMessage::from_bytes(&bytes).expect("deserialization should work");

        assert_eq!(msg.type_name(), recovered.type_name());
    }

    #[test]
    fn test_message_type_names() {
        let proposal = P2PMessage::Proposal(ConsensusProposal {
            view: 1,
            sequence: 1,
            proposal: ProposalContent {
                change_type: StateChangeType::ChallengeSubmission,
                data: vec![],
                data_hash: [0u8; 32],
            },
            proposer: Hotkey([0u8; 32]),
            signature: vec![],
            timestamp: 0,
        });
        assert_eq!(proposal.type_name(), "Proposal");

        let heartbeat = P2PMessage::Heartbeat(HeartbeatMessage {
            validator: Hotkey([0u8; 32]),
            state_hash: [0u8; 32],
            sequence: 0,
            stake: 0,
            timestamp: 0,
            signature: vec![],
        });
        assert_eq!(heartbeat.type_name(), "Heartbeat");
    }

    #[test]
    fn test_state_change_types() {
        assert_eq!(
            StateChangeType::ChallengeSubmission,
            StateChangeType::ChallengeSubmission
        );
        assert_ne!(
            StateChangeType::ChallengeSubmission,
            StateChangeType::WeightUpdate
        );
    }

    #[test]
    fn test_evaluation_metrics() {
        let metrics = EvaluationMetrics {
            primary_score: 0.95,
            secondary_metrics: vec![("accuracy".to_string(), 0.98)],
            execution_time_ms: 5000,
            memory_usage_bytes: Some(1024 * 1024),
            timed_out: false,
            error: None,
        };

        let serialized = bincode::serialize(&metrics).expect("serialize");
        let deserialized: EvaluationMetrics =
            bincode::deserialize(&serialized).expect("deserialize");

        assert!((deserialized.primary_score - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn test_signed_message_signing_bytes() {
        let msg = SignedP2PMessage {
            message: P2PMessage::Heartbeat(HeartbeatMessage {
                validator: Hotkey([1u8; 32]),
                state_hash: [0u8; 32],
                sequence: 1,
                stake: 0,
                timestamp: 0,
                signature: vec![],
            }),
            signer: Hotkey([1u8; 32]),
            signature: vec![],
            nonce: 42,
        };

        let bytes = msg.signing_bytes().expect("should get signing bytes");
        assert!(!bytes.is_empty());
    }
}
