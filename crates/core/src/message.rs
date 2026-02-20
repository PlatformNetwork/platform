//! Network messages for P2P communication

use crate::{
    BlockHeight, ChainState, Challenge, ChallengeId, Hotkey, Job, NetworkConfig, Result, Score,
    SignedMessage, StateSnapshot, ValidatorInfo,
};
use serde::{Deserialize, Serialize};

/// All network message types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// Handshake when connecting (includes version check)
    Handshake(HandshakeMessage),

    /// Sudo action from subnet owner
    SudoAction(SudoAction),

    /// Proposal for consensus
    Proposal(Proposal),

    /// Vote on a proposal
    Vote(Vote),

    /// Job assignment
    JobAssignment(JobAssignment),

    /// Evaluation result
    EvaluationResult(EvaluationResult),

    /// State synchronization
    StateSync(StateSyncMessage),

    /// Heartbeat/ping
    Heartbeat(HeartbeatMessage),

    /// Weight commitment (commit-reveal phase 1)
    WeightCommitment(WeightCommitmentMessage),

    /// Weight reveal (commit-reveal phase 2)
    WeightReveal(WeightRevealMessage),

    /// Epoch transition notification
    EpochTransition(EpochTransitionMessage),

    /// Agent submission for challenge (P2P propagation) - DEPRECATED
    /// Use ChallengeMessage for new submissions
    AgentSubmission(AgentSubmissionMessage),

    /// Generic challenge P2P message (routes to challenge handlers)
    /// Used for secure submissions, ACKs, evaluations, weights
    ChallengeMessage(ChallengeNetworkMessage),

    /// Real-time task progress update (for evaluation tracking)
    TaskProgress(TaskProgressMessage),

    /// Agent log proposal for consensus validation
    AgentLogProposal(AgentLogProposalMessage),

    /// Version incompatible - disconnect
    VersionMismatch {
        our_version: String,
        required_min_version: String,
    },
}

/// Real-time task progress message
/// Broadcast when each task in an evaluation completes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskProgressMessage {
    /// Challenge ID
    pub challenge_id: String,
    /// Agent being evaluated
    pub agent_hash: String,
    /// Evaluation ID (unique per evaluation run)
    pub evaluation_id: String,
    /// Task ID that completed
    pub task_id: String,
    /// Task index (1-based for display)
    pub task_index: u32,
    /// Total number of tasks
    pub total_tasks: u32,
    /// Whether this task passed
    pub passed: bool,
    /// Task score (0.0 - 1.0)
    pub score: f64,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Cost in USD for this task
    pub cost_usd: f64,
    /// Error message if task failed
    pub error: Option<String>,
    /// Validator performing the evaluation
    pub validator_hotkey: String,
    /// Timestamp
    pub timestamp: u64,
}

impl TaskProgressMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_id: String,
        agent_hash: String,
        evaluation_id: String,
        task_id: String,
        task_index: u32,
        total_tasks: u32,
        passed: bool,
        score: f64,
        execution_time_ms: u64,
        cost_usd: f64,
        error: Option<String>,
        validator_hotkey: String,
    ) -> Self {
        Self {
            challenge_id,
            agent_hash,
            evaluation_id,
            task_id,
            task_index,
            total_tasks,
            passed,
            score,
            execution_time_ms,
            cost_usd,
            error,
            validator_hotkey,
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }
}

/// Agent log proposal message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentLogProposalMessage {
    pub submission_id: String,
    pub challenge_id: String,
    pub miner_hotkey: String,
    pub logs_hash: [u8; 32],
    pub logs_data: Vec<u8>,
    pub validator_hotkey: String,
    pub epoch: u64,
}

/// Challenge-specific network message
/// Contains serialized challenge P2P message that will be routed to the challenge handler
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeNetworkMessage {
    /// Challenge ID (e.g., "term-bench")
    pub challenge_id: String,
    /// Serialized challenge message (challenge-specific format)
    pub payload: Vec<u8>,
    /// Message type hint (for routing without deserializing)
    pub message_type: ChallengeMessageType,
}

/// Type hints for challenge messages
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ChallengeMessageType {
    /// Encrypted submission (commit phase)
    EncryptedSubmission,
    /// Acknowledgment of submission receipt
    SubmissionAck,
    /// Decryption key reveal (reveal phase)
    KeyReveal,
    /// Evaluation result
    EvaluationResult,
    /// Request evaluations
    RequestEvaluations,
    /// Evaluations response
    EvaluationsResponse,
    /// Weight calculation result
    WeightResult,
    /// Distributed storage: write announcement
    StorageWrite,
    /// Distributed storage: request entry
    StorageRequest,
    /// Distributed storage: entry response
    StorageResponse,
    /// Distributed storage: sync request
    StorageSync,
    /// Custom challenge-specific message
    Custom(String),
}

/// Agent submission message for P2P propagation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentSubmissionMessage {
    /// Challenge ID
    pub challenge_id: String,
    /// Agent hash (SHA256 of source code)
    pub agent_hash: String,
    /// Miner hotkey
    pub miner_hotkey: String,
    /// Source code (may be obfuscated for non-top validators)
    pub source_code: Option<String>,
    /// Obfuscated code hash (for validators without source)
    pub obfuscated_hash: Option<String>,
    /// Submission timestamp
    pub submitted_at: chrono::DateTime<chrono::Utc>,
    /// Submitting validator (who received the original submission)
    pub submitting_validator: Hotkey,
    /// Signature from miner
    pub miner_signature: Vec<u8>,
    /// Source code size (for stats)
    pub source_code_len: usize,
}

impl AgentSubmissionMessage {
    /// Create a new agent submission message
    pub fn new(
        challenge_id: String,
        agent_hash: String,
        miner_hotkey: String,
        source_code: Option<String>,
        submitting_validator: Hotkey,
    ) -> Self {
        let source_code_len = source_code.as_ref().map(|s| s.len()).unwrap_or(0);
        Self {
            challenge_id,
            agent_hash,
            miner_hotkey,
            source_code,
            obfuscated_hash: None,
            submitted_at: chrono::Utc::now(),
            submitting_validator,
            miner_signature: vec![],
            source_code_len,
        }
    }
}

/// Handshake message when a node connects
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub hotkey: Hotkey,
    pub block_height: BlockHeight,
    pub state_hash: [u8; 32],
    pub version: String,
    pub version_major: u32,
    pub version_minor: u32,
    pub version_patch: u32,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl HandshakeMessage {
    pub fn new(hotkey: Hotkey, block_height: BlockHeight, state_hash: [u8; 32]) -> Self {
        use crate::constants::{
            PROTOCOL_VERSION, PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
            PROTOCOL_VERSION_PATCH,
        };
        Self {
            hotkey,
            block_height,
            state_hash,
            version: PROTOCOL_VERSION.to_string(),
            version_major: PROTOCOL_VERSION_MAJOR,
            version_minor: PROTOCOL_VERSION_MINOR,
            version_patch: PROTOCOL_VERSION_PATCH,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Check if this handshake is from a compatible version
    pub fn is_compatible(&self) -> bool {
        crate::constants::is_version_compatible(
            self.version_major,
            self.version_minor,
            self.version_patch,
        )
    }
}

/// Sudo actions that only the subnet owner can perform
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SudoAction {
    // === Network Configuration ===
    /// Update network configuration
    UpdateConfig { config: NetworkConfig },

    // === Weight Allocation ===
    /// Set challenge weight ratio on a mechanism (0.0 - 1.0)
    /// Remaining weight goes to UID 0 (burn) unless other challenges share the mechanism
    SetChallengeWeight {
        challenge_id: ChallengeId,
        mechanism_id: u8,
        /// Weight ratio for this challenge (0.0 - 1.0)
        /// If multiple challenges on same mechanism, ratios are normalized
        weight_ratio: f64,
    },

    /// Set mechanism burn rate (weight that goes to UID 0)
    /// Applied after challenge weights are distributed
    SetMechanismBurnRate {
        mechanism_id: u8,
        /// Burn rate (0.0 - 1.0), e.g., 0.1 = 10% to UID 0
        burn_rate: f64,
    },

    /// Configure mechanism weight distribution
    SetMechanismConfig {
        mechanism_id: u8,
        config: MechanismWeightConfig,
    },

    // === Version Management ===
    /// Set required validator version (triggers auto-update)
    SetRequiredVersion {
        min_version: String,
        recommended_version: String,
        mandatory: bool,
        deadline_block: Option<u64>,
        release_notes: Option<String>,
    },

    // === Validator Management ===
    /// Add a validator
    AddValidator { info: ValidatorInfo },

    /// Remove a validator
    RemoveValidator { hotkey: Hotkey },

    // === Emergency Controls ===
    /// Emergency pause
    EmergencyPause { reason: String },

    /// Resume after pause
    Resume,

    /// Force state update (for recovery)
    ForceStateUpdate { state: ChainState },
}

/// Configuration for how weights are distributed on a mechanism
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MechanismWeightConfig {
    /// Mechanism ID on Bittensor
    pub mechanism_id: u8,
    /// Base burn rate - percentage of weights that go to UID 0 (0.0 - 1.0)
    /// Applied before challenge distribution
    pub base_burn_rate: f64,
    /// Whether to distribute remaining weight equally among challenges
    /// If false, uses per-challenge weight_ratio
    pub equal_distribution: bool,
    /// Minimum weight per miner (prevents dust weights)
    pub min_weight_threshold: f64,
    /// Maximum weight cap per miner (DEPRECATED - set to 1.0)
    /// NOTE: Weight caps have been removed. Challenges receive pure weights.
    pub max_weight_cap: f64,
    /// Whether this mechanism is active
    pub active: bool,
}

impl MechanismWeightConfig {
    pub fn new(mechanism_id: u8) -> Self {
        Self {
            mechanism_id,
            base_burn_rate: 0.0,
            equal_distribution: true,
            min_weight_threshold: 0.0001,
            max_weight_cap: 1.0, // No cap - pure weights
            active: true,
        }
    }

    pub fn with_burn_rate(mut self, rate: f64) -> Self {
        self.base_burn_rate = rate.clamp(0.0, 1.0);
        self
    }

    pub fn with_max_cap(mut self, cap: f64) -> Self {
        self.max_weight_cap = cap.clamp(0.0, 1.0);
        self
    }
}

impl Default for MechanismWeightConfig {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Challenge weight allocation on a mechanism
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeWeightAllocation {
    /// Challenge ID
    pub challenge_id: ChallengeId,
    /// Mechanism ID this challenge is on
    pub mechanism_id: u8,
    /// Weight ratio for this challenge (0.0 - 1.0)
    /// If sum of all challenges on mechanism > 1.0, they are normalized
    pub weight_ratio: f64,
    /// Whether this allocation is active
    pub active: bool,
}

impl ChallengeWeightAllocation {
    pub fn new(challenge_id: ChallengeId, mechanism_id: u8, weight_ratio: f64) -> Self {
        Self {
            challenge_id,
            mechanism_id,
            weight_ratio: weight_ratio.clamp(0.0, 1.0),
            active: true,
        }
    }
}

/// Proposal for consensus
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub id: uuid::Uuid,
    pub block_height: BlockHeight,
    pub action: ProposalAction,
    pub proposer: Hotkey,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Proposal {
    pub fn new(action: ProposalAction, proposer: Hotkey, block_height: BlockHeight) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            block_height,
            action,
            proposer,
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Actions that can be proposed for consensus
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum ProposalAction {
    /// Sudo action (only from subnet owner)
    Sudo(SudoAction),

    /// New block
    NewBlock { state_hash: [u8; 32] },

    /// Job completion with result
    JobCompletion {
        job_id: uuid::Uuid,
        result: Score,
        validator: Hotkey,
    },
}

/// Vote on a proposal
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub proposal_id: uuid::Uuid,
    pub voter: Hotkey,
    pub approve: bool,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Vote {
    pub fn approve(proposal_id: uuid::Uuid, voter: Hotkey) -> Self {
        Self {
            proposal_id,
            voter,
            approve: true,
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn reject(proposal_id: uuid::Uuid, voter: Hotkey) -> Self {
        Self {
            proposal_id,
            voter,
            approve: false,
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Job assignment message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobAssignment {
    pub job: Job,
    pub assigned_to: Hotkey,
    pub deadline: chrono::DateTime<chrono::Utc>,
}

/// Evaluation result from a validator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub job_id: uuid::Uuid,
    pub challenge_id: ChallengeId,
    pub agent_hash: String,
    pub score: Score,
    pub execution_time_ms: u64,
    pub validator: Hotkey,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl EvaluationResult {
    pub fn new(
        job_id: uuid::Uuid,
        challenge_id: ChallengeId,
        agent_hash: String,
        score: Score,
        execution_time_ms: u64,
        validator: Hotkey,
    ) -> Self {
        Self {
            job_id,
            challenge_id,
            agent_hash,
            score,
            execution_time_ms,
            validator,
            timestamp: chrono::Utc::now(),
        }
    }
}

/// State synchronization message
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum StateSyncMessage {
    /// Request state snapshot
    RequestSnapshot,

    /// Full state response
    FullState(ChainState),

    /// Snapshot response (lightweight)
    Snapshot(StateSnapshot),

    /// Request specific data
    RequestData { data_type: SyncDataType },

    /// Data response
    DataResponse {
        data_type: SyncDataType,
        data: Vec<u8>,
    },
}

/// Types of data that can be synced
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncDataType {
    Validators,
    Challenges,
    PendingJobs,
    Config,
}

/// Heartbeat message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    pub hotkey: Hotkey,
    pub block_height: BlockHeight,
    pub state_hash: [u8; 32],
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl HeartbeatMessage {
    pub fn new(hotkey: Hotkey, block_height: BlockHeight, state_hash: [u8; 32]) -> Self {
        Self {
            hotkey,
            block_height,
            state_hash,
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Weight commitment message (phase 1 of commit-reveal)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightCommitmentMessage {
    pub validator: Hotkey,
    pub challenge_id: ChallengeId,
    pub epoch: u64,
    pub commitment_hash: [u8; 32],
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl WeightCommitmentMessage {
    pub fn new(
        validator: Hotkey,
        challenge_id: ChallengeId,
        epoch: u64,
        commitment_hash: [u8; 32],
    ) -> Self {
        Self {
            validator,
            challenge_id,
            epoch,
            commitment_hash,
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Weight reveal message (phase 2 of commit-reveal)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightRevealMessage {
    pub validator: Hotkey,
    pub challenge_id: ChallengeId,
    pub epoch: u64,
    pub weights: Vec<WeightEntry>,
    pub secret: Vec<u8>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Single weight entry for an agent
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightEntry {
    pub agent_hash: String,
    pub weight: f64,
}

impl WeightRevealMessage {
    pub fn new(
        validator: Hotkey,
        challenge_id: ChallengeId,
        epoch: u64,
        weights: Vec<WeightEntry>,
        secret: Vec<u8>,
    ) -> Self {
        Self {
            validator,
            challenge_id,
            epoch,
            weights,
            secret,
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Epoch transition notification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochTransitionMessage {
    pub epoch: u64,
    pub phase: String,
    pub block_height: BlockHeight,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl EpochTransitionMessage {
    pub fn new(epoch: u64, phase: &str, block_height: BlockHeight) -> Self {
        Self {
            epoch,
            phase: phase.to_string(),
            block_height,
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Signed network message wrapper
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedNetworkMessage {
    pub message: NetworkMessage,
    pub signature: SignedMessage,
}

impl SignedNetworkMessage {
    /// Create and sign a network message
    pub fn new(message: NetworkMessage, keypair: &crate::Keypair) -> Result<Self> {
        let signed = keypair.sign_data(&message)?;
        Ok(Self {
            message,
            signature: signed,
        })
    }

    /// Verify the message signature
    pub fn verify(&self) -> Result<bool> {
        self.signature.verify()
    }

    /// Get the signer's hotkey
    pub fn signer(&self) -> &Hotkey {
        &self.signature.signer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keypair;

    #[test]
    fn test_signed_message() {
        let kp = Keypair::generate();
        let msg = NetworkMessage::Heartbeat(HeartbeatMessage::new(kp.hotkey(), 100, [0u8; 32]));

        let signed = SignedNetworkMessage::new(msg, &kp).unwrap();
        assert!(signed.verify().unwrap());
        assert_eq!(signed.signer(), &kp.hotkey());
    }

    #[test]
    fn test_proposal() {
        let kp = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [1u8; 32],
            },
            kp.hotkey(),
            100,
        );

        assert_eq!(proposal.proposer, kp.hotkey());
        assert_eq!(proposal.block_height, 100);
    }

    #[test]
    fn test_vote() {
        let kp = Keypair::generate();
        let vote = Vote::approve(uuid::Uuid::new_v4(), kp.hotkey());
        assert!(vote.approve);

        let vote2 = Vote::reject(uuid::Uuid::new_v4(), kp.hotkey());
        assert!(!vote2.approve);
    }

    #[test]
    fn test_heartbeat_message() {
        let hotkey = Hotkey([1u8; 32]);
        let hb = HeartbeatMessage::new(hotkey.clone(), 42, [0xab; 32]);
        assert_eq!(hb.hotkey, hotkey);
        assert_eq!(hb.block_height, 42);
    }

    #[test]
    fn test_network_message_variants() {
        let hotkey = Hotkey([1u8; 32]);

        // Test Heartbeat
        let hb = NetworkMessage::Heartbeat(HeartbeatMessage::new(hotkey.clone(), 1, [0; 32]));
        match hb {
            NetworkMessage::Heartbeat(_) => (),
            _ => panic!("Expected Heartbeat"),
        }

        // Test StateSync
        let sync_msg = NetworkMessage::StateSync(StateSyncMessage::RequestSnapshot);
        match sync_msg {
            NetworkMessage::StateSync(StateSyncMessage::RequestSnapshot) => (),
            _ => panic!("Expected StateSync::RequestSnapshot"),
        }
    }

    #[test]
    fn test_state_sync_message_variants() {
        // Test RequestSnapshot
        let msg = StateSyncMessage::RequestSnapshot;
        match msg {
            StateSyncMessage::RequestSnapshot => (),
            _ => panic!("Expected RequestSnapshot"),
        }

        // Test RequestData
        let msg2 = StateSyncMessage::RequestData {
            data_type: SyncDataType::Validators,
        };
        match msg2 {
            StateSyncMessage::RequestData {
                data_type: SyncDataType::Validators,
            } => (),
            _ => panic!("Expected RequestData::Validators"),
        }
    }

    #[test]
    fn test_sudo_action_variants() {
        // Test EmergencyPause
        let cmd = SudoAction::EmergencyPause {
            reason: "test".to_string(),
        };
        match cmd {
            SudoAction::EmergencyPause { reason } => assert_eq!(reason, "test"),
            _ => panic!("Expected EmergencyPause"),
        }

        // Test Resume
        let cmd2 = SudoAction::Resume;
        match cmd2 {
            SudoAction::Resume => (),
            _ => panic!("Expected Resume"),
        }
    }

    #[test]
    fn test_proposal_action_new_block() {
        let action = ProposalAction::NewBlock {
            state_hash: [0xff; 32],
        };
        match action {
            ProposalAction::NewBlock { state_hash } => {
                assert_eq!(state_hash, [0xff; 32]);
            }
            _ => panic!("Expected NewBlock"),
        }
    }

    #[test]
    fn test_signed_network_message_signer() {
        let kp = Keypair::generate();
        let msg = NetworkMessage::Heartbeat(HeartbeatMessage::new(kp.hotkey(), 1, [0; 32]));
        let signed = SignedNetworkMessage::new(msg, &kp).unwrap();
        assert_eq!(signed.signer(), &kp.hotkey());
    }

    #[test]
    fn test_agent_submission_message() {
        let hotkey = Hotkey([1u8; 32]);
        let msg = AgentSubmissionMessage::new(
            "test-challenge".to_string(),
            "abc123".to_string(),
            "miner123".to_string(),
            Some("print('hello')".to_string()),
            hotkey.clone(),
        );

        assert_eq!(msg.challenge_id, "test-challenge");
        assert_eq!(msg.agent_hash, "abc123");
        assert_eq!(msg.miner_hotkey, "miner123");
        assert!(msg.source_code.is_some());
        assert_eq!(msg.source_code_len, 14);
        assert_eq!(msg.submitting_validator, hotkey);
    }

    #[test]
    fn test_handshake_message() {
        let hotkey = Hotkey([2u8; 32]);
        let hs = HandshakeMessage::new(hotkey.clone(), 100, [0xab; 32]);

        assert_eq!(hs.hotkey, hotkey);
        assert_eq!(hs.block_height, 100);
        assert_eq!(hs.state_hash, [0xab; 32]);
        assert!(!hs.version.is_empty());
        assert!(hs.is_compatible());
    }

    #[test]
    fn test_challenge_message_types() {
        let types = vec![
            ChallengeMessageType::EncryptedSubmission,
            ChallengeMessageType::SubmissionAck,
            ChallengeMessageType::KeyReveal,
            ChallengeMessageType::EvaluationResult,
            ChallengeMessageType::RequestEvaluations,
            ChallengeMessageType::EvaluationsResponse,
            ChallengeMessageType::WeightResult,
            ChallengeMessageType::StorageWrite,
            ChallengeMessageType::StorageRequest,
            ChallengeMessageType::StorageResponse,
            ChallengeMessageType::StorageSync,
            ChallengeMessageType::Custom("test".to_string()),
        ];

        for t in types {
            let msg = ChallengeNetworkMessage {
                challenge_id: "test".to_string(),
                payload: vec![1, 2, 3],
                message_type: t.clone(),
            };
            assert_eq!(msg.challenge_id, "test");
            assert_eq!(msg.payload, vec![1, 2, 3]);
        }
    }

    #[test]
    fn test_sudo_action_set_required_version() {
        let action = SudoAction::SetRequiredVersion {
            min_version: "0.2.0".to_string(),
            recommended_version: "0.3.0".to_string(),
            mandatory: true,
            deadline_block: Some(1000),
            release_notes: Some("Bug fixes".to_string()),
        };

        match action {
            SudoAction::SetRequiredVersion {
                min_version,
                mandatory,
                ..
            } => {
                assert_eq!(min_version, "0.2.0");
                assert!(mandatory);
            }
            _ => panic!("Expected SetRequiredVersion"),
        }
    }

    #[test]
    fn test_sudo_action_add_validator() {
        let hotkey = Hotkey([3u8; 32]);
        let info = ValidatorInfo::new(hotkey.clone(), crate::Stake(1000));
        let action = SudoAction::AddValidator { info: info.clone() };

        match action {
            SudoAction::AddValidator { info: i } => {
                assert_eq!(i.hotkey, hotkey);
            }
            _ => panic!("Expected AddValidator"),
        }
    }

    #[test]
    fn test_sudo_action_remove_validator() {
        let hotkey = Hotkey([4u8; 32]);
        let action = SudoAction::RemoveValidator {
            hotkey: hotkey.clone(),
        };

        match action {
            SudoAction::RemoveValidator { hotkey: h } => {
                assert_eq!(h, hotkey);
            }
            _ => panic!("Expected RemoveValidator"),
        }
    }

    #[test]
    fn test_evaluation_result() {
        let kp = Keypair::generate();
        let job_id = uuid::Uuid::new_v4();
        let challenge_id = ChallengeId::new();
        let score = Score::new(0.85, 1.0);

        let result = EvaluationResult::new(
            job_id,
            challenge_id,
            "agent123".to_string(),
            score,
            100,
            kp.hotkey(),
        );

        assert_eq!(result.job_id, job_id);
        assert_eq!(result.challenge_id, challenge_id);
        assert_eq!(result.score.value, score.value);
        assert_eq!(result.execution_time_ms, 100);
    }

    #[test]
    fn test_weight_commitment_message() {
        let hotkey = Hotkey([5u8; 32]);
        let challenge_id = ChallengeId::new();
        let commitment = WeightCommitmentMessage::new(hotkey.clone(), challenge_id, 10, [0xab; 32]);

        assert_eq!(commitment.validator, hotkey);
        assert_eq!(commitment.challenge_id, challenge_id);
        assert_eq!(commitment.epoch, 10);
        assert_eq!(commitment.commitment_hash, [0xab; 32]);
    }

    #[test]
    fn test_weight_reveal_message() {
        let hotkey = Hotkey([6u8; 32]);
        let challenge_id = ChallengeId::new();
        let weights = vec![
            WeightEntry {
                agent_hash: "agent1".to_string(),
                weight: 0.5,
            },
            WeightEntry {
                agent_hash: "agent2".to_string(),
                weight: 0.3,
            },
        ];
        let reveal =
            WeightRevealMessage::new(hotkey.clone(), challenge_id, 10, weights, vec![1, 2, 3, 4]);

        assert_eq!(reveal.validator, hotkey);
        assert_eq!(reveal.challenge_id, challenge_id);
        assert_eq!(reveal.weights.len(), 2);
        assert_eq!(reveal.epoch, 10);
    }

    #[test]
    fn test_epoch_transition_message() {
        let transition = EpochTransitionMessage::new(10, "commit", 1000);

        assert_eq!(transition.epoch, 10);
        assert_eq!(transition.phase, "commit");
        assert_eq!(transition.block_height, 1000);
    }

    #[test]
    fn test_job_assignment() {
        let job = Job::new(ChallengeId::new(), "abc123".to_string());

        let hotkey = Hotkey([7u8; 32]);
        let assignment = JobAssignment {
            job: job.clone(),
            assigned_to: hotkey.clone(),
            deadline: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        assert_eq!(assignment.job.id, job.id);
        assert_eq!(assignment.assigned_to, hotkey);
    }

    #[test]
    fn test_state_sync_message_all_variants() {
        // Test all SyncDataType variants
        let data_types = vec![
            SyncDataType::Validators,
            SyncDataType::Challenges,
            SyncDataType::PendingJobs,
            SyncDataType::Config,
        ];

        for dt in data_types {
            let msg = StateSyncMessage::RequestData {
                data_type: dt.clone(),
            };
            match msg {
                StateSyncMessage::RequestData { data_type } => {
                    assert_eq!(data_type, dt);
                }
                _ => panic!("Expected RequestData"),
            }
        }
    }

    #[test]
    fn test_network_message_serialization() {
        let hotkey = Hotkey([8u8; 32]);
        let msg = NetworkMessage::Heartbeat(HeartbeatMessage::new(hotkey, 100, [0; 32]));

        // Test serialization
        let serialized = bincode::serialize(&msg).unwrap();
        assert!(!serialized.is_empty());

        // Test deserialization
        let deserialized: NetworkMessage = bincode::deserialize(&serialized).unwrap();
        match deserialized {
            NetworkMessage::Heartbeat(hb) => {
                assert_eq!(hb.block_height, 100);
            }
            _ => panic!("Expected Heartbeat"),
        }
    }

    #[test]
    fn test_challenge_network_message() {
        let msg = ChallengeNetworkMessage {
            challenge_id: "term-bench".to_string(),
            payload: vec![1, 2, 3, 4, 5],
            message_type: ChallengeMessageType::EvaluationResult,
        };

        assert_eq!(msg.challenge_id, "term-bench");
        assert_eq!(msg.payload.len(), 5);
        assert_eq!(msg.message_type, ChallengeMessageType::EvaluationResult);
    }

    #[test]
    fn test_proposal_action_variants() {
        // Test Sudo action
        let sudo = SudoAction::EmergencyPause {
            reason: "test".to_string(),
        };
        let action = ProposalAction::Sudo(sudo);
        match action {
            ProposalAction::Sudo(SudoAction::EmergencyPause { reason }) => {
                assert_eq!(reason, "test");
            }
            _ => panic!("Expected Sudo"),
        }

        // Test NewBlock action
        let action = ProposalAction::NewBlock {
            state_hash: [0xab; 32],
        };
        match action {
            ProposalAction::NewBlock { state_hash } => {
                assert_eq!(state_hash, [0xab; 32]);
            }
            _ => panic!("Expected NewBlock"),
        }

        // Test JobCompletion action
        let job_id = uuid::Uuid::new_v4();
        let hotkey = Hotkey([10u8; 32]);
        let score = Score::new(0.95, 1.0);
        let action = ProposalAction::JobCompletion {
            job_id,
            result: score,
            validator: hotkey.clone(),
        };
        match action {
            ProposalAction::JobCompletion {
                job_id: jid,
                result,
                validator,
            } => {
                assert_eq!(jid, job_id);
                assert_eq!(result.value, score.value);
                assert_eq!(validator, hotkey);
            }
            _ => panic!("Expected JobCompletion"),
        }
    }

    #[test]
    fn test_sudo_action_update_config() {
        let config = NetworkConfig::default();
        let action = SudoAction::UpdateConfig {
            config: config.clone(),
        };
        match action {
            SudoAction::UpdateConfig { config: c } => {
                assert_eq!(c.subnet_id, config.subnet_id);
            }
            _ => panic!("Expected UpdateConfig"),
        }
    }

    #[test]
    fn test_sudo_action_force_state_update() {
        let kp = Keypair::generate();
        let state = ChainState::new(kp.hotkey(), NetworkConfig::default());
        let action = SudoAction::ForceStateUpdate {
            state: state.clone(),
        };
        match action {
            SudoAction::ForceStateUpdate { state: s } => {
                assert_eq!(s.block_height, state.block_height);
            }
            _ => panic!("Expected ForceStateUpdate"),
        }
    }

    #[test]
    fn test_state_sync_snapshot() {
        let snapshot = StateSnapshot {
            block_height: 100,
            state_hash: [0xab; 32],
            validator_count: 5,
            challenge_count: 2,
            pending_jobs: 10,
            timestamp: chrono::Utc::now(),
        };
        let msg = StateSyncMessage::Snapshot(snapshot.clone());
        match msg {
            StateSyncMessage::Snapshot(s) => {
                assert_eq!(s.block_height, 100);
                assert_eq!(s.validator_count, 5);
            }
            _ => panic!("Expected Snapshot"),
        }
    }

    #[test]
    fn test_version_mismatch_message() {
        let msg = NetworkMessage::VersionMismatch {
            our_version: "0.1.0".to_string(),
            required_min_version: "0.2.0".to_string(),
        };
        match msg {
            NetworkMessage::VersionMismatch {
                our_version,
                required_min_version,
            } => {
                assert_eq!(our_version, "0.1.0");
                assert_eq!(required_min_version, "0.2.0");
            }
            _ => panic!("Expected VersionMismatch"),
        }
    }

    #[test]
    fn test_all_network_message_variants() {
        let hotkey = Hotkey([1u8; 32]);

        // Handshake
        let _ = NetworkMessage::Handshake(HandshakeMessage::new(hotkey.clone(), 1, [0; 32]));

        // SudoAction
        let _ = NetworkMessage::SudoAction(SudoAction::Resume);

        // Proposal
        let _ = NetworkMessage::Proposal(Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0; 32],
            },
            hotkey.clone(),
            1,
        ));

        // Vote
        let _ = NetworkMessage::Vote(Vote::approve(uuid::Uuid::new_v4(), hotkey.clone()));

        // JobAssignment
        let job = Job::new(ChallengeId::new(), "test".to_string());
        let _ = NetworkMessage::JobAssignment(JobAssignment {
            job,
            assigned_to: hotkey.clone(),
            deadline: chrono::Utc::now(),
        });

        // EvaluationResult
        let _ = NetworkMessage::EvaluationResult(EvaluationResult::new(
            uuid::Uuid::new_v4(),
            ChallengeId::new(),
            "hash".to_string(),
            crate::Score::new(0.5, 1.0),
            100,
            hotkey.clone(),
        ));

        // StateSync
        let _ = NetworkMessage::StateSync(StateSyncMessage::RequestSnapshot);

        // Heartbeat
        let _ = NetworkMessage::Heartbeat(HeartbeatMessage::new(hotkey.clone(), 1, [0; 32]));

        // WeightCommitment
        let _ = NetworkMessage::WeightCommitment(WeightCommitmentMessage::new(
            hotkey.clone(),
            ChallengeId::new(),
            1,
            [0; 32],
        ));

        // WeightReveal
        let _ = NetworkMessage::WeightReveal(WeightRevealMessage::new(
            hotkey.clone(),
            ChallengeId::new(),
            1,
            vec![],
            vec![1, 2, 3],
        ));

        // EpochTransition
        let _ = NetworkMessage::EpochTransition(EpochTransitionMessage::new(1, "commit", 100));

        // AgentSubmission
        let _ = NetworkMessage::AgentSubmission(AgentSubmissionMessage::new(
            "test".to_string(),
            "hash".to_string(),
            "miner".to_string(),
            None,
            hotkey.clone(),
        ));

        // ChallengeMessage
        let _ = NetworkMessage::ChallengeMessage(ChallengeNetworkMessage {
            challenge_id: "test".to_string(),
            payload: vec![],
            message_type: ChallengeMessageType::EvaluationResult,
        });

        // TaskProgress (already covered above via TaskProgress variant)

        // AgentLogProposal
        let _ = NetworkMessage::AgentLogProposal(AgentLogProposalMessage {
            submission_id: "sub-1".to_string(),
            challenge_id: "challenge-1".to_string(),
            miner_hotkey: "miner-1".to_string(),
            logs_hash: [0u8; 32],
            logs_data: vec![1, 2, 3],
            validator_hotkey: "validator-1".to_string(),
            epoch: 1,
        });

        // VersionMismatch
        let _ = NetworkMessage::VersionMismatch {
            our_version: "0.1.0".to_string(),
            required_min_version: "0.2.0".to_string(),
        };
    }

    // =========================================================================
    // Task Progress & Mechanism Weight Tests
    // =========================================================================

    #[test]
    fn test_task_progress_message_new() {
        let msg = TaskProgressMessage::new(
            "test-challenge".to_string(),
            "agent-hash".to_string(),
            "eval-123".to_string(),
            "task-1".to_string(),
            1,
            10,
            true,
            0.95,
            1500,
            0.002,
            None,
            "validator-key".to_string(),
        );
        assert_eq!(msg.challenge_id, "test-challenge");
        assert_eq!(msg.task_index, 1);
        assert_eq!(msg.total_tasks, 10);
        assert!(msg.passed);
        assert_eq!(msg.score, 0.95);
        assert!(msg.timestamp > 0);
    }

    #[test]
    fn test_mechanism_weight_config_new() {
        let config = MechanismWeightConfig::new(5);
        assert_eq!(config.mechanism_id, 5);
        assert_eq!(config.base_burn_rate, 0.0);
        assert!(config.equal_distribution);
        assert!(config.active);
    }

    #[test]
    fn test_mechanism_weight_config_with_burn_rate() {
        let config = MechanismWeightConfig::new(1).with_burn_rate(0.15);
        assert_eq!(config.base_burn_rate, 0.15);
    }

    #[test]
    fn test_mechanism_weight_config_with_max_cap() {
        let config = MechanismWeightConfig::new(1).with_max_cap(0.8);
        assert_eq!(config.max_weight_cap, 0.8);
    }

    #[test]
    fn test_challenge_weight_allocation_new() {
        let challenge_id = ChallengeId::new();
        let allocation = ChallengeWeightAllocation::new(challenge_id, 1, 0.7);
        assert_eq!(allocation.challenge_id, challenge_id);
        assert_eq!(allocation.mechanism_id, 1);
        assert_eq!(allocation.weight_ratio, 0.7);
        assert!(allocation.active);
    }

    #[test]
    fn test_mechanism_weight_config_default() {
        let config = MechanismWeightConfig::default();
        assert_eq!(config.mechanism_id, 0);
        assert_eq!(config.base_burn_rate, 0.0);
        assert!(config.equal_distribution);
        assert!(config.active);
    }
}
