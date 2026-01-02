//! Data models for Platform Server

use serde::{Deserialize, Serialize};

// ============================================================================
// VALIDATOR
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub hotkey: String,
    pub stake: u64,
    pub last_seen: Option<i64>,
    pub is_active: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRegistration {
    pub hotkey: String,
    pub stake: u64,
    pub signature: String,
    pub timestamp: i64,
}

// ============================================================================
// SUBMISSION
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Submission {
    pub id: String,
    pub agent_hash: String,
    pub miner_hotkey: String,
    pub source_code: Option<String>,
    pub source_hash: String,
    pub name: Option<String>,
    pub version: String,
    pub epoch: u64,
    pub status: SubmissionStatus,
    /// API key for LLM inferences (stored securely)
    pub api_key: Option<String>,
    /// API provider (openrouter, chutes, openai, anthropic, grok)
    pub api_provider: Option<String>,
    /// Total cost accumulated for this submission (USD)
    pub total_cost_usd: Option<f64>,
    /// Deprecated: use api_key instead
    pub api_keys_encrypted: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionStatus {
    Pending,
    Evaluating,
    Completed,
    Failed,
    Rejected,
}

impl ToString for SubmissionStatus {
    fn to_string(&self) -> String {
        match self {
            SubmissionStatus::Pending => "pending".to_string(),
            SubmissionStatus::Evaluating => "evaluating".to_string(),
            SubmissionStatus::Completed => "completed".to_string(),
            SubmissionStatus::Failed => "failed".to_string(),
            SubmissionStatus::Rejected => "rejected".to_string(),
        }
    }
}

impl From<&str> for SubmissionStatus {
    fn from(s: &str) -> Self {
        match s {
            "pending" => SubmissionStatus::Pending,
            "evaluating" => SubmissionStatus::Evaluating,
            "completed" => SubmissionStatus::Completed,
            "failed" => SubmissionStatus::Failed,
            "rejected" => SubmissionStatus::Rejected,
            _ => SubmissionStatus::Pending,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitAgentRequest {
    pub source_code: String,
    pub miner_hotkey: String,
    pub signature: String,
    pub name: Option<String>,
    /// API key for LLM inferences (plaintext - server handles securely)
    pub api_key: Option<String>,
    /// API provider: openrouter, chutes, openai, anthropic, grok
    pub api_provider: Option<String>,
    /// Deprecated: use api_key instead
    pub api_keys_encrypted: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitAgentResponse {
    pub success: bool,
    pub submission_id: Option<String>,
    pub agent_hash: Option<String>,
    pub error: Option<String>,
}

// ============================================================================
// EVALUATION
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evaluation {
    pub id: String,
    pub submission_id: String,
    pub agent_hash: String,
    pub validator_hotkey: String,
    pub score: f64,
    pub tasks_passed: u32,
    pub tasks_total: u32,
    pub tasks_failed: u32,
    pub total_cost_usd: f64,
    pub execution_time_ms: Option<i64>,
    pub task_results: Option<String>,
    pub execution_log: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitEvaluationRequest {
    pub submission_id: String,
    pub agent_hash: String,
    pub validator_hotkey: String,
    pub signature: String,
    pub score: f64,
    pub tasks_passed: u32,
    pub tasks_total: u32,
    pub tasks_failed: u32,
    pub total_cost_usd: f64,
    pub execution_time_ms: Option<i64>,
    pub task_results: Option<serde_json::Value>,
    pub execution_log: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub passed: bool,
    pub score: f64,
    pub execution_time_ms: i64,
    pub cost_usd: f64,
    pub error: Option<String>,
}

// ============================================================================
// LEADERBOARD
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderboardEntry {
    pub agent_hash: String,
    pub miner_hotkey: String,
    pub name: Option<String>,
    pub consensus_score: f64,
    pub evaluation_count: u32,
    pub rank: u32,
    pub first_epoch: u64,
    pub last_epoch: u64,
    pub best_rank: Option<u32>,
    pub total_rewards: f64,
    pub updated_at: i64,
}

// ============================================================================
// CHALLENGE CONFIG
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeConfig {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    /// Mechanism ID for Bittensor (each challenge = one mechanism)
    pub mechanism_id: u8,
    /// Emission weight for this challenge (0.0 - 1.0)
    /// Remaining weight (1.0 - emission_weight) goes to UID 0 (burn)
    pub emission_weight: f64,
    /// Challenge version (for updates)
    pub version: String,
    /// Challenge status (active, paused, deprecated)
    pub status: ChallengeStatus,
    pub max_agents_per_epoch: f64,
    pub min_stake: u64,
    pub module_whitelist: Option<Vec<String>>,
    pub model_whitelist: Option<Vec<String>>,
    pub pricing_config: Option<PricingConfig>,
    pub evaluation_config: Option<EvaluationConfig>,
    pub updated_at: i64,
    pub updated_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Active,
    Paused,
    Deprecated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingConfig {
    pub max_cost_per_task: f64,
    pub max_total_cost: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationConfig {
    pub max_tasks: u32,
    pub timeout_seconds: u32,
    pub max_steps_per_task: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfigRequest {
    pub owner_hotkey: String,
    pub signature: String,
    pub config: serde_json::Value,
}

// ============================================================================
// TASK LEASE (Claim/Lease Anti-Duplication Mechanism)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskLease {
    pub task_id: String,
    pub validator_hotkey: String,
    pub claimed_at: i64,
    pub expires_at: i64,
    pub status: TaskLeaseStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TaskLeaseStatus {
    Active,
    Completed,
    Failed,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimTaskRequest {
    pub task_id: String,
    pub validator_hotkey: String,
    pub signature: String,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimTaskResponse {
    pub success: bool,
    pub lease: Option<TaskLease>,
    pub error: Option<String>,
}

// ============================================================================
// WEBSOCKET EVENTS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum WsEvent {
    #[serde(rename = "submission_received")]
    SubmissionReceived(SubmissionEvent),

    #[serde(rename = "evaluation_complete")]
    EvaluationComplete(EvaluationEvent),

    #[serde(rename = "leaderboard_updated")]
    LeaderboardUpdated(LeaderboardUpdateEvent),

    #[serde(rename = "challenge_updated")]
    ChallengeUpdated(ChallengeUpdateEvent),

    #[serde(rename = "challenge_registered")]
    ChallengeRegistered(ChallengeRegisteredEvent),

    #[serde(rename = "challenge_started")]
    ChallengeStarted(ChallengeStartedEvent),

    #[serde(rename = "challenge_stopped")]
    ChallengeStopped(ChallengeStoppedEvent),

    #[serde(rename = "validator_joined")]
    ValidatorJoined(ValidatorEvent),

    #[serde(rename = "validator_left")]
    ValidatorLeft(ValidatorEvent),

    #[serde(rename = "network_state")]
    NetworkState(NetworkStateEvent),

    #[serde(rename = "task_claimed")]
    TaskClaimed(TaskClaimedEvent),

    #[serde(rename = "job_assigned")]
    JobAssigned(JobAssignedEvent),

    /// Custom challenge event - each challenge can define its own event types
    /// Validators filter by challenge_id to receive only relevant events
    #[serde(rename = "challenge_event")]
    ChallengeEvent(ChallengeCustomEvent),

    #[serde(rename = "job_progress")]
    JobProgress(JobProgressEvent),

    #[serde(rename = "job_completed")]
    JobCompleted(JobCompletedEvent),

    #[serde(rename = "ping")]
    Ping,

    #[serde(rename = "pong")]
    Pong,
}

// ============================================================================
// EVALUATION JOB QUEUE
// ============================================================================

/// Evaluation job to be assigned to validators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationJob {
    pub id: String,
    pub submission_id: String,
    pub agent_hash: String,
    pub miner_hotkey: String,
    pub source_code: String,
    pub api_key: Option<String>,
    pub api_provider: Option<String>,
    pub challenge_id: String,
    pub created_at: i64,
    pub status: JobStatus,
    pub assigned_validator: Option<String>,
    pub assigned_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Assigned,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobAssignedEvent {
    pub job_id: String,
    pub submission_id: String,
    pub agent_hash: String,
    pub validator_hotkey: String,
    pub challenge_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobProgressEvent {
    pub job_id: String,
    pub validator_hotkey: String,
    pub task_index: u32,
    pub task_total: u32,
    pub task_id: String,
    pub status: TaskProgressStatus,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TaskProgressStatus {
    Started,
    Running,
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobCompletedEvent {
    pub job_id: String,
    pub validator_hotkey: String,
    pub submission_id: String,
    pub agent_hash: String,
    pub score: f64,
    pub tasks_passed: u32,
    pub tasks_total: u32,
    pub total_cost_usd: f64,
    pub execution_time_ms: u64,
    pub task_results: Vec<TaskResultSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResultSummary {
    pub task_id: String,
    pub passed: bool,
    pub score: f64,
    pub cost_usd: f64,
    pub execution_time_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionEvent {
    pub submission_id: String,
    pub agent_hash: String,
    pub miner_hotkey: String,
    pub name: Option<String>,
    pub epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationEvent {
    pub submission_id: String,
    pub agent_hash: String,
    pub validator_hotkey: String,
    pub score: f64,
    pub tasks_passed: u32,
    pub tasks_total: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderboardUpdateEvent {
    pub agent_hash: String,
    pub new_rank: u32,
    pub old_rank: Option<u32>,
    pub consensus_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeUpdateEvent {
    pub field: String,
    pub old_value: Option<String>,
    pub new_value: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRegisteredEvent {
    pub id: String,
    pub name: String,
    pub docker_image: String,
    pub mechanism_id: u8,
    pub emission_weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeStartedEvent {
    pub id: String,
    pub endpoint: String,
    pub docker_image: String,
    pub mechanism_id: u8,
    pub emission_weight: f64,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_cpu")]
    pub cpu_cores: f64,
    #[serde(default = "default_memory")]
    pub memory_mb: u64,
    #[serde(default)]
    pub gpu_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeStoppedEvent {
    pub id: String,
}

/// Custom event from a challenge - allows challenges to broadcast their own events
/// Validators subscribe and filter by challenge_id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeCustomEvent {
    /// Challenge identifier (e.g., "term-challenge")
    pub challenge_id: String,
    /// Event name within the challenge (e.g., "new_submission", "evaluation_needed")
    pub event_name: String,
    /// Event payload as JSON - challenge-specific data
    pub payload: serde_json::Value,
    /// Timestamp when event was created
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorEvent {
    pub hotkey: String,
    pub stake: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStateEvent {
    pub current_epoch: u64,
    pub current_block: u64,
    pub total_stake: u64,
    pub active_validators: u32,
    pub pending_submissions: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskClaimedEvent {
    pub task_id: String,
    pub validator_hotkey: String,
    pub expires_at: i64,
}

// ============================================================================
// AUTH
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub hotkey: String,
    pub timestamp: i64,
    pub signature: String,
    pub role: AuthRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthRole {
    Validator,
    Miner,
    Owner,
    Challenge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub success: bool,
    pub token: Option<String>,
    pub expires_at: Option<i64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub hotkey: String,
    pub role: AuthRole,
    pub expires_at: i64,
}

// ============================================================================
// DATA API - Snapshot for /get_weights
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightSnapshot {
    pub epoch: u64,
    pub weights: Vec<WeightEntry>,
    pub snapshot_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightEntry {
    pub hotkey: String,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteResultRequest {
    pub agent_hash: String,
    pub validator_hotkey: String,
    pub signature: String,
    pub score: f64,
    pub task_results: Option<serde_json::Value>,
    pub execution_time_ms: Option<i64>,
}

// ============================================================================
// REGISTERED CHALLENGES (Dynamic Orchestration)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredChallenge {
    pub id: String,
    pub name: String,
    pub docker_image: String,
    pub mechanism_id: u8,
    pub emission_weight: f64,
    pub timeout_secs: u64,
    pub cpu_cores: f64,
    pub memory_mb: u64,
    pub gpu_required: bool,
    pub status: String,
    pub endpoint: Option<String>,
    pub container_id: Option<String>,
    pub last_health_check: Option<i64>,
    pub is_healthy: bool,
}

impl RegisteredChallenge {
    pub fn new(id: &str, name: &str, docker_image: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            docker_image: docker_image.to_string(),
            mechanism_id: 1,
            emission_weight: 0.1,
            timeout_secs: 3600,
            cpu_cores: 2.0,
            memory_mb: 4096,
            gpu_required: false,
            status: "active".to_string(),
            endpoint: None,
            container_id: None,
            last_health_check: None,
            is_healthy: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterChallengeRequest {
    pub id: String,
    pub name: String,
    pub docker_image: String,
    #[serde(default = "default_mechanism_id")]
    pub mechanism_id: u8,
    #[serde(default = "default_emission_weight")]
    pub emission_weight: f64,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_cpu")]
    pub cpu_cores: f64,
    #[serde(default = "default_memory")]
    pub memory_mb: u64,
    #[serde(default)]
    pub gpu_required: bool,
    pub owner_hotkey: String,
    pub signature: String,
}

fn default_mechanism_id() -> u8 {
    1
}
fn default_emission_weight() -> f64 {
    0.1
}
fn default_timeout() -> u64 {
    3600
}
fn default_cpu() -> f64 {
    2.0
}
fn default_memory() -> u64 {
    4096
}

/// Request to start/stop a challenge (requires owner signature)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeActionRequest {
    pub owner_hotkey: String,
    pub signature: String,
    pub timestamp: i64,
}
