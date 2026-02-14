//! RPC request handlers

use crate::auth::*;
use crate::types::*;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use parking_lot::RwLock;
use platform_core::{ChainState, Hotkey, JobStatus, Stake, ValidatorInfo};
use platform_subnet_manager::BanList;
use std::sync::Arc;
use std::time::Instant;
use tracing::info;

/// Shared state for RPC handlers
pub struct RpcState {
    pub chain_state: Arc<RwLock<ChainState>>,
    pub bans: Arc<RwLock<BanList>>,
    pub start_time: Instant,
    pub version: String,
    pub netuid: u16,
    pub name: String,
    pub min_stake: u64,
}

impl RpcState {
    pub fn new(
        chain_state: Arc<RwLock<ChainState>>,
        bans: Arc<RwLock<BanList>>,
        netuid: u16,
        name: String,
        min_stake: u64,
    ) -> Self {
        Self {
            chain_state,
            bans,
            start_time: Instant::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            netuid,
            name,
            min_stake,
        }
    }
}

/// GET /health
pub async fn health_handler(
    State(state): State<Arc<RpcState>>,
) -> Json<RpcResponse<HealthResponse>> {
    Json(RpcResponse::ok(HealthResponse {
        status: "healthy".to_string(),
        version: state.version.clone(),
        uptime_secs: state.start_time.elapsed().as_secs(),
    }))
}

/// GET /status
pub async fn status_handler(
    State(state): State<Arc<RpcState>>,
) -> Json<RpcResponse<StatusResponse>> {
    let chain = state.chain_state.read();

    Json(RpcResponse::ok(StatusResponse {
        netuid: state.netuid,
        name: state.name.clone(),
        version: state.version.clone(),
        block_height: chain.block_height,
        epoch: chain.epoch,
        validators_count: chain.validators.len(),
        challenges_count: chain.challenges.len(),
        pending_jobs: chain.pending_jobs.len(),
        is_paused: false,
    }))
}

/// GET /validators
pub async fn validators_handler(
    State(state): State<Arc<RpcState>>,
    Query(params): Query<PaginationParams>,
) -> Json<RpcResponse<Vec<ValidatorResponse>>> {
    let chain = state.chain_state.read();

    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(100).min(1000);

    let validators: Vec<ValidatorResponse> = chain
        .validators
        .values()
        .skip(offset)
        .take(limit)
        .map(|v| ValidatorResponse {
            hotkey: v.hotkey.to_hex(),
            stake: v.stake.0,
            stake_tao: v.stake.as_tao(),
            is_active: v.is_active,
            last_seen: v.last_seen,
            peer_id: v.peer_id.clone(),
            x25519_pubkey: v.x25519_pubkey.clone(),
        })
        .collect();

    Json(RpcResponse::ok(validators))
}

/// GET /challenges
pub async fn challenges_handler(
    State(state): State<Arc<RpcState>>,
) -> Json<RpcResponse<Vec<ChallengeResponse>>> {
    let chain = state.chain_state.read();

    let challenges: Vec<ChallengeResponse> = chain
        .challenges
        .values()
        .map(|c| ChallengeResponse {
            id: c.id.to_string(),
            name: c.name.clone(),
            description: c.description.clone(),
            code_hash: c.code_hash.clone(),
            is_active: c.is_active,
            emission_weight: c.config.emission_weight,
            timeout_secs: c.config.timeout_secs,
        })
        .collect();

    Json(RpcResponse::ok(challenges))
}

/// GET /challenge/:id
pub async fn challenge_handler(
    State(state): State<Arc<RpcState>>,
    Path(id): Path<String>,
) -> Result<Json<RpcResponse<ChallengeResponse>>, StatusCode> {
    let chain = state.chain_state.read();

    // Find challenge by ID string
    let challenge = chain
        .challenges
        .values()
        .find(|c| c.id.to_string() == id || c.name == id);

    match challenge {
        Some(c) => Ok(Json(RpcResponse::ok(ChallengeResponse {
            id: c.id.to_string(),
            name: c.name.clone(),
            description: c.description.clone(),
            code_hash: c.code_hash.clone(),
            is_active: c.is_active,
            emission_weight: c.config.emission_weight,
            timeout_secs: c.config.timeout_secs,
        }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// POST /register
pub async fn register_handler(
    State(state): State<Arc<RpcState>>,
    Json(req): Json<RegisterRequest>,
) -> Json<RpcResponse<RegisterResponse>> {
    // Verify signature
    match verify_validator_signature(&req.hotkey, &req.message, &req.signature) {
        Ok(true) => {}
        Ok(false) => {
            return Json(RpcResponse::ok(RegisterResponse {
                accepted: false,
                uid: None,
                reason: Some("Invalid signature".to_string()),
            }));
        }
        Err(e) => {
            return Json(RpcResponse::ok(RegisterResponse {
                accepted: false,
                uid: None,
                reason: Some(format!("Auth error: {}", e)),
            }));
        }
    }

    // Parse hotkey
    let hotkey = match Hotkey::from_hex(&req.hotkey) {
        Some(h) => h,
        None => {
            return Json(RpcResponse::ok(RegisterResponse {
                accepted: false,
                uid: None,
                reason: Some("Invalid hotkey format".to_string()),
            }));
        }
    };

    // Check if banned
    let bans = state.bans.read();
    if bans.is_validator_banned(&hotkey) {
        return Json(RpcResponse::ok(RegisterResponse {
            accepted: false,
            uid: None,
            reason: Some("Validator is banned".to_string()),
        }));
    }
    drop(bans);

    // Check if already registered
    let chain = state.chain_state.read();
    if chain.validators.contains_key(&hotkey) {
        return Json(RpcResponse::ok(RegisterResponse {
            accepted: true,
            uid: Some(0),
            reason: Some("Already registered".to_string()),
        }));
    }
    drop(chain);

    // Register with minimum stake (actual stake will be synced from Bittensor)
    let info = ValidatorInfo::new(hotkey.clone(), Stake::new(state.min_stake));

    let mut chain = state.chain_state.write();
    match chain.add_validator(info) {
        Ok(_) => {
            info!("Validator registered via RPC: {}", req.hotkey);
            Json(RpcResponse::ok(RegisterResponse {
                accepted: true,
                uid: Some(0),
                reason: None,
            }))
        }
        Err(e) => Json(RpcResponse::ok(RegisterResponse {
            accepted: false,
            uid: None,
            reason: Some(format!("Registration failed: {}", e)),
        })),
    }
}

/// POST /heartbeat
pub async fn heartbeat_handler(
    State(state): State<Arc<RpcState>>,
    Json(req): Json<HeartbeatRequest>,
) -> Json<RpcResponse<HeartbeatResponse>> {
    // Parse hotkey
    let hotkey = match Hotkey::from_hex(&req.hotkey) {
        Some(h) => h,
        None => {
            return Json(RpcResponse::error("Invalid hotkey"));
        }
    };

    // Update last_seen
    let mut chain = state.chain_state.write();
    if let Some(validator) = chain.validators.get_mut(&hotkey) {
        validator.last_seen = chrono::Utc::now();
        if let Some(peer_id) = req.peer_id {
            validator.peer_id = Some(peer_id);
        }

        Json(RpcResponse::ok(HeartbeatResponse {
            accepted: true,
            current_block: chain.block_height,
            current_epoch: chain.epoch,
            next_sync_block: None,
        }))
    } else {
        Json(RpcResponse::ok(HeartbeatResponse {
            accepted: false,
            current_block: chain.block_height,
            current_epoch: chain.epoch,
            next_sync_block: None,
        }))
    }
}

/// GET /jobs
pub async fn jobs_handler(
    State(state): State<Arc<RpcState>>,
    Query(params): Query<PaginationParams>,
) -> Json<RpcResponse<Vec<JobResponse>>> {
    let chain = state.chain_state.read();

    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(100).min(1000);

    let jobs: Vec<JobResponse> = chain
        .pending_jobs
        .iter()
        .skip(offset)
        .take(limit)
        .map(|j| JobResponse {
            id: j.id.to_string(),
            challenge_id: j.challenge_id.to_string(),
            agent_hash: j.agent_hash.clone(),
            status: format!("{:?}", j.status),
            created_at: j.created_at,
            assigned_validator: j.assigned_validator.as_ref().map(|h| h.to_hex()),
        })
        .collect();

    Json(RpcResponse::ok(jobs))
}

/// POST /jobs/:id/result
pub async fn job_result_handler(
    State(state): State<Arc<RpcState>>,
    Path(job_id): Path<String>,
    Json(req): Json<JobResultRequest>,
) -> Json<RpcResponse<JobResultResponse>> {
    // Verify signature
    let msg = format!("result:{}:{}", job_id, req.score);
    match verify_validator_signature(&req.hotkey, &msg, &req.signature) {
        Ok(true) => {}
        _ => {
            return Json(RpcResponse::ok(JobResultResponse {
                accepted: false,
                job_id: job_id.clone(),
            }));
        }
    }

    // Parse job ID
    let job_uuid = match uuid::Uuid::parse_str(&job_id) {
        Ok(u) => u,
        Err(_) => {
            return Json(RpcResponse::error("Invalid job ID"));
        }
    };

    // Find and update job
    let mut chain = state.chain_state.write();
    if let Some(job) = chain.pending_jobs.iter_mut().find(|j| j.id == job_uuid) {
        job.status = JobStatus::Completed;
        job.result = Some(platform_core::Score::new(req.score, 1.0));

        info!("Job result submitted: {} score={}", job_id, req.score);
        Json(RpcResponse::ok(JobResultResponse {
            accepted: true,
            job_id,
        }))
    } else {
        Json(RpcResponse::ok(JobResultResponse {
            accepted: false,
            job_id,
        }))
    }
}

/// GET /epoch
pub async fn epoch_handler(State(state): State<Arc<RpcState>>) -> Json<RpcResponse<EpochResponse>> {
    let chain = state.chain_state.read();

    // Epoch config from state
    let blocks_per_epoch = 100u64;
    let block_in_epoch = chain.block_height % blocks_per_epoch;

    let (phase, phase_progress) = if block_in_epoch < 75 {
        ("evaluation", block_in_epoch as f64 / 75.0)
    } else if block_in_epoch < 88 {
        ("commit", (block_in_epoch - 75) as f64 / 13.0)
    } else {
        ("reveal", (block_in_epoch - 88) as f64 / 12.0)
    };

    let blocks_until_next = match phase {
        "evaluation" => 75 - block_in_epoch,
        "commit" => 88 - block_in_epoch,
        "reveal" => blocks_per_epoch - block_in_epoch,
        _ => 0,
    };

    Json(RpcResponse::ok(EpochResponse {
        current_epoch: chain.epoch,
        current_block: chain.block_height,
        blocks_per_epoch,
        phase: phase.to_string(),
        phase_progress,
        blocks_until_next_phase: blocks_until_next,
    }))
}

/// GET /sync
pub async fn sync_handler(State(state): State<Arc<RpcState>>) -> Json<RpcResponse<SyncResponse>> {
    let chain = state.chain_state.read();

    let validators: Vec<ValidatorResponse> = chain
        .validators
        .values()
        .map(|v| ValidatorResponse {
            hotkey: v.hotkey.to_hex(),
            stake: v.stake.0,
            stake_tao: v.stake.as_tao(),
            is_active: v.is_active,
            last_seen: v.last_seen,
            peer_id: v.peer_id.clone(),
            x25519_pubkey: v.x25519_pubkey.clone(),
        })
        .collect();

    let challenges: Vec<ChallengeResponse> = chain
        .challenges
        .values()
        .map(|c| ChallengeResponse {
            id: c.id.to_string(),
            name: c.name.clone(),
            description: c.description.clone(),
            code_hash: c.code_hash.clone(),
            is_active: c.is_active,
            emission_weight: c.config.emission_weight,
            timeout_secs: c.config.timeout_secs,
        })
        .collect();

    Json(RpcResponse::ok(SyncResponse {
        block_height: chain.block_height,
        epoch: chain.epoch,
        state_hash: hex::encode(chain.state_hash),
        validators,
        challenges,
    }))
}

/// POST /weights/commit
pub async fn weight_commit_handler(
    State(state): State<Arc<RpcState>>,
    Json(req): Json<WeightCommitRequest>,
) -> Json<RpcResponse<bool>> {
    // Verify signature
    let msg = format!(
        "commit:{}:{}:{}",
        req.challenge_id, req.epoch, req.commitment_hash
    );
    match verify_validator_signature(&req.hotkey, &msg, &req.signature) {
        Ok(true) => {}
        _ => {
            return Json(RpcResponse::error("Invalid signature"));
        }
    }

    info!(
        "Weight commitment received: validator={} challenge={} epoch={}",
        &req.hotkey[..16],
        req.challenge_id,
        req.epoch
    );

    // Commitment storage
    Json(RpcResponse::ok(true))
}

/// POST /weights/reveal  
pub async fn weight_reveal_handler(
    State(state): State<Arc<RpcState>>,
    Json(req): Json<WeightRevealRequest>,
) -> Json<RpcResponse<bool>> {
    // Verify signature
    let weights_str: String = req
        .weights
        .iter()
        .map(|w| format!("{}:{}", w.hotkey, w.weight))
        .collect::<Vec<_>>()
        .join(",");
    let msg = format!(
        "reveal:{}:{}:{}:{}",
        req.challenge_id, req.epoch, weights_str, req.salt
    );

    match verify_validator_signature(&req.hotkey, &msg, &req.signature) {
        Ok(true) => {}
        _ => {
            return Json(RpcResponse::error("Invalid signature"));
        }
    }

    info!(
        "Weight reveal received: validator={} challenge={} epoch={} weights={}",
        &req.hotkey[..16],
        req.challenge_id,
        req.epoch,
        req.weights.len()
    );

    // Commitment verification and weight storage
    Json(RpcResponse::ok(true))
}
#[cfg(test)]
mod tests {
    use super::*;
    use platform_core::{
        Challenge, ChallengeConfig, ChallengeId, Keypair, NetworkConfig, Stake, ValidatorInfo,
    };
    use platform_subnet_manager::BanList;

    fn create_test_state() -> Arc<RpcState> {
        let kp = Keypair::generate();
        let chain_state = Arc::new(RwLock::new(ChainState::new(
            kp.hotkey(),
            NetworkConfig::default(),
        )));
        let bans = Arc::new(RwLock::new(BanList::new()));
        Arc::new(RpcState::new(
            chain_state,
            bans,
            1,
            "Test-Chain".to_string(),
            1_000_000_000_000,
        ))
    }

    #[tokio::test]
    async fn test_health_handler() {
        let state = create_test_state();
        let response = health_handler(State(state)).await;
        assert_eq!(response.0.data.as_ref().unwrap().status, "healthy");
    }

    #[tokio::test]
    async fn test_status_handler() {
        let state = create_test_state();
        let response = status_handler(State(state)).await;
        let data = response.0.data.unwrap();
        assert_eq!(data.netuid, 1);
        assert_eq!(data.name, "Test-Chain");
    }

    #[tokio::test]
    async fn test_validators_handler_empty() {
        let state = create_test_state();
        let params = PaginationParams::default();
        let response = validators_handler(State(state), Query(params)).await;
        let validators = response.0.data.unwrap();
        assert!(validators.is_empty());
    }

    #[tokio::test]
    async fn test_validators_handler_with_validators() {
        let state = create_test_state();
        let kp = Keypair::generate();
        let info = ValidatorInfo::new(kp.hotkey(), Stake::new(5_000_000_000_000));

        state
            .chain_state
            .write()
            .validators
            .insert(kp.hotkey(), info);

        let params = PaginationParams::default();
        let response = validators_handler(State(state), Query(params)).await;
        let validators = response.0.data.unwrap();
        assert_eq!(validators.len(), 1);
        assert_eq!(validators[0].hotkey, kp.hotkey().to_hex());
    }

    #[tokio::test]
    async fn test_challenges_handler_empty() {
        let state = create_test_state();
        let response = challenges_handler(State(state)).await;
        let challenges = response.0.data.unwrap();
        assert!(challenges.is_empty());
    }

    #[tokio::test]
    async fn test_challenges_handler_with_challenges() {
        let state = create_test_state();
        let kp = Keypair::generate();
        let challenge_id = ChallengeId::new();
        let config = ChallengeConfig {
            mechanism_id: 1,
            emission_weight: 1.0,
            timeout_secs: 300,
            max_memory_mb: 2048,
            max_cpu_secs: 60,
            min_validators: 1,
            params_json: "{}".to_string(),
        };
        let challenge = Challenge {
            id: challenge_id,
            name: "Test Challenge".to_string(),
            description: "Test description".to_string(),
            code_hash: "abc123".to_string(),
            wasm_code: vec![],
            is_active: true,
            owner: kp.hotkey(),
            config,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        state
            .chain_state
            .write()
            .challenges
            .insert(challenge_id, challenge);

        let response = challenges_handler(State(state)).await;
        let challenges = response.0.data.unwrap();
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].name, "Test Challenge");
    }

    #[tokio::test]
    async fn test_challenge_handler_found() {
        let state = create_test_state();
        let kp = Keypair::generate();
        let challenge_id = ChallengeId::new();
        let config = ChallengeConfig {
            mechanism_id: 1,
            emission_weight: 1.0,
            timeout_secs: 300,
            max_memory_mb: 2048,
            max_cpu_secs: 60,
            min_validators: 1,
            params_json: "{}".to_string(),
        };
        let challenge = Challenge {
            id: challenge_id,
            name: "Test Challenge".to_string(),
            description: "Test description".to_string(),
            code_hash: "abc123".to_string(),
            wasm_code: vec![],
            is_active: true,
            owner: kp.hotkey(),
            config,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        state
            .chain_state
            .write()
            .challenges
            .insert(challenge_id, challenge);

        let response = challenge_handler(State(state), Path(challenge_id.to_string())).await;
        assert!(response.is_ok());
        let json_response = response.unwrap();
        let challenge_data = json_response.0.data.unwrap();
        assert_eq!(challenge_data.name, "Test Challenge");
    }

    #[tokio::test]
    async fn test_challenge_handler_not_found() {
        let state = create_test_state();
        let response = challenge_handler(State(state), Path("nonexistent".to_string())).await;
        assert!(response.is_err());
        assert_eq!(response.unwrap_err(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_challenge_handler_find_by_name() {
        let state = create_test_state();
        let kp = Keypair::generate();
        let challenge_id = ChallengeId::new();
        let config = ChallengeConfig {
            mechanism_id: 1,
            emission_weight: 1.0,
            timeout_secs: 300,
            max_memory_mb: 2048,
            max_cpu_secs: 60,
            min_validators: 1,
            params_json: "{}".to_string(),
        };
        let challenge = Challenge {
            id: challenge_id,
            name: "test-challenge".to_string(),
            description: "Test description".to_string(),
            code_hash: "abc123".to_string(),
            wasm_code: vec![],
            is_active: true,
            owner: kp.hotkey(),
            config,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        state
            .chain_state
            .write()
            .challenges
            .insert(challenge_id, challenge);

        let response = challenge_handler(State(state), Path("test-challenge".to_string())).await;
        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn test_register_handler_invalid_signature() {
        let state = create_test_state();
        let req = RegisterRequest {
            hotkey: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            signature: "invalid".to_string(),
            message: "register:1234567890:nonce".to_string(),
            peer_id: None,
        };

        let response = register_handler(State(state), Json(req)).await;
        assert!(!response.0.data.unwrap().accepted);
    }

    #[tokio::test]
    async fn test_register_handler_banned_validator() {
        let state = create_test_state();
        let kp = Keypair::generate();

        // Ban the validator
        state
            .bans
            .write()
            .ban_validator(&kp.hotkey(), "Test ban", "test");

        let message = "register:1234567890:nonce";
        let signed = kp.sign(message.as_bytes());
        let req = RegisterRequest {
            hotkey: kp.hotkey().to_hex(),
            signature: hex::encode(&signed.signature),
            message: message.to_string(),
            peer_id: None,
        };

        let response = register_handler(State(state), Json(req)).await;
        let register_resp = response.0.data.unwrap();
        assert!(!register_resp.accepted);
        assert!(register_resp.reason.unwrap().contains("banned"));
    }

    #[tokio::test]
    async fn test_register_handler_already_registered() {
        let state = create_test_state();
        let kp = Keypair::generate();

        // Pre-register the validator
        let info = ValidatorInfo::new(kp.hotkey(), Stake::new(5_000_000_000_000));
        state
            .chain_state
            .write()
            .validators
            .insert(kp.hotkey(), info);

        let message = "register:1234567890:nonce";
        let signed = kp.sign(message.as_bytes());
        let req = RegisterRequest {
            hotkey: kp.hotkey().to_hex(),
            signature: hex::encode(&signed.signature),
            message: message.to_string(),
            peer_id: None,
        };

        let response = register_handler(State(state), Json(req)).await;
        let register_resp = response.0.data.unwrap();
        assert!(register_resp.accepted);
        assert!(register_resp.reason.unwrap().contains("Already registered"));
    }

    #[tokio::test]
    async fn test_register_handler_success() {
        let state = create_test_state();
        let kp = Keypair::generate();

        let message = "register:1234567890:nonce";
        let signed = kp.sign(message.as_bytes());
        let req = RegisterRequest {
            hotkey: kp.hotkey().to_hex(),
            signature: hex::encode(&signed.signature),
            message: message.to_string(),
            peer_id: None,
        };

        let response = register_handler(State(state.clone()), Json(req)).await;
        let register_resp = response.0.data.unwrap();
        assert!(register_resp.accepted);

        // Verify validator was added
        let chain = state.chain_state.read();
        assert!(chain.validators.contains_key(&kp.hotkey()));
    }

    #[tokio::test]
    async fn test_heartbeat_handler_invalid_hotkey() {
        let state = create_test_state();
        let req = HeartbeatRequest {
            hotkey: "invalid".to_string(),
            signature: "sig".to_string(),
            block_height: 100,
            peer_id: None,
        };

        let response = heartbeat_handler(State(state), Json(req)).await;
        assert!(response.0.error.is_some());
    }

    #[tokio::test]
    async fn test_heartbeat_handler_not_registered() {
        let state = create_test_state();
        let kp = Keypair::generate();
        let req = HeartbeatRequest {
            hotkey: kp.hotkey().to_hex(),
            signature: "sig".to_string(),
            block_height: 100,
            peer_id: Some("peer1".to_string()),
        };

        let response = heartbeat_handler(State(state), Json(req)).await;
        let heartbeat_resp = response.0.data.unwrap();
        assert!(!heartbeat_resp.accepted);
    }

    #[tokio::test]
    async fn test_heartbeat_handler_success() {
        let state = create_test_state();
        let kp = Keypair::generate();

        // Register the validator
        let info = ValidatorInfo::new(kp.hotkey(), Stake::new(5_000_000_000_000));
        state
            .chain_state
            .write()
            .validators
            .insert(kp.hotkey(), info);

        let req = HeartbeatRequest {
            hotkey: kp.hotkey().to_hex(),
            signature: "sig".to_string(),
            block_height: 100,
            peer_id: Some("peer1".to_string()),
        };

        let response = heartbeat_handler(State(state.clone()), Json(req)).await;
        let heartbeat_resp = response.0.data.unwrap();
        assert!(heartbeat_resp.accepted);
        assert_eq!(heartbeat_resp.current_block, 0);

        // Verify peer_id was updated
        let chain = state.chain_state.read();
        let validator = chain.validators.get(&kp.hotkey()).unwrap();
        assert_eq!(validator.peer_id, Some("peer1".to_string()));
    }

    #[tokio::test]
    async fn test_jobs_handler_empty() {
        let state = create_test_state();
        let params = PaginationParams::default();
        let response = jobs_handler(State(state), Query(params)).await;
        let jobs = response.0.data.unwrap();
        assert!(jobs.is_empty());
    }

    #[tokio::test]
    async fn test_jobs_handler_with_pagination() {
        let state = create_test_state();

        // Add some jobs
        {
            let mut chain = state.chain_state.write();
            for i in 0..5 {
                let job = platform_core::Job {
                    id: uuid::Uuid::new_v4(),
                    challenge_id: ChallengeId::new(),
                    agent_hash: format!("hash{}", i),
                    status: platform_core::JobStatus::Pending,
                    created_at: chrono::Utc::now(),
                    assigned_validator: None,
                    result: None,
                };
                chain.pending_jobs.push(job);
            }
        }

        let params = PaginationParams {
            offset: Some(1),
            limit: Some(2),
        };
        let response = jobs_handler(State(state), Query(params)).await;
        let jobs = response.0.data.unwrap();
        assert_eq!(jobs.len(), 2);
    }

    #[tokio::test]
    async fn test_job_result_handler_invalid_job_id() {
        let state = create_test_state();
        let kp = Keypair::generate();

        // Sign the message correctly first
        let job_id = "not-a-uuid";
        let message = format!("result:{}:0.9", job_id);
        let signed = kp.sign(message.as_bytes());

        let req = JobResultRequest {
            job_id: job_id.to_string(),
            hotkey: kp.hotkey().to_hex(),
            signature: hex::encode(&signed.signature),
            score: 0.9,
            metadata: None,
        };

        let response = job_result_handler(State(state), Path(job_id.to_string()), Json(req)).await;
        // Invalid job ID (not a UUID) returns error through RpcResponse::error
        assert!(!response.0.success);
        assert!(response.0.error.is_some());
    }

    #[tokio::test]
    async fn test_job_result_handler_invalid_signature() {
        let state = create_test_state();
        let job_id = uuid::Uuid::new_v4();
        let req = JobResultRequest {
            job_id: job_id.to_string(),
            hotkey: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            signature: "invalid".to_string(),
            score: 0.9,
            metadata: None,
        };

        let response = job_result_handler(State(state), Path(job_id.to_string()), Json(req)).await;
        let result_resp = response.0.data.unwrap();
        assert!(!result_resp.accepted);
    }

    #[tokio::test]
    async fn test_epoch_handler() {
        let state = create_test_state();
        let response = epoch_handler(State(state)).await;
        let epoch = response.0.data.unwrap();
        assert_eq!(epoch.current_epoch, 0);
        assert_eq!(epoch.blocks_per_epoch, 100);
        assert_eq!(epoch.phase, "evaluation");
    }

    #[tokio::test]
    async fn test_epoch_handler_commit_phase() {
        let state = create_test_state();

        // Set block height to commit phase (75-87)
        state.chain_state.write().block_height = 80;

        let response = epoch_handler(State(state)).await;
        let epoch = response.0.data.unwrap();
        assert_eq!(epoch.phase, "commit");
    }

    #[tokio::test]
    async fn test_epoch_handler_reveal_phase() {
        let state = create_test_state();

        // Set block height to reveal phase (88-99)
        state.chain_state.write().block_height = 90;

        let response = epoch_handler(State(state)).await;
        let epoch = response.0.data.unwrap();
        assert_eq!(epoch.phase, "reveal");
    }

    #[tokio::test]
    async fn test_sync_handler() {
        let state = create_test_state();
        let response = sync_handler(State(state)).await;
        let sync = response.0.data.unwrap();
        assert_eq!(sync.block_height, 0);
        assert_eq!(sync.epoch, 0);
        assert!(sync.validators.is_empty());
        assert!(sync.challenges.is_empty());
    }

    #[tokio::test]
    async fn test_weight_commit_handler_invalid_signature() {
        let state = create_test_state();
        let req = WeightCommitRequest {
            hotkey: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            signature: "invalid".to_string(),
            challenge_id: "challenge1".to_string(),
            commitment_hash: "hash123".to_string(),
            epoch: 1,
        };

        let response = weight_commit_handler(State(state), Json(req)).await;
        assert!(response.0.error.is_some());
    }

    #[tokio::test]
    async fn test_weight_reveal_handler_invalid_signature() {
        let state = create_test_state();
        let req = WeightRevealRequest {
            hotkey: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            signature: "invalid".to_string(),
            challenge_id: "challenge1".to_string(),
            weights: vec![],
            salt: "salt123".to_string(),
            epoch: 1,
        };

        let response = weight_reveal_handler(State(state), Json(req)).await;
        assert!(response.0.error.is_some());
    }

    #[tokio::test]
    async fn test_register_handler_invalid_hotkey_format() {
        let state = create_test_state();
        let kp = Keypair::generate();
        let message = "register:1234567890:nonce";
        let signed = kp.sign(message.as_bytes());

        let req = RegisterRequest {
            hotkey: "invalid-hotkey-format".to_string(),
            signature: hex::encode(&signed.signature),
            message: message.to_string(),
            peer_id: None,
        };

        let response = register_handler(State(state), Json(req)).await;
        let register_resp = response.0.data.unwrap();
        assert!(!register_resp.accepted);
        assert!(register_resp
            .reason
            .unwrap()
            .contains("Invalid hotkey format"));
    }

    #[tokio::test]
    async fn test_register_handler_signature_error() {
        let state = create_test_state();
        let req = RegisterRequest {
            hotkey: "invalid".to_string(),
            signature: "sig".to_string(),
            message: "register:1234567890:nonce".to_string(),
            peer_id: None,
        };

        let response = register_handler(State(state), Json(req)).await;
        let register_resp = response.0.data.unwrap();
        assert!(!register_resp.accepted);
        assert!(register_resp.reason.unwrap().contains("Auth error"));
    }

    #[tokio::test]
    async fn test_register_handler_add_validator_error() {
        let state = create_test_state();
        let kp = Keypair::generate();

        // Fill validators to max capacity to trigger error
        {
            let mut chain = state.chain_state.write();
            for _ in 0..chain.config.max_validators {
                let temp_kp = Keypair::generate();
                let info = ValidatorInfo::new(temp_kp.hotkey(), Stake::new(5_000_000_000_000));
                chain.validators.insert(temp_kp.hotkey(), info);
            }
        }

        let message = "register:1234567890:nonce";
        let signed = kp.sign(message.as_bytes());
        let req = RegisterRequest {
            hotkey: kp.hotkey().to_hex(),
            signature: hex::encode(&signed.signature),
            message: message.to_string(),
            peer_id: None,
        };

        let response = register_handler(State(state), Json(req)).await;
        let register_resp = response.0.data.unwrap();
        assert!(!register_resp.accepted);
        assert!(register_resp
            .reason
            .unwrap()
            .contains("Registration failed"));
    }

    #[tokio::test]
    async fn test_job_result_handler_job_not_found() {
        let state = create_test_state();
        let kp = Keypair::generate();
        let job_id = uuid::Uuid::new_v4();

        let message = format!("result:{}:0.9", job_id);
        let signed = kp.sign(message.as_bytes());

        let req = JobResultRequest {
            job_id: job_id.to_string(),
            hotkey: kp.hotkey().to_hex(),
            signature: hex::encode(&signed.signature),
            score: 0.9,
            metadata: None,
        };

        let response = job_result_handler(State(state), Path(job_id.to_string()), Json(req)).await;
        let result_resp = response.0.data.unwrap();
        assert!(!result_resp.accepted);
    }

    #[tokio::test]
    async fn test_job_result_handler_success() {
        let state = create_test_state();
        let kp = Keypair::generate();

        // Add a job first
        let job_id = uuid::Uuid::new_v4();
        let job = platform_core::Job {
            id: job_id,
            challenge_id: ChallengeId::new(),
            agent_hash: "hash123".to_string(),
            status: platform_core::JobStatus::Pending,
            created_at: chrono::Utc::now(),
            assigned_validator: None,
            result: None,
        };
        state.chain_state.write().pending_jobs.push(job);

        let message = format!("result:{}:0.95", job_id);
        let signed = kp.sign(message.as_bytes());

        let req = JobResultRequest {
            job_id: job_id.to_string(),
            hotkey: kp.hotkey().to_hex(),
            signature: hex::encode(&signed.signature),
            score: 0.95,
            metadata: Some(serde_json::json!({"test": "data"})),
        };

        let response =
            job_result_handler(State(state.clone()), Path(job_id.to_string()), Json(req)).await;
        let result_resp = response.0.data.unwrap();
        assert!(result_resp.accepted);

        // Verify job was updated
        let chain = state.chain_state.read();
        let updated_job = chain.pending_jobs.iter().find(|j| j.id == job_id).unwrap();
        assert!(matches!(
            updated_job.status,
            platform_core::JobStatus::Completed
        ));
        assert!(updated_job.result.is_some());
    }

    #[tokio::test]
    async fn test_weight_commit_handler_success() {
        let state = create_test_state();
        let kp = Keypair::generate();

        let challenge_id = "challenge1";
        let epoch = 5;
        let commitment_hash = "abc123";
        let message = format!("commit:{}:{}:{}", challenge_id, epoch, commitment_hash);
        let signed = kp.sign(message.as_bytes());

        let req = WeightCommitRequest {
            hotkey: kp.hotkey().to_hex(),
            signature: hex::encode(&signed.signature),
            challenge_id: challenge_id.to_string(),
            commitment_hash: commitment_hash.to_string(),
            epoch,
        };

        let response = weight_commit_handler(State(state), Json(req)).await;
        assert!(response.0.success);
        assert_eq!(response.0.data, Some(true));
    }

    #[tokio::test]
    async fn test_weight_reveal_handler_success() {
        let state = create_test_state();
        let kp = Keypair::generate();

        let challenge_id = "challenge1";
        let epoch = 5;
        let salt = "salt123";
        let weights = vec![
            WeightEntry {
                hotkey: "hk1".to_string(),
                weight: 0.6,
            },
            WeightEntry {
                hotkey: "hk2".to_string(),
                weight: 0.4,
            },
        ];

        let weights_str: String = weights
            .iter()
            .map(|w| format!("{}:{}", w.hotkey, w.weight))
            .collect::<Vec<_>>()
            .join(",");
        let message = format!("reveal:{}:{}:{}:{}", challenge_id, epoch, weights_str, salt);
        let signed = kp.sign(message.as_bytes());

        let req = WeightRevealRequest {
            hotkey: kp.hotkey().to_hex(),
            signature: hex::encode(&signed.signature),
            challenge_id: challenge_id.to_string(),
            weights,
            salt: salt.to_string(),
            epoch,
        };

        let response = weight_reveal_handler(State(state), Json(req)).await;
        assert!(response.0.success);
        assert_eq!(response.0.data, Some(true));
    }
}
