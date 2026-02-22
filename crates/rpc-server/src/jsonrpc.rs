//! Substrate-style JSON-RPC 2.0 Server
//!
//! Complete JSON-RPC API for Mini-Chain.
//!
//! # Namespaces
//!
//! ## system_* - System information
//! - system_health        - Health check
//! - system_version       - Get version info
//! - system_name          - Get chain name
//! - system_properties    - Get chain properties
//! - system_peers         - Get connected peers
//! - system_networkState  - Get network state
//!
//! ## chain_* - Chain data
//! - chain_getHead            - Get latest block header
//! - chain_getBlock           - Get block by number
//! - chain_getBlockHash       - Get block hash by number
//! - chain_getFinalizedHead   - Get finalized block
//!
//! ## state_* - State queries
//! - state_getStorage         - Get storage by key
//! - state_getKeys            - Get storage keys with prefix
//! - state_getMetadata        - Get runtime metadata
//! - state_getRuntimeVersion  - Get runtime version
//!
//! ## author_* - Authoring (transactions)
//! - author_submitExtrinsic   - Submit a transaction
//! - author_pendingExtrinsics - Get pending transactions
//!
//! ## validator_* - Validator queries
//! - validator_list           - List all validators
//! - validator_get            - Get validator by hotkey
//! - validator_count          - Get validator count
//!
//! ## challenge_* - Challenge management
//! - challenge_list           - List all challenges
//! - challenge_get            - Get challenge by ID/name
//! - challenge_getRoutes      - Get routes for a challenge
//! - challenge_listAllRoutes  - List all challenge routes
//! - challenge_call           - Call a challenge route
//!
//! ## job_* - Job management
//! - job_list                 - List pending jobs
//! - job_get                  - Get job by ID
//! - job_submit               - Submit a job
//!
//! ## epoch_* - Epoch information
//! - epoch_current            - Get current epoch info
//! - epoch_getPhase           - Get current phase

use parking_lot::RwLock;
use platform_challenge_sdk::{
    ChallengeRoute, RouteRequest, RouteResponse as ChallengeRouteResponse,
};
use platform_core::ChainState;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};

/// Handler for challenge routes
pub type ChallengeRouteHandler = Arc<
    dyn Fn(
            String,
            RouteRequest,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = ChallengeRouteResponse> + Send>>
        + Send
        + Sync,
>;

/// JSON-RPC 2.0 Request
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    pub id: Value,
}

/// JSON-RPC 2.0 Response
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Value,
}

/// JSON-RPC 2.0 Error
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    pub fn result(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }

    pub fn error_with_data(id: Value, code: i32, message: impl Into<String>, data: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: Some(data),
            }),
            id,
        }
    }
}

// Standard JSON-RPC error codes
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

// Custom error codes
pub const CHALLENGE_NOT_FOUND: i32 = -32000;
pub const VALIDATOR_NOT_FOUND: i32 = -32001;
pub const JOB_NOT_FOUND: i32 = -32002;
pub const ROUTE_NOT_FOUND: i32 = -32003;
pub const INSUFFICIENT_STAKE: i32 = -32004;
pub const UNAUTHORIZED: i32 = -32005;

/// Registered challenge route info
#[derive(Clone, Debug, Serialize)]
pub struct RegisteredChallengeRoute {
    pub challenge_id: String,
    pub challenge_name: String,
    pub route: ChallengeRouteInfo,
}

/// Simplified route info for serialization
#[derive(Clone, Debug, Serialize)]
pub struct ChallengeRouteInfo {
    pub method: String,
    pub path: String,
    pub full_path: String,
    pub description: String,
    pub requires_auth: bool,
    pub rate_limit: u32,
}

/// RPC Handler State
pub struct RpcHandler {
    pub chain_state: Arc<RwLock<ChainState>>,
    pub start_time: Instant,
    pub version: String,
    pub netuid: u16,
    pub chain_name: String,
    pub peers: Arc<RwLock<Vec<String>>>,
    /// Registered challenge routes: challenge_id -> routes
    pub challenge_routes: Arc<RwLock<HashMap<String, Vec<ChallengeRoute>>>>,
    /// Challenge route handler callback
    pub route_handler: Arc<RwLock<Option<ChallengeRouteHandler>>>,
    /// Channel to send signed messages for P2P broadcast
    pub broadcast_tx: Arc<RwLock<Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>>,
    /// Keypair for signing P2P messages (optional, set by validator)
    pub keypair: Arc<RwLock<Option<platform_core::Keypair>>>,
}

impl RpcHandler {
    pub fn new(chain_state: Arc<RwLock<ChainState>>, netuid: u16) -> Self {
        Self {
            chain_state,
            start_time: Instant::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            netuid,
            chain_name: format!("MiniChain-{}", netuid),
            peers: Arc::new(RwLock::new(Vec::new())),
            challenge_routes: Arc::new(RwLock::new(HashMap::new())),
            route_handler: Arc::new(RwLock::new(None)),
            broadcast_tx: Arc::new(RwLock::new(None)),
            keypair: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the keypair for signing P2P messages
    pub fn set_keypair(&self, keypair: platform_core::Keypair) {
        *self.keypair.write() = Some(keypair);
    }

    /// Set the broadcast channel for P2P message sending
    pub fn set_broadcast_tx(&self, tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>) {
        *self.broadcast_tx.write() = Some(tx);
    }

    /// Normalize challenge name: lowercase, replace spaces with dashes, remove special chars
    pub fn normalize_challenge_name(name: &str) -> String {
        name.trim()
            .to_lowercase()
            .replace([' ', '_'], "-")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .collect::<String>()
            .trim_matches('-')
            .to_string()
    }

    /// Register routes for a challenge
    pub fn register_challenge_routes(&self, challenge_id: &str, routes: Vec<ChallengeRoute>) {
        if routes.is_empty() {
            return;
        }
        info!(
            "Registering {} routes for challenge {}",
            routes.len(),
            challenge_id
        );
        for route in &routes {
            debug!(
                "  {} {}: {}",
                route.method.as_str(),
                route.path,
                route.description
            );
        }
        self.challenge_routes
            .write()
            .insert(challenge_id.to_string(), routes);
    }

    /// Unregister routes for a challenge
    pub fn unregister_challenge_routes(&self, challenge_id: &str) {
        self.challenge_routes.write().remove(challenge_id);
    }

    /// Set the route handler callback
    pub fn set_route_handler(&self, handler: ChallengeRouteHandler) {
        *self.route_handler.write() = Some(handler);
    }

    /// Get all registered challenge routes
    pub fn get_all_challenge_routes(&self) -> Vec<RegisteredChallengeRoute> {
        let routes = self.challenge_routes.read();
        let chain = self.chain_state.read();

        let mut result = Vec::new();
        for (challenge_id, challenge_routes) in routes.iter() {
            let challenge_name = chain
                .challenges
                .values()
                .find(|c| c.id.to_string() == *challenge_id)
                .map(|c| c.name.clone())
                .unwrap_or_else(|| challenge_id.clone());

            for route in challenge_routes {
                result.push(RegisteredChallengeRoute {
                    challenge_id: challenge_id.clone(),
                    challenge_name: challenge_name.clone(),
                    route: ChallengeRouteInfo {
                        method: route.method.as_str().to_string(),
                        path: route.path.clone(),
                        full_path: format!("/challenge/{}{}", challenge_id, route.path),
                        description: route.description.clone(),
                        requires_auth: route.requires_auth,
                        rate_limit: route.rate_limit,
                    },
                });
            }
        }
        result
    }

    /// Handle a JSON-RPC request
    pub fn handle(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        debug!("RPC: {}", req.method);

        // Route to appropriate handler based on namespace
        let parts: Vec<&str> = req.method.splitn(2, '_').collect();

        match parts.as_slice() {
            // System namespace
            ["system", "health"] => self.system_health(req.id),
            ["system", "version"] => self.system_version(req.id),
            ["system", "name"] => self.system_name(req.id),
            ["system", "properties"] => self.system_properties(req.id),
            ["system", "peers"] => self.system_peers(req.id),
            ["system", "networkState"] => self.system_network_state(req.id),

            // Chain namespace
            ["chain", "getHead"] => self.chain_get_head(req.id),
            ["chain", "getBlock"] => self.chain_get_block(req.id, req.params),
            ["chain", "getBlockHash"] => self.chain_get_block_hash(req.id, req.params),
            ["chain", "getFinalizedHead"] => self.chain_get_finalized_head(req.id),
            ["chain", "getState"] => self.chain_get_state(req.id),

            // State namespace
            ["state", "getStorage"] => self.state_get_storage(req.id, req.params),
            ["state", "getKeys"] => self.state_get_keys(req.id, req.params),
            ["state", "getMetadata"] => self.state_get_metadata(req.id),
            ["state", "getRuntimeVersion"] => self.state_get_runtime_version(req.id),

            // Validator namespace
            ["validator", "list"] => self.validator_list(req.id, req.params),
            ["validator", "get"] => self.validator_get(req.id, req.params),
            ["validator", "count"] => self.validator_count(req.id),

            // Metagraph namespace
            ["metagraph", "hotkeys"] => self.metagraph_hotkeys(req.id),
            ["metagraph", "isRegistered"] => self.metagraph_is_registered(req.id, req.params),

            // Challenge namespace
            ["challenge", "list"] => self.challenge_list(req.id, req.params),
            ["challenge", "get"] => self.challenge_get(req.id, req.params),
            ["challenge", "getRoutes"] => self.challenge_get_routes(req.id, req.params),
            ["challenge", "listAllRoutes"] => self.challenge_list_all_routes(req.id),
            // challenge_call is handled asynchronously via handle_async()
            ["challenge", "call"] => JsonRpcResponse::error(
                req.id,
                INTERNAL_ERROR,
                "challenge_call must be invoked via handle_async()",
            ),

            // Job namespace
            ["job", "list"] => self.job_list(req.id, req.params),
            ["job", "get"] => self.job_get(req.id, req.params),

            // Epoch namespace
            ["epoch", "current"] => self.epoch_current(req.id),
            ["epoch", "getPhase"] => self.epoch_get_phase(req.id),

            // Leaderboard namespace
            ["leaderboard", "get"] => self.leaderboard_get(req.id, req.params),

            // Evaluation namespace
            ["evaluation", "getProgress"] => self.evaluation_get_progress(req.id, req.params),
            ["evaluation", "getLogs"] => self.evaluation_get_logs(req.id, req.params),

            // Agent namespace
            ["agent", "getCode"] => self.agent_get_code(req.id, req.params),
            ["agent", "getLogs"] => self.agent_get_logs(req.id, req.params),

            // RPC info
            ["rpc", "methods"] => self.rpc_methods(req.id),

            // Sudo namespace (for subnet owner actions)
            ["sudo", "submit"] => self.sudo_submit(req.id, req.params),

            _ => {
                warn!("Unknown RPC method: {}", req.method);
                JsonRpcResponse::error(
                    req.id,
                    METHOD_NOT_FOUND,
                    format!(
                        "Method not found: {}. Use rpc_methods to list available methods.",
                        req.method
                    ),
                )
            }
        }
    }

    // ==================== RPC Info ====================

    fn rpc_methods(&self, id: Value) -> JsonRpcResponse {
        JsonRpcResponse::result(
            id,
            json!({
                "version": 1,
                "methods": [
                    // System
                    "system_health", "system_version", "system_name",
                    "system_properties", "system_peers", "system_networkState",
                    // Chain
                    "chain_getHead", "chain_getBlock", "chain_getBlockHash",
                    "chain_getFinalizedHead", "chain_getState",
                    // State
                    "state_getStorage", "state_getKeys", "state_getMetadata",
                    "state_getRuntimeVersion",
                    // Validator
                    "validator_list", "validator_get", "validator_count",
                    // Challenge
                    "challenge_list", "challenge_get", "challenge_getRoutes",
                    "challenge_listAllRoutes", "challenge_call",
                    // Job
                    "job_list", "job_get",
                    // Epoch
                    "epoch_current", "epoch_getPhase",
                    // Leaderboard
                    "leaderboard_get",
                    // Evaluation
                    "evaluation_getProgress", "evaluation_getLogs",
                    // Agent
                    "agent_getCode", "agent_getLogs",
                    // RPC
                    "rpc_methods",
                    // Monitor
                ]
            }),
        )
    }

    // ==================== System Namespace ====================

    fn system_health(&self, id: Value) -> JsonRpcResponse {
        let chain = self.chain_state.read();
        let peers_count = self.peers.read().len();

        JsonRpcResponse::result(
            id,
            json!({
                "isSyncing": false,
                "peers": peers_count,
                "shouldHavePeers": true,
                "health": if peers_count > 0 || !chain.validators.is_empty() { "healthy" } else { "degraded" }
            }),
        )
    }

    fn system_version(&self, id: Value) -> JsonRpcResponse {
        JsonRpcResponse::result(id, json!(self.version))
    }

    fn system_name(&self, id: Value) -> JsonRpcResponse {
        JsonRpcResponse::result(id, json!(self.chain_name))
    }

    fn system_properties(&self, id: Value) -> JsonRpcResponse {
        let chain = self.chain_state.read();
        JsonRpcResponse::result(
            id,
            json!({
                "netuid": self.netuid,
                "tokenSymbol": "TAO",
                "tokenDecimals": 9,
                "ss58Format": 42,
                "minStake": chain.config.min_stake.0,
                "minStakeTao": chain.config.min_stake.as_tao(),
                "consensusThreshold": chain.config.consensus_threshold,
                "blockTimeMs": chain.config.block_time_ms,
            }),
        )
    }

    fn system_peers(&self, id: Value) -> JsonRpcResponse {
        let peers = self.peers.read();
        JsonRpcResponse::result(id, json!(peers.clone()))
    }

    fn system_network_state(&self, id: Value) -> JsonRpcResponse {
        let chain = self.chain_state.read();
        let peers = self.peers.read();

        JsonRpcResponse::result(
            id,
            json!({
                "peerId": null,
                "listenedAddresses": [],
                "connectedPeers": peers.len(),
                "notConnectedPeers": [],
                "averagePing": null,
                "validators": chain.validators.len(),
            }),
        )
    }

    // ==================== Chain Namespace ====================

    fn chain_get_head(&self, id: Value) -> JsonRpcResponse {
        let chain = self.chain_state.read();
        JsonRpcResponse::result(
            id,
            json!({
                "number": chain.block_height,
                "hash": format!("0x{}", hex::encode(&chain.state_hash)),
                "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "stateRoot": format!("0x{}", hex::encode(&chain.state_hash)),
                "extrinsicsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
            }),
        )
    }

    fn chain_get_block(&self, id: Value, params: Value) -> JsonRpcResponse {
        let block_num = self.get_param_u64(&params, 0, "number");
        let chain = self.chain_state.read();

        // For now, only current block is available
        if block_num.map(|n| n == chain.block_height).unwrap_or(true) {
            JsonRpcResponse::result(
                id,
                json!({
                    "block": {
                        "header": {
                            "number": chain.block_height,
                            "hash": format!("0x{}", hex::encode(&chain.state_hash)),
                            "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                            "stateRoot": format!("0x{}", hex::encode(&chain.state_hash)),
                        },
                        "extrinsics": []
                    },
                    "justifications": null
                }),
            )
        } else {
            JsonRpcResponse::error(
                id,
                INVALID_PARAMS,
                "Block not found (only current block available)",
            )
        }
    }

    fn chain_get_block_hash(&self, id: Value, params: Value) -> JsonRpcResponse {
        let block_num = self.get_param_u64(&params, 0, "number");
        let chain = self.chain_state.read();

        if block_num.map(|n| n == chain.block_height).unwrap_or(true) {
            JsonRpcResponse::result(id, json!(format!("0x{}", hex::encode(&chain.state_hash))))
        } else {
            JsonRpcResponse::result(id, Value::Null)
        }
    }

    fn chain_get_finalized_head(&self, id: Value) -> JsonRpcResponse {
        let chain = self.chain_state.read();
        JsonRpcResponse::result(id, json!(format!("0x{}", hex::encode(&chain.state_hash))))
    }

    fn chain_get_state(&self, id: Value) -> JsonRpcResponse {
        let chain = self.chain_state.read();

        // Serialize mechanism_configs
        let mechanism_configs: serde_json::Map<String, Value> = chain
            .mechanism_configs
            .iter()
            .map(|(id, config)| {
                (
                    id.to_string(),
                    json!({
                        "mechanism_id": config.mechanism_id,
                        "base_burn_rate": config.base_burn_rate,
                        "equal_distribution": config.equal_distribution,
                        "min_weight_threshold": config.min_weight_threshold,
                        "max_weight_cap": config.max_weight_cap,
                        "is_active": config.active,
                    }),
                )
            })
            .collect();

        // Serialize challenge_weights
        let challenge_weights: serde_json::Map<String, Value> = chain
            .challenge_weights
            .iter()
            .map(|(id, alloc)| {
                (
                    id.to_string(),
                    json!({
                        "challenge_id": id.to_string(),
                        "mechanism_id": alloc.mechanism_id,
                        "weight_ratio": alloc.weight_ratio,
                        "active": alloc.active,
                    }),
                )
            })
            .collect();

        // Serialize validators
        let validators: serde_json::Map<String, Value> = chain
            .validators
            .iter()
            .map(|(hotkey, info)| {
                (
                    hotkey.to_hex(),
                    json!({
                        "hotkey": hotkey.to_hex(),
                        "stake": info.stake.0,
                        "stake_tao": info.stake.as_tao(),
                    }),
                )
            })
            .collect();

        JsonRpcResponse::result(
            id,
            json!({
                "blockHeight": chain.block_height,
                "epoch": chain.epoch,
                "stateHash": format!("0x{}", hex::encode(&chain.state_hash)),
                "sudoKey": chain.sudo_key.to_hex(),
                "validators": validators,
                "challenges": chain.challenges.len(),
                "mechanism_configs": mechanism_configs,
                "challenge_weights": challenge_weights,
                "pendingJobs": chain.pending_jobs.len(),
                "config": {
                    "subnetId": chain.config.subnet_id,
                    "minStake": chain.config.min_stake.0,
                    "minStakeTao": chain.config.min_stake.as_tao(),
                    "consensusThreshold": chain.config.consensus_threshold,
                    "blockTimeMs": chain.config.block_time_ms,
                    "maxValidators": chain.config.max_validators,
                }
            }),
        )
    }

    // ==================== State Namespace ====================

    fn state_get_storage(&self, id: Value, params: Value) -> JsonRpcResponse {
        let key = self.get_param_str(&params, 0, "key");

        let key = match key {
            Some(k) => k,
            None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing 'key' parameter"),
        };

        let chain = self.chain_state.read();

        let result = match key.as_str() {
            "blockHeight" => json!(chain.block_height),
            "epoch" => json!(chain.epoch),
            "stateHash" => json!(format!("0x{}", hex::encode(&chain.state_hash))),
            "sudoKey" => json!(chain.sudo_key.to_hex()),
            "validatorCount" => json!(chain.validators.len()),
            "challengeCount" => json!(chain.challenges.len()),
            "jobCount" => json!(chain.pending_jobs.len()),
            k if k.starts_with("validator:") => {
                let hotkey = &k[10..];
                if let Some(hk) = platform_core::Hotkey::from_hex(hotkey) {
                    if let Some(v) = chain.validators.get(&hk) {
                        json!({
                            "hotkey": v.hotkey.to_hex(),
                            "stake": v.stake.0,
                            "stakeTao": v.stake.as_tao(),
                            "isActive": v.is_active,
                            "lastSeen": v.last_seen.to_rfc3339(),
                            "peerId": v.peer_id,
                        })
                    } else {
                        Value::Null
                    }
                } else {
                    return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid hotkey format");
                }
            }
            k if k.starts_with("challenge:") => {
                let challenge_id = &k[10..];
                let challenge = chain
                    .challenges
                    .values()
                    .find(|c| c.id.to_string() == challenge_id || c.name == challenge_id);

                if let Some(c) = challenge {
                    json!({
                        "id": c.id.to_string(),
                        "name": c.name,
                        "description": c.description,
                        "codeHash": c.code_hash,
                        "isActive": c.is_active,
                        "mechanismId": c.config.mechanism_id,
                        "emissionWeight": c.config.emission_weight,
                        "timeoutSecs": c.config.timeout_secs,
                    })
                } else {
                    Value::Null
                }
            }
            _ => {
                return JsonRpcResponse::error(
                    id,
                    INVALID_PARAMS,
                    format!("Unknown storage key: {}. Available: blockHeight, epoch, stateHash, sudoKey, validatorCount, challengeCount, jobCount, validator:<hotkey>, challenge:<id>", key),
                );
            }
        };

        JsonRpcResponse::result(id, result)
    }

    fn state_get_keys(&self, id: Value, params: Value) -> JsonRpcResponse {
        let prefix = self.get_param_str(&params, 0, "prefix").unwrap_or_default();
        let chain = self.chain_state.read();

        let mut keys = vec![
            "blockHeight",
            "epoch",
            "stateHash",
            "sudoKey",
            "validatorCount",
            "challengeCount",
            "jobCount",
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();

        // Add validator keys
        for v in chain.validators.keys() {
            keys.push(format!("validator:{}", v.to_hex()));
        }

        // Add challenge keys
        for c in chain.challenges.values() {
            keys.push(format!("challenge:{}", c.id));
            keys.push(format!("challenge:{}", c.name));
        }

        // Filter by prefix
        let filtered: Vec<_> = keys
            .into_iter()
            .filter(|k| k.starts_with(&prefix))
            .collect();

        JsonRpcResponse::result(id, json!(filtered))
    }

    fn state_get_metadata(&self, id: Value) -> JsonRpcResponse {
        let chain = self.chain_state.read();
        let routes = self.challenge_routes.read();

        JsonRpcResponse::result(
            id,
            json!({
                "version": self.version,
                "pallets": [
                    {
                        "name": "System",
                        "storage": ["blockHeight", "epoch", "stateHash"]
                    },
                    {
                        "name": "Validators",
                        "storage": ["validatorCount"],
                        "calls": ["validator_list", "validator_get"]
                    },
                    {
                        "name": "Challenges",
                        "storage": ["challengeCount"],
                        "calls": ["challenge_list", "challenge_get", "challenge_getRoutes"]
                    },
                    {
                        "name": "Jobs",
                        "storage": ["jobCount"],
                        "calls": ["job_list", "job_get"]
                    }
                ],
                "extrinsics": [],
                "constants": {
                    "netuid": self.netuid,
                    "minStake": chain.config.min_stake.0,
                },
                "challengeRoutes": routes.len(),
            }),
        )
    }

    fn state_get_runtime_version(&self, id: Value) -> JsonRpcResponse {
        JsonRpcResponse::result(
            id,
            json!({
                "specName": "platform",
                "implName": "platform-node",
                "specVersion": 1,
                "implVersion": 1,
                "apis": [
                    ["system", 1],
                    ["chain", 1],
                    ["state", 1],
                    ["validator", 1],
                    ["challenge", 1],
                    ["job", 1],
                    ["epoch", 1],
                ],
            }),
        )
    }

    // ==================== Validator Namespace ====================

    fn validator_list(&self, id: Value, params: Value) -> JsonRpcResponse {
        let chain = self.chain_state.read();
        let offset = self.get_param_u64(&params, 0, "offset").unwrap_or(0) as usize;
        let limit = self
            .get_param_u64(&params, 1, "limit")
            .unwrap_or(100)
            .min(1000) as usize;

        let validators: Vec<Value> = chain
            .validators
            .values()
            .skip(offset)
            .take(limit)
            .map(|v| {
                json!({
                    "hotkey": v.hotkey.to_hex(),
                    "stake": v.stake.0,
                    "stakeTao": v.stake.as_tao(),
                    "isActive": v.is_active,
                    "lastSeen": v.last_seen.to_rfc3339(),
                    "peerId": v.peer_id,
                })
            })
            .collect();

        JsonRpcResponse::result(
            id,
            json!({
                "total": chain.validators.len(),
                "offset": offset,
                "limit": limit,
                "validators": validators,
            }),
        )
    }

    fn validator_get(&self, id: Value, params: Value) -> JsonRpcResponse {
        let hotkey = match self.get_param_str(&params, 0, "hotkey") {
            Some(h) => h,
            None => {
                return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing 'hotkey' parameter")
            }
        };

        let hk = match platform_core::Hotkey::from_hex(&hotkey) {
            Some(h) => h,
            None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid hotkey format"),
        };

        let chain = self.chain_state.read();

        match chain.validators.get(&hk) {
            Some(v) => JsonRpcResponse::result(
                id,
                json!({
                    "hotkey": v.hotkey.to_hex(),
                    "stake": v.stake.0,
                    "stakeTao": v.stake.as_tao(),
                    "isActive": v.is_active,
                    "lastSeen": v.last_seen.to_rfc3339(),
                    "peerId": v.peer_id,
                }),
            ),
            None => JsonRpcResponse::error(id, VALIDATOR_NOT_FOUND, "Validator not found"),
        }
    }

    fn validator_count(&self, id: Value) -> JsonRpcResponse {
        let chain = self.chain_state.read();
        JsonRpcResponse::result(id, json!(chain.validators.len()))
    }

    // ==================== Metagraph Namespace ====================

    /// Get all registered hotkeys from metagraph (miners + validators)
    fn metagraph_hotkeys(&self, id: Value) -> JsonRpcResponse {
        let chain = self.chain_state.read();
        let hotkeys: Vec<String> = chain
            .registered_hotkeys
            .iter()
            .map(|h| h.to_hex())
            .collect();

        JsonRpcResponse::result(
            id,
            json!({
                "count": hotkeys.len(),
                "hotkeys": hotkeys,
            }),
        )
    }

    /// Check if a hotkey is registered in the metagraph
    fn metagraph_is_registered(&self, id: Value, params: Value) -> JsonRpcResponse {
        let hotkey = match self.get_param_str(&params, 0, "hotkey") {
            Some(h) => h,
            None => {
                return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing 'hotkey' parameter")
            }
        };

        let hk = match platform_core::Hotkey::from_hex(&hotkey) {
            Some(h) => h,
            None => {
                // Try SS58 format
                match platform_core::Hotkey::from_ss58(&hotkey) {
                    Some(h) => h,
                    None => {
                        return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid hotkey format")
                    }
                }
            }
        };

        let chain = self.chain_state.read();
        let is_registered = chain.registered_hotkeys.contains(&hk);

        JsonRpcResponse::result(
            id,
            json!({
                "hotkey": hotkey,
                "isRegistered": is_registered,
            }),
        )
    }

    // ==================== Challenge Namespace ====================

    fn challenge_list(&self, id: Value, params: Value) -> JsonRpcResponse {
        let chain = self.chain_state.read();
        let only_active = self.get_param_bool(&params, "onlyActive").unwrap_or(false);

        // Get WASM challenges only
        let challenges: Vec<Value> = chain
            .wasm_challenge_configs
            .values()
            .filter(|c| !only_active || c.is_active)
            .map(|c| {
                // Read routes from ChainState
                let routes_count = chain
                    .challenge_routes
                    .get(&c.challenge_id)
                    .map(|r| r.len())
                    .unwrap_or(0);

                json!({
                    "id": c.challenge_id.to_string(),
                    "name": c.name,
                    "description": c.description,
                    "codeHash": c.module.code_hash,
                    "isActive": c.is_active,
                    "owner": c.owner.to_hex(),
                    "version": c.module.version,
                    "routesCount": routes_count,
                })
            })
            .collect();

        JsonRpcResponse::result(
            id,
            json!({
                "total": challenges.len(),
                "challenges": challenges,
            }),
        )
    }

    fn challenge_get(&self, id: Value, params: Value) -> JsonRpcResponse {
        let challenge_id = match self.get_param_str(&params, 0, "id") {
            Some(c) => c,
            None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing 'id' parameter"),
        };

        let chain = self.chain_state.read();
        let routes = self.challenge_routes.read();

        let challenge = chain
            .challenges
            .values()
            .find(|c| c.id.to_string() == challenge_id || c.name == challenge_id);

        match challenge {
            Some(c) => {
                let challenge_routes: Vec<Value> = routes
                    .get(&c.id.to_string())
                    .map(|rs| {
                        rs.iter()
                            .map(|r| {
                                json!({
                                    "method": r.method.as_str(),
                                    "path": r.path,
                                    "fullPath": format!("/challenge/{}{}", c.id, r.path),
                                    "description": r.description,
                                    "requiresAuth": r.requires_auth,
                                    "rateLimit": r.rate_limit,
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                JsonRpcResponse::result(
                    id,
                    json!({
                        "id": c.id.to_string(),
                        "name": c.name,
                        "description": c.description,
                        "codeHash": c.code_hash,
                        "codeSize": c.wasm_code.len(),
                        "isActive": c.is_active,
                        "owner": c.owner.to_hex(),
                        "mechanismId": c.config.mechanism_id,
                        "emissionWeight": c.config.emission_weight,
                        "timeoutSecs": c.config.timeout_secs,
                        "createdAt": c.created_at.to_rfc3339(),
                        "routes": challenge_routes,
                    }),
                )
            }
            None => JsonRpcResponse::error(
                id,
                CHALLENGE_NOT_FOUND,
                format!("Challenge '{}' not found", challenge_id),
            ),
        }
    }

    fn challenge_get_routes(&self, id: Value, params: Value) -> JsonRpcResponse {
        let challenge_id = match self.get_param_str(&params, 0, "id") {
            Some(c) => c,
            None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing 'id' parameter"),
        };

        let routes = self.challenge_routes.read();
        let chain = self.chain_state.read();

        // Find actual challenge ID (might be name)
        let actual_id = chain
            .challenges
            .values()
            .find(|c| c.id.to_string() == challenge_id || c.name == challenge_id)
            .map(|c| c.id.to_string())
            .unwrap_or_else(|| challenge_id.clone());

        match routes.get(&actual_id) {
            Some(challenge_routes) => {
                let routes_json: Vec<Value> = challenge_routes
                    .iter()
                    .map(|r| {
                        json!({
                            "method": r.method.as_str(),
                            "path": r.path,
                            "fullPath": format!("/challenge/{}{}", actual_id, r.path),
                            "description": r.description,
                            "requiresAuth": r.requires_auth,
                            "rateLimit": r.rate_limit,
                        })
                    })
                    .collect();

                JsonRpcResponse::result(
                    id,
                    json!({
                        "challengeId": actual_id,
                        "routesCount": routes_json.len(),
                        "routes": routes_json,
                    }),
                )
            }
            None => JsonRpcResponse::result(
                id,
                json!({
                    "challengeId": actual_id,
                    "routesCount": 0,
                    "routes": [],
                }),
            ),
        }
    }

    fn challenge_list_all_routes(&self, id: Value) -> JsonRpcResponse {
        let all_routes = self.get_all_challenge_routes();

        let routes_json: Vec<Value> = all_routes
            .iter()
            .map(|r| {
                json!({
                    "challengeId": r.challenge_id,
                    "challengeName": r.challenge_name,
                    "method": r.route.method,
                    "path": r.route.path,
                    "fullPath": r.route.full_path,
                    "description": r.route.description,
                    "requiresAuth": r.route.requires_auth,
                })
            })
            .collect();

        JsonRpcResponse::result(
            id,
            json!({
                "total": routes_json.len(),
                "routes": routes_json,
            }),
        )
    }

    // ==================== Async Handler ====================

    /// Handle a JSON-RPC request, supporting both sync and async methods.
    ///
    /// Methods like `challenge_call` require async execution (the route handler
    /// callback is async). This method handles those asynchronously and delegates
    /// all other methods to the synchronous [`handle()`](Self::handle).
    pub async fn handle_async(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let parts: Vec<&str> = req.method.splitn(2, '_').collect();
        match parts.as_slice() {
            ["challenge", "call"] => self.challenge_call(req.id, req.params).await,
            _ => self.handle(req),
        }
    }

    /// Call a challenge route handler
    async fn challenge_call(&self, id: Value, params: Value) -> JsonRpcResponse {
        let challenge_id = match self.get_param_str(&params, 0, "challengeId") {
            Some(c) => c,
            None => {
                return JsonRpcResponse::error(
                    id,
                    INVALID_PARAMS,
                    "Missing 'challengeId' parameter",
                )
            }
        };

        let method = self
            .get_param_str(&params, 1, "method")
            .unwrap_or_else(|| "GET".to_string());

        let path = self
            .get_param_str(&params, 2, "path")
            .unwrap_or_else(|| "/".to_string());

        let body = params
            .get("body")
            .or_else(|| params.get(3))
            .cloned()
            .unwrap_or(Value::Null);

        let query: std::collections::HashMap<String, String> = params
            .get("query")
            .or_else(|| params.get(4))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        // Verify the challenge has registered routes
        {
            let routes = self.challenge_routes.read();
            if !routes.contains_key(&challenge_id) {
                // Try to find by name
                let chain = self.chain_state.read();
                let found = chain.challenges.values().any(|c| c.name == challenge_id);
                if !found {
                    return JsonRpcResponse::error(
                        id,
                        CHALLENGE_NOT_FOUND,
                        format!("Challenge '{}' not found or has no routes", challenge_id),
                    );
                }
            }
        }

        let request = RouteRequest {
            method,
            path,
            params: std::collections::HashMap::new(),
            query,
            headers: std::collections::HashMap::new(),
            body,
            auth_hotkey: None,
        };

        let maybe_handler = self.route_handler.read().clone();
        match maybe_handler {
            Some(handler) => {
                let response = handler(challenge_id.clone(), request).await;
                JsonRpcResponse::result(
                    id,
                    json!({
                        "challengeId": challenge_id,
                        "status": response.status,
                        "headers": response.headers,
                        "body": response.body,
                    }),
                )
            }
            None => JsonRpcResponse::error(
                id,
                INTERNAL_ERROR,
                "No route handler registered. Challenge route handlers are not configured.",
            ),
        }
    }

    // ==================== Job Namespace ====================

    fn job_list(&self, id: Value, params: Value) -> JsonRpcResponse {
        let chain = self.chain_state.read();
        let offset = self.get_param_u64(&params, 0, "offset").unwrap_or(0) as usize;
        let limit = self
            .get_param_u64(&params, 1, "limit")
            .unwrap_or(100)
            .min(1000) as usize;
        let status_filter = self.get_param_str(&params, 2, "status");

        let jobs: Vec<Value> = chain
            .pending_jobs
            .iter()
            .filter(|j| {
                status_filter
                    .as_ref()
                    .map(|s| format!("{:?}", j.status).to_lowercase() == s.to_lowercase())
                    .unwrap_or(true)
            })
            .skip(offset)
            .take(limit)
            .map(|j| {
                json!({
                    "id": j.id.to_string(),
                    "challengeId": j.challenge_id.to_string(),
                    "agentHash": j.agent_hash,
                    "status": format!("{:?}", j.status),
                    "createdAt": j.created_at.to_rfc3339(),
                    "assignedValidator": j.assigned_validator.as_ref().map(|h| h.to_hex()),
                })
            })
            .collect();

        JsonRpcResponse::result(
            id,
            json!({
                "total": chain.pending_jobs.len(),
                "offset": offset,
                "limit": limit,
                "jobs": jobs,
            }),
        )
    }

    fn job_get(&self, id: Value, params: Value) -> JsonRpcResponse {
        let job_id = match self.get_param_str(&params, 0, "id") {
            Some(j) => j,
            None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing 'id' parameter"),
        };

        let job_uuid = match uuid::Uuid::parse_str(&job_id) {
            Ok(u) => u,
            Err(_) => return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid job ID format"),
        };

        let chain = self.chain_state.read();

        match chain.pending_jobs.iter().find(|j| j.id == job_uuid) {
            Some(j) => JsonRpcResponse::result(
                id,
                json!({
                    "id": j.id.to_string(),
                    "challengeId": j.challenge_id.to_string(),
                    "agentHash": j.agent_hash,
                    "status": format!("{:?}", j.status),
                    "createdAt": j.created_at.to_rfc3339(),
                    "assignedValidator": j.assigned_validator.as_ref().map(|h| h.to_hex()),
                    "result": j.result.as_ref().map(|r| json!({
                        "value": r.value,
                        "weight": r.weight,
                    })),
                }),
            ),
            None => {
                JsonRpcResponse::error(id, JOB_NOT_FOUND, format!("Job '{}' not found", job_id))
            }
        }
    }

    // ==================== Epoch Namespace ====================

    fn epoch_current(&self, id: Value) -> JsonRpcResponse {
        let chain = self.chain_state.read();

        // Epoch config from runtime
        let blocks_per_epoch = 100u64;
        let block_in_epoch = chain.block_height % blocks_per_epoch;

        let (phase, phase_start, phase_end) = if block_in_epoch < 75 {
            ("evaluation", 0, 75)
        } else if block_in_epoch < 88 {
            ("commit", 75, 88)
        } else {
            ("reveal", 88, blocks_per_epoch)
        };

        let blocks_until_next = match phase {
            "evaluation" => 75 - block_in_epoch,
            "commit" => 88 - block_in_epoch,
            _ => blocks_per_epoch - block_in_epoch,
        };

        JsonRpcResponse::result(
            id,
            json!({
                "epochNumber": chain.epoch,
                "currentBlock": chain.block_height,
                "blocksPerEpoch": blocks_per_epoch,
                "blockInEpoch": block_in_epoch,
                "phase": phase,
                "phaseStart": phase_start,
                "phaseEnd": phase_end,
                "blocksUntilNextPhase": blocks_until_next,
                "progress": (block_in_epoch as f64 / blocks_per_epoch as f64 * 100.0).round() / 100.0,
                "estimatedTimeToNextPhase": blocks_until_next * 12, // 12s per block
            }),
        )
    }

    fn epoch_get_phase(&self, id: Value) -> JsonRpcResponse {
        let chain = self.chain_state.read();
        let blocks_per_epoch = 100u64;
        let block_in_epoch = chain.block_height % blocks_per_epoch;

        let phase = if block_in_epoch < 75 {
            "evaluation"
        } else if block_in_epoch < 88 {
            "commit"
        } else {
            "reveal"
        };

        JsonRpcResponse::result(id, json!(phase))
    }

    // ==================== Leaderboard Namespace ====================

    fn leaderboard_get(&self, id: Value, params: Value) -> JsonRpcResponse {
        let challenge_id = match self.get_param_str(&params, 0, "challenge_id") {
            Some(c) => c,
            None => {
                return JsonRpcResponse::error(
                    id,
                    INVALID_PARAMS,
                    "Missing 'challenge_id' parameter",
                )
            }
        };
        let limit = self
            .get_param_u64(&params, 1, "limit")
            .unwrap_or(100)
            .min(1000);
        let offset = self.get_param_u64(&params, 2, "offset").unwrap_or(0);

        let chain = self.chain_state.read();

        let challenge_uuid = chain
            .challenges
            .values()
            .find(|c| c.id.to_string() == challenge_id || c.name == challenge_id)
            .map(|c| c.id);

        match challenge_uuid {
            Some(_cid) => JsonRpcResponse::result(
                id,
                json!({
                    "challengeId": challenge_id,
                    "entries": [],
                    "total": 0,
                    "limit": limit,
                    "offset": offset,
                }),
            ),
            None => JsonRpcResponse::error(
                id,
                CHALLENGE_NOT_FOUND,
                format!("Challenge '{}' not found", challenge_id),
            ),
        }
    }

    // ==================== Evaluation Namespace ====================

    fn evaluation_get_progress(&self, id: Value, params: Value) -> JsonRpcResponse {
        let submission_id = match self.get_param_str(&params, 0, "submission_id") {
            Some(s) => s,
            None => {
                return JsonRpcResponse::error(
                    id,
                    INVALID_PARAMS,
                    "Missing 'submission_id' parameter",
                )
            }
        };

        JsonRpcResponse::result(
            id,
            json!({
                "submissionId": submission_id,
                "progress": [],
                "total": 0,
            }),
        )
    }

    fn evaluation_get_logs(&self, id: Value, params: Value) -> JsonRpcResponse {
        let submission_id = match self.get_param_str(&params, 0, "submission_id") {
            Some(s) => s,
            None => {
                return JsonRpcResponse::error(
                    id,
                    INVALID_PARAMS,
                    "Missing 'submission_id' parameter",
                )
            }
        };

        JsonRpcResponse::result(
            id,
            json!({
                "submissionId": submission_id,
                "logs": null,
                "validated": false,
            }),
        )
    }

    // ==================== Agent Namespace ====================

    fn agent_get_code(&self, id: Value, params: Value) -> JsonRpcResponse {
        let miner_hotkey = match self.get_param_str(&params, 0, "miner_hotkey") {
            Some(h) => h,
            None => {
                return JsonRpcResponse::error(
                    id,
                    INVALID_PARAMS,
                    "Missing 'miner_hotkey' parameter",
                )
            }
        };
        let _epoch = self.get_param_u64(&params, 1, "epoch");

        let _hk = match platform_core::Hotkey::from_hex(&miner_hotkey) {
            Some(h) => h,
            None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid hotkey format"),
        };

        JsonRpcResponse::result(
            id,
            json!({
                "minerHotkey": miner_hotkey,
                "entry": null,
            }),
        )
    }

    fn agent_get_logs(&self, id: Value, params: Value) -> JsonRpcResponse {
        let miner_hotkey = match self.get_param_str(&params, 0, "miner_hotkey") {
            Some(h) => h,
            None => {
                return JsonRpcResponse::error(
                    id,
                    INVALID_PARAMS,
                    "Missing 'miner_hotkey' parameter",
                )
            }
        };
        let _epoch = self.get_param_u64(&params, 1, "epoch");

        JsonRpcResponse::result(
            id,
            json!({
                "minerHotkey": miner_hotkey,
                "logs": [],
                "total": 0,
            }),
        )
    }

    // ==================== Helper Methods ====================

    fn get_param_str(&self, params: &Value, index: usize, name: &str) -> Option<String> {
        params
            .get(index)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                params
                    .get(name)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
    }

    fn get_param_u64(&self, params: &Value, index: usize, name: &str) -> Option<u64> {
        params
            .get(index)
            .and_then(|v| v.as_u64())
            .or_else(|| params.get(name).and_then(|v| v.as_u64()))
    }

    fn get_param_bool(&self, params: &Value, name: &str) -> Option<bool> {
        params.get(name).and_then(|v| v.as_bool())
    }

    /// Update peers list
    pub fn set_peers(&self, peers: Vec<String>) {
        *self.peers.write() = peers;
    }

    /// Add a peer
    pub fn add_peer(&self, peer: String) {
        self.peers.write().push(peer);
    }

    /// Remove a peer
    pub fn remove_peer(&self, peer: &str) {
        self.peers.write().retain(|p| p != peer);
    }

    // ==================== Sudo Namespace ====================

    /// Submit a signed sudo action to be broadcast via P2P
    /// This allows csudo to submit actions via RPC instead of running its own P2P node
    fn sudo_submit(&self, id: Value, params: Value) -> JsonRpcResponse {
        // Get the signed message bytes (hex-encoded)
        let message_hex = match self.get_param_str(&params, 0, "signedMessage") {
            Some(m) => m,
            None => {
                return JsonRpcResponse::error(
                    id,
                    INVALID_PARAMS,
                    "Missing 'signedMessage' parameter (hex-encoded)",
                )
            }
        };

        // Decode hex to bytes
        let message_bytes = match hex::decode(&message_hex) {
            Ok(b) => b,
            Err(e) => {
                return JsonRpcResponse::error(id, INVALID_PARAMS, format!("Invalid hex: {}", e))
            }
        };

        // Verify it's a valid SignedNetworkMessage
        let signed: platform_core::SignedNetworkMessage = match bincode::deserialize(&message_bytes)
        {
            Ok(s) => s,
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    INVALID_PARAMS,
                    format!("Invalid message format: {}", e),
                )
            }
        };

        // Verify signature
        if !signed.verify().unwrap_or(false) {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid signature");
        }

        // Check if it's from the sudo key
        let (is_sudo, chain_sudo_key) = {
            let state = self.chain_state.read();
            (state.is_sudo(signed.signer()), state.sudo_key.to_hex())
        };

        if !is_sudo {
            info!(
                "Sudo check failed: signer={} chain_sudo={}",
                signed.signer().to_hex(),
                chain_sudo_key
            );
            return JsonRpcResponse::error(
                id,
                INVALID_PARAMS,
                format!(
                    "Signer {} is not the sudo key {}",
                    signed.signer().to_hex(),
                    chain_sudo_key
                ),
            );
        }

        // Send to broadcast channel for P2P propagation
        let tx = self.broadcast_tx.read();
        match tx.as_ref() {
            Some(sender) => {
                if let Err(e) = sender.send(message_bytes.clone()) {
                    return JsonRpcResponse::error(
                        id,
                        INTERNAL_ERROR,
                        format!("Failed to queue broadcast: {}", e),
                    );
                }
                info!(
                    "Sudo action queued for P2P broadcast from {}",
                    signed.signer()
                );
            }
            None => {
                return JsonRpcResponse::error(
                    id,
                    INTERNAL_ERROR,
                    "Broadcast channel not configured",
                );
            }
        }

        JsonRpcResponse::result(
            id,
            json!({
                "success": true,
                "message": "Sudo action applied locally and queued for P2P broadcast",
                "signer": signed.signer().to_hex(),
            }),
        )
    }

    // ==================== Monitor Namespace ====================
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_core::{Keypair, NetworkConfig};

    fn create_handler() -> RpcHandler {
        let kp = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            kp.hotkey(),
            NetworkConfig::default(),
        )));
        RpcHandler::new(state, 1)
    }

    #[test]
    fn test_rpc_methods() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "rpc_methods".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_system_health() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "system_health".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_chain_get_state() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "chain_getState".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_method_not_found() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "unknown_method".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
    }

    #[test]
    fn test_validator_not_found() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "validator_get".to_string(),
            params: json!(["0000000000000000000000000000000000000000000000000000000000000000"]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, VALIDATOR_NOT_FOUND);
    }

    #[test]
    fn test_system_version() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "system_version".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_system_name() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "system_name".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_system_properties() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "system_properties".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert!(result.get("tokenSymbol").is_some());
        assert_eq!(result["tokenSymbol"], "TAO");
    }

    #[test]
    fn test_system_peers() {
        let handler = create_handler();
        handler.add_peer("peer1".to_string());
        handler.add_peer("peer2".to_string());

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "system_peers".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        let peers = resp.result.unwrap();
        assert_eq!(peers.as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_system_network_state() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "system_networkState".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_chain_get_head() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "chain_getHead".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_chain_get_finalized_head() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "chain_getFinalizedHead".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_chain_get_block() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "chain_getBlock".to_string(),
            params: json!([0]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_json_rpc_request_parsing() {
        let json_str = r#"{"jsonrpc":"2.0","method":"test","params":null,"id":1}"#;
        let req: JsonRpcRequest = serde_json::from_str(json_str).unwrap();
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.method, "test");
    }

    #[test]
    fn test_json_rpc_response_result() {
        let resp = JsonRpcResponse::result(json!(1), json!({"data": "test"}));
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
        assert_eq!(resp.id, json!(1));
    }

    #[test]
    fn test_json_rpc_response_error() {
        let resp = JsonRpcResponse::error(json!(2), -32600, "Invalid Request");
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32600);
    }

    #[test]
    fn test_peer_management() {
        let handler = create_handler();

        // Add peers
        handler.add_peer("peer1".to_string());
        handler.add_peer("peer2".to_string());
        assert_eq!(handler.peers.read().len(), 2);

        // Remove peer
        handler.remove_peer("peer1");
        assert_eq!(handler.peers.read().len(), 1);

        // Set peers
        handler.set_peers(vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        assert_eq!(handler.peers.read().len(), 3);
    }

    #[test]
    fn test_invalid_params() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "validator_get".to_string(),
            params: json!([]), // Empty params, missing hotkey
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
    }

    #[test]
    fn test_chain_get_block_hash() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "chain_getBlockHash".to_string(),
            params: json!([0]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_state_get_keys() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "state_getKeys".to_string(),
            params: json!(["challenges"]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_state_get_runtime_version() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "state_getRuntimeVersion".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_validator_list() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "validator_list".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert!(result.get("validators").is_some());
    }

    #[test]
    fn test_validator_list_with_pagination() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "validator_list".to_string(),
            params: json!([10, 50]), // offset, limit
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert_eq!(result["offset"], 10);
        assert_eq!(result["limit"], 50);
    }

    #[test]
    fn test_validator_count() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "validator_count".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_metagraph_hotkeys() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "metagraph_hotkeys".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert!(result.get("hotkeys").is_some());
        assert!(result.get("count").is_some());
    }

    #[test]
    fn test_metagraph_is_registered_invalid_hotkey() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "metagraph_isRegistered".to_string(),
            params: json!(["invalid_hotkey"]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
    }

    #[test]
    fn test_metagraph_is_registered_missing_param() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "metagraph_isRegistered".to_string(),
            params: json!([]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn test_challenge_list() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "challenge_list".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert!(result.get("challenges").is_some());
    }

    #[test]
    fn test_challenge_list_only_active() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "challenge_list".to_string(),
            params: json!({"onlyActive": true}),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_challenge_get_not_found() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "challenge_get".to_string(),
            params: json!(["nonexistent"]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, CHALLENGE_NOT_FOUND);
    }

    #[test]
    fn test_challenge_get_missing_param() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "challenge_get".to_string(),
            params: json!([]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn test_challenge_get_routes_no_routes() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "challenge_getRoutes".to_string(),
            params: json!(["test-challenge"]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert_eq!(result["routesCount"], 0);
    }

    #[test]
    fn test_challenge_list_all_routes() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "challenge_listAllRoutes".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert!(result.get("routes").is_some());
    }

    #[test]
    fn test_job_list() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "job_list".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert!(result.get("jobs").is_some());
    }

    #[test]
    fn test_job_list_with_filter() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "job_list".to_string(),
            params: json!([0, 100, "pending"]), // offset, limit, status
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_job_get_invalid_id() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "job_get".to_string(),
            params: json!(["not-a-uuid"]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn test_job_get_not_found() {
        let handler = create_handler();
        let job_id = uuid::Uuid::new_v4().to_string();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "job_get".to_string(),
            params: json!([job_id]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, JOB_NOT_FOUND);
    }

    #[test]
    fn test_job_get_missing_param() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "job_get".to_string(),
            params: json!([]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn test_epoch_current() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "epoch_current".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert!(result.get("epochNumber").is_some());
        assert!(result.get("phase").is_some());
        assert!(result.get("blocksPerEpoch").is_some());
    }

    #[test]
    fn test_epoch_get_phase() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "epoch_getPhase".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        let phase = resp.result.unwrap();
        assert!(phase.is_string());
    }

    #[test]
    fn test_state_get_storage_invalid_key() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "state_getStorage".to_string(),
            params: json!(["unknownKey"]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn test_state_get_storage_block_height() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "state_getStorage".to_string(),
            params: json!(["blockHeight"]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_state_get_storage_missing_key() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "state_getStorage".to_string(),
            params: json!([]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn test_state_get_storage_validator_key() {
        let handler = create_handler();
        let kp = Keypair::generate();
        let key = format!("validator:{}", kp.hotkey().to_hex());
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "state_getStorage".to_string(),
            params: json!([key]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_state_get_storage_challenge_key() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "state_getStorage".to_string(),
            params: json!(["challenge:test"]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_state_get_metadata() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "state_getMetadata".to_string(),
            params: Value::Null,
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert!(result.get("pallets").is_some());
    }

    #[test]
    fn test_sudo_submit_missing_param() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "sudo_submit".to_string(),
            params: json!([]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn test_sudo_submit_invalid_hex() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "sudo_submit".to_string(),
            params: json!(["not-hex"]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn test_json_rpc_error_with_data() {
        let resp = JsonRpcResponse::error_with_data(
            json!(1),
            -32000,
            "Custom error",
            json!({"detail": "extra info"}),
        );
        assert!(resp.error.is_some());
        let error = resp.error.unwrap();
        assert_eq!(error.code, -32000);
        assert!(error.data.is_some());
    }

    #[test]
    fn test_normalize_challenge_name() {
        assert_eq!(
            RpcHandler::normalize_challenge_name("Test Challenge"),
            "test-challenge"
        );
        assert_eq!(
            RpcHandler::normalize_challenge_name("My_Cool_Challenge"),
            "my-cool-challenge"
        );
        assert_eq!(RpcHandler::normalize_challenge_name("  Spaces  "), "spaces");
        assert_eq!(
            RpcHandler::normalize_challenge_name("Special!@#$%Chars"),
            "specialchars"
        );
    }

    #[test]
    fn test_register_challenge_routes() {
        let handler = create_handler();
        use platform_challenge_sdk::ChallengeRoute;

        let routes = vec![
            ChallengeRoute::get("/test", "Test route"),
            ChallengeRoute::post("/submit", "Submit route"),
        ];

        handler.register_challenge_routes("test-challenge", routes);

        let registered = handler.challenge_routes.read();
        assert!(registered.contains_key("test-challenge"));
        assert_eq!(registered.get("test-challenge").unwrap().len(), 2);
    }

    #[test]
    fn test_unregister_challenge_routes() {
        let handler = create_handler();
        use platform_challenge_sdk::ChallengeRoute;

        let routes = vec![ChallengeRoute::get("/test", "Test route")];
        handler.register_challenge_routes("test-challenge", routes);

        handler.unregister_challenge_routes("test-challenge");

        let registered = handler.challenge_routes.read();
        assert!(!registered.contains_key("test-challenge"));
    }

    #[test]
    fn test_get_all_challenge_routes() {
        let handler = create_handler();
        use platform_challenge_sdk::ChallengeRoute;

        let routes = vec![ChallengeRoute::get("/test", "Test route")];
        handler.register_challenge_routes("test-challenge", routes);

        let all_routes = handler.get_all_challenge_routes();
        assert_eq!(all_routes.len(), 1);
    }

    #[test]
    fn test_set_keypair() {
        let handler = create_handler();
        let kp = Keypair::generate();
        handler.set_keypair(kp.clone());

        let stored = handler.keypair.read();
        assert!(stored.is_some());
    }

    #[test]
    fn test_json_rpc_request_default_params() {
        let json_str = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;
        let req: JsonRpcRequest = serde_json::from_str(json_str).unwrap();
        assert_eq!(req.params, Value::Null);
    }

    #[test]
    fn test_get_param_helpers() {
        let handler = create_handler();
        let params = json!([10, "test", true]);

        assert_eq!(handler.get_param_u64(&params, 0, "x"), Some(10));
        assert_eq!(
            handler.get_param_str(&params, 1, "y"),
            Some("test".to_string())
        );
    }

    #[test]
    fn test_set_broadcast_tx() {
        let handler = create_handler();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        handler.set_broadcast_tx(tx);
        assert!(handler.broadcast_tx.read().is_some());
    }

    #[test]
    fn test_set_route_handler() {
        let handler = create_handler();
        let route_handler: ChallengeRouteHandler = Arc::new(|_challenge_id, _req| {
            Box::pin(async move {
                ChallengeRouteResponse {
                    status: 200,
                    body: json!({"success": true}),
                    headers: std::collections::HashMap::new(),
                }
            })
        });
        handler.set_route_handler(route_handler);
        assert!(handler.route_handler.read().is_some());
    }

    #[test]
    fn test_chain_get_block_invalid_number() {
        let handler = create_handler();
        // Request a block that doesn't exist
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "chain_getBlock".to_string(),
            params: json!([999]), // Block that doesn't exist
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
    }

    #[test]
    fn test_chain_get_block_hash_invalid() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "chain_getBlockHash".to_string(),
            params: json!([999]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        assert_eq!(resp.result.unwrap(), serde_json::Value::Null);
    }

    #[test]
    fn test_state_get_storage_validator_key_invalid_hotkey() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "state_getStorage".to_string(),
            params: json!(["validator:invalid_hex"]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
    }

    #[test]
    fn test_validator_get_invalid_hotkey_format() {
        let handler = create_handler();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "validator_get".to_string(),
            params: json!(["not_a_valid_hotkey"]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn test_metagraph_is_registered_with_valid_hotkey() {
        let handler = create_handler();
        let kp = Keypair::generate();

        // Add hotkey to registered_hotkeys
        {
            let mut chain = handler.chain_state.write();
            chain.registered_hotkeys.insert(kp.hotkey());
        }

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "metagraph_isRegistered".to_string(),
            params: json!([kp.hotkey().to_hex()]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert_eq!(result["isRegistered"], true);
    }

    #[test]
    fn test_challenge_get_with_routes() {
        let handler = create_handler();
        use platform_challenge_sdk::ChallengeRoute;

        // Add a challenge
        let kp = Keypair::generate();
        let challenge_id = platform_core::ChallengeId::new();
        let config = platform_core::ChallengeConfig::default();
        let challenge = platform_core::Challenge {
            id: challenge_id,
            name: "test-challenge".to_string(),
            description: "Test description".to_string(),
            wasm_code: vec![1, 2, 3],
            code_hash: "abc123".to_string(),
            wasm_metadata: platform_core::WasmModuleMetadata::from_code_hash("abc123".to_string()),
            owner: kp.hotkey(),
            config,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            is_active: true,
        };

        handler
            .chain_state
            .write()
            .challenges
            .insert(challenge_id, challenge);

        // Register routes for the challenge
        let routes = vec![
            ChallengeRoute::get("/test", "Test route"),
            ChallengeRoute::post("/submit", "Submit route"),
        ];
        handler.register_challenge_routes(&challenge_id.to_string(), routes);

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "challenge_get".to_string(),
            params: json!([challenge_id.to_string()]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert_eq!(result["routes"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_challenge_get_routes_by_name() {
        let handler = create_handler();
        use platform_challenge_sdk::ChallengeRoute;

        // Add a challenge
        let kp = Keypair::generate();
        let challenge_id = platform_core::ChallengeId::new();
        let config = platform_core::ChallengeConfig::default();
        let challenge = platform_core::Challenge {
            id: challenge_id,
            name: "my-challenge".to_string(),
            description: "Test description".to_string(),
            wasm_code: vec![],
            code_hash: "abc123".to_string(),
            wasm_metadata: platform_core::WasmModuleMetadata::from_code_hash("abc123".to_string()),
            owner: kp.hotkey(),
            config,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            is_active: true,
        };

        handler
            .chain_state
            .write()
            .challenges
            .insert(challenge_id, challenge);

        // Register routes
        let routes = vec![ChallengeRoute::get("/status", "Status route")];
        handler.register_challenge_routes(&challenge_id.to_string(), routes);

        // Query by name instead of ID
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "challenge_getRoutes".to_string(),
            params: json!(["my-challenge"]),
            id: json!(1),
        };
        let resp = handler.handle(req);
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert_eq!(result["routesCount"], 1);
    }

    #[test]
    fn test_register_empty_routes() {
        let handler = create_handler();
        // Registering empty routes should be a no-op
        handler.register_challenge_routes("test-challenge", vec![]);
        let routes = handler.challenge_routes.read();
        assert!(!routes.contains_key("test-challenge"));
    }
}
