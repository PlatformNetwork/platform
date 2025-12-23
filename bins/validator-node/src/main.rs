//! Validator Node Binary
//!
//! Runs a validator node in the platform P2P network.

use anyhow::Result;
use challenge_orchestrator::{ChallengeOrchestrator, OrchestratorConfig};
use clap::Parser;
use distributed_db::{ConsensusStatus, DBSyncEvent, DBSyncManager, DBSyncMessage, DistributedDB};
use parking_lot::RwLock;
use platform_bittensor::{
    signer_from_seed, sync_metagraph, BittensorClient, BlockSync, BlockSyncConfig, BlockSyncEvent,
    ExtrinsicWait, Subtensor,
};
use platform_challenge_runtime::{ChallengeRuntime, RuntimeConfig, RuntimeEvent};
use platform_consensus::PBFTEngine;
use platform_core::{
    production_sudo_key, ChainState, ChallengeContainerConfig, ChallengeMessageType,
    ChallengeNetworkMessage, Hotkey, Keypair, NetworkConfig, NetworkMessage, SignedNetworkMessage,
    Stake, SudoAction, ValidatorInfo, SUDO_KEY_SS58,
};
use platform_epoch::{EpochConfig, EpochPhase, EpochTransition};
use platform_network::{
    NetworkEvent, NetworkNode, NetworkProtection, NodeConfig, ProtectionConfig, SyncResponse,
};
use platform_rpc::{OrchestratorCommand, RpcConfig, RpcServer};
use platform_storage::Storage;
use platform_subnet_manager::BanList;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

// ==================== Container Authentication ====================

/// Session with a challenge container
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ContainerAuthSession {
    /// The authentication token
    token: String,
    /// When the session expires
    expires_at: u64,
    /// Challenge container name (for logging)
    container_name: String,
}

/// Request body for authenticating with a challenge container
#[derive(Debug, Clone, serde::Serialize)]
struct ContainerAuthRequest {
    hotkey: String,
    challenge_id: String,
    timestamp: u64,
    nonce: String,
    signature: String,
}

/// Response from challenge container authentication
#[derive(Debug, Clone, serde::Deserialize)]
struct ContainerAuthResponse {
    success: bool,
    session_token: Option<String>,
    expires_at: Option<u64>,
    error: Option<String>,
}

#[derive(Parser, Debug)]
#[command(name = "validator-node")]
#[command(about = "Mini-chain validator node")]
struct Args {
    /// Secret key or mnemonic (REQUIRED - all participants must register)
    /// Can be hex encoded 32 bytes or BIP39 mnemonic phrase
    #[arg(short, long, env = "VALIDATOR_SECRET_KEY", required = true)]
    secret_key: String,

    /// Listen address
    #[arg(short, long, default_value = "/ip4/0.0.0.0/tcp/9000")]
    listen: String,

    /// Bootstrap peer addresses (comma-separated)
    #[arg(short, long)]
    bootstrap: Option<String>,

    /// Disable bootnode connection (for running as bootnode or isolated testing)
    #[arg(long)]
    no_bootnode: bool,

    /// Data directory
    #[arg(short, long, default_value = "./data")]
    data_dir: PathBuf,

    /// Subnet owner public key (hex encoded, 32 bytes)
    /// Default: 5GziQCcRpN8NCJktX343brnfuVe3w6gUYieeStXPD1Dag2At
    #[arg(long, env = "SUDO_KEY")]
    sudo_key: Option<String>,

    /// Initial stake amount in TAO (used when --no-bittensor is set)
    /// When connected to Bittensor, stake is read from the metagraph
    #[arg(long, default_value = "1000")]
    stake: f64,

    /// Minimum stake required to participate as validator (in TAO)
    /// Default: 1000 TAO. Set lower for testnets or new subnets
    #[arg(long, env = "MIN_STAKE_TAO", default_value = "1000")]
    min_stake: f64,

    // === Bittensor Options ===
    /// Bittensor network endpoint
    #[arg(
        long,
        env = "SUBTENSOR_ENDPOINT",
        default_value = "wss://entrypoint-finney.opentensor.ai:443"
    )]
    subtensor_endpoint: String,

    /// Subnet UID (netuid) on Bittensor
    #[arg(long, env = "NETUID", default_value = "100")]
    netuid: u16,

    /// Disable Bittensor connection (local testing)
    #[arg(long)]
    no_bittensor: bool,

    /// Use commit-reveal for weights (vs direct set_weights)
    #[arg(long, default_value = "true")]
    commit_reveal: bool,

    // === Epoch Options ===
    /// Blocks per epoch
    #[arg(long, default_value = "100")]
    epoch_length: u64,

    /// Evaluation phase blocks (percentage of epoch)
    #[arg(long, default_value = "75")]
    eval_blocks: u64,

    /// Commit phase blocks
    #[arg(long, default_value = "13")]
    commit_blocks: u64,

    /// Reveal phase blocks
    #[arg(long, default_value = "12")]
    reveal_blocks: u64,

    // === RPC Options ===
    /// RPC server port (0 to disable)
    #[arg(long, default_value = "8080")]
    rpc_port: u16,

    /// RPC server bind address
    #[arg(long, default_value = "0.0.0.0")]
    rpc_addr: String,

    /// Enable CORS for RPC server
    #[arg(long, default_value = "true")]
    rpc_cors: bool,

    // === Docker Challenge Options ===
    /// Enable Docker challenge orchestration (requires docker.sock mount)
    #[arg(long, default_value = "true")]
    docker_challenges: bool,

    /// Health check interval for challenge containers (seconds)
    #[arg(long, default_value = "30")]
    health_check_interval: u64,
}

/// Initialize Sentry error monitoring
/// Enabled by default - can be disabled by setting SENTRY_DSN="" or overridden with custom DSN
fn init_sentry() -> Option<sentry::ClientInitGuard> {
    // Default DSN for Platform Network error monitoring
    const DEFAULT_DSN: &str = "https://56a006330cecdc120766a602a5091eb9@o4510579978272768.ingest.us.sentry.io/4510579979911168";

    // Allow override or disable via env var (empty string disables)
    let dsn = std::env::var("SENTRY_DSN").unwrap_or_else(|_| DEFAULT_DSN.to_string());

    if dsn.is_empty() {
        return None;
    }

    let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "production".to_string());

    let guard = sentry::init((
        dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            environment: Some(environment.into()),
            // SECURITY: Do not send PII (IP addresses, headers, etc.)
            send_default_pii: false,
            // Only sample 100% of errors, 10% of transactions
            sample_rate: 1.0,
            traces_sample_rate: 0.1,
            // Attach stacktraces to all events
            attach_stacktrace: true,
            ..Default::default()
        },
    ));

    tracing::info!("Sentry error monitoring initialized");
    Some(guard)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize Sentry error monitoring (optional - requires SENTRY_DSN env var)
    // SECURITY: DSN must be provided via environment variable, never hardcode
    let _sentry_guard = init_sentry();

    // Initialize logging with Sentry integration
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,platform=debug".into()),
        )
        .finish();

    // Add Sentry layer to capture ERROR and WARN level events
    use tracing_subscriber::layer::SubscriberExt;
    let subscriber =
        subscriber.with(
            sentry_tracing::layer().event_filter(|metadata| match *metadata.level() {
                tracing::Level::ERROR => sentry_tracing::EventFilter::Event,
                tracing::Level::WARN => sentry_tracing::EventFilter::Breadcrumb,
                _ => sentry_tracing::EventFilter::Ignore,
            }),
        );
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    let args = Args::parse();

    info!("Starting validator node...");

    // Parse required secret key (hex or mnemonic)
    // For Bittensor, we pass the secret directly (mnemonic or hex seed)
    // The internal keypair uses the same derivation as Bittensor (SR25519)
    let bittensor_seed = args.secret_key.clone();

    // Derive keypair using proper Substrate SR25519 derivation (same as Bittensor)
    // Derive sr25519 keypair - compatible with Bittensor/Substrate
    // Hotkey will be the sr25519 public key that can be verified on Bittensor metagraph
    let keypair = {
        let secret = args.secret_key.trim();

        // Strip 0x prefix if present
        let hex_str = secret.strip_prefix("0x").unwrap_or(secret);

        // Try hex decode first (64 hex chars = 32 bytes seed)
        if hex_str.len() == 64 {
            if let Ok(bytes) = hex::decode(hex_str) {
                if bytes.len() != 32 {
                    anyhow::bail!("Hex seed must be 32 bytes");
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                info!("Loading sr25519 keypair from hex seed");
                Keypair::from_seed(&arr)?
            } else {
                // Not valid hex, try as mnemonic
                info!("Loading sr25519 keypair from mnemonic");
                Keypair::from_mnemonic(secret)?
            }
        } else {
            // Assume it's a mnemonic phrase
            info!("Loading sr25519 keypair from mnemonic");
            Keypair::from_mnemonic(secret)?
        }
    };

    // Log the derived hotkey for verification against Bittensor metagraph
    // SS58 is the standard format used on Bittensor blockchain
    info!("Validator hotkey: {}", keypair.ss58_address());
    debug!("Validator hotkey (hex): {}", keypair.hotkey().to_hex());

    // Set VALIDATOR_HOTKEY env var for challenge containers
    // This allows challenge containers to authenticate and sign P2P messages
    std::env::set_var("VALIDATOR_HOTKEY", keypair.hotkey().to_hex());

    // The identity seed for P2P is derived from the hotkey (public key)
    // This ensures the peer ID corresponds to the SS58 address
    let identity_seed = keypair.hotkey().0;

    // Canonicalize data directory to ensure absolute paths for Docker
    let data_dir = if args.data_dir.exists() {
        std::fs::canonicalize(&args.data_dir)?
    } else {
        std::fs::create_dir_all(&args.data_dir)?;
        std::fs::canonicalize(&args.data_dir)?
    };
    info!("Using data directory: {:?}", data_dir);

    // Open storage
    let storage = Storage::open(&data_dir)?;

    // Open distributed database for decentralized storage
    let db_path = data_dir.join("distributed-db");
    info!("Opening distributed database at {:?}", db_path);
    let distributed_db = Arc::new(DistributedDB::open(&db_path, keypair.hotkey())?);
    info!(
        "Distributed DB initialized - state root: {}",
        hex::encode(&distributed_db.state_root()[..8])
    );

    // Initialize DB Sync Manager for P2P state synchronization
    let (db_sync_tx, _db_sync_rx) = mpsc::unbounded_channel::<DBSyncMessage>();
    // Note: db_sync_rx messages would be broadcast to P2P network via gossipsub
    // DBSyncMessage broadcast via NetworkNode gossipsub
    let (db_sync_manager, mut db_sync_event_rx) =
        DBSyncManager::new(keypair.clone(), distributed_db.clone(), db_sync_tx.clone());
    let db_sync_manager = Arc::new(db_sync_manager);
    info!("DB Sync Manager initialized - will sync state with peers");

    // Calculate minimum stake in RAO from CLI argument
    let min_stake_tao = args.min_stake;
    let min_stake_rao = (args.min_stake * 1_000_000_000.0) as u64;

    // Load or create chain state
    let chain_state = if let Some(mut state) = storage.load_state()? {
        info!("Loaded existing state at block {}", state.block_height);
        // IMPORTANT: Sync the loaded state's min_stake with CLI argument
        // This ensures add_validator uses the same threshold as metagraph sync
        let old_min_stake = state.config.min_stake.0;
        state.config.min_stake = Stake::new(min_stake_rao);
        if old_min_stake != min_stake_rao {
            info!(
                "Updated state config min_stake: {} -> {} RAO ({} TAO)",
                old_min_stake, min_stake_rao, min_stake_tao
            );
        }
        Arc::new(RwLock::new(state))
    } else {
        info!("Creating new chain state");

        // Determine sudo key - use production key by default
        let sudo_key = if let Some(sudo_hex) = &args.sudo_key {
            info!("Using custom sudo key");
            Hotkey::from_hex(sudo_hex).ok_or_else(|| anyhow::anyhow!("Invalid sudo key"))?
        } else {
            // Production sudo key: 5GziQCcRpN8NCJktX343brnfuVe3w6gUYieeStXPD1Dag2At
            info!("Using production sudo key: {}", SUDO_KEY_SS58);
            production_sudo_key()
        };

        // Select network configuration based on Bittensor connection
        // Use min_stake from CLI argument for consistency
        let mut config = if args.no_bittensor {
            NetworkConfig::default()
        } else {
            NetworkConfig::production()
        };
        config.min_stake = Stake::new(min_stake_rao);

        let state = ChainState::new(sudo_key, config);
        Arc::new(RwLock::new(state))
    };

    // Set OWNER_HOTKEY env var for challenge containers
    // This allows challenge containers to identify the subnet owner for sudo operations
    {
        let state = chain_state.read();
        std::env::set_var("OWNER_HOTKEY", state.sudo_key.to_hex());
        info!("Owner hotkey set: {}", state.sudo_key.to_hex());
    }

    // Initialize network protection (DDoS + stake validation)
    let protection_config = ProtectionConfig {
        min_stake_rao,                      // Configurable minimum stake
        rate_limit: 100,                    // 100 msg/sec per peer
        max_connections_per_ip: 5,          // 5 connections max per IP
        blacklist_duration_secs: 3600,      // 1 hour blacklist
        validate_stake: !args.no_bittensor, // Only validate if connected to Bittensor
        rate_limiting: true,
        connection_limiting: true,
        max_failed_attempts: 10,
    };
    let protection = Arc::new(NetworkProtection::new(protection_config));
    info!(
        "Network protection enabled: min_stake={} TAO, rate_limit={} msg/s",
        min_stake_tao, 100
    );

    // Add ourselves as a validator
    {
        let stake_raw = (args.stake * 1_000_000_000.0) as u64;

        // Validate our own stake meets minimum
        if stake_raw < min_stake_rao {
            warn!(
                "WARNING: Own stake ({} TAO) is below minimum ({} TAO). You may be rejected by other validators.",
                args.stake, min_stake_tao
            );
        }

        let info = ValidatorInfo::new(keypair.hotkey(), Stake::new(stake_raw));
        let mut state = chain_state.write();
        if state.get_validator(&keypair.hotkey()).is_none() {
            state.add_validator(info)?;
            info!("Added self as validator with {} TAO stake", args.stake);
        }
    }

    // Create epoch config from CLI args (will be updated with Bittensor tempo if connected)
    let mut epoch_config = EpochConfig {
        blocks_per_epoch: args.epoch_length,
        evaluation_blocks: args.eval_blocks,
        commit_blocks: args.commit_blocks,
        reveal_blocks: args.reveal_blocks,
        min_validators_for_consensus: 1,
        weight_smoothing: 0.1,
    };
    info!(
        "Initial epoch config: {} blocks (eval={}, commit={}, reveal={})",
        args.epoch_length, args.eval_blocks, args.commit_blocks, args.reveal_blocks
    );

    // Create challenge runtime
    let current_block = chain_state.read().block_height;
    let runtime_config = RuntimeConfig {
        data_dir: data_dir.join("challenges"),
        epoch_config: epoch_config.clone(),
        max_concurrent_evaluations: 4,
        evaluation_timeout_secs: 3600, // 1 hour - long evaluations allowed
        ..Default::default()
    };

    let mut challenge_runtime =
        ChallengeRuntime::new(runtime_config, keypair.hotkey(), current_block);

    // Take event receiver
    let mut runtime_event_rx = challenge_runtime.take_event_receiver().unwrap();
    let challenge_runtime = Arc::new(challenge_runtime);

    // Load challenges dynamically from ChainState (configured via SudoAction::AddChallenge)
    // Challenges are Docker containers managed by ChallengeOrchestrator
    let challenge_configs: Vec<ChallengeContainerConfig> = {
        let state = chain_state.read();
        state.challenge_configs.values().cloned().collect()
    };

    if challenge_configs.is_empty() {
        info!("No challenges configured in ChainState. Waiting for SudoAction::AddChallenge...");
        info!("Subnet owner can add challenges via: SudoAction::AddChallenge {{ config }}");
    } else {
        info!(
            "Found {} challenge(s) configured in ChainState",
            challenge_configs.len()
        );
        for config in &challenge_configs {
            info!(
                "  - {} (mechanism {}, image: {})",
                config.name, config.mechanism_id, config.docker_image
            );
            // Store challenge in distributed DB
            if let Err(e) = distributed_db.store_challenge(config) {
                warn!("Failed to store challenge in DB: {}", e);
            }
        }
    }

    // Store challenge endpoints for HTTP proxying (challenge_id -> endpoint URL)
    let challenge_endpoints: Arc<RwLock<std::collections::HashMap<String, String>>> =
        Arc::new(RwLock::new(std::collections::HashMap::new()));

    // Store authenticated sessions with challenge containers
    let container_auth_sessions: Arc<RwLock<HashMap<String, ContainerAuthSession>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Start RPC server (if enabled)
    // Challenge-specific logic is handled by Docker containers
    // The validator only proxies requests to challenges via HTTP
    let (_rpc_handle, rpc_handler, rpc_broadcast_rx, orchestrator_cmd_rx) = if args.rpc_port > 0 {
        let rpc_addr = format!("{}:{}", args.rpc_addr, args.rpc_port);
        let rpc_config = RpcConfig {
            addr: rpc_addr.parse()?,
            netuid: args.netuid,
            name: format!("MiniChain-{}", args.netuid),
            min_stake: min_stake_rao,
            cors_enabled: args.rpc_cors,
        };

        let bans = Arc::new(RwLock::new(BanList::new()));
        let rpc_server = RpcServer::new(rpc_config, chain_state.clone(), bans);

        // Register routes for each configured challenge
        // Routes are dynamically registered based on ChainState
        for config in &challenge_configs {
            let challenge_id = config.challenge_id.to_string();
            // Standard routes that all challenges expose
            use platform_challenge_sdk::ChallengeRoute;
            let routes = vec![
                ChallengeRoute::post("/submit", "Submit an agent"),
                ChallengeRoute::get("/status/:hash", "Get agent status"),
                ChallengeRoute::get("/leaderboard", "Get leaderboard"),
                ChallengeRoute::get("/config", "Get challenge config"),
                ChallengeRoute::get("/stats", "Get statistics"),
            ];
            rpc_server
                .rpc_handler()
                .register_challenge_routes(&challenge_id, routes);

            // Store endpoint for this challenge (container name derived from challenge name + validator suffix)
            // Must match logic in challenge-orchestrator/docker.rs
            let validator_suffix = std::env::var("VALIDATOR_NAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| format!("{:x}", std::process::id()));
            let container_name = format!(
                "challenge-{}-{}",
                config.name.to_lowercase().replace(' ', "-"),
                validator_suffix.to_lowercase().replace('-', "").replace(' ', "")
            );
            let endpoint = format!("http://{}:8080", container_name);
            challenge_endpoints.write().insert(challenge_id, endpoint);
        }

        // Clone for use in handler closure
        let endpoints_for_handler = challenge_endpoints.clone();
        let chain_state_for_handler = chain_state.clone();
        let keypair_for_handler = keypair.clone();

        // Create shared channel for P2P agent submission broadcasts
        let agent_broadcast_tx: Arc<RwLock<Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>> =
            Arc::new(RwLock::new(None));
        let agent_broadcast_for_handler = agent_broadcast_tx.clone();

        // Set up route handler that proxies to challenge containers
        let handler: platform_rpc::ChallengeRouteHandler = Arc::new(move |challenge_id, req| {
            let endpoints = endpoints_for_handler.clone();
            let chain_state = chain_state_for_handler.clone();
            let keypair = keypair_for_handler.clone();
            let broadcast_tx = agent_broadcast_for_handler.clone();
            Box::pin(async move {
                use platform_challenge_sdk::RouteResponse;

                // Get endpoint for this challenge (check endpoints map first, then derive from config)
                let endpoint = {
                    let eps = endpoints.read();
                    if let Some(ep) = eps.get(&challenge_id) {
                        ep.clone()
                    } else {
                        // Try to derive from challenge_configs (for dynamically added challenges)
                        drop(eps);
                        let state = chain_state.read();
                        let config = state.challenge_configs.values().find(|c| {
                            c.challenge_id.to_string() == challenge_id || c.name == challenge_id
                        });

                        match config {
                            Some(cfg) => {
                                // Must match logic in challenge-orchestrator/docker.rs
                                let validator_suffix = std::env::var("VALIDATOR_NAME")
                                    .or_else(|_| std::env::var("HOSTNAME"))
                                    .unwrap_or_else(|_| format!("{:x}", std::process::id()));
                                let container_name = format!(
                                    "challenge-{}-{}",
                                    cfg.name.to_lowercase().replace(' ', "-"),
                                    validator_suffix.to_lowercase().replace('-', "").replace(' ', "")
                                );
                                format!("http://{}:8080", container_name)
                            }
                            None => {
                                return RouteResponse::new(
                                    404,
                                    serde_json::json!({"error": format!("Challenge {} not configured", challenge_id)}),
                                );
                            }
                        }
                    }
                };

                // Build URL for challenge container
                let url = format!("{}{}", endpoint, req.path);

                // Create HTTP client
                let client = reqwest::Client::new();

                // Forward request to challenge container
                let result = match req.method.as_str() {
                    "GET" => client.get(&url).send().await,
                    "POST" => client.post(&url).json(&req.body).send().await,
                    "PUT" => client.put(&url).json(&req.body).send().await,
                    "DELETE" => client.delete(&url).send().await,
                    _ => return RouteResponse::bad_request("Unsupported method"),
                };

                match result {
                    Ok(response) => {
                        let status = response.status();
                        match response.json::<serde_json::Value>().await {
                            Ok(body) => {
                                if status.is_success() {
                                    // Broadcast successful submissions via P2P
                                    if req.path == "/submit"
                                        && body
                                            .get("success")
                                            .and_then(|v| v.as_bool())
                                            .unwrap_or(false)
                                    {
                                        if let Some(agent_hash) =
                                            body.get("agent_hash").and_then(|v| v.as_str())
                                        {
                                            // Extract submission details from request body
                                            let miner_hotkey = req
                                                .body
                                                .get("miner_hotkey")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("unknown")
                                                .to_string();
                                            let source_code = req
                                                .body
                                                .get("source_code")
                                                .and_then(|v| v.as_str())
                                                .map(String::from);

                                            // Create AgentSubmission message
                                            let submission_msg =
                                                platform_core::AgentSubmissionMessage::new(
                                                    challenge_id.clone(),
                                                    agent_hash.to_string(),
                                                    miner_hotkey.clone(),
                                                    source_code,
                                                    keypair.hotkey(),
                                                );

                                            let network_msg =
                                                platform_core::NetworkMessage::AgentSubmission(
                                                    submission_msg,
                                                );
                                            if let Ok(signed) =
                                                platform_core::SignedNetworkMessage::new(
                                                    network_msg,
                                                    &keypair,
                                                )
                                            {
                                                if let Ok(bytes) = bincode::serialize(&signed) {
                                                    let tx = broadcast_tx.read();
                                                    if let Some(sender) = tx.as_ref() {
                                                        if sender.send(bytes).is_ok() {
                                                            tracing::info!(
                                                                "Agent {} broadcast via P2P to other validators (challenge: {}, miner: {})",
                                                                agent_hash, challenge_id, miner_hotkey
                                                            );
                                                        }
                                                    }
                                                }
                                            }

                                            // Submitting validator also signs consensus
                                            let agent_h = agent_hash.to_string();
                                            let validator_h = keypair.hotkey().to_hex();
                                            let container =
                                                challenge_id.to_lowercase().replace(' ', "-");
                                            let obfuscated = body
                                                .get("status")
                                                .and_then(|s| s.get("distribution_status"))
                                                .and_then(|d| d.get("obfuscated_hash"))
                                                .and_then(|v| v.as_str())
                                                .unwrap_or(&agent_h)
                                                .to_string();

                                            tokio::spawn(async move {
                                                let client = reqwest::Client::new();
                                                let sign_url = format!(
                                                    "http://challenge-{}:8080/consensus/sign",
                                                    container
                                                );
                                                let payload = serde_json::json!({
                                                    "agent_hash": agent_h,
                                                    "validator_hotkey": validator_h,
                                                    "obfuscated_hash": obfuscated,
                                                    "signature": "0000000000000000000000000000000000000000000000000000000000000000"
                                                });
                                                if let Ok(resp) = client
                                                    .post(&sign_url)
                                                    .json(&payload)
                                                    .send()
                                                    .await
                                                {
                                                    if resp.status().is_success() {
                                                        tracing::info!("Submitting validator signed consensus for agent {}", agent_h);
                                                    }
                                                }
                                            });
                                        }
                                    }
                                    RouteResponse::json(body)
                                } else {
                                    RouteResponse::new(
                                        status.as_u16(),
                                        serde_json::json!({"error": body.to_string()}),
                                    )
                                }
                            }
                            Err(_) => RouteResponse::new(
                                status.as_u16(),
                                serde_json::json!({"error": "Invalid response"}),
                            ),
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to proxy request to challenge {}: {}",
                            challenge_id,
                            e
                        );
                        RouteResponse::new(
                            502,
                            serde_json::json!({"error": format!("Challenge unavailable: {}", e)}),
                        )
                    }
                }
            })
        });
        rpc_server.rpc_handler().set_route_handler(handler);

        info!(
            "Registered {} challenge routes (proxied to containers)",
            rpc_server.rpc_handler().get_all_challenge_routes().len()
        );

        info!(
            "Starting JSON-RPC server on {}:{}",
            args.rpc_addr, args.rpc_port
        );
        info!("  POST / or /rpc with JSON-RPC 2.0 requests");

        // Keep reference to RPC handler for peer updates and broadcast channel
        let rpc_handler = rpc_server.rpc_handler();

        // Create channel for RPC -> P2P broadcast (for sudo_submit and agent submissions)
        let (rpc_broadcast_tx, rpc_broadcast_rx) =
            tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        rpc_handler.set_broadcast_tx(rpc_broadcast_tx.clone());

        // Create channel for RPC -> Orchestrator (for challenge container management)
        let (orchestrator_tx, orchestrator_rx) =
            tokio::sync::mpsc::unbounded_channel::<OrchestratorCommand>();
        rpc_handler.set_orchestrator_tx(orchestrator_tx);

        // Set keypair for signing P2P messages (for webhook progress broadcasts)
        rpc_handler.set_keypair(keypair.clone());

        // Also set the agent broadcast channel (used by route handler for /submit)
        *agent_broadcast_tx.write() = Some(rpc_broadcast_tx);

        (
            Some(rpc_server.spawn()),
            Some(rpc_handler),
            Some(rpc_broadcast_rx),
            Some(orchestrator_rx),
        )
    } else {
        info!("RPC server disabled (--rpc-port 0)");
        (None, None, None, None)
    };

    // Setup Bittensor connection (if enabled)
    // Use bittensor_rs::Subtensor directly for weight submission (handles commit-reveal automatically)
    let subtensor: Option<Arc<Subtensor>>;
    let subtensor_signer: Option<Arc<platform_bittensor::BittensorSigner>>;
    let mut block_sync: Option<BlockSync> = None;
    let mut block_sync_rx: Option<tokio::sync::mpsc::Receiver<BlockSyncEvent>> = None;

    if !args.no_bittensor {
        info!(
            "Connecting to Bittensor: {} (netuid={})",
            args.subtensor_endpoint, args.netuid
        );

        // Create Subtensor with persistence for automatic commit-reveal handling
        let state_path = data_dir.join("subtensor_state.json");
        match Subtensor::with_persistence(&args.subtensor_endpoint, state_path.clone()).await {
            Ok(st) => {
                info!("Subtensor connected with persistence at {:?}", state_path);

                // Create signer from seed
                match signer_from_seed(&bittensor_seed) {
                    Ok(signer) => {
                        info!("Bittensor hotkey: {}", signer.account_id());
                        subtensor_signer = Some(Arc::new(signer));
                    }
                    Err(e) => {
                        warn!("Failed to create Bittensor signer: {}", e);
                        subtensor_signer = None;
                    }
                }

                subtensor = Some(Arc::new(st));

                // Setup block sync with a separate connection to Bittensor
                // (BlockListener needs its own client for subscription)
                match BittensorClient::new(&args.subtensor_endpoint).await {
                    Ok(bt_client_for_sync) => {
                        let sync_config = BlockSyncConfig {
                            netuid: args.netuid,
                            channel_capacity: 100,
                        };

                        let mut sync = BlockSync::new(sync_config);
                        match sync.connect(Arc::new(bt_client_for_sync)).await {
                            Ok(_) => {
                                // Get tempo from BlockSync and update epoch config
                                let tempo = sync.tempo().await;
                                epoch_config.blocks_per_epoch = tempo;
                                epoch_config.evaluation_blocks = (tempo * 75) / 100; // 75%
                                epoch_config.commit_blocks = (tempo * 15) / 100; // 15%
                                epoch_config.reveal_blocks = tempo
                                    - epoch_config.evaluation_blocks
                                    - epoch_config.commit_blocks;

                                challenge_runtime.update_epoch_config(epoch_config.clone());

                                info!(
                                    "Using Bittensor tempo: {} blocks (eval={}, commit={}, reveal={})",
                                    tempo, epoch_config.evaluation_blocks, epoch_config.commit_blocks, epoch_config.reveal_blocks
                                );

                                block_sync_rx = sync.take_event_receiver();
                                if let Err(e) = sync.start().await {
                                    warn!("Failed to start block sync: {}", e);
                                } else {
                                    info!("Block sync started - listening to Bittensor finalized blocks");
                                }
                                block_sync = Some(sync);
                            }
                            Err(e) => {
                                warn!("Failed to connect block sync: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to create block sync client: {}", e);
                    }
                }

                // Initial metagraph sync to populate validators from Bittensor
                // IMPORTANT: Must complete before accepting peer connections to validate their stake
                info!(
                    "Waiting for metagraph sync to load validators (netuid={})...",
                    args.netuid
                );

                let max_retries = 3;
                let mut sync_success = false;

                for attempt in 1..=max_retries {
                    info!("Metagraph sync attempt {}/{}...", attempt, max_retries);

                    match BittensorClient::new(&args.subtensor_endpoint).await {
                        Ok(metagraph_client) => {
                            match sync_metagraph(&metagraph_client, args.netuid).await {
                                Ok(metagraph) => {
                                    let mut added = 0;
                                    let mut state = chain_state.write();

                                    // Debug: collect top stakes for logging
                                    let mut top_stakes: Vec<(u64, u128, u128, u128)> = metagraph
                                        .neurons
                                        .iter()
                                        .map(|(uid, n)| {
                                            (
                                                *uid,
                                                n.stake,
                                                n.root_stake,
                                                n.stake.saturating_add(n.root_stake),
                                            )
                                        })
                                        .collect();
                                    top_stakes.sort_by(|a, b| b.3.cmp(&a.3));

                                    info!("Top 10 neurons by effective stake:");
                                    for (uid, alpha, root, total) in top_stakes.iter().take(10) {
                                        info!("  UID {}: alpha={:.2} TAO, root={:.2} TAO, total={:.2} TAO",
                                            uid,
                                            *alpha as f64 / 1e9,
                                            *root as f64 / 1e9,
                                            *total as f64 / 1e9
                                        );
                                    }

                                    let mut skipped_low_stake = 0;
                                    let mut add_failed = 0;

                                    for neuron in metagraph.neurons.values() {
                                        // Convert AccountId32 hotkey to our Hotkey type
                                        let hotkey_bytes: &[u8; 32] = neuron.hotkey.as_ref();
                                        let hotkey = Hotkey(*hotkey_bytes);
                                        let hotkey_hex = hotkey.to_hex();

                                        // Use total_stake from metagraph - this is the ACTUAL stake used in consensus
                                        // It includes: alpha stake + (tao stake * tao_weight)
                                        // The runtime API calculates this including parent inheritance
                                        let stake_rao =
                                            neuron.total_stake.min(u64::MAX as u128) as u64;

                                        // ALWAYS cache stake in protection for debugging
                                        // This allows us to show actual stake when rejecting low-stake validators
                                        protection.validate_stake(&hotkey_hex, stake_rao);

                                        // Skip adding to state if below minimum stake
                                        if stake_rao < min_stake_rao {
                                            skipped_low_stake += 1;
                                            continue;
                                        }

                                        // Add validator if not already present
                                        if state.get_validator(&hotkey).is_none() {
                                            let info = ValidatorInfo::new(
                                                hotkey.clone(),
                                                Stake::new(stake_rao),
                                            );
                                            match state.add_validator(info) {
                                                Ok(_) => {
                                                    added += 1;
                                                    debug!(
                                                        "Added validator {} with {:.2} TAO",
                                                        hotkey.to_ss58(),
                                                        stake_rao as f64 / 1e9
                                                    );
                                                }
                                                Err(e) => {
                                                    add_failed += 1;
                                                    warn!(
                                                        "Failed to add validator {} ({:.2} TAO): {}",
                                                        hotkey.to_ss58(),
                                                        stake_rao as f64 / 1e9,
                                                        e
                                                    );
                                                }
                                            }
                                        } else if let Some(v) = state.validators.get_mut(&hotkey) {
                                            // Update stake for existing validator
                                            v.stake = Stake::new(stake_rao);
                                        }
                                    }

                                    if skipped_low_stake > 0 {
                                        debug!(
                                            "Skipped {} neurons with stake below {} TAO threshold",
                                            skipped_low_stake, min_stake_tao
                                        );
                                    }
                                    if add_failed > 0 {
                                        warn!(
                                            "Failed to add {} validators (check config.min_stake or max_validators)",
                                            add_failed
                                        );
                                    }

                                    info!("Metagraph sync complete: {} neurons, {} validators with sufficient stake (min {} TAO)", 
                                        metagraph.n, added, min_stake_tao);
                                    info!("Validator identity verification ready - will accept messages from {} known validators", 
                                        state.validators.len());
                                    sync_success = true;
                                    break;
                                }
                                Err(e) => {
                                    warn!("Metagraph sync attempt {} failed: {}", attempt, e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to connect for metagraph sync (attempt {}): {}",
                                attempt, e
                            );
                        }
                    }

                    if attempt < max_retries {
                        info!("Retrying metagraph sync in 5 seconds...");
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    }
                }

                if !sync_success {
                    warn!(
                        "CRITICAL: Metagraph sync failed after {} attempts!",
                        max_retries
                    );
                    warn!("Validator will only recognize itself and sudo. Other validators may be rejected.");
                    warn!("Periodic sync will retry every 10 minutes.");
                }
            }
            Err(e) => {
                warn!("Failed to connect to Subtensor: {} (continuing without)", e);
                subtensor = None;
                subtensor_signer = None;
            }
        }
    } else {
        info!("Bittensor disabled (--no-bittensor)");
        subtensor = None;
        subtensor_signer = None;
    };

    // Create message channel for consensus
    let (msg_tx, mut msg_rx) = mpsc::channel::<SignedNetworkMessage>(1000);

    // Create consensus engine (wrapped in Arc for sharing)
    let consensus = Arc::new(PBFTEngine::new(
        keypair.clone(),
        chain_state.clone(),
        msg_tx,
    ));
    consensus.sync_validators();

    // Parse bootstrap peers (default to official bootnode if not specified)
    const DEFAULT_BOOTNODE: &str = "/dns4/bootnode.platform.network/tcp/9000/p2p/12D3KooWEpZoR9A1fpMN4QGspuRSa9UYHYvnFda2GWkXXZyYgAkN";
    let bootstrap_peers: Vec<_> = if args.no_bootnode {
        info!("Bootnode connection disabled (--no-bootnode)");
        vec![]
    } else {
        args.bootstrap
            .as_ref()
            .map(|s| {
                s.split(',')
                    .filter_map(|addr| addr.trim().parse().ok())
                    .collect()
            })
            .unwrap_or_else(|| {
                // Use default bootnode
                vec![DEFAULT_BOOTNODE
                    .parse()
                    .expect("Invalid default bootnode address")]
            })
    };

    // Create network node with deterministic peer ID derived from hotkey public key
    let node_config = NodeConfig {
        listen_addr: args.listen.parse()?,
        bootstrap_peers,
        identity_seed: Some(identity_seed),
        ..Default::default()
    };

    // Pass our hotkey to the network for identify protocol (stake validation)
    let our_hotkey_hex = keypair.hotkey().to_hex();
    let mut network = NetworkNode::with_hotkey(node_config.clone(), Some(&our_hotkey_hex)).await?;
    let mut event_rx = network.take_event_receiver().unwrap();

    info!(
        "Local peer ID: {} (hotkey: {})",
        network.local_peer_id(),
        keypair.ss58_address()
    );

    // Start network
    network.start(&node_config).await?;

    // Channel for sending commands to network
    let (net_cmd_tx, mut net_cmd_rx) = mpsc::channel::<NetworkCommand>(100);

    // Spawn network event loop in a separate task
    tokio::spawn(async move {
        // Bootstrap retry interval - reconnect to bootnode if disconnected
        let mut bootstrap_retry_interval =
            tokio::time::interval(std::time::Duration::from_secs(30));
        bootstrap_retry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                // Process network commands
                Some(cmd) = net_cmd_rx.recv() => {
                    match cmd {
                        NetworkCommand::Broadcast(msg) => {
                            if let Err(e) = network.broadcast(&msg) {
                                error!("Broadcast error: {}", e);
                            }
                        }
                        NetworkCommand::BroadcastRaw(data) => {
                            // Broadcast raw bytes (from RPC sudo_submit)
                            if let Err(e) = network.broadcast_raw(data) {
                                error!("Raw broadcast error: {}", e);
                            }
                        }
                        NetworkCommand::SendResponse(channel, response) => {
                            network.send_sync_response(channel, response);
                        }
                    }
                }
                // Process swarm events
                _ = network.process_next_event() => {}
                // Retry bootstrap connection every 30s if not connected
                _ = bootstrap_retry_interval.tick() => {
                    network.retry_bootstrap_if_needed();
                }
            }
        }
    });

    // Spawn RPC broadcast forwarder (for sudo_submit)
    if let Some(mut rx) = rpc_broadcast_rx {
        let net_cmd_tx_for_rpc = net_cmd_tx.clone();
        tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                info!(
                    "Forwarding RPC broadcast ({} bytes) to P2P network",
                    data.len()
                );
                if let Err(e) = net_cmd_tx_for_rpc
                    .send(NetworkCommand::BroadcastRaw(data))
                    .await
                {
                    error!("Failed to forward RPC broadcast: {}", e);
                }
            }
        });
    }

    // Note: WASM evaluation loop disabled - Docker challenges handle their own evaluation
    // The ChallengeRuntime is kept for epoch management and weight collection only
    // tokio::spawn(async move { runtime_for_eval.run_evaluation_loop().await; });

    // Initialize Challenge Orchestrator for Docker containers (if enabled)
    let challenge_orchestrator: Option<Arc<ChallengeOrchestrator>> = if args.docker_challenges {
        info!("Initializing Docker challenge orchestrator...");
        let orchestrator_config = OrchestratorConfig {
            health_check_interval: std::time::Duration::from_secs(args.health_check_interval),
            ..Default::default()
        };

        match ChallengeOrchestrator::new(orchestrator_config).await {
            Ok(orchestrator) => {
                let orchestrator = Arc::new(orchestrator);

                // Sync with existing challenge configs from ChainState
                let configs: Vec<ChallengeContainerConfig> = {
                    let state = chain_state.read();
                    state.challenge_configs.values().cloned().collect()
                };

                if !configs.is_empty() {
                    info!("Syncing {} challenge configs from state...", configs.len());
                    if let Err(e) = orchestrator.sync_challenges(&configs).await {
                        warn!("Failed to sync challenges: {}", e);
                    }

                    // Discover routes from running containers
                    // Note: This happens at startup, so routes_map may not be available yet
                    // Routes will be discovered when containers are added via RPC
                    info!(
                        "Challenge sync complete. Routes will be discovered when RPC handler is ready."
                    );
                }

                // Start health monitoring in background
                let orchestrator_for_health = orchestrator.clone();
                tokio::spawn(async move {
                    if let Err(e) = orchestrator_for_health.start().await {
                        error!("Challenge health monitor error: {}", e);
                    }
                });

                info!("Docker challenge orchestrator started");
                Some(orchestrator)
            }
            Err(e) => {
                warn!("Failed to initialize challenge orchestrator: {}", e);
                warn!("  Make sure /var/run/docker.sock is mounted");
                None
            }
        }
    } else {
        info!("Docker challenge orchestration disabled");
        None
    };

    // Spawn orchestrator command handler (receives commands from RPC sudo_submit)
    // Also handles dynamic route discovery via /.well-known/routes
    if let (Some(mut rx), Some(orch)) = (orchestrator_cmd_rx, challenge_orchestrator.clone()) {
        let routes_map = rpc_handler.as_ref().map(|h| h.challenge_routes.clone());
        let endpoints_for_orch = challenge_endpoints.clone();
        tokio::spawn(async move {
            info!("Orchestrator command handler started (with route discovery)");
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    OrchestratorCommand::Add(config) => {
                        info!("RPC -> Orchestrator: Adding challenge '{}'", config.name);
                        if let Err(e) = orch.add_challenge(config.clone()).await {
                            error!("Failed to add challenge container '{}': {}", config.name, e);
                        } else {
                            info!("Challenge container '{}' started successfully", config.name);

                            // Get actual endpoint from orchestrator and update the endpoints map
                            let endpoint = if let Some(instance) =
                                orch.get_challenge(&config.challenge_id)
                            {
                                instance.endpoint.clone()
                            } else {
                                // Fallback to constructed URL if instance not found
                                let container_name = config.name.to_lowercase().replace(' ', "-");
                                format!("http://challenge-{}:8080", container_name)
                            };

                            // Update endpoints map for HTTP proxying (store by both UUID and name)
                            {
                                let mut eps = endpoints_for_orch.write();
                                eps.insert(config.challenge_id.to_string(), endpoint.clone());
                                eps.insert(config.name.clone(), endpoint.clone());
                            }
                            info!(
                                "Updated endpoint for challenge '{}' ({}): {}",
                                config.name, config.challenge_id, endpoint
                            );

                            // Discover routes from the container via /.well-known/routes
                            if let Some(ref routes) = routes_map {
                                let routes_url = format!("{}/.well-known/routes", endpoint);

                                // Wait a bit for container to be ready
                                tokio::time::sleep(std::time::Duration::from_secs(3)).await;

                                // Retry up to 5 times with backoff
                                for attempt in 1..=5 {
                                    match discover_routes(&routes_url).await {
                                        Ok(manifest) => {
                                            info!(
                                                "Discovered {} routes from challenge '{}' (v{})",
                                                manifest.routes.len(),
                                                manifest.name,
                                                manifest.version
                                            );

                                            // Register discovered routes
                                            let challenge_routes: Vec<
                                                platform_challenge_sdk::ChallengeRoute,
                                            > = manifest
                                                .routes
                                                .into_iter()
                                                .map(|r| {
                                                    let mut route =
                                                        platform_challenge_sdk::ChallengeRoute::new(
                                                            match r.method.as_str() {
                                                                "POST" => {
                                                                    platform_challenge_sdk::HttpMethod::Post
                                                                }
                                                                "PUT" => {
                                                                    platform_challenge_sdk::HttpMethod::Put
                                                                }
                                                                "DELETE" => {
                                                                    platform_challenge_sdk::HttpMethod::Delete
                                                                }
                                                                _ => {
                                                                    platform_challenge_sdk::HttpMethod::Get
                                                                }
                                                            },
                                                            r.path,
                                                            r.description,
                                                        );
                                                    route.requires_auth = r.requires_auth;
                                                    route.rate_limit = r.rate_limit;
                                                    route
                                                })
                                                .collect();

                                            routes
                                                .write()
                                                .insert(manifest.name.clone(), challenge_routes);
                                            info!(
                                                "Registered routes for challenge '{}'",
                                                manifest.name
                                            );
                                            break;
                                        }
                                        Err(e) => {
                                            if attempt < 5 {
                                                warn!(
                                                    "Route discovery attempt {}/5 failed for '{}': {} (retrying...)",
                                                    attempt, config.name, e
                                                );
                                                tokio::time::sleep(std::time::Duration::from_secs(
                                                    attempt as u64 * 2,
                                                ))
                                                .await;
                                            } else {
                                                error!(
                                                    "Route discovery failed for '{}' after 5 attempts: {}",
                                                    config.name, e
                                                );
                                                // Fall back to standard routes
                                                let default_routes = vec![
                                                    platform_challenge_sdk::ChallengeRoute::post(
                                                        "/submit",
                                                        "Submit an agent",
                                                    ),
                                                    platform_challenge_sdk::ChallengeRoute::get(
                                                        "/status/:hash",
                                                        "Get agent status",
                                                    ),
                                                    platform_challenge_sdk::ChallengeRoute::get(
                                                        "/leaderboard",
                                                        "Get leaderboard",
                                                    ),
                                                    platform_challenge_sdk::ChallengeRoute::get(
                                                        "/config",
                                                        "Get challenge config",
                                                    ),
                                                    platform_challenge_sdk::ChallengeRoute::get(
                                                        "/stats",
                                                        "Get statistics",
                                                    ),
                                                    platform_challenge_sdk::ChallengeRoute::get(
                                                        "/health",
                                                        "Health check",
                                                    ),
                                                ];
                                                routes
                                                    .write()
                                                    .insert(config.name.clone(), default_routes);
                                                warn!("Using default routes for '{}'", config.name);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    OrchestratorCommand::Update(config) => {
                        info!("RPC -> Orchestrator: Updating challenge '{}'", config.name);
                        if let Err(e) = orch.update_challenge(config.clone()).await {
                            error!(
                                "Failed to update challenge container '{}': {}",
                                config.name, e
                            );
                        }
                    }
                    OrchestratorCommand::Remove(id) => {
                        info!("RPC -> Orchestrator: Removing challenge {:?}", id);
                        if let Err(e) = orch.remove_challenge(id).await {
                            error!("Failed to remove challenge container {:?}: {}", id, e);
                        }
                    }
                }
            }
        });
    }

    // Spawn startup route discovery task for pre-existing challenges
    // This runs after RPC is ready and discovers routes from containers started at sync
    if let (Some(ref handler), Some(ref orch)) = (&rpc_handler, &challenge_orchestrator) {
        let routes_map = handler.challenge_routes.clone();
        let state_for_discovery = chain_state.clone();
        let orch_for_discovery = orch.clone();
        tokio::spawn(async move {
            // Wait for containers to be fully started
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            let configs: Vec<ChallengeContainerConfig> = {
                let state = state_for_discovery.read();
                state.challenge_configs.values().cloned().collect()
            };

            for config in configs {
                // Get actual endpoint from orchestrator (includes validator suffix in dev mode)
                let routes_url = if let Some(instance) =
                    orch_for_discovery.get_challenge(&config.challenge_id)
                {
                    format!("{}/.well-known/routes", instance.endpoint)
                } else {
                    // Fallback to constructed URL if instance not found
                    let container_name = config.name.to_lowercase().replace(' ', "-");
                    format!(
                        "http://challenge-{}:8080/.well-known/routes",
                        container_name
                    )
                };

                info!(
                    "Discovering routes for startup challenge '{}'...",
                    config.name
                );

                match discover_routes(&routes_url).await {
                    Ok(manifest) => {
                        info!(
                            "Discovered {} routes from '{}' (v{})",
                            manifest.routes.len(),
                            manifest.name,
                            manifest.version
                        );

                        let challenge_routes: Vec<platform_challenge_sdk::ChallengeRoute> =
                            manifest
                                .routes
                                .into_iter()
                                .map(|r| {
                                    let mut route = platform_challenge_sdk::ChallengeRoute::new(
                                        match r.method.as_str() {
                                            "POST" => platform_challenge_sdk::HttpMethod::Post,
                                            "PUT" => platform_challenge_sdk::HttpMethod::Put,
                                            "DELETE" => platform_challenge_sdk::HttpMethod::Delete,
                                            _ => platform_challenge_sdk::HttpMethod::Get,
                                        },
                                        r.path,
                                        r.description,
                                    );
                                    route.requires_auth = r.requires_auth;
                                    route.rate_limit = r.rate_limit;
                                    route
                                })
                                .collect();

                        routes_map.write().insert(manifest.name, challenge_routes);
                    }
                    Err(e) => {
                        warn!(
                            "Failed to discover routes for '{}': {} (using defaults)",
                            config.name, e
                        );
                        // Use default routes
                        let default_routes = vec![
                            platform_challenge_sdk::ChallengeRoute::post(
                                "/submit",
                                "Submit an agent",
                            ),
                            platform_challenge_sdk::ChallengeRoute::get(
                                "/status/:hash",
                                "Get agent status",
                            ),
                            platform_challenge_sdk::ChallengeRoute::get(
                                "/leaderboard",
                                "Get leaderboard",
                            ),
                            platform_challenge_sdk::ChallengeRoute::get(
                                "/config",
                                "Get challenge config",
                            ),
                            platform_challenge_sdk::ChallengeRoute::get("/stats", "Get statistics"),
                            platform_challenge_sdk::ChallengeRoute::get("/health", "Health check"),
                        ];
                        routes_map
                            .write()
                            .insert(config.name.clone(), default_routes);
                    }
                }
            }
            info!("Startup route discovery complete");
        });
    }

    // Spawn P2P outbox polling task for challenge containers
    // This polls each container's /p2p/outbox endpoint and broadcasts messages to the network
    if let Some(ref _orch) = challenge_orchestrator {
        let state_for_outbox = chain_state.clone();
        let net_cmd_tx_for_outbox = net_cmd_tx.clone();
        let keypair_for_outbox = keypair.clone();

        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let poll_interval = std::time::Duration::from_secs(5);

            loop {
                tokio::time::sleep(poll_interval).await;

                // Get all challenge containers
                let configs: Vec<ChallengeContainerConfig> = {
                    let state = state_for_outbox.read();
                    state.challenge_configs.values().cloned().collect()
                };

                for config in configs {
                    let container_name = config.name.to_lowercase().replace([' ', '_'], "-");
                    let outbox_url = format!("http://challenge-{}:8080/p2p/outbox", container_name);

                    match client.get(&outbox_url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            if let Ok(outbox) = resp.json::<serde_json::Value>().await {
                                if let Some(messages) =
                                    outbox.get("messages").and_then(|m| m.as_array())
                                {
                                    for msg_value in messages {
                                        // Parse the outbox message
                                        if let (Some(message), target) = (
                                            msg_value.get("message"),
                                            msg_value.get("target").and_then(|t| t.as_str()),
                                        ) {
                                            // Check if this is a DecryptApiKeyRequest - handle locally
                                            if let Ok(platform_challenge_sdk::ChallengeP2PMessage::DecryptApiKeyRequest(req)) =
                                                serde_json::from_value::<platform_challenge_sdk::ChallengeP2PMessage>(message.clone()) {
                                                    // Decrypt the API key locally and send response back to container
                                                    let response = match platform_challenge_sdk::decrypt_api_key(
                                                        &req.encrypted_key,
                                                        &keypair_for_outbox.seed(),
                                                    ) {
                                                        Ok(api_key) => {
                                                            info!("Decrypted API key for agent {} (request {})", &req.agent_hash[..16.min(req.agent_hash.len())], &req.request_id[..8]);
                                                            platform_challenge_sdk::DecryptApiKeyResponse {
                                                                challenge_id: req.challenge_id.clone(),
                                                                agent_hash: req.agent_hash.clone(),
                                                                request_id: req.request_id.clone(),
                                                                success: true,
                                                                api_key: Some(api_key),
                                                                error: None,
                                                            }
                                                        }
                                                        Err(e) => {
                                                            warn!("Failed to decrypt API key for agent {}: {}", &req.agent_hash[..16.min(req.agent_hash.len())], e);
                                                            platform_challenge_sdk::DecryptApiKeyResponse {
                                                                challenge_id: req.challenge_id.clone(),
                                                                agent_hash: req.agent_hash.clone(),
                                                                request_id: req.request_id.clone(),
                                                                success: false,
                                                                api_key: None,
                                                                error: Some(e.to_string()),
                                                            }
                                                        }
                                                    };

                                                    // Send response back to container via P2P message endpoint
                                                    let p2p_response = platform_challenge_sdk::ChallengeP2PMessage::DecryptApiKeyResponse(response);
                                                    let p2p_endpoint = format!("http://challenge-{}:8080/p2p/message", container_name);
                                                    let req_body = serde_json::json!({
                                                        "from_hotkey": keypair_for_outbox.hotkey().to_hex(),
                                                        "message": p2p_response
                                                    });

                                                    if let Err(e) = client.post(&p2p_endpoint).json(&req_body).send().await {
                                                        debug!("Failed to send decrypt response to container: {}", e);
                                                    }
                                                    continue; // Don't broadcast this message
                                            }

                                            // Create ChallengeNetworkMessage to broadcast
                                            let challenge_msg = ChallengeNetworkMessage {
                                                challenge_id: config.name.clone(),
                                                message_type: ChallengeMessageType::Custom(
                                                    "p2p_bridge".to_string(),
                                                ),
                                                payload: serde_json::to_vec(message)
                                                    .unwrap_or_default(),
                                            };

                                            let network_msg =
                                                NetworkMessage::ChallengeMessage(challenge_msg);
                                            if let Ok(signed) = SignedNetworkMessage::new(
                                                network_msg,
                                                &keypair_for_outbox,
                                            ) {
                                                if target.is_some() {
                                                    // TODO: Implement targeted send to specific validator
                                                    debug!("Targeted P2P send not yet implemented");
                                                } else {
                                                    // Broadcast to all
                                                    if let Err(e) = net_cmd_tx_for_outbox
                                                        .send(NetworkCommand::Broadcast(signed))
                                                        .await
                                                    {
                                                        debug!("Failed to broadcast outbox message: {}", e);
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    let count = messages.len();
                                    if count > 0 {
                                        debug!(
                                            "Broadcast {} P2P messages from container '{}'",
                                            count, config.name
                                        );
                                    }
                                }
                            }
                        }
                        Ok(_) => {
                            // Container might not be ready yet, silently ignore
                        }
                        Err(_) => {
                            // Container might not be running, silently ignore
                        }
                    }
                }
            }
        });
        info!("P2P outbox polling task started (interval: 5s)");
    }

    // Main event loop
    info!("Validator node running. Press Ctrl+C to stop.");

    let chain_state_clone = chain_state.clone();
    // Clone keypair and auth sessions for P2P message handling
    let keypair_for_p2p = Some(keypair.clone());
    let auth_sessions_for_p2p = Some(container_auth_sessions.clone());
    // Get challenge_routes Arc for auto-registration when receiving via P2P
    let challenge_routes_for_p2p = rpc_handler.as_ref().map(|h| h.challenge_routes.clone());
    // Get challenge_endpoints Arc for endpoint updates when starting containers from P2P
    let endpoints_for_p2p = Some(challenge_endpoints.clone());
    // Get distributed_db for P2P message handling
    let db_for_p2p = Some(distributed_db.clone());
    let storage = Arc::new(storage); // Keep reference for state persistence
    let runtime_for_blocks = challenge_runtime.clone();
    let subtensor_clone = subtensor.clone();
    let subtensor_signer_clone = subtensor_signer.clone();
    let db_for_blocks = distributed_db.clone();
    let db_sync_for_loop = db_sync_manager.clone();
    let mut block_counter = 0u64;
    let use_bittensor_blocks = block_sync_rx.is_some();
    let netuid = args.netuid;
    let subtensor_endpoint = args.subtensor_endpoint.clone();
    let mut last_metagraph_sync = std::time::Instant::now();
    let metagraph_sync_interval = std::time::Duration::from_secs(600); // Sync metagraph every 10 minutes

    // Fetch mechanism count from Bittensor and submit initial weights
    // This prevents vtrust penalty from not having set weights yet
    let subnet_mechanism_count: u8 = if let Some(ref st) = subtensor {
        match st.get_mechanism_count(netuid).await {
            Ok(count) => {
                info!(
                    "Subnet has {} mechanisms (IDs: 0 to {})",
                    count,
                    count.saturating_sub(1)
                );
                count
            }
            Err(e) => {
                warn!("Failed to fetch mechanism count, assuming 1: {}", e);
                1
            }
        }
    } else {
        1
    };

    // Submit initial weights on startup for ALL mechanisms
    // But first check if we have pending commits from a previous session
    // Note: With Subtensor, calling set_weights() will automatically reveal pending commits first
    if let (Some(st), Some(signer)) = (subtensor.as_ref(), subtensor_signer.as_ref()) {
        // Get current epoch from Bittensor (for logging)
        let _current_epoch = match st.get_current_epoch(netuid).await {
            Ok(epoch) => {
                info!("Current Bittensor epoch: {}", epoch);
                epoch
            }
            Err(e) => {
                warn!("Failed to get current epoch: {}, using 0", e);
                0
            }
        };

        // Check if we have pending commits from a previous session
        if st.has_pending_commits().await {
            info!(
                "Found pending commits from previous session: {}",
                st.pending_commits_info().await
            );

            // Check if we're currently in the reveal window - if so, reveal immediately!
            match st.is_in_reveal_phase(netuid).await {
                Ok(true) => {
                    info!("Currently in reveal window - revealing pending commits immediately...");
                    match st
                        .reveal_all_pending(signer, ExtrinsicWait::Finalized)
                        .await
                    {
                        Ok(results) => {
                            for resp in &results {
                                if resp.success {
                                    info!(
                                        "Pending weights revealed on startup: {:?}",
                                        resp.tx_hash
                                    );
                                }
                            }
                        }
                        Err(e) => error!("Failed to reveal pending commits on startup: {}", e),
                    }
                }
                Ok(false) => {
                    info!("Not in reveal window yet - next set_weights() call will reveal automatically");
                }
                Err(e) => {
                    warn!(
                        "Failed to check reveal phase: {} - next set_weights() will handle it",
                        e
                    );
                }
            }
            // Proceed with initial weight submission
            info!(
                "Submitting initial weights on startup for {} mechanisms...",
                subnet_mechanism_count
            );

            // Get registered challenge mechanisms
            let registered_mechanisms = challenge_runtime.get_registered_mechanism_ids();
            let registered_set: std::collections::HashSet<u8> =
                registered_mechanisms.iter().copied().collect();

            // Build weights for ALL mechanisms (0 to count-1) and submit
            for mechanism_id in 0..subnet_mechanism_count {
                let (uids, weights) = if registered_set.contains(&mechanism_id) {
                    // This mechanism has a challenge - check for evaluation weights
                    let eval_weights = challenge_runtime.get_mechanism_weights_for_submission();
                    if let Some((_, u, w)) =
                        eval_weights.iter().find(|(m, _, _)| *m == mechanism_id)
                    {
                        info!(
                            "Mechanism {} has evaluation weights ({} entries)",
                            mechanism_id,
                            u.len()
                        );
                        (u.clone(), w.clone())
                    } else {
                        // Challenge registered but no evaluations yet - burn weights
                        info!(
                            "Mechanism {} (challenge registered) - submitting burn weights",
                            mechanism_id
                        );
                        (vec![0u16], vec![65535u16])
                    }
                } else {
                    // No challenge for this mechanism - burn weights to UID 0
                    info!(
                        "Mechanism {} (no challenge) - submitting burn weights to UID 0",
                        mechanism_id
                    );
                    (vec![0u16], vec![65535u16])
                };

                // Submit weights using Subtensor (handles commit-reveal automatically)
                match st
                    .set_mechanism_weights(
                        signer,
                        netuid,
                        mechanism_id,
                        &uids,
                        &weights,
                        1, // version_key
                        ExtrinsicWait::Finalized,
                    )
                    .await
                {
                    Ok(resp) => {
                        if resp.success {
                            info!(
                                "Mechanism {} initial weights submitted: {:?}",
                                mechanism_id, resp.tx_hash
                            );
                        } else {
                            warn!(
                                "Mechanism {} weight submission failed: {}",
                                mechanism_id, resp.message
                            );
                        }
                    }
                    Err(e) => warn!("Failed to submit mechanism {} weights: {}", mechanism_id, e),
                }
            }
        }
    }

    loop {
        tokio::select! {
            // Handle Bittensor block sync events (if connected)
            Some(event) = async {
                match &mut block_sync_rx {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match event {
                    BlockSyncEvent::NewBlock { block_number, epoch_info } => {
                        let secs_remaining = epoch_info.blocks_remaining * 12;
                        let mins = secs_remaining / 60;
                        let secs = secs_remaining % 60;
                        debug!(
                            "Bittensor block {}: epoch={}, phase={}, remaining={} blocks (~{}m{}s)",
                            block_number, epoch_info.epoch_number, epoch_info.phase,
                            epoch_info.blocks_remaining, mins, secs
                        );

                        // Process block in challenge runtime
                        if let Err(e) = runtime_for_blocks.on_new_block(block_number).await {
                            error!("Block processing error: {}", e);
                        }

                        // Confirm pending transactions in distributed DB at this block
                        match db_for_blocks.confirm_block(block_number) {
                            Ok(confirmation) => {
                                if confirmation.confirmed_count > 0 {
                                    debug!(
                                        "Confirmed {} transactions at block {}, state root: {}",
                                        confirmation.confirmed_count,
                                        block_number,
                                        hex::encode(&confirmation.state_root[..8])
                                    );
                                }
                            }
                            Err(e) => {
                                warn!("Failed to confirm block in distributed DB: {}", e);
                            }
                        }

                        // Update chain state block height
                        chain_state_clone.write().block_height = block_number;
                    }
                    BlockSyncEvent::EpochTransition { old_epoch, new_epoch, block } => {
                        // tempo blocks until next epoch = tempo * 12 seconds
                        let tempo = if let Some(ref sync) = block_sync {
                            sync.tempo().await
                        } else { 360 };
                        let secs_until_next = tempo * 12;
                        let mins = secs_until_next / 60;
                        info!(
                            "Bittensor epoch transition: {} -> {} at block {} (next in ~{}min)",
                            old_epoch, new_epoch, block, mins
                        );
                    }
                    BlockSyncEvent::PhaseChange { block_number, old_phase, new_phase, epoch } => {
                        info!(
                            "Bittensor phase change at block {}: {} -> {} (epoch {})",
                            block_number, old_phase, new_phase, epoch
                        );
                    }
                    BlockSyncEvent::CommitWindowOpen { epoch, block } => {
                        info!("Commit window opened for epoch {} at block {}", epoch, block);

                        // Collect and commit weights for all mechanisms
                        // With Subtensor, set_weights() handles commit-reveal automatically
                        if let (Some(st), Some(signer)) = (subtensor_clone.as_ref(), subtensor_signer_clone.as_ref()) {
                            // Collect weights from all challenges
                            let mechanism_weights = runtime_for_blocks.collect_and_get_weights().await;

                            let weights_to_submit = if mechanism_weights.is_empty() {
                                // No challenge weights - submit burn weights to UID 0
                                info!("No challenge weights for epoch {} - submitting burn weights", epoch);
                                vec![(0u8, vec![0u16], vec![65535u16])]
                            } else {
                                info!("Submitting weights for {} mechanisms", mechanism_weights.len());
                                mechanism_weights
                            };

                            // Submit each mechanism's weights (Subtensor handles commit-reveal)
                            for (mechanism_id, uids, weights) in weights_to_submit {
                                match st.set_mechanism_weights(
                                    signer,
                                    netuid,
                                    mechanism_id,
                                    &uids,
                                    &weights,
                                    1,
                                    ExtrinsicWait::Finalized,
                                ).await {
                                    Ok(resp) if resp.success => {
                                        info!("Mechanism {} weights submitted: {:?}", mechanism_id, resp.tx_hash);
                                    }
                                    Ok(resp) => {
                                        warn!("Mechanism {} submission issue: {}", mechanism_id, resp.message);
                                    }
                                    Err(e) => error!("Failed to submit mechanism {} weights: {}", mechanism_id, e),
                                }
                            }
                        }
                    }
                    BlockSyncEvent::RevealWindowOpen { epoch, block } => {
                        info!("Reveal window opened for epoch {} at block {}", epoch, block);

                        // With Subtensor, reveals are handled automatically by set_weights()
                        // But we can force reveal any remaining pending commits here
                        if let (Some(st), Some(signer)) = (subtensor_clone.as_ref(), subtensor_signer_clone.as_ref()) {
                            if st.has_pending_commits().await {
                                info!("Revealing pending commits...");
                                match st.reveal_all_pending(signer, ExtrinsicWait::Finalized).await {
                                    Ok(results) => {
                                        for resp in results {
                                            if resp.success {
                                                info!("Weights revealed: {:?}", resp.tx_hash);
                                            }
                                        }
                                    }
                                    Err(e) => error!("Failed to reveal pending weights: {}", e),
                                }
                            }
                        }
                    }
                    BlockSyncEvent::Disconnected(err) => {
                        warn!("Bittensor connection lost: {}", err);
                    }
                    BlockSyncEvent::Reconnected => {
                        info!("Bittensor connection restored");
                    }
                }
            }

            // Handle network events
            Some(event) = event_rx.recv() => {
                match event {
                    NetworkEvent::PeerConnected(peer) => {
                        let peer_str = peer.to_string();

                        // Check if peer is blacklisted
                        if protection.is_peer_blacklisted(&peer_str) {
                            warn!("Rejected blacklisted peer: {}", peer);
                            // Peer disconnect handled
                            continue;
                        }

                        // Update RPC handler peer list
                        if let Some(ref handler) = rpc_handler {
                            handler.add_peer(peer_str.clone());
                        }

                        debug!("Peer connected: {} (awaiting identify)", peer);
                        // Hotkey and stake validation happens in PeerIdentified event
                    }
                    NetworkEvent::PeerIdentified { peer_id, hotkey, agent_version } => {
                        let peer_str = peer_id.to_string();
                        let should_validate_stake = protection.config().validate_stake;

                        if let Some(ref hk) = hotkey {
                            // Convert hex hotkey to SS58 for display
                            let ss58 = if let Ok(bytes) = hex::decode(hk) {
                                if bytes.len() == 32 {
                                    let hotkey_obj = Hotkey(bytes.try_into().unwrap());
                                    hotkey_obj.to_ss58()
                                } else {
                                    hk[..16.min(hk.len())].to_string()
                                }
                            } else {
                                hk[..16.min(hk.len())].to_string()
                            };

                            // Skip stake validation if disabled (--no-bittensor mode)
                            if !should_validate_stake {
                                protection.check_hotkey_connection(hk, &peer_str, None);
                                info!("Peer identified: {} (hotkey: {}, stake: N/A - local mode)", peer_id, ss58);
                                continue;
                            }

                            // Validate stake immediately and get actual stake for logging
                            let (has_sufficient_stake, actual_stake_tao) = {
                                if let Ok(bytes) = hex::decode(hk) {
                                    if bytes.len() == 32 {
                                        let hotkey_obj = Hotkey(bytes.try_into().unwrap());
                                        let state = chain_state_clone.read();
                                        if let Some(validator) = state.get_validator(&hotkey_obj) {
                                            let stake = validator.stake.0 as f64 / 1e9;
                                            (validator.stake.0 >= min_stake_rao, Some(stake))
                                        } else {
                                            // Check cached stake
                                            match protection.check_cached_stake(hk) {
                                                Some(platform_network::StakeValidation::Valid { stake_tao }) => {
                                                    (true, Some(stake_tao))
                                                }
                                                Some(platform_network::StakeValidation::Insufficient { stake_tao, .. }) => {
                                                    (false, Some(stake_tao))
                                                }
                                                _ => (false, None)
                                            }
                                        }
                                    } else {
                                        (false, None)
                                    }
                                } else {
                                    (false, None)
                                }
                            };

                            if has_sufficient_stake {
                                // Track hotkey connection
                                protection.check_hotkey_connection(hk, &peer_str, None);
                                let stake_display = actual_stake_tao.map(|s| format!("{:.2} TAO", s)).unwrap_or_else(|| "OK".to_string());
                                info!("Peer identified: {} (hotkey: {}, stake: {})", peer_id, ss58, stake_display);
                            } else {
                                // Show actual stake if known for better debugging
                                match actual_stake_tao {
                                    Some(stake) => {
                                        warn!(
                                            "Peer {} has insufficient stake (hotkey: {}, stake: {:.2} TAO, required: {} TAO)",
                                            peer_id, ss58, stake, min_stake_tao
                                        );
                                    }
                                    None => {
                                        warn!(
                                            "Peer {} not in metagraph (hotkey: {}, required: {} TAO on subnet {})",
                                            peer_id, ss58, min_stake_tao, args.netuid
                                        );
                                    }
                                }
                                // Don't disconnect - they may still provide useful gossip
                                // But we won't accept their signed messages
                            }
                        } else {
                            // No hotkey in identify - old client or non-validator
                            debug!(
                                "Peer {} did not provide hotkey in identify (agent: {})",
                                peer_id, agent_version
                            );
                        }
                    }
                    NetworkEvent::PeerDisconnected(peer) => {
                        let peer_str = peer.to_string();
                        // Clean up hotkey tracking for this peer
                        protection.disconnect_hotkey(&peer_str);
                        // Update RPC handler peer list
                        if let Some(ref handler) = rpc_handler {
                            handler.remove_peer(&peer_str);
                        }
                        // Try to get SS58 from protection tracking for better logging
                        info!("Peer disconnected: {}", peer);
                    }
                    NetworkEvent::MessageReceived { from, data } => {
                        // Rate limiting check
                        let peer_str = from.to_string();
                        if !protection.check_rate_limit(&peer_str) {
                            warn!("Rate limit exceeded for peer: {}", peer_str);
                            protection.blacklist_peer(
                                &peer_str,
                                std::time::Duration::from_secs(300), // 5 min ban
                                "Rate limit exceeded".to_string(),
                            );
                            continue;
                        }

                        if let Ok(signed) = bincode::deserialize::<SignedNetworkMessage>(&data) {
                            if signed.verify().unwrap_or(false) {
                                // Validate stake from signer
                                let signer_hex = signed.signer().to_hex();

                                // Track hotkey connection (disconnects old peer if hotkey reconnects)
                                // This handles validator restarts with new peer_id
                                protection.check_hotkey_connection(
                                    &signer_hex,
                                    &peer_str,
                                    None, // IP extracted separately if needed
                                );

                                // Check if we have a validator with sufficient stake
                                let (has_sufficient_stake, actual_stake_tao) = {
                                    let state = chain_state_clone.read();
                                    if let Some(validator) = state.get_validator(signed.signer()) {
                                        let actual = validator.stake.0 as f64 / 1e9;
                                        (validator.stake.0 >= min_stake_rao, Some(actual))
                                    } else {
                                        // Unknown validator - check against cached stake
                                        match protection.check_cached_stake(&signer_hex) {
                                            Some(platform_network::StakeValidation::Valid { stake_tao }) => {
                                                (true, Some(stake_tao))
                                            }
                                            Some(platform_network::StakeValidation::Insufficient { stake_tao, .. }) => {
                                                (false, Some(stake_tao))
                                            }
                                            _ => {
                                                // Not in metagraph at all
                                                (false, None)
                                            }
                                        }
                                    }
                                };

                                if has_sufficient_stake {
                                    // Forward all messages to consensus handler
                                    handle_message(&consensus, signed, &chain_state_clone, challenge_orchestrator.as_ref(), challenge_routes_for_p2p.as_ref(), endpoints_for_p2p.as_ref(), db_for_p2p.as_ref(), keypair_for_p2p.as_ref(), auth_sessions_for_p2p.as_ref()).await;
                                } else {
                                    // Allow Sudo to bypass stake check for bootstrapping and upgrades
                                    let is_sudo = {
                                        let state = chain_state_clone.read();
                                        state.is_sudo(signed.signer())
                                    };

                                    if is_sudo {
                                        info!("Bypassing stake check for Sudo message from {}", &signer_hex[..16]);
                                        handle_message(&consensus, signed, &chain_state_clone, challenge_orchestrator.as_ref(), challenge_routes_for_p2p.as_ref(), endpoints_for_p2p.as_ref(), db_for_p2p.as_ref(), keypair_for_p2p.as_ref(), auth_sessions_for_p2p.as_ref()).await;
                                    } else {
                                        // Show actual stake if known, otherwise indicate not in metagraph
                                        let signer_ss58 = signed.signer().to_ss58();
                                        match actual_stake_tao {
                                            Some(stake) => {
                                                warn!(
                                                    "Rejected message from {} (SS58: {}) - stake {:.2} TAO below minimum {} TAO",
                                                    &signer_hex[..16], signer_ss58, stake, min_stake_tao
                                                );
                                            }
                                            None => {
                                                warn!(
                                                    "Rejected message from {} (SS58: {}) - not registered on subnet {} (min {} TAO required)",
                                                    &signer_hex[..16], signer_ss58, args.netuid, min_stake_tao
                                                );
                                            }
                                        }
                                    }
                                }
                            } else {
                                warn!("Invalid signature from {:?}", from);
                            }
                        }
                    }
                    NetworkEvent::SyncRequest { from: _, request, channel } => {
                        let response = handle_sync_request(&chain_state_clone, &request);
                        let _ = net_cmd_tx.send(NetworkCommand::SendResponse(channel, response)).await;
                    }
                }
            }

            // Handle outgoing messages from consensus
            Some(msg) = msg_rx.recv() => {
                let _ = net_cmd_tx.send(NetworkCommand::Broadcast(msg)).await;
            }

            // Handle challenge runtime events
            Some(event) = runtime_event_rx.recv() => {
                match event {
                    RuntimeEvent::ChallengeLoaded { id, name, mechanism_id } => {
                        info!("Challenge loaded: {} ({}) -> mechanism {}", name, id, mechanism_id);
                    }
                    RuntimeEvent::ChallengeUnloaded { id } => {
                        info!("Challenge unloaded: {:?}", id);
                    }
                    RuntimeEvent::EvaluationCompleted { challenge_id, job_id, result } => {
                        info!(
                            "Evaluation completed: challenge={:?}, job={}, score={:.4}",
                            challenge_id, job_id, result.score
                        );
                    }
                    RuntimeEvent::EvaluationFailed { challenge_id, job_id, error } => {
                        error!(
                            "Evaluation failed: challenge={:?}, job={}, error={}",
                            challenge_id, job_id, error
                        );
                    }
                    RuntimeEvent::WeightsCollected { epoch, mechanisms } => {
                        info!("Weights collected for epoch {}: {} mechanisms", epoch, mechanisms.len());
                    }
                    RuntimeEvent::MechanismWeightsCommitted { mechanism_id, epoch, commit_hash } => {
                        info!("Mechanism {} weights committed for epoch {}: hash={}", mechanism_id, epoch, &commit_hash[..16]);
                    }
                    RuntimeEvent::MechanismWeightsRevealed { mechanism_id, epoch, num_weights } => {
                        info!("Mechanism {} weights revealed for epoch {}: {} weights", mechanism_id, epoch, num_weights);
                    }
                    RuntimeEvent::WeightsReadyForSubmission { epoch, mechanism_weights } => {
                        let is_empty = mechanism_weights.is_empty();
                        info!(
                            "Epoch {} weights ready for Bittensor: {} mechanisms",
                            epoch, mechanism_weights.len()
                        );

                        // Submit weights to Bittensor if connected
                        if let (Some(st), Some(signer)) = (subtensor_clone.as_ref(), subtensor_signer_clone.as_ref()) {
                            let weights_to_submit = if is_empty {
                                // No challenges configured - submit default weights to UID 0 (burn)
                                warn!(
                                    "No challenge weights for epoch {} - submitting default burn weights to UID 0",
                                    epoch
                                );
                                vec![(0u8, vec![0u16], vec![65535u16])]
                            } else {
                                mechanism_weights
                            };

                            for (mechanism_id, uids, weights) in weights_to_submit {
                                match st.set_mechanism_weights(
                                    signer,
                                    netuid,
                                    mechanism_id,
                                    &uids,
                                    &weights,
                                    1,
                                    ExtrinsicWait::Finalized,
                                ).await {
                                    Ok(resp) if resp.success => {
                                        info!("Mechanism {} weights submitted: {:?}", mechanism_id, resp.tx_hash);
                                    }
                                    Ok(resp) => {
                                        warn!("Mechanism {} submission issue: {}", mechanism_id, resp.message);
                                    }
                                    Err(e) => error!("Failed to submit mechanism {} weights: {}", mechanism_id, e),
                                }
                            }
                        }
                    }
                    RuntimeEvent::EpochTransition(transition) => {
                        info!("Epoch transition: {:?}", transition);

                        // Fallback: trigger pending reveals on internal phase detection
                        if let EpochTransition::PhaseChange { new_phase: EpochPhase::Reveal, .. } = transition {
                            if let (Some(st), Some(signer)) = (subtensor_clone.as_ref(), subtensor_signer_clone.as_ref()) {
                                if st.has_pending_commits().await {
                                    info!("Reveal phase detected (internal) - revealing pending commits...");
                                    match st.reveal_all_pending(signer, ExtrinsicWait::Finalized).await {
                                        Ok(results) => {
                                            for resp in results {
                                                if resp.success {
                                                    info!("Weights revealed: {:?}", resp.tx_hash);
                                                }
                                            }
                                        }
                                        Err(e) => error!("Failed to reveal pending weights: {}", e),
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Simulated block timer (only used when Bittensor is disabled)
            _ = async {
                if use_bittensor_blocks {
                    // When using Bittensor blocks, just do periodic maintenance
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await
                } else {
                    // Simulate blocks when not connected to Bittensor
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await
                }
            } => {
                if !use_bittensor_blocks {
                    // Simulate new block only when not using Bittensor
                    block_counter += 1;

                    if let Err(e) = runtime_for_blocks.on_new_block(block_counter).await {
                        error!("Block processing error: {}", e);
                    }
                }

                // Periodic maintenance (every 10 simulated blocks or 10 seconds)
                if block_counter.is_multiple_of(10) || use_bittensor_blocks {
                    if let Err(e) = consensus.check_timeouts().await {
                        error!("Timeout check error: {}", e);
                    }

                    // Persist state periodically (challenge_configs, etc.)
                    {
                        let state = chain_state.read();
                        if let Err(e) = storage.save_state(&state) {
                            warn!("Failed to persist state: {}", e);
                        }
                    }

                    // Cleanup expired protection entries
                    protection.cleanup();

                    // Cleanup stale hotkey connections (no heartbeat for 5 minutes)
                    protection.cleanup_stale_hotkeys(std::time::Duration::from_secs(300));

                    // Periodic metagraph sync to update validators from Bittensor
                    if use_bittensor_blocks && last_metagraph_sync.elapsed() >= metagraph_sync_interval {
                        last_metagraph_sync = std::time::Instant::now();
                        let endpoint = subtensor_endpoint.clone();
                        let chain_state_for_sync = chain_state.clone();
                        let protection_for_sync = protection.clone();
                        let min_stake_for_sync = min_stake_rao;

                        tokio::spawn(async move {
                            match BittensorClient::new(&endpoint).await {
                                Ok(client) => {
                                    match sync_metagraph(&client, netuid).await {
                                        Ok(metagraph) => {
                                            let mut added = 0;
                                            let mut updated = 0;
                                            let mut state = chain_state_for_sync.write();

                                            for neuron in metagraph.neurons.values() {
                                                let hotkey_bytes: &[u8; 32] = neuron.hotkey.as_ref();
                                                let hotkey = Hotkey(*hotkey_bytes);
                                                let hotkey_hex = hotkey.to_hex();

                                                // Use total_stake from metagraph (includes parent inheritance + TAO weight)
                                                let stake_rao = neuron.total_stake.min(u64::MAX as u128) as u64;

                                                // ALWAYS update stake cache for debugging (even low-stake validators)
                                                protection_for_sync.validate_stake(&hotkey_hex, stake_rao);

                                                // Only add to state if sufficient stake
                                                if stake_rao < min_stake_for_sync {
                                                    continue;
                                                }

                                                if state.get_validator(&hotkey).is_none() {
                                                    let info = ValidatorInfo::new(hotkey.clone(), Stake::new(stake_rao));
                                                    if state.add_validator(info).is_ok() {
                                                        added += 1;
                                                    }
                                                } else if let Some(v) = state.validators.get_mut(&hotkey) {
                                                    if v.stake.0 != stake_rao {
                                                        v.stake = Stake::new(stake_rao);
                                                        updated += 1;
                                                    }
                                                }
                                            }

                                            if added > 0 || updated > 0 {
                                                info!("Metagraph periodic sync: {} added, {} updated (total: {} validators)",
                                                    added, updated, state.validators.len());
                                            }
                                        }
                                        Err(e) => {
                                            warn!("Periodic metagraph sync failed: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    debug!("Failed to connect for metagraph sync: {}", e);
                                }
                            }
                        });
                    }

                    // Log protection stats periodically
                    let prot_stats = protection.stats();
                    let connected_validators = protection.connected_validator_count();
                    if prot_stats.blacklisted_peers > 0 || prot_stats.blacklisted_ips > 0 || connected_validators > 0 {
                        debug!(
                            "Protection: validators={}, limiters={}, blacklisted_peers={}, blacklisted_ips={}",
                            connected_validators,
                            prot_stats.active_rate_limiters,
                            prot_stats.blacklisted_peers,
                            prot_stats.blacklisted_ips
                        );
                    }

                    // Log runtime status
                    let status = runtime_for_blocks.status();
                    debug!(
                        "Runtime: epoch={}, phase={:?}, challenges={}, mechanisms={}, pending={}, running={}",
                        status.current_epoch,
                        status.current_phase,
                        status.challenges_loaded,
                        status.mechanisms_registered,
                        status.pending_jobs,
                        status.running_jobs
                    );

                    // Note: Challenge-specific evaluation is handled by challenge containers
                    // The validator only coordinates and proxies requests

                    // Announce DB state to peers periodically
                    if let Err(e) = db_sync_for_loop.announce_state() {
                        debug!("DB sync announce error: {}", e);
                    }

                    // Check consensus status with peers
                    match db_sync_for_loop.check_consensus() {
                        ConsensusStatus::InConsensus { state_root, peers_in_sync, total_peers } => {
                            if peers_in_sync > 0 {
                                debug!(
                                    "DB consensus: {}/{} peers in sync, root={}",
                                    peers_in_sync, total_peers, hex::encode(&state_root[..8])
                                );
                            }
                        }
                        ConsensusStatus::Diverged { our_root, majority_root, majority_count, total_peers } => {
                            warn!(
                                "DB DIVERGENCE: our_root={} vs majority_root={} ({}/{} peers)",
                                hex::encode(&our_root[..8]),
                                hex::encode(&majority_root[..8]),
                                majority_count, total_peers
                            );
                        }
                        ConsensusStatus::NoPeers => {
                            // Normal when no peers connected yet
                        }
                    }

                    // Cleanup stale peer states
                    db_sync_for_loop.cleanup_stale_peers(std::time::Duration::from_secs(120));
                }
            }

            // Handle DB sync events
            Some(event) = db_sync_event_rx.recv() => {
                match event {
                    DBSyncEvent::PeerStateReceived { hotkey, state_root, block_number } => {
                        debug!(
                            "DB sync: peer {} state root={} block={}",
                            hex::encode(&hotkey.as_bytes()[..8]),
                            hex::encode(&state_root[..8]),
                            block_number
                        );
                    }
                    DBSyncEvent::SyncStarted { hotkey } => {
                        info!("DB sync started with peer {}", hex::encode(&hotkey.as_bytes()[..8]));
                    }
                    DBSyncEvent::SyncCompleted { hotkey, entries_synced } => {
                        info!(
                            "DB sync completed with peer {}: {} entries synced",
                            hex::encode(&hotkey.as_bytes()[..8]),
                            entries_synced
                        );
                    }
                    DBSyncEvent::SyncFailed { hotkey, error } => {
                        warn!(
                            "DB sync failed with peer {}: {}",
                            hex::encode(&hotkey.as_bytes()[..8]),
                            error
                        );
                    }
                    DBSyncEvent::InConsensus { state_root, peers_count } => {
                        info!(
                            "DB in consensus: root={} with {} peers",
                            hex::encode(&state_root[..8]),
                            peers_count
                        );
                    }
                    DBSyncEvent::Divergence { our_root, majority_root } => {
                        warn!(
                            "DB divergence detected! our={} majority={}",
                            hex::encode(&our_root[..8]),
                            hex::encode(&majority_root[..8])
                        );
                    }
                }
            }

            // Handle shutdown
            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down...");

                // Stop block sync if running
                if let Some(ref sync) = block_sync {
                    sync.stop().await;
                }

                // Shutdown challenge runtime
                challenge_runtime.shutdown();

                // State is on Bittensor chain, no local persistence needed

                break;
            }
        }
    }

    info!("Validator node stopped.");
    Ok(())
}

/// Commands to send to the network task
#[allow(clippy::large_enum_variant)]
enum NetworkCommand {
    Broadcast(SignedNetworkMessage),
    BroadcastRaw(Vec<u8>), // For RPC sudo_submit - already serialized
    SendResponse(platform_network::ResponseChannelWrapper, SyncResponse),
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
async fn handle_message(
    consensus: &PBFTEngine,
    msg: SignedNetworkMessage,
    chain_state: &Arc<RwLock<ChainState>>,
    challenge_orchestrator: Option<&Arc<ChallengeOrchestrator>>,
    challenge_routes: Option<
        &Arc<RwLock<HashMap<String, Vec<platform_challenge_sdk::ChallengeRoute>>>>,
    >,
    challenge_endpoints: Option<&Arc<RwLock<std::collections::HashMap<String, String>>>>,
    distributed_db: Option<&Arc<distributed_db::DistributedDB>>,
    keypair: Option<&Keypair>,
    container_auth_sessions: Option<&Arc<RwLock<HashMap<String, ContainerAuthSession>>>>,
) {
    let signer = msg.signer().clone();

    match msg.message {
        NetworkMessage::VersionMismatch {
            our_version,
            required_min_version,
        } => {
            warn!(
                "Peer has incompatible version: {} (requires >= {})",
                our_version, required_min_version
            );
        }
        NetworkMessage::SudoAction(action) => {
            // Verify sender is Sudo
            let is_sudo = chain_state.read().is_sudo(&signer);
            if !is_sudo {
                warn!("Rejected SudoAction from non-sudo sender: {:?}", signer);
                return;
            }

            info!("Processing SudoAction from Sudo");
            match action {
                SudoAction::AddChallenge { config } => {
                    info!(
                        "Adding challenge: {} (image: {}, mechanism: {})",
                        config.name, config.docker_image, config.mechanism_id
                    );

                    // Update ChainState
                    chain_state
                        .write()
                        .challenge_configs
                        .insert(config.challenge_id, config.clone());

                    // Start container via orchestrator
                    if let Some(orchestrator) = challenge_orchestrator {
                        if let Err(e) = orchestrator.add_challenge(config.clone()).await {
                            error!("Failed to start challenge container: {}", e);
                        } else {
                            info!("Challenge container started: {}", config.name);

                            // Update endpoints map with actual container endpoint
                            if let Some(endpoints) = challenge_endpoints {
                                if let Some(instance) =
                                    orchestrator.get_challenge(&config.challenge_id)
                                {
                                    let endpoint = instance.endpoint.clone();
                                    let mut eps = endpoints.write();
                                    eps.insert(
                                        config.challenge_id.to_string(),
                                        endpoint.clone(),
                                    );
                                    eps.insert(config.name.clone(), endpoint.clone());
                                    info!(
                                        "Updated endpoint for challenge '{}': {}",
                                        config.name, endpoint
                                    );

                                    // Sync validators to the challenge container
                                    let validators: Vec<_> = chain_state
                                        .read()
                                        .validators
                                        .iter()
                                        .map(|(hotkey, info)| {
                                            serde_json::json!({
                                                "hotkey": hotkey,
                                                "stake": info.stake.0,
                                                "endpoint": ""
                                            })
                                        })
                                        .collect();

                                    if !validators.is_empty() {
                                        let sync_url = format!("{}/p2p/validators", endpoint);
                                        let client = reqwest::Client::new();
                                        match client
                                            .post(&sync_url)
                                            .json(&serde_json::json!({ "validators": validators }))
                                            .timeout(std::time::Duration::from_secs(5))
                                            .send()
                                            .await
                                        {
                                            Ok(resp) if resp.status().is_success() => {
                                                info!(
                                                    "Synced {} validators to challenge '{}'",
                                                    validators.len(),
                                                    config.name
                                                );
                                            }
                                            Ok(resp) => {
                                                warn!(
                                                    "Failed to sync validators to challenge '{}': {}",
                                                    config.name,
                                                    resp.status()
                                                );
                                            }
                                            Err(e) => {
                                                warn!(
                                                    "Failed to sync validators to challenge '{}': {}",
                                                    config.name, e
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Auto-register routes for P2P-received challenges
                    if let Some(routes_map) = challenge_routes {
                        use platform_challenge_sdk::ChallengeRoute;
                        let default_routes = vec![
                            ChallengeRoute::post("/submit", "Submit an agent"),
                            ChallengeRoute::get("/status/:hash", "Get agent status"),
                            ChallengeRoute::get("/leaderboard", "Get leaderboard"),
                            ChallengeRoute::get("/config", "Get challenge config"),
                            ChallengeRoute::get("/stats", "Get statistics"),
                            ChallengeRoute::get("/health", "Health check"),
                        ];
                        routes_map
                            .write()
                            .insert(config.name.clone(), default_routes);
                        info!("Auto-registered routes for challenge '{}'", config.name);
                    }
                }
                SudoAction::UpdateChallenge { config } => {
                    info!(
                        "Updating challenge: {} -> {}",
                        config.challenge_id, config.docker_image
                    );

                    // Update ChainState
                    chain_state
                        .write()
                        .challenge_configs
                        .insert(config.challenge_id, config.clone());

                    // Update container via orchestrator
                    if let Some(orchestrator) = challenge_orchestrator {
                        if let Err(e) = orchestrator.update_challenge(config.clone()).await {
                            error!("Failed to update challenge container: {}", e);
                        } else {
                            info!("Challenge container updated: {}", config.docker_image);
                        }
                    }
                }
                SudoAction::RemoveChallenge { id } => {
                    info!("Removing challenge: {:?}", id);

                    // Update ChainState
                    chain_state.write().challenge_configs.remove(&id);

                    // Remove container via orchestrator
                    if let Some(orchestrator) = challenge_orchestrator {
                        if let Err(e) = orchestrator.remove_challenge(id).await {
                            error!("Failed to remove challenge container: {}", e);
                        } else {
                            info!("Challenge container removed");
                        }
                    }
                }
                SudoAction::RefreshChallenges { challenge_id } => {
                    if let Some(orchestrator) = challenge_orchestrator {
                        match challenge_id {
                            Some(id) => {
                                info!("Refreshing challenge: {:?}", id);
                                if let Err(e) = orchestrator.refresh_challenge(id).await {
                                    error!("Failed to refresh challenge: {}", e);
                                } else {
                                    info!("Challenge refreshed successfully");
                                }
                            }
                            None => {
                                info!("Refreshing all challenges (re-pulling images)");
                                if let Err(e) = orchestrator.refresh_all_challenges().await {
                                    error!("Failed to refresh challenges: {}", e);
                                } else {
                                    info!("All challenges refreshed successfully");
                                }
                            }
                        }
                    }
                }
                SudoAction::SetRequiredVersion {
                    min_version,
                    recommended_version,
                    docker_image,
                    mandatory,
                    deadline_block,
                    ..
                } => {
                    info!(
                        "Version update: min={}, recommended={}, mandatory={}",
                        min_version, recommended_version, mandatory
                    );
                    // Store version requirement - validators use external tools like Watchtower
                    chain_state.write().required_version = Some(platform_core::RequiredVersion {
                        min_version,
                        recommended_version,
                        docker_image,
                        mandatory,
                        deadline_block,
                    });
                }
                _ => {
                    debug!("Unhandled SudoAction: {:?}", action);
                }
            }
        }
        NetworkMessage::Proposal(proposal) => {
            // Check if this is a Sudo AddChallenge proposal and handle it
            if let platform_core::ProposalAction::Sudo(platform_core::SudoAction::AddChallenge {
                ref config,
            }) = proposal.action
            {
                // Auto-register routes
                if let Some(routes_map) = challenge_routes {
                    use platform_challenge_sdk::ChallengeRoute;
                    let default_routes = vec![
                        ChallengeRoute::post("/submit", "Submit an agent"),
                        ChallengeRoute::get("/status/:hash", "Get agent status"),
                        ChallengeRoute::get("/leaderboard", "Get leaderboard"),
                        ChallengeRoute::get("/config", "Get challenge config"),
                        ChallengeRoute::get("/stats", "Get statistics"),
                        ChallengeRoute::get("/health", "Health check"),
                    ];
                    routes_map
                        .write()
                        .insert(config.name.clone(), default_routes);
                    info!(
                        "Auto-registered routes for challenge '{}' (from P2P Proposal)",
                        config.name
                    );
                }

                // Start container via orchestrator (same as SudoAction handler)
                if let Some(orchestrator) = challenge_orchestrator {
                    info!(
                        "Starting challenge container '{}' from P2P Proposal",
                        config.name
                    );
                    if let Err(e) = orchestrator.add_challenge(config.clone()).await {
                        error!("Failed to start challenge container from P2P: {}", e);
                    } else {
                        info!("Challenge container '{}' started from P2P", config.name);

                        // Update endpoints map with actual container endpoint
                        if let Some(endpoints) = challenge_endpoints {
                            if let Some(instance) = orchestrator.get_challenge(&config.challenge_id)
                            {
                                let endpoint = instance.endpoint.clone();
                                let mut eps = endpoints.write();
                                eps.insert(
                                    config.challenge_id.to_string(),
                                    endpoint.clone(),
                                );
                                eps.insert(config.name.clone(), endpoint.clone());
                                info!(
                                    "Updated endpoint for challenge '{}' (P2P): {}",
                                    config.name, endpoint
                                );

                                // Sync validators to the challenge container
                                let validators: Vec<_> = chain_state
                                    .read()
                                    .validators
                                    .iter()
                                    .map(|(hotkey, info)| {
                                        serde_json::json!({
                                            "hotkey": hotkey,
                                            "stake": info.stake.0,
                                            "endpoint": ""
                                        })
                                    })
                                    .collect();

                                if !validators.is_empty() {
                                    let sync_url = format!("{}/p2p/validators", endpoint);
                                    let client = reqwest::Client::new();
                                    match client
                                        .post(&sync_url)
                                        .json(&serde_json::json!({ "validators": validators }))
                                        .timeout(std::time::Duration::from_secs(5))
                                        .send()
                                        .await
                                    {
                                        Ok(resp) if resp.status().is_success() => {
                                            info!(
                                                "Synced {} validators to challenge '{}' (P2P)",
                                                validators.len(),
                                                config.name
                                            );
                                        }
                                        Ok(resp) => {
                                            warn!(
                                                "Failed to sync validators to challenge '{}': {}",
                                                config.name,
                                                resp.status()
                                            );
                                        }
                                        Err(e) => {
                                            warn!(
                                                "Failed to sync validators to challenge '{}': {}",
                                                config.name, e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if let Err(e) = consensus.handle_proposal(proposal, &signer).await {
                error!("Failed to handle proposal: {}", e);
            }
        }
        NetworkMessage::Vote(vote) => {
            if let Err(e) = consensus.handle_vote(vote, &signer).await {
                error!("Failed to handle vote: {}", e);
            }
        }
        NetworkMessage::Heartbeat(hb) => {
            tracing::debug!(
                "Heartbeat from {:?} at block {}",
                hb.hotkey,
                hb.block_height
            );
        }
        NetworkMessage::WeightCommitment(commit) => {
            debug!(
                "Weight commitment from {:?}: challenge={:?}, epoch={}",
                commit.validator, commit.challenge_id, commit.epoch
            );
            // Commitment stored for aggregation
        }
        NetworkMessage::WeightReveal(reveal) => {
            debug!(
                "Weight reveal from {:?}: challenge={:?}, epoch={}, {} weights",
                reveal.validator,
                reveal.challenge_id,
                reveal.epoch,
                reveal.weights.len()
            );
            // Reveal verification and weight aggregation
        }
        NetworkMessage::EpochTransition(transition) => {
            debug!(
                "Epoch transition notification: epoch={}, phase={}, block={}",
                transition.epoch, transition.phase, transition.block_height
            );
        }
        NetworkMessage::ChallengeMessage(challenge_msg) => {
            debug!(
                "Challenge message from {:?}: challenge={}, type={:?}",
                signer, challenge_msg.challenge_id, challenge_msg.message_type
            );

            // Forward challenge message to the appropriate container via HTTP
            // Need keypair for authentication
            if keypair.is_none() || container_auth_sessions.is_none() {
                debug!("Skipping challenge message forward - no auth context available");
                return;
            }

            let challenge_id = challenge_msg.challenge_id.clone();
            let container_name = challenge_id.to_lowercase().replace([' ', '_'], "-");
            let from_hotkey = signer.to_hex();
            let msg_payload = challenge_msg.payload.clone();
            let kp = keypair.unwrap().clone();
            let sessions = container_auth_sessions.unwrap().clone();

            tokio::spawn(async move {
                let client = reqwest::Client::new();
                let base_url = format!("http://challenge-{}:8080", container_name);
                let p2p_endpoint = format!("{}/p2p/message", base_url);

                // Get or create authentication token
                let auth_token =
                    match get_container_auth(&sessions, &base_url, &challenge_id, &kp).await {
                        Ok(token) => token,
                        Err(e) => {
                            warn!(
                                "Failed to authenticate with container {}: {}",
                                container_name, e
                            );
                            return;
                        }
                    };

                // Convert ChallengeMessageType to ChallengeP2PMessage for the container
                let p2p_message = match challenge_msg.message_type {
                    platform_core::ChallengeMessageType::EvaluationResult => {
                        // Parse payload as evaluation result
                        if let Ok(eval) = serde_json::from_slice::<
                            platform_challenge_sdk::EvaluationResultMessage,
                        >(&msg_payload)
                        {
                            Some(
                                platform_challenge_sdk::ChallengeP2PMessage::EvaluationResult(eval),
                            )
                        } else {
                            warn!("Failed to parse EvaluationResult payload");
                            None
                        }
                    }
                    platform_core::ChallengeMessageType::WeightResult => {
                        if let Ok(weights) = serde_json::from_slice::<
                            platform_challenge_sdk::WeightResultMessage,
                        >(&msg_payload)
                        {
                            Some(platform_challenge_sdk::ChallengeP2PMessage::WeightResult(
                                weights,
                            ))
                        } else {
                            warn!("Failed to parse WeightResult payload");
                            None
                        }
                    }
                    _ => {
                        debug!(
                            "Unhandled challenge message type: {:?}",
                            challenge_msg.message_type
                        );
                        None
                    }
                };

                if let Some(message) = p2p_message {
                    let req_body = serde_json::json!({
                        "from_hotkey": from_hotkey,
                        "message": message
                    });

                    match client
                        .post(&p2p_endpoint)
                        .header("X-Auth-Token", &auth_token)
                        .json(&req_body)
                        .send()
                        .await
                    {
                        Ok(resp) if resp.status().is_success() => {
                            debug!(
                                "Forwarded challenge message to container {} (authenticated)",
                                container_name
                            );
                        }
                        Ok(resp) if resp.status() == reqwest::StatusCode::UNAUTHORIZED => {
                            // Token expired, remove from cache
                            sessions.write().remove(&challenge_id);
                            warn!("Auth token expired for container {}, will re-authenticate on next message", container_name);
                        }
                        Ok(resp) => {
                            debug!("Container {} returned {}", container_name, resp.status());
                        }
                        Err(e) => {
                            debug!("Failed to forward to container {}: {}", container_name, e);
                        }
                    }
                }
            });
        }
        NetworkMessage::AgentSubmission(submission) => {
            info!(
                "Agent submission received via P2P: challenge={}, agent={}, from={}",
                submission.challenge_id,
                &submission.agent_hash[..16.min(submission.agent_hash.len())],
                submission.miner_hotkey
            );

            // Verify we have this challenge configured
            let challenge_id_opt = {
                let state = chain_state.read();
                state
                    .challenge_configs
                    .values()
                    .find(|c| c.name == submission.challenge_id)
                    .map(|c| c.challenge_id)
            };

            let challenge_id = match challenge_id_opt {
                Some(id) => id,
                None => {
                    warn!(
                        "Received agent for unknown challenge: {}",
                        submission.challenge_id
                    );
                    return;
                }
            };

            // For Docker challenges, sign consensus and forward to challenge container
            let challenge_config = {
                let state = chain_state.read();
                state.challenge_configs.get(&challenge_id).cloned()
            };

            if let Some(config) = challenge_config {
                let container_name = config.name.to_lowercase().replace([' ', '_'], "-");
                let agent_hash = submission.agent_hash.clone();
                let agent_hash_for_log = agent_hash.clone();
                let challenge_name = submission.challenge_id.clone();
                let miner = submission.miner_hotkey.clone();
                let miner_for_log = miner.clone();
                let source_code = submission.source_code.clone();
                let miner_signature = submission.miner_signature.clone();
                let obfuscated_hash = submission.obfuscated_hash.clone().unwrap_or_else(|| {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(agent_hash.as_bytes());
                    hasher.update(b"obfuscated");
                    hex::encode(hasher.finalize())
                });
                let validator_hotkey = signer.to_hex();

                // Forward agent submission to container and sign consensus
                tokio::spawn(async move {
                    let client = reqwest::Client::new();

                    // Step 1: If we have source code, submit the agent to our local container
                    // This ensures the container has the agent registered for evaluation
                    if let Some(ref code) = source_code {
                        let submit_endpoint =
                            format!("http://challenge-{}:8080/submit", container_name);

                        let submit_payload = serde_json::json!({
                            "source_code": code,
                            "miner_hotkey": miner,
                            "signature": hex::encode(&miner_signature),
                            "stake": 1000000000000u64,
                            "from_p2p": true,
                        });

                        match client
                            .post(&submit_endpoint)
                            .json(&submit_payload)
                            .send()
                            .await
                        {
                            Ok(resp) if resp.status().is_success() => {
                                info!(
                                    "Agent {} registered in local container via P2P",
                                    &agent_hash[..16.min(agent_hash.len())]
                                );
                            }
                            Ok(resp) => {
                                // 409 Conflict means agent already exists, which is fine
                                if resp.status().as_u16() != 409 {
                                    debug!(
                                        "Submit to container returned {}: agent {}",
                                        resp.status(),
                                        &agent_hash[..16.min(agent_hash.len())]
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to submit agent {} to local container: {}",
                                    &agent_hash[..16.min(agent_hash.len())],
                                    e
                                );
                            }
                        }
                    }

                    // Step 2: Sign consensus for this agent (allows evaluation to proceed)
                    let consensus_endpoint =
                        format!("http://challenge-{}:8080/consensus/sign", container_name);

                    let sign_payload = serde_json::json!({
                        "agent_hash": agent_hash,
                        "validator_hotkey": validator_hotkey,
                        "obfuscated_hash": obfuscated_hash,
                        "signature": "0000000000000000000000000000000000000000000000000000000000000000"
                    });

                    match client
                        .post(&consensus_endpoint)
                        .json(&sign_payload)
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            if resp.status().is_success() {
                                if let Ok(result) = resp.json::<serde_json::Value>().await {
                                    let consensus_reached = result
                                        .get("consensus_reached")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);
                                    info!(
                                        "Validator signed consensus for agent {}: consensus_reached={}",
                                        &agent_hash[..16.min(agent_hash.len())],
                                        consensus_reached
                                    );
                                }
                            } else {
                                debug!(
                                    "Consensus sign returned {}: agent {}",
                                    resp.status(),
                                    &agent_hash[..16.min(agent_hash.len())]
                                );
                            }
                        }
                        Err(e) => {
                            debug!(
                                "Failed to sign consensus for agent {}: {}",
                                &agent_hash[..16.min(agent_hash.len())],
                                e
                            );
                        }
                    }
                });

                info!(
                    "Agent {} received via P2P (challenge: {}, miner: {})",
                    &agent_hash_for_log[..16.min(agent_hash_for_log.len())],
                    challenge_name,
                    miner_for_log
                );
            } else {
                warn!(
                    "Challenge config not found for: {}",
                    submission.challenge_id
                );
            }
        }
        NetworkMessage::EvaluationResult(result) => {
            info!(
                "Evaluation result received via P2P: job={}, agent={}, score={:.4}",
                result.job_id,
                &result.agent_hash[..16.min(result.agent_hash.len())],
                result.score.value
            );

            // Store in distributed DB for aggregation and verification
            if let Some(db) = distributed_db {
                use distributed_db::StoredEvaluation;

                // Create stored evaluation from P2P message
                let stored_eval = StoredEvaluation {
                    id: format!("{}_{}", result.job_id, &result.validator.to_hex()[..16]),
                    agent_hash: result.agent_hash.clone(),
                    challenge_id: result.challenge_id.to_string(),
                    validator: result.validator.to_hex(),
                    score: result.score.value,
                    metrics: serde_json::json!({
                        "execution_time_ms": result.execution_time_ms,
                        "weight": result.score.weight,
                    }),
                    evaluated_at: result.timestamp.timestamp() as u64,
                    block_number: 0, // Current block will be set by DB
                };

                // Store in distributed DB
                if let Err(e) = db.store_evaluation(&stored_eval) {
                    error!("Failed to store evaluation result in DB: {}", e);
                } else {
                    info!(
                        "Stored evaluation result: agent={}, validator={}, score={:.4}",
                        &result.agent_hash[..16.min(result.agent_hash.len())],
                        &result.validator.to_hex()[..16],
                        result.score.value
                    );
                }
            }

            debug!(
                "Evaluation from validator: challenge={:?}, execution_time={}ms",
                result.challenge_id, result.execution_time_ms
            );
        }
        NetworkMessage::TaskProgress(progress) => {
            // Real-time task progress update received via P2P
            info!(
                "Task progress: {} [{}/{}] agent={} task={} passed={} score={:.2} (validator: {})",
                progress.challenge_id,
                progress.task_index,
                progress.total_tasks,
                &progress.agent_hash[..16.min(progress.agent_hash.len())],
                progress.task_id,
                progress.passed,
                progress.score,
                &progress.validator_hotkey[..16.min(progress.validator_hotkey.len())]
            );

            // Store task progress in distributed DB for real-time tracking
            if let Some(db) = distributed_db {
                let progress_key = format!(
                    "{}:{}:{}",
                    progress.agent_hash, progress.task_id, progress.validator_hotkey
                );

                let progress_data = serde_json::json!({
                    "challenge_id": progress.challenge_id,
                    "agent_hash": progress.agent_hash,
                    "evaluation_id": progress.evaluation_id,
                    "task_id": progress.task_id,
                    "task_index": progress.task_index,
                    "total_tasks": progress.total_tasks,
                    "passed": progress.passed,
                    "score": progress.score,
                    "execution_time_ms": progress.execution_time_ms,
                    "cost_usd": progress.cost_usd,
                    "error": progress.error,
                    "validator_hotkey": progress.validator_hotkey,
                    "timestamp": progress.timestamp,
                });

                // Store task progress (informational for real-time tracking)
                // Final results go through consensus Proposals
                if let Err(e) = db.put(
                    "task_progress",
                    progress_key.as_bytes(),
                    progress_data.to_string().as_bytes(),
                ) {
                    debug!("Failed to store task progress: {}", e);
                }
            }
        }
        _ => {}
    }
}

fn handle_sync_request(
    state: &Arc<RwLock<ChainState>>,
    request: &platform_network::SyncRequest,
) -> SyncResponse {
    use platform_network::SyncRequest;

    match request {
        SyncRequest::FullState => {
            let state = state.read().clone();
            match bincode::serialize(&state) {
                Ok(data) => SyncResponse::FullState { data },
                Err(e) => SyncResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        SyncRequest::Snapshot => {
            let snapshot = state.read().snapshot();
            match bincode::serialize(&snapshot) {
                Ok(data) => SyncResponse::Snapshot { data },
                Err(e) => SyncResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        SyncRequest::Validators => {
            let validators: Vec<_> = state.read().validators.values().cloned().collect();
            match bincode::serialize(&validators) {
                Ok(data) => SyncResponse::Validators { data },
                Err(e) => SyncResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        SyncRequest::Challenge { id: _ } => SyncResponse::Challenge { data: None },
    }
}

/// Response from /.well-known/routes endpoint
#[derive(Debug, Clone, serde::Deserialize)]
struct RoutesManifestResponse {
    name: String,
    version: String,
    #[allow(dead_code)]
    description: String,
    routes: Vec<RouteEntry>,
    #[allow(dead_code)]
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct RouteEntry {
    method: String,
    path: String,
    description: String,
    #[serde(default)]
    requires_auth: bool,
    #[serde(default)]
    rate_limit: u32,
}

/// Discover routes from a challenge container via /.well-known/routes
async fn discover_routes(url: &str) -> anyhow::Result<RoutesManifestResponse> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Route discovery failed with status: {}", response.status());
    }

    let manifest: RoutesManifestResponse = response.json().await?;
    Ok(manifest)
}

/// Authenticate with a challenge container
/// Returns the session token on success
async fn authenticate_with_container(
    base_url: &str,
    challenge_id: &str,
    keypair: &Keypair,
) -> anyhow::Result<ContainerAuthSession> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Generate random nonce
    let nonce: [u8; 32] = rand::random();
    let nonce_hex = hex::encode(nonce);

    // Create message to sign: "auth:{challenge_id}:{timestamp}:{nonce}"
    let message = format!("auth:{}:{}:{}", challenge_id, timestamp, nonce_hex);

    // Sign the message
    let signed = keypair.sign(message.as_bytes());
    let signature_hex = hex::encode(&signed.signature);

    let auth_request = ContainerAuthRequest {
        hotkey: keypair.hotkey().to_hex(),
        challenge_id: challenge_id.to_string(),
        timestamp,
        nonce: nonce_hex,
        signature: signature_hex,
    };

    let auth_url = format!("{}/auth", base_url.trim_end_matches('/'));

    info!(
        "Authenticating with container at {} for challenge {}",
        auth_url, challenge_id
    );

    let response = client.post(&auth_url).json(&auth_request).send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "Container authentication failed with status {}: {}",
            status,
            body
        );
    }

    let auth_response: ContainerAuthResponse = response.json().await?;

    if !auth_response.success {
        anyhow::bail!(
            "Container authentication rejected: {}",
            auth_response
                .error
                .unwrap_or_else(|| "Unknown error".to_string())
        );
    }

    let token = auth_response
        .session_token
        .ok_or_else(|| anyhow::anyhow!("No session token in auth response"))?;

    let expires_at = auth_response.expires_at.unwrap_or(timestamp + 3600); // Default 1 hour

    let container_name = challenge_id.to_lowercase().replace([' ', '_'], "-");

    info!(
        "Successfully authenticated with container {} (expires at {})",
        container_name, expires_at
    );

    Ok(ContainerAuthSession {
        token,
        expires_at,
        container_name,
    })
}

/// Check if a session is still valid (not expired)
fn is_session_valid(session: &ContainerAuthSession) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Add 60 second buffer before expiry
    now < session.expires_at.saturating_sub(60)
}

/// Get or refresh authentication session for a container
async fn get_container_auth(
    sessions: &RwLock<HashMap<String, ContainerAuthSession>>,
    base_url: &str,
    challenge_id: &str,
    keypair: &Keypair,
) -> anyhow::Result<String> {
    // Check if we have a valid session
    {
        let sessions_read = sessions.read();
        if let Some(session) = sessions_read.get(challenge_id) {
            if is_session_valid(session) {
                return Ok(session.token.clone());
            }
        }
    }

    // Need to authenticate or re-authenticate
    let session = authenticate_with_container(base_url, challenge_id, keypair).await?;
    let token = session.token.clone();

    {
        let mut sessions_write = sessions.write();
        sessions_write.insert(challenge_id.to_string(), session);
    }

    Ok(token)
}
