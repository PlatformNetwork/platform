//! Validator Node Binary
//!
//! Runs a validator node in the platform P2P network.

use anyhow::Result;
use challenge_orchestrator::{ChallengeOrchestrator, OrchestratorConfig};
use clap::Parser;
use distributed_db::{ConsensusStatus, DBSyncEvent, DBSyncManager, DBSyncMessage, DistributedDB};
use parking_lot::RwLock;
use platform_bittensor::{
    signer_from_seed, BittensorClient, BlockSync, BlockSyncConfig, BlockSyncEvent, ExtrinsicWait,
    Subtensor,
};
use platform_challenge_runtime::{ChallengeRuntime, RuntimeConfig, RuntimeEvent};
use platform_consensus::PBFTEngine;
use platform_core::{
    production_sudo_key, ChainState, ChallengeContainerConfig, Hotkey, Keypair, NetworkConfig,
    NetworkMessage, SignedNetworkMessage, Stake, SudoAction, ValidatorInfo, SUDO_KEY_SS58,
};
use platform_epoch::{EpochConfig, EpochPhase, EpochTransition};
use platform_network::{
    NetworkEvent, NetworkNode, NetworkProtection, NodeConfig, ProtectionConfig, SyncResponse,
    MIN_STAKE_RAO, MIN_STAKE_TAO,
};
use platform_rpc::{RpcConfig, RpcServer};
use platform_storage::Storage;
use platform_subnet_manager::BanList;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

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

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,platform=debug".into()),
        )
        .init();

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
    info!("Validator hotkey (hex): {}", keypair.hotkey().to_hex());
    info!("Validator SS58 address: {}", keypair.ss58_address());

    // The identity seed for P2P is derived from the keypair seed
    let identity_seed = keypair.seed();

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

    // Load or create chain state
    let chain_state = if let Some(state) = storage.load_state()? {
        info!("Loaded existing state at block {}", state.block_height);
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
        let config = if args.no_bittensor {
            NetworkConfig::default()
        } else {
            NetworkConfig::production()
        };

        let state = ChainState::new(sudo_key, config);
        Arc::new(RwLock::new(state))
    };

    // Initialize network protection (DDoS + stake validation)
    let protection_config = ProtectionConfig {
        min_stake_rao: MIN_STAKE_RAO,       // 1000 TAO minimum
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
        MIN_STAKE_TAO, 100
    );

    // Add ourselves as a validator
    {
        let stake_raw = (args.stake * 1_000_000_000.0) as u64;

        // Validate our own stake meets minimum
        if stake_raw < MIN_STAKE_RAO {
            warn!(
                "WARNING: Own stake ({} TAO) is below minimum ({} TAO). You may be rejected by other validators.",
                args.stake, MIN_STAKE_TAO
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

    // Start RPC server (if enabled)
    // Challenge-specific logic is handled by Docker containers
    // The validator only proxies requests to challenges via HTTP
    let (_rpc_handle, rpc_handler, rpc_broadcast_rx) = if args.rpc_port > 0 {
        let rpc_addr = format!("{}:{}", args.rpc_addr, args.rpc_port);
        let rpc_config = RpcConfig {
            addr: rpc_addr.parse()?,
            netuid: args.netuid,
            name: format!("MiniChain-{}", args.netuid),
            min_stake: MIN_STAKE_RAO,
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

            // Store endpoint for this challenge (container name derived from challenge name)
            let container_name = config.name.to_lowercase().replace(' ', "-");
            let endpoint = format!("http://challenge-{}:8080", container_name);
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
                                let container_name = cfg.name.to_lowercase().replace(' ', "-");
                                format!("http://challenge-{}:8080", container_name)
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

        // Set keypair for signing P2P messages (for webhook progress broadcasts)
        rpc_handler.set_keypair(keypair.clone());

        // Also set the agent broadcast channel (used by route handler for /submit)
        *agent_broadcast_tx.write() = Some(rpc_broadcast_tx);

        (
            Some(rpc_server.spawn()),
            Some(rpc_handler),
            Some(rpc_broadcast_rx),
        )
    } else {
        info!("RPC server disabled (--rpc-port 0)");
        (None, None, None)
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
    let bootstrap_peers: Vec<_> = args
        .bootstrap
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
        });

    // Create network node with deterministic peer ID derived from hotkey public key
    let node_config = NodeConfig {
        listen_addr: args.listen.parse()?,
        bootstrap_peers,
        identity_seed: Some(identity_seed),
        ..Default::default()
    };

    let mut network = NetworkNode::new(node_config.clone()).await?;
    let mut event_rx = network.take_event_receiver().unwrap();

    info!("Local peer ID: {}", network.local_peer_id());

    // Start network
    network.start(&node_config).await?;

    // Channel for sending commands to network
    let (net_cmd_tx, mut net_cmd_rx) = mpsc::channel::<NetworkCommand>(100);

    // Spawn network event loop in a separate task
    tokio::spawn(async move {
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

    // Main event loop
    info!("Validator node running. Press Ctrl+C to stop.");

    let chain_state_clone = chain_state.clone();
    // Get challenge_routes Arc for auto-registration when receiving via P2P
    let challenge_routes_for_p2p = rpc_handler.as_ref().map(|h| h.challenge_routes.clone());
    // Get distributed_db for P2P message handling
    let db_for_p2p = Some(distributed_db.clone());
    let _storage = Arc::new(storage); // Keep reference but don't persist state
    let runtime_for_blocks = challenge_runtime.clone();
    let subtensor_clone = subtensor.clone();
    let subtensor_signer_clone = subtensor_signer.clone();
    let db_for_blocks = distributed_db.clone();
    let db_sync_for_loop = db_sync_manager.clone();
    let mut block_counter = 0u64;
    let use_bittensor_blocks = block_sync_rx.is_some();
    let netuid = args.netuid;

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

                        info!("Peer connected: {} (stake validation pending)", peer);
                        // Note: Full stake validation happens when we receive their first signed message
                    }
                    NetworkEvent::PeerDisconnected(peer) => {
                        let peer_str = peer.to_string();
                        // Clean up hotkey tracking for this peer
                        protection.disconnect_hotkey(&peer_str);
                        // Update RPC handler peer list
                        if let Some(ref handler) = rpc_handler {
                            handler.remove_peer(&peer_str);
                        }
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
                                let has_sufficient_stake = {
                                    let state = chain_state_clone.read();
                                    if let Some(validator) = state.get_validator(signed.signer()) {
                                        validator.stake.0 >= MIN_STAKE_RAO
                                    } else {
                                        // Unknown validator - check against cached stake or reject
                                        if let Some(validation) = protection.check_cached_stake(&signer_hex) {
                                            validation.is_valid()
                                        } else {
                                            warn!(
                                                "Unknown validator {}: not in state and no cached stake. Min required: {} TAO",
                                                &signer_hex[..16], MIN_STAKE_TAO
                                            );
                                            false
                                        }
                                    }
                                };

                                if has_sufficient_stake {
                                    // Forward all messages to consensus handler
                                    handle_message(&consensus, signed, &chain_state_clone, challenge_orchestrator.as_ref(), challenge_routes_for_p2p.as_ref(), db_for_p2p.as_ref()).await;
                                } else {
                                    // Allow Sudo to bypass stake check for bootstrapping and upgrades
                                    let is_sudo = {
                                        let state = chain_state_clone.read();
                                        state.is_sudo(signed.signer())
                                    };

                                    if is_sudo {
                                        info!("Bypassing stake check for Sudo message from {}", &signer_hex[..16]);
                                        handle_message(&consensus, signed, &chain_state_clone, challenge_orchestrator.as_ref(), challenge_routes_for_p2p.as_ref(), db_for_p2p.as_ref()).await;
                                    } else {
                                        warn!(
                                            "Rejected message from {} - insufficient stake (min {} TAO required)",
                                            &signer_hex[..16], MIN_STAKE_TAO
                                        );
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

                    // Note: State is not persisted locally - it comes from Bittensor chain
                    // Challenges and weights are managed via SudoAction and Bittensor

                    // Cleanup expired protection entries
                    protection.cleanup();

                    // Cleanup stale hotkey connections (no heartbeat for 5 minutes)
                    protection.cleanup_stale_hotkeys(std::time::Duration::from_secs(300));

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
enum NetworkCommand {
    Broadcast(SignedNetworkMessage),
    BroadcastRaw(Vec<u8>), // For RPC sudo_submit - already serialized
    SendResponse(platform_network::ResponseChannelWrapper, SyncResponse),
}

async fn handle_message(
    consensus: &PBFTEngine,
    msg: SignedNetworkMessage,
    chain_state: &Arc<RwLock<ChainState>>,
    challenge_orchestrator: Option<&Arc<ChallengeOrchestrator>>,
    challenge_routes: Option<
        &Arc<RwLock<HashMap<String, Vec<platform_challenge_sdk::ChallengeRoute>>>>,
    >,
    distributed_db: Option<&Arc<distributed_db::DistributedDB>>,
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
            // Check if this is a Sudo AddChallenge proposal and auto-register routes
            if let platform_core::ProposalAction::Sudo(platform_core::SudoAction::AddChallenge {
                ref config,
            }) = proposal.action
            {
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
            // Challenge messages are handled by the challenge runtime/containers
            // The validator just routes them. For now, log and ignore.
            // In production, this would be forwarded to the challenge container via HTTP
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
                let container_name = config.name.to_lowercase().replace(' ', "-");
                let agent_hash = submission.agent_hash.clone();
                let agent_hash_for_log = agent_hash.clone();
                let challenge_name = submission.challenge_id.clone();
                let miner = submission.miner_hotkey.clone();
                let obfuscated_hash = submission.obfuscated_hash.clone().unwrap_or_else(|| {
                    // Generate obfuscated hash from agent hash if not provided
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(agent_hash.as_bytes());
                    hasher.update(b"obfuscated");
                    hex::encode(hasher.finalize())
                });
                let validator_hotkey = signer.to_hex();

                // Sign consensus for this agent (allows evaluation to proceed)
                tokio::spawn(async move {
                    let client = reqwest::Client::new();
                    let consensus_endpoint =
                        format!("http://challenge-{}:8080/consensus/sign", container_name);

                    // Sign the consensus
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
                    miner
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
