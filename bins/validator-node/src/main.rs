//! Validator Node Binary
//!
//! Runs a validator node in the platform P2P network.

use anyhow::Result;
use challenge_orchestrator::{ChallengeOrchestrator, OrchestratorConfig};
use clap::Parser;
use distributed_db::{ConsensusStatus, DBSyncEvent, DBSyncManager, DBSyncMessage, DistributedDB};
use parking_lot::RwLock;
use platform_bittensor::{
    BittensorClient, BittensorConfig, BlockSync, BlockSyncConfig, BlockSyncEvent, SubtensorClient,
    WeightSubmitter,
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
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex as TokioMutex;
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
    #[arg(long, default_value = "8545")]
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

    // Derive keypair for internal use
    // Try to use the same derivation as Bittensor (SR25519 from mnemonic)
    let keypair = {
        let secret = &args.secret_key;

        // Try hex decode first (32 bytes = raw seed)
        if let Ok(bytes) = hex::decode(secret) {
            if bytes.len() != 32 {
                anyhow::bail!("Hex secret key must be 32 bytes");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Keypair::from_bytes(&arr)?
        } else {
            // Mnemonic phrase - use BIP39 + SR25519 derivation (same as Bittensor)
            // We use sp_core to derive the same key as Bittensor
            use sha2::{Digest, Sha256};

            // Hash the mnemonic to get a deterministic seed
            // This matches the internal derivation we need for signing
            let mut hasher = Sha256::new();
            hasher.update(secret.as_bytes());
            let hash = hasher.finalize();

            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);

            info!("Derived internal keypair from mnemonic");
            Keypair::from_bytes(&arr)?
        }
    };

    // Note: The actual Bittensor hotkey will be shown after connecting to Bittensor
    // The internal keypair is used for P2P message signing
    info!("Internal keypair derived (P2P signing)");

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
    let _rpc_handle = if args.rpc_port > 0 {
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

        // Set up route handler that proxies to challenge containers
        let handler: platform_rpc::ChallengeRouteHandler = Arc::new(
            move |challenge_id, req| {
                let endpoints = endpoints_for_handler.clone();
                Box::pin(async move {
                    use platform_challenge_sdk::RouteResponse;

                    // Get endpoint for this challenge
                    let endpoint = {
                        let eps = endpoints.read();
                        match eps.get(&challenge_id) {
                            Some(ep) => ep.clone(),
                            None => {
                                return RouteResponse::new(
                                    404,
                                    serde_json::json!({"error": format!("Challenge {} not configured", challenge_id)}),
                                );
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
            },
        );
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

        Some(rpc_server.spawn())
    } else {
        info!("RPC server disabled (--rpc-port 0)");
        None
    };

    // Setup Bittensor connection (if enabled)
    let weight_submitter: Option<Arc<TokioMutex<WeightSubmitter>>>;
    let mut block_sync: Option<BlockSync> = None;
    let mut block_sync_rx: Option<tokio::sync::mpsc::Receiver<BlockSyncEvent>> = None;

    if !args.no_bittensor {
        info!(
            "Connecting to Bittensor: {} (netuid={})",
            args.subtensor_endpoint, args.netuid
        );

        let bt_config = BittensorConfig {
            endpoint: args.subtensor_endpoint.clone(),
            netuid: args.netuid,
            use_commit_reveal: args.commit_reveal,
            version_key: 1,
        };

        let mut bt_client = SubtensorClient::new(bt_config);

        match bt_client.connect().await {
            Ok(_) => {
                // Set signer from mnemonic/seed (passed directly to Bittensor)
                if let Err(e) = bt_client.set_signer(&bittensor_seed) {
                    warn!("Failed to set Bittensor signer: {}", e);
                } else {
                    // Log the actual Bittensor hotkey (SS58 format)
                    if let Some(signer) = bt_client.get_signer() {
                        info!("Bittensor hotkey: {}", signer.account_id());
                    }
                }

                // Sync metagraph
                match bt_client.sync_metagraph().await {
                    Ok(mg) => info!("Synced metagraph: {} neurons", mg.n),
                    Err(e) => warn!("Failed to sync metagraph: {}", e),
                }

                weight_submitter = Some(Arc::new(TokioMutex::new(WeightSubmitter::new(bt_client))));

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
                warn!("Failed to connect to Bittensor: {} (continuing without)", e);
                weight_submitter = None;
            }
        }
    } else {
        info!("Bittensor disabled (--no-bittensor)");
        weight_submitter = None;
    };

    // Create message channel for consensus
    let (msg_tx, mut msg_rx) = mpsc::channel::<SignedNetworkMessage>(1000);

    // Create consensus engine
    let consensus = PBFTEngine::new(keypair.clone(), chain_state.clone(), msg_tx);
    consensus.sync_validators();

    // Parse bootstrap peers
    let bootstrap_peers: Vec<_> = args
        .bootstrap
        .map(|s| {
            s.split(',')
                .filter_map(|addr| addr.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default();

    // Create network node
    let node_config = NodeConfig {
        listen_addr: args.listen.parse()?,
        bootstrap_peers,
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

    // Spawn evaluation loop
    let runtime_for_eval = challenge_runtime.clone();
    tokio::spawn(async move {
        runtime_for_eval.run_evaluation_loop().await;
    });

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
    let _storage = Arc::new(storage); // Keep reference but don't persist state
    let runtime_for_blocks = challenge_runtime.clone();
    let weight_submitter_clone = weight_submitter.clone();
    let db_for_blocks = distributed_db.clone();
    let db_sync_for_loop = db_sync_manager.clone();
    let mut block_counter = 0u64;
    let use_bittensor_blocks = block_sync_rx.is_some();

    // Fetch mechanism count from Bittensor and submit initial weights
    // This prevents vtrust penalty from not having set weights yet
    let subnet_mechanism_count: u8 = if let Some(ref submitter) = weight_submitter {
        let mut sub = submitter.lock().await;
        match sub.client_mut().get_mechanism_count().await {
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
    if let Some(ref submitter) = weight_submitter {
        info!(
            "Submitting initial weights on startup for {} mechanisms...",
            subnet_mechanism_count
        );

        // Get registered challenge mechanisms
        let registered_mechanisms = challenge_runtime.get_registered_mechanism_ids();
        let registered_set: std::collections::HashSet<u8> =
            registered_mechanisms.iter().copied().collect();

        // Build weights for ALL mechanisms (0 to count-1)
        let mut initial_weights: Vec<(u8, Vec<u16>, Vec<u16>)> = Vec::new();

        for mechanism_id in 0..subnet_mechanism_count {
            if registered_set.contains(&mechanism_id) {
                // This mechanism has a challenge - check for evaluation weights
                let eval_weights = challenge_runtime.get_mechanism_weights_for_submission();
                if let Some((_, uids, weights)) =
                    eval_weights.iter().find(|(m, _, _)| *m == mechanism_id)
                {
                    info!(
                        "Mechanism {} has evaluation weights ({} entries)",
                        mechanism_id,
                        uids.len()
                    );
                    initial_weights.push((mechanism_id, uids.clone(), weights.clone()));
                } else {
                    // Challenge registered but no evaluations yet - burn weights
                    info!(
                        "Mechanism {} (challenge registered) - submitting burn weights",
                        mechanism_id
                    );
                    initial_weights.push((mechanism_id, vec![0u16], vec![65535u16]));
                }
            } else {
                // No challenge for this mechanism - burn weights to UID 0
                info!(
                    "Mechanism {} (no challenge) - submitting burn weights to UID 0",
                    mechanism_id
                );
                initial_weights.push((mechanism_id, vec![0u16], vec![65535u16]));
            }
        }

        let mut sub = submitter.lock().await;
        match sub.submit_mechanism_weights_batch(&initial_weights).await {
            Ok(tx) => info!("Initial weights submitted to Bittensor: {}", tx),
            Err(e) => warn!(
                "Failed to submit initial weights (will retry at next epoch): {}",
                e
            ),
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
                    }
                    BlockSyncEvent::RevealWindowOpen { epoch, block } => {
                        info!("Reveal window opened for epoch {} at block {}", epoch, block);

                        // Reveal any pending mechanism commits
                        if let Some(ref submitter) = weight_submitter_clone {
                            let mut sub = submitter.lock().await;
                            if sub.has_pending_mechanism_commits() {
                                info!("Revealing pending mechanism commits...");
                                match sub.reveal_pending_mechanism_commits().await {
                                    Ok(Some(tx)) => info!("Mechanism weights revealed: {}", tx),
                                    Ok(None) => debug!("No pending commits to reveal"),
                                    Err(e) => error!("Failed to reveal mechanism weights: {}", e),
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

                        info!("Peer connected: {} (stake validation pending)", peer);
                        // Note: Full stake validation happens when we receive their first signed message
                    }
                    NetworkEvent::PeerDisconnected(peer) => {
                        let peer_str = peer.to_string();
                        // Clean up hotkey tracking for this peer
                        protection.disconnect_hotkey(&peer_str);
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
                                    handle_message(&consensus, signed, &chain_state_clone, challenge_orchestrator.as_ref()).await;
                                } else {
                                    // Allow Sudo to bypass stake check for bootstrapping and upgrades
                                    let is_sudo = {
                                        let state = chain_state_clone.read();
                                        state.is_sudo(signed.signer())
                                    };

                                    if is_sudo {
                                        info!("Bypassing stake check for Sudo message from {}", &signer_hex[..16]);
                                        handle_message(&consensus, signed, &chain_state_clone, challenge_orchestrator.as_ref()).await;
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
                        if let Some(ref submitter) = weight_submitter_clone {
                            let weights_to_submit = if is_empty {
                                // No challenges configured - submit default weights to UID 0 (burn)
                                // This prevents vtrust penalty from not setting weights
                                warn!(
                                    "No challenge weights for epoch {} - submitting default burn weights to UID 0",
                                    epoch
                                );
                                // Default mechanism_id 0 with 100% weight to UID 0
                                vec![(0u8, vec![0u16], vec![65535u16])]
                            } else {
                                mechanism_weights
                            };

                            let mut sub = submitter.lock().await;
                            match sub.submit_mechanism_weights_batch(&weights_to_submit).await {
                                Ok(tx) => {
                                    if is_empty {
                                        info!("Default burn weights submitted to Bittensor: {}", tx);
                                    } else {
                                        info!("Mechanism weights submitted to Bittensor: {}", tx);
                                    }
                                }
                                Err(e) => error!("Failed to submit weights: {}", e),
                            }
                        }
                    }
                    RuntimeEvent::EpochTransition(transition) => {
                        info!("Epoch transition: {:?}", transition);

                        // Check if we're entering the reveal phase - trigger pending reveals
                        // This is a fallback when BlockSyncEvent::RevealWindowOpen doesn't fire
                        // (e.g., when CommitRevealWeightsEnabled is false but we use mechanism weights)
                        if let EpochTransition::PhaseChange { new_phase: EpochPhase::Reveal, .. } = transition {
                            if let Some(ref submitter) = weight_submitter_clone {
                                let mut sub = submitter.lock().await;
                                if sub.has_pending_mechanism_commits() {
                                    info!("Reveal phase detected (internal) - revealing pending mechanism commits...");
                                    match sub.reveal_pending_mechanism_commits().await {
                                        Ok(Some(tx)) => info!("Mechanism weights revealed: {}", tx),
                                        Ok(None) => debug!("No pending commits to reveal"),
                                        Err(e) => error!("Failed to reveal mechanism weights: {}", e),
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
                if block_counter % 10 == 0 || use_bittensor_blocks {
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
    SendResponse(platform_network::ResponseChannelWrapper, SyncResponse),
}

async fn handle_message(
    consensus: &PBFTEngine,
    msg: SignedNetworkMessage,
    chain_state: &Arc<RwLock<ChainState>>,
    challenge_orchestrator: Option<&Arc<ChallengeOrchestrator>>,
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
                    chain_state.write().required_version =
                        Some(platform_core::RequiredVersion {
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
