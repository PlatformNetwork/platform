//! Platform Validator Node
//!
//! Fully decentralized P2P validator for the Platform network.
//! Uses libp2p for gossipsub consensus and Kademlia DHT for storage.
//! Submits weights to Bittensor at epoch boundaries.

mod challenge_storage;
mod wasm_executor;

use anyhow::Result;
use bittensor_rs::chain::{signer_from_seed, BittensorSigner, ExtrinsicWait};
use clap::Parser;
use parking_lot::RwLock;
use platform_bittensor::{
    sync_metagraph, BittensorClient, BlockSync, BlockSyncConfig, BlockSyncEvent, Metagraph,
    Subtensor, SubtensorClient,
};
use platform_core::{
    checkpoint::{
        CheckpointData, CheckpointManager, CompletedEvaluationState, PendingEvaluationState,
        WeightVoteState,
    },
    ChallengeId, Hotkey, Keypair, SUDO_KEY_SS58,
};
use platform_distributed_storage::{
    DistributedStoreExt, LocalStorage, LocalStorageBuilder, StorageKey,
};
use platform_p2p_consensus::{
    ChainState, ConsensusEngine, EvaluationMessage, EvaluationMetrics, EvaluationRecord,
    HeartbeatMessage, JobRecord, JobStatus, NetworkEvent, P2PConfig, P2PMessage, P2PNetwork,
    StateManager, TaskProgressRecord, ValidatorRecord, ValidatorSet,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use wasm_executor::{WasmChallengeExecutor, WasmExecutorConfig};

/// Storage key for persisted chain state
const STATE_STORAGE_KEY: &str = "chain_state";

/// Maximum length for user-provided strings logged from P2P messages
const MAX_LOG_FIELD_LEN: usize = 256;
const JOB_TIMEOUT_MS: i64 = 300_000;

/// Sanitize a user-provided string for safe logging.
///
/// Replaces control characters (newlines, tabs, ANSI escapes) with spaces
/// and truncates to `MAX_LOG_FIELD_LEN` to prevent log injection attacks.
fn sanitize_for_log(s: &str) -> String {
    let truncated = if s.len() > MAX_LOG_FIELD_LEN {
        &s[..MAX_LOG_FIELD_LEN]
    } else {
        s
    };
    truncated
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

// ==================== Shutdown Handler ====================

/// Handles graceful shutdown with state persistence
struct ShutdownHandler {
    checkpoint_manager: CheckpointManager,
    state_manager: Arc<StateManager>,
    netuid: u16,
}

impl ShutdownHandler {
    fn new(checkpoint_dir: &Path, state_manager: Arc<StateManager>, netuid: u16) -> Result<Self> {
        let checkpoint_manager = CheckpointManager::new(checkpoint_dir.join("checkpoints"), 10)?;
        Ok(Self {
            checkpoint_manager,
            state_manager,
            netuid,
        })
    }

    /// Create checkpoint from current state
    fn create_checkpoint(&mut self) -> Result<()> {
        let state = self.state_manager.snapshot();

        let mut checkpoint_data = CheckpointData::new(state.sequence, state.epoch, self.netuid);

        // Convert pending evaluations
        for (id, record) in &state.pending_evaluations {
            let pending = PendingEvaluationState {
                submission_id: id.clone(),
                challenge_id: record.challenge_id,
                miner: record.miner.clone(),
                submission_hash: record.agent_hash.clone(),
                scores: record
                    .evaluations
                    .iter()
                    .map(|(k, v)| (k.clone(), v.score))
                    .collect(),
                created_at: record.created_at,
                finalizing: record.finalized,
            };
            checkpoint_data.add_pending(pending);
        }

        // Convert completed evaluations (current epoch only)
        if let Some(completed) = state.completed_evaluations.get(&state.epoch) {
            for record in completed {
                if let Some(score) = record.aggregated_score {
                    let completed_state = CompletedEvaluationState {
                        submission_id: record.submission_id.clone(),
                        challenge_id: record.challenge_id,
                        final_score: score,
                        epoch: state.epoch,
                        completed_at: record.finalized_at.unwrap_or(record.created_at),
                    };
                    checkpoint_data.add_completed(completed_state);
                }
            }
        }

        // Convert weight votes
        if let Some(ref votes) = state.weight_votes {
            checkpoint_data.weight_votes = Some(WeightVoteState {
                epoch: votes.epoch,
                netuid: votes.netuid,
                votes: votes.votes.clone(),
                finalized: votes.finalized,
                final_weights: votes.final_weights.clone(),
            });
        }

        checkpoint_data.bittensor_block = state.bittensor_block;

        self.checkpoint_manager
            .create_checkpoint(&checkpoint_data)?;
        info!("Shutdown checkpoint created at sequence {}", state.sequence);

        Ok(())
    }
}

// ==================== CLI ====================

#[derive(Parser)]
#[command(name = "validator-node")]
#[command(about = "Platform Validator - Decentralized P2P Architecture")]
struct Args {
    /// Secret key (hex or mnemonic)
    #[arg(short = 'k', long, env = "VALIDATOR_SECRET_KEY")]
    secret_key: Option<String>,

    /// Data directory
    #[arg(short, long, default_value = "./data")]
    data_dir: PathBuf,

    /// P2P listen address
    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/8090")]
    listen_addr: String,

    /// External address to announce to peers (multiaddr format, e.g. /ip4/1.2.3.4/tcp/8090)
    /// Use this when running behind NAT or in Docker to announce your public IP
    #[arg(long, env = "EXTERNAL_ADDR")]
    external_addr: Option<String>,

    /// Bootstrap peers (multiaddr format)
    #[arg(long)]
    bootstrap: Vec<String>,

    /// Subtensor endpoint
    #[arg(
        long,
        env = "SUBTENSOR_ENDPOINT",
        default_value = "wss://entrypoint-finney.opentensor.ai:443"
    )]
    subtensor_endpoint: String,

    /// Network UID
    #[arg(long, env = "NETUID", default_value = "100")]
    netuid: u16,

    /// Version key
    #[arg(long, env = "VERSION_KEY", default_value = "1")]
    version_key: u64,

    /// Disable Bittensor (for testing)
    #[arg(long)]
    no_bittensor: bool,

    /// Run as bootnode (read-only Bittensor access, no signing required)
    #[arg(long)]
    bootnode: bool,

    /// Directory where WASM challenge modules are stored
    #[arg(long, env = "WASM_MODULE_DIR", default_value = "./wasm_modules")]
    wasm_module_dir: PathBuf,

    /// Maximum memory for WASM execution in bytes (default: 512MB)
    #[arg(long, env = "WASM_MAX_MEMORY", default_value = "536870912")]
    wasm_max_memory: u64,

    /// Enable fuel metering for WASM execution
    #[arg(long, env = "WASM_ENABLE_FUEL")]
    wasm_enable_fuel: bool,

    /// Fuel limit per WASM execution (requires --wasm-enable-fuel)
    #[arg(long, env = "WASM_FUEL_LIMIT")]
    wasm_fuel_limit: Option<u64>,
}

impl std::fmt::Debug for Args {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Args")
            .field(
                "secret_key",
                &self.secret_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("data_dir", &self.data_dir)
            .field("listen_addr", &self.listen_addr)
            .field("bootstrap", &self.bootstrap)
            .field("subtensor_endpoint", &self.subtensor_endpoint)
            .field("netuid", &self.netuid)
            .field("version_key", &self.version_key)
            .field("no_bittensor", &self.no_bittensor)
            .field("bootnode", &self.bootnode)
            .field("wasm_module_dir", &self.wasm_module_dir)
            .field("wasm_max_memory", &self.wasm_max_memory)
            .field("wasm_enable_fuel", &self.wasm_enable_fuel)
            .field("wasm_fuel_limit", &self.wasm_fuel_limit)
            .finish()
    }
}

// ==================== Main ====================

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "info,validator_node=debug,platform_p2p_consensus=debug".into()
            }),
        )
        .init();

    let args = Args::parse();

    info!("Starting decentralized validator");
    info!("SudoOwner: {}", SUDO_KEY_SS58);

    // Load keypair
    let keypair = load_keypair(&args)?;
    let validator_hotkey = keypair.ss58_address();
    info!("Validator hotkey: {}", validator_hotkey);

    // Create data directory
    std::fs::create_dir_all(&args.data_dir)?;
    let data_dir = std::fs::canonicalize(&args.data_dir)?;

    // Initialize distributed storage
    let storage = LocalStorageBuilder::new(&validator_hotkey)
        .path(
            data_dir
                .join("distributed.db")
                .to_string_lossy()
                .to_string(),
        )
        .build()?;
    let storage = Arc::new(storage);
    info!("Distributed storage initialized");

    // Build P2P config - use defaults and add any extra bootstrap peers from CLI
    let mut p2p_config = P2PConfig::default()
        .with_listen_addr(&args.listen_addr)
        .with_netuid(args.netuid)
        .with_min_stake(10_000_000_000_000); // 10000 TAO

    // Set external address if provided (for NAT/Docker environments)
    if let Some(ref external_addr) = args.external_addr {
        p2p_config = p2p_config.with_external_addrs(vec![external_addr.clone()]);
        info!("External address configured: {}", external_addr);
    }

    // Add CLI bootstrap peers to defaults (don't replace)
    for peer in &args.bootstrap {
        if !p2p_config.bootstrap_peers.contains(peer) {
            p2p_config.bootstrap_peers.push(peer.clone());
        }
    }

    if p2p_config.bootstrap_peers.is_empty() {
        warn!("No bootstrap peers configured. This node will act as a bootnode (waiting for peers to connect).");
    } else {
        info!("Bootstrap peers: {:?}", p2p_config.bootstrap_peers);
    }

    // Initialize validator set (ourselves first)
    let validator_set = Arc::new(ValidatorSet::new(keypair.clone(), p2p_config.min_stake));
    info!("P2P network config initialized");

    // Initialize state manager, loading persisted state if available
    let state_manager = Arc::new(
        load_state_from_storage(&storage, args.netuid)
            .await
            .unwrap_or_else(|| {
                info!("No persisted state found, starting fresh");
                StateManager::for_netuid(args.netuid)
            }),
    );

    // Create event channel for network events
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<NetworkEvent>(256);

    // Initialize P2P network
    let network = Arc::new(P2PNetwork::new(
        keypair.clone(),
        p2p_config,
        validator_set.clone(),
        event_tx.clone(),
    )?);
    info!(
        "P2P network initialized, local peer: {:?}",
        network.local_peer_id()
    );

    // Create command channel for P2P network
    let (p2p_cmd_tx, p2p_cmd_rx) =
        tokio::sync::mpsc::channel::<platform_p2p_consensus::P2PCommand>(256);

    // Spawn P2P network task
    let network_clone = network.clone();
    tokio::spawn(async move {
        if let Err(e) = network_clone.run(p2p_cmd_rx).await {
            error!("P2P network error: {}", e);
        }
    });

    // Initialize consensus engine
    let consensus = Arc::new(RwLock::new(ConsensusEngine::new(
        keypair.clone(),
        validator_set.clone(),
        state_manager.clone(),
    )));

    // Connect to Bittensor
    let subtensor: Option<Arc<Subtensor>>;
    let subtensor_signer: Option<Arc<BittensorSigner>>;
    let mut subtensor_client: Option<SubtensorClient>;
    let bittensor_client_for_metagraph: Option<Arc<BittensorClient>>;
    let mut block_rx: Option<tokio::sync::mpsc::Receiver<BlockSyncEvent>> = None;

    if !args.no_bittensor {
        info!("Connecting to Bittensor: {}", args.subtensor_endpoint);

        if args.bootnode {
            // Bootnode mode: read-only access to metagraph, no signing required
            info!("Running in bootnode mode (read-only Bittensor access)");
            subtensor = None;
            subtensor_signer = None;

            // Create SubtensorClient for metagraph only
            let mut client = SubtensorClient::new(platform_bittensor::BittensorConfig {
                endpoint: args.subtensor_endpoint.clone(),
                netuid: args.netuid,
                ..Default::default()
            });

            match BittensorClient::new(&args.subtensor_endpoint).await {
                Ok(bittensor_client) => {
                    let bittensor_client = Arc::new(bittensor_client);
                    match sync_metagraph(&bittensor_client, args.netuid).await {
                        Ok(mg) => {
                            info!("Metagraph synced: {} neurons", mg.n);
                            update_validator_set_from_metagraph(&mg, &validator_set);
                            info!(
                                "Validator set: {} active validators",
                                validator_set.active_count()
                            );
                            client.set_metagraph(mg);
                        }
                        Err(e) => warn!("Metagraph sync failed: {}", e),
                    }
                    subtensor_client = Some(client);
                    bittensor_client_for_metagraph = Some(bittensor_client);
                }
                Err(e) => {
                    error!("Bittensor client connection failed: {}", e);
                    subtensor_client = None;
                    bittensor_client_for_metagraph = None;
                }
            }
        } else {
            // Full validator mode: requires signing key
            let state_path = data_dir.join("subtensor_state.json");
            match Subtensor::with_persistence(&args.subtensor_endpoint, state_path).await {
                Ok(st) => {
                    let secret = args
                        .secret_key
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("VALIDATOR_SECRET_KEY required"))?;

                    let signer = signer_from_seed(secret).map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to create Bittensor signer from secret key: {}. \
                            A valid signer is required for weight submission. \
                            Use --no-bittensor flag if running without Bittensor.",
                            e
                        )
                    })?;
                    info!("Bittensor signer initialized: {}", signer.account_id());
                    subtensor_signer = Some(Arc::new(signer));

                    subtensor = Some(Arc::new(st));

                    // Create SubtensorClient for metagraph
                    let mut client = SubtensorClient::new(platform_bittensor::BittensorConfig {
                        endpoint: args.subtensor_endpoint.clone(),
                        netuid: args.netuid,
                        ..Default::default()
                    });

                    let bittensor_client =
                        Arc::new(BittensorClient::new(&args.subtensor_endpoint).await?);
                    match sync_metagraph(&bittensor_client, args.netuid).await {
                        Ok(mg) => {
                            info!("Metagraph synced: {} neurons", mg.n);

                            // Update validator set from metagraph
                            update_validator_set_from_metagraph(&mg, &validator_set);
                            info!(
                                "Validator set: {} active validators",
                                validator_set.active_count()
                            );

                            client.set_metagraph(mg);
                        }
                        Err(e) => warn!("Metagraph sync failed: {}", e),
                    }

                    subtensor_client = Some(client);

                    // Store bittensor client for metagraph refreshes
                    bittensor_client_for_metagraph = Some(bittensor_client.clone());

                    // Block sync
                    let mut sync = BlockSync::new(BlockSyncConfig {
                        netuid: args.netuid,
                        ..Default::default()
                    });
                    let rx = sync.take_event_receiver();

                    if let Err(e) = sync.connect(bittensor_client).await {
                        warn!("Block sync failed: {}", e);
                    } else {
                        tokio::spawn(async move {
                            if let Err(e) = sync.start().await {
                                error!("Block sync error: {}", e);
                            }
                        });
                        block_rx = rx;
                        info!("Block sync started");
                    }
                }
                Err(e) => {
                    error!("Subtensor connection failed: {}", e);
                    subtensor = None;
                    subtensor_signer = None;
                    subtensor_client = None;
                    bittensor_client_for_metagraph = None;
                }
            }
        }
    } else {
        info!("Bittensor disabled");
        subtensor = None;
        subtensor_signer = None;
        subtensor_client = None;
        bittensor_client_for_metagraph = None;
    }

    // Initialize WASM challenge executor
    let wasm_module_dir = if args.wasm_module_dir.is_relative() {
        data_dir.join(&args.wasm_module_dir)
    } else {
        args.wasm_module_dir.clone()
    };
    std::fs::create_dir_all(&wasm_module_dir)?;

    let challenges_subdir = wasm_module_dir.join("challenges");
    std::fs::create_dir_all(&challenges_subdir)?;

    let wasm_executor = match WasmChallengeExecutor::new(WasmExecutorConfig {
        module_dir: wasm_module_dir.clone(),
        max_memory_bytes: args.wasm_max_memory,
        enable_fuel: args.wasm_enable_fuel,
        fuel_limit: args.wasm_fuel_limit,
        storage_host_config: wasm_runtime_interface::StorageHostConfig::default(),
        storage_backend: std::sync::Arc::new(wasm_runtime_interface::InMemoryStorageBackend::new()),
        chutes_api_key: None,
    }) {
        Ok(executor) => {
            info!(
                module_dir = %wasm_module_dir.display(),
                max_memory = args.wasm_max_memory,
                fuel_enabled = args.wasm_enable_fuel,
                "WASM challenge executor ready"
            );
            Some(Arc::new(executor))
        }
        Err(e) => {
            error!(
                "Failed to initialize WASM executor: {}. WASM evaluations disabled.",
                e
            );
            None
        }
    };

    // Initialize shutdown handler for graceful checkpoint persistence
    let mut shutdown_handler =
        match ShutdownHandler::new(&data_dir, state_manager.clone(), args.netuid) {
            Ok(handler) => {
                info!("Shutdown handler initialized with checkpoint directory");
                Some(handler)
            }
            Err(e) => {
                warn!(
                    "Failed to initialize shutdown handler: {}. Checkpoints disabled.",
                    e
                );
                None
            }
        };

    info!("Decentralized validator running. Press Ctrl+C to stop.");

    let netuid = args.netuid;
    let version_key = args.version_key;
    let is_bootnode = args.bootnode;
    let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(30));
    let mut metagraph_interval = tokio::time::interval(Duration::from_secs(300));
    let mut stale_check_interval = tokio::time::interval(Duration::from_secs(60));
    let mut state_persist_interval = tokio::time::interval(Duration::from_secs(60));
    let mut checkpoint_interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
    let mut wasm_eval_interval = tokio::time::interval(Duration::from_secs(5));
    let mut stale_job_interval = tokio::time::interval(Duration::from_secs(120));

    // Clone p2p_cmd_tx for use in the loop
    let p2p_broadcast_tx = p2p_cmd_tx.clone();

    loop {
        tokio::select! {
            // P2P network events
            Some(event) = event_rx.recv() => {
                handle_network_event(
                    event,
                    &consensus,
                    &validator_set,
                    &state_manager,
                    &wasm_executor,
                ).await;
            }

            // Bittensor block events
            Some(event) = async {
                match block_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                handle_block_event(
                    event,
                    &subtensor,
                    &subtensor_signer,
                    &subtensor_client,
                    &state_manager,
                    netuid,
                    version_key,
                    &wasm_executor,
                    &keypair,
                ).await;
            }

            // Heartbeat - broadcast to other validators (skip in bootnode mode)
            _ = heartbeat_interval.tick() => {
                if !is_bootnode {
                    let state_hash = state_manager.state_hash();
                    let sequence = state_manager.sequence();
                    let our_hotkey = keypair.hotkey();
                    
                    // Get our stake from validator set
                    let our_stake = validator_set.stake_for(&our_hotkey);
                    
                    let heartbeat = P2PMessage::Heartbeat(HeartbeatMessage {
                        validator: our_hotkey,
                        state_hash,
                        sequence,
                        stake: our_stake,
                        timestamp: chrono::Utc::now().timestamp_millis(),
                        signature: vec![], // Will be signed by P2P layer
                    });
                    
                    if let Err(e) = p2p_broadcast_tx.send(platform_p2p_consensus::P2PCommand::Broadcast(heartbeat)).await {
                        warn!("Failed to broadcast heartbeat: {}", e);
                    }
                    
                    debug!("Heartbeat: sequence={}, state_hash={}", sequence, hex::encode(&state_hash[..8]));
                }
                
                // Update validator activity count (both bootnode and validators)
                validator_set.mark_stale_validators();
                debug!("Active validators: {}", validator_set.active_count());
            }

            // Periodic state persistence
            _ = state_persist_interval.tick() => {
                if let Err(e) = persist_state_to_storage(&storage, &state_manager).await {
                    warn!("Failed to persist state: {}", e);
                } else {
                    debug!("State persisted to storage");
                }
            }

            // Metagraph refresh
            _ = metagraph_interval.tick() => {
                if let Some(client) = bittensor_client_for_metagraph.as_ref() {
                    debug!("Refreshing metagraph from Bittensor...");
                    match sync_metagraph(client, netuid).await {
                        Ok(mg) => {
                            info!("Metagraph refreshed: {} neurons", mg.n);
                            update_validator_set_from_metagraph(&mg, &validator_set);
                            if let Some(sc) = subtensor_client.as_mut() {
                                sc.set_metagraph(mg);
                            }
                            info!("Validator set updated: {} active validators", validator_set.active_count());
                        }
                        Err(e) => {
                            warn!("Metagraph refresh failed: {}. Will retry on next interval.", e);
                        }
                    }
                } else {
                    debug!("Metagraph refresh skipped (Bittensor not connected)");
                }
            }

            // Check for stale validators
            _ = stale_check_interval.tick() => {
                validator_set.mark_stale_validators();
                debug!("Active validators: {}", validator_set.active_count());
            }

            // WASM evaluation check
            _ = wasm_eval_interval.tick() => {
                if let Some(ref executor) = wasm_executor {
                    process_wasm_evaluations(
                        executor,
                        &state_manager,
                        &keypair,
                        &p2p_broadcast_tx,
                    ).await;
                }
            }

            // Stale job cleanup
            _ = stale_job_interval.tick() => {
                let now = chrono::Utc::now().timestamp_millis();
                let stale = state_manager.apply(|state| state.cleanup_stale_jobs(now));
                if !stale.is_empty() {
                    info!(count = stale.len(), "Cleaned up stale jobs");
                }
            }

            // Periodic checkpoint
            _ = checkpoint_interval.tick() => {
                if let Some(handler) = shutdown_handler.as_mut() {
                    if let Err(e) = handler.create_checkpoint() {
                        warn!("Failed to create periodic checkpoint: {}", e);
                    } else {
                        debug!("Periodic checkpoint created");
                    }
                }
            }

            // Ctrl+C
            _ = tokio::signal::ctrl_c() => {
                info!("Received shutdown signal, creating final checkpoint...");
                if let Some(handler) = shutdown_handler.as_mut() {
                    if let Err(e) = handler.create_checkpoint() {
                        error!("Failed to create shutdown checkpoint: {}", e);
                    } else {
                        info!("Shutdown checkpoint saved successfully");
                    }
                }
                info!("Shutting down...");
                break;
            }
        }
    }

    info!("Stopped.");
    Ok(())
}

fn load_keypair(args: &Args) -> Result<Keypair> {
    match args.secret_key.as_ref() {
        Some(secret) => {
            let secret = secret.trim();
            let hex = secret.strip_prefix("0x").unwrap_or(secret);

            if hex.len() == 64 {
                if let Ok(bytes) = hex::decode(hex) {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        return Ok(Keypair::from_seed(&arr)?);
                    }
                }
            }

            Ok(Keypair::from_mnemonic(secret)?)
        }
        None => {
            if args.bootnode {
                // Bootnode mode without secret key - generate random keypair
                // Note: This means the PeerId will change on each restart.
                // For a stable PeerId, provide BOOTNODE_SECRET_KEY.
                warn!("No secret key provided in bootnode mode, generating random keypair (PeerId will change on restart)");
                let seed: [u8; 32] = rand::random();
                Ok(Keypair::from_seed(&seed)?)
            } else {
                Err(anyhow::anyhow!("VALIDATOR_SECRET_KEY required"))
            }
        }
    }
}

/// Load persisted state from distributed storage
async fn load_state_from_storage(storage: &Arc<LocalStorage>, netuid: u16) -> Option<StateManager> {
    let key = StorageKey::new("state", STATE_STORAGE_KEY);
    match storage.get_json::<ChainState>(&key).await {
        Ok(Some(state)) => {
            // Verify the state is for the correct netuid
            if state.netuid != netuid {
                warn!(
                    "Persisted state has different netuid ({} vs {}), ignoring",
                    state.netuid, netuid
                );
                return None;
            }
            info!(
                "Loaded persisted state: sequence={}, epoch={}, validators={}",
                state.sequence,
                state.epoch,
                state.validators.len()
            );
            Some(StateManager::new(state))
        }
        Ok(None) => {
            debug!("No persisted state found in storage");
            None
        }
        Err(e) => {
            warn!("Failed to load persisted state: {}", e);
            None
        }
    }
}

/// Persist current state to distributed storage
async fn persist_state_to_storage(
    storage: &Arc<LocalStorage>,
    state_manager: &Arc<StateManager>,
) -> Result<()> {
    let state = state_manager.snapshot();
    let key = StorageKey::new("state", STATE_STORAGE_KEY);
    storage.put_json(key, &state).await?;
    Ok(())
}

/// Update validator set from metagraph data
fn update_validator_set_from_metagraph(metagraph: &Metagraph, validator_set: &Arc<ValidatorSet>) {
    for neuron in metagraph.neurons.values() {
        let hotkey_bytes: [u8; 32] = neuron.hotkey.clone().into();
        let hotkey = Hotkey(hotkey_bytes);
        // Get effective stake capped to u64::MAX (neuron.stake is u128)
        let stake = neuron.stake.min(u64::MAX as u128) as u64;
        let record = ValidatorRecord::new(hotkey, stake);
        if let Err(e) = validator_set.register_validator(record) {
            debug!("Skipping validator registration: {}", e);
        }
    }
}

async fn handle_network_event(
    event: NetworkEvent,
    consensus: &Arc<RwLock<ConsensusEngine>>,
    validator_set: &Arc<ValidatorSet>,
    state_manager: &Arc<StateManager>,
    wasm_executor_ref: &Option<Arc<WasmChallengeExecutor>>,
) {
    match event {
        NetworkEvent::Message { source, message } => match message {
            P2PMessage::Proposal(proposal) => {
                let engine = consensus.write();
                match engine.handle_proposal(proposal) {
                    Ok(_prepare) => {
                        debug!("Proposal handled, prepare sent");
                    }
                    Err(e) => {
                        warn!("Failed to handle proposal: {}", e);
                    }
                }
            }
            P2PMessage::PrePrepare(_pp) => {
                debug!("Received pre-prepare from {:?}", source);
            }
            P2PMessage::Prepare(p) => {
                let engine = consensus.write();
                match engine.handle_prepare(p) {
                    Ok(Some(_commit)) => {
                        debug!("Prepare quorum reached, commit created");
                    }
                    Ok(None) => {
                        debug!("Prepare received, waiting for quorum");
                    }
                    Err(e) => {
                        warn!("Failed to handle prepare: {}", e);
                    }
                }
            }
            P2PMessage::Commit(c) => {
                let engine = consensus.write();
                match engine.handle_commit(c) {
                    Ok(Some(decision)) => {
                        info!("Consensus achieved for sequence {}", decision.sequence);
                    }
                    Ok(None) => {
                        debug!("Commit received, waiting for quorum");
                    }
                    Err(e) => {
                        warn!("Failed to handle commit: {}", e);
                    }
                }
            }
            P2PMessage::ViewChange(vc) => {
                let engine = consensus.write();
                match engine.handle_view_change(vc) {
                    Ok(Some(new_view)) => {
                        info!("View change completed, new view: {}", new_view.view);
                    }
                    Ok(None) => {
                        debug!("View change in progress");
                    }
                    Err(e) => {
                        warn!("View change error: {}", e);
                    }
                }
            }
            P2PMessage::NewView(nv) => {
                let engine = consensus.write();
                if let Err(e) = engine.handle_new_view(nv) {
                    warn!("Failed to handle new view: {}", e);
                }
            }
            P2PMessage::Heartbeat(hb) => {
                if let Err(e) = validator_set.update_from_heartbeat(
                    &hb.validator,
                    hb.state_hash,
                    hb.sequence,
                    hb.stake,
                ) {
                    debug!("Heartbeat update skipped: {}", e);
                }
            }
            P2PMessage::Submission(sub) => {
                info!(
                    submission_id = %sub.submission_id,
                    challenge_id = %sub.challenge_id,
                    miner = %sub.miner.to_hex(),
                    "Received submission from P2P network"
                );
                let already_exists = state_manager
                    .read(|state| state.pending_evaluations.contains_key(&sub.submission_id));
                if already_exists {
                    debug!(
                        submission_id = %sub.submission_id,
                        "Submission already exists in pending evaluations, skipping"
                    );
                } else {
                    let record = EvaluationRecord {
                        submission_id: sub.submission_id.clone(),
                        challenge_id: sub.challenge_id,
                        miner: sub.miner,
                        agent_hash: sub.agent_hash,
                        evaluations: std::collections::HashMap::new(),
                        aggregated_score: None,
                        finalized: false,
                        created_at: sub.timestamp,
                        finalized_at: None,
                    };
                    state_manager.apply(|state| {
                        state.add_evaluation(record);
                    });
                    info!(
                        submission_id = %sub.submission_id,
                        "Submission added to pending evaluations"
                    );
                }
            }
            P2PMessage::Evaluation(eval) => {
                info!(
                    submission_id = %eval.submission_id,
                    validator = %eval.validator.to_hex(),
                    score = eval.score,
                    "Received evaluation from peer validator"
                );
                let validator_hotkey = eval.validator.clone();
                let stake = validator_set
                    .get_validator(&validator_hotkey)
                    .map(|v| v.stake)
                    .unwrap_or(0);
                let validator_eval = platform_p2p_consensus::ValidatorEvaluation {
                    score: eval.score,
                    stake,
                    timestamp: eval.timestamp,
                    signature: eval.signature.clone(),
                };
                state_manager.apply(|state| {
                    if let Err(e) = state.add_validator_evaluation(
                        &eval.submission_id,
                        validator_hotkey.clone(),
                        validator_eval,
                        &eval.signature,
                    ) {
                        warn!(
                            submission_id = %eval.submission_id,
                            validator = %validator_hotkey.to_hex(),
                            error = %e,
                            "Failed to add peer evaluation to state"
                        );
                    } else {
                        debug!(
                            submission_id = %eval.submission_id,
                            validator = %validator_hotkey.to_hex(),
                            score = eval.score,
                            "Peer evaluation recorded in state"
                        );
                    }
                });
            }
            P2PMessage::StateRequest(req) => {
                debug!(
                    requester = %req.requester.to_hex(),
                    sequence = req.current_sequence,
                    "Received state request"
                );
            }
            P2PMessage::StateResponse(resp) => {
                debug!(
                    responder = %resp.responder.to_hex(),
                    sequence = resp.sequence,
                    "Received state response"
                );
            }
            P2PMessage::WeightVote(wv) => {
                debug!(
                    validator = %wv.validator.to_hex(),
                    epoch = wv.epoch,
                    "Received weight vote"
                );
            }
            P2PMessage::PeerAnnounce(pa) => {
                debug!(
                    validator = %pa.validator.to_hex(),
                    peer_id = %pa.peer_id,
                    addresses = pa.addresses.len(),
                    "Received peer announce"
                );
            }
            P2PMessage::JobClaim(claim) => {
                info!(
                    validator = %claim.validator.to_hex(),
                    challenge_id = %claim.challenge_id,
                    max_jobs = claim.max_jobs,
                    "Received job claim"
                );
            }
            P2PMessage::JobAssignment(assignment) => {
                info!(
                    submission_id = %assignment.submission_id,
                    challenge_id = %assignment.challenge_id,
                    assigned_validator = %assignment.assigned_validator.to_hex(),
                    assigner = %assignment.assigner.to_hex(),
                    "Received job assignment"
                );
                let job = JobRecord {
                    submission_id: assignment.submission_id.clone(),
                    challenge_id: assignment.challenge_id,
                    assigned_validator: assignment.assigned_validator,
                    assigned_at: assignment.timestamp,
                    timeout_at: assignment.timestamp + JOB_TIMEOUT_MS,
                    status: JobStatus::Pending,
                };
                state_manager.apply(|state| {
                    state.assign_job(job);
                });
            }
            P2PMessage::DataRequest(req) => {
                debug!(
                    request_id = %req.request_id,
                    requester = %req.requester.to_hex(),
                    challenge_id = %req.challenge_id,
                    data_type = %req.data_type,
                    "Received data request"
                );
            }
            P2PMessage::DataResponse(resp) => {
                debug!(
                    request_id = %resp.request_id,
                    responder = %resp.responder.to_hex(),
                    challenge_id = %resp.challenge_id,
                    data_bytes = resp.data.len(),
                    "Received data response"
                );
            }
            P2PMessage::TaskProgress(progress) => {
                debug!(
                    submission_id = %progress.submission_id,
                    challenge_id = %progress.challenge_id,
                    validator = %progress.validator.to_hex(),
                    task_index = progress.task_index,
                    total_tasks = progress.total_tasks,
                    progress_pct = progress.progress_pct,
                    "Received task progress"
                );
                let record = TaskProgressRecord {
                    submission_id: progress.submission_id.clone(),
                    challenge_id: progress.challenge_id,
                    validator: progress.validator,
                    task_index: progress.task_index,
                    total_tasks: progress.total_tasks,
                    status: progress.status,
                    progress_pct: progress.progress_pct,
                    updated_at: progress.timestamp,
                };
                state_manager.apply(|state| {
                    state.update_task_progress(record);
                });
            }
            P2PMessage::TaskResult(result) => {
                info!(
                    submission_id = %result.submission_id,
                    challenge_id = %result.challenge_id,
                    validator = %result.validator.to_hex(),
                    task_id = %result.task_id,
                    passed = result.passed,
                    score = result.score,
                    execution_time_ms = result.execution_time_ms,
                    "Received task result"
                );
            }
            P2PMessage::LeaderboardRequest(req) => {
                debug!(
                    requester = %req.requester.to_hex(),
                    challenge_id = %req.challenge_id,
                    limit = req.limit,
                    offset = req.offset,
                    "Received leaderboard request"
                );
            }
            P2PMessage::LeaderboardResponse(resp) => {
                debug!(
                    responder = %resp.responder.to_hex(),
                    challenge_id = %resp.challenge_id,
                    total_count = resp.total_count,
                    "Received leaderboard response"
                );
            }
            P2PMessage::ChallengeUpdate(update) => {
                let updater_ss58 = update.updater.to_hex();
                if updater_ss58 == platform_p2p_consensus::SUDO_HOTKEY
                    || update.updater.0 == platform_core::SUDO_KEY_BYTES
                {
                    info!(
                        challenge_id = %update.challenge_id,
                        updater = %updater_ss58,
                        update_type = %update.update_type,
                        data_bytes = update.data.len(),
                        "Received authorized challenge update from sudo key"
                    );
                    if let Some(ref executor) = wasm_executor_ref {
                        executor.invalidate_cache(&update.challenge_id.to_string());
                    }
                } else {
                    warn!(
                        challenge_id = %update.challenge_id,
                        updater = %updater_ss58,
                        "Rejected challenge update from non-sudo key"
                    );
                }
            }
            P2PMessage::StorageProposal(proposal) => {
                debug!(
                    proposal_id = %hex::encode(&proposal.proposal_id[..8]),
                    challenge_id = %proposal.challenge_id,
                    proposer = %proposal.proposer.to_hex(),
                    key_len = proposal.key.len(),
                    value_len = proposal.value.len(),
                    "Received storage proposal"
                );
            }
            P2PMessage::StorageVote(vote) => {
                debug!(
                    proposal_id = %hex::encode(&vote.proposal_id[..8]),
                    voter = %vote.voter.to_hex(),
                    approve = vote.approve,
                    "Received storage vote"
                );
            }
            P2PMessage::ReviewAssignment(msg) => {
                debug!(
                    submission_id = %msg.submission_id,
                    assigner = %msg.assigner.to_hex(),
                    assigned_count = msg.assigned_validators.len(),
                    "Received review assignment"
                );
            }
            P2PMessage::ReviewDecline(msg) => {
                let safe_reason = sanitize_for_log(&msg.reason);
                debug!(
                    submission_id = %msg.submission_id,
                    validator = %msg.validator.to_hex(),
                    reason = %safe_reason,
                    "Received review decline"
                );
            }
            P2PMessage::ReviewResult(msg) => {
                debug!(
                    submission_id = %msg.submission_id,
                    validator = %msg.validator.to_hex(),
                    score = msg.score,
                    "Received review result"
                );
            }
            P2PMessage::AgentLogProposal(msg) => {
                debug!(
                    submission_id = %msg.submission_id,
                    validator = %msg.validator_hotkey.to_hex(),
                    "Received agent log proposal"
                );
            }
        },
        NetworkEvent::PeerConnected(peer_id) => {
            info!("Peer connected: {}", peer_id);
        }
        NetworkEvent::PeerDisconnected(peer_id) => {
            info!("Peer disconnected: {}", peer_id);
        }
        NetworkEvent::PeerIdentified {
            peer_id,
            hotkey,
            addresses,
        } => {
            info!(
                "Peer identified: {} with {} addresses",
                peer_id,
                addresses.len()
            );
            if let Some(hk) = hotkey {
                debug!("  Hotkey: {:?}", hk);
            }
        }
    }
}

async fn handle_block_event(
    event: BlockSyncEvent,
    subtensor: &Option<Arc<Subtensor>>,
    signer: &Option<Arc<BittensorSigner>>,
    _client: &Option<SubtensorClient>,
    state_manager: &Arc<StateManager>,
    netuid: u16,
    version_key: u64,
    wasm_executor: &Option<Arc<WasmChallengeExecutor>>,
    keypair: &Keypair,
) {
    match event {
        BlockSyncEvent::NewBlock { block_number, .. } => {
            debug!("Block {}", block_number);
            // Link state to Bittensor block (block hash not available in event, use zeros)
            state_manager.apply(|state| {
                state.link_to_bittensor_block(block_number, [0u8; 32]);
            });
        }
        BlockSyncEvent::EpochTransition {
            old_epoch,
            new_epoch,
            block,
        } => {
            info!(
                "Epoch transition: {} -> {} (block {})",
                old_epoch, new_epoch, block
            );

            // Transition state to next epoch
            state_manager.apply(|state| {
                state.next_epoch();
            });
        }
        BlockSyncEvent::CommitWindowOpen { epoch, block } => {
            info!(
                "=== COMMIT WINDOW OPEN: epoch {} block {} ===",
                epoch, block
            );

            // Collect WASM-computed weights from challenges before finalizing
            if let Some(ref executor) = wasm_executor {
                let challenges: Vec<String> = state_manager
                    .apply(|state| state.challenges.keys().map(|k| k.to_string()).collect());
                let local_hotkey = keypair.hotkey();
                for cid in &challenges {
                    match executor.execute_get_weights(cid) {
                        Ok(weights) if !weights.is_empty() => {
                            state_manager.apply(|state| {
                                if let Err(e) = state.submit_weight_vote(
                                    local_hotkey.clone(),
                                    netuid,
                                    weights.clone(),
                                ) {
                                    warn!(
                                        challenge_id = %cid,
                                        error = %e,
                                        "Failed to submit WASM-computed weights"
                                    );
                                }
                            });
                            info!(
                                challenge_id = %cid,
                                weight_count = weights.len(),
                                "Integrated WASM-computed weights"
                            );
                        }
                        Ok(_) => {}
                        Err(e) => {
                            debug!(
                                challenge_id = %cid,
                                error = %e,
                                "WASM get_weights not available for challenge"
                            );
                        }
                    }
                }
            }

            // Get weights from decentralized state
            if let (Some(st), Some(sig)) = (subtensor.as_ref(), signer.as_ref()) {
                let final_weights = state_manager.apply(|state| state.finalize_weights());

                match final_weights {
                    Some(weights) if !weights.is_empty() => {
                        // Convert to arrays for submission
                        let uids: Vec<u16> = weights.iter().map(|(uid, _)| *uid).collect();
                        let vals: Vec<u16> = weights.iter().map(|(_, w)| *w).collect();

                        info!("Submitting weights for {} UIDs", uids.len());
                        match st
                            .set_mechanism_weights(
                                sig,
                                netuid,
                                0,
                                &uids,
                                &vals,
                                version_key,
                                ExtrinsicWait::Finalized,
                            )
                            .await
                        {
                            Ok(resp) if resp.success => {
                                info!("Weights submitted: {:?}", resp.tx_hash);
                            }
                            Ok(resp) => warn!("Weight submission issue: {}", resp.message),
                            Err(e) => error!("Weight submission failed: {}", e),
                        }
                    }
                    _ => {
                        info!("No challenge weights for epoch {} - submitting burn weights (100% to UID 0)", epoch);
                        match st
                            .set_mechanism_weights(
                                sig,
                                netuid,
                                0,
                                &[0u16],
                                &[65535u16],
                                version_key,
                                ExtrinsicWait::Finalized,
                            )
                            .await
                        {
                            Ok(resp) if resp.success => {
                                info!("Burn weights submitted: {:?}", resp.tx_hash);
                            }
                            Ok(resp) => warn!("Burn weight submission issue: {}", resp.message),
                            Err(e) => error!("Burn weight submission failed: {}", e),
                        }
                    }
                }
            }
        }
        BlockSyncEvent::RevealWindowOpen { epoch, block } => {
            info!(
                "=== REVEAL WINDOW OPEN: epoch {} block {} ===",
                epoch, block
            );

            if let (Some(st), Some(sig)) = (subtensor.as_ref(), signer.as_ref()) {
                if st.has_pending_commits().await {
                    info!("Revealing pending commits...");
                    match st.reveal_all_pending(sig, ExtrinsicWait::Finalized).await {
                        Ok(results) => {
                            for resp in results {
                                if resp.success {
                                    info!("Revealed: {:?}", resp.tx_hash);
                                } else {
                                    warn!("Reveal issue: {}", resp.message);
                                }
                            }
                        }
                        Err(e) => error!("Reveal failed: {}", e),
                    }
                } else {
                    debug!("No pending commits to reveal");
                }
            }
        }
        BlockSyncEvent::PhaseChange {
            old_phase,
            new_phase,
            epoch,
            ..
        } => {
            debug!(
                "Phase change: {:?} -> {:?} (epoch {})",
                old_phase, new_phase, epoch
            );
        }
        BlockSyncEvent::Disconnected(reason) => {
            warn!("Bittensor disconnected: {}", reason);
        }
        BlockSyncEvent::Reconnected => {
            info!("Bittensor reconnected");
        }
    }
}

async fn process_wasm_evaluations(
    executor: &Arc<WasmChallengeExecutor>,
    state_manager: &Arc<StateManager>,
    keypair: &Keypair,
    p2p_cmd_tx: &tokio::sync::mpsc::Sender<platform_p2p_consensus::P2PCommand>,
) {
    let pending: Vec<(String, ChallengeId, String)> = state_manager.read(|state| {
        state
            .pending_evaluations
            .iter()
            .filter(|(_, record)| {
                !record.finalized && !record.evaluations.contains_key(&keypair.hotkey())
            })
            .map(|(id, record)| (id.clone(), record.challenge_id, record.agent_hash.clone()))
            .collect()
    });

    if pending.is_empty() {
        return;
    }

    for (submission_id, challenge_id, _agent_hash) in pending {
        let module_filename = format!("{}.wasm", challenge_id);

        if !executor.module_exists(&module_filename) {
            debug!(
                submission_id = %submission_id,
                challenge_id = %challenge_id,
                "No WASM module found for challenge, skipping WASM evaluation"
            );
            continue;
        }

        let network_policy = wasm_runtime_interface::NetworkPolicy::default();

        let input_data = submission_id.as_bytes().to_vec();
        let challenge_id_str = challenge_id.to_string();

        let executor = Arc::clone(executor);
        let module_filename_clone = module_filename.clone();

        let result = tokio::task::spawn_blocking(move || {
            executor.execute_evaluation(
                &module_filename_clone,
                &network_policy,
                &input_data,
                &challenge_id_str,
                &[],
            )
        })
        .await;

        let (score, eval_metrics) = match result {
            Ok(Ok((output, metrics))) => {
                info!(
                    submission_id = %submission_id,
                    challenge_id = %challenge_id,
                    score = output.score,
                    valid = output.valid,
                    message = %output.message,
                    execution_time_ms = metrics.execution_time_ms,
                    memory_bytes = metrics.memory_used_bytes,
                    network_requests = metrics.network_requests_made,
                    fuel_consumed = ?metrics.fuel_consumed,
                    "WASM evaluation succeeded"
                );
                let normalized = (output.score as f64) / i64::MAX as f64;
                let em = EvaluationMetrics {
                    primary_score: normalized,
                    secondary_metrics: vec![],
                    execution_time_ms: metrics.execution_time_ms as u64,
                    memory_usage_bytes: Some(metrics.memory_used_bytes),
                    timed_out: false,
                    error: None,
                };
                (normalized, em)
            }
            Ok(Err(e)) => {
                warn!(
                    submission_id = %submission_id,
                    challenge_id = %challenge_id,
                    error = %e,
                    "WASM evaluation failed, reporting score 0"
                );
                let em = EvaluationMetrics {
                    primary_score: 0.0,
                    secondary_metrics: vec![],
                    execution_time_ms: 0,
                    memory_usage_bytes: None,
                    timed_out: false,
                    error: Some(e.to_string()),
                };
                (0.0, em)
            }
            Err(e) => {
                error!(
                    submission_id = %submission_id,
                    challenge_id = %challenge_id,
                    error = %e,
                    "WASM evaluation task panicked, reporting score 0"
                );
                let em = EvaluationMetrics {
                    primary_score: 0.0,
                    secondary_metrics: vec![],
                    execution_time_ms: 0,
                    memory_usage_bytes: None,
                    timed_out: false,
                    error: Some(e.to_string()),
                };
                (0.0, em)
            }
        };

        let score_clamped = score.clamp(0.0, 1.0);
        let validator_hotkey = keypair.hotkey();
        let timestamp = chrono::Utc::now().timestamp_millis();

        #[derive(serde::Serialize)]
        struct EvaluationSigningData<'a> {
            submission_id: &'a str,
            score: f64,
        }
        let signing_data = EvaluationSigningData {
            submission_id: &submission_id,
            score: score_clamped,
        };
        let signing_bytes = match bincode::serialize(&signing_data) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!(
                    submission_id = %submission_id,
                    error = %e,
                    "Failed to serialize evaluation signing data"
                );
                continue;
            }
        };
        let signature = match keypair.sign_bytes(&signing_bytes) {
            Ok(sig) => sig,
            Err(e) => {
                error!(
                    submission_id = %submission_id,
                    error = %e,
                    "Failed to sign evaluation"
                );
                continue;
            }
        };

        let eval = platform_p2p_consensus::ValidatorEvaluation {
            score: score_clamped,
            stake: 0,
            timestamp,
            signature: signature.clone(),
        };

        state_manager.apply(|state| {
            if let Err(e) = state.add_validator_evaluation(
                &submission_id,
                validator_hotkey.clone(),
                eval,
                &signature,
            ) {
                warn!(
                    submission_id = %submission_id,
                    error = %e,
                    "Failed to add WASM evaluation to state"
                );
            } else {
                debug!(
                    submission_id = %submission_id,
                    score = score_clamped,
                    "WASM evaluation recorded in state"
                );
            }
        });

        let eval_msg = P2PMessage::Evaluation(EvaluationMessage {
            submission_id: submission_id.clone(),
            challenge_id,
            validator: validator_hotkey,
            score: score_clamped,
            metrics: eval_metrics,
            signature,
            timestamp,
        });
        if let Err(e) = p2p_cmd_tx
            .send(platform_p2p_consensus::P2PCommand::Broadcast(eval_msg))
            .await
        {
            warn!(
                submission_id = %submission_id,
                error = %e,
                "Failed to queue evaluation broadcast"
            );
        }
    }
}
