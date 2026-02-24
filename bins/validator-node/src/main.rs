//! Platform Validator Node
//!
//! Fully decentralized P2P validator for the Platform network.
//! Uses libp2p for gossipsub consensus and Kademlia DHT for storage.
//! Submits weights to Bittensor at epoch boundaries.
#![allow(
    clippy::too_many_arguments,
    clippy::await_holding_lock,
    clippy::needless_borrow
)]

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
    DistributedStore, DistributedStoreExt, LocalStorageBuilder, PutOptions, StorageKey,
    TrackedStorage, TrackedStorageConfig,
};

use platform_p2p_consensus::{
    ChainState, ConsensusEngine, EvaluationMessage, EvaluationMetrics, EvaluationRecord,
    HeartbeatMessage, JobRecord, JobStatus, NetworkEvent, P2PConfig, P2PMessage, P2PNetwork,
    StateManager, StorageProposal, StorageVoteMessage, TaskProgressRecord, ValidatorRecord,
    ValidatorSet,
};
use platform_rpc::{RpcConfig, RpcServer};
use platform_subnet_manager::BanList;
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use wasm_executor::{WasmChallengeExecutor, WasmExecutorConfig};

/// Storage key for persisted P2P chain state
const STATE_STORAGE_KEY: &str = "chain_state";
/// Storage key for persisted core ChainState (wasm_challenge_configs, routes, etc.)
const CORE_STATE_STORAGE_KEY: &str = "core_chain_state";

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

/// Helper to mutate ChainState and automatically persist changes.
/// This ensures we never forget to persist after mutations.
async fn mutate_and_persist<F, R>(
    storage: Arc<TrackedStorage>,
    chain_state: Arc<RwLock<platform_core::ChainState>>,
    operation: &str,
    f: F,
) -> R
where
    F: FnOnce(&mut platform_core::ChainState) -> R,
{
    let result = {
        let mut cs = chain_state.write();
        f(&mut cs)
    };

    // Always persist after mutation
    if let Err(e) = persist_core_state_to_storage(&storage, &chain_state).await {
        warn!("Failed to persist state after {}: {}", operation, e);
    } else {
        debug!("State persisted after {}", operation);
    }

    result
}

/// Create PutOptions with the current block number for tracking
fn put_options_with_block(state_manager: &StateManager) -> PutOptions {
    let block = state_manager.apply(|state| state.bittensor_block);
    PutOptions::with_block(block)
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

    /// Also run an embedded bootnode on a separate port (validator + bootnode mode)
    #[arg(long, env = "WITH_BOOTNODE")]
    with_bootnode: bool,

    /// Bootnode P2P port (only used with --with-bootnode)
    #[arg(long, env = "BOOTNODE_PORT", default_value = "8090")]
    bootnode_port: u16,

    /// P2P port (simpler alternative to --listen-addr)
    #[arg(long, env = "P2P_PORT")]
    p2p_port: Option<u16>,

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

    /// RPC server listen address (default: 0.0.0.0:8080)
    #[arg(long, env = "RPC_ADDR", default_value = "0.0.0.0:8080")]
    rpc_addr: String,

    /// Chutes API key for LLM inference (enables LLM review in WASM challenges)
    #[arg(long, env = "CHUTES_API_KEY")]
    chutes_api_key: Option<String>,

    /// Disable RPC server
    #[arg(long)]
    no_rpc: bool,
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
            .field("with_bootnode", &self.with_bootnode)
            .field("bootnode_port", &self.bootnode_port)
            .field("p2p_port", &self.p2p_port)
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
    let args = Args::parse();

    // Load keypair first to get hotkey for Sentry
    let keypair = load_keypair(&args)?;
    let validator_hotkey = keypair.ss58_address();

    // Initialize Sentry for error tracking (captures warn/error/panic)
    let _sentry_guard = sentry::init((
        "https://fb4324072ce6cfa8cb8a772ca37d1b19@o4510579978272768.ingest.us.sentry.io/4510934791094272",
        sentry::ClientOptions {
            release: sentry::release_name!(),
            send_default_pii: true,
            traces_sample_rate: 0.1,
            ..Default::default()
        },
    ));
    sentry::configure_scope(|scope| {
        scope.set_user(Some(sentry::User {
            id: Some(validator_hotkey.clone()),
            username: Some(validator_hotkey.clone()),
            ..Default::default()
        }));
        scope.set_tag("validator_hotkey", &validator_hotkey);
    });

    // Initialize tracing with Sentry layer to capture warn/error logs
    use tracing_subscriber::prelude::*;
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "info,validator_node=debug,platform_p2p_consensus=debug".into()
            }),
        ))
        .with(sentry_tracing::layer().event_filter(|meta| {
            // Send warn and error events to Sentry
            match meta.level() {
                &tracing::Level::ERROR | &tracing::Level::WARN => {
                    sentry_tracing::EventFilter::Event
                }
                _ => sentry_tracing::EventFilter::Ignore,
            }
        }))
        .init();

    info!("Starting decentralized validator");
    info!("SudoOwner: {}", SUDO_KEY_SS58);
    info!("Validator hotkey: {}", validator_hotkey);
    info!("Sentry initialized - errors and warnings will be reported");

    // Create data directory
    std::fs::create_dir_all(&args.data_dir)?;
    let data_dir = std::fs::canonicalize(&args.data_dir)?;

    // Initialize distributed storage with compression and tracking
    let local_storage = LocalStorageBuilder::new(&validator_hotkey)
        .path(
            data_dir
                .join("distributed.db")
                .to_string_lossy()
                .to_string(),
        )
        .build()?;

    // Wrap with TrackedStorage for automatic compression, indexing, and audit
    let tracked_config = TrackedStorageConfig {
        validator_id: validator_hotkey.clone(),
        ..Default::default()
    };
    let tracked_storage = TrackedStorage::new(Arc::new(local_storage), tracked_config);
    let storage = Arc::new(tracked_storage);
    info!("Distributed storage initialized with compression and tracking");

    // Determine listen address - p2p_port overrides listen_addr if specified
    let listen_addr = if let Some(port) = args.p2p_port {
        format!("/ip4/0.0.0.0/tcp/{}", port)
    } else if args.with_bootnode {
        // When running with embedded bootnode, default validator to port 8091
        // (bootnode will use 8090)
        "/ip4/0.0.0.0/tcp/8091".to_string()
    } else {
        args.listen_addr.clone()
    };

    // Build P2P config - use defaults and add any extra bootstrap peers from CLI
    let mut p2p_config = P2PConfig::default()
        .with_listen_addr(&listen_addr)
        .with_netuid(args.netuid)
        .with_min_stake(10_000_000_000_000); // 10000 TAO

    // If running with embedded bootnode, add bootnode port as additional listener
    if args.with_bootnode {
        let bootnode_addr = format!("/ip4/0.0.0.0/tcp/{}", args.bootnode_port);
        p2p_config = p2p_config.add_listen_addr(&bootnode_addr);
        info!(
            "Running validator + bootnode mode: validator on {}, bootnode on {}",
            listen_addr, bootnode_addr
        );
    }

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

    // Load persisted core ChainState or create fresh
    let core_state = load_core_state_from_storage(&storage)
        .await
        .unwrap_or_else(|| {
            info!("No persisted core state found, starting fresh");
            platform_core::ChainState::production_default()
        });
    let chain_state = Arc::new(RwLock::new(core_state));

    // Initialize state manager, loading persisted state if available
    let state_manager = Arc::new(
        load_state_from_storage(&storage, args.netuid)
            .await
            .unwrap_or_else(|| {
                info!("No persisted state found, starting fresh");
                StateManager::for_netuid(args.netuid)
            }),
    );

    // Shared set of valid voter hotkeys for distributed storage consensus
    let valid_voters: Arc<RwLock<std::collections::HashSet<Hotkey>>> =
        Arc::new(RwLock::new(std::collections::HashSet::new()));

    // Initialize state root consensus for cross-validator state verification
    let state_root_consensus = Arc::new(parking_lot::Mutex::new(
        platform_distributed_storage::state_consensus::StateRootConsensus::new(
            keypair.hotkey(),
            validator_set.quorum_size().max(1),
        ),
    ));

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
        tokio::sync::mpsc::channel::<platform_p2p_consensus::P2PCommand>(4096);

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
                            update_validator_set_from_metagraph(
                                &mg,
                                &validator_set,
                                &chain_state,
                                &valid_voters,
                                &state_root_consensus,
                                &state_manager,
                            );
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
                            update_validator_set_from_metagraph(
                                &mg,
                                &validator_set,
                                &chain_state,
                                &valid_voters,
                                &state_root_consensus,
                                &state_manager,
                            );
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

    // Channel for local storage proposals (proposer adds to own state)
    let (local_proposal_tx, mut local_proposal_rx) =
        tokio::sync::mpsc::channel::<StorageProposal>(4096);

    // Cast storage to trait object for WASM executor
    let storage_dyn: Arc<dyn DistributedStore> = Arc::clone(&storage) as Arc<dyn DistributedStore>;

    // Shared chain state data for WASM instances
    let shared_llm_validators_json: Arc<parking_lot::RwLock<Vec<u8>>> =
        Arc::new(parking_lot::RwLock::new(Vec::new()));
    let shared_registered_hotkeys_json: Arc<parking_lot::RwLock<Vec<u8>>> =
        Arc::new(parking_lot::RwLock::new(Vec::new()));

    let wasm_executor = match WasmChallengeExecutor::new(WasmExecutorConfig {
        module_dir: wasm_module_dir.clone(),
        max_memory_bytes: args.wasm_max_memory,
        enable_fuel: args.wasm_enable_fuel,
        fuel_limit: args.wasm_fuel_limit,
        storage_host_config: wasm_runtime_interface::StorageHostConfig::default(),
        storage_backend: std::sync::Arc::new(challenge_storage::ChallengeStorageBackend::with_p2p(
            storage_dyn.clone(),
            p2p_cmd_tx.clone(),
            local_proposal_tx,
            keypair.clone(),
        )),
        chutes_api_key: args.chutes_api_key.clone(),
        distributed_storage: Some(storage_dyn),
        llm_validators_json: Arc::clone(&shared_llm_validators_json),
        registered_hotkeys_json: Arc::clone(&shared_registered_hotkeys_json),
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

    // Create channel for RPC -> P2P communication
    let (rpc_p2p_tx, mut rpc_p2p_rx) =
        tokio::sync::mpsc::channel::<platform_rpc::RpcP2PCommand>(64);

    let bans = Arc::new(RwLock::new(BanList::new()));

    // Start RPC server (enabled by default)
    let mut rpc_handler_opt: Option<Arc<platform_rpc::RpcHandler>> = None;
    if !args.no_rpc {
        let rpc_addr: std::net::SocketAddr =
            args.rpc_addr.parse().expect("Invalid RPC address format");

        let rpc_config = RpcConfig {
            addr: rpc_addr,
            netuid: args.netuid,
            name: "Platform Validator".to_string(),
            min_stake: 10_000_000_000_000,
            cors_enabled: true,
        };

        let rpc_server = RpcServer::with_p2p(
            rpc_config,
            chain_state.clone(),
            bans.clone(),
            rpc_p2p_tx.clone(),
        )
        .with_storage(
            Arc::clone(&storage) as Arc<dyn platform_distributed_storage::DistributedStore>
        );

        // Configure WASM route handler if executor is available
        if let Some(ref executor) = wasm_executor {
            let wasm_exec = Arc::clone(executor);
            let chain_state_for_handler = chain_state.clone();
            let handler: platform_rpc::ChallengeRouteHandler = std::sync::Arc::new(
                move |challenge_id: String, request: platform_challenge_sdk::RouteRequest| {
                    let executor = Arc::clone(&wasm_exec);
                    let chain = chain_state_for_handler.clone();
                    Box::pin(async move {
                        // Find the WASM module path for this challenge (by UUID or name)
                        let module_path: Option<String> = {
                            let chain_guard = chain.read();

                            // Try parsing as UUID first
                            if let Ok(uuid) = uuid::Uuid::parse_str(&challenge_id) {
                                let cid = platform_core::ChallengeId(uuid);
                                chain_guard
                                    .wasm_challenge_configs
                                    .get(&cid)
                                    .map(|c| c.module.module_path.clone())
                            } else {
                                // Search by name in wasm_challenge_configs
                                chain_guard
                                    .wasm_challenge_configs
                                    .values()
                                    .find(|c| c.name == challenge_id)
                                    .map(|c| c.module.module_path.clone())
                            }
                        };

                        let module_path = match module_path {
                            Some(p) => p,
                            None => {
                                return platform_challenge_sdk::RouteResponse {
                                    status: 404,
                                    headers: std::collections::HashMap::new(),
                                    body: serde_json::json!({
                                        "error": "challenge_not_found",
                                        "message": format!("WASM module not found for challenge {}", challenge_id)
                                    }),
                                };
                            }
                        };

                        // Execute handle_route in WASM (sync call in spawn_blocking)
                        let exec = executor;
                        let path = module_path;
                        let req = request;
                        match tokio::task::spawn_blocking(move || exec.call_route(&path, req)).await
                        {
                            Ok(Ok(response)) => response,
                            Ok(Err(e)) => platform_challenge_sdk::RouteResponse {
                                status: 500,
                                headers: std::collections::HashMap::new(),
                                body: serde_json::json!({
                                    "error": "wasm_execution_error",
                                    "message": format!("{}", e)
                                }),
                            },
                            Err(e) => platform_challenge_sdk::RouteResponse {
                                status: 500,
                                headers: std::collections::HashMap::new(),
                                body: serde_json::json!({
                                    "error": "task_join_error",
                                    "message": format!("{}", e)
                                }),
                            },
                        }
                    })
                },
            );
            rpc_server.rpc_handler().set_route_handler(handler);
        }

        rpc_handler_opt = Some(rpc_server.rpc_handler());

        tokio::spawn(async move {
            if let Err(e) = rpc_server.run().await {
                error!("RPC server error: {}", e);
            }
        });

        info!("RPC server started on {}", args.rpc_addr);
    }

    // Reload WASM modules from persisted challenges on startup
    if let Some(ref executor) = wasm_executor {
        let challenges: Vec<(platform_core::ChallengeId, String)> = {
            let cs = chain_state.read();
            cs.wasm_challenge_configs
                .iter()
                .map(|(id, config)| (*id, config.module.module_path.clone()))
                .collect()
        };

        if !challenges.is_empty() {
            info!(
                "Reloading {} WASM modules from persisted state",
                challenges.len()
            );
            let mut handles = Vec::new();
            for (challenge_id, module_path) in &challenges {
                let challenge_id_str = challenge_id.to_string();
                let wasm_key =
                    platform_distributed_storage::StorageKey::new("wasm", &challenge_id_str);
                match storage
                    .get(
                        &wasm_key,
                        platform_distributed_storage::GetOptions::default(),
                    )
                    .await
                {
                    Ok(Some(stored)) => {
                        let exec = executor.clone();
                        let cid = *challenge_id;
                        let mp = if module_path.is_empty() {
                            challenge_id_str.clone()
                        } else {
                            module_path.clone()
                        };
                        let cs = chain_state.clone();
                        let wasm_bytes = stored.data;
                        let handle = std::thread::spawn(move || {
                            match exec.execute_get_routes_from_bytes(
                                &mp,
                                &wasm_bytes,
                                &wasm_runtime_interface::NetworkPolicy::development(),
                                &wasm_runtime_interface::SandboxPolicy::default(),
                            ) {
                                Ok((routes_data, _)) => {
                                    if let Ok(routes) =
                                        bincode::deserialize::<
                                            Vec<platform_challenge_sdk_wasm::WasmRouteDefinition>,
                                        >(&routes_data)
                                    {
                                        tracing::info!(
                                            challenge_id = %cid,
                                            routes_count = routes.len(),
                                            "Reloaded WASM routes on startup"
                                        );
                                        let route_infos: Vec<platform_core::ChallengeRouteInfo> =
                                            routes
                                                .iter()
                                                .map(|r| platform_core::ChallengeRouteInfo {
                                                    method: r.method.clone(),
                                                    path: r.path.clone(),
                                                    description: r.description.clone(),
                                                    requires_auth: r.requires_auth,
                                                })
                                                .collect();
                                        let mut state = cs.write();
                                        state.register_challenge_routes(cid, route_infos);
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        challenge_id = %cid,
                                        error = %e,
                                        "Failed to reload WASM module on startup"
                                    );
                                }
                            }
                        });
                        handles.push((challenge_id_str, handle));
                    }
                    Ok(None) => {
                        warn!(
                            challenge_id = %challenge_id,
                            "WASM bytes not found in storage for persisted challenge"
                        );
                    }
                    Err(e) => {
                        warn!(
                            challenge_id = %challenge_id,
                            error = %e,
                            "Failed to load WASM bytes from storage"
                        );
                    }
                }
            }
            // Wait for all WASM compilation threads to finish
            for (cid, handle) in handles {
                if let Err(e) = handle.join() {
                    warn!(challenge_id = %cid, "WASM compilation thread panicked: {:?}", e);
                }
            }
            info!("All WASM modules reloaded");

            // Run sync() on each challenge at startup
            for (challenge_id, module_path) in &challenges {
                let mp = if module_path.is_empty() {
                    challenge_id.to_string()
                } else {
                    module_path.clone()
                };
                match executor.execute_sync_with_block(&mp, 120, 0) {
                    Ok(result) => {
                        info!(
                            challenge_id = %challenge_id,
                            total_users = result.total_users,
                            "Startup sync completed"
                        );
                    }
                    Err(e) => {
                        warn!(challenge_id = %challenge_id, error = %e, "Startup sync failed");
                    }
                }
            }
        }
    }

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
    let mut weight_check_interval = tokio::time::interval(Duration::from_secs(30));
    let mut last_weight_submission_epoch: u64 = 0;
    let startup_rpc_precompute_delay = tokio::time::sleep(Duration::from_secs(70));
    tokio::pin!(startup_rpc_precompute_delay);
    let mut startup_rpc_precomputed = false;
    let startup_weight_delay = tokio::time::sleep(Duration::from_secs(90));
    tokio::pin!(startup_weight_delay);
    let mut startup_weights_submitted = false;
    let mut challenge_sync_interval = tokio::time::interval(Duration::from_secs(30)); // Check every 30s
    let mut last_sync_block: u64 = 0;
    let sync_block_interval: u64 = 1; // Call WASM sync every block, WASM decides frequency internally
    let mut storage_stats_interval = tokio::time::interval(Duration::from_secs(300));
    // Track last synced block per challenge for delta sync
    let challenge_last_sync: Arc<
        RwLock<std::collections::HashMap<platform_core::ChallengeId, u64>>,
    > = Arc::new(RwLock::new(std::collections::HashMap::new()));

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
                    &storage,
                    &keypair,
                    &p2p_cmd_tx,
                    &chain_state,
                    &challenge_last_sync,
                    &shared_llm_validators_json,
                    &shared_registered_hotkeys_json,
                    &rpc_handler_opt,
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
                    &chain_state,
                    &storage,
                    &mut last_weight_submission_epoch,
                ).await;
            }

            // RPC -> P2P commands (challenge updates from sudo)
            Some(cmd) = rpc_p2p_rx.recv() => {
                match cmd {
                    platform_rpc::RpcP2PCommand::BroadcastSudoAction { action } => {
                        info!("Received sudo action from RPC: {:?}", action);

                        // Apply to local chain state and persist
                        mutate_and_persist(
                            storage.clone(),
                            chain_state.clone(),
                            "sudo_action_rpc",
                            |cs| {
                                if let Err(e) = cs.apply_sudo_action(&action) {
                                    error!("Failed to apply sudo action: {}", e);
                                }
                            },
                        )
                        .await;

                        // Broadcast as a ChallengeUpdate with type "sudo_action"
                        // so peer validators can receive and apply it
                        let action_bytes = match bincode::serialize(&action) {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                error!("Failed to serialize sudo action: {}", e);
                                continue;
                            }
                        };

                        let timestamp = chrono::Utc::now().timestamp_millis();
                        let msg_to_sign = format!("challenge_update:sudo:sudo_action:{}", timestamp);
                        let signature = keypair.sign(msg_to_sign.as_bytes());

                        let update_msg = platform_p2p_consensus::ChallengeUpdateMessage {
                            challenge_id: platform_core::ChallengeId::from_string("sudo"),
                            updater: keypair.hotkey(),
                            update_type: "sudo_action".to_string(),
                            data: action_bytes,
                            name: None,
                            timestamp,
                            signature: signature.signature.to_vec(),
                        };

                        let msg = P2PMessage::ChallengeUpdate(update_msg);
                        if let Err(e) = p2p_broadcast_tx.send(platform_p2p_consensus::P2PCommand::Broadcast(msg)).await {
                            error!("Failed to broadcast sudo action: {}", e);
                        } else {
                            info!("Sudo action broadcast to P2P network");
                        }
                    }
                    platform_rpc::RpcP2PCommand::BroadcastChallengeUpdate { challenge_id, update_type, data, name } => {
                        info!(
                            challenge_id = %challenge_id,
                            update_type = %update_type,
                            data_bytes = data.len(),
                            name = ?name,
                            "Broadcasting ChallengeUpdate from RPC"
                        );

                        // Create and sign the message
                        let timestamp = chrono::Utc::now().timestamp_millis();
                        let msg_to_sign = format!("challenge_update:{}:{}:{}", challenge_id, update_type, timestamp);
                        let signature = keypair.sign(msg_to_sign.as_bytes());

                        let update_msg = platform_p2p_consensus::ChallengeUpdateMessage {
                            challenge_id,
                            updater: keypair.hotkey(),
                            update_type: update_type.clone(),
                            data: data.clone(),
                            name: name.clone(),
                            timestamp,
                            signature: signature.signature.to_vec(),
                        };

                        let msg = P2PMessage::ChallengeUpdate(update_msg);
                        if let Err(e) = p2p_broadcast_tx.send(platform_p2p_consensus::P2PCommand::Broadcast(msg)).await {
                            error!("Failed to broadcast ChallengeUpdate: {}", e);
                        } else {
                            info!(
                                challenge_id = %challenge_id,
                                update_type = %update_type,
                                "ChallengeUpdate broadcast successful"
                            );

                            // Broadcast StateMutationProposal for consensus validation
                            if update_type == "wasm_upload" || update_type == "rename" || update_type == "sudo_action" {
                                let mutation_type = match update_type.as_str() {
                                    "wasm_upload" => platform_p2p_consensus::StateMutationType::WasmUpload { challenge_id },
                                    "rename" => platform_p2p_consensus::StateMutationType::ChallengeRename { challenge_id },
                                    "sudo_action" => platform_p2p_consensus::StateMutationType::SudoAction,
                                    _ => unreachable!(),
                                };

                                let mutation_seq = chain_state.read().mutation_sequence;
                                let proposal_id = platform_core::hash_data(&(&data, mutation_seq))
                                    .unwrap_or([0u8; 32]);

                                let ts = chrono::Utc::now().timestamp_millis();
                                let sign_data = bincode::serialize(&(&proposal_id, ts)).unwrap_or_default();
                                let sig = keypair.sign_bytes(&sign_data).unwrap_or_default();

                                let mutation_msg = P2PMessage::StateMutationProposal(
                                    platform_p2p_consensus::StateMutationProposalMessage {
                                        proposal_id,
                                        mutation_type,
                                        data: data.clone(),
                                        proposer: keypair.hotkey(),
                                        timestamp: ts,
                                        signature: sig,
                                        mutation_sequence: mutation_seq,
                                    },
                                );

                                if let Err(e) = p2p_broadcast_tx
                                    .send(platform_p2p_consensus::P2PCommand::Broadcast(mutation_msg))
                                    .await
                                {
                                    warn!(error = %e, "Failed to broadcast StateMutationProposal");
                                }
                            }

                            // Also handle locally (store WASM if it's an upload)
                            if update_type == "wasm_upload" && !data.is_empty() {
                                // Validate WASM before storing
                                let is_valid = if let Some(ref executor) = wasm_executor {
                                    match executor.validate_wasm_module(&data) {
                                        Ok(()) => true,
                                        Err(e) => {
                                            error!(
                                                challenge_id = %challenge_id,
                                                error = %e,
                                                "Invalid WASM module, rejecting upload"
                                            );
                                            false
                                        }
                                    }
                                } else {
                                    true
                                };

                                if is_valid {
                                let challenge_id_str = challenge_id.to_string();
                                let wasm_key = StorageKey::new("wasm", &challenge_id_str);
                                let wasm_data = data.clone(); // Clone for route loading later
                                match storage.put(wasm_key, data, put_options_with_block(&state_manager)).await {
                                    Ok(metadata) => {
                                        info!(
                                            challenge_id = %challenge_id,
                                            version = metadata.version,
                                            "WASM stored locally in distributed storage"
                                        );

                                        // Sync to ChainState for RPC and persist
                                        let challenge_name = name.as_deref().unwrap_or(&challenge_id_str).to_string();
                                        let owner = keypair.hotkey();
                                        let code_hash = hex::encode(metadata.value_hash);
                                        let version = metadata.version.to_string();
                                        let module_path = challenge_id_str.clone();
                                        mutate_and_persist(
                                            storage.clone(),
                                            chain_state.clone(),
                                            "wasm_upload_local",
                                            |cs| {
                                                let wasm_config = platform_core::WasmChallengeConfig {
                                                    challenge_id,
                                                    name: challenge_name,
                                                    description: String::new(),
                                                    owner,
                                                    module: platform_core::WasmModuleMetadata {
                                                        module_path,
                                                        code_hash,
                                                        version,
                                                        ..Default::default()
                                                    },
                                                    config: platform_core::ChallengeConfig::default(),
                                                    is_active: true,
                                                };
                                                cs.register_wasm_challenge(wasm_config);
                                            },
                                        )
                                        .await;

                                        // Load routes in a blocking thread to avoid tokio runtime issues
                                        if let Some(ref executor) = wasm_executor {
                                            let wasm_bytes = wasm_data.clone();
                                            let executor = executor.clone();
                                            let challenge_id_for_routes = challenge_id;
                                            let challenge_id_str_for_routes = challenge_id_str.clone();
                                            let chain_state_for_routes = chain_state.clone();

                                            std::thread::spawn(move || {
                                                match executor.execute_get_routes_from_bytes(
                                                    &challenge_id_str_for_routes,
                                                    &wasm_bytes,
                                                    &wasm_runtime_interface::NetworkPolicy::development(),
                                                    &wasm_runtime_interface::SandboxPolicy::default(),
                                                ) {
                                                    Ok((routes_data, _)) => {
                                                        if let Ok(routes) = bincode::deserialize::<Vec<platform_challenge_sdk_wasm::WasmRouteDefinition>>(&routes_data) {
                                                            tracing::info!(
                                                                challenge_id = %challenge_id_for_routes,
                                                                routes_count = routes.len(),
                                                                "Loaded WASM challenge routes (local upload)"
                                                            );
                                                            let route_infos: Vec<platform_core::ChallengeRouteInfo> = routes.iter().map(|r| {
                                                                platform_core::ChallengeRouteInfo {
                                                                    method: r.method.clone(),
                                                                    path: r.path.clone(),
                                                                    description: r.description.clone(),
                                                                    requires_auth: r.requires_auth,
                                                                }
                                                            }).collect();
                                                            let mut cs = chain_state_for_routes.write();
                                                            cs.register_challenge_routes(challenge_id_for_routes, route_infos);
                                                        }
                                                    }
                                                    Err(e) => {
                                                        tracing::debug!(
                                                            challenge_id = %challenge_id_for_routes,
                                                            error = %e,
                                                            "No routes exported by WASM module"
                                                        );
                                                    }
                                                }
                                            });
                                        }
                                        /*
                                        // Old code - kept for reference
                                        if let Some(ref executor) = wasm_executor {
                                            let wasm_bytes_result = storage.get(
                                                &StorageKey::new("wasm", &challenge_id_str),
                                                platform_distributed_storage::GetOptions::default()
                                            ).await;

                                            if let Ok(Some(stored)) = wasm_bytes_result {
                                            match executor.execute_get_routes_from_bytes(
                                                &challenge_id_str,
                                                &stored.data,
                                                &wasm_runtime_interface::NetworkPolicy::development(),
                                                &wasm_runtime_interface::SandboxPolicy::default(),
                                            ) {
                                                Ok((routes_data, _)) => {
                                                    if let Ok(routes) = bincode::deserialize::<Vec<platform_challenge_sdk_wasm::WasmRouteDefinition>>(&routes_data) {
                                                        info!(
                                                            challenge_id = %challenge_id,
                                                            routes_count = routes.len(),
                                                            "Loaded WASM challenge routes (local upload)"
                                                        );
                                                        let route_infos: Vec<platform_core::ChallengeRouteInfo> = routes.iter().map(|r| {
                                                            platform_core::ChallengeRouteInfo {
                                                                method: r.method.clone(),
                                                                path: r.path.clone(),
                                                                description: r.description.clone(),
                                                                requires_auth: r.requires_auth,
                                                            }
                                                        }).collect();
                                                        let mut cs = chain_state.write();
                                                        cs.register_challenge_routes(challenge_id, route_infos);
                                                    }
                                                }
                                                Err(e) => {
                                                    debug!(
                                                        challenge_id = %challenge_id,
                                                        error = %e,
                                                        "No routes exported by WASM module"
                                                    );
                                                }
                                            }
                                            } // end if wasm_bytes_result
                                        }
                                        */
                                    }
                                    Err(e) => {
                                        error!(
                                            challenge_id = %challenge_id,
                                            error = %e,
                                            "Failed to store WASM locally"
                                        );
                                    }
                                }
                                } // end if is_valid
                            } else if update_type == "rename" && !data.is_empty() {
                                // Handle rename action
                                if let Ok(new_name) = String::from_utf8(data) {
                                    let name_clone = new_name.clone();
                                    let renamed = mutate_and_persist(storage.clone(), chain_state.clone(), "rename_local", |cs| {
                                        cs.rename_challenge(&challenge_id, name_clone)
                                    }).await;
                                    if renamed {
                                        info!(
                                            challenge_id = %challenge_id,
                                            new_name = %new_name,
                                            "Challenge renamed locally"
                                        );
                                    } else {
                                        warn!(
                                            challenge_id = %challenge_id,
                                            new_name = %new_name,
                                            "Failed to rename challenge - not found or name conflict"
                                        );
                                    }
                                }
                            } else if update_type == "activate" {
                                // Handle activate action locally
                                mutate_and_persist(storage.clone(), chain_state.clone(), "activate_local", |cs| {
                                    cs.set_challenge_active(&challenge_id, true);
                                }).await;
                                state_manager.apply(|state| {
                                    state.set_challenge_active(&challenge_id, true);
                                });
                                info!(challenge_id = %challenge_id, "Challenge activated locally");
                            } else if update_type == "deactivate" {
                                // Handle deactivate action locally
                                mutate_and_persist(storage.clone(), chain_state.clone(), "deactivate_local", |cs| {
                                    cs.set_challenge_active(&challenge_id, false);
                                }).await;
                                state_manager.apply(|state| {
                                    state.set_challenge_active(&challenge_id, false);
                                });
                                info!(challenge_id = %challenge_id, "Challenge deactivated locally");
                            } else if update_type == "remove" {
                                // Remove challenge from both states and delete WASM
                                mutate_and_persist(storage.clone(), chain_state.clone(), "remove_local", |cs| {
                                    cs.remove_wasm_challenge(&challenge_id);
                                }).await;
                                state_manager.apply(|state| {
                                    state.remove_challenge(&challenge_id);
                                });
                                let challenge_id_str = challenge_id.to_string();
                                let wasm_key = StorageKey::new("wasm", &challenge_id_str);
                                let _ = storage.delete(&wasm_key).await;
                                info!(challenge_id = %challenge_id, "Challenge removed locally");
                            }
                        }
                    }
                }
            }

            // Heartbeat - broadcast to other validators (skip in bootnode mode)
            _ = heartbeat_interval.tick() => {
                if !is_bootnode {
                    let state_hash = state_manager.state_hash();
                    let sequence = state_manager.sequence();
                    let our_hotkey = keypair.hotkey();

                    // Get our stake from validator set
                    let our_stake = validator_set.stake_for(&our_hotkey);

                    let core_state_hash = chain_state.read().state_hash;

                    let heartbeat = P2PMessage::Heartbeat(HeartbeatMessage {
                        validator: our_hotkey,
                        state_hash,
                        core_state_hash,
                        sequence,
                        stake: our_stake,
                        timestamp: chrono::Utc::now().timestamp_millis(),
                        signature: vec![], // Will be signed by P2P layer
                        capabilities: platform_p2p_consensus::ValidatorCapabilities {
                            has_llm: args.chutes_api_key.is_some(),
                        },
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
                    warn!("Failed to persist P2P state: {}", e);
                } else {
                    debug!("State persisted to storage");
                }
                if let Err(e) = persist_core_state_to_storage(&storage, &chain_state).await {
                    warn!("Failed to persist core state: {}", e);
                }
            }

            // Local storage proposals (from our own WASM executions) - batch drain
            Some(first_proposal) = local_proposal_rx.recv() => {
                let mut batch = vec![first_proposal];
                while let Ok(p) = local_proposal_rx.try_recv() {
                    batch.push(p);
                }
                let batch_size = batch.len();
                if batch_size > 1 {
                    debug!("Processing batch of {} local proposals", batch_size);
                }

                // Vote for all proposals and collect those that reached consensus
                let my_hotkey = keypair.hotkey();
                let mut to_write = Vec::new();
                for proposal in batch {
                    let proposal_id = proposal.proposal_id;
                    state_manager.apply(|state| {
                        state.add_storage_proposal(proposal);
                    });
                    let consensus_result = state_manager.apply(|state| {
                        state.vote_storage_proposal(&proposal_id, my_hotkey.clone(), true)
                    });
                    if let Some(true) = consensus_result {
                        if let Some(p) = state_manager.apply(|state| {
                            state.remove_storage_proposal(&proposal_id)
                        }) {
                            to_write.push(p);
                        }
                    }
                }

                // Write all consensus-reached proposals
                for p in to_write {
                    let storage_key = StorageKey::new(
                        &p.challenge_id.to_string(),
                        hex::encode(&p.key),
                    );
                    let result = if p.value.is_empty() {
                        storage.delete(&storage_key).await
                    } else {
                        storage.put(storage_key.clone(), p.value.clone(), put_options_with_block(&state_manager)).await.map(|_| true)
                    };
                    match result {
                        Ok(_) => {
                            let op = if p.value.is_empty() { "deleted" } else { "written" };
                            info!(
                                proposal_id = %hex::encode(&p.proposal_id[..8]),
                                challenge_id = %p.challenge_id,
                                key_len = p.key.len(),
                                "Local proposal consensus reached, data {}", op
                            );
                        }
                        Err(e) => {
                            error!(
                                proposal_id = %hex::encode(&p.proposal_id[..8]),
                                error = %e,
                                "Failed to write local consensus storage"
                            );
                        }
                    }
                }
            }

            // Metagraph refresh
            _ = metagraph_interval.tick() => {
                if let Some(client) = bittensor_client_for_metagraph.as_ref() {
                    debug!("Refreshing metagraph from Bittensor...");
                    match sync_metagraph(client, netuid).await {
                        Ok(mg) => {
                            info!("Metagraph refreshed: {} neurons", mg.n);
                            update_validator_set_from_metagraph(&mg, &validator_set, &chain_state, &valid_voters, &state_root_consensus, &state_manager);
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
                // Clean up old state mutation proposals (5 min timeout)
                state_manager.apply(|state| state.cleanup_old_state_mutations(300_000));
                // Clean up old storage proposals (5 min timeout)
                state_manager.apply(|state| state.cleanup_old_proposals(300_000));
            }

            // Weight submission is handled entirely by CommitWindowOpen in handle_block_event.
            // The old weight_check_interval was redundant and overwrote WASM-computed weights
            // with burn weights because it couldn't see them in finalize_weights() after
            // the CommitWindowOpen handler already consumed them.
            _ = weight_check_interval.tick() => {
                // No-op: weights are submitted in CommitWindowOpen via CRv4
            }

            // Pre-compute weights for RPC 70s after boot so other validators
            // without P2P can fetch via subnet_getWeights before on-chain submission.
            _ = &mut startup_rpc_precompute_delay, if !startup_rpc_precomputed => {
                startup_rpc_precomputed = true;
                let current_block = state_manager.apply(|state| state.bittensor_block);
                if current_block == 0 {
                    warn!("RPC pre-compute skipped: blockchain not yet synced");
                } else if let Some(ref executor) = wasm_executor {
                    let challenges: Vec<(String, u8, f64)> = {
                        let cs = chain_state.read();
                        cs.wasm_challenge_configs.iter()
                            .filter(|(_, cfg)| cfg.is_active)
                            .map(|(id, cfg)| (id.to_string(), cfg.config.mechanism_id, cfg.config.emission_weight))
                            .collect()
                    };
                    if challenges.is_empty() {
                        warn!("RPC pre-compute skipped: no active challenges loaded");
                    } else {
                        let tempo = 360u64;
                        let netuid_plus_one = (netuid as u64).saturating_add(1);
                        let epoch = current_block.saturating_add(netuid_plus_one) / (tempo + 1);
                        let mut precomputed: Vec<(u8, Vec<u16>, Vec<u16>)> = Vec::new();
                        for (cid, mid, ew) in &challenges {
                            let ew = ew.clamp(0.0, 1.0);
                            if ew < 0.001 { continue; }
                            if let Ok(assignments) = executor.execute_get_weights_with_block(cid, current_block, epoch) {
                                if assignments.is_empty() { continue; }
                                let total: f64 = assignments.iter().map(|a| a.weight).sum();
                                if total <= 0.0 { continue; }
                                // Merge duplicate UIDs
                                let mut uid_map: std::collections::BTreeMap<u16, f64> = std::collections::BTreeMap::new();
                                let mut assigned = 0.0f64;
                                for a in &assignments {
                                    if let Some(uid) = subtensor_client.as_ref().and_then(|c| c.get_uid_for_hotkey(&a.hotkey)) {
                                        let scaled = (a.weight / total) * ew;
                                        *uid_map.entry(uid).or_insert(0.0) += scaled;
                                        assigned += scaled;
                                    }
                                }
                                let mut uids = Vec::new();
                                let mut vals = Vec::new();
                                for (uid, w) in &uid_map {
                                    let v = (w * 65535.0).round() as u16;
                                    if v > 0 { uids.push(*uid); vals.push(v); }
                                }
                                let burn = 1.0 - assigned;
                                if burn > 0.001 {
                                    let bv = (burn * 65535.0).round() as u16;
                                    if let Some(pos) = uids.iter().position(|&u| u == 0) {
                                        vals[pos] = vals[pos].saturating_add(bv);
                                    } else { uids.push(0); vals.push(bv); }
                                }
                                if !uids.is_empty() {
                                    let mx = *vals.iter().max().unwrap() as f64;
                                    if mx > 0.0 && mx < 65535.0 {
                                        vals = vals.iter().map(|v| ((*v as f64 / mx) * 65535.0).round() as u16).collect();
                                    }
                                    precomputed.push((*mid, uids, vals));
                                }
                            }
                        }
                        if !precomputed.is_empty() {
                            info!("RPC pre-compute: {} mechanism entries available via subnet_getWeights (70s after boot)", precomputed.len());
                            let mut cs = chain_state.write();
                            cs.last_computed_weights = precomputed;
                        } else {
                            warn!("RPC pre-compute: no weights computed (WASM returned empty)");
                        }
                    }
                }
            }

            // Submit weights on-chain 90s after boot (after RPC pre-compute at 70s).
            _ = &mut startup_weight_delay, if !startup_weights_submitted => {
                startup_weights_submitted = true;
                let current_block = state_manager.apply(|state| state.bittensor_block);
                if current_block == 0 {
                    warn!("Startup weight submission skipped: blockchain not yet synced");
                } else if subtensor.is_none() || subtensor_signer.is_none() {
                    warn!("Startup weight submission skipped: subtensor not connected");
                } else if wasm_executor.is_none() {
                    warn!("Startup weight submission skipped: WASM executor not ready");
                } else {
                    let has_challenges = {
                        let cs = chain_state.read();
                        cs.wasm_challenge_configs.iter().any(|(_, cfg)| cfg.is_active)
                    };
                    if !has_challenges {
                        warn!("Startup weight submission skipped: no active challenges loaded");
                    } else {
                        let tempo = 360u64;
                        let netuid_plus_one = (netuid as u64).saturating_add(1);
                        let epoch = current_block.saturating_add(netuid_plus_one) / (tempo + 1);
                        info!("Startup weight submission: epoch {} block {} (90s after boot)", epoch, current_block);
                        handle_block_event(
                            BlockSyncEvent::CommitWindowOpen { epoch, block: current_block },
                            &subtensor, &subtensor_signer, &subtensor_client,
                            &state_manager, netuid, version_key, &wasm_executor,
                            &keypair, &chain_state, &storage,
                            &mut last_weight_submission_epoch,
                        ).await;
                    }
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

            // Challenge sync ticker - every 60 blocks, sync all challenges
            _ = challenge_sync_interval.tick() => {
                if !is_bootnode {
                    let current_block = state_manager.apply(|state| state.bittensor_block);

                    // Check if we should sync (every 60 blocks)
                    if current_block / sync_block_interval > last_sync_block / sync_block_interval {
                        last_sync_block = current_block;

                        // Get all active challenges
                        let challenges: Vec<_> = {
                            let cs = chain_state.read();
                            cs.wasm_challenge_configs
                                .iter()
                                .filter(|(_, cfg)| cfg.is_active)
                                .map(|(id, _)| *id)
                                .collect()
                        };

                        let current_epoch = current_block / 360;
                        for challenge_id in challenges {
                            let challenge_id_str = challenge_id.to_string();
                            let module_path = format!("{}.wasm", challenge_id_str);

                            if let Some(ref executor) = wasm_executor {
                                match executor.execute_sync_with_block(&module_path, current_block, current_epoch) {
                                    Ok(sync_result) => {
                                        info!(
                                            challenge_id = %challenge_id,
                                            block = current_block,
                                            total_users = sync_result.total_users,
                                            "Challenge sync completed, broadcasting proposal"
                                        );

                                        // Broadcast sync proposal
                                        let timestamp = chrono::Utc::now().timestamp_millis();
                                        let proposal_data = bincode::serialize(&(
                                            &challenge_id,
                                            &sync_result.leaderboard_hash,
                                            current_block,
                                            timestamp
                                        )).unwrap_or_default();
                                        let signature = keypair.sign_bytes(&proposal_data).unwrap_or_default();

                                        let proposal_msg = P2PMessage::ChallengeSyncProposal(
                                            platform_p2p_consensus::ChallengeSyncProposalMessage {
                                                challenge_id,
                                                sync_result_hash: sync_result.leaderboard_hash,
                                                proposer: keypair.hotkey(),
                                                block_number: current_block,
                                                timestamp,
                                                signature,
                                            }
                                        );

                                        if let Err(e) = p2p_broadcast_tx.send(platform_p2p_consensus::P2PCommand::Broadcast(proposal_msg)).await {
                                            warn!(error = %e, "Failed to broadcast sync proposal");
                                        }
                                    }
                                    Err(e) => {
                                        debug!(
                                            challenge_id = %challenge_id,
                                            error = %e,
                                            "Failed to execute sync (WASM may not support sync)"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Periodic storage stats logging
            _ = storage_stats_interval.tick() => {
                let stats = storage.tracked_stats().await;
                if stats.total_writes > 0 {
                    let savings = if stats.bytes_written_uncompressed > 0 {
                        100.0 * (1.0 - stats.compression_ratio)
                    } else {
                        0.0
                    };
                    info!(
                        total_writes = stats.total_writes,
                        total_reads = stats.total_reads,
                        uncompressed_bytes = stats.bytes_written_uncompressed,
                        compressed_bytes = stats.bytes_written_compressed,
                        compression_ratio = format!("{:.2}", stats.compression_ratio),
                        savings_pct = format!("{:.1}%", savings),
                        current_block = storage.current_block(),
                        "Storage statistics"
                    );
                }
            }

            // Ctrl+C
            _ = tokio::signal::ctrl_c() => {
                info!("Received shutdown signal, persisting state...");

                // Persist core state (wasm_challenge_configs, routes, validators)
                if let Err(e) = persist_core_state_to_storage(&storage, &chain_state).await {
                    error!("Failed to persist core state on shutdown: {}", e);
                } else {
                    info!("Core state persisted on shutdown");
                }

                // Persist P2P consensus state
                if let Err(e) = persist_state_to_storage(&storage, &state_manager).await {
                    error!("Failed to persist P2P state on shutdown: {}", e);
                } else {
                    info!("P2P state persisted on shutdown");
                }

                // Create checkpoint
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
async fn load_state_from_storage(
    storage: &Arc<TrackedStorage>,
    netuid: u16,
) -> Option<StateManager> {
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
    storage: &Arc<TrackedStorage>,
    state_manager: &Arc<StateManager>,
) -> Result<()> {
    let state = state_manager.snapshot();
    let key = StorageKey::new("state", STATE_STORAGE_KEY);
    storage.put_json(key, &state).await?;
    Ok(())
}

/// Load persisted core ChainState (wasm_challenge_configs, routes, etc.)
async fn load_core_state_from_storage(
    storage: &Arc<TrackedStorage>,
) -> Option<platform_core::ChainState> {
    let key = StorageKey::new("state", CORE_STATE_STORAGE_KEY);
    match storage.get_json::<platform_core::ChainState>(&key).await {
        Ok(Some(state)) => {
            info!(
                "Loaded persisted core state: wasm_challenges={}, challenge_routes={}, validators={}",
                state.wasm_challenge_configs.len(),
                state.challenge_routes.len(),
                state.validators.len(),
            );
            Some(state)
        }
        Ok(None) => {
            debug!("No persisted core state found in storage");
            None
        }
        Err(e) => {
            warn!("Failed to load persisted core state: {}", e);
            None
        }
    }
}

/// Persist core ChainState to distributed storage
async fn persist_core_state_to_storage(
    storage: &Arc<TrackedStorage>,
    chain_state: &Arc<RwLock<platform_core::ChainState>>,
) -> Result<()> {
    let state = chain_state.read().clone();
    let key = StorageKey::new("state", CORE_STATE_STORAGE_KEY);
    storage.put_json(key, &state).await?;
    Ok(())
}

/// Update validator set from metagraph data and sync to ChainState
fn update_validator_set_from_metagraph(
    metagraph: &Metagraph,
    validator_set: &Arc<ValidatorSet>,
    chain_state: &Arc<RwLock<platform_core::ChainState>>,
    valid_voters: &Arc<RwLock<std::collections::HashSet<Hotkey>>>,
    state_root_consensus: &Arc<
        parking_lot::Mutex<platform_distributed_storage::state_consensus::StateRootConsensus>,
    >,
    state_manager: &Arc<StateManager>,
) {
    let mut cs = chain_state.write();
    cs.registered_hotkeys.clear();

    // Collect validators for P2P state manager
    let mut p2p_validators: Vec<(Hotkey, u64)> = Vec::new();

    for neuron in metagraph.neurons.values() {
        let hotkey_bytes: [u8; 32] = neuron.hotkey.clone().into();
        let hotkey = Hotkey(hotkey_bytes);
        // Get effective stake capped to u64::MAX (neuron.stake is u128)
        let stake = neuron.stake.min(u64::MAX as u128) as u64;

        // Register in validator set
        let record = ValidatorRecord::new(hotkey.clone(), stake);
        if let Err(e) = validator_set.register_validator(record) {
            debug!("Skipping validator registration: {}", e);
        }

        // Sync to ChainState
        cs.registered_hotkeys.insert(hotkey.clone());

        // H5 fix: Also update cs.validators so RPC webhook auth can find metagraph-registered validators
        // Use the same min_stake threshold as the P2P validator set (10000 TAO = 10e12 RAO)
        if stake >= 10_000_000_000_000 {
            cs.validators.entry(hotkey.clone()).or_insert_with(|| {
                platform_core::ValidatorInfo::new(hotkey.clone(), platform_core::Stake(stake))
            });
            p2p_validators.push((hotkey, stake));
        }
    }

    // Update valid voters for distributed storage consensus layers
    let voter_hotkeys: std::collections::HashSet<Hotkey> = cs.validators.keys().cloned().collect();
    *valid_voters.write() = voter_hotkeys.clone();
    state_root_consensus.lock().set_valid_voters(voter_hotkeys);

    cs.update_hash();

    // Sync validators to P2P state manager for storage consensus
    state_manager.apply(|state| {
        for (hotkey, stake) in p2p_validators {
            state.update_validator(hotkey, stake);
        }
    });
}

async fn handle_network_event(
    event: NetworkEvent,
    consensus: &Arc<RwLock<ConsensusEngine>>,
    validator_set: &Arc<ValidatorSet>,
    state_manager: &Arc<StateManager>,
    wasm_executor_ref: &Option<Arc<WasmChallengeExecutor>>,
    storage: &Arc<TrackedStorage>,
    keypair: &Keypair,
    p2p_cmd_tx: &tokio::sync::mpsc::Sender<platform_p2p_consensus::P2PCommand>,
    chain_state: &Arc<RwLock<platform_core::ChainState>>,
    challenge_last_sync: &Arc<RwLock<std::collections::HashMap<platform_core::ChallengeId, u64>>>,
    shared_llm_validators_json: &Arc<parking_lot::RwLock<Vec<u8>>>,
    shared_registered_hotkeys_json: &Arc<parking_lot::RwLock<Vec<u8>>>,
    rpc_handler: &Option<Arc<platform_rpc::RpcHandler>>,
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
                } else {
                    // Sync validator to ChainState for RPC
                    let mut state = chain_state.write();
                    let validator_info = platform_core::ValidatorInfo {
                        hotkey: hb.validator.clone(),
                        stake: platform_core::Stake(hb.stake),
                        is_active: true,
                        last_seen: chrono::Utc::now(),
                        peer_id: None,
                        x25519_pubkey: None,
                    };
                    state
                        .validators
                        .insert(hb.validator.clone(), validator_info);

                    // Track LLM-capable validators
                    if hb.capabilities.has_llm {
                        state.llm_capable_validators.insert(hb.validator.clone());
                    } else {
                        state.llm_capable_validators.remove(&hb.validator);
                    }

                    // Update shared WASM-accessible chain state
                    if let Ok(json) = serde_json::to_vec(
                        &state
                            .llm_capable_validators
                            .iter()
                            .map(|h| h.to_ss58())
                            .collect::<Vec<_>>(),
                    ) {
                        *shared_llm_validators_json.write() = json;
                    }
                    if let Ok(json) = serde_json::to_vec(
                        &state
                            .registered_hotkeys
                            .iter()
                            .map(|h| h.to_ss58())
                            .collect::<Vec<_>>(),
                    ) {
                        *shared_registered_hotkeys_json.write() = json;
                    }

                    // Check core state hash divergence
                    let our_core_hash = state.state_hash;
                    drop(state);

                    if hb.core_state_hash != [0u8; 32] && hb.core_state_hash != our_core_hash {
                        let our_mutation_seq = chain_state.read().mutation_sequence;
                        debug!(
                            peer = %hb.validator.to_ss58(),
                            peer_core_hash = %hex::encode(&hb.core_state_hash[..8]),
                            our_core_hash = %hex::encode(&our_core_hash[..8]),
                            "Core state hash divergence detected, requesting sync"
                        );

                        let timestamp = chrono::Utc::now().timestamp_millis();
                        let sign_data =
                            bincode::serialize(&(&our_core_hash, our_mutation_seq, timestamp))
                                .unwrap_or_default();
                        let signature = keypair.sign_bytes(&sign_data).unwrap_or_default();

                        let req = P2PMessage::CoreStateRequest(
                            platform_p2p_consensus::CoreStateRequestMessage {
                                requester: keypair.hotkey(),
                                current_hash: our_core_hash,
                                mutation_sequence: our_mutation_seq,
                                timestamp,
                                signature,
                            },
                        );

                        if let Err(e) = p2p_cmd_tx
                            .send(platform_p2p_consensus::P2PCommand::Broadcast(req))
                            .await
                        {
                            warn!(error = %e, "Failed to send core state request");
                        }
                    }
                }
            }
            P2PMessage::Submission(sub) => {
                info!(
                    submission_id = %sub.submission_id,
                    challenge_id = %sub.challenge_id,
                    miner = %sub.miner.to_ss58(),
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
                    validator = %eval.validator.to_ss58(),
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
                            validator = %validator_hotkey.to_ss58(),
                            error = %e,
                            "Failed to add peer evaluation to state"
                        );
                    } else {
                        debug!(
                            submission_id = %eval.submission_id,
                            validator = %validator_hotkey.to_ss58(),
                            score = eval.score,
                            "Peer evaluation recorded in state"
                        );
                    }
                });
            }
            P2PMessage::StateRequest(req) => {
                debug!(
                    requester = %req.requester.to_ss58(),
                    sequence = req.current_sequence,
                    "Received state request"
                );
            }
            P2PMessage::StateResponse(resp) => {
                debug!(
                    responder = %resp.responder.to_ss58(),
                    sequence = resp.sequence,
                    "Received state response"
                );
            }
            P2PMessage::WeightVote(wv) => {
                debug!(
                    validator = %wv.validator.to_ss58(),
                    epoch = wv.epoch,
                    "Received weight vote"
                );
            }
            P2PMessage::PeerAnnounce(pa) => {
                debug!(
                    validator = %pa.validator.to_ss58(),
                    peer_id = %pa.peer_id,
                    addresses = pa.addresses.len(),
                    "Received peer announce"
                );
            }
            P2PMessage::JobClaim(claim) => {
                info!(
                    validator = %claim.validator.to_ss58(),
                    challenge_id = %claim.challenge_id,
                    max_jobs = claim.max_jobs,
                    "Received job claim"
                );
            }
            P2PMessage::JobAssignment(assignment) => {
                info!(
                    submission_id = %assignment.submission_id,
                    challenge_id = %assignment.challenge_id,
                    assigned_validator = %assignment.assigned_validator.to_ss58(),
                    assigner = %assignment.assigner.to_ss58(),
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
                    requester = %req.requester.to_ss58(),
                    challenge_id = %req.challenge_id,
                    data_type = %req.data_type,
                    "Received data request"
                );

                if !validator_set.is_validator(&req.requester) {
                    warn!(requester = %req.requester.to_ss58(), "Data request from unknown validator");
                } else if req.data_type == "challenge_storage" {
                    // Respond with storage data for the requested challenge
                    let challenge_id_str = req.challenge_id.to_string();

                    // List all keys in this challenge's namespace using list_prefix
                    let list_result = storage
                        .list_prefix(&challenge_id_str, None, 10000, None)
                        .await;

                    match list_result {
                        Ok(list_result) => {
                            // Collect all key-value pairs for this challenge
                            let mut storage_entries: Vec<(String, Vec<u8>)> = Vec::new();
                            for (key, stored) in list_result.items {
                                // Store key as hex-encoded string (matches our key format)
                                let key_str = String::from_utf8(key.key.clone())
                                    .unwrap_or_else(|_| hex::encode(&key.key));
                                storage_entries.push((key_str, stored.data));
                            }

                            let data = bincode::serialize(&storage_entries).unwrap_or_default();
                            let timestamp = chrono::Utc::now().timestamp_millis();
                            let request_id = req.request_id.clone();
                            let challenge_id = req.challenge_id;
                            let sign_data = bincode::serialize(&(&request_id, &data, timestamp))
                                .unwrap_or_default();
                            let signature = keypair.sign_bytes(&sign_data).unwrap_or_default();

                            let response = P2PMessage::DataResponse(
                                platform_p2p_consensus::DataResponseMessage {
                                    request_id: request_id.clone(),
                                    responder: keypair.hotkey(),
                                    challenge_id,
                                    data_type: "challenge_storage".to_string(),
                                    data,
                                    timestamp,
                                    signature,
                                },
                            );

                            if let Err(e) = p2p_cmd_tx
                                .send(platform_p2p_consensus::P2PCommand::Broadcast(response))
                                .await
                            {
                                warn!(error = %e, "Failed to send storage data response");
                            } else {
                                info!(
                                    request_id = %request_id,
                                    challenge_id = %challenge_id,
                                    entries = storage_entries.len(),
                                    "Sent challenge storage data response"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                challenge_id = %req.challenge_id,
                                error = %e,
                                "Failed to list storage entries for data request"
                            );
                        }
                    }
                }
            }
            P2PMessage::DataResponse(resp) => {
                debug!(
                    request_id = %resp.request_id,
                    responder = %resp.responder.to_ss58(),
                    challenge_id = %resp.challenge_id,
                    data_bytes = resp.data.len(),
                    "Received data response"
                );

                if !validator_set.is_validator(&resp.responder) {
                    warn!(responder = %resp.responder.to_ss58(), "Data response from unknown validator");
                } else if resp.data_type == "challenge_storage" {
                    // Merge storage data from peer
                    match bincode::deserialize::<Vec<(String, Vec<u8>)>>(&resp.data) {
                        Ok(entries) => {
                            let challenge_id_str = resp.challenge_id.to_string();
                            let mut imported = 0;

                            for (key, value) in entries {
                                let storage_key = StorageKey::new(&challenge_id_str, key);
                                // Only import if we don't have this key
                                match storage
                                    .get(
                                        &storage_key,
                                        platform_distributed_storage::GetOptions::default(),
                                    )
                                    .await
                                {
                                    Ok(None) => {
                                        if let Err(e) = storage
                                            .put(storage_key, value, PutOptions::default())
                                            .await
                                        {
                                            warn!(error = %e, "Failed to import storage entry");
                                        } else {
                                            imported += 1;
                                        }
                                    }
                                    Ok(Some(_)) => {
                                        // Already have this key, skip
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "Failed to check existing storage entry");
                                    }
                                }
                            }

                            if imported > 0 {
                                info!(
                                    challenge_id = %resp.challenge_id,
                                    imported = imported,
                                    "Imported storage entries from peer"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                "Failed to deserialize challenge storage data response"
                            );
                        }
                    }
                }
            }
            P2PMessage::TaskProgress(progress) => {
                debug!(
                    submission_id = %progress.submission_id,
                    challenge_id = %progress.challenge_id,
                    validator = %progress.validator.to_ss58(),
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
                    validator = %result.validator.to_ss58(),
                    task_id = %result.task_id,
                    passed = result.passed,
                    score = result.score,
                    execution_time_ms = result.execution_time_ms,
                    "Received task result"
                );
            }
            P2PMessage::LeaderboardRequest(req) => {
                debug!(
                    requester = %req.requester.to_ss58(),
                    challenge_id = %req.challenge_id,
                    limit = req.limit,
                    offset = req.offset,
                    "Received leaderboard request"
                );
            }
            P2PMessage::LeaderboardResponse(resp) => {
                debug!(
                    responder = %resp.responder.to_ss58(),
                    challenge_id = %resp.challenge_id,
                    total_count = resp.total_count,
                    "Received leaderboard response"
                );
            }
            P2PMessage::ChallengeUpdate(update) => {
                let updater_ss58 = update.updater.to_ss58();
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

                    // Handle different update types
                    let challenge_id_str = update.challenge_id.to_string();
                    match update.update_type.as_str() {
                        "wasm_upload" => {
                            // Validate WASM before storing
                            let is_valid = if let Some(ref executor) = wasm_executor_ref {
                                match executor.validate_wasm_module(&update.data) {
                                    Ok(()) => true,
                                    Err(e) => {
                                        error!(
                                            challenge_id = %update.challenge_id,
                                            error = %e,
                                            "Invalid WASM module from P2P, rejecting"
                                        );
                                        false
                                    }
                                }
                            } else {
                                true // No executor, can't validate
                            };

                            if !is_valid {
                                // Skip storing invalid WASM
                            } else {
                                // Store WASM in distributed storage
                                let wasm_key = StorageKey::new("wasm", &challenge_id_str);
                                match storage
                                    .put(wasm_key, update.data.clone(), PutOptions::default())
                                    .await
                                {
                                    Ok(metadata) => {
                                        info!(
                                            challenge_id = %update.challenge_id,
                                            version = metadata.version,
                                            size_bytes = update.data.len(),
                                            "Stored WASM module in distributed storage"
                                        );
                                        // Use name from P2P message, fallback to UUID
                                        let challenge_name = update
                                            .name
                                            .as_deref()
                                            .unwrap_or(&challenge_id_str)
                                            .to_string();

                                        // Register challenge in state if not exists
                                        state_manager.apply(|state| {
                                            if state.get_challenge(&update.challenge_id).is_none() {
                                                let challenge_config =
                                                    platform_p2p_consensus::ChallengeConfig {
                                                        id: update.challenge_id,
                                                        name: challenge_name.clone(),
                                                        weight: 100, // Default weight
                                                        is_active: true,
                                                        creator: update.updater.clone(),
                                                        created_at: chrono::Utc::now()
                                                            .timestamp_millis(),
                                                        wasm_hash: metadata.value_hash,
                                                    };
                                                state.add_challenge(challenge_config);
                                            }
                                        });

                                        // Sync challenge to ChainState for RPC and persist
                                        let cid = update.challenge_id;
                                        let owner = update.updater.clone();
                                        let code_hash = hex::encode(metadata.value_hash);
                                        let version = metadata.version.to_string();
                                        let module_path = challenge_id_str.clone();
                                        let cname = challenge_name.clone();
                                        mutate_and_persist(
                                            storage.clone(),
                                            chain_state.clone(),
                                            "wasm_upload_p2p",
                                            |cs| {
                                                let wasm_config =
                                                    platform_core::WasmChallengeConfig {
                                                        challenge_id: cid,
                                                        name: cname,
                                                        description: String::new(),
                                                        owner,
                                                        module: platform_core::WasmModuleMetadata {
                                                            module_path,
                                                            code_hash,
                                                            version,
                                                            ..Default::default()
                                                        },
                                                        config:
                                                            platform_core::ChallengeConfig::default(
                                                            ),
                                                        is_active: true,
                                                    };
                                                cs.register_wasm_challenge(wasm_config);
                                            },
                                        )
                                        .await;

                                        // Load routes in a blocking thread to avoid tokio runtime issues
                                        if let Some(ref executor) = wasm_executor_ref {
                                            let wasm_bytes = update.data.clone();
                                            let executor = executor.clone();
                                            let challenge_id_for_routes = update.challenge_id;
                                            let challenge_id_str_for_routes =
                                                challenge_id_str.clone();
                                            let chain_state_for_routes = chain_state.clone();

                                            std::thread::spawn(move || {
                                                match executor.execute_get_routes_from_bytes(
                                                    &challenge_id_str_for_routes,
                                                    &wasm_bytes,
                                                    &wasm_runtime_interface::NetworkPolicy::development(),
                                                    &wasm_runtime_interface::SandboxPolicy::default(),
                                                ) {
                                                    Ok((routes_data, _)) => {
                                                        if let Ok(routes) = bincode::deserialize::<Vec<platform_challenge_sdk_wasm::WasmRouteDefinition>>(&routes_data) {
                                                            tracing::info!(
                                                                challenge_id = %challenge_id_for_routes,
                                                                routes_count = routes.len(),
                                                                "Loaded WASM challenge routes (P2P)"
                                                            );
                                                            for route in &routes {
                                                                tracing::info!(
                                                                    challenge_id = %challenge_id_for_routes,
                                                                    method = %route.method,
                                                                    path = %route.path,
                                                                    "  Route: {} {}",
                                                                    route.method,
                                                                    route.path
                                                                );
                                                            }
                                                            let route_infos: Vec<platform_core::ChallengeRouteInfo> = routes.iter().map(|r| {
                                                                platform_core::ChallengeRouteInfo {
                                                                    method: r.method.clone(),
                                                                    path: r.path.clone(),
                                                                    description: r.description.clone(),
                                                                    requires_auth: r.requires_auth,
                                                                }
                                                            }).collect();
                                                            let mut cs = chain_state_for_routes.write();
                                                            cs.register_challenge_routes(challenge_id_for_routes, route_infos);
                                                        }
                                                    }
                                                    Err(e) => {
                                                        tracing::debug!(
                                                            challenge_id = %challenge_id_for_routes,
                                                            error = %e,
                                                            "No routes exported by WASM module"
                                                        );
                                                    }
                                                }
                                            });
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            challenge_id = %update.challenge_id,
                                            error = %e,
                                            "Failed to store WASM module"
                                        );
                                    }
                                }
                            } // end else for is_valid
                        }
                        "activate" => {
                            let cid = update.challenge_id;
                            mutate_and_persist(
                                storage.clone(),
                                chain_state.clone(),
                                "activate",
                                |cs| {
                                    cs.set_challenge_active(&cid, true);
                                },
                            )
                            .await;
                            state_manager.apply(|state| {
                                state.set_challenge_active(&cid, true);
                            });
                            info!(challenge_id = %cid, "Challenge activated");
                        }
                        "deactivate" => {
                            let cid = update.challenge_id;
                            mutate_and_persist(
                                storage.clone(),
                                chain_state.clone(),
                                "deactivate",
                                |cs| {
                                    cs.set_challenge_active(&cid, false);
                                },
                            )
                            .await;
                            state_manager.apply(|state| {
                                state.set_challenge_active(&cid, false);
                            });
                            info!(challenge_id = %cid, "Challenge deactivated");
                        }
                        "rename" => {
                            if let Ok(new_name) = String::from_utf8(update.data.clone()) {
                                let cid = update.challenge_id;
                                let name_clone = new_name.clone();
                                let renamed = mutate_and_persist(
                                    storage.clone(),
                                    chain_state.clone(),
                                    "rename",
                                    |cs| cs.rename_challenge(&cid, name_clone),
                                )
                                .await;
                                if renamed {
                                    info!(
                                        challenge_id = %cid,
                                        new_name = %new_name,
                                        "Challenge renamed via P2P"
                                    );
                                } else {
                                    warn!(
                                        challenge_id = %cid,
                                        new_name = %new_name,
                                        "Failed to rename challenge - not found or name conflict"
                                    );
                                }
                            }
                        }
                        "sudo_action" => {
                            match bincode::deserialize::<platform_core::SudoAction>(&update.data) {
                                Ok(action) => {
                                    info!("Applying sudo action from P2P: {:?}", action);
                                    mutate_and_persist(
                                        storage.clone(),
                                        chain_state.clone(),
                                        "sudo_action",
                                        |cs| {
                                            if let Err(e) = cs.apply_sudo_action(&action) {
                                                error!(
                                                    "Failed to apply sudo action from P2P: {}",
                                                    e
                                                );
                                            } else {
                                                info!("Sudo action applied from P2P successfully");
                                            }
                                        },
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    error!("Failed to deserialize sudo action from P2P: {}", e);
                                }
                            }
                        }
                        "remove" => {
                            let cid = update.challenge_id;
                            mutate_and_persist(
                                storage.clone(),
                                chain_state.clone(),
                                "remove_p2p",
                                |cs| {
                                    cs.remove_wasm_challenge(&cid);
                                },
                            )
                            .await;
                            state_manager.apply(|state| {
                                state.remove_challenge(&cid);
                            });
                            let wasm_key = StorageKey::new("wasm", &challenge_id_str);
                            let _ = storage.delete(&wasm_key).await;
                            info!(challenge_id = %cid, "Challenge removed via P2P");
                        }
                        other => {
                            warn!(
                                challenge_id = %update.challenge_id,
                                update_type = %other,
                                "Unknown challenge update type"
                            );
                        }
                    }

                    // Invalidate WASM cache (skip for wasm_upload - module was just compiled fresh)
                    if update.update_type != "wasm_upload" {
                        if let Some(ref executor) = wasm_executor_ref {
                            executor.invalidate_cache(&challenge_id_str);
                        }
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
                info!(
                    proposal_id = %hex::encode(&proposal.proposal_id[..8]),
                    challenge_id = %proposal.challenge_id,
                    proposer = %proposal.proposer.to_ss58(),
                    key_len = proposal.key.len(),
                    value_len = proposal.value.len(),
                    "Received storage proposal"
                );

                // Verify proposer is a known validator
                let proposer_valid = validator_set.is_validator(&proposal.proposer);

                if !proposer_valid {
                    warn!(
                        proposer = %proposal.proposer.to_ss58(),
                        "Storage proposal from unknown validator, ignoring"
                    );
                } else {
                    // Add proposal to state
                    let storage_proposal = StorageProposal {
                        proposal_id: proposal.proposal_id,
                        challenge_id: proposal.challenge_id,
                        proposer: proposal.proposer.clone(),
                        key: proposal.key.clone(),
                        value: proposal.value.clone(),
                        timestamp: proposal.timestamp,
                        votes: std::collections::HashMap::new(),
                        finalized: false,
                    };

                    state_manager.apply(|state| {
                        state.add_storage_proposal(storage_proposal);
                    });

                    // Validate proposal before voting
                    let max_key_size = 1024;
                    let max_value_size = 10 * 1024 * 1024; // 10MB
                    let in_bootstrap = state_manager.apply(|s| s.is_in_bootstrap_period());
                    let is_bootstrap_validator = proposal.proposer.to_ss58()
                        == platform_core::constants::BOOTSTRAP_VALIDATOR_SS58;

                    // During bootstrap, only accept storage proposals from bootstrap validator
                    let approve = if in_bootstrap && !is_bootstrap_validator {
                        debug!(
                            proposal_id = %hex::encode(&proposal.proposal_id[..8]),
                            proposer = %proposal.proposer.to_ss58(),
                            "Bootstrap: rejecting storage proposal from non-bootstrap validator"
                        );
                        false
                    } else {
                        !proposal.key.is_empty()
                            && proposal.key.len() <= max_key_size
                            && proposal.value.len() <= max_value_size
                            && proposal.challenge_id.0 != uuid::Uuid::nil()
                            && !proposal.signature.is_empty()
                    };

                    if !approve {
                        warn!(
                            proposal_id = %hex::encode(&proposal.proposal_id[..8]),
                            "Storage proposal failed validation, voting reject"
                        );
                    }

                    let my_hotkey = keypair.hotkey();
                    let timestamp = chrono::Utc::now().timestamp_millis();

                    let vote_data =
                        bincode::serialize(&(&proposal.proposal_id, approve, timestamp))
                            .unwrap_or_default();
                    let signature = keypair.sign_bytes(&vote_data).unwrap_or_default();

                    let vote_msg = P2PMessage::StorageVote(StorageVoteMessage {
                        proposal_id: proposal.proposal_id,
                        voter: my_hotkey.clone(),
                        approve,
                        timestamp,
                        signature,
                    });

                    // Add our own vote locally (we don't receive our own broadcasts)
                    let consensus_result = state_manager.apply(|state| {
                        state.vote_storage_proposal(&proposal.proposal_id, my_hotkey, approve)
                    });

                    // If consensus reached immediately (e.g. bootstrap auto-accept), write now
                    if let Some(true) = consensus_result {
                        let proposal_opt = state_manager
                            .apply(|state| state.remove_storage_proposal(&proposal.proposal_id));
                        if let Some(p) = proposal_opt {
                            let storage_key =
                                StorageKey::new(&p.challenge_id.to_string(), hex::encode(&p.key));
                            let result = if p.value.is_empty() {
                                storage.delete(&storage_key).await
                            } else {
                                storage
                                    .put(
                                        storage_key.clone(),
                                        p.value.clone(),
                                        put_options_with_block(&state_manager),
                                    )
                                    .await
                                    .map(|_| true)
                            };
                            match result {
                                Ok(_) => {
                                    info!(
                                        proposal_id = %hex::encode(&p.proposal_id[..8]),
                                        challenge_id = %p.challenge_id,
                                        "Bootstrap: proposal auto-accepted and written"
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        proposal_id = %hex::encode(&p.proposal_id[..8]),
                                        error = %e,
                                        "Failed to write bootstrap-accepted proposal"
                                    );
                                }
                            }
                        }
                    }

                    if let Err(e) = p2p_cmd_tx
                        .send(platform_p2p_consensus::P2PCommand::Broadcast(vote_msg))
                        .await
                    {
                        warn!(error = %e, "Failed to broadcast storage vote");
                    }
                }
            }
            P2PMessage::StorageVote(vote) => {
                debug!(
                    proposal_id = %hex::encode(&vote.proposal_id[..8]),
                    voter = %vote.voter.to_ss58(),
                    approve = vote.approve,
                    "Received storage vote"
                );

                // Verify voter is a known validator
                if !validator_set.is_validator(&vote.voter) {
                    warn!(voter = %vote.voter.to_ss58(), "Vote from unknown validator");
                } else {
                    // Add vote to proposal
                    let consensus_result = state_manager.apply(|state| {
                        state.vote_storage_proposal(
                            &vote.proposal_id,
                            vote.voter.clone(),
                            vote.approve,
                        )
                    });

                    // If consensus reached and approved, write to distributed storage
                    if let Some(true) = consensus_result {
                        let proposal_opt = state_manager
                            .apply(|state| state.remove_storage_proposal(&vote.proposal_id));

                        if let Some(proposal) = proposal_opt {
                            // Use same key format as ChallengeStorageBackend:
                            // namespace = challenge_id.to_string(), key = hex::encode(key_bytes)
                            let storage_key = StorageKey::new(
                                &proposal.challenge_id.to_string(),
                                hex::encode(&proposal.key),
                            );

                            // Empty value means delete
                            let result = if proposal.value.is_empty() {
                                storage.delete(&storage_key).await
                            } else {
                                storage
                                    .put(
                                        storage_key.clone(),
                                        proposal.value.clone(),
                                        put_options_with_block(state_manager),
                                    )
                                    .await
                                    .map(|_| true)
                            };

                            match result {
                                Ok(_) => {
                                    let op = if proposal.value.is_empty() {
                                        "deleted"
                                    } else {
                                        "written"
                                    };
                                    info!(
                                        proposal_id = %hex::encode(&proposal.proposal_id[..8]),
                                        challenge_id = %proposal.challenge_id,
                                        key_len = proposal.key.len(),
                                        "Storage proposal consensus reached, data {}", op
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        proposal_id = %hex::encode(&proposal.proposal_id[..8]),
                                        error = %e,
                                        "Failed to write consensus storage"
                                    );
                                }
                            }
                        }
                    } else if let Some(false) = consensus_result {
                        info!(
                            proposal_id = %hex::encode(&vote.proposal_id[..8]),
                            "Storage proposal rejected by consensus"
                        );
                        state_manager.apply(|state| {
                            state.remove_storage_proposal(&vote.proposal_id);
                        });
                    }
                }
            }
            P2PMessage::ReviewAssignment(msg) => {
                debug!(
                    submission_id = %msg.submission_id,
                    assigner = %msg.assigner.to_ss58(),
                    assigned_count = msg.assigned_validators.len(),
                    "Received review assignment"
                );
            }
            P2PMessage::ReviewDecline(msg) => {
                let safe_reason = sanitize_for_log(&msg.reason);
                debug!(
                    submission_id = %msg.submission_id,
                    validator = %msg.validator.to_ss58(),
                    reason = %safe_reason,
                    "Received review decline"
                );
            }
            P2PMessage::ReviewResult(msg) => {
                debug!(
                    submission_id = %msg.submission_id,
                    validator = %msg.validator.to_ss58(),
                    score = msg.score,
                    "Received review result"
                );
            }
            P2PMessage::AgentLogProposal(msg) => {
                // Verify logs hash matches data
                let computed_hash = platform_core::crypto::hash(&msg.logs_data);
                if computed_hash != msg.logs_hash {
                    warn!("Agent log proposal hash mismatch, ignoring");
                } else {
                    debug!(
                        submission_id = %msg.submission_id,
                        validator = %msg.validator_hotkey.to_ss58(),
                        "Received valid agent log proposal"
                    );
                    // Store in chain state for consensus
                    state_manager.apply(|state| {
                        state
                            .agent_log_proposals
                            .entry(msg.submission_id.clone())
                            .or_default()
                            .insert(msg.validator_hotkey.clone(), msg.logs_data.clone());
                    });
                }
            }
            P2PMessage::StorageRootSync(msg) => {
                if !validator_set.is_validator(&msg.validator) {
                    warn!(validator = %msg.validator.to_ss58(), "Storage root sync from unknown validator");
                } else {
                    let local_roots: Vec<(platform_core::ChallengeId, [u8; 32])> = state_manager
                        .apply(|state| {
                            state
                                .challenge_storage_roots
                                .iter()
                                .map(|(k, v)| (*k, *v))
                                .collect()
                        });
                    let local_map: std::collections::HashMap<_, _> =
                        local_roots.into_iter().collect();
                    for (cid, remote_root) in &msg.roots {
                        let needs_sync = match local_map.get(cid) {
                            Some(local_root) => local_root != remote_root,
                            None => true, // We don't have this challenge's storage at all
                        };

                        if needs_sync {
                            info!(
                                challenge_id = %cid,
                                remote_validator = %msg.validator.to_ss58(),
                                "Storage divergence detected, requesting challenge data"
                            );

                            // Request storage data for this challenge
                            let request_id = format!(
                                "storage_sync_{}_{}",
                                cid,
                                chrono::Utc::now().timestamp_millis()
                            );
                            let timestamp = chrono::Utc::now().timestamp_millis();
                            let sign_data =
                                bincode::serialize(&(&request_id, timestamp)).unwrap_or_default();
                            let signature = keypair.sign_bytes(&sign_data).unwrap_or_default();

                            let req = P2PMessage::DataRequest(
                                platform_p2p_consensus::DataRequestMessage {
                                    request_id,
                                    requester: keypair.hotkey(),
                                    challenge_id: *cid,
                                    data_type: "challenge_storage".to_string(),
                                    data_key: "all".to_string(),
                                    timestamp,
                                    signature,
                                },
                            );

                            if let Err(e) = p2p_cmd_tx
                                .send(platform_p2p_consensus::P2PCommand::Broadcast(req))
                                .await
                            {
                                warn!(error = %e, "Failed to send storage sync request");
                            }
                        }
                    }
                }
            }
            P2PMessage::StateMutationProposal(proposal) => {
                info!(
                    proposal_id = %hex::encode(&proposal.proposal_id[..8]),
                    mutation_type = ?proposal.mutation_type,
                    proposer = %proposal.proposer.to_ss58(),
                    "Received state mutation proposal"
                );

                if !validator_set.is_validator(&proposal.proposer) {
                    warn!(proposer = %proposal.proposer.to_ss58(), "State mutation from unknown validator");
                } else {
                    // Add proposal to P2P state
                    let entry = platform_p2p_consensus::StateMutationEntry {
                        proposal_id: proposal.proposal_id,
                        mutation_type: proposal.mutation_type.clone(),
                        data: proposal.data.clone(),
                        proposer: proposal.proposer.clone(),
                        timestamp: proposal.timestamp,
                        mutation_sequence: proposal.mutation_sequence,
                        votes: std::collections::HashMap::new(),
                        finalized: false,
                    };
                    state_manager.apply(|state| {
                        state.add_state_mutation(entry);
                    });

                    // Validate and vote
                    let approve = match &proposal.mutation_type {
                        platform_p2p_consensus::StateMutationType::WasmUpload { .. } => {
                            // Validate WASM module
                            if let Some(ref executor) = wasm_executor_ref {
                                executor.validate_wasm_module(&proposal.data).is_ok()
                            } else {
                                true
                            }
                        }
                        platform_p2p_consensus::StateMutationType::SudoAction => {
                            // Verify proposer is sudo
                            let proposer_hex = proposal.proposer.to_ss58();
                            proposer_hex == platform_p2p_consensus::SUDO_HOTKEY
                                || proposal.proposer.0 == platform_core::SUDO_KEY_BYTES
                        }
                        _ => true,
                    };

                    let my_hotkey = keypair.hotkey();
                    let timestamp = chrono::Utc::now().timestamp_millis();
                    let vote_data =
                        bincode::serialize(&(&proposal.proposal_id, approve, timestamp))
                            .unwrap_or_default();
                    let signature = keypair.sign_bytes(&vote_data).unwrap_or_default();

                    let vote_msg = P2PMessage::StateMutationVote(
                        platform_p2p_consensus::StateMutationVoteMessage {
                            proposal_id: proposal.proposal_id,
                            voter: my_hotkey,
                            approve,
                            timestamp,
                            signature,
                        },
                    );

                    if let Err(e) = p2p_cmd_tx
                        .send(platform_p2p_consensus::P2PCommand::Broadcast(vote_msg))
                        .await
                    {
                        warn!(error = %e, "Failed to broadcast state mutation vote");
                    }
                }
            }
            P2PMessage::StateMutationVote(vote) => {
                debug!(
                    proposal_id = %hex::encode(&vote.proposal_id[..8]),
                    voter = %vote.voter.to_ss58(),
                    approve = vote.approve,
                    "Received state mutation vote"
                );

                if !validator_set.is_validator(&vote.voter) {
                    warn!(voter = %vote.voter.to_ss58(), "State mutation vote from unknown validator");
                } else {
                    let consensus_result = state_manager.apply(|state| {
                        state.vote_state_mutation(
                            &vote.proposal_id,
                            vote.voter.clone(),
                            vote.approve,
                        )
                    });

                    if let Some(approved) = consensus_result {
                        let entry_opt = state_manager
                            .apply(|state| state.remove_state_mutation(&vote.proposal_id));

                        if let Some(entry) = entry_opt {
                            if approved {
                                info!(
                                    proposal_id = %hex::encode(&entry.proposal_id[..8]),
                                    mutation_type = ?entry.mutation_type,
                                    "State mutation consensus reached - applying"
                                );

                                // Apply the mutation to core chain state
                                match &entry.mutation_type {
                                    platform_p2p_consensus::StateMutationType::WasmUpload { challenge_id } => {
                                        let challenge_id_str = challenge_id.to_string();
                                        let wasm_key = StorageKey::new("wasm", &challenge_id_str);
                                        match storage.put(wasm_key, entry.data.clone(), put_options_with_block(&state_manager)).await {
                                            Ok(metadata) => {
                                                let cid = *challenge_id;
                                                let owner = entry.proposer.clone();
                                                let code_hash = hex::encode(metadata.value_hash);
                                                let version = metadata.version.to_string();
                                                let module_path = challenge_id_str.clone();
                                                let cname = challenge_id_str.clone();
                                                mutate_and_persist(
                                                    storage.clone(),
                                                    chain_state.clone(),
                                                    "wasm_consensus",
                                                    |cs| {
                                                        let wasm_config = platform_core::WasmChallengeConfig {
                                                            challenge_id: cid,
                                                            name: cname,
                                                            description: String::new(),
                                                            owner,
                                                            module: platform_core::WasmModuleMetadata {
                                                                module_path,
                                                                code_hash,
                                                                version,
                                                                ..Default::default()
                                                            },
                                                            config: platform_core::ChallengeConfig::default(),
                                                            is_active: true,
                                                        };
                                                        cs.register_wasm_challenge(wasm_config);
                                                    },
                                                )
                                                .await;

                                                info!(
                                                    challenge_id = %challenge_id,
                                                    "WASM challenge registered via consensus"
                                                );
                                            }
                                            Err(e) => {
                                                error!(error = %e, "Failed to store WASM after consensus");
                                            }
                                        }
                                    }
                                    platform_p2p_consensus::StateMutationType::SudoAction => {
                                        if let Ok(action) = bincode::deserialize::<platform_core::SudoAction>(&entry.data) {
                                            mutate_and_persist(storage.clone(), chain_state.clone(), "sudo_consensus", |cs| {
                                                if let Err(e) = cs.apply_sudo_action(&action) {
                                                    error!("Failed to apply sudo action via consensus: {}", e);
                                                }
                                            }).await;
                                        }
                                    }
                                    platform_p2p_consensus::StateMutationType::ChallengeRename { challenge_id } => {
                                        if let Ok(new_name) = String::from_utf8(entry.data.clone()) {
                                            let cid = *challenge_id;
                                            mutate_and_persist(storage.clone(), chain_state.clone(), "rename_consensus", |cs| {
                                                cs.rename_challenge(&cid, new_name);
                                            }).await;
                                        }
                                    }
                                    platform_p2p_consensus::StateMutationType::RouteRegistration { challenge_id } => {
                                        if let Ok(routes) = bincode::deserialize::<Vec<platform_core::ChallengeRouteInfo>>(&entry.data) {
                                            let cid = *challenge_id;
                                            mutate_and_persist(storage.clone(), chain_state.clone(), "routes_consensus", |cs| {
                                                cs.register_challenge_routes(cid, routes);
                                            }).await;
                                        }
                                    }
                                    platform_p2p_consensus::StateMutationType::ChallengeActivation { challenge_id, active } => {
                                        let cid = *challenge_id;
                                        let is_active = *active;
                                        mutate_and_persist(storage.clone(), chain_state.clone(), "activation_consensus", |cs| {
                                            cs.set_challenge_active(&cid, is_active);
                                        }).await;
                                        state_manager.apply(|state| {
                                            state.set_challenge_active(&cid, is_active);
                                        });
                                    }
                                    platform_p2p_consensus::StateMutationType::EpochTransition { new_epoch } => {
                                        info!(new_epoch = new_epoch, "Epoch transition via consensus");
                                        state_manager.apply(|state| {
                                            state.next_epoch();
                                        });
                                    }
                                }

                                // Persist immediately after consensus-approved mutation
                                if let Err(e) =
                                    persist_core_state_to_storage(storage, chain_state).await
                                {
                                    warn!(
                                        "Failed to persist core state after consensus mutation: {}",
                                        e
                                    );
                                }
                            } else {
                                info!(
                                    proposal_id = %hex::encode(&entry.proposal_id[..8]),
                                    "State mutation rejected by consensus"
                                );
                            }
                        }
                    }
                }
            }
            P2PMessage::CoreStateRequest(req) => {
                info!(
                    requester = %req.requester.to_ss58(),
                    mutation_seq = req.mutation_sequence,
                    "Received core state sync request"
                );

                if !validator_set.is_validator(&req.requester) {
                    warn!(requester = %req.requester.to_ss58(), "Core state request from unknown validator");
                } else {
                    let cs = chain_state.read();
                    let state_data = serde_json::to_vec(&*cs).unwrap_or_default();
                    let state_hash = cs.state_hash;
                    let mutation_sequence = cs.mutation_sequence;
                    drop(cs);

                    let timestamp = chrono::Utc::now().timestamp_millis();
                    let sign_data =
                        bincode::serialize(&(&state_hash, mutation_sequence, timestamp))
                            .unwrap_or_default();
                    let signature = keypair.sign_bytes(&sign_data).unwrap_or_default();

                    let response = P2PMessage::CoreStateResponse(
                        platform_p2p_consensus::CoreStateResponseMessage {
                            responder: keypair.hotkey(),
                            state_hash,
                            mutation_sequence,
                            state_data,
                            timestamp,
                            signature,
                        },
                    );

                    if let Err(e) = p2p_cmd_tx
                        .send(platform_p2p_consensus::P2PCommand::Broadcast(response))
                        .await
                    {
                        warn!(error = %e, "Failed to send core state response");
                    }
                }
            }
            P2PMessage::CoreStateResponse(resp) => {
                info!(
                    responder = %resp.responder.to_ss58(),
                    mutation_seq = resp.mutation_sequence,
                    "Received core state sync response"
                );

                if !validator_set.is_validator(&resp.responder) {
                    warn!(responder = %resp.responder.to_ss58(), "Core state response from unknown validator");
                } else {
                    // Deserialize and merge
                    match serde_json::from_slice::<platform_core::ChainState>(&resp.state_data) {
                        Ok(peer_state) => {
                            let mut cs = chain_state.write();
                            if cs.merge_from(&peer_state) {
                                info!(
                                    new_mutation_seq = cs.mutation_sequence,
                                    "Core state merged from peer"
                                );
                                drop(cs);

                                // Persist merged state
                                if let Err(e) =
                                    persist_core_state_to_storage(storage, chain_state).await
                                {
                                    warn!("Failed to persist merged core state: {}", e);
                                }
                            } else {
                                debug!("Core state from peer not newer, skipping merge");
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to deserialize peer core state");
                        }
                    }
                }
            }
            P2PMessage::ChallengeSyncProposal(proposal) => {
                let challenge_id_str = proposal.challenge_id.to_string();
                let module_path = format!("{}.wasm", challenge_id_str);

                // Compute our own sync hash to compare
                let our_hash = if let Some(ref executor) = wasm_executor_ref {
                    let block = state_manager.apply(|s| s.bittensor_block);
                    match executor.execute_sync_with_block(&module_path, block, block / 360) {
                        Ok(result) => result.leaderboard_hash,
                        Err(_) => [0u8; 32],
                    }
                } else {
                    [0u8; 32]
                };

                if our_hash != [0u8; 32] && our_hash == proposal.sync_result_hash {
                    // In sync -- update last_sync_block
                    challenge_last_sync
                        .write()
                        .insert(proposal.challenge_id, proposal.block_number);
                    debug!(
                        challenge_id = %proposal.challenge_id,
                        "Sync hash matches peer, storage is in sync"
                    );
                } else if proposal.sync_result_hash != [0u8; 32] {
                    // Delta sync: only request entries since our last known good block
                    let since_block = challenge_last_sync
                        .read()
                        .get(&proposal.challenge_id)
                        .copied()
                        .unwrap_or(0);

                    info!(
                        challenge_id = %proposal.challenge_id,
                        proposer = %proposal.proposer.to_ss58(),
                        our_hash = %hex::encode(&our_hash[..8]),
                        peer_hash = %hex::encode(&proposal.sync_result_hash[..8]),
                        since_block = since_block,
                        "Sync hash divergence, requesting delta sync"
                    );

                    let timestamp = chrono::Utc::now().timestamp_millis();
                    let sign_data =
                        bincode::serialize(&(&proposal.challenge_id, &our_hash, timestamp))
                            .unwrap_or_default();
                    let signature = keypair.sign_bytes(&sign_data).unwrap_or_default();

                    let req = P2PMessage::StorageSyncRequest(
                        platform_p2p_consensus::StorageSyncRequestMessage {
                            challenge_id: proposal.challenge_id,
                            requester: keypair.hotkey(),
                            current_hash: our_hash,
                            since_block,
                            timestamp,
                            signature,
                        },
                    );

                    if let Err(e) = p2p_cmd_tx
                        .send(platform_p2p_consensus::P2PCommand::Broadcast(req))
                        .await
                    {
                        warn!(error = %e, "Failed to send storage sync request");
                    }
                }
            }
            P2PMessage::ChallengeSyncVote(vote) => {
                debug!(
                    challenge_id = %vote.challenge_id,
                    voter = %vote.voter.to_ss58(),
                    "Received challenge sync vote"
                );
            }
            P2PMessage::StorageSyncRequest(req) => {
                if !validator_set.is_validator(&req.requester) {
                    warn!(requester = %req.requester.to_ss58(), "Storage sync request from non-validator");
                } else {
                    let challenge_ns = req.challenge_id.to_string();
                    let since = req.since_block;
                    info!(
                        challenge_id = %req.challenge_id,
                        requester = %req.requester.to_ss58(),
                        since_block = since,
                        "Responding to storage sync request (delta)"
                    );

                    // Collect items: if since_block > 0, delta only
                    let items_result: Result<
                        Vec<(
                            platform_distributed_storage::StorageKey,
                            platform_distributed_storage::StoredValue,
                        )>,
                        _,
                    > = if since > 0 {
                        storage
                            .list_after_block(&challenge_ns, since, 10_000)
                            .await
                            .map(|qr| qr.items)
                    } else {
                        storage
                            .list_prefix(&challenge_ns, None, 10_000, None)
                            .await
                            .map(|lr| lr.items)
                    };

                    match items_result {
                        Ok(items) => {
                            let entries: Vec<platform_p2p_consensus::StorageSyncEntry> = items
                                .iter()
                                .map(|(key, value)| platform_p2p_consensus::StorageSyncEntry {
                                    namespace: key.namespace.clone(),
                                    key: key.key.clone(),
                                    value: value.data.clone(),
                                    version: value.metadata.version,
                                    updated_block: value.metadata.updated_block,
                                })
                                .collect();

                            let total = entries.len() as u64;

                            // Compute hash of all entries for verification
                            let mut hasher = sha2::Sha256::new();
                            for e in &entries {
                                sha2::Digest::update(&mut hasher, &e.key);
                                sha2::Digest::update(&mut hasher, &e.value);
                            }
                            let data_hash: [u8; 32] = hasher.finalize().into();

                            let timestamp = chrono::Utc::now().timestamp_millis();
                            let sign_data = bincode::serialize(&(
                                &req.challenge_id,
                                &data_hash,
                                total,
                                timestamp,
                            ))
                            .unwrap_or_default();
                            let signature = keypair.sign_bytes(&sign_data).unwrap_or_default();

                            let resp = P2PMessage::StorageSyncResponse(
                                platform_p2p_consensus::StorageSyncResponseMessage {
                                    challenge_id: req.challenge_id,
                                    responder: keypair.hotkey(),
                                    data_hash,
                                    entries,
                                    total_entries: total,
                                    timestamp,
                                    signature,
                                },
                            );

                            if let Err(e) = p2p_cmd_tx
                                .send(platform_p2p_consensus::P2PCommand::Broadcast(resp))
                                .await
                            {
                                warn!(error = %e, "Failed to send storage sync response");
                            } else {
                                info!(
                                    challenge_id = %req.challenge_id,
                                    entries = total,
                                    since_block = since,
                                    "Storage sync delta response sent"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                challenge_id = %req.challenge_id,
                                error = %e,
                                "Failed to read storage for sync response"
                            );
                        }
                    }
                }
            }
            P2PMessage::StorageSyncResponse(resp) => {
                if !validator_set.is_validator(&resp.responder) {
                    warn!(responder = %resp.responder.to_ss58(), "Storage sync response from non-validator");
                } else if resp.entries.is_empty() {
                    debug!(
                        challenge_id = %resp.challenge_id,
                        "Empty storage sync response, nothing to apply"
                    );
                } else {
                    info!(
                        challenge_id = %resp.challenge_id,
                        responder = %resp.responder.to_ss58(),
                        entries = resp.entries.len(),
                        "Applying storage sync from peer"
                    );

                    let mut applied = 0u64;
                    let mut skipped = 0u64;
                    let mut max_block = 0u64;
                    let opts = put_options_with_block(state_manager);

                    for entry in &resp.entries {
                        let key = StorageKey::new(&entry.namespace, hex::encode(&entry.key));

                        // Only apply if peer version is newer
                        match storage
                            .get(&key, platform_distributed_storage::GetOptions::default())
                            .await
                        {
                            Ok(Some(existing)) if existing.metadata.version >= entry.version => {
                                skipped += 1;
                            }
                            _ => {
                                if let Err(e) =
                                    storage.put(key, entry.value.clone(), opts.clone()).await
                                {
                                    warn!(error = %e, "Failed to apply synced entry");
                                } else {
                                    applied += 1;
                                    if entry.updated_block > max_block {
                                        max_block = entry.updated_block;
                                    }
                                }
                            }
                        }
                    }

                    // Update last_sync_block for this challenge
                    if max_block > 0 {
                        challenge_last_sync
                            .write()
                            .insert(resp.challenge_id, max_block);
                    }

                    info!(
                        challenge_id = %resp.challenge_id,
                        applied = applied,
                        skipped = skipped,
                        max_block = max_block,
                        "Storage delta sync complete"
                    );
                }
            }
        },
        NetworkEvent::PeerConnected(peer_id) => {
            info!("Peer connected: {}", peer_id);
            if let Some(handler) = rpc_handler {
                handler.add_peer(peer_id.to_string());
            }
        }
        NetworkEvent::PeerDisconnected(peer_id) => {
            info!("Peer disconnected: {}", peer_id);
            if let Some(handler) = rpc_handler {
                handler.remove_peer(&peer_id.to_string());
            }
        }
        NetworkEvent::PeerIdentified {
            peer_id,
            hotkey,
            addresses,
        } => {
            info!(
                peer_id = %peer_id,
                address_count = addresses.len(),
                "Peer identified"
            );
            if hotkey.is_some() {
                debug!(peer_id = %peer_id, "Peer hotkey verified");
            }
        }
    }
}

async fn handle_block_event(
    event: BlockSyncEvent,
    subtensor: &Option<Arc<Subtensor>>,
    signer: &Option<Arc<BittensorSigner>>,
    client: &Option<SubtensorClient>,
    state_manager: &Arc<StateManager>,
    netuid: u16,
    version_key: u64,
    wasm_executor: &Option<Arc<WasmChallengeExecutor>>,
    _keypair: &Keypair,
    chain_state: &Arc<RwLock<platform_core::ChainState>>,
    storage: &Arc<TrackedStorage>,
    last_weight_submission_epoch: &mut u64,
) {
    match event {
        BlockSyncEvent::NewBlock { block_number, .. } => {
            debug!("Block {}", block_number);
            // Update storage block tracking
            storage.set_block(block_number);
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

            if epoch <= *last_weight_submission_epoch {
                info!(
                    "Skipping weight submission for epoch {} (already submitted in epoch {})",
                    epoch, *last_weight_submission_epoch
                );
                return;
            }

            // Single submission path: collect WASM weights, convert hotkey->UID,
            // apply emission_weight, and submit directly via Subtensor.
            if let (Some(st), Some(sig)) = (subtensor.as_ref(), signer.as_ref()) {
                let mut mechanism_weights: Vec<(u8, Vec<u16>, Vec<u16>)> = Vec::new();

                if let Some(ref executor) = wasm_executor {
                    let challenges: Vec<(String, u8, f64)> = {
                        let cs = chain_state.read();
                        cs.wasm_challenge_configs
                            .iter()
                            .filter(|(_, cfg)| cfg.is_active)
                            .map(|(id, cfg)| {
                                let mechanism_id = cfg.config.mechanism_id;
                                let emission_weight = cfg.config.emission_weight;
                                (id.to_string(), mechanism_id, emission_weight)
                            })
                            .collect()
                    };

                    let block_height = state_manager.apply(|state| state.bittensor_block);

                    for (cid, mechanism_id, emission_weight) in &challenges {
                        let emission_weight = emission_weight.clamp(0.0, 1.0);
                        if emission_weight < 0.001 {
                            debug!(
                                "Skipping challenge {} (emission_weight={:.4}, effectively zero)",
                                cid, emission_weight
                            );
                            continue;
                        }
                        match executor.execute_get_weights_with_block(cid, block_height, epoch) {
                            Ok(assignments) if !assignments.is_empty() => {
                                let total_weight: f64 = assignments.iter().map(|a| a.weight).sum();

                                // Use a map to merge duplicate UIDs (same hotkey appearing multiple times)
                                let mut uid_weight_map: std::collections::BTreeMap<u16, f64> =
                                    std::collections::BTreeMap::new();
                                let mut assigned_weight: f64 = 0.0;

                                if total_weight > 0.0 {
                                    for assignment in &assignments {
                                        let uid = client
                                            .as_ref()
                                            .and_then(|c| c.get_uid_for_hotkey(&assignment.hotkey));

                                        if let Some(uid) = uid {
                                            let normalized = assignment.weight / total_weight;
                                            let scaled = normalized * emission_weight;
                                            *uid_weight_map.entry(uid).or_insert(0.0) += scaled;
                                            assigned_weight += scaled;
                                        } else {
                                            warn!(
                                                "Hotkey {} not found in metagraph, weight goes to burn",
                                                &assignment.hotkey[..std::cmp::min(16, assignment.hotkey.len())]
                                            );
                                        }
                                    }
                                }

                                let mut uids: Vec<u16> = Vec::new();
                                let mut vals: Vec<u16> = Vec::new();
                                for (uid, w) in &uid_weight_map {
                                    let weight_u16 = (w * 65535.0).round() as u16;
                                    if weight_u16 > 0 {
                                        uids.push(*uid);
                                        vals.push(weight_u16);
                                    }
                                }

                                // Remaining weight goes to burn (UID 0)
                                let burn_weight = 1.0 - assigned_weight;
                                if burn_weight > 0.001 {
                                    let burn_u16 = (burn_weight * 65535.0).round() as u16;
                                    if let Some(pos) = uids.iter().position(|&u| u == 0) {
                                        vals[pos] = vals[pos].saturating_add(burn_u16);
                                    } else {
                                        uids.push(0);
                                        vals.push(burn_u16);
                                    }
                                    info!("  Burn (UID 0): {:.4} = {}", burn_weight, burn_u16);
                                }

                                if !uids.is_empty() {
                                    // Max-upscale so largest = 65535 (matches convert_weights_and_uids_for_emit)
                                    let max_val = *vals.iter().max().unwrap() as f64;
                                    if max_val > 0.0 && max_val < 65535.0 {
                                        vals = vals
                                            .iter()
                                            .map(|v| {
                                                ((*v as f64 / max_val) * 65535.0).round() as u16
                                            })
                                            .collect();
                                    }

                                    info!(
                                        challenge_id = %cid,
                                        mechanism_id = mechanism_id,
                                        emission_weight = emission_weight,
                                        uid_count = uids.len(),
                                        "WASM weights collected (max-upscaled)"
                                    );
                                    debug!("  UIDs: {:?}, Weights: {:?}", uids, vals);
                                    mechanism_weights.push((*mechanism_id, uids, vals));
                                } else {
                                    warn!(
                                        "Challenge {} has weights but no UIDs resolved - sending 100% burn",
                                        cid
                                    );
                                    mechanism_weights.push((
                                        *mechanism_id,
                                        vec![0u16],
                                        vec![65535u16],
                                    ));
                                }
                            }
                            Ok(_) => {
                                info!("Challenge {} has no weights - sending 100% burn", cid);
                                mechanism_weights.push((*mechanism_id, vec![0u16], vec![65535u16]));
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to get weights for {} - sending 100% burn: {}",
                                    cid, e
                                );
                                mechanism_weights.push((*mechanism_id, vec![0u16], vec![65535u16]));
                            }
                        }
                    }
                }

                // Deduplicate by mechanism_id: pick the best (most UIDs) entry per
                // mechanism to avoid nonce conflicts from multiple submissions.
                // Burn-only entries (single UID 0) are used only if no real weights exist.
                let weights_to_submit: Vec<(u8, Vec<u16>, Vec<u16>)> = if mechanism_weights
                    .is_empty()
                {
                    let mechanism_id = {
                        let cs = chain_state.read();
                        cs.mechanism_configs.keys().next().copied().unwrap_or(0u8)
                    };
                    info!("No weights - submitting burn weights to UID 0");
                    vec![(mechanism_id, vec![0u16], vec![65535u16])]
                } else {
                    use std::collections::HashMap;
                    let mut best_per_mechanism: HashMap<u8, (Vec<u16>, Vec<u16>)> = HashMap::new();
                    for (mid, uids, vals) in &mechanism_weights {
                        let is_burn_only = uids.len() == 1 && uids[0] == 0;
                        let existing = best_per_mechanism.get(mid);
                        let replace = match existing {
                            None => true,
                            Some((ex_uids, _)) => {
                                let ex_is_burn = ex_uids.len() == 1 && ex_uids[0] == 0;
                                // Prefer real weights over burn; among real, prefer more UIDs
                                if is_burn_only && !ex_is_burn {
                                    false
                                } else if !is_burn_only && ex_is_burn {
                                    true
                                } else {
                                    uids.len() > ex_uids.len()
                                }
                            }
                        };
                        if replace {
                            best_per_mechanism.insert(*mid, (uids.clone(), vals.clone()));
                        }
                    }
                    let mut result = Vec::new();
                    for (mid, (uids, vals)) in best_per_mechanism {
                        info!(
                            "Selected weights for mechanism {}: {} UIDs",
                            mid,
                            uids.len()
                        );
                        debug!("  UIDs: {:?}, Weights: {:?}", uids, vals);
                        result.push((mid, uids, vals));
                    }
                    if result.is_empty() {
                        let mechanism_id = {
                            let cs = chain_state.read();
                            cs.mechanism_configs.keys().next().copied().unwrap_or(0u8)
                        };
                        vec![(mechanism_id, vec![0u16], vec![65535u16])]
                    } else {
                        result
                    }
                };

                // Fallback: if all weights are burn-only, try fetching from
                // the primary validator's RPC (chain.platform.network).
                let all_burn_only = weights_to_submit
                    .iter()
                    .all(|(_, uids, _)| uids.len() == 1 && uids[0] == 0);
                let weights_to_submit = if all_burn_only {
                    info!("All local weights are burn-only, attempting HTTP fallback from chain.platform.network");
                    match fetch_remote_weights().await {
                        Ok(remote) if !remote.is_empty() => {
                            info!(
                                "Fetched {} mechanism weight entries from remote",
                                remote.len()
                            );
                            remote
                        }
                        Ok(_) => {
                            warn!("Remote returned empty weights, using local burn-only");
                            weights_to_submit
                        }
                        Err(e) => {
                            warn!(
                                "Failed to fetch remote weights: {}, using local burn-only",
                                e
                            );
                            weights_to_submit
                        }
                    }
                } else {
                    weights_to_submit
                };

                // Store computed weights in chain state for the subnet_getWeights RPC
                {
                    let mut cs = chain_state.write();
                    cs.last_computed_weights = weights_to_submit.clone();
                }

                for (mechanism_id, uids, weights) in weights_to_submit {
                    info!(
                        "Submitting weights for mechanism {} ({} UIDs)",
                        mechanism_id,
                        uids.len()
                    );
                    match st
                        .set_mechanism_weights(
                            sig,
                            netuid,
                            mechanism_id,
                            &uids,
                            &weights,
                            version_key,
                            ExtrinsicWait::Finalized,
                        )
                        .await
                    {
                        Ok(resp) if resp.success => {
                            info!(
                                "Mechanism {} weights submitted: {:?}",
                                mechanism_id, resp.tx_hash
                            );
                            *last_weight_submission_epoch = epoch;
                        }
                        Ok(resp) => {
                            warn!("Mechanism {} issue: {}", mechanism_id, resp.message);
                        }
                        Err(e) => {
                            let err_str = format!("{}", e);
                            if err_str.contains("Priority is too low") || err_str.contains("1010") {
                                warn!(
                                    "Mechanism {}: transaction rejected ({}) - marking epoch as submitted to avoid retry loop",
                                    mechanism_id, err_str
                                );
                                *last_weight_submission_epoch = epoch;
                            } else {
                                error!(
                                    "Mechanism {} weight submission failed: {}",
                                    mechanism_id, e
                                );
                            }
                        }
                    }
                }
            } else {
                warn!("No Subtensor/signer - cannot submit weights");
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

        let network_policy = wasm_runtime_interface::NetworkPolicy::development();

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
/// Fetch pre-computed weights from the primary validator's RPC endpoint.
/// Returns Vec<(mechanism_id, uids, weights)> ready for submission.
async fn fetch_remote_weights() -> anyhow::Result<Vec<(u8, Vec<u16>, Vec<u16>)>> {
    let url = "https://chain.platform.network/rpc";
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "subnet_getWeights",
        "params": {},
        "id": 1
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let weights_arr = resp
        .get("result")
        .and_then(|r| r.get("weights"))
        .and_then(|w| w.as_array())
        .ok_or_else(|| anyhow::anyhow!("Invalid response: missing result.weights"))?;

    let mut result = Vec::new();
    for entry in weights_arr {
        let mechanism_id = entry
            .get("mechanismId")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;
        let entries = entry
            .get("entries")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow::anyhow!("Missing entries in weight entry"))?;

        let mut uids = Vec::new();
        let mut vals = Vec::new();
        for e in entries {
            let uid = e.get("uid").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let weight = e.get("weight").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            uids.push(uid);
            vals.push(weight);
        }

        if !uids.is_empty() {
            result.push((mechanism_id, uids, vals));
        }
    }

    Ok(result)
}

// Build trigger: 1771754356
