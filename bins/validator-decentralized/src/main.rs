//! Decentralized Validator Node
//!
//! Fully P2P validator without centralized platform-server.
//! Uses libp2p for gossipsub consensus and Kademlia DHT for storage.
//! Submits weights to Bittensor at epoch boundaries.

use anyhow::Result;
use bittensor_rs::chain::{signer_from_seed, BittensorSigner, ExtrinsicWait};
use clap::Parser;
use parking_lot::RwLock;
use platform_bittensor::{
    sync_metagraph, BittensorClient, BlockSync, BlockSyncConfig, BlockSyncEvent, Metagraph,
    Subtensor, SubtensorClient,
};
use platform_core::{Hotkey, Keypair, SUDO_KEY_SS58};
use platform_distributed_storage::{
    DistributedStoreExt, LocalStorage, LocalStorageBuilder, StorageKey,
};
use platform_p2p_consensus::{
    ChainState, ConsensusEngine, NetworkEvent, P2PConfig, P2PMessage, P2PNetwork, StateManager,
    ValidatorRecord, ValidatorSet,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Storage key for persisted chain state
const STATE_STORAGE_KEY: &str = "chain_state";

// ==================== CLI ====================

#[derive(Parser, Debug)]
#[command(name = "validator-decentralized")]
#[command(about = "Platform Validator - Decentralized P2P Architecture")]
struct Args {
    /// Secret key (hex or mnemonic)
    #[arg(short = 'k', long, env = "VALIDATOR_SECRET_KEY")]
    secret_key: Option<String>,

    /// Data directory
    #[arg(short, long, default_value = "./data")]
    data_dir: PathBuf,

    /// P2P listen address
    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/9000")]
    listen_addr: String,

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

    /// Docker challenges support
    #[arg(long, default_value = "true")]
    docker_challenges: bool,
}

// ==================== Main ====================

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "info,validator_decentralized=debug,platform_p2p_consensus=debug".into()
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

    // Initialize P2P network config
    let p2p_config = P2PConfig::default()
        .with_listen_addr(&args.listen_addr)
        .with_bootstrap_peers(args.bootstrap.clone())
        .with_netuid(args.netuid)
        .with_min_stake(1_000_000_000_000); // 1000 TAO

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
    } else {
        info!("Bittensor disabled");
        subtensor = None;
        subtensor_signer = None;
        subtensor_client = None;
        bittensor_client_for_metagraph = None;
    }

    info!("Decentralized validator running. Press Ctrl+C to stop.");

    let netuid = args.netuid;
    let version_key = args.version_key;
    let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(30));
    let mut metagraph_interval = tokio::time::interval(Duration::from_secs(300));
    let mut stale_check_interval = tokio::time::interval(Duration::from_secs(60));
    let mut state_persist_interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        tokio::select! {
            // P2P network events
            Some(event) = event_rx.recv() => {
                handle_network_event(
                    event,
                    &consensus,
                    &validator_set,
                    &state_manager,
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
                ).await;
            }

            // Heartbeat
            _ = heartbeat_interval.tick() => {
                let state_hash = state_manager.state_hash();
                let sequence = state_manager.sequence();
                debug!("Heartbeat: sequence={}, state_hash={}", sequence, hex::encode(&state_hash[..8]));
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

            // Ctrl+C
            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down...");
                break;
            }
        }
    }

    info!("Stopped.");
    Ok(())
}

fn load_keypair(args: &Args) -> Result<Keypair> {
    let secret = args
        .secret_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("VALIDATOR_SECRET_KEY required"))?
        .trim();

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
    for (_uid, neuron) in &metagraph.neurons {
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
    _state_manager: &Arc<StateManager>,
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
            _ => {
                debug!("Unhandled P2P message type");
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
) {
    match event {
        BlockSyncEvent::NewBlock { block_number, .. } => {
            debug!("Block {}", block_number);
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
                        info!("No weights for epoch {} - submitting burn weights", epoch);
                        // Submit burn weights (uid 0 with max weight)
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
