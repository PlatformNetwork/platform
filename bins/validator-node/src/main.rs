//! Validator Node - Centralized Architecture
//!
//! All communication via platform-server (chain.platform.network).
//! No P2P networking. Weights submitted via Subtensor (handles CRv4 automatically).

use anyhow::Result;
use challenge_orchestrator::{ChallengeOrchestrator, OrchestratorConfig};
use clap::Parser;
use parking_lot::RwLock;
use platform_bittensor::{
    signer_from_seed, sync_metagraph, BittensorClient, BittensorSigner, BlockSync, BlockSyncConfig,
    BlockSyncEvent, ExtrinsicWait, Subtensor,
};
use platform_core::{production_sudo_key, ChainState, Keypair, NetworkConfig};
use platform_rpc::{RpcConfig, RpcServer};
use platform_storage::Storage;
use platform_subnet_manager::BanList;
use secure_container_runtime::{run_ws_server, ContainerBroker, SecurityPolicy, WsConfig};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

// ==================== Platform Server Client ====================

#[derive(Clone)]
pub struct PlatformServerClient {
    base_url: String,
    client: reqwest::Client,
}

impl PlatformServerClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("HTTP client"),
        }
    }

    pub async fn health(&self) -> bool {
        self.client
            .get(format!("{}/health", self.base_url))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    pub async fn list_challenges(&self) -> Result<Vec<ChallengeInfo>> {
        Ok(self
            .client
            .get(format!("{}/api/v1/challenges", self.base_url))
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn get_weights(&self, challenge_id: &str, epoch: u64) -> Result<Vec<(u16, u16)>> {
        let resp: serde_json::Value = self
            .client
            .get(format!(
                "{}/api/v1/challenges/{}/get_weights?epoch={}",
                self.base_url, challenge_id, epoch
            ))
            .send()
            .await?
            .json()
            .await?;

        Ok(resp
            .get("weights")
            .and_then(|w| w.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|w| {
                        Some((
                            w.get("uid")?.as_u64()? as u16,
                            w.get("weight")?.as_u64()? as u16,
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default())
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ChallengeInfo {
    pub id: String,
    #[allow(dead_code)]
    pub name: String,
    pub mechanism_id: i32,
    #[allow(dead_code)]
    pub emission_weight: f64,
    pub is_healthy: bool,
}

// ==================== CLI ====================

#[derive(Parser, Debug)]
#[command(name = "validator-node")]
#[command(about = "Platform Validator - Centralized Architecture")]
struct Args {
    /// Secret key (hex or mnemonic)
    #[arg(short = 'k', long, env = "VALIDATOR_SECRET_KEY")]
    secret_key: Option<String>,

    /// Data directory
    #[arg(short, long, default_value = "./data")]
    data_dir: PathBuf,

    /// Stake in TAO (for --no-bittensor mode)
    #[arg(long, default_value = "1000")]
    stake: f64,

    #[arg(
        long,
        env = "SUBTENSOR_ENDPOINT",
        default_value = "wss://entrypoint-finney.opentensor.ai:443"
    )]
    subtensor_endpoint: String,

    #[arg(long, env = "NETUID", default_value = "100")]
    netuid: u16,

    #[arg(long)]
    no_bittensor: bool,

    #[arg(long, default_value = "8080")]
    rpc_port: u16,

    #[arg(long, default_value = "0.0.0.0")]
    rpc_addr: String,

    #[arg(long, default_value = "true")]
    docker_challenges: bool,

    #[arg(long, env = "BROKER_WS_PORT", default_value = "8090")]
    broker_port: u16,

    #[arg(long, env = "BROKER_JWT_SECRET")]
    broker_jwt_secret: Option<String>,

    #[arg(
        long,
        env = "PLATFORM_SERVER_URL",
        default_value = "https://chain.platform.network"
    )]
    platform_server: String,

    #[arg(long, env = "VERSION_KEY", default_value = "1")]
    version_key: u64,
}

// ==================== Main ====================

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,validator_node=debug".into()),
        )
        .init();

    let args = Args::parse();
    info!("Starting validator (centralized mode)");

    // Keypair
    let keypair = load_keypair(&args)?;
    info!("Validator: {}", keypair.ss58_address());

    // Data dir
    std::fs::create_dir_all(&args.data_dir)?;
    let data_dir = std::fs::canonicalize(&args.data_dir)?;

    // Storage
    let storage = Storage::open(data_dir.join("validator.db"))?;
    let _storage = Arc::new(storage);

    // Chain state
    let chain_state = Arc::new(RwLock::new(ChainState::new(
        production_sudo_key(),
        NetworkConfig::default(),
    )));
    let bans = Arc::new(RwLock::new(BanList::default()));

    // Platform server
    let platform_client = Arc::new(PlatformServerClient::new(&args.platform_server));
    info!("Platform server: {}", args.platform_server);

    if platform_client.health().await {
        info!("Platform server: connected");
    } else {
        warn!("Platform server: not reachable (will retry)");
    }

    // List challenges
    match platform_client.list_challenges().await {
        Ok(c) if !c.is_empty() => {
            info!("Challenges:");
            for ch in &c {
                info!(
                    "  - {} (mechanism={}, healthy={})",
                    ch.id, ch.mechanism_id, ch.is_healthy
                );
            }
        }
        Ok(_) => info!("No challenges yet"),
        Err(e) => warn!("Failed to list challenges: {}", e),
    }

    // Container broker
    info!("Container broker on port {}...", args.broker_port);
    let broker = Arc::new(ContainerBroker::with_policy(SecurityPolicy::default()).await?);
    let ws_config = WsConfig {
        bind_addr: format!("0.0.0.0:{}", args.broker_port),
        jwt_secret: args.broker_jwt_secret.clone(),
        allowed_challenges: vec![],
        max_connections_per_challenge: 10,
    };
    let broker_clone = broker.clone();
    tokio::spawn(async move {
        if let Err(e) = run_ws_server(broker_clone, ws_config).await {
            error!("Broker error: {}", e);
        }
    });

    // Challenge orchestrator
    let _orchestrator = if args.docker_challenges {
        match ChallengeOrchestrator::new(OrchestratorConfig {
            network_name: "platform-network".to_string(),
            health_check_interval: Duration::from_secs(30),
            stop_timeout: Duration::from_secs(30),
            registry: None,
        })
        .await
        {
            Ok(o) => Some(Arc::new(o)),
            Err(e) => {
                warn!("Docker orchestrator failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    // RPC server
    let addr: SocketAddr = format!("{}:{}", args.rpc_addr, args.rpc_port).parse()?;
    let rpc_server = RpcServer::new(
        RpcConfig {
            addr,
            netuid: args.netuid,
            name: "Platform".to_string(),
            min_stake: (args.stake * 1e9) as u64,
            cors_enabled: true,
        },
        chain_state.clone(),
        bans.clone(),
    );
    let _rpc = rpc_server.spawn();
    info!("RPC: http://{}:{}", args.rpc_addr, args.rpc_port);

    // Bittensor setup
    let subtensor: Option<Arc<Subtensor>>;
    let subtensor_signer: Option<Arc<BittensorSigner>>;
    let mut block_rx: Option<tokio::sync::mpsc::Receiver<BlockSyncEvent>> = None;

    if !args.no_bittensor {
        info!(
            "Bittensor: {} (netuid={})",
            args.subtensor_endpoint, args.netuid
        );

        // Create Subtensor with persistence for automatic commit-reveal handling
        let state_path = data_dir.join("subtensor_state.json");
        match Subtensor::with_persistence(&args.subtensor_endpoint, state_path.clone()).await {
            Ok(st) => {
                info!("Subtensor connected with persistence at {:?}", state_path);

                // Create signer
                let secret = args.secret_key.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("VALIDATOR_SECRET_KEY required for Bittensor")
                })?;

                match signer_from_seed(secret) {
                    Ok(signer) => {
                        info!("Bittensor hotkey: {}", signer.account_id());
                        subtensor_signer = Some(Arc::new(signer));
                    }
                    Err(e) => {
                        error!("Failed to create signer: {}", e);
                        subtensor_signer = None;
                    }
                }

                subtensor = Some(Arc::new(st));

                // Sync metagraph
                let client = BittensorClient::new(&args.subtensor_endpoint).await?;
                match sync_metagraph(&client, args.netuid).await {
                    Ok(mg) => info!("Metagraph: {} neurons", mg.n),
                    Err(e) => warn!("Metagraph sync failed: {}", e),
                }

                // Block sync
                let mut sync = BlockSync::new(BlockSyncConfig {
                    netuid: args.netuid,
                    ..Default::default()
                });
                let rx = sync.take_event_receiver();

                let client = Arc::new(client);
                if let Err(e) = sync.connect(client).await {
                    warn!("Block sync connect failed: {}", e);
                } else {
                    tokio::spawn(async move {
                        if let Err(e) = sync.start().await {
                            error!("Block sync error: {}", e);
                        }
                    });
                    block_rx = rx;
                    info!("Block sync: started");
                }
            }
            Err(e) => {
                error!("Subtensor connection failed: {}", e);
                subtensor = None;
                subtensor_signer = None;
            }
        }
    } else {
        info!("Bittensor: disabled");
        subtensor = None;
        subtensor_signer = None;
    }

    info!("Validator running. Ctrl+C to stop.");

    let netuid = args.netuid;
    let version_key = args.version_key;
    let mut interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        tokio::select! {
            Some(event) = async {
                match block_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                handle_block_event(
                    event,
                    &platform_client,
                    &subtensor,
                    &subtensor_signer,
                    netuid,
                    version_key,
                ).await;
            }

            _ = interval.tick() => {
                debug!("Heartbeat");
            }

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

async fn handle_block_event(
    event: BlockSyncEvent,
    platform_client: &Arc<PlatformServerClient>,
    subtensor: &Option<Arc<Subtensor>>,
    signer: &Option<Arc<BittensorSigner>>,
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
            info!("Epoch: {} -> {} (block {})", old_epoch, new_epoch, block);
        }

        BlockSyncEvent::CommitWindowOpen { epoch, block } => {
            info!("=== COMMIT WINDOW: epoch {} block {} ===", epoch, block);

            // Submit weights via Subtensor (handles CRv4/commit-reveal automatically)
            if let (Some(st), Some(sig)) = (subtensor.as_ref(), signer.as_ref()) {
                // Fetch weights from platform-server
                let mechanism_weights = match platform_client.list_challenges().await {
                    Ok(challenges) if !challenges.is_empty() => {
                        let mut weights = Vec::new();

                        for challenge in challenges.iter().filter(|c| c.is_healthy) {
                            match platform_client.get_weights(&challenge.id, epoch).await {
                                Ok(w) if !w.is_empty() => {
                                    let uids: Vec<u16> = w.iter().map(|(u, _)| *u).collect();
                                    let vals: Vec<u16> = w.iter().map(|(_, v)| *v).collect();

                                    info!(
                                        "Challenge {} (mech {}): {} weights",
                                        challenge.id,
                                        challenge.mechanism_id,
                                        uids.len()
                                    );

                                    weights.push((challenge.mechanism_id as u8, uids, vals));
                                }
                                Ok(_) => debug!("Challenge {} has no weights", challenge.id),
                                Err(e) => {
                                    warn!("Failed to get weights for {}: {}", challenge.id, e)
                                }
                            }
                        }

                        weights
                    }
                    Ok(_) => {
                        info!("No challenges on platform-server");
                        vec![]
                    }
                    Err(e) => {
                        warn!("Failed to list challenges: {}", e);
                        vec![]
                    }
                };

                // Submit weights (or burn weights if none)
                let weights_to_submit = if mechanism_weights.is_empty() {
                    info!("No weights - submitting burn weights to UID 0");
                    vec![(0u8, vec![0u16], vec![65535u16])]
                } else {
                    mechanism_weights
                };

                // Submit each mechanism via Subtensor (handles CRv4 automatically)
                for (mechanism_id, uids, weights) in weights_to_submit {
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
                        }
                        Ok(resp) => {
                            warn!("Mechanism {} issue: {}", mechanism_id, resp.message);
                        }
                        Err(e) => {
                            error!("Mechanism {} failed: {}", mechanism_id, e);
                        }
                    }
                }
            } else {
                warn!("No Subtensor/signer - cannot submit weights");
            }
        }

        BlockSyncEvent::RevealWindowOpen { epoch, block } => {
            info!("=== REVEAL WINDOW: epoch {} block {} ===", epoch, block);

            // With CRv4, reveals are automatic via DRAND
            // For older versions, Subtensor handles reveals internally
            if let (Some(st), Some(sig)) = (subtensor.as_ref(), signer.as_ref()) {
                if st.has_pending_commits().await {
                    info!("Revealing pending commits...");
                    match st.reveal_all_pending(sig, ExtrinsicWait::Finalized).await {
                        Ok(results) => {
                            for resp in results {
                                if resp.success {
                                    info!("Revealed: {:?}", resp.tx_hash);
                                }
                            }
                        }
                        Err(e) => error!("Reveal failed: {}", e),
                    }
                }
            }
        }

        BlockSyncEvent::PhaseChange {
            old_phase,
            new_phase,
            ..
        } => {
            debug!("Phase: {:?} -> {:?}", old_phase, new_phase);
        }

        BlockSyncEvent::Disconnected(e) => warn!("Bittensor disconnected: {}", e),
        BlockSyncEvent::Reconnected => info!("Bittensor reconnected"),
    }
}
