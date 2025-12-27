//! Validator Node - Centralized Architecture
//!
//! All communication via platform-server (chain.platform.network).
//! No P2P networking.

use anyhow::Result;
use challenge_orchestrator::{ChallengeOrchestrator, OrchestratorConfig};
use clap::Parser;
use parking_lot::RwLock;
use platform_bittensor::{
    signer_from_seed, sync_metagraph, BittensorClient, BittensorSigner, BlockSync, BlockSyncConfig,
    BlockSyncEvent,
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

/// HTTP client for platform-server
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

    // Bittensor
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

    // RPC
    #[arg(long, default_value = "8080")]
    rpc_port: u16,

    #[arg(long, default_value = "0.0.0.0")]
    rpc_addr: String,

    // Docker
    #[arg(long, default_value = "true")]
    docker_challenges: bool,

    // Container broker
    #[arg(long, env = "BROKER_WS_PORT", default_value = "8090")]
    broker_port: u16,

    #[arg(long, env = "BROKER_JWT_SECRET")]
    broker_jwt_secret: Option<String>,

    // Platform server (central)
    #[arg(
        long,
        env = "PLATFORM_SERVER_URL",
        default_value = "https://chain.platform.network"
    )]
    platform_server: String,
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
    info!("Starting validator (centralized mode - no P2P)");

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
    let platform_client = PlatformServerClient::new(&args.platform_server);
    info!("Platform server: {}", args.platform_server);

    if platform_client.health().await {
        info!("Platform server: connected");
    } else {
        warn!("Platform server: not reachable (will retry)");
    }

    // List challenges
    match platform_client.list_challenges().await {
        Ok(c) if !c.is_empty() => {
            info!("Challenges from platform-server:");
            for ch in &c {
                info!(
                    "  - {} (mechanism={}, healthy={})",
                    ch.id, ch.mechanism_id, ch.is_healthy
                );
            }
        }
        Ok(_) => info!("No challenges on platform-server yet"),
        Err(e) => warn!("Failed to list challenges: {}", e),
    }

    // Container broker
    info!("Container broker starting on port {}...", args.broker_port);
    if args.broker_jwt_secret.is_none() {
        warn!("Container broker: no JWT secret (dev mode)");
    }
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
    info!("Container broker: ws://0.0.0.0:{}", args.broker_port);

    // Challenge orchestrator
    let _orchestrator = if args.docker_challenges {
        info!("Docker orchestrator starting...");
        match ChallengeOrchestrator::new(OrchestratorConfig {
            network_name: "platform-challenges".to_string(),
            health_check_interval: Duration::from_secs(30),
            stop_timeout: Duration::from_secs(30),
            registry: None,
        })
        .await
        {
            Ok(o) => {
                info!("Docker orchestrator: ready");
                Some(Arc::new(o))
            }
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

    // Bittensor block sync
    let mut block_rx: Option<tokio::sync::mpsc::Receiver<BlockSyncEvent>> = None;
    if !args.no_bittensor {
        info!(
            "Bittensor: {} (netuid={})",
            args.subtensor_endpoint, args.netuid
        );

        let mut sync = BlockSync::new(BlockSyncConfig {
            netuid: args.netuid,
            ..Default::default()
        });
        let rx = sync.take_event_receiver();

        match BittensorClient::new(&args.subtensor_endpoint).await {
            Ok(client) => {
                let client = Arc::new(client);

                // Sync metagraph
                match sync_metagraph(&client, args.netuid).await {
                    Ok(mg) => info!("Metagraph: {} neurons", mg.n),
                    Err(e) => warn!("Metagraph sync failed: {}", e),
                }

                // Start block sync
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
            Err(e) => warn!("Bittensor connection failed: {}", e),
        }
    } else {
        info!("Bittensor: disabled (--no-bittensor)");
    }
    let _subtensor: Option<()> = None; // Placeholder

    // Signer for weight submission
    let signer = args
        .secret_key
        .as_ref()
        .and_then(|s| signer_from_seed(s).ok());

    info!("Validator running. Ctrl+C to stop.");

    // Main loop
    let mut interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        tokio::select! {
            Some(event) = async {
                match block_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                handle_block_event(event, &platform_client, &signer, args.netuid).await;
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
    client: &PlatformServerClient,
    _signer: &Option<BittensorSigner>,
    _netuid: u16,
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
            info!("Commit window: epoch {} block {}", epoch, block);

            // Fetch weights from platform-server
            match client.list_challenges().await {
                Ok(challenges) => {
                    for c in challenges.iter().filter(|c| c.is_healthy) {
                        match client.get_weights(&c.id, epoch).await {
                            Ok(w) if !w.is_empty() => {
                                info!(
                                    "Challenge {} weights: {} entries (mechanism {})",
                                    c.id,
                                    w.len(),
                                    c.mechanism_id
                                );
                                // TODO: Submit weights via WeightSubmitter
                            }
                            Ok(_) => debug!("Challenge {} has no weights", c.id),
                            Err(e) => warn!("Failed to get weights for {}: {}", c.id, e),
                        }
                    }
                }
                Err(e) => warn!("Platform-server error: {}", e),
            }
        }

        BlockSyncEvent::RevealWindowOpen { epoch, block } => {
            info!("Reveal window: epoch {} block {}", epoch, block);
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
