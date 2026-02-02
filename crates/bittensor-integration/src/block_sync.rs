//! Block synchronization with Bittensor
//!
//! Syncs platform blocks with Bittensor finalized blocks
//! to ensure epochs are aligned with on-chain state.

pub use bittensor_rs::blocks::{
    BlockEvent, BlockListener, BlockListenerConfig, EpochInfo, EpochPhase, EpochTransition,
};
use bittensor_rs::chain::BittensorClient;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{info, warn};

/// Events emitted by the block sync
#[derive(Debug, Clone)]
pub enum BlockSyncEvent {
    /// New block from Bittensor
    NewBlock {
        block_number: u64,
        epoch_info: EpochInfo,
    },
    /// Epoch transition on Bittensor
    EpochTransition {
        old_epoch: u64,
        new_epoch: u64,
        block: u64,
    },
    /// Phase changed (evaluation -> commit -> reveal)
    PhaseChange {
        block_number: u64,
        old_phase: EpochPhase,
        new_phase: EpochPhase,
        epoch: u64,
    },
    /// Time to commit weights
    CommitWindowOpen { epoch: u64, block: u64 },
    /// Time to reveal weights  
    RevealWindowOpen { epoch: u64, block: u64 },
    /// Connection lost (will retry)
    Disconnected(String),
    /// Reconnected
    Reconnected,
}

/// Block synchronizer configuration
#[derive(Debug, Clone)]
pub struct BlockSyncConfig {
    /// Subnet UID
    pub netuid: u16,
    /// Event channel capacity
    pub channel_capacity: usize,
}

impl Default for BlockSyncConfig {
    fn default() -> Self {
        Self {
            netuid: 1,
            channel_capacity: 100,
        }
    }
}

/// Synchronizes platform with Bittensor blocks
pub struct BlockSync {
    config: BlockSyncConfig,
    listener: Option<BlockListener>,
    client: Option<Arc<BittensorClient>>,
    running: Arc<RwLock<bool>>,
    event_tx: mpsc::Sender<BlockSyncEvent>,
    event_rx: Option<mpsc::Receiver<BlockSyncEvent>>,
    current_block: Arc<RwLock<u64>>,
    current_epoch: Arc<RwLock<u64>>,
    current_phase: Arc<RwLock<EpochPhase>>,
    tempo: Arc<RwLock<u64>>,
}

impl BlockSync {
    /// Create a new block sync
    pub fn new(config: BlockSyncConfig) -> Self {
        let (event_tx, event_rx) = mpsc::channel(config.channel_capacity);

        Self {
            config,
            listener: None,
            client: None,
            running: Arc::new(RwLock::new(false)),
            event_tx,
            event_rx: Some(event_rx),
            current_block: Arc::new(RwLock::new(0)),
            current_epoch: Arc::new(RwLock::new(0)),
            current_phase: Arc::new(RwLock::new(EpochPhase::Evaluation)),
            tempo: Arc::new(RwLock::new(360)), // default Bittensor tempo
        }
    }

    /// Take the event receiver (can only be called once)
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<BlockSyncEvent>> {
        self.event_rx.take()
    }

    /// Connect to Bittensor and start syncing blocks
    pub async fn connect(&mut self, client: Arc<BittensorClient>) -> anyhow::Result<()> {
        let listener_config = BlockListenerConfig {
            netuid: self.config.netuid,
            channel_capacity: self.config.channel_capacity,
            auto_reconnect: true,
            reconnect_delay_ms: 5000,
        };

        let listener = BlockListener::new(listener_config);
        listener.init(&client).await?;

        // Get initial block info
        let epoch_info = listener.current_epoch_info(&client).await?;
        *self.current_block.write().await = epoch_info.current_block;
        *self.current_epoch.write().await = epoch_info.epoch_number;
        *self.current_phase.write().await = epoch_info.phase;
        *self.tempo.write().await = epoch_info.tempo;

        let secs_remaining = epoch_info.blocks_remaining * 12;
        let mins = secs_remaining / 60;
        let secs = secs_remaining % 60;
        info!(
            "BlockSync connected: block={}, epoch={}, phase={}, tempo={}",
            epoch_info.current_block, epoch_info.epoch_number, epoch_info.phase, epoch_info.tempo
        );
        info!(
            "Next epoch in {} blocks (~{}m{}s)",
            epoch_info.blocks_remaining, mins, secs
        );

        self.listener = Some(listener);
        self.client = Some(client);

        Ok(())
    }

    /// Get the Bittensor tempo (blocks per epoch)
    pub async fn tempo(&self) -> u64 {
        *self.tempo.read().await
    }

    /// Start the block sync loop
    pub async fn start(&self) -> anyhow::Result<()> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not connected - call connect() first"))?;

        let client = self
            .client
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not connected"))?;

        // Check if already running
        {
            let mut running = self.running.write().await;
            if *running {
                return Ok(());
            }
            *running = true;
        }

        // Subscribe to block events
        let mut block_rx = listener.subscribe();
        let event_tx = self.event_tx.clone();
        let running = self.running.clone();
        let current_block = self.current_block.clone();
        let current_epoch = self.current_epoch.clone();
        let current_phase = self.current_phase.clone();

        // Start the listener
        listener.start(client.clone()).await?;

        // Process events in background
        tokio::spawn(async move {
            let mut was_disconnected = false;

            loop {
                if !*running.read().await {
                    break;
                }

                match block_rx.recv().await {
                    Ok(event) => {
                        let should_break = BlockSync::handle_block_event(
                            event,
                            &event_tx,
                            &current_block,
                            &current_epoch,
                            &current_phase,
                            &mut was_disconnected,
                        )
                        .await;

                        if should_break {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Block sync lagged by {} events", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("Block event channel closed");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    async fn handle_block_event(
        event: BlockEvent,
        event_tx: &mpsc::Sender<BlockSyncEvent>,
        current_block: &Arc<RwLock<u64>>,
        current_epoch: &Arc<RwLock<u64>>,
        current_phase: &Arc<RwLock<EpochPhase>>,
        was_disconnected: &mut bool,
    ) -> bool {
        match event {
            BlockEvent::NewBlock {
                block_number,
                epoch_info,
            } => {
                *current_block.write().await = block_number;
                *current_epoch.write().await = epoch_info.epoch_number;
                *current_phase.write().await = epoch_info.phase;

                if let Err(e) = event_tx
                    .send(BlockSyncEvent::NewBlock {
                        block_number,
                        epoch_info,
                    })
                    .await
                {
                    warn!("Failed to send NewBlock event: {}", e);
                }

                if *was_disconnected {
                    *was_disconnected = false;
                    if let Err(e) = event_tx.send(BlockSyncEvent::Reconnected).await {
                        warn!("Failed to send Reconnected event: {}", e);
                    }
                }
            }
            BlockEvent::EpochTransition(EpochTransition::NewEpoch {
                old_epoch,
                new_epoch,
                block,
            }) => {
                info!(
                    "Bittensor epoch transition: {} -> {} at block {}",
                    old_epoch, new_epoch, block
                );
                if let Err(e) = event_tx
                    .send(BlockSyncEvent::EpochTransition {
                        old_epoch,
                        new_epoch,
                        block,
                    })
                    .await
                {
                    warn!("Failed to send EpochTransition event: {}", e);
                }
            }
            BlockEvent::PhaseChange {
                block_number,
                old_phase,
                new_phase,
                epoch,
            } => {
                info!(
                    "Bittensor phase change: {} -> {} at block {} (epoch {})",
                    old_phase, new_phase, block_number, epoch
                );

                if let Err(e) = event_tx
                    .send(BlockSyncEvent::PhaseChange {
                        block_number,
                        old_phase,
                        new_phase,
                        epoch,
                    })
                    .await
                {
                    warn!("Failed to send PhaseChange event: {}", e);
                }

                match new_phase {
                    EpochPhase::CommitWindow => {
                        if let Err(e) = event_tx
                            .send(BlockSyncEvent::CommitWindowOpen {
                                epoch,
                                block: block_number,
                            })
                            .await
                        {
                            warn!("Failed to send CommitWindowOpen event: {}", e);
                        }
                    }
                    EpochPhase::RevealWindow => {
                        if let Err(e) = event_tx
                            .send(BlockSyncEvent::RevealWindowOpen {
                                epoch,
                                block: block_number,
                            })
                            .await
                        {
                            warn!("Failed to send RevealWindowOpen event: {}", e);
                        }
                    }
                    _ => {}
                }
            }
            BlockEvent::ConnectionError(e) => {
                warn!("Bittensor connection error: {}", e);
                *was_disconnected = true;
                if let Err(send_err) = event_tx.send(BlockSyncEvent::Disconnected(e)).await {
                    warn!("Failed to send Disconnected event: {}", send_err);
                }
            }
            BlockEvent::Stopped => {
                info!("Block listener stopped");
                return true;
            }
        }

        false
    }

    /// Stop the block sync
    pub async fn stop(&self) {
        *self.running.write().await = false;
        if let Some(ref listener) = self.listener {
            listener.stop().await;
        }
    }

    /// Get current Bittensor block number
    pub async fn current_block(&self) -> u64 {
        *self.current_block.read().await
    }

    /// Get current Bittensor epoch number
    pub async fn current_epoch(&self) -> u64 {
        *self.current_epoch.read().await
    }

    /// Get current Bittensor epoch phase
    pub async fn current_phase(&self) -> EpochPhase {
        *self.current_phase.read().await
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.client.is_some()
    }

    /// Check if running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

// Re-export types from bittensor_rs for convenience (already imported at top)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_sync_config_default() {
        let config = BlockSyncConfig::default();
        assert_eq!(config.netuid, 1);
        assert_eq!(config.channel_capacity, 100);
    }

    #[tokio::test]
    async fn test_block_sync_initial_state() {
        let mut sync = BlockSync::new(BlockSyncConfig {
            netuid: 42,
            channel_capacity: 8,
        });

        assert!(!sync.is_connected());
        assert!(!sync.is_running().await);
        assert_eq!(sync.current_block().await, 0);
        assert_eq!(sync.current_epoch().await, 0);
        assert!(matches!(sync.current_phase().await, EpochPhase::Evaluation));

        let first_receiver = sync.take_event_receiver();
        assert!(first_receiver.is_some());
        assert!(sync.take_event_receiver().is_none());
    }

    fn sample_epoch_info(block: u64, epoch: u64, phase: EpochPhase) -> EpochInfo {
        EpochInfo {
            current_block: block,
            tempo: 360,
            epoch_start_block: epoch * 360,
            next_epoch_start_block: epoch * 360 + 360,
            blocks_remaining: 10,
            epoch_number: epoch,
            phase,
            commit_reveal_enabled: true,
            reveal_period_epochs: 1,
        }
    }

    #[tokio::test]
    async fn test_handle_block_event_new_block_emits_reconnect() {
        let (tx, mut rx) = mpsc::channel(4);
        let current_block = Arc::new(RwLock::new(0));
        let current_epoch = Arc::new(RwLock::new(0));
        let current_phase = Arc::new(RwLock::new(EpochPhase::Evaluation));
        let mut was_disconnected = true;

        let epoch_info = sample_epoch_info(123, 9, EpochPhase::CommitWindow);

        let should_break = BlockSync::handle_block_event(
            BlockEvent::NewBlock {
                block_number: 123,
                epoch_info: epoch_info.clone(),
            },
            &tx,
            &current_block,
            &current_epoch,
            &current_phase,
            &mut was_disconnected,
        )
        .await;

        assert!(!should_break);
        assert_eq!(*current_block.read().await, 123);
        assert_eq!(*current_epoch.read().await, 9);
        assert!(matches!(
            *current_phase.read().await,
            EpochPhase::CommitWindow
        ));

        let first = rx.recv().await.unwrap();
        assert!(matches!(first, BlockSyncEvent::NewBlock { .. }));
        let second = rx.recv().await.unwrap();
        assert!(matches!(second, BlockSyncEvent::Reconnected));
        assert!(!was_disconnected);
    }

    #[tokio::test]
    async fn test_handle_block_event_phase_change_emits_windows() {
        let (tx, mut rx) = mpsc::channel(4);
        let current_block = Arc::new(RwLock::new(0));
        let current_epoch = Arc::new(RwLock::new(0));
        let current_phase = Arc::new(RwLock::new(EpochPhase::Evaluation));
        let mut was_disconnected = false;

        let should_break = BlockSync::handle_block_event(
            BlockEvent::PhaseChange {
                block_number: 200,
                old_phase: EpochPhase::Evaluation,
                new_phase: EpochPhase::CommitWindow,
                epoch: 7,
            },
            &tx,
            &current_block,
            &current_epoch,
            &current_phase,
            &mut was_disconnected,
        )
        .await;

        assert!(!should_break);
        assert_eq!(*current_epoch.read().await, 0); // unchanged for phase events
        assert!(matches!(
            *current_phase.read().await,
            EpochPhase::Evaluation
        ));

        let phase_event = rx.recv().await.unwrap();
        assert!(matches!(phase_event, BlockSyncEvent::PhaseChange { .. }));
        let window_event = rx.recv().await.unwrap();
        assert!(matches!(
            window_event,
            BlockSyncEvent::CommitWindowOpen { .. }
        ));
    }

    #[tokio::test]
    async fn test_handle_block_event_stopped_breaks_loop() {
        let (tx, mut rx) = mpsc::channel(1);
        let current_block = Arc::new(RwLock::new(0));
        let current_epoch = Arc::new(RwLock::new(0));
        let current_phase = Arc::new(RwLock::new(EpochPhase::Evaluation));
        let mut was_disconnected = false;

        let should_break = BlockSync::handle_block_event(
            BlockEvent::Stopped,
            &tx,
            &current_block,
            &current_epoch,
            &current_phase,
            &mut was_disconnected,
        )
        .await;

        assert!(should_break);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_handle_block_event_epoch_transition_emits_event() {
        let (tx, mut rx) = mpsc::channel(1);
        let current_block = Arc::new(RwLock::new(0));
        let current_epoch = Arc::new(RwLock::new(0));
        let current_phase = Arc::new(RwLock::new(EpochPhase::Evaluation));
        let mut was_disconnected = false;

        BlockSync::handle_block_event(
            BlockEvent::EpochTransition(EpochTransition::NewEpoch {
                old_epoch: 5,
                new_epoch: 6,
                block: 1234,
            }),
            &tx,
            &current_block,
            &current_epoch,
            &current_phase,
            &mut was_disconnected,
        )
        .await;

        let evt = rx.recv().await.unwrap();
        assert!(matches!(
            evt,
            BlockSyncEvent::EpochTransition {
                old_epoch: 5,
                new_epoch: 6,
                block: 1234
            }
        ));
    }

    #[tokio::test]
    async fn test_handle_block_event_reveal_window_emits_open_event() {
        let (tx, mut rx) = mpsc::channel(3);
        let current_block = Arc::new(RwLock::new(0));
        let current_epoch = Arc::new(RwLock::new(0));
        let current_phase = Arc::new(RwLock::new(EpochPhase::Evaluation));
        let mut was_disconnected = false;

        BlockSync::handle_block_event(
            BlockEvent::PhaseChange {
                block_number: 500,
                old_phase: EpochPhase::CommitWindow,
                new_phase: EpochPhase::RevealWindow,
                epoch: 11,
            },
            &tx,
            &current_block,
            &current_epoch,
            &current_phase,
            &mut was_disconnected,
        )
        .await;

        let phase_event = rx.recv().await.unwrap();
        assert!(matches!(phase_event, BlockSyncEvent::PhaseChange { .. }));
        let reveal_event = rx.recv().await.unwrap();
        assert!(matches!(
            reveal_event,
            BlockSyncEvent::RevealWindowOpen {
                epoch: 11,
                block: 500
            }
        ));
    }

    #[tokio::test]
    async fn test_handle_block_event_connection_error_sets_flag() {
        let (tx, mut rx) = mpsc::channel(1);
        let current_block = Arc::new(RwLock::new(0));
        let current_epoch = Arc::new(RwLock::new(0));
        let current_phase = Arc::new(RwLock::new(EpochPhase::Evaluation));
        let mut was_disconnected = false;

        let should_break = BlockSync::handle_block_event(
            BlockEvent::ConnectionError("network wobble".into()),
            &tx,
            &current_block,
            &current_epoch,
            &current_phase,
            &mut was_disconnected,
        )
        .await;

        assert!(!should_break);
        assert!(was_disconnected);
        let evt = rx.recv().await.unwrap();
        assert!(matches!(evt, BlockSyncEvent::Disconnected(_)));
    }
}
