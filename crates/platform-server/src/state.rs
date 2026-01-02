//! Application state

use crate::challenge_proxy::ChallengeProxy;
use crate::db::DbPool;
use crate::models::{AuthSession, TaskLease, WsEvent};
use crate::orchestration::ChallengeManager;
use crate::websocket::events::EventBroadcaster;
use dashmap::DashMap;
use parking_lot::RwLock;
use platform_bittensor::Metagraph;
use std::sync::Arc;

pub struct AppState {
    pub db: DbPool,
    pub challenge_id: Option<String>,
    pub sessions: DashMap<String, AuthSession>,
    pub broadcaster: Arc<EventBroadcaster>,
    pub owner_hotkey: Option<String>,
    pub challenge_proxy: Option<Arc<ChallengeProxy>>,
    /// Dynamic challenge manager
    pub challenge_manager: Option<Arc<ChallengeManager>>,
    /// Active task leases (task_id -> lease info)
    pub task_leases: DashMap<String, TaskLease>,
    /// Metagraph for validator stake lookups
    pub metagraph: RwLock<Option<Metagraph>>,
}

impl AppState {
    /// Legacy constructor for single challenge mode
    pub fn new(
        db: DbPool,
        challenge_id: String,
        owner_hotkey: Option<String>,
        challenge_proxy: Arc<ChallengeProxy>,
    ) -> Self {
        Self {
            db,
            challenge_id: Some(challenge_id),
            sessions: DashMap::new(),
            broadcaster: Arc::new(EventBroadcaster::new(1000)),
            owner_hotkey,
            challenge_proxy: Some(challenge_proxy),
            challenge_manager: None,
            task_leases: DashMap::new(),
            metagraph: RwLock::new(None),
        }
    }

    /// New constructor for dynamic orchestration mode
    pub fn new_dynamic(
        db: DbPool,
        owner_hotkey: Option<String>,
        challenge_manager: Option<Arc<ChallengeManager>>,
        metagraph: Option<Metagraph>,
    ) -> Self {
        Self {
            db,
            challenge_id: None,
            sessions: DashMap::new(),
            broadcaster: Arc::new(EventBroadcaster::new(1000)),
            owner_hotkey,
            challenge_proxy: None,
            challenge_manager,
            task_leases: DashMap::new(),
            metagraph: RwLock::new(metagraph),
        }
    }

    /// Get validator stake from metagraph (returns 0 if not found)
    pub fn get_validator_stake(&self, hotkey: &str) -> u64 {
        use sp_core::crypto::Ss58Codec;
        let mg = self.metagraph.read();
        if let Some(ref metagraph) = *mg {
            for (_uid, neuron) in &metagraph.neurons {
                if neuron.hotkey.to_ss58check() == hotkey {
                    // Stake is u128, convert to u64 (saturating)
                    return neuron.stake.min(u64::MAX as u128) as u64;
                }
            }
        }
        0
    }

    /// Update metagraph
    pub fn set_metagraph(&self, metagraph: Metagraph) {
        *self.metagraph.write() = Some(metagraph);
    }

    pub async fn broadcast_event(&self, event: WsEvent) {
        self.broadcaster.broadcast(event);
    }

    pub fn is_owner(&self, hotkey: &str) -> bool {
        self.owner_hotkey
            .as_ref()
            .map(|o| o == hotkey)
            .unwrap_or(false)
    }
}
