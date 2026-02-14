//! Validator Sync from Bittensor Metagraph
//!
//! Automatically syncs validators from the Bittensor blockchain.
//! Validators join/leave based on their registration status.
//! Stake is proportional to their Bittensor stake (power).

use crate::SubtensorClient;
use bittensor_rs::metagraph::Metagraph;
use parking_lot::RwLock;
use platform_core::{ChainState, Hotkey, Stake, ValidatorInfo};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, info};

/// Validator info from Bittensor metagraph
#[derive(Clone, Debug)]
pub struct MetagraphValidator {
    /// Hotkey (SS58 address converted to bytes)
    pub hotkey: Hotkey,
    /// UID on the subnet
    pub uid: u16,
    /// Stake in RAO (1 TAO = 1e9 RAO)
    pub stake: u64,
    /// Is validator active
    pub active: bool,
    /// Incentive score
    pub incentive: f64,
    /// Trust score
    pub trust: f64,
    /// Consensus score  
    pub consensus: f64,
}

/// Validator sync manager
pub struct ValidatorSync {
    /// Bittensor client (needs async lock for sync)
    client: Arc<TokioMutex<SubtensorClient>>,
    /// Netuid
    netuid: u16,
    /// Minimum stake to be considered a validator (in RAO)
    min_stake: u64,
    /// Last sync block
    last_sync_block: u64,
    /// Sync interval (blocks)
    sync_interval: u64,
}

impl ValidatorSync {
    /// Create a new validator sync manager
    pub fn new(client: Arc<TokioMutex<SubtensorClient>>, netuid: u16, min_stake: u64) -> Self {
        Self {
            client,
            netuid,
            min_stake,
            last_sync_block: 0,
            sync_interval: 100, // Sync every 100 blocks (~20 minutes)
        }
    }

    /// Set sync interval
    pub fn with_sync_interval(mut self, blocks: u64) -> Self {
        self.sync_interval = blocks;
        self
    }

    /// Check if sync is needed
    pub fn needs_sync(&self, current_block: u64) -> bool {
        current_block >= self.last_sync_block + self.sync_interval
    }

    /// Sync validators from Bittensor metagraph
    /// Pass banned_validators set to skip banned validators
    pub async fn sync(
        &mut self,
        state: &Arc<RwLock<ChainState>>,
        banned_validators: Option<&std::collections::HashSet<String>>,
    ) -> Result<SyncResult, SyncError> {
        info!(
            "Syncing validators from Bittensor metagraph (netuid={})",
            self.netuid
        );

        // Get metagraph data from Bittensor
        let mut client = self.client.lock().await;
        let metagraph = client
            .sync_metagraph()
            .await
            .map_err(|e| SyncError::ClientError(e.to_string()))?;

        // Parse validators and all hotkeys from metagraph
        let (bt_validators, all_hotkeys) = self.parse_metagraph(metagraph)?;
        drop(client); // Release lock

        // Update registered hotkeys in state (all miners + validators)
        {
            let mut state_guard = state.write();
            state_guard.registered_hotkeys = all_hotkeys;
        }

        // Update state with validators
        let result = self.update_state(state, bt_validators, banned_validators);

        // Update last sync block
        self.last_sync_block = state.read().block_height;

        info!(
            "Validator sync complete: {} added, {} removed, {} updated, {} skipped (banned)",
            result.added, result.removed, result.updated, result.skipped_banned
        );

        Ok(result)
    }

    /// Parse metagraph data to extract validators and all registered hotkeys
    fn parse_metagraph(
        &self,
        metagraph: &Metagraph,
    ) -> Result<(Vec<MetagraphValidator>, std::collections::HashSet<Hotkey>), SyncError> {
        let mut validators = Vec::new();
        let mut all_hotkeys = std::collections::HashSet::new();

        // Parse neurons from metagraph
        for (uid, neuron) in &metagraph.neurons {
            // Convert AccountId32 hotkey to our Hotkey type
            let hotkey_bytes: &[u8; 32] = neuron.hotkey.as_ref();
            let hotkey = Hotkey(*hotkey_bytes);

            // Add ALL hotkeys to the registered set (miners + validators)
            all_hotkeys.insert(hotkey.clone());

            // Get effective stake: alpha stake + root stake (TAO on root subnet)
            // This matches how Bittensor calculates validator weight
            let alpha_stake = neuron.stake;
            let root_stake = neuron.root_stake;
            let effective_stake = alpha_stake.saturating_add(root_stake);
            let stake = effective_stake.min(u64::MAX as u128) as u64;

            // Only add to validators if above minimum stake
            if stake >= self.min_stake {
                // Extract normalized scores (u16 -> f64, divide by u16::MAX)
                let incentive = neuron.incentive / u16::MAX as f64;
                let trust = neuron.trust / u16::MAX as f64;
                let consensus = neuron.consensus / u16::MAX as f64;

                // Check if active (has stake)
                let active = stake > 0;

                validators.push(MetagraphValidator {
                    hotkey,
                    uid: *uid as u16,
                    stake,
                    active,
                    incentive,
                    trust,
                    consensus,
                });
            }
        }

        debug!(
            "Parsed {} validators and {} total hotkeys from metagraph",
            validators.len(),
            all_hotkeys.len()
        );
        Ok((validators, all_hotkeys))
    }

    /// Update chain state with validators from Bittensor
    fn update_state(
        &self,
        state: &Arc<RwLock<ChainState>>,
        bt_validators: Vec<MetagraphValidator>,
        banned_validators: Option<&std::collections::HashSet<String>>,
    ) -> SyncResult {
        let mut state = state.write();
        let mut result = SyncResult::default();

        // Create map of Bittensor validators
        let bt_map: HashMap<Hotkey, MetagraphValidator> = bt_validators
            .into_iter()
            .map(|v| (v.hotkey.clone(), v))
            .collect();

        // Remove validators not in Bittensor metagraph
        let current_hotkeys: Vec<Hotkey> = state.validators.keys().cloned().collect();
        for hotkey in current_hotkeys {
            if !bt_map.contains_key(&hotkey) && !state.is_sudo(&hotkey) {
                state.validators.remove(&hotkey);
                result.removed += 1;
                debug!("Removed validator not in metagraph: {}", hotkey);
            }
        }

        // Add/update validators from Bittensor
        for (hotkey, bt_val) in bt_map {
            // Skip banned validators
            if let Some(banned) = banned_validators {
                if banned.contains(&hotkey.to_hex()) {
                    result.skipped_banned += 1;
                    debug!("Skipping banned validator: {}", hotkey);
                    continue;
                }
            }

            if let Some(existing) = state.validators.get_mut(&hotkey) {
                // Update stake if changed
                let new_stake = Stake::new(bt_val.stake);
                if existing.stake != new_stake {
                    existing.stake = new_stake;
                    existing.is_active = bt_val.active;
                    result.updated += 1;
                    debug!("Updated validator stake: {} -> {}", hotkey, bt_val.stake);
                }
            } else {
                // Add new validator
                let info = ValidatorInfo::new(hotkey.clone(), Stake::new(bt_val.stake));
                if state.add_validator(info).is_ok() {
                    result.added += 1;
                    debug!(
                        "Added validator from metagraph: {} (stake={})",
                        hotkey, bt_val.stake
                    );
                }
            }
        }

        result.total = state.validators.len();
        result
    }

    /// Get current sync status
    pub fn status(&self) -> SyncStatus {
        SyncStatus {
            last_sync_block: self.last_sync_block,
            sync_interval: self.sync_interval,
            netuid: self.netuid,
            min_stake: self.min_stake,
        }
    }
}

/// Sync result
#[derive(Clone, Debug, Default)]
pub struct SyncResult {
    /// Validators added
    pub added: usize,
    /// Validators removed
    pub removed: usize,
    /// Validators updated (stake changed)
    pub updated: usize,
    /// Validators skipped (banned)
    pub skipped_banned: usize,
    /// Total validators after sync
    pub total: usize,
}

/// Sync status
#[derive(Clone, Debug)]
pub struct SyncStatus {
    pub last_sync_block: u64,
    pub sync_interval: u64,
    pub netuid: u16,
    pub min_stake: u64,
}

/// Sync error
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("Client error: {0}")]
    ClientError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("State error: {0}")]
    StateError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BittensorConfig;
    use platform_core::{Keypair, NetworkConfig, Stake};
    use std::sync::Arc;
    use tokio::sync::Mutex as TokioMutex;

    #[test]
    fn test_sync_result() {
        let result = SyncResult {
            added: 5,
            removed: 2,
            updated: 3,
            skipped_banned: 1,
            total: 10,
        };

        assert_eq!(result.added, 5);
        assert_eq!(result.skipped_banned, 1);
        assert_eq!(result.total, 10);
    }

    #[test]
    fn test_sync_status() {
        let status = SyncStatus {
            last_sync_block: 1000,
            sync_interval: 100,
            netuid: 1,
            min_stake: 1_000_000_000,
        };

        assert_eq!(status.netuid, 1);
    }

    #[test]
    fn test_validator_sync_needs_sync_respects_interval() {
        let client = Arc::new(TokioMutex::new(SubtensorClient::new(
            BittensorConfig::local(1),
        )));
        let sync = ValidatorSync::new(client, 1, 1_000_000_000);

        assert!(!sync.needs_sync(50));
        assert!(sync.needs_sync(100));
        assert!(sync.needs_sync(150));
    }

    #[test]
    fn test_validator_sync_with_sync_interval_customizes_threshold() {
        let client = Arc::new(TokioMutex::new(SubtensorClient::new(
            BittensorConfig::local(1),
        )));
        let sync = ValidatorSync::new(client, 1, 1_000_000_000).with_sync_interval(10);

        assert!(!sync.needs_sync(9));
        assert!(sync.needs_sync(10));
    }

    fn sample_metagraph_validator(hotkey: Hotkey, stake: u64) -> MetagraphValidator {
        MetagraphValidator {
            hotkey,
            uid: 1,
            stake,
            active: true,
            incentive: 0.5,
            trust: 0.5,
            consensus: 0.5,
        }
    }

    #[test]
    fn test_update_state_skips_banned_validators() {
        let client = Arc::new(TokioMutex::new(SubtensorClient::new(
            BittensorConfig::local(1),
        )));
        let sync = ValidatorSync::new(client, 1, 1_000_000_000);
        let state = Arc::new(RwLock::new(ChainState::default()));

        let hotkey = Hotkey([7u8; 32]);
        let banned = std::collections::HashSet::from([hotkey.to_hex()]);
        let validators = vec![sample_metagraph_validator(hotkey.clone(), 2_000_000_000)];

        let result = sync.update_state(&state, validators, Some(&banned));

        assert_eq!(result.added, 0);
        assert_eq!(result.skipped_banned, 1);
        assert!(state.read().validators.is_empty());
    }

    #[test]
    fn test_update_state_removes_and_updates_validators() {
        let client = Arc::new(TokioMutex::new(SubtensorClient::new(
            BittensorConfig::local(1),
        )));
        let sync = ValidatorSync::new(client, 1, 1_000_000_000);
        let state = Arc::new(RwLock::new(ChainState::default()));

        let keep_hotkey = Hotkey([1u8; 32]);
        let remove_hotkey = Hotkey([2u8; 32]);

        {
            let mut guard = state.write();
            guard
                .add_validator(ValidatorInfo::new(
                    keep_hotkey.clone(),
                    Stake::new(1_500_000_000),
                ))
                .unwrap();
            guard
                .add_validator(ValidatorInfo::new(
                    remove_hotkey.clone(),
                    Stake::new(1_500_000_000),
                ))
                .unwrap();
        }

        let bt_validators = vec![MetagraphValidator {
            hotkey: keep_hotkey.clone(),
            uid: 9,
            stake: 3_000_000_000,
            active: false,
            incentive: 0.4,
            trust: 0.3,
            consensus: 0.2,
        }];

        let result = sync.update_state(&state, bt_validators, None);

        assert_eq!(result.removed, 1);
        assert_eq!(result.updated, 1);
        assert_eq!(result.total, 1);

        let guard = state.read();
        assert!(!guard.validators.contains_key(&remove_hotkey));
        let updated = guard.validators.get(&keep_hotkey).unwrap();
        assert_eq!(updated.stake, Stake::new(3_000_000_000));
        assert!(!updated.is_active);
    }

    #[test]
    fn test_update_state_adds_new_validator() {
        let client = Arc::new(TokioMutex::new(SubtensorClient::new(
            BittensorConfig::local(1),
        )));
        let sync = ValidatorSync::new(client, 1, 1_000_000_000);
        let state = Arc::new(RwLock::new(ChainState::default()));

        let new_hotkey = Hotkey([9u8; 32]);
        let validators = vec![sample_metagraph_validator(
            new_hotkey.clone(),
            2_500_000_000,
        )];

        let result = sync.update_state(&state, validators, None);

        assert_eq!(result.added, 1);
        assert_eq!(result.total, 1);
        let guard = state.read();
        assert!(guard.validators.contains_key(&new_hotkey));
    }
}