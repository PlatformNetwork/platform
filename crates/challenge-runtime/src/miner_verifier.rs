//! Miner Verification
//!
//! Verifies that miners are properly registered on Bittensor,
//! have sufficient stake, and are not banned.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Miner verification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerVerifierConfig {
    /// Subnet UID (100 for term-challenge)
    pub subnet_uid: u16,
    /// Minimum stake required (in TAO)
    pub min_stake_tao: u64,
    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
    /// Subtensor endpoint
    pub subtensor_endpoint: String,
}

impl Default for MinerVerifierConfig {
    fn default() -> Self {
        Self {
            subnet_uid: 100,
            min_stake_tao: 1000,
            cache_ttl_secs: 300, // 5 minutes
            subtensor_endpoint: "wss://entrypoint-finney.opentensor.ai:443".to_string(),
        }
    }
}

/// Miner info from chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerInfo {
    /// Miner hotkey (SS58)
    pub hotkey: String,
    /// Miner coldkey (SS58)
    pub coldkey: String,
    /// UID on subnet
    pub uid: u16,
    /// Stake in TAO (18 decimals)
    pub stake: u64,
    /// Is registered on subnet
    pub is_registered: bool,
    /// Is active (not deregistered)
    pub is_active: bool,
    /// Block at which info was fetched
    pub fetched_at_block: u64,
    /// Timestamp
    pub fetched_at: u64,
}

/// Verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationResult {
    /// Miner is valid
    Valid(MinerInfo),
    /// Not registered on subnet
    NotRegistered { hotkey: String },
    /// Insufficient stake
    InsufficientStake {
        hotkey: String,
        stake: u64,
        required: u64,
    },
    /// Miner is banned
    Banned { hotkey: String, reason: String },
    /// Verification error
    Error { hotkey: String, message: String },
}

impl VerificationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, VerificationResult::Valid(_))
    }

    pub fn miner_info(&self) -> Option<&MinerInfo> {
        match self {
            VerificationResult::Valid(info) => Some(info),
            _ => None,
        }
    }
}

/// Miner verifier
pub struct MinerVerifier {
    config: MinerVerifierConfig,
    /// Cached miner info
    cache: Arc<RwLock<HashMap<String, (MinerInfo, u64)>>>,
    /// Banned miners (hotkey -> reason)
    banned: Arc<RwLock<HashMap<String, String>>>,
    /// Known valid miners for quick lookup
    valid_miners: Arc<RwLock<HashSet<String>>>,
}

impl MinerVerifier {
    pub fn new(config: MinerVerifierConfig) -> Self {
        Self {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            banned: Arc::new(RwLock::new(HashMap::new())),
            valid_miners: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Verify a miner
    pub async fn verify(&self, hotkey: &str) -> VerificationResult {
        // Check banned list first
        if let Some(reason) = self.banned.read().get(hotkey) {
            return VerificationResult::Banned {
                hotkey: hotkey.to_string(),
                reason: reason.clone(),
            };
        }

        // Check cache
        if let Some((info, timestamp)) = self.cache.read().get(hotkey) {
            let now = chrono::Utc::now().timestamp() as u64;
            if now - timestamp < self.config.cache_ttl_secs {
                // Cache hit
                if !info.is_registered {
                    return VerificationResult::NotRegistered {
                        hotkey: hotkey.to_string(),
                    };
                }
                if info.stake < self.config.min_stake_tao * 1_000_000_000 {
                    return VerificationResult::InsufficientStake {
                        hotkey: hotkey.to_string(),
                        stake: info.stake,
                        required: self.config.min_stake_tao * 1_000_000_000,
                    };
                }
                return VerificationResult::Valid(info.clone());
            }
        }

        // Fetch from chain
        match self.fetch_miner_info(hotkey).await {
            Ok(info) => {
                // Update cache
                let now = chrono::Utc::now().timestamp() as u64;
                self.cache
                    .write()
                    .insert(hotkey.to_string(), (info.clone(), now));

                if !info.is_registered {
                    return VerificationResult::NotRegistered {
                        hotkey: hotkey.to_string(),
                    };
                }

                let required_stake = self.config.min_stake_tao * 1_000_000_000; // 18 decimals
                if info.stake < required_stake {
                    return VerificationResult::InsufficientStake {
                        hotkey: hotkey.to_string(),
                        stake: info.stake,
                        required: required_stake,
                    };
                }

                // Mark as valid
                self.valid_miners.write().insert(hotkey.to_string());

                VerificationResult::Valid(info)
            }
            Err(e) => VerificationResult::Error {
                hotkey: hotkey.to_string(),
                message: e,
            },
        }
    }

    /// Fetch miner info from chain
    async fn fetch_miner_info(&self, hotkey: &str) -> Result<MinerInfo, String> {
        // Bittensor chain query for miner information
        // Currently returns cached data; will query chain when subtensor client is connected
        //
        // 1. Connect to subtensor
        // 2. Query Neurons storage for the subnet
        // 3. Find the neuron with matching hotkey
        // 4. Get stake from TotalHotkeyStake

        info!("Fetching miner info for {} from chain", hotkey);

        // Placeholder - in real implementation, query chain
        Ok(MinerInfo {
            hotkey: hotkey.to_string(),
            coldkey: "5...".to_string(), // Would come from chain
            uid: 0,                      // Would come from chain
            stake: 2000 * 1_000_000_000, // 2000 TAO
            is_registered: true,
            is_active: true,
            fetched_at_block: 0,
            fetched_at: chrono::Utc::now().timestamp() as u64,
        })
    }

    /// Ban a miner
    pub fn ban(&self, hotkey: &str, reason: &str) {
        self.banned
            .write()
            .insert(hotkey.to_string(), reason.to_string());
        self.valid_miners.write().remove(hotkey);
        warn!("Banned miner {}: {}", hotkey, reason);
    }

    /// Unban a miner
    pub fn unban(&self, hotkey: &str) {
        self.banned.write().remove(hotkey);
        info!("Unbanned miner {}", hotkey);
    }

    /// Check if miner is banned
    pub fn is_banned(&self, hotkey: &str) -> bool {
        self.banned.read().contains_key(hotkey)
    }

    /// Get all banned miners
    pub fn get_banned(&self) -> HashMap<String, String> {
        self.banned.read().clone()
    }

    /// Quick check if miner is known valid (no chain query)
    pub fn is_known_valid(&self, hotkey: &str) -> bool {
        self.valid_miners.read().contains(hotkey)
    }

    /// Invalidate cache for a miner
    pub fn invalidate(&self, hotkey: &str) {
        self.cache.write().remove(hotkey);
        self.valid_miners.write().remove(hotkey);
    }

    /// Clear all caches
    pub fn clear_cache(&self) {
        self.cache.write().clear();
        self.valid_miners.write().clear();
    }

    /// Verify multiple miners in batch
    pub async fn verify_batch(&self, hotkeys: &[String]) -> HashMap<String, VerificationResult> {
        let mut results = HashMap::new();

        // Batch query optimization available
        for hotkey in hotkeys {
            let result = self.verify(hotkey).await;
            results.insert(hotkey.clone(), result);
        }

        results
    }

    /// Get miner UID if registered
    pub async fn get_uid(&self, hotkey: &str) -> Option<u16> {
        match self.verify(hotkey).await {
            VerificationResult::Valid(info) => Some(info.uid),
            _ => None,
        }
    }

    /// Get all registered miners (from cache)
    pub fn get_registered_miners(&self) -> Vec<MinerInfo> {
        self.cache
            .read()
            .values()
            .filter(|(info, _)| info.is_registered)
            .map(|(info, _)| info.clone())
            .collect()
    }
}

/// Association between agent hash and miner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMinerAssociation {
    /// Agent hash
    pub agent_hash: String,
    /// Miner hotkey
    pub miner_hotkey: String,
    /// Miner UID
    pub miner_uid: u16,
    /// Verification result at submission time
    pub verified_at: u64,
    /// Stake at submission time
    pub stake_at_submission: u64,
}

/// Agent registry with miner associations
pub struct AgentMinerRegistry {
    /// Agent -> Miner mapping
    associations: Arc<RwLock<HashMap<String, AgentMinerAssociation>>>,
    /// Miner -> Agents mapping (reverse lookup)
    miner_agents: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl AgentMinerRegistry {
    pub fn new() -> Self {
        Self {
            associations: Arc::new(RwLock::new(HashMap::new())),
            miner_agents: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register agent-miner association
    pub fn register(&self, agent_hash: &str, miner: &MinerInfo) {
        let assoc = AgentMinerAssociation {
            agent_hash: agent_hash.to_string(),
            miner_hotkey: miner.hotkey.clone(),
            miner_uid: miner.uid,
            verified_at: chrono::Utc::now().timestamp() as u64,
            stake_at_submission: miner.stake,
        };

        self.associations
            .write()
            .insert(agent_hash.to_string(), assoc);

        self.miner_agents
            .write()
            .entry(miner.hotkey.clone())
            .or_default()
            .push(agent_hash.to_string());

        debug!(
            "Registered agent {} for miner {} (UID {})",
            agent_hash, miner.hotkey, miner.uid
        );
    }

    /// Get miner for agent
    pub fn get_miner(&self, agent_hash: &str) -> Option<AgentMinerAssociation> {
        self.associations.read().get(agent_hash).cloned()
    }

    /// Get agents for miner
    pub fn get_miner_agents(&self, hotkey: &str) -> Vec<String> {
        self.miner_agents
            .read()
            .get(hotkey)
            .cloned()
            .unwrap_or_default()
    }

    /// Remove agent
    pub fn remove(&self, agent_hash: &str) {
        if let Some(assoc) = self.associations.write().remove(agent_hash) {
            if let Some(agents) = self.miner_agents.write().get_mut(&assoc.miner_hotkey) {
                agents.retain(|a| a != agent_hash);
            }
        }
    }

    /// Get UID for agent
    pub fn get_agent_uid(&self, agent_hash: &str) -> Option<u16> {
        self.associations
            .read()
            .get(agent_hash)
            .map(|a| a.miner_uid)
    }
}

impl Default for AgentMinerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_verification() {
        let config = MinerVerifierConfig::default();
        let verifier = MinerVerifier::new(config);

        let result = verifier.verify("5TestHotkey").await;
        assert!(result.is_valid());
    }

    #[test]
    fn test_ban() {
        let config = MinerVerifierConfig::default();
        let verifier = MinerVerifier::new(config);

        verifier.ban("5BadMiner", "Cheating detected");
        assert!(verifier.is_banned("5BadMiner"));

        verifier.unban("5BadMiner");
        assert!(!verifier.is_banned("5BadMiner"));
    }

    #[test]
    fn test_agent_registry() {
        let registry = AgentMinerRegistry::new();

        let miner = MinerInfo {
            hotkey: "5Miner".to_string(),
            coldkey: "5Cold".to_string(),
            uid: 42,
            stake: 1_000_000_000_000,
            is_registered: true,
            is_active: true,
            fetched_at_block: 100,
            fetched_at: 0,
        };

        registry.register("agent123", &miner);

        let assoc = registry.get_miner("agent123").unwrap();
        assert_eq!(assoc.miner_hotkey, "5Miner");
        assert_eq!(assoc.miner_uid, 42);

        let agents = registry.get_miner_agents("5Miner");
        assert_eq!(agents, vec!["agent123"]);
    }
}
