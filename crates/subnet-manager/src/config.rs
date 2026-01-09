//! Subnet configuration management

use chrono::{DateTime, Utc};
use platform_core::Hotkey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Subnet configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubnetConfig {
    /// Subnet UID on Bittensor
    pub netuid: u16,

    /// Subnet name
    pub name: String,

    /// Subnet description
    pub description: String,

    /// Version string
    pub version: String,

    /// Minimum validator stake (in RAO)
    pub min_stake: u64,

    /// Maximum validators
    pub max_validators: u32,

    /// Epoch length in blocks
    pub epoch_length: u64,

    /// Weight submission interval (in epochs)
    pub weight_interval: u64,

    /// Enable automatic updates
    pub auto_update: bool,

    /// Update check interval (seconds)
    pub update_check_interval: u64,

    /// Snapshot interval (in epochs)
    pub snapshot_interval: u64,

    /// Maximum snapshots to keep
    pub max_snapshots: u32,

    /// Recovery mode settings
    pub recovery: RecoveryConfig,

    /// Health check settings
    pub health: HealthConfig,
}

/// Minimum stake to be a validator: 1000 TAO
pub const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000_000; // 1000 TAO in RAO

impl Default for SubnetConfig {
    fn default() -> Self {
        Self {
            netuid: 1,
            name: "Mini-Chain Subnet".to_string(),
            description: "P2P validator network".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            min_stake: MIN_VALIDATOR_STAKE, // 1000 TAO
            max_validators: 256,
            epoch_length: 100,
            weight_interval: 1,
            auto_update: true,
            update_check_interval: 300, // 5 minutes
            snapshot_interval: 10,      // Every 10 epochs
            max_snapshots: 5,
            recovery: RecoveryConfig::default(),
            health: HealthConfig::default(),
        }
    }
}

/// Recovery configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Enable automatic recovery
    pub auto_recover: bool,

    /// Maximum recovery attempts
    pub max_attempts: u32,

    /// Recovery cooldown (seconds)
    pub cooldown_secs: u64,

    /// Rollback to last snapshot on repeated failures
    pub rollback_on_failure: bool,

    /// Pause subnet on critical errors
    pub pause_on_critical: bool,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            auto_recover: true,
            max_attempts: 3,
            cooldown_secs: 60,
            rollback_on_failure: true,
            pause_on_critical: true,
        }
    }
}

/// Health check configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthConfig {
    /// Health check interval (seconds)
    pub check_interval: u64,

    /// Maximum consecutive failures before alert
    pub failure_threshold: u32,

    /// Memory usage warning threshold (%)
    pub memory_warn_percent: u32,

    /// CPU usage warning threshold (%)
    pub cpu_warn_percent: u32,

    /// Disk usage warning threshold (%)
    pub disk_warn_percent: u32,

    /// Maximum pending jobs before warning
    pub max_pending_jobs: u32,

    /// Maximum evaluation time (seconds)
    pub max_eval_time: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval: 30,
            failure_threshold: 3,
            memory_warn_percent: 80,
            cpu_warn_percent: 90,
            disk_warn_percent: 85,
            max_pending_jobs: 1000,
            max_eval_time: 600,
        }
    }
}

/// Challenge configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeConfig {
    /// Challenge ID
    pub id: String,

    /// Challenge name
    pub name: String,

    /// WASM bytecode hash
    pub wasm_hash: String,

    /// WASM bytecode URL or path
    pub wasm_source: String,

    /// Emission weight (0.0 - 1.0)
    pub emission_weight: f64,

    /// Is challenge active
    pub active: bool,

    /// Evaluation timeout (seconds)
    pub timeout_secs: u64,

    /// Maximum concurrent evaluations
    pub max_concurrent: u32,
}

impl SubnetConfig {
    /// Load from file
    pub fn load(path: &PathBuf) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Save to file
    pub fn save(&self, path: &PathBuf) -> anyhow::Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.epoch_length == 0 {
            return Err(ConfigError::InvalidValue("epoch_length must be > 0".into()));
        }
        if self.max_validators == 0 {
            return Err(ConfigError::InvalidValue(
                "max_validators must be > 0".into(),
            ));
        }
        if self.weight_interval == 0 {
            return Err(ConfigError::InvalidValue(
                "weight_interval must be > 0".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Invalid value: {0}")]
    InvalidValue(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Ban entry with reason and timestamp
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BanEntry {
    /// Reason for ban
    pub reason: String,
    /// When banned
    pub banned_at: DateTime<Utc>,
    /// Who banned (subnet owner hotkey)
    pub banned_by: String,
}

/// Ban list for validators and emission recipients
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BanList {
    /// Banned validators (can't join network, won't sync from Bittensor)
    pub banned_validators: HashMap<String, BanEntry>,

    /// Banned hotkeys (no emissions for any challenge)
    pub banned_hotkeys: HashMap<String, BanEntry>,

    /// Banned coldkeys (all associated hotkeys get no emissions)
    pub banned_coldkeys: HashMap<String, BanEntry>,
}

impl BanList {
    /// Create empty ban list
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from file
    pub fn load(path: &PathBuf) -> anyhow::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let list: Self = serde_json::from_str(&content)?;
            Ok(list)
        } else {
            Ok(Self::default())
        }
    }

    /// Save to file
    pub fn save(&self, path: &PathBuf) -> anyhow::Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Ban a validator
    pub fn ban_validator(&mut self, hotkey: &Hotkey, reason: &str, banned_by: &str) {
        self.banned_validators.insert(
            hotkey.to_hex(),
            BanEntry {
                reason: reason.to_string(),
                banned_at: Utc::now(),
                banned_by: banned_by.to_string(),
            },
        );
    }

    /// Unban a validator
    pub fn unban_validator(&mut self, hotkey: &Hotkey) -> bool {
        self.banned_validators.remove(&hotkey.to_hex()).is_some()
    }

    /// Check if validator is banned
    pub fn is_validator_banned(&self, hotkey: &Hotkey) -> bool {
        self.banned_validators.contains_key(&hotkey.to_hex())
    }

    /// Ban a hotkey from emissions
    pub fn ban_hotkey(&mut self, hotkey: &Hotkey, reason: &str, banned_by: &str) {
        self.banned_hotkeys.insert(
            hotkey.to_hex(),
            BanEntry {
                reason: reason.to_string(),
                banned_at: Utc::now(),
                banned_by: banned_by.to_string(),
            },
        );
    }

    /// Unban a hotkey
    pub fn unban_hotkey(&mut self, hotkey: &Hotkey) -> bool {
        self.banned_hotkeys.remove(&hotkey.to_hex()).is_some()
    }

    /// Check if hotkey is banned from emissions
    pub fn is_hotkey_banned(&self, hotkey: &Hotkey) -> bool {
        self.banned_hotkeys.contains_key(&hotkey.to_hex())
    }

    /// Ban a coldkey (all associated hotkeys)
    pub fn ban_coldkey(&mut self, coldkey: &str, reason: &str, banned_by: &str) {
        self.banned_coldkeys.insert(
            coldkey.to_string(),
            BanEntry {
                reason: reason.to_string(),
                banned_at: Utc::now(),
                banned_by: banned_by.to_string(),
            },
        );
    }

    /// Unban a coldkey
    pub fn unban_coldkey(&mut self, coldkey: &str) -> bool {
        self.banned_coldkeys.remove(coldkey).is_some()
    }

    /// Check if coldkey is banned
    pub fn is_coldkey_banned(&self, coldkey: &str) -> bool {
        self.banned_coldkeys.contains_key(coldkey)
    }

    /// Check if an entity should receive emissions
    /// Returns false if hotkey or associated coldkey is banned
    pub fn can_receive_emissions(&self, hotkey: &Hotkey, coldkey: Option<&str>) -> bool {
        if self.is_hotkey_banned(hotkey) {
            return false;
        }
        if let Some(ck) = coldkey {
            if self.is_coldkey_banned(ck) {
                return false;
            }
        }
        true
    }

    /// Get summary of bans
    pub fn summary(&self) -> BanSummary {
        BanSummary {
            banned_validators: self.banned_validators.len(),
            banned_hotkeys: self.banned_hotkeys.len(),
            banned_coldkeys: self.banned_coldkeys.len(),
        }
    }
}

/// Summary of ban list
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BanSummary {
    pub banned_validators: usize,
    pub banned_hotkeys: usize,
    pub banned_coldkeys: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_subnet_config_load_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("subnet_config.json");

        let mut config = SubnetConfig::default();
        config.name = "Load Test".into();
        config.max_validators = 42;
        config.save(&path).unwrap();

        let loaded = SubnetConfig::load(&path).unwrap();
        let expected = serde_json::to_value(&config).unwrap();
        let actual = serde_json::to_value(&loaded).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_subnet_config_validate_errors() {
        let mut config = SubnetConfig::default();
        config.epoch_length = 0;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(msg) if msg.contains("epoch_length")));

        let mut config = SubnetConfig::default();
        config.max_validators = 0;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(msg) if msg.contains("max_validators")));

        let mut config = SubnetConfig::default();
        config.weight_interval = 0;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(msg) if msg.contains("weight_interval")));
    }

    #[test]
    fn test_ban_list() {
        let mut bans = BanList::new();
        let hotkey = Hotkey([1u8; 32]);

        // Ban validator
        bans.ban_validator(&hotkey, "Bad behavior", "sudo");
        assert!(bans.is_validator_banned(&hotkey));

        // Unban
        assert!(bans.unban_validator(&hotkey));
        assert!(!bans.is_validator_banned(&hotkey));
    }

    #[test]
    fn test_emission_ban() {
        let mut bans = BanList::new();
        let hotkey = Hotkey([2u8; 32]);

        // Initially can receive
        assert!(bans.can_receive_emissions(&hotkey, None));

        // Ban hotkey
        bans.ban_hotkey(&hotkey, "Cheating", "sudo");
        assert!(!bans.can_receive_emissions(&hotkey, None));

        // Test coldkey ban
        let hotkey2 = Hotkey([3u8; 32]);
        bans.ban_coldkey("5ColdKeyAddress", "All accounts banned", "sudo");
        assert!(!bans.can_receive_emissions(&hotkey2, Some("5ColdKeyAddress")));
    }

    #[test]
    fn test_min_stake_constant() {
        // 1000 TAO = 1000 * 10^9 RAO
        assert_eq!(MIN_VALIDATOR_STAKE, 1_000_000_000_000);
    }

    #[test]
    fn test_ban_list_load_from_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bans.json");
        let hotkey = Hotkey([9u8; 32]);

        {
            let mut bans = BanList::new();
            bans.ban_validator(&hotkey, "test", "sudo");
            bans.save(&path).unwrap();
        }

        let loaded = BanList::load(&path).unwrap();
        assert!(loaded.is_validator_banned(&hotkey));
    }

    #[test]
    fn test_ban_list_load_missing_file_returns_default() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does_not_exist.json");

        let loaded = BanList::load(&path).unwrap();

        assert!(loaded.banned_validators.is_empty());
        assert!(loaded.banned_hotkeys.is_empty());
        assert!(loaded.banned_coldkeys.is_empty());
    }
}
