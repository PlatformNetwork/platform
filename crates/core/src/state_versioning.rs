//! State versioning and migration system
//!
//! This module provides backward-compatible state serialization with automatic
//! migration support. When ChainState structure changes between versions,
//! old data can still be loaded and migrated to the current format.
//!
//! # Usage
//!
//! Instead of directly serializing/deserializing ChainState, use:
//! - `VersionedState::from_state()` to wrap a ChainState for serialization
//! - `VersionedState::into_state()` to get the migrated ChainState
//!
//! # Adding a new version
//!
//! 1. Increment `CURRENT_STATE_VERSION`
//! 2. Keep the old `ChainStateVX` struct as-is (rename current to VX)
//! 3. Create new `ChainState` with your changes
//! 4. Implement migration in `migrate_state()`
//! 5. Add `#[serde(default)]` to any new fields

use crate::{
    BlockHeight, Challenge, ChallengeId, ChallengeWeightAllocation, Hotkey, Job,
    MechanismWeightConfig, NetworkConfig, Result, Stake, ValidatorInfo, WasmChallengeConfig,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{info, warn};

/// Current state version - increment when ChainState structure changes
/// V1: Original format (no registered_hotkeys)
/// V2: Added registered_hotkeys
/// V3: Added x25519_pubkey to ValidatorInfo
/// V4: Added wasm_challenge_configs
/// V5: Added WASM restart metadata
/// V6: Removed docker challenge configs
pub const CURRENT_STATE_VERSION: u32 = 6;

/// Minimum supported version for migration
pub const MIN_SUPPORTED_VERSION: u32 = 1;

/// Versioned state wrapper for serialization
///
/// This wrapper allows us to detect the version of serialized state and
/// migrate it to the current format automatically.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionedState {
    /// State format version
    pub version: u32,
    /// Serialized state data (version-specific format)
    pub data: Vec<u8>,
}

impl VersionedState {
    /// Create a versioned state from current ChainState
    pub fn from_state(state: &crate::ChainState) -> Result<Self> {
        let data = bincode::serialize(state)
            .map_err(|e| crate::MiniChainError::Serialization(e.to_string()))?;
        Ok(Self {
            version: CURRENT_STATE_VERSION,
            data,
        })
    }

    /// Deserialize and migrate to current ChainState
    pub fn into_state(self) -> Result<crate::ChainState> {
        if self.version == CURRENT_STATE_VERSION {
            // Current version - deserialize directly
            bincode::deserialize(&self.data)
                .map_err(|e| crate::MiniChainError::Serialization(e.to_string()))
        } else if self.version >= MIN_SUPPORTED_VERSION {
            // Old version - migrate
            info!(
                "Migrating state from version {} to {}",
                self.version, CURRENT_STATE_VERSION
            );
            migrate_state(self.version, &self.data)
        } else {
            Err(crate::MiniChainError::Serialization(format!(
                "State version {} is too old (minimum supported: {})",
                self.version, MIN_SUPPORTED_VERSION
            )))
        }
    }
}

// ============================================================================
// ValidatorInfo versions (for backward compatibility)
// ============================================================================

/// ValidatorInfo V1/V2 - without x25519_pubkey field
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfoLegacy {
    pub hotkey: Hotkey,
    pub stake: Stake,
    pub is_active: bool,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub peer_id: Option<String>,
    // V1/V2 did NOT have x25519_pubkey
}

impl ValidatorInfoLegacy {
    /// Migrate to current ValidatorInfo
    pub fn migrate(self) -> ValidatorInfo {
        ValidatorInfo {
            hotkey: self.hotkey,
            stake: self.stake,
            is_active: self.is_active,
            last_seen: self.last_seen,
            peer_id: self.peer_id,
            x25519_pubkey: None, // New field in V3
        }
    }
}

// ============================================================================
// Version 1 State (original format, before registered_hotkeys)
// ============================================================================

/// ChainState V1 - original format without registered_hotkeys
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainStateV1 {
    pub block_height: BlockHeight,
    pub epoch: u64,
    pub config: NetworkConfig,
    pub sudo_key: Hotkey,
    pub validators: HashMap<Hotkey, ValidatorInfoLegacy>,
    pub challenges: HashMap<ChallengeId, Challenge>,
    #[serde(default)]
    pub wasm_challenge_configs: HashMap<ChallengeId, WasmChallengeConfig>,
    pub mechanism_configs: HashMap<u8, MechanismWeightConfig>,
    pub challenge_weights: HashMap<ChallengeId, ChallengeWeightAllocation>,
    pub required_version: Option<crate::RequiredVersion>,
    pub pending_jobs: Vec<Job>,
    pub state_hash: [u8; 32],
    pub last_updated: chrono::DateTime<chrono::Utc>,
    // V1 did NOT have registered_hotkeys
}

impl ChainStateV1 {
    /// Migrate V1 to current ChainState
    pub fn migrate(self) -> crate::ChainState {
        crate::ChainState {
            block_height: self.block_height,
            epoch: self.epoch,
            config: self.config,
            sudo_key: self.sudo_key,
            validators: self
                .validators
                .into_iter()
                .map(|(k, v)| (k, v.migrate()))
                .collect(),
            challenges: self.challenges,
            wasm_challenge_configs: self.wasm_challenge_configs,
            mechanism_configs: self.mechanism_configs,
            challenge_weights: self.challenge_weights,
            required_version: self.required_version,
            pending_jobs: self.pending_jobs,
            state_hash: self.state_hash,
            last_updated: self.last_updated,
            registered_hotkeys: HashSet::new(), // New in V2
            challenge_routes: HashMap::new(),
        }
    }
}

// ============================================================================
// Version 2 State (added registered_hotkeys, but ValidatorInfo without x25519_pubkey)
// ============================================================================

/// ChainState V2 - added registered_hotkeys, ValidatorInfo without x25519_pubkey
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainStateV2 {
    pub block_height: BlockHeight,
    pub epoch: u64,
    pub config: NetworkConfig,
    pub sudo_key: Hotkey,
    pub validators: HashMap<Hotkey, ValidatorInfoLegacy>,
    pub challenges: HashMap<ChallengeId, Challenge>,
    #[serde(default)]
    pub wasm_challenge_configs: HashMap<ChallengeId, WasmChallengeConfig>,
    pub mechanism_configs: HashMap<u8, MechanismWeightConfig>,
    pub challenge_weights: HashMap<ChallengeId, ChallengeWeightAllocation>,
    pub required_version: Option<crate::RequiredVersion>,
    pub pending_jobs: Vec<Job>,
    pub state_hash: [u8; 32],
    pub last_updated: chrono::DateTime<chrono::Utc>,
    pub registered_hotkeys: HashSet<Hotkey>, // Added in V2
}

impl ChainStateV2 {
    /// Migrate V2 to current ChainState
    pub fn migrate(self) -> crate::ChainState {
        crate::ChainState {
            block_height: self.block_height,
            epoch: self.epoch,
            config: self.config,
            sudo_key: self.sudo_key,
            validators: self
                .validators
                .into_iter()
                .map(|(k, v)| (k, v.migrate()))
                .collect(),
            challenges: self.challenges,
            wasm_challenge_configs: self.wasm_challenge_configs,
            mechanism_configs: self.mechanism_configs,
            challenge_weights: self.challenge_weights,
            required_version: self.required_version,
            pending_jobs: self.pending_jobs,
            state_hash: self.state_hash,
            last_updated: self.last_updated,
            registered_hotkeys: self.registered_hotkeys,
            challenge_routes: HashMap::new(),
        }
    }
}

// ============================================================================
// Migration Logic
// ============================================================================

/// Migrate state from an old version to current
fn migrate_state(version: u32, data: &[u8]) -> Result<crate::ChainState> {
    match version {
        1 => {
            // V1 -> V6: Add registered_hotkeys, x25519_pubkey, wasm_challenge_configs
            let v1: ChainStateV1 = bincode::deserialize(data).map_err(|e| {
                crate::MiniChainError::Serialization(format!("V1 migration failed: {}", e))
            })?;
            info!(
                "Migrated state V1->V6: block_height={}, validators={}",
                v1.block_height,
                v1.validators.len()
            );
            Ok(v1.migrate())
        }
        2 => {
            // V2 -> V6: Add x25519_pubkey to ValidatorInfo and wasm_challenge_configs
            let v2: ChainStateV2 = bincode::deserialize(data).map_err(|e| {
                crate::MiniChainError::Serialization(format!("V2 migration failed: {}", e))
            })?;
            info!(
                "Migrated state V2->V6: block_height={}, validators={}",
                v2.block_height,
                v2.validators.len()
            );
            Ok(v2.migrate())
        }
        3 => {
            // V3 -> V6: Add wasm_challenge_configs
            let mut v3: crate::ChainState = bincode::deserialize(data).map_err(|e| {
                crate::MiniChainError::Serialization(format!("V3 migration failed: {}", e))
            })?;
            v3.wasm_challenge_configs = HashMap::new();
            info!(
                "Migrated state V3->V6: block_height={}, validators={}",
                v3.block_height,
                v3.validators.len()
            );
            Ok(v3)
        }
        4 => {
            // V4 -> V6: Added WASM restart metadata and removed docker configs
            let v4: crate::ChainState = bincode::deserialize(data).map_err(|e| {
                crate::MiniChainError::Serialization(format!("V4 migration failed: {}", e))
            })?;
            info!(
                "Migrated state V4->V6: block_height={}, validators={}",
                v4.block_height,
                v4.validators.len()
            );
            Ok(v4)
        }
        5 => {
            // V5 -> V6: Remove docker configs (handled by serde defaults)
            let v5: crate::ChainState = bincode::deserialize(data).map_err(|e| {
                crate::MiniChainError::Serialization(format!("V5 migration failed: {}", e))
            })?;
            info!(
                "Migrated state V5->V6: block_height={}, validators={}",
                v5.block_height,
                v5.validators.len()
            );
            Ok(v5)
        }
        _ => Err(crate::MiniChainError::Serialization(format!(
            "Unknown state version: {}",
            version
        ))),
    }
}

// ============================================================================
// Smart Deserialization (tries versioned first, then raw, then legacy)
// ============================================================================

/// Deserialize state with automatic version detection and migration
///
/// This function tries multiple strategies to load state:
/// 1. Try as VersionedState (new format with version header)
/// 2. Try as current ChainState directly (for states saved without version)
/// 3. Try as ChainStateV2 (legacy format with registered_hotkeys but no x25519_pubkey)
/// 4. Try as ChainStateV1 (oldest format)
/// 5. Return error if all fail
pub fn deserialize_state_smart(data: &[u8]) -> Result<crate::ChainState> {
    // Strategy 1: Try as VersionedState (preferred format)
    if let Ok(versioned) = bincode::deserialize::<VersionedState>(data) {
        return versioned.into_state();
    }

    // Strategy 2: Try as current ChainState (unversioned but current format)
    if let Ok(state) = bincode::deserialize::<crate::ChainState>(data) {
        info!("Loaded unversioned state (current format)");
        return Ok(state);
    }

    // Strategy 3: Try as V2 (with registered_hotkeys, without x25519_pubkey)
    if let Ok(v2) = bincode::deserialize::<ChainStateV2>(data) {
        warn!("Loaded legacy V2 state, migrating...");
        return Ok(v2.migrate());
    }

    // Strategy 4: Try as V1 (oldest format without registered_hotkeys)
    if let Ok(v1) = bincode::deserialize::<ChainStateV1>(data) {
        warn!("Loaded legacy V1 state, migrating...");
        return Ok(v1.migrate());
    }

    // All strategies failed
    Err(crate::MiniChainError::Serialization(
        "Failed to deserialize state: incompatible format".to_string(),
    ))
}

/// Serialize state with version header
pub fn serialize_state_versioned(state: &crate::ChainState) -> Result<Vec<u8>> {
    let versioned = VersionedState::from_state(state)?;
    bincode::serialize(&versioned).map_err(|e| crate::MiniChainError::Serialization(e.to_string()))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keypair, NetworkConfig};

    fn create_test_state() -> crate::ChainState {
        let sudo = Keypair::generate();
        crate::ChainState::new(sudo.hotkey(), NetworkConfig::default())
    }

    #[test]
    fn test_versioned_roundtrip() {
        let original = create_test_state();

        // Serialize with version
        let data = serialize_state_versioned(&original).unwrap();

        // Deserialize
        let loaded = deserialize_state_smart(&data).unwrap();

        assert_eq!(original.block_height, loaded.block_height);
        assert_eq!(original.epoch, loaded.epoch);
    }

    #[test]
    fn test_validator_info_roundtrip() {
        let kp = Keypair::generate();
        let info = ValidatorInfo::new(kp.hotkey(), Stake::new(10_000_000_000));

        // Test bincode roundtrip of just ValidatorInfo
        let data = bincode::serialize(&info).unwrap();
        let loaded: ValidatorInfo = bincode::deserialize(&data).unwrap();

        assert_eq!(info.hotkey, loaded.hotkey);
        assert_eq!(info.stake, loaded.stake);
        assert_eq!(info.x25519_pubkey, loaded.x25519_pubkey);
    }

    #[test]
    fn test_versioned_roundtrip_with_validators() {
        let mut state = create_test_state();

        // Add some validators
        for _ in 0..4 {
            let kp = Keypair::generate();
            let info = ValidatorInfo::new(kp.hotkey(), Stake::new(10_000_000_000));
            state.add_validator(info).unwrap();
        }

        assert_eq!(state.validators.len(), 4);

        // First test: direct bincode roundtrip (should work)
        let direct_data = bincode::serialize(&state).unwrap();
        let direct_loaded: crate::ChainState = bincode::deserialize(&direct_data).unwrap();
        assert_eq!(state.validators.len(), direct_loaded.validators.len());

        // Second test: versioned roundtrip
        let data = serialize_state_versioned(&state).unwrap();

        // Deserialize
        let loaded = deserialize_state_smart(&data).unwrap();

        assert_eq!(state.block_height, loaded.block_height);
        assert_eq!(state.validators.len(), loaded.validators.len());
    }

    #[test]
    fn test_v1_migration() {
        // Create a V1 state
        let sudo = Keypair::generate();
        let v1 = ChainStateV1 {
            block_height: 100,
            epoch: 5,
            config: NetworkConfig::default(),
            sudo_key: sudo.hotkey(),
            validators: HashMap::new(),
            challenges: HashMap::new(),
            wasm_challenge_configs: HashMap::new(),
            mechanism_configs: HashMap::new(),
            challenge_weights: HashMap::new(),
            required_version: None,
            pending_jobs: Vec::new(),
            state_hash: [0u8; 32],
            last_updated: chrono::Utc::now(),
        };

        // Serialize as V1
        let v1_data = bincode::serialize(&v1).unwrap();

        // Wrap in VersionedState with version 1
        let versioned = VersionedState {
            version: 1,
            data: v1_data,
        };
        let versioned_bytes = bincode::serialize(&versioned).unwrap();

        // Load and migrate
        let migrated = deserialize_state_smart(&versioned_bytes).unwrap();

        assert_eq!(migrated.block_height, 100);
        assert_eq!(migrated.epoch, 5);
        assert!(migrated.registered_hotkeys.is_empty()); // New field initialized
    }

    #[test]
    fn test_legacy_v1_direct() {
        // Test loading raw V1 data (no version wrapper)
        let sudo = Keypair::generate();
        let v1 = ChainStateV1 {
            block_height: 50,
            epoch: 2,
            config: NetworkConfig::default(),
            sudo_key: sudo.hotkey(),
            validators: HashMap::new(),
            challenges: HashMap::new(),
            wasm_challenge_configs: HashMap::new(),
            mechanism_configs: HashMap::new(),
            challenge_weights: HashMap::new(),
            required_version: None,
            pending_jobs: Vec::new(),
            state_hash: [0u8; 32],
            last_updated: chrono::Utc::now(),
        };

        // Serialize raw V1 (no version wrapper)
        let raw_v1 = bincode::serialize(&v1).unwrap();

        // Smart deserialize should detect and migrate
        let migrated = deserialize_state_smart(&raw_v1).unwrap();

        assert_eq!(migrated.block_height, 50);
    }

    #[test]
    fn test_version_constants() {
        const _: () = assert!(CURRENT_STATE_VERSION >= MIN_SUPPORTED_VERSION);
        assert_eq!(CURRENT_STATE_VERSION, 6);
    }

    #[test]
    fn test_validator_info_legacy_migrate() {
        let kp = Keypair::generate();
        let legacy = ValidatorInfoLegacy {
            hotkey: kp.hotkey(),
            stake: Stake::new(5_000_000_000),
            is_active: true,
            last_seen: chrono::Utc::now(),
            peer_id: Some("peer123".to_string()),
        };

        let migrated = legacy.migrate();
        assert_eq!(migrated.hotkey, kp.hotkey());
        assert_eq!(migrated.stake.0, 5_000_000_000);
        assert!(migrated.x25519_pubkey.is_none());
    }

    #[test]
    fn test_chainstate_v2_migrate() {
        let sudo = Keypair::generate();
        let mut registered = HashSet::new();
        registered.insert(sudo.hotkey());

        let v2 = ChainStateV2 {
            block_height: 200,
            epoch: 10,
            config: NetworkConfig::default(),
            sudo_key: sudo.hotkey(),
            validators: HashMap::new(),
            challenges: HashMap::new(),
            wasm_challenge_configs: HashMap::new(),
            mechanism_configs: HashMap::new(),
            challenge_weights: HashMap::new(),
            required_version: None,
            pending_jobs: Vec::new(),
            state_hash: [1u8; 32],
            last_updated: chrono::Utc::now(),
            registered_hotkeys: registered.clone(),
        };

        let migrated = v2.migrate();
        assert_eq!(migrated.block_height, 200);
        assert_eq!(migrated.registered_hotkeys, registered);
    }

    #[test]
    fn test_deserialize_state_smart_v2() {
        // Create V2 state and serialize it
        let sudo = Keypair::generate();
        let v2 = ChainStateV2 {
            block_height: 150,
            epoch: 8,
            config: NetworkConfig::default(),
            sudo_key: sudo.hotkey(),
            validators: HashMap::new(),
            challenges: HashMap::new(),
            wasm_challenge_configs: HashMap::new(),
            mechanism_configs: HashMap::new(),
            challenge_weights: HashMap::new(),
            required_version: None,
            pending_jobs: Vec::new(),
            state_hash: [2u8; 32],
            last_updated: chrono::Utc::now(),
            registered_hotkeys: HashSet::new(),
        };

        let data = bincode::serialize(&v2).unwrap();
        let loaded = deserialize_state_smart(&data).unwrap();
        assert_eq!(loaded.block_height, 150);
    }

    #[test]
    fn test_deserialize_state_smart_current_format() {
        let state = create_test_state();
        // Use versioned serialization (the proper way)
        let data = serialize_state_versioned(&state).unwrap();
        let loaded = deserialize_state_smart(&data).unwrap();
        assert_eq!(loaded.block_height, state.block_height);
    }

    #[test]
    fn test_into_state_version_too_old() {
        // Test the error path when version is too old
        let versioned = VersionedState {
            version: 0, // Version 0 is below MIN_SUPPORTED_VERSION (1)
            data: vec![1, 2, 3],
        };
        let result = versioned.into_state();
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::MiniChainError::Serialization(msg) => {
                assert!(msg.contains("too old"));
                assert!(msg.contains("minimum supported"));
            }
            _ => panic!("Expected Serialization error"),
        }
    }

    #[test]
    fn test_migrate_state_v1_deserialization_error() {
        // Test that V1 migration handles deserialization errors
        let bad_data = vec![0xFF, 0xFF, 0xFF]; // Invalid bincode data
        let result = migrate_state(1, &bad_data);
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::MiniChainError::Serialization(msg) => {
                assert!(msg.contains("V1 migration failed"));
            }
            _ => panic!("Expected Serialization error"),
        }
    }

    #[test]
    fn test_migrate_state_v2_deserialization_error() {
        // Test that V2 migration handles deserialization errors
        let bad_data = vec![0xFF, 0xFF, 0xFF]; // Invalid bincode data
        let result = migrate_state(2, &bad_data);
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::MiniChainError::Serialization(msg) => {
                assert!(msg.contains("V2 migration failed"));
            }
            _ => panic!("Expected Serialization error"),
        }
    }

    #[test]
    fn test_migrate_state_unknown_version() {
        // Test that unknown version returns error
        let data = vec![1, 2, 3];
        let result = migrate_state(99, &data);
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::MiniChainError::Serialization(msg) => {
                assert!(msg.contains("Unknown state version"));
                assert!(msg.contains("99"));
            }
            _ => panic!("Expected Serialization error"),
        }
    }

    #[test]
    fn test_deserialize_state_smart_all_strategies_fail() {
        // Test that when all deserialization strategies fail, we get proper error
        let bad_data = vec![0xFF; 100]; // Completely invalid data
        let result = deserialize_state_smart(&bad_data);
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::MiniChainError::Serialization(msg) => {
                assert!(msg.contains("Failed to deserialize state"));
                assert!(msg.contains("incompatible format"));
            }
            _ => panic!("Expected Serialization error"),
        }
    }
}
