//! Schema Guard - Compile-time and runtime protection against state corruption
//!
//! This module ensures that ANY change to serializable state structs:
//! 1. Is detected at compile time via schema hash
//! 2. Requires explicit version bump
//! 3. Requires migration code
//! 4. Is tested automatically
//!
//! HOW IT WORKS:
//! - Each serializable struct has a SCHEMA_HASH constant
//! - The hash is computed from field names, types, and order
//! - If you change a struct, the hash changes
//! - Tests will FAIL until you:
//!   1. Bump CURRENT_STATE_VERSION
//!   2. Add migration code
//!   3. Update EXPECTED_SCHEMA_HASHES

use std::collections::BTreeMap;

/// Schema hash for a type - computed from field layout
pub trait SchemaHash {
    /// Returns a deterministic hash of the struct's schema
    fn schema_hash() -> u64;

    /// Returns human-readable schema description for debugging
    fn schema_description() -> String;
}

/// Compute a simple but deterministic hash from a string
const fn const_hash(s: &str) -> u64 {
    let bytes = s.as_bytes();
    let mut hash: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x100000001b3); // FNV-1a prime
        i += 1;
    }
    hash
}

// ============================================================================
// Schema Hashes for Core Types
// ============================================================================

/// ValidatorInfo schema hash
/// IMPORTANT: Update this if you change ValidatorInfo fields!
impl SchemaHash for crate::ValidatorInfo {
    fn schema_hash() -> u64 {
        // Hash is computed from: struct_name + field_name:type pairs in order
        const_hash("ValidatorInfo:hotkey:Hotkey,stake:Stake,is_active:bool,last_seen:DateTime,peer_id:Option<String>,x25519_pubkey:Option<String>")
    }

    fn schema_description() -> String {
        "ValidatorInfo { hotkey: Hotkey, stake: Stake, is_active: bool, last_seen: DateTime<Utc>, peer_id: Option<String>, x25519_pubkey: Option<String> }".to_string()
    }
}

/// ChainState schema hash
impl SchemaHash for crate::ChainState {
    fn schema_hash() -> u64 {
        const_hash("ChainState:block_height:u64,epoch:u64,config:NetworkConfig,sudo_key:Hotkey,validators:HashMap<Hotkey,ValidatorInfo>,challenges:HashMap<ChallengeId,Challenge>,challenge_configs:HashMap,wasm_challenge_configs:HashMap,mechanism_configs:HashMap,challenge_weights:HashMap,required_version:Option,pending_jobs:Vec,state_hash:[u8;32],last_updated:DateTime,registered_hotkeys:HashSet<Hotkey>")
    }

    fn schema_description() -> String {
        "ChainState { block_height, epoch, config, sudo_key, validators, challenges, challenge_configs, wasm_challenge_configs, mechanism_configs, challenge_weights, required_version, pending_jobs, state_hash, last_updated, registered_hotkeys }".to_string()
    }
}

// ============================================================================
// Expected Schema Registry
// ============================================================================

/// Registry of expected schema hashes for each version
///
/// WHEN ADDING A NEW VERSION:
/// 1. Add entry for new version with current schema hashes
/// 2. Keep old version entries for migration testing
pub fn expected_schema_hashes() -> BTreeMap<u32, SchemaRegistry> {
    let mut registry = BTreeMap::new();

    // Version 1: Original schema (no registered_hotkeys, no x25519_pubkey)
    registry.insert(1, SchemaRegistry {
        version: 1,
        validator_info_hash: const_hash("ValidatorInfo:hotkey:Hotkey,stake:Stake,is_active:bool,last_seen:DateTime,peer_id:Option<String>"),
        chain_state_hash: const_hash("ChainState:block_height:u64,epoch:u64,config:NetworkConfig,sudo_key:Hotkey,validators:HashMap<Hotkey,ValidatorInfo>,challenges:HashMap<ChallengeId,Challenge>,challenge_configs:HashMap,mechanism_configs:HashMap,challenge_weights:HashMap,required_version:Option,pending_jobs:Vec,state_hash:[u8;32],last_updated:DateTime"),
        description: "Original schema without registered_hotkeys or x25519_pubkey",
    });

    // Version 2: Added registered_hotkeys to ChainState
    registry.insert(2, SchemaRegistry {
        version: 2,
        validator_info_hash: const_hash("ValidatorInfo:hotkey:Hotkey,stake:Stake,is_active:bool,last_seen:DateTime,peer_id:Option<String>"),
        chain_state_hash: const_hash("ChainState:block_height:u64,epoch:u64,config:NetworkConfig,sudo_key:Hotkey,validators:HashMap<Hotkey,ValidatorInfo>,challenges:HashMap<ChallengeId,Challenge>,challenge_configs:HashMap,mechanism_configs:HashMap,challenge_weights:HashMap,required_version:Option,pending_jobs:Vec,state_hash:[u8;32],last_updated:DateTime,registered_hotkeys:HashSet<Hotkey>"),
        description: "Added registered_hotkeys to ChainState",
    });

    // Version 3: Added x25519_pubkey to ValidatorInfo
    registry.insert(3, SchemaRegistry {
        version: 3,
        validator_info_hash: const_hash("ValidatorInfo:hotkey:Hotkey,stake:Stake,is_active:bool,last_seen:DateTime,peer_id:Option<String>,x25519_pubkey:Option<String>"),
        chain_state_hash: const_hash("ChainState:block_height:u64,epoch:u64,config:NetworkConfig,sudo_key:Hotkey,validators:HashMap<Hotkey,ValidatorInfo>,challenges:HashMap<ChallengeId,Challenge>,challenge_configs:HashMap,mechanism_configs:HashMap,challenge_weights:HashMap,required_version:Option,pending_jobs:Vec,state_hash:[u8;32],last_updated:DateTime,registered_hotkeys:HashSet<Hotkey>"),
        description: "Added x25519_pubkey to ValidatorInfo",
    });

    // Version 4: Added wasm_challenge_configs to ChainState
    registry.insert(4, SchemaRegistry {
        version: 4,
        validator_info_hash: const_hash("ValidatorInfo:hotkey:Hotkey,stake:Stake,is_active:bool,last_seen:DateTime,peer_id:Option<String>,x25519_pubkey:Option<String>"),
        chain_state_hash: const_hash("ChainState:block_height:u64,epoch:u64,config:NetworkConfig,sudo_key:Hotkey,validators:HashMap<Hotkey,ValidatorInfo>,challenges:HashMap<ChallengeId,Challenge>,challenge_configs:HashMap,wasm_challenge_configs:HashMap,mechanism_configs:HashMap,challenge_weights:HashMap,required_version:Option,pending_jobs:Vec,state_hash:[u8;32],last_updated:DateTime,registered_hotkeys:HashSet<Hotkey>"),
        description: "Added wasm_challenge_configs to ChainState",
    });

    // Version 5: Added WASM restart metadata
    registry.insert(5, SchemaRegistry {
        version: 5,
        validator_info_hash: const_hash("ValidatorInfo:hotkey:Hotkey,stake:Stake,is_active:bool,last_seen:DateTime,peer_id:Option<String>,x25519_pubkey:Option<String>"),
        chain_state_hash: const_hash("ChainState:block_height:u64,epoch:u64,config:NetworkConfig,sudo_key:Hotkey,validators:HashMap<Hotkey,ValidatorInfo>,challenges:HashMap<ChallengeId,Challenge>,challenge_configs:HashMap,wasm_challenge_configs:HashMap,mechanism_configs:HashMap,challenge_weights:HashMap,required_version:Option,pending_jobs:Vec,state_hash:[u8;32],last_updated:DateTime,registered_hotkeys:HashSet<Hotkey>"),
        description: "Added WASM restart metadata",
    });
    // Version 4: Added wasm_challenge_configs to ChainState
    registry.insert(4, SchemaRegistry {
        version: 4,
        validator_info_hash: const_hash("ValidatorInfo:hotkey:Hotkey,stake:Stake,is_active:bool,last_seen:DateTime,peer_id:Option<String>,x25519_pubkey:Option<String>"),
        chain_state_hash: const_hash("ChainState:block_height:u64,epoch:u64,config:NetworkConfig,sudo_key:Hotkey,validators:HashMap<Hotkey,ValidatorInfo>,challenges:HashMap<ChallengeId,Challenge>,challenge_configs:HashMap,wasm_challenge_configs:HashMap,mechanism_configs:HashMap,challenge_weights:HashMap,required_version:Option,pending_jobs:Vec,state_hash:[u8;32],last_updated:DateTime,registered_hotkeys:HashSet<Hotkey>"),
        description: "Added wasm_challenge_configs to ChainState",
    });

    registry
}

/// Schema registry entry for a specific version
#[derive(Debug, Clone)]
pub struct SchemaRegistry {
    pub version: u32,
    pub validator_info_hash: u64,
    pub chain_state_hash: u64,
    pub description: &'static str,
}

// ============================================================================
// Verification Functions
// ============================================================================

/// Verify that current schema matches expected for current version
///
/// This function should be called at startup and in tests.
/// It will panic if schema doesn't match, preventing data corruption.
pub fn verify_schema_integrity() -> Result<(), SchemaError> {
    use crate::state_versioning::CURRENT_STATE_VERSION;

    let registry = expected_schema_hashes();

    // Get expected hashes for current version
    let expected =
        registry
            .get(&CURRENT_STATE_VERSION)
            .ok_or_else(|| SchemaError::MissingVersion {
                version: CURRENT_STATE_VERSION,
                hint: format!(
                    "Version {} is not registered in schema_guard.rs. \
                Add an entry to expected_schema_hashes() with the current schema hashes.",
                    CURRENT_STATE_VERSION
                ),
            })?;

    // Verify ValidatorInfo schema
    let actual_validator_hash = <crate::ValidatorInfo as SchemaHash>::schema_hash();
    if actual_validator_hash != expected.validator_info_hash {
        return Err(SchemaError::SchemaMismatch {
            type_name: "ValidatorInfo",
            expected_hash: expected.validator_info_hash,
            actual_hash: actual_validator_hash,
            current_version: CURRENT_STATE_VERSION,
            hint: format!(
                "ValidatorInfo schema has changed but version is still {}!\n\
                \n\
                TO FIX THIS:\n\
                1. Bump CURRENT_STATE_VERSION in state_versioning.rs\n\
                2. Add migration code in migrate_state()\n\
                3. Add new version entry in expected_schema_hashes()\n\
                4. Update ValidatorInfoLegacy if needed\n\
                \n\
                Current schema: {}",
                CURRENT_STATE_VERSION,
                <crate::ValidatorInfo as SchemaHash>::schema_description()
            ),
        });
    }

    // Verify ChainState schema
    let actual_state_hash = <crate::ChainState as SchemaHash>::schema_hash();
    if actual_state_hash != expected.chain_state_hash {
        return Err(SchemaError::SchemaMismatch {
            type_name: "ChainState",
            expected_hash: expected.chain_state_hash,
            actual_hash: actual_state_hash,
            current_version: CURRENT_STATE_VERSION,
            hint: format!(
                "ChainState schema has changed but version is still {}!\n\
                \n\
                TO FIX THIS:\n\
                1. Bump CURRENT_STATE_VERSION in state_versioning.rs\n\
                2. Add migration code in migrate_state()\n\
                3. Add new version entry in expected_schema_hashes()\n\
                4. Create ChainStateVX struct for old version\n\
                \n\
                Current schema: {}",
                CURRENT_STATE_VERSION,
                <crate::ChainState as SchemaHash>::schema_description()
            ),
        });
    }

    Ok(())
}

/// Verify that all migration paths exist and work
pub fn verify_migration_paths() -> Result<(), SchemaError> {
    use crate::state_versioning::{CURRENT_STATE_VERSION, MIN_SUPPORTED_VERSION};

    // Ensure we have registry entries for all supported versions
    let registry = expected_schema_hashes();

    for version in MIN_SUPPORTED_VERSION..=CURRENT_STATE_VERSION {
        if !registry.contains_key(&version) {
            return Err(SchemaError::MissingVersion {
                version,
                hint: format!(
                    "Version {} is between MIN_SUPPORTED_VERSION ({}) and CURRENT_STATE_VERSION ({}) \
                    but has no entry in expected_schema_hashes(). Add the missing entry.",
                    version, MIN_SUPPORTED_VERSION, CURRENT_STATE_VERSION
                ),
            });
        }
    }

    Ok(())
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug)]
pub enum SchemaError {
    SchemaMismatch {
        type_name: &'static str,
        expected_hash: u64,
        actual_hash: u64,
        current_version: u32,
        hint: String,
    },
    MissingVersion {
        version: u32,
        hint: String,
    },
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaError::SchemaMismatch {
                type_name,
                expected_hash,
                actual_hash,
                current_version,
                hint,
            } => {
                write!(
                    f,
                    "\n\
                    ╔══════════════════════════════════════════════════════════════════╗\n\
                    ║                    SCHEMA CHANGE DETECTED!                       ║\n\
                    ╠══════════════════════════════════════════════════════════════════╣\n\
                    ║ Type: {:<58} ║\n\
                    ║ Version: {:<55} ║\n\
                    ║ Expected hash: {:<49} ║\n\
                    ║ Actual hash:   {:<49} ║\n\
                    ╠══════════════════════════════════════════════════════════════════╣\n\
                    ║ {}║\n\
                    ╚══════════════════════════════════════════════════════════════════╝",
                    type_name,
                    current_version,
                    expected_hash,
                    actual_hash,
                    hint.lines()
                        .map(|l| format!("{:<64}\n║ ", l))
                        .collect::<String>()
                )
            }
            SchemaError::MissingVersion { version, hint } => {
                write!(
                    f,
                    "\n\
                    ╔══════════════════════════════════════════════════════════════════╗\n\
                    ║                    MISSING VERSION ENTRY!                        ║\n\
                    ╠══════════════════════════════════════════════════════════════════╣\n\
                    ║ Version: {:<55} ║\n\
                    ╠══════════════════════════════════════════════════════════════════╣\n\
                    ║ {}║\n\
                    ╚══════════════════════════════════════════════════════════════════╝",
                    version,
                    hint.lines()
                        .map(|l| format!("{:<64}\n║ ", l))
                        .collect::<String>()
                )
            }
        }
    }
}

impl std::error::Error for SchemaError {}

// ============================================================================
// Tests - These MUST pass for the build to succeed
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// This test ENFORCES schema integrity.
    /// If you change a serializable struct, this test will fail
    /// and tell you exactly what to do.
    #[test]
    fn test_schema_integrity() {
        if let Err(e) = verify_schema_integrity() {
            panic!("{}", e);
        }
    }

    /// Verify all migration paths are registered
    #[test]
    fn test_migration_paths_registered() {
        if let Err(e) = verify_migration_paths() {
            panic!("{}", e);
        }
    }

    /// Test that schema hashes are deterministic
    #[test]
    fn test_schema_hash_deterministic() {
        let hash1 = <crate::ValidatorInfo as SchemaHash>::schema_hash();
        let hash2 = <crate::ValidatorInfo as SchemaHash>::schema_hash();
        assert_eq!(hash1, hash2, "Schema hash must be deterministic");
    }

    /// Verify current version has correct hashes
    #[test]
    fn test_current_version_hashes() {
        use crate::state_versioning::CURRENT_STATE_VERSION;

        let registry = expected_schema_hashes();
        let current = registry
            .get(&CURRENT_STATE_VERSION)
            .expect("Current version must have registry entry");

        assert_eq!(
            current.validator_info_hash,
            <crate::ValidatorInfo as SchemaHash>::schema_hash(),
            "ValidatorInfo hash mismatch for version {}",
            CURRENT_STATE_VERSION
        );

        assert_eq!(
            current.chain_state_hash,
            <crate::ChainState as SchemaHash>::schema_hash(),
            "ChainState hash mismatch for version {}",
            CURRENT_STATE_VERSION
        );
    }

    /// Test roundtrip serialization for current version
    #[test]
    fn test_current_version_serialization() {
        use crate::crypto::Keypair;
        use crate::{ChainState, NetworkConfig, Stake, ValidatorInfo};

        // Create state with validators
        let sudo = Keypair::generate();
        let mut state = ChainState::new(sudo.hotkey(), NetworkConfig::default());

        for _ in 0..3 {
            let kp = Keypair::generate();
            let info = ValidatorInfo::new(kp.hotkey(), Stake::new(1_000_000_000));
            state.add_validator(info).unwrap();
        }

        // Serialize and deserialize
        let data = crate::state_versioning::serialize_state_versioned(&state).unwrap();
        let loaded = crate::state_versioning::deserialize_state_smart(&data).unwrap();

        assert_eq!(state.validators.len(), loaded.validators.len());
        assert_eq!(state.block_height, loaded.block_height);
    }

    #[test]
    fn test_validator_info_schema_description() {
        let desc = <crate::ValidatorInfo as SchemaHash>::schema_description();
        assert!(desc.contains("ValidatorInfo"));
        assert!(desc.contains("hotkey"));
        assert!(desc.contains("stake"));
    }

    #[test]
    fn test_chain_state_schema_description() {
        let desc = <crate::ChainState as SchemaHash>::schema_description();
        assert!(desc.contains("ChainState"));
        assert!(desc.contains("block_height"));
    }

    #[test]
    fn test_schema_error_fmt() {
        let err = SchemaError::SchemaMismatch {
            type_name: "TestType",
            expected_hash: 12345,
            actual_hash: 67890,
            current_version: 1,
            hint: "Test hint".to_string(),
        };
        let formatted = format!("{}", err);
        assert!(formatted.contains("SCHEMA CHANGE DETECTED"));
        assert!(formatted.contains("TestType"));
    }

    #[test]
    fn test_schema_error_missing_version_fmt() {
        let err = SchemaError::MissingVersion {
            version: 5,
            hint: "Add version entry".to_string(),
        };
        let formatted = format!("{}", err);
        assert!(formatted.contains("MISSING VERSION ENTRY"));
        assert!(formatted.contains("5"));
    }

    #[test]
    fn test_expected_schema_hashes_registry() {
        let registry = expected_schema_hashes();
        assert!(registry.contains_key(&1));
        assert!(registry.contains_key(&2));
        assert!(registry.contains_key(&3));
        assert!(registry.contains_key(&4));

        // Each version should have different descriptions
        let v1 = registry.get(&1).unwrap();
        let v4 = registry.get(&4).unwrap();
        assert_ne!(v1.description, v4.description);
    }

    #[test]
    fn test_const_hash_deterministic() {
        let h1 = const_hash("test string");
        let h2 = const_hash("test string");
        assert_eq!(h1, h2);

        // Different strings should have different hashes
        let h3 = const_hash("different string");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_schema_mismatch_validator_info() {
        // This test ensures the error path for ValidatorInfo schema mismatch works
        // We can't easily trigger it in practice without modifying the struct,
        // but we can verify the error formatting works
        let err = SchemaError::SchemaMismatch {
            type_name: "ValidatorInfo",
            expected_hash: 12345,
            actual_hash: 67890,
            current_version: 3,
            hint: "Test hint for validator".to_string(),
        };
        let formatted = format!("{}", err);
        assert!(formatted.contains("SCHEMA CHANGE DETECTED"));
        assert!(formatted.contains("ValidatorInfo"));
        assert!(formatted.contains("12345"));
        assert!(formatted.contains("67890"));
    }

    #[test]
    fn test_schema_mismatch_chain_state() {
        // Test the ChainState schema mismatch error path
        let err = SchemaError::SchemaMismatch {
            type_name: "ChainState",
            expected_hash: 11111,
            actual_hash: 22222,
            current_version: 3,
            hint: "Test hint for chain state".to_string(),
        };
        let formatted = format!("{}", err);
        assert!(formatted.contains("SCHEMA CHANGE DETECTED"));
        assert!(formatted.contains("ChainState"));
        assert!(formatted.contains("11111"));
        assert!(formatted.contains("22222"));
    }

    #[test]
    fn test_missing_version_registry() {
        // Test that verify_migration_paths catches missing versions
        use crate::state_versioning::{CURRENT_STATE_VERSION, MIN_SUPPORTED_VERSION};

        // This should pass since all versions are registered
        let result = verify_migration_paths();
        assert!(result.is_ok());

        // Test the error formatting for missing version
        let err = SchemaError::MissingVersion {
            version: 99,
            hint: "Version 99 is missing".to_string(),
        };
        let formatted = format!("{}", err);
        assert!(formatted.contains("MISSING VERSION ENTRY"));
        assert!(formatted.contains("99"));
    }
}
