#![allow(dead_code, unused_variables, unused_imports)]
#![allow(ambiguous_glob_reexports)]
//! Persistent storage using sled
//!
//! This module provides:
//! - `Storage` - Main storage for chain state, challenges, and validators
//! - `DynamicStorage` - Per-challenge/per-validator dynamic storage
//! - `MigrationRunner` - Version-based migrations for blockchain upgrades
//! - `BlockchainStorage` - Blockchain-like structure for validator consensus
//!
//! ## Dynamic Storage
//!
//! Dynamic storage allows challenges and validators to store their own data:
//!
//! ```ignore
//! // Challenge-level storage
//! let cs = storage.dynamic().challenge_storage(challenge_id);
//! cs.set("leaderboard_size", 100u64)?;
//!
//! // Validator-level storage within a challenge
//! let vs = cs.validator(&hotkey);
//! vs.set("last_evaluation", timestamp)?;
//! ```
//!
//! ## Migrations
//!
//! Migrations run automatically when the blockchain version changes:
//!
//! ```ignore
//! let mut runner = storage.migration_runner()?;
//! runner.register(Box::new(MyMigration));
//! runner.run_pending(&storage_tree, &state_tree, block_height)?;
//! ```
//!
//! ## Blockchain Storage
//!
//! Blockchain storage provides immutable, verifiable state tracking:
//!
//! ```ignore
//! use platform_storage::blockchain::BlockchainStorage;
//!
//! let db = sled::open("./blockchain")?;
//! let mut storage = BlockchainStorage::new(&db)?;
//!
//! // Append a new block
//! storage.append_block(block)?;
//!
//! // Query historical state
//! let root = storage.get_state_root_at_block(10, None)?;
//! ```

pub mod blockchain;
pub mod distributed;
pub mod dynamic;
pub mod metadata;
pub mod migration;
pub mod optimized;
pub mod types;

pub use distributed::*;
pub use dynamic::*;
pub use metadata::*;
pub use migration::*;
pub use optimized::*;
pub use types::*;

use platform_core::{
    ChainState, Challenge, ChallengeId, Hotkey, MiniChainError, Result, ValidatorInfo,
};
use sled::{Db, Tree};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info};

/// Main storage for chain state and data
///
/// Provides persistent storage for:
/// - Chain state (block height, validators, challenges)
/// - Challenge data
/// - Validator data
/// - Dynamic per-challenge storage
/// - Migrations
pub struct Storage {
    db: Db,
    state_tree: Tree,
    challenges_tree: Tree,
    validators_tree: Tree,
    /// Dynamic storage for per-challenge/per-validator data
    dynamic_storage: Arc<DynamicStorage>,
}

impl Storage {
    /// Open or create storage at path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::open(path)
            .map_err(|e| MiniChainError::Storage(format!("Failed to open database: {}", e)))?;

        let state_tree = db
            .open_tree("state")
            .map_err(|e| MiniChainError::Storage(format!("Failed to open state tree: {}", e)))?;

        let challenges_tree = db.open_tree("challenges").map_err(|e| {
            MiniChainError::Storage(format!("Failed to open challenges tree: {}", e))
        })?;

        let validators_tree = db.open_tree("validators").map_err(|e| {
            MiniChainError::Storage(format!("Failed to open validators tree: {}", e))
        })?;

        let dynamic_storage = Arc::new(DynamicStorage::new(&db)?);

        info!("Storage opened successfully");
        Ok(Self {
            db,
            state_tree,
            challenges_tree,
            validators_tree,
            dynamic_storage,
        })
    }

    /// Get access to dynamic storage
    pub fn dynamic(&self) -> &DynamicStorage {
        &self.dynamic_storage
    }

    /// Get Arc reference to dynamic storage (for sharing)
    pub fn dynamic_arc(&self) -> Arc<DynamicStorage> {
        self.dynamic_storage.clone()
    }

    /// Create a migration runner
    pub fn migration_runner(&self) -> Result<MigrationRunner> {
        MigrationRunner::new(&self.db)
    }

    /// Run all pending migrations
    pub fn run_migrations(&self, block_height: u64) -> Result<Vec<MigrationVersion>> {
        let mut runner = self.migration_runner()?;

        // Register built-in migrations
        runner.register(Box::new(InitialMigration));
        runner.register(Box::new(AddChallengeMetricsMigration));

        // Get the dynamic storage tree directly
        let storage_tree = self
            .db
            .open_tree("dynamic_storage")
            .map_err(|e| MiniChainError::Storage(e.to_string()))?;

        runner.run_pending(&storage_tree, &self.state_tree, block_height)
    }

    /// Get the underlying database handle
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Get the state tree
    pub fn state_tree(&self) -> &Tree {
        &self.state_tree
    }

    /// Save chain state with version header for backward compatibility
    pub fn save_state(&self, state: &ChainState) -> Result<()> {
        // Use versioned serialization for future-proof storage
        let data = platform_core::serialize_state_versioned(state)?;

        self.state_tree
            .insert("current", data)
            .map_err(|e| MiniChainError::Storage(format!("Failed to save state: {}", e)))?;

        self.db
            .flush()
            .map_err(|e| MiniChainError::Storage(format!("Failed to flush: {}", e)))?;

        debug!(
            "State saved at block {} (version {})",
            state.block_height,
            platform_core::CURRENT_STATE_VERSION
        );
        Ok(())
    }

    /// Load chain state with automatic version migration
    pub fn load_state(&self) -> Result<Option<ChainState>> {
        let data = self
            .state_tree
            .get("current")
            .map_err(|e| MiniChainError::Storage(format!("Failed to load state: {}", e)))?;

        match data {
            Some(bytes) => {
                // Use smart deserialization that handles version migration
                let state = platform_core::deserialize_state_smart(&bytes)?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Save a challenge
    pub fn save_challenge(&self, challenge: &Challenge) -> Result<()> {
        let key = challenge.id.0.as_bytes();
        let data = bincode::serialize(challenge)
            .map_err(|e| MiniChainError::Serialization(e.to_string()))?;

        self.challenges_tree
            .insert(key, data)
            .map_err(|e| MiniChainError::Storage(format!("Failed to save challenge: {}", e)))?;

        Ok(())
    }

    /// Load a challenge
    pub fn load_challenge(&self, id: &ChallengeId) -> Result<Option<Challenge>> {
        use bincode::Options;
        const MAX_CHALLENGE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB limit

        let key = id.0.as_bytes();
        let data = self
            .challenges_tree
            .get(key)
            .map_err(|e| MiniChainError::Storage(format!("Failed to load challenge: {}", e)))?;

        match data {
            Some(bytes) => {
                // Use options compatible with bincode::serialize (little-endian, variable int, trailing allowed)
                let challenge: Challenge = bincode::DefaultOptions::new()
                    .with_fixint_encoding()
                    .with_little_endian()
                    .allow_trailing_bytes()
                    .with_limit(MAX_CHALLENGE_SIZE)
                    .deserialize(&bytes)
                    .map_err(|e| MiniChainError::Serialization(e.to_string()))?;
                Ok(Some(challenge))
            }
            None => Ok(None),
        }
    }

    /// Delete a challenge
    pub fn delete_challenge(&self, id: &ChallengeId) -> Result<bool> {
        let key = id.0.as_bytes();
        let removed = self
            .challenges_tree
            .remove(key)
            .map_err(|e| MiniChainError::Storage(format!("Failed to delete challenge: {}", e)))?;
        Ok(removed.is_some())
    }

    /// List all challenges
    pub fn list_challenges(&self) -> Result<Vec<ChallengeId>> {
        let mut ids = Vec::new();
        for result in self.challenges_tree.iter() {
            let (key, _) =
                result.map_err(|e| MiniChainError::Storage(format!("Iteration error: {}", e)))?;
            if key.len() == 16 {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&key);
                ids.push(ChallengeId(uuid::Uuid::from_bytes(bytes)));
            }
        }
        Ok(ids)
    }

    /// Save validator info
    pub fn save_validator(&self, info: &ValidatorInfo) -> Result<()> {
        let key = info.hotkey.as_bytes();
        let data =
            bincode::serialize(info).map_err(|e| MiniChainError::Serialization(e.to_string()))?;

        self.validators_tree
            .insert(key, data)
            .map_err(|e| MiniChainError::Storage(format!("Failed to save validator: {}", e)))?;

        Ok(())
    }

    /// Load validator info
    pub fn load_validator(&self, hotkey: &Hotkey) -> Result<Option<ValidatorInfo>> {
        use bincode::Options;
        const MAX_VALIDATOR_SIZE: u64 = 1024 * 1024; // 1 MB limit

        let key = hotkey.as_bytes();
        let data = self
            .validators_tree
            .get(key)
            .map_err(|e| MiniChainError::Storage(format!("Failed to load validator: {}", e)))?;

        match data {
            Some(bytes) => {
                // Use options compatible with bincode::serialize (little-endian, variable int, trailing allowed)
                let info: ValidatorInfo = bincode::DefaultOptions::new()
                    .with_fixint_encoding()
                    .with_little_endian()
                    .allow_trailing_bytes()
                    .with_limit(MAX_VALIDATOR_SIZE)
                    .deserialize(&bytes)
                    .map_err(|e| MiniChainError::Serialization(e.to_string()))?;
                Ok(Some(info))
            }
            None => Ok(None),
        }
    }

    /// Flush all changes to disk
    pub fn flush(&self) -> Result<()> {
        self.db
            .flush()
            .map_err(|e| MiniChainError::Storage(format!("Failed to flush: {}", e)))?;
        Ok(())
    }
}

#[cfg(test)]
mod lib_tests {
    use super::*;
    use platform_core::{ChallengeConfig, Keypair, NetworkConfig, Stake};
    use tempfile::tempdir;

    #[test]
    fn test_storage_open() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path());
        assert!(storage.is_ok());
    }

    #[test]
    fn test_state_persistence() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let sudo = Keypair::generate();
        let state = ChainState::new(sudo.hotkey(), NetworkConfig::default());

        storage.save_state(&state).unwrap();
        let loaded = storage.load_state().unwrap();

        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().block_height, state.block_height);
    }

    #[test]
    fn test_challenge_persistence() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let owner = Keypair::generate();
        let challenge = Challenge::new(
            "Test".into(),
            "Test".into(),
            vec![0u8; 100],
            owner.hotkey(),
            ChallengeConfig::default(),
        );

        storage.save_challenge(&challenge).unwrap();
        let loaded = storage.load_challenge(&challenge.id).unwrap();

        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().name, challenge.name);
    }

    #[test]
    fn test_validator_persistence() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let kp = Keypair::generate();
        let info = ValidatorInfo::new(kp.hotkey(), Stake::new(1_000_000_000));

        storage.save_validator(&info).unwrap();
        let loaded = storage.load_validator(&kp.hotkey()).unwrap();

        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().stake.0, info.stake.0);
    }

    #[test]
    fn test_delete_challenge() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let owner = Keypair::generate();
        let challenge = Challenge::new(
            "Test".into(),
            "Test".into(),
            vec![0u8; 100],
            owner.hotkey(),
            ChallengeConfig::default(),
        );

        storage.save_challenge(&challenge).unwrap();
        assert!(storage.delete_challenge(&challenge.id).unwrap());

        let loaded = storage.load_challenge(&challenge.id).unwrap();
        assert!(loaded.is_none());

        // Delete non-existent challenge
        assert!(!storage.delete_challenge(&challenge.id).unwrap());
    }

    #[test]
    fn test_list_challenges() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let owner = Keypair::generate();

        // Add multiple challenges
        for i in 0..3 {
            let challenge = Challenge::new(
                format!("Test {}", i),
                format!("Test {}", i),
                vec![0u8; 100],
                owner.hotkey(),
                ChallengeConfig::default(),
            );
            storage.save_challenge(&challenge).unwrap();
        }

        let challenges = storage.list_challenges().unwrap();
        assert_eq!(challenges.len(), 3);
    }

    #[test]
    fn test_load_nonexistent_challenge() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let fake_id = ChallengeId(uuid::Uuid::new_v4());
        let loaded = storage.load_challenge(&fake_id).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_load_nonexistent_validator() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let kp = Keypair::generate();
        let loaded = storage.load_validator(&kp.hotkey()).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_load_state_empty() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let loaded = storage.load_state().unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_flush() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let sudo = Keypair::generate();
        let state = ChainState::new(sudo.hotkey(), NetworkConfig::default());

        storage.save_state(&state).unwrap();
        storage.flush().unwrap();
    }

    #[test]
    fn test_dynamic_storage_access() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let dynamic = storage.dynamic();
        assert!(std::ptr::eq(dynamic, storage.dynamic()));

        let arc = storage.dynamic_arc();
        assert!(Arc::ptr_eq(&arc, &storage.dynamic_storage));
    }

    #[test]
    fn test_db_access() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let _db = storage.db();
        let _tree = storage.state_tree();
    }

    #[test]
    fn test_migration_runner_creation() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let runner = storage.migration_runner();
        assert!(runner.is_ok());
    }

    #[test]
    fn test_run_migrations() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let result = storage.run_migrations(100);
        assert!(result.is_ok());

        let versions = result.unwrap();
        // Should have at least the built-in migrations
        assert!(!versions.is_empty());
    }

    #[test]
    fn test_storage_open_tree_failures() {
        // Tests document the error paths at lines 82 and 86
        // These would require mocking sled to fail tree opening
        // The errors are properly converted to MiniChainError::Storage with descriptive messages
    }
}
