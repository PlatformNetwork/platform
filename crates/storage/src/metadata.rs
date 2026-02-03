#![allow(dead_code, unused_variables, unused_imports)]
//! Unified Metadata Registry for Challenge Storage Validation
//!
//! This module provides a centralized registry for tracking:
//! - Schema versions per challenge
//! - Configuration metadata
//! - State versions and merkle roots
//! - Migration status
//!
//! The metadata system enables blockchain-like properties for tracking
//! storage schemas and ensuring state consistency across the validator network.

use platform_core::{ChallengeId, MiniChainError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sled::{Db, Tree};
use std::collections::HashMap;
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Storage format version for challenge data
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageFormat {
    /// Original storage format
    V1,
    /// Updated storage format with improved serialization
    V2,
    /// Challenge-specific custom format
    Custom,
}

impl Default for StorageFormat {
    fn default() -> Self {
        StorageFormat::V1
    }
}

/// Metadata for a single challenge
///
/// Contains all tracking information for a challenge's storage state,
/// including schema version, merkle root, and configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeMetadata {
    /// Unique identifier for the challenge
    pub challenge_id: ChallengeId,
    /// Current schema version for this challenge's data
    pub schema_version: u64,
    /// Storage format used by this challenge
    pub storage_format: StorageFormat,
    /// When this challenge was first registered
    pub created_at: SystemTime,
    /// When this challenge's metadata was last updated
    pub updated_at: SystemTime,
    /// Current merkle root of all challenge state
    pub merkle_root: [u8; 32],
    /// Challenge-specific configuration as JSON string (serialized for bincode compatibility)
    config_json: String,
}

impl ChallengeMetadata {
    /// Create new challenge metadata with default values
    pub fn new(challenge_id: ChallengeId, config: serde_json::Value) -> Self {
        let now = SystemTime::now();
        Self {
            challenge_id,
            schema_version: 1,
            storage_format: StorageFormat::default(),
            created_at: now,
            updated_at: now,
            merkle_root: [0u8; 32],
            config_json: config.to_string(),
        }
    }

    /// Get the challenge configuration as a JSON Value
    pub fn config(&self) -> serde_json::Value {
        serde_json::from_str(&self.config_json).unwrap_or(serde_json::Value::Null)
    }

    /// Set the challenge configuration
    pub fn set_config(&mut self, config: serde_json::Value) {
        self.config_json = config.to_string();
        self.updated_at = SystemTime::now();
    }

    /// Update the merkle root and timestamp
    pub fn update_state_root(&mut self, state_root: [u8; 32]) {
        self.merkle_root = state_root;
        self.updated_at = SystemTime::now();
    }

    /// Update the schema version
    pub fn update_schema_version(&mut self, version: u64) {
        self.schema_version = version;
        self.updated_at = SystemTime::now();
    }
}

/// Global metadata tracking all challenges and network state
///
/// Provides a unified view of the entire storage system including
/// all registered challenges and their combined state root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GlobalMetadata {
    /// Network protocol version string
    pub network_version: String,
    /// Global schema version for the metadata system
    pub schema_version: u64,
    /// When the network was initialized
    pub genesis_timestamp: SystemTime,
    /// Metadata for all registered challenges
    pub challenges: HashMap<ChallengeId, ChallengeMetadata>,
    /// Combined merkle root of all challenge states
    pub global_state_root: [u8; 32],
}

impl GlobalMetadata {
    /// Create new global metadata with default values
    pub fn new(network_version: String) -> Self {
        Self {
            network_version,
            schema_version: 1,
            genesis_timestamp: SystemTime::now(),
            challenges: HashMap::new(),
            global_state_root: [0u8; 32],
        }
    }

    /// Get the number of registered challenges
    pub fn challenge_count(&self) -> usize {
        self.challenges.len()
    }
}

/// Database key prefixes for metadata storage
const METADATA_TREE_NAME: &str = "metadata_registry";
const GLOBAL_METADATA_KEY: &str = "global";
const CHALLENGE_PREFIX: &str = "challenge:";

/// Centralized registry for tracking challenge storage metadata
///
/// The MetadataRegistry provides:
/// - Registration and tracking of challenge metadata
/// - State root computation and validation
/// - Schema version management
/// - Persistence to sled database
///
/// # Example
///
/// ```ignore
/// let registry = MetadataRegistry::new(&db)?;
/// registry.register_challenge(challenge_id, serde_json::json!({}))?;
/// registry.update_challenge_state_root(&challenge_id, state_root)?;
/// ```
pub struct MetadataRegistry {
    /// The metadata storage tree
    tree: Tree,
    /// Cached global metadata (loaded on init)
    global: GlobalMetadata,
}

impl MetadataRegistry {
    /// Create or open a metadata registry
    ///
    /// If the registry already exists in the database, it will be loaded.
    /// Otherwise, a new registry is initialized.
    ///
    /// # Arguments
    ///
    /// * `db` - Reference to the sled database
    ///
    /// # Returns
    ///
    /// A Result containing the MetadataRegistry or an error
    ///
    /// # Errors
    ///
    /// Returns an error if the database tree cannot be opened or if
    /// existing metadata cannot be deserialized.
    pub fn new(db: &Db) -> Result<Self> {
        let tree = db
            .open_tree(METADATA_TREE_NAME)
            .map_err(|e| MiniChainError::Storage(format!("Failed to open metadata tree: {}", e)))?;

        // Try to load existing global metadata, or create new
        let global = match tree.get(GLOBAL_METADATA_KEY) {
            Ok(Some(data)) => bincode::deserialize(&data).map_err(|e| {
                MiniChainError::Serialization(format!(
                    "Failed to deserialize global metadata: {}",
                    e
                ))
            })?,
            Ok(None) => {
                info!("Initializing new metadata registry");
                let global = GlobalMetadata::new("1.0.0".to_string());
                let data = bincode::serialize(&global).map_err(|e| {
                    MiniChainError::Serialization(format!(
                        "Failed to serialize global metadata: {}",
                        e
                    ))
                })?;
                tree.insert(GLOBAL_METADATA_KEY, data).map_err(|e| {
                    MiniChainError::Storage(format!("Failed to persist global metadata: {}", e))
                })?;
                global
            }
            Err(e) => {
                return Err(MiniChainError::Storage(format!(
                    "Failed to read global metadata: {}",
                    e
                )));
            }
        };

        debug!(
            "Metadata registry loaded with {} challenges",
            global.challenge_count()
        );

        Ok(Self { tree, global })
    }

    /// Register a new challenge in the metadata registry
    ///
    /// Creates metadata for a new challenge and persists it to storage.
    /// If the challenge already exists, returns an error.
    ///
    /// # Arguments
    ///
    /// * `challenge_id` - Unique identifier for the challenge
    /// * `config` - Challenge-specific configuration as JSON
    ///
    /// # Returns
    ///
    /// Ok(()) on success, or an error if the challenge already exists
    /// or persistence fails.
    pub fn register_challenge(
        &mut self,
        challenge_id: ChallengeId,
        config: serde_json::Value,
    ) -> Result<()> {
        // Check if challenge already exists
        if self.global.challenges.contains_key(&challenge_id) {
            return Err(MiniChainError::Validation(format!(
                "Challenge {} is already registered",
                challenge_id
            )));
        }

        let metadata = ChallengeMetadata::new(challenge_id, config);

        // Persist challenge metadata
        let key = format!("{}{}", CHALLENGE_PREFIX, challenge_id);
        let data = bincode::serialize(&metadata).map_err(|e| {
            MiniChainError::Serialization(format!("Failed to serialize challenge metadata: {}", e))
        })?;
        self.tree.insert(key.as_bytes(), data).map_err(|e| {
            MiniChainError::Storage(format!("Failed to persist challenge metadata: {}", e))
        })?;

        // Update global metadata
        self.global.challenges.insert(challenge_id, metadata);
        self.persist_global()?;

        info!("Registered challenge {}", challenge_id);
        Ok(())
    }

    /// Update the state root for a challenge
    ///
    /// Updates the merkle root representing the current state of a challenge
    /// and recomputes the global state root.
    ///
    /// # Arguments
    ///
    /// * `challenge_id` - The challenge to update
    /// * `state_root` - The new merkle root for the challenge state
    ///
    /// # Returns
    ///
    /// Ok(()) on success, or an error if the challenge is not found
    /// or persistence fails.
    pub fn update_challenge_state_root(
        &mut self,
        challenge_id: &ChallengeId,
        state_root: [u8; 32],
    ) -> Result<()> {
        let metadata = self
            .global
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| {
                MiniChainError::NotFound(format!("Challenge {} not found", challenge_id))
            })?;

        metadata.update_state_root(state_root);

        // Persist challenge metadata
        let key = format!("{}{}", CHALLENGE_PREFIX, challenge_id);
        let data = bincode::serialize(metadata).map_err(|e| {
            MiniChainError::Serialization(format!("Failed to serialize challenge metadata: {}", e))
        })?;
        self.tree.insert(key.as_bytes(), data).map_err(|e| {
            MiniChainError::Storage(format!("Failed to persist challenge metadata: {}", e))
        })?;

        // Recompute global state root
        self.global.global_state_root = self.compute_global_state_root();
        self.persist_global()?;

        debug!(
            "Updated state root for challenge {}: {:02x}{:02x}{:02x}{:02x}...",
            challenge_id, state_root[0], state_root[1], state_root[2], state_root[3]
        );
        Ok(())
    }

    /// Get metadata for a specific challenge
    ///
    /// # Arguments
    ///
    /// * `challenge_id` - The challenge to look up
    ///
    /// # Returns
    ///
    /// Ok(Some(metadata)) if found, Ok(None) if not found,
    /// or an error if deserialization fails.
    pub fn get_challenge_metadata(
        &self,
        challenge_id: &ChallengeId,
    ) -> Result<Option<ChallengeMetadata>> {
        Ok(self.global.challenges.get(challenge_id).cloned())
    }

    /// Compute the combined merkle root of all challenge states
    ///
    /// Creates a deterministic hash by sorting challenges by ID and
    /// hashing their merkle roots together.
    ///
    /// # Returns
    ///
    /// A 32-byte hash representing the combined state of all challenges.
    pub fn compute_global_state_root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Sort challenges by ID for deterministic ordering
        let mut challenge_ids: Vec<_> = self.global.challenges.keys().collect();
        challenge_ids.sort_by_key(|id| id.0);

        for challenge_id in challenge_ids {
            if let Some(metadata) = self.global.challenges.get(challenge_id) {
                // Include challenge ID in hash
                hasher.update(challenge_id.0.as_bytes());
                // Include challenge merkle root
                hasher.update(&metadata.merkle_root);
            }
        }

        hasher.finalize().into()
    }

    /// Validate that a challenge's state root matches an expected value
    ///
    /// # Arguments
    ///
    /// * `challenge_id` - The challenge to validate
    /// * `expected_root` - The expected merkle root
    ///
    /// # Returns
    ///
    /// `true` if the challenge exists and its state root matches,
    /// `false` otherwise.
    pub fn validate_state_root(&self, challenge_id: &ChallengeId, expected_root: [u8; 32]) -> bool {
        self.global
            .challenges
            .get(challenge_id)
            .map(|m| m.merkle_root == expected_root)
            .unwrap_or(false)
    }

    /// List all registered challenge IDs
    ///
    /// # Returns
    ///
    /// A vector of all registered challenge IDs.
    pub fn list_challenges(&self) -> Vec<ChallengeId> {
        self.global.challenges.keys().copied().collect()
    }

    /// Get the schema version for a specific challenge
    ///
    /// # Arguments
    ///
    /// * `challenge_id` - The challenge to look up
    ///
    /// # Returns
    ///
    /// The schema version if the challenge exists, None otherwise.
    pub fn get_schema_version(&self, challenge_id: &ChallengeId) -> Option<u64> {
        self.global
            .challenges
            .get(challenge_id)
            .map(|m| m.schema_version)
    }

    /// Get the current global metadata
    ///
    /// # Returns
    ///
    /// A reference to the global metadata.
    pub fn global_metadata(&self) -> &GlobalMetadata {
        &self.global
    }

    /// Update the schema version for a challenge
    ///
    /// # Arguments
    ///
    /// * `challenge_id` - The challenge to update
    /// * `version` - The new schema version
    ///
    /// # Returns
    ///
    /// Ok(()) on success, or an error if the challenge is not found.
    pub fn update_schema_version(
        &mut self,
        challenge_id: &ChallengeId,
        version: u64,
    ) -> Result<()> {
        let metadata = self
            .global
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| {
                MiniChainError::NotFound(format!("Challenge {} not found", challenge_id))
            })?;

        metadata.update_schema_version(version);

        // Persist challenge metadata
        let key = format!("{}{}", CHALLENGE_PREFIX, challenge_id);
        let data = bincode::serialize(metadata).map_err(|e| {
            MiniChainError::Serialization(format!("Failed to serialize challenge metadata: {}", e))
        })?;
        self.tree.insert(key.as_bytes(), data).map_err(|e| {
            MiniChainError::Storage(format!("Failed to persist challenge metadata: {}", e))
        })?;

        self.persist_global()?;

        info!(
            "Updated schema version for challenge {} to {}",
            challenge_id, version
        );
        Ok(())
    }

    /// Remove a challenge from the registry
    ///
    /// # Arguments
    ///
    /// * `challenge_id` - The challenge to remove
    ///
    /// # Returns
    ///
    /// Ok(true) if the challenge was removed, Ok(false) if it didn't exist.
    pub fn unregister_challenge(&mut self, challenge_id: &ChallengeId) -> Result<bool> {
        if self.global.challenges.remove(challenge_id).is_none() {
            return Ok(false);
        }

        // Remove from storage
        let key = format!("{}{}", CHALLENGE_PREFIX, challenge_id);
        self.tree.remove(key.as_bytes()).map_err(|e| {
            MiniChainError::Storage(format!("Failed to remove challenge metadata: {}", e))
        })?;

        // Update global state
        self.global.global_state_root = self.compute_global_state_root();
        self.persist_global()?;

        info!("Unregistered challenge {}", challenge_id);
        Ok(true)
    }

    /// Flush all pending changes to disk
    pub fn flush(&self) -> Result<()> {
        self.tree
            .flush()
            .map_err(|e| MiniChainError::Storage(format!("Failed to flush metadata: {}", e)))?;
        Ok(())
    }

    /// Persist global metadata to storage
    fn persist_global(&self) -> Result<()> {
        let data = bincode::serialize(&self.global).map_err(|e| {
            MiniChainError::Serialization(format!("Failed to serialize global metadata: {}", e))
        })?;
        self.tree.insert(GLOBAL_METADATA_KEY, data).map_err(|e| {
            MiniChainError::Storage(format!("Failed to persist global metadata: {}", e))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_db() -> sled::Db {
        let dir = tempdir().expect("Failed to create temp dir");
        sled::open(dir.path()).expect("Failed to open sled db")
    }

    #[test]
    fn test_metadata_registry_new() {
        let db = create_test_db();
        let registry = MetadataRegistry::new(&db);
        assert!(registry.is_ok());

        let registry = registry.unwrap();
        assert_eq!(registry.global.challenge_count(), 0);
        assert_eq!(registry.global.network_version, "1.0.0");
    }

    #[test]
    fn test_metadata_registry_persistence() {
        let dir = tempdir().expect("Failed to create temp dir");
        let challenge_id = ChallengeId::new();

        // Create and register challenge
        {
            let db = sled::open(dir.path()).expect("Failed to open sled db");
            let mut registry = MetadataRegistry::new(&db).unwrap();
            registry
                .register_challenge(challenge_id, serde_json::json!({"key": "value"}))
                .unwrap();
            registry.flush().unwrap();
        }

        // Reopen and verify
        {
            let db = sled::open(dir.path()).expect("Failed to open sled db");
            let registry = MetadataRegistry::new(&db).unwrap();
            assert_eq!(registry.global.challenge_count(), 1);

            let metadata = registry.get_challenge_metadata(&challenge_id).unwrap();
            assert!(metadata.is_some());
            let metadata = metadata.unwrap();
            assert_eq!(metadata.challenge_id, challenge_id);
        }
    }

    #[test]
    fn test_register_challenge() {
        let db = create_test_db();
        let mut registry = MetadataRegistry::new(&db).unwrap();

        let challenge_id = ChallengeId::new();
        let config = serde_json::json!({
            "timeout": 3600,
            "max_submissions": 100
        });

        let result = registry.register_challenge(challenge_id, config.clone());
        assert!(result.is_ok());

        // Verify registration
        let metadata = registry.get_challenge_metadata(&challenge_id).unwrap();
        assert!(metadata.is_some());
        let metadata = metadata.unwrap();
        assert_eq!(metadata.challenge_id, challenge_id);
        assert_eq!(metadata.schema_version, 1);
        assert_eq!(metadata.storage_format, StorageFormat::V1);
        assert_eq!(metadata.config(), config);
    }

    #[test]
    fn test_register_duplicate_challenge() {
        let db = create_test_db();
        let mut registry = MetadataRegistry::new(&db).unwrap();

        let challenge_id = ChallengeId::new();
        registry
            .register_challenge(challenge_id, serde_json::json!({}))
            .unwrap();

        // Try to register again
        let result = registry.register_challenge(challenge_id, serde_json::json!({}));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MiniChainError::Validation(_)));
    }

    #[test]
    fn test_update_challenge_state_root() {
        let db = create_test_db();
        let mut registry = MetadataRegistry::new(&db).unwrap();

        let challenge_id = ChallengeId::new();
        registry
            .register_challenge(challenge_id, serde_json::json!({}))
            .unwrap();

        let state_root = [42u8; 32];
        let result = registry.update_challenge_state_root(&challenge_id, state_root);
        assert!(result.is_ok());

        // Verify update
        let metadata = registry
            .get_challenge_metadata(&challenge_id)
            .unwrap()
            .unwrap();
        assert_eq!(metadata.merkle_root, state_root);
    }

    #[test]
    fn test_update_nonexistent_challenge_state_root() {
        let db = create_test_db();
        let mut registry = MetadataRegistry::new(&db).unwrap();

        let challenge_id = ChallengeId::new();
        let result = registry.update_challenge_state_root(&challenge_id, [0u8; 32]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MiniChainError::NotFound(_)));
    }

    #[test]
    fn test_get_challenge_metadata_not_found() {
        let db = create_test_db();
        let registry = MetadataRegistry::new(&db).unwrap();

        let challenge_id = ChallengeId::new();
        let metadata = registry.get_challenge_metadata(&challenge_id).unwrap();
        assert!(metadata.is_none());
    }

    #[test]
    fn test_compute_global_state_root() {
        let db = create_test_db();
        let mut registry = MetadataRegistry::new(&db).unwrap();

        // Empty registry should have consistent hash
        let root1 = registry.compute_global_state_root();

        // Add a challenge
        let challenge_id = ChallengeId::new();
        registry
            .register_challenge(challenge_id, serde_json::json!({}))
            .unwrap();

        // Hash should change
        let root2 = registry.compute_global_state_root();
        assert_ne!(root1, root2);

        // Update state root
        registry
            .update_challenge_state_root(&challenge_id, [1u8; 32])
            .unwrap();

        // Hash should change again
        let root3 = registry.compute_global_state_root();
        assert_ne!(root2, root3);
    }

    #[test]
    fn test_compute_global_state_root_deterministic() {
        let db = create_test_db();
        let mut registry = MetadataRegistry::new(&db).unwrap();

        let challenge_id1 = ChallengeId::new();
        let challenge_id2 = ChallengeId::new();

        registry
            .register_challenge(challenge_id1, serde_json::json!({}))
            .unwrap();
        registry
            .register_challenge(challenge_id2, serde_json::json!({}))
            .unwrap();

        // Should be deterministic
        let root1 = registry.compute_global_state_root();
        let root2 = registry.compute_global_state_root();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_validate_state_root() {
        let db = create_test_db();
        let mut registry = MetadataRegistry::new(&db).unwrap();

        let challenge_id = ChallengeId::new();
        registry
            .register_challenge(challenge_id, serde_json::json!({}))
            .unwrap();

        let state_root = [123u8; 32];
        registry
            .update_challenge_state_root(&challenge_id, state_root)
            .unwrap();

        // Valid root
        assert!(registry.validate_state_root(&challenge_id, state_root));

        // Invalid root
        assert!(!registry.validate_state_root(&challenge_id, [0u8; 32]));

        // Non-existent challenge
        let fake_id = ChallengeId::new();
        assert!(!registry.validate_state_root(&fake_id, state_root));
    }

    #[test]
    fn test_list_challenges() {
        let db = create_test_db();
        let mut registry = MetadataRegistry::new(&db).unwrap();

        assert!(registry.list_challenges().is_empty());

        let challenge_id1 = ChallengeId::new();
        let challenge_id2 = ChallengeId::new();

        registry
            .register_challenge(challenge_id1, serde_json::json!({}))
            .unwrap();
        registry
            .register_challenge(challenge_id2, serde_json::json!({}))
            .unwrap();

        let challenges = registry.list_challenges();
        assert_eq!(challenges.len(), 2);
        assert!(challenges.contains(&challenge_id1));
        assert!(challenges.contains(&challenge_id2));
    }

    #[test]
    fn test_get_schema_version() {
        let db = create_test_db();
        let mut registry = MetadataRegistry::new(&db).unwrap();

        let challenge_id = ChallengeId::new();
        registry
            .register_challenge(challenge_id, serde_json::json!({}))
            .unwrap();

        assert_eq!(registry.get_schema_version(&challenge_id), Some(1));

        // Non-existent challenge
        let fake_id = ChallengeId::new();
        assert_eq!(registry.get_schema_version(&fake_id), None);
    }

    #[test]
    fn test_update_schema_version() {
        let db = create_test_db();
        let mut registry = MetadataRegistry::new(&db).unwrap();

        let challenge_id = ChallengeId::new();
        registry
            .register_challenge(challenge_id, serde_json::json!({}))
            .unwrap();

        let result = registry.update_schema_version(&challenge_id, 2);
        assert!(result.is_ok());

        assert_eq!(registry.get_schema_version(&challenge_id), Some(2));
    }

    #[test]
    fn test_update_schema_version_not_found() {
        let db = create_test_db();
        let mut registry = MetadataRegistry::new(&db).unwrap();

        let challenge_id = ChallengeId::new();
        let result = registry.update_schema_version(&challenge_id, 2);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MiniChainError::NotFound(_)));
    }

    #[test]
    fn test_unregister_challenge() {
        let db = create_test_db();
        let mut registry = MetadataRegistry::new(&db).unwrap();

        let challenge_id = ChallengeId::new();
        registry
            .register_challenge(challenge_id, serde_json::json!({}))
            .unwrap();

        assert_eq!(registry.list_challenges().len(), 1);

        let result = registry.unregister_challenge(&challenge_id);
        assert!(result.is_ok());
        assert!(result.unwrap());

        assert!(registry.list_challenges().is_empty());
        assert!(registry
            .get_challenge_metadata(&challenge_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_unregister_nonexistent_challenge() {
        let db = create_test_db();
        let mut registry = MetadataRegistry::new(&db).unwrap();

        let challenge_id = ChallengeId::new();
        let result = registry.unregister_challenge(&challenge_id);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_global_metadata_accessor() {
        let db = create_test_db();
        let registry = MetadataRegistry::new(&db).unwrap();

        let global = registry.global_metadata();
        assert_eq!(global.network_version, "1.0.0");
        assert_eq!(global.schema_version, 1);
    }

    #[test]
    fn test_storage_format_default() {
        assert_eq!(StorageFormat::default(), StorageFormat::V1);
    }

    #[test]
    fn test_storage_format_variants() {
        let v1 = StorageFormat::V1;
        let v2 = StorageFormat::V2;
        let custom = StorageFormat::Custom;

        assert_ne!(v1, v2);
        assert_ne!(v2, custom);
        assert_ne!(v1, custom);
    }

    #[test]
    fn test_challenge_metadata_new() {
        let challenge_id = ChallengeId::new();
        let config = serde_json::json!({"test": true});
        let metadata = ChallengeMetadata::new(challenge_id, config.clone());

        assert_eq!(metadata.challenge_id, challenge_id);
        assert_eq!(metadata.schema_version, 1);
        assert_eq!(metadata.storage_format, StorageFormat::V1);
        assert_eq!(metadata.merkle_root, [0u8; 32]);
        assert_eq!(metadata.config(), config);
    }

    #[test]
    fn test_challenge_metadata_update_state_root() {
        let challenge_id = ChallengeId::new();
        let mut metadata = ChallengeMetadata::new(challenge_id, serde_json::json!({}));

        let initial_updated_at = metadata.updated_at;
        std::thread::sleep(std::time::Duration::from_millis(10));

        let new_root = [99u8; 32];
        metadata.update_state_root(new_root);

        assert_eq!(metadata.merkle_root, new_root);
        assert!(metadata.updated_at > initial_updated_at);
    }

    #[test]
    fn test_challenge_metadata_update_schema_version() {
        let challenge_id = ChallengeId::new();
        let mut metadata = ChallengeMetadata::new(challenge_id, serde_json::json!({}));

        let initial_updated_at = metadata.updated_at;
        std::thread::sleep(std::time::Duration::from_millis(10));

        metadata.update_schema_version(5);

        assert_eq!(metadata.schema_version, 5);
        assert!(metadata.updated_at > initial_updated_at);
    }

    #[test]
    fn test_global_metadata_new() {
        let global = GlobalMetadata::new("2.0.0".to_string());

        assert_eq!(global.network_version, "2.0.0");
        assert_eq!(global.schema_version, 1);
        assert!(global.challenges.is_empty());
        assert_eq!(global.global_state_root, [0u8; 32]);
    }

    #[test]
    fn test_global_metadata_challenge_count() {
        let mut global = GlobalMetadata::new("1.0.0".to_string());
        assert_eq!(global.challenge_count(), 0);

        let challenge_id = ChallengeId::new();
        global.challenges.insert(
            challenge_id,
            ChallengeMetadata::new(challenge_id, serde_json::json!({})),
        );
        assert_eq!(global.challenge_count(), 1);
    }

    #[test]
    fn test_metadata_serialization() {
        let challenge_id = ChallengeId::new();
        let metadata = ChallengeMetadata::new(
            challenge_id,
            serde_json::json!({
                "timeout": 60,
                "nested": {"key": "value"}
            }),
        );

        let serialized = bincode::serialize(&metadata);
        assert!(serialized.is_ok());

        let deserialized: std::result::Result<ChallengeMetadata, _> =
            bincode::deserialize(&serialized.unwrap());
        assert!(deserialized.is_ok());

        let deserialized = deserialized.unwrap();
        assert_eq!(deserialized.challenge_id, challenge_id);
    }

    #[test]
    fn test_global_metadata_serialization() {
        let mut global = GlobalMetadata::new("1.0.0".to_string());
        let challenge_id = ChallengeId::new();
        global.challenges.insert(
            challenge_id,
            ChallengeMetadata::new(challenge_id, serde_json::json!({})),
        );

        let serialized = bincode::serialize(&global);
        assert!(serialized.is_ok());

        let deserialized: std::result::Result<GlobalMetadata, _> =
            bincode::deserialize(&serialized.unwrap());
        assert!(deserialized.is_ok());

        let deserialized = deserialized.unwrap();
        assert_eq!(deserialized.challenge_count(), 1);
    }

    #[test]
    fn test_flush() {
        let db = create_test_db();
        let mut registry = MetadataRegistry::new(&db).unwrap();

        let challenge_id = ChallengeId::new();
        registry
            .register_challenge(challenge_id, serde_json::json!({}))
            .unwrap();

        let result = registry.flush();
        assert!(result.is_ok());
    }

    #[test]
    fn test_multiple_challenges_state_roots() {
        let db = create_test_db();
        let mut registry = MetadataRegistry::new(&db).unwrap();

        let challenge_id1 = ChallengeId::new();
        let challenge_id2 = ChallengeId::new();

        registry
            .register_challenge(challenge_id1, serde_json::json!({}))
            .unwrap();
        registry
            .register_challenge(challenge_id2, serde_json::json!({}))
            .unwrap();

        registry
            .update_challenge_state_root(&challenge_id1, [1u8; 32])
            .unwrap();
        registry
            .update_challenge_state_root(&challenge_id2, [2u8; 32])
            .unwrap();

        assert!(registry.validate_state_root(&challenge_id1, [1u8; 32]));
        assert!(registry.validate_state_root(&challenge_id2, [2u8; 32]));

        // Global state root should reflect both
        let global_root = registry.compute_global_state_root();
        assert_ne!(global_root, [0u8; 32]);
    }
}
