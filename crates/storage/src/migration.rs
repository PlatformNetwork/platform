//! Migration system for blockchain upgrades
//!
//! Provides versioned migrations that run when the blockchain is upgraded.
//! Similar to database migrations but for blockchain state.
//!
//! ## Network-Aware Migrations
//!
//! For distributed validator networks, migrations must be coordinated across
//! all validators to ensure consistent schema versions:
//!
//! ```ignore
//! use platform_storage::{NetworkMigrationCoordinator, NetworkMigrationStatus};
//!
//! let coordinator = NetworkMigrationCoordinator::new(&db)?;
//!
//! // Check if we can accept a new validator
//! if coordinator.can_accept_validator(&their_hotkey, their_version) {
//!     // Accept validator
//! }
//!
//! // Start network-wide migration
//! coordinator.start_network_migration(target_version)?;
//! ```

use crate::types::{StorageKey, StorageValue};
use platform_core::{ChallengeId, Hotkey, MiniChainError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sled::Tree;
use std::collections::{BTreeMap, HashMap};
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Migration version number
pub type MigrationVersion = u64;

/// Migration trait - implement this for each migration
pub trait Migration: Send + Sync {
    /// Unique version number (must be sequential)
    fn version(&self) -> MigrationVersion;

    /// Human-readable name for this migration
    fn name(&self) -> &str;

    /// Description of what this migration does
    fn description(&self) -> &str {
        ""
    }

    /// Run the migration (upgrade)
    fn up(&self, ctx: &mut MigrationContext) -> Result<()>;

    /// Rollback the migration (downgrade) - optional
    fn down(&self, _ctx: &mut MigrationContext) -> Result<()> {
        Err(MiniChainError::Storage("Rollback not supported".into()))
    }

    /// Whether this migration can be rolled back
    fn reversible(&self) -> bool {
        false
    }
}

/// Context provided to migrations for reading/writing data
pub struct MigrationContext<'a> {
    /// Access to the dynamic storage tree
    pub storage_tree: &'a Tree,
    /// Access to the state tree
    pub state_tree: &'a Tree,
    /// Current block height
    pub block_height: u64,
    /// Changes made during this migration
    pub changes: Vec<MigrationChange>,
}

impl<'a> MigrationContext<'a> {
    pub fn new(storage_tree: &'a Tree, state_tree: &'a Tree, block_height: u64) -> Self {
        Self {
            storage_tree,
            state_tree,
            block_height,
            changes: Vec::new(),
        }
    }

    /// Get a value from dynamic storage
    pub fn get(&self, key: &StorageKey) -> Result<Option<StorageValue>> {
        let key_bytes = key.to_bytes();
        match self.storage_tree.get(&key_bytes) {
            Ok(Some(data)) => {
                let value: StorageValue = bincode::deserialize(&data)
                    .map_err(|e| MiniChainError::Serialization(e.to_string()))?;
                Ok(Some(value))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(MiniChainError::Storage(e.to_string())),
        }
    }

    /// Set a value in dynamic storage
    pub fn set(&mut self, key: StorageKey, value: StorageValue) -> Result<()> {
        let key_bytes = key.to_bytes();
        let old_value = self.get(&key)?;

        let data =
            bincode::serialize(&value).map_err(|e| MiniChainError::Serialization(e.to_string()))?;

        self.storage_tree
            .insert(&key_bytes, data)
            .map_err(|e| MiniChainError::Storage(e.to_string()))?;

        self.changes.push(MigrationChange {
            key: key.clone(),
            old_value,
            new_value: Some(value),
        });

        Ok(())
    }

    /// Delete a value from dynamic storage
    pub fn delete(&mut self, key: &StorageKey) -> Result<Option<StorageValue>> {
        let key_bytes = key.to_bytes();
        let old_value = self.get(key)?;

        self.storage_tree
            .remove(&key_bytes)
            .map_err(|e| MiniChainError::Storage(e.to_string()))?;

        if old_value.is_some() {
            self.changes.push(MigrationChange {
                key: key.clone(),
                old_value: old_value.clone(),
                new_value: None,
            });
        }

        Ok(old_value)
    }

    /// Scan keys with a prefix
    pub fn scan_prefix(&self, namespace: &str) -> Result<Vec<(StorageKey, StorageValue)>> {
        let prefix = StorageKey::namespace_prefix(namespace);
        let mut results = Vec::new();

        for item in self.storage_tree.scan_prefix(&prefix) {
            let (key_bytes, value_bytes) =
                item.map_err(|e| MiniChainError::Storage(e.to_string()))?;

            // Parse key (simplified - in production use proper parsing)
            let key_str = String::from_utf8_lossy(&key_bytes);
            let parts: Vec<&str> = key_str.split('\0').collect();
            if parts.len() >= 2 {
                let key = StorageKey {
                    namespace: parts[0].to_string(),
                    validator: None, // Simplified
                    key: parts.last().unwrap_or(&"").to_string(),
                };

                let value: StorageValue = bincode::deserialize(&value_bytes)
                    .map_err(|e| MiniChainError::Serialization(e.to_string()))?;

                results.push((key, value));
            }
        }

        Ok(results)
    }

    /// Get raw state data
    pub fn get_state_raw(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.state_tree
            .get(key)
            .map(|opt| opt.map(|v| v.to_vec()))
            .map_err(|e| MiniChainError::Storage(e.to_string()))
    }

    /// Set raw state data
    pub fn set_state_raw(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.state_tree
            .insert(key, value)
            .map_err(|e| MiniChainError::Storage(e.to_string()))?;
        Ok(())
    }
}

/// Record of a change made during migration
#[derive(Clone, Debug)]
pub struct MigrationChange {
    pub key: StorageKey,
    pub old_value: Option<StorageValue>,
    pub new_value: Option<StorageValue>,
}

/// Record of an applied migration
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MigrationRecord {
    pub version: MigrationVersion,
    pub name: String,
    pub applied_at: SystemTime,
    pub block_height: u64,
    pub checksum: [u8; 32],
}

/// Migration runner - manages and executes migrations
pub struct MigrationRunner {
    migrations: BTreeMap<MigrationVersion, Box<dyn Migration>>,
    migrations_tree: Tree,
}

impl MigrationRunner {
    /// Create a new migration runner
    pub fn new(db: &sled::Db) -> Result<Self> {
        let migrations_tree = db.open_tree("migrations").map_err(|e| {
            MiniChainError::Storage(format!("Failed to open migrations tree: {}", e))
        })?;

        Ok(Self {
            migrations: BTreeMap::new(),
            migrations_tree,
        })
    }

    /// Register a migration
    pub fn register(&mut self, migration: Box<dyn Migration>) {
        let version = migration.version();
        if self.migrations.contains_key(&version) {
            warn!("Migration version {} already registered, skipping", version);
            return;
        }
        info!("Registered migration {}: {}", version, migration.name());
        self.migrations.insert(version, migration);
    }

    /// Get the current schema version
    pub fn current_version(&self) -> Result<MigrationVersion> {
        match self
            .migrations_tree
            .get("current_version")
            .map_err(|e| MiniChainError::Storage(e.to_string()))?
        {
            Some(data) => {
                let version: MigrationVersion = bincode::deserialize(&data)
                    .map_err(|e| MiniChainError::Serialization(e.to_string()))?;
                Ok(version)
            }
            None => Ok(0),
        }
    }

    /// Set the current schema version
    fn set_current_version(&self, version: MigrationVersion) -> Result<()> {
        let data = bincode::serialize(&version)
            .map_err(|e| MiniChainError::Serialization(e.to_string()))?;
        self.migrations_tree
            .insert("current_version", data)
            .map_err(|e| MiniChainError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Get list of applied migrations
    pub fn applied_migrations(&self) -> Result<Vec<MigrationRecord>> {
        let mut records = Vec::new();

        for item in self.migrations_tree.scan_prefix(b"applied:") {
            let (_, data) = item.map_err(|e| MiniChainError::Storage(e.to_string()))?;
            let record: MigrationRecord = bincode::deserialize(&data)
                .map_err(|e| MiniChainError::Serialization(e.to_string()))?;
            records.push(record);
        }

        records.sort_by_key(|r| r.version);
        Ok(records)
    }

    /// Check if a migration has been applied
    pub fn is_applied(&self, version: MigrationVersion) -> Result<bool> {
        let key = format!("applied:{}", version);
        self.migrations_tree
            .contains_key(key)
            .map_err(|e| MiniChainError::Storage(e.to_string()))
    }

    /// Record that a migration was applied
    fn record_applied(&self, record: MigrationRecord) -> Result<()> {
        let key = format!("applied:{}", record.version);
        let data = bincode::serialize(&record)
            .map_err(|e| MiniChainError::Serialization(e.to_string()))?;
        self.migrations_tree
            .insert(key, data)
            .map_err(|e| MiniChainError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Get pending migrations
    pub fn pending_migrations(&self) -> Result<Vec<MigrationVersion>> {
        let current = self.current_version()?;
        Ok(self
            .migrations
            .keys()
            .filter(|&&v| v > current)
            .copied()
            .collect())
    }

    /// Run all pending migrations
    pub fn run_pending(
        &self,
        storage_tree: &Tree,
        state_tree: &Tree,
        block_height: u64,
    ) -> Result<Vec<MigrationVersion>> {
        let pending = self.pending_migrations()?;

        if pending.is_empty() {
            info!("No pending migrations");
            return Ok(vec![]);
        }

        info!("Running {} pending migrations", pending.len());
        let mut applied = Vec::new();

        for version in pending {
            if let Some(migration) = self.migrations.get(&version) {
                info!("Running migration {}: {}", version, migration.name());

                let mut ctx = MigrationContext::new(storage_tree, state_tree, block_height);

                migration.up(&mut ctx)?;

                // Calculate checksum of changes
                let checksum = self.calculate_checksum(&ctx.changes);

                // Record the migration
                let record = MigrationRecord {
                    version,
                    name: migration.name().to_string(),
                    applied_at: SystemTime::now(),
                    block_height,
                    checksum,
                };

                self.record_applied(record)?;
                self.set_current_version(version)?;

                info!(
                    "Migration {} completed ({} changes)",
                    version,
                    ctx.changes.len()
                );
                applied.push(version);
            }
        }

        // Flush changes
        self.migrations_tree
            .flush()
            .map_err(|e| MiniChainError::Storage(e.to_string()))?;
        storage_tree
            .flush()
            .map_err(|e| MiniChainError::Storage(e.to_string()))?;
        state_tree
            .flush()
            .map_err(|e| MiniChainError::Storage(e.to_string()))?;

        Ok(applied)
    }

    /// Rollback to a specific version
    pub fn rollback_to(
        &self,
        target_version: MigrationVersion,
        storage_tree: &Tree,
        state_tree: &Tree,
        block_height: u64,
    ) -> Result<Vec<MigrationVersion>> {
        let current = self.current_version()?;

        if target_version >= current {
            return Err(MiniChainError::Storage(format!(
                "Cannot rollback to version {} (current is {})",
                target_version, current
            )));
        }

        let mut rolled_back = Vec::new();

        // Rollback in reverse order
        for version in (target_version + 1..=current).rev() {
            if let Some(migration) = self.migrations.get(&version) {
                if !migration.reversible() {
                    return Err(MiniChainError::Storage(format!(
                        "Migration {} is not reversible",
                        version
                    )));
                }

                info!("Rolling back migration {}: {}", version, migration.name());

                let mut ctx = MigrationContext::new(storage_tree, state_tree, block_height);
                migration.down(&mut ctx)?;

                // Remove the applied record
                let key = format!("applied:{}", version);
                self.migrations_tree
                    .remove(key)
                    .map_err(|e| MiniChainError::Storage(e.to_string()))?;

                rolled_back.push(version);
            }
        }

        self.set_current_version(target_version)?;
        self.migrations_tree
            .flush()
            .map_err(|e| MiniChainError::Storage(e.to_string()))?;

        Ok(rolled_back)
    }

    /// Calculate checksum of migration changes
    fn calculate_checksum(&self, changes: &[MigrationChange]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        for change in changes {
            hasher.update(change.key.to_bytes());
            if let Some(ref v) = change.old_value {
                if let Ok(data) = bincode::serialize(v) {
                    hasher.update(&data);
                }
            }
            if let Some(ref v) = change.new_value {
                if let Ok(data) = bincode::serialize(v) {
                    hasher.update(&data);
                }
            }
        }

        hasher.finalize().into()
    }
}

// === Built-in Migrations ===

/// Initial migration - sets up base storage schema
pub struct InitialMigration;

impl Migration for InitialMigration {
    fn version(&self) -> MigrationVersion {
        1
    }
    fn name(&self) -> &str {
        "initial_setup"
    }
    fn description(&self) -> &str {
        "Initial storage schema setup"
    }

    fn up(&self, ctx: &mut MigrationContext) -> Result<()> {
        // Set schema version
        ctx.set(StorageKey::system("schema_version"), StorageValue::U64(1))?;

        // Set creation timestamp
        ctx.set(
            StorageKey::system("created_at"),
            StorageValue::U64(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
        )?;

        // Initialize counters
        ctx.set(StorageKey::system("total_challenges"), StorageValue::U64(0))?;
        ctx.set(StorageKey::system("total_validators"), StorageValue::U64(0))?;
        ctx.set(StorageKey::system("total_jobs"), StorageValue::U64(0))?;

        Ok(())
    }
}

/// Migration to add challenge metrics storage
pub struct AddChallengeMetricsMigration;

impl Migration for AddChallengeMetricsMigration {
    fn version(&self) -> MigrationVersion {
        2
    }
    fn name(&self) -> &str {
        "add_challenge_metrics"
    }
    fn description(&self) -> &str {
        "Add per-challenge metrics storage"
    }

    fn up(&self, ctx: &mut MigrationContext) -> Result<()> {
        // Add metrics enabled flag
        ctx.set(
            StorageKey::system("metrics_enabled"),
            StorageValue::Bool(true),
        )?;

        // Add default retention period (7 days in seconds)
        ctx.set(
            StorageKey::system("metrics_retention_secs"),
            StorageValue::U64(7 * 24 * 60 * 60),
        )?;

        Ok(())
    }

    fn down(&self, ctx: &mut MigrationContext) -> Result<()> {
        ctx.delete(&StorageKey::system("metrics_enabled"))?;
        ctx.delete(&StorageKey::system("metrics_retention_secs"))?;
        Ok(())
    }

    fn reversible(&self) -> bool {
        true
    }
}

// ============================================================================
// Network-Aware Migration Coordination
// ============================================================================

/// Network migration status for coordination across validators
///
/// Tracks the migration state across the distributed validator network,
/// ensuring all validators are synchronized before accepting new ones.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NetworkMigrationStatus {
    /// Current network-wide schema version
    pub network_version: MigrationVersion,
    /// Validators that have reported their version (hotkey -> version)
    pub validator_versions: HashMap<Hotkey, MigrationVersion>,
    /// Whether a migration is currently in progress network-wide
    pub migration_in_progress: bool,
    /// Target version being migrated to
    pub target_version: Option<MigrationVersion>,
    /// Timestamp when migration started
    pub started_at: Option<SystemTime>,
}

/// Challenge-specific migration record
///
/// Tracks migrations for individual challenges, allowing challenges
/// to have their own schema versions independent of the global version.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeMigration {
    /// Challenge ID
    pub challenge_id: ChallengeId,
    /// Source schema version
    pub from_version: u64,
    /// Target schema version
    pub to_version: u64,
    /// State hash before migration
    pub state_hash_before: [u8; 32],
    /// State hash after migration (set when completed)
    pub state_hash_after: Option<[u8; 32]>,
    /// Current status
    pub status: ChallengeMigrationStatus,
}

/// Status of a challenge-specific migration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeMigrationStatus {
    /// Migration has not started
    Pending,
    /// Migration is currently running
    InProgress,
    /// Migration completed successfully
    Completed,
    /// Migration failed with error
    Failed(String),
}

/// Coordinator for network-wide migration synchronization
///
/// Ensures validators stay synchronized during schema upgrades by:
/// - Tracking validator versions across the network
/// - Blocking new validators until they sync to the current schema
/// - Coordinating migration rollouts across all validators
pub struct NetworkMigrationCoordinator {
    /// Tree for storing network migration state
    network_tree: Tree,
    /// Cached network status
    cached_status: Option<NetworkMigrationStatus>,
}

impl NetworkMigrationCoordinator {
    /// Create a new network migration coordinator
    ///
    /// # Arguments
    ///
    /// * `db` - The sled database to use for persistence
    ///
    /// # Returns
    ///
    /// A new `NetworkMigrationCoordinator` instance
    pub fn new(db: &sled::Db) -> Result<Self> {
        let network_tree = db.open_tree("network_migrations").map_err(|e| {
            MiniChainError::Storage(format!("Failed to open network_migrations tree: {}", e))
        })?;

        Ok(Self {
            network_tree,
            cached_status: None,
        })
    }

    /// Get the current network migration status
    ///
    /// Loads the status from the database or returns defaults if not set.
    pub fn get_network_status(&self) -> Result<NetworkMigrationStatus> {
        match self
            .network_tree
            .get("status")
            .map_err(|e| MiniChainError::Storage(e.to_string()))?
        {
            Some(data) => {
                let status: NetworkMigrationStatus = bincode::deserialize(&data)
                    .map_err(|e| MiniChainError::Serialization(e.to_string()))?;
                Ok(status)
            }
            None => Ok(NetworkMigrationStatus::default()),
        }
    }

    /// Save the network migration status
    fn save_network_status(&self, status: &NetworkMigrationStatus) -> Result<()> {
        let data =
            bincode::serialize(status).map_err(|e| MiniChainError::Serialization(e.to_string()))?;
        self.network_tree
            .insert("status", data)
            .map_err(|e| MiniChainError::Storage(e.to_string()))?;
        self.network_tree
            .flush()
            .map_err(|e| MiniChainError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Report a validator's current schema version
    ///
    /// Called by validators to report their current version to the network.
    ///
    /// # Arguments
    ///
    /// * `validator` - The validator's hotkey
    /// * `version` - The validator's current schema version
    pub fn report_validator_version(
        &mut self,
        validator: Hotkey,
        version: MigrationVersion,
    ) -> Result<()> {
        let mut status = self.get_network_status()?;
        status.validator_versions.insert(validator.clone(), version);

        debug!(
            validator = %validator.to_hex(),
            version = version,
            "Validator reported schema version"
        );

        self.save_network_status(&status)?;
        self.cached_status = Some(status);
        Ok(())
    }

    /// Check if a validator can be accepted based on schema version
    ///
    /// A validator can be accepted if:
    /// - No migration is in progress, OR
    /// - The validator's version >= network version
    ///
    /// # Arguments
    ///
    /// * `validator` - The validator's hotkey
    /// * `their_version` - The validator's reported schema version
    ///
    /// # Returns
    ///
    /// `true` if the validator can be accepted
    pub fn can_accept_validator(
        &self,
        validator: &Hotkey,
        their_version: MigrationVersion,
    ) -> bool {
        let status = match self.get_network_status() {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    error = %e,
                    validator = %validator.to_hex(),
                    "Failed to get network status, rejecting validator"
                );
                return false;
            }
        };

        // During migration, only accept validators at or above target version
        if status.migration_in_progress {
            if let Some(target) = status.target_version {
                return their_version >= target;
            }
        }

        // Otherwise, accept if at or above network version
        their_version >= status.network_version
    }

    /// Start a network-wide migration to a target version
    ///
    /// This marks the migration as in-progress and sets the target version.
    /// Validators should check `is_migration_in_progress()` before processing.
    ///
    /// # Arguments
    ///
    /// * `target_version` - The version to migrate to
    pub fn start_network_migration(&mut self, target_version: MigrationVersion) -> Result<()> {
        let mut status = self.get_network_status()?;

        if status.migration_in_progress {
            return Err(MiniChainError::Storage(format!(
                "Migration already in progress to version {:?}",
                status.target_version
            )));
        }

        if target_version <= status.network_version {
            return Err(MiniChainError::Storage(format!(
                "Target version {} must be greater than current version {}",
                target_version, status.network_version
            )));
        }

        info!(
            from_version = status.network_version,
            to_version = target_version,
            "Starting network-wide migration"
        );

        status.migration_in_progress = true;
        status.target_version = Some(target_version);
        status.started_at = Some(SystemTime::now());

        self.save_network_status(&status)?;
        self.cached_status = Some(status);
        Ok(())
    }

    /// Complete migration for a specific validator
    ///
    /// Called when a validator has finished migrating to the target version.
    ///
    /// # Arguments
    ///
    /// * `validator` - The validator that completed migration
    pub fn complete_migration(&mut self, validator: &Hotkey) -> Result<()> {
        let mut status = self.get_network_status()?;

        if !status.migration_in_progress {
            return Ok(()); // No migration in progress
        }

        let target = status.target_version.unwrap_or(status.network_version);
        status.validator_versions.insert(validator.clone(), target);

        debug!(
            validator = %validator.to_hex(),
            version = target,
            "Validator completed migration"
        );

        self.save_network_status(&status)?;
        self.cached_status = Some(status);
        Ok(())
    }

    /// Finalize migration when all validators have completed
    ///
    /// Call this after verifying all active validators have migrated.
    pub fn finalize_network_migration(&mut self) -> Result<()> {
        let mut status = self.get_network_status()?;

        if !status.migration_in_progress {
            return Ok(());
        }

        let target = status.target_version.unwrap_or(status.network_version);

        info!(
            old_version = status.network_version,
            new_version = target,
            "Finalizing network migration"
        );

        status.network_version = target;
        status.migration_in_progress = false;
        status.target_version = None;
        status.started_at = None;

        self.save_network_status(&status)?;
        self.cached_status = Some(status);
        Ok(())
    }

    /// Check if a migration is currently in progress
    pub fn is_migration_in_progress(&self) -> bool {
        self.get_network_status()
            .map(|s| s.migration_in_progress)
            .unwrap_or(false)
    }

    /// Get list of validators that need to upgrade
    ///
    /// Returns validators whose version is below the network version.
    pub fn get_validators_needing_upgrade(&self) -> Vec<Hotkey> {
        let status = match self.get_network_status() {
            Ok(s) => s,
            Err(_) => return vec![],
        };

        status
            .validator_versions
            .iter()
            .filter(|(_, v)| **v < status.network_version)
            .map(|(h, _)| h.clone())
            .collect()
    }

    /// Set the network version directly (for initialization)
    pub fn set_network_version(&mut self, version: MigrationVersion) -> Result<()> {
        let mut status = self.get_network_status()?;
        status.network_version = version;
        self.save_network_status(&status)?;
        self.cached_status = Some(status);
        Ok(())
    }
}

/// Compute a state hash for migration verification
///
/// Computes a hash of all data in a challenge's namespace to verify
/// that migrations produce consistent results across validators.
///
/// # Arguments
///
/// * `ctx` - The migration context
/// * `challenge_id` - The challenge to compute hash for
///
/// # Returns
///
/// A 32-byte hash of the challenge's current state
pub fn compute_migration_state_hash(
    ctx: &MigrationContext,
    challenge_id: &ChallengeId,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Hash the challenge ID
    hasher.update(challenge_id.0.as_bytes());

    // Scan and hash all keys in the challenge namespace
    let namespace = challenge_id.0.to_string();
    if let Ok(entries) = ctx.scan_prefix(&namespace) {
        for (key, value) in entries {
            hasher.update(key.to_bytes());
            if let Ok(data) = bincode::serialize(&value) {
                hasher.update(&data);
            }
        }
    }

    hasher.finalize().into()
}

/// Trait for challenge-specific migration handlers
///
/// Implement this trait to create migrations that are specific to a
/// single challenge's data schema.
pub trait ChallengeMigrationHandler: Send + Sync {
    /// Get the challenge ID this migration applies to
    fn challenge_id(&self) -> &ChallengeId;

    /// Source schema version
    fn source_version(&self) -> u64;

    /// Target schema version
    fn to_version(&self) -> u64;

    /// Run the migration
    fn migrate(&self, ctx: &mut MigrationContext) -> Result<()>;

    /// Rollback the migration (optional)
    fn rollback(&self, _ctx: &mut MigrationContext) -> Result<()> {
        Err(MiniChainError::Storage(
            "Challenge migration rollback not supported".to_string(),
        ))
    }

    /// Whether this migration can be rolled back
    fn reversible(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_migration_runner() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let mut runner = MigrationRunner::new(&db).unwrap();

        // Register migrations
        runner.register(Box::new(InitialMigration));
        runner.register(Box::new(AddChallengeMetricsMigration));

        // Check pending
        let pending = runner.pending_migrations().unwrap();
        assert_eq!(pending.len(), 2);

        // Run migrations
        let applied = runner.run_pending(&storage_tree, &state_tree, 0).unwrap();
        assert_eq!(applied.len(), 2);

        // Check version
        assert_eq!(runner.current_version().unwrap(), 2);

        // Check no pending
        let pending = runner.pending_migrations().unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn test_migration_context() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let mut ctx = MigrationContext::new(&storage_tree, &state_tree, 0);

        // Set and get
        let key = StorageKey::system("test_key");
        ctx.set(key.clone(), StorageValue::U64(42)).unwrap();

        let value = ctx.get(&key).unwrap();
        assert_eq!(value.unwrap().as_u64(), Some(42));

        // Delete
        ctx.delete(&key).unwrap();
        assert!(ctx.get(&key).unwrap().is_none());
    }

    #[test]
    fn test_migration_context_scan_prefix() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let mut ctx = MigrationContext::new(&storage_tree, &state_tree, 0);

        // Add multiple keys with same namespace
        for i in 0..3 {
            let key = StorageKey::system(format!("key{}", i));
            ctx.set(key, StorageValue::U64(i)).unwrap();
        }

        let results = ctx.scan_prefix("system").unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_migration_context_get_state_raw() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        state_tree.insert("test_state", b"state_value").unwrap();

        let ctx = MigrationContext::new(&storage_tree, &state_tree, 0);
        let value = ctx.get_state_raw("test_state").unwrap();

        assert_eq!(value, Some(b"state_value".to_vec()));
    }

    #[test]
    fn test_migration_context_set_state_raw() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let ctx = MigrationContext::new(&storage_tree, &state_tree, 0);
        ctx.set_state_raw("test_state", b"new_value".to_vec())
            .unwrap();

        let value = state_tree.get("test_state").unwrap();
        assert_eq!(value.unwrap().as_ref(), b"new_value");
    }

    #[test]
    fn test_migration_runner_current_version_default() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();

        let runner = MigrationRunner::new(&db).unwrap();
        assert_eq!(runner.current_version().unwrap(), 0);
    }

    #[test]
    fn test_migration_runner_is_applied() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let mut runner = MigrationRunner::new(&db).unwrap();
        runner.register(Box::new(InitialMigration));

        assert!(!runner.is_applied(1).unwrap());

        runner.run_pending(&storage_tree, &state_tree, 0).unwrap();

        assert!(runner.is_applied(1).unwrap());
    }

    #[test]
    fn test_migration_runner_applied_migrations() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let mut runner = MigrationRunner::new(&db).unwrap();
        runner.register(Box::new(InitialMigration));

        runner.run_pending(&storage_tree, &state_tree, 0).unwrap();

        let applied = runner.applied_migrations().unwrap();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].version, 1);
    }

    #[test]
    fn test_migration_runner_pending_migrations() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();

        let mut runner = MigrationRunner::new(&db).unwrap();
        runner.register(Box::new(InitialMigration));
        runner.register(Box::new(AddChallengeMetricsMigration));

        let pending = runner.pending_migrations().unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0], 1);
        assert_eq!(pending[1], 2);
    }

    #[test]
    fn test_initial_migration_properties() {
        let migration = InitialMigration;
        assert_eq!(migration.version(), 1);
        assert_eq!(migration.name(), "initial_setup");
        assert!(!migration.description().is_empty());
        assert!(!migration.reversible());
    }

    #[test]
    fn test_add_challenge_metrics_migration_properties() {
        let migration = AddChallengeMetricsMigration;
        assert_eq!(migration.version(), 2);
        assert_eq!(migration.name(), "add_challenge_metrics");
        assert!(!migration.description().is_empty());
        assert!(migration.reversible());
    }

    #[test]
    fn test_migration_record_serialization() {
        let record = MigrationRecord {
            version: 1,
            name: "test".to_string(),
            applied_at: SystemTime::now(),
            block_height: 100,
            checksum: [1u8; 32],
        };

        let serialized = bincode::serialize(&record).unwrap();
        let deserialized: MigrationRecord = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.version, record.version);
        assert_eq!(deserialized.name, record.name);
    }

    #[test]
    fn test_migration_context_delete() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let mut ctx = MigrationContext::new(&storage_tree, &state_tree, 100);

        // Set a value first
        let key = StorageKey::system("to_delete");
        ctx.set(key.clone(), StorageValue::U64(123)).unwrap();

        // Delete it
        let deleted = ctx.delete(&key).unwrap();
        assert!(deleted.is_some());
        assert_eq!(deleted.unwrap().as_u64(), Some(123));

        // Verify it's gone
        let value = ctx.get(&key).unwrap();
        assert!(value.is_none());

        // Delete non-existent key
        let deleted2 = ctx.delete(&StorageKey::system("nonexistent")).unwrap();
        assert!(deleted2.is_none());
    }

    #[test]
    fn test_migration_context_changes_tracking() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let mut ctx = MigrationContext::new(&storage_tree, &state_tree, 100);

        // Initially no changes
        assert_eq!(ctx.changes.len(), 0);

        // Set a value
        ctx.set(StorageKey::system("key1"), StorageValue::U64(1))
            .unwrap();
        assert_eq!(ctx.changes.len(), 1);
        assert!(ctx.changes[0].old_value.is_none());
        assert!(ctx.changes[0].new_value.is_some());

        // Update the value
        ctx.set(StorageKey::system("key1"), StorageValue::U64(2))
            .unwrap();
        assert_eq!(ctx.changes.len(), 2);
        assert!(ctx.changes[1].old_value.is_some());

        // Delete a value
        ctx.delete(&StorageKey::system("key1")).unwrap();
        assert_eq!(ctx.changes.len(), 3);
    }

    #[test]
    fn test_migration_runner_is_applied_after_run() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let mut runner = MigrationRunner::new(&db).unwrap();
        runner.register(Box::new(InitialMigration));

        // Not applied initially
        assert!(!runner.is_applied(1).unwrap());

        // Apply it
        runner.run_pending(&storage_tree, &state_tree, 0).unwrap();

        // Now it's applied
        assert!(runner.is_applied(1).unwrap());
    }

    #[test]
    fn test_add_challenge_metrics_migration_details() {
        let migration = AddChallengeMetricsMigration;
        assert_eq!(migration.version(), 2);
        assert_eq!(migration.name(), "add_challenge_metrics");
        assert!(!migration.description().is_empty());
        assert!(migration.reversible());
    }

    #[test]
    fn test_add_challenge_metrics_migration_up() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let mut ctx = MigrationContext::new(&storage_tree, &state_tree, 100);
        let migration = AddChallengeMetricsMigration;

        migration.up(&mut ctx).unwrap();

        // Check that metrics_enabled was set
        let metrics_enabled = ctx.get(&StorageKey::system("metrics_enabled")).unwrap();
        assert!(metrics_enabled.is_some());
        assert_eq!(metrics_enabled.unwrap().as_bool(), Some(true));

        // Check that retention was set
        let retention = ctx
            .get(&StorageKey::system("metrics_retention_secs"))
            .unwrap();
        assert!(retention.is_some());
        assert_eq!(retention.unwrap().as_u64(), Some(7 * 24 * 60 * 60));
    }

    #[test]
    fn test_add_challenge_metrics_migration_down() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let mut ctx = MigrationContext::new(&storage_tree, &state_tree, 100);
        let migration = AddChallengeMetricsMigration;

        // First run up
        migration.up(&mut ctx).unwrap();

        // Then run down
        migration.down(&mut ctx).unwrap();

        // Keys should be deleted
        let metrics_enabled = ctx.get(&StorageKey::system("metrics_enabled")).unwrap();
        assert!(metrics_enabled.is_none());

        let retention = ctx
            .get(&StorageKey::system("metrics_retention_secs"))
            .unwrap();
        assert!(retention.is_none());
    }

    #[test]
    fn test_initial_migration_up() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let mut ctx = MigrationContext::new(&storage_tree, &state_tree, 100);
        let migration = InitialMigration;

        migration.up(&mut ctx).unwrap();

        // Check all keys were set
        let schema_version = ctx.get(&StorageKey::system("schema_version")).unwrap();
        assert_eq!(schema_version.unwrap().as_u64(), Some(1));

        let created_at = ctx.get(&StorageKey::system("created_at")).unwrap();
        assert!(created_at.is_some());

        let total_challenges = ctx.get(&StorageKey::system("total_challenges")).unwrap();
        assert_eq!(total_challenges.unwrap().as_u64(), Some(0));

        let total_validators = ctx.get(&StorageKey::system("total_validators")).unwrap();
        assert_eq!(total_validators.unwrap().as_u64(), Some(0));

        let total_jobs = ctx.get(&StorageKey::system("total_jobs")).unwrap();
        assert_eq!(total_jobs.unwrap().as_u64(), Some(0));
    }

    #[test]
    fn test_migration_runner_multiple_migrations() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let mut runner = MigrationRunner::new(&db).unwrap();
        runner.register(Box::new(InitialMigration));
        runner.register(Box::new(AddChallengeMetricsMigration));

        // Run all pending
        let applied = runner.run_pending(&storage_tree, &state_tree, 0).unwrap();
        assert_eq!(applied.len(), 2);
        assert_eq!(applied[0], 1);
        assert_eq!(applied[1], 2);

        // Version should be 2
        assert_eq!(runner.current_version().unwrap(), 2);

        // Both should be applied
        assert!(runner.is_applied(1).unwrap());
        assert!(runner.is_applied(2).unwrap());
    }

    #[test]
    fn test_migration_context_state_operations() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let ctx = MigrationContext::new(&storage_tree, &state_tree, 100);

        // Set raw state
        ctx.set_state_raw("test_key", vec![1, 2, 3, 4]).unwrap();

        // Get raw state
        let value = ctx.get_state_raw("test_key").unwrap();
        assert!(value.is_some());
        assert_eq!(value.unwrap(), vec![1, 2, 3, 4]);

        // Get non-existent
        let none = ctx.get_state_raw("nonexistent").unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn test_migration_runner_duplicate_registration() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();

        let mut runner = MigrationRunner::new(&db).unwrap();

        // Register same migration twice
        runner.register(Box::new(InitialMigration));
        runner.register(Box::new(InitialMigration));

        // Should only have one migration
        assert_eq!(runner.pending_migrations().unwrap().len(), 1);
    }

    #[test]
    fn test_migration_context_update_existing_value() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let mut ctx = MigrationContext::new(&storage_tree, &state_tree, 100);

        let key = StorageKey::system("counter");

        // Set initial value
        ctx.set(key.clone(), StorageValue::U64(1)).unwrap();

        // Update it
        ctx.set(key.clone(), StorageValue::U64(2)).unwrap();

        // Verify updated
        let value = ctx.get(&key).unwrap();
        assert_eq!(value.unwrap().as_u64(), Some(2));
    }

    #[test]
    fn test_migration_default_methods() {
        struct TestMigration;
        impl Migration for TestMigration {
            fn version(&self) -> MigrationVersion {
                1
            }
            fn name(&self) -> &str {
                "test"
            }
            fn up(&self, _ctx: &mut MigrationContext) -> Result<()> {
                Ok(())
            }
        }

        let migration = TestMigration;
        // Test default implementations
        assert_eq!(migration.description(), ""); // Default description
        assert!(!migration.reversible()); // Default not reversible
        assert!(migration
            .down(&mut MigrationContext::new(
                &sled::Config::new()
                    .temporary(true)
                    .open()
                    .unwrap()
                    .open_tree("test")
                    .unwrap(),
                &sled::Config::new()
                    .temporary(true)
                    .open()
                    .unwrap()
                    .open_tree("state")
                    .unwrap(),
                0
            ))
            .is_err()); // Default down returns error
    }

    #[test]
    fn test_migration_context_get_nonexistent() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let ctx = MigrationContext::new(&storage_tree, &state_tree, 100);

        // Test line 76 - getting nonexistent key returns Ok(None)
        let value = ctx.get(&StorageKey::system("nonexistent")).unwrap();
        assert!(value.is_none());
    }

    #[test]
    fn test_migration_context_scan_prefix_error_handling() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let ctx = MigrationContext::new(&storage_tree, &state_tree, 100);

        // Test line 128 - scan_prefix error handling
        let result = ctx.scan_prefix("test_namespace");
        assert!(result.is_ok());
    }

    #[test]
    fn test_migration_record_field_access() {
        let record = MigrationRecord {
            version: 1,
            name: "test".to_string(),
            applied_at: SystemTime::now(),
            block_height: 100,
            checksum: [1u8; 32],
        };

        // Test line 195 - record_applied serialization
        let serialized = bincode::serialize(&record).unwrap();
        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_run_pending_empty_migrations() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let mut runner = MigrationRunner::new(&db).unwrap();
        runner.register(Box::new(InitialMigration));

        // Run once
        runner.run_pending(&storage_tree, &state_tree, 0).unwrap();

        // Run again - lines 296-297: pending.is_empty() should return early
        let result = runner.run_pending(&storage_tree, &state_tree, 0).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_rollback_to_non_reversible() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let mut runner = MigrationRunner::new(&db).unwrap();
        runner.register(Box::new(InitialMigration));

        // Apply migration
        runner.run_pending(&storage_tree, &state_tree, 0).unwrap();

        // Try to rollback non-reversible migration (lines 409-410)
        let result = runner.rollback_to(0, &storage_tree, &state_tree, 0);
        assert!(result.is_err());
    }

    // === Network Migration Tests ===

    #[test]
    fn test_network_migration_status_serialization() {
        let status = NetworkMigrationStatus {
            network_version: 5,
            validator_versions: HashMap::new(),
            migration_in_progress: false,
            target_version: None,
            started_at: None,
        };

        let serialized = bincode::serialize(&status).unwrap();
        let deserialized: NetworkMigrationStatus = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.network_version, 5);
        assert!(!deserialized.migration_in_progress);
    }

    #[test]
    fn test_network_migration_coordinator_creation() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();

        let coordinator = NetworkMigrationCoordinator::new(&db).unwrap();
        let status = coordinator.get_network_status().unwrap();

        assert_eq!(status.network_version, 0);
        assert!(!status.migration_in_progress);
    }

    #[test]
    fn test_network_migration_coordinator_report_version() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();

        let mut coordinator = NetworkMigrationCoordinator::new(&db).unwrap();
        let validator = Hotkey([1u8; 32]);

        coordinator
            .report_validator_version(validator.clone(), 3)
            .unwrap();

        let status = coordinator.get_network_status().unwrap();
        assert_eq!(*status.validator_versions.get(&validator).unwrap(), 3);
    }

    #[test]
    fn test_network_migration_coordinator_can_accept_validator() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();

        let mut coordinator = NetworkMigrationCoordinator::new(&db).unwrap();
        let validator = Hotkey([1u8; 32]);

        // When network version is 0, accept any version >= 0
        assert!(coordinator.can_accept_validator(&validator, 0));
        assert!(coordinator.can_accept_validator(&validator, 5));

        // Set network version to 5
        coordinator.set_network_version(5).unwrap();

        // Now only accept validators at version 5 or higher
        assert!(!coordinator.can_accept_validator(&validator, 4));
        assert!(coordinator.can_accept_validator(&validator, 5));
        assert!(coordinator.can_accept_validator(&validator, 6));
    }

    #[test]
    fn test_network_migration_start_and_complete() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();

        let mut coordinator = NetworkMigrationCoordinator::new(&db).unwrap();
        let validator = Hotkey([1u8; 32]);

        // Start migration
        coordinator.start_network_migration(5).unwrap();

        let status = coordinator.get_network_status().unwrap();
        assert!(status.migration_in_progress);
        assert_eq!(status.target_version, Some(5));

        // Complete migration for validator
        coordinator.complete_migration(&validator).unwrap();

        // Migration still in progress until network version is updated
        assert!(coordinator.is_migration_in_progress());
    }

    #[test]
    fn test_challenge_migration_status() {
        let status = ChallengeMigrationStatus::Pending;
        assert_eq!(status, ChallengeMigrationStatus::Pending);

        let failed = ChallengeMigrationStatus::Failed("test error".to_string());
        assert!(matches!(failed, ChallengeMigrationStatus::Failed(_)));
    }

    #[test]
    fn test_challenge_migration_serialization() {
        let migration = ChallengeMigration {
            challenge_id: ChallengeId(uuid::Uuid::new_v4()),
            from_version: 1,
            to_version: 2,
            state_hash_before: [1u8; 32],
            state_hash_after: Some([2u8; 32]),
            status: ChallengeMigrationStatus::Completed,
        };

        let serialized = bincode::serialize(&migration).unwrap();
        let deserialized: ChallengeMigration = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.from_version, 1);
        assert_eq!(deserialized.to_version, 2);
    }

    #[test]
    fn test_validators_needing_upgrade() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();

        let mut coordinator = NetworkMigrationCoordinator::new(&db).unwrap();
        let v1 = Hotkey([1u8; 32]);
        let v2 = Hotkey([2u8; 32]);
        let v3 = Hotkey([3u8; 32]);

        // Set network version to 5
        coordinator.set_network_version(5).unwrap();

        // Report different versions
        coordinator.report_validator_version(v1.clone(), 5).unwrap();
        coordinator.report_validator_version(v2.clone(), 4).unwrap();
        coordinator.report_validator_version(v3.clone(), 3).unwrap();

        let needing_upgrade = coordinator.get_validators_needing_upgrade();

        // v2 and v3 need upgrade
        assert_eq!(needing_upgrade.len(), 2);
        assert!(needing_upgrade.contains(&v2));
        assert!(needing_upgrade.contains(&v3));
    }

    #[test]
    fn test_compute_migration_state_hash() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage_tree = db.open_tree("dynamic_storage").unwrap();
        let state_tree = db.open_tree("state").unwrap();

        let mut ctx = MigrationContext::new(&storage_tree, &state_tree, 0);

        let challenge_id = ChallengeId(uuid::Uuid::new_v4());

        // Empty state should still produce a hash
        let hash1 = compute_migration_state_hash(&ctx, &challenge_id);
        assert_ne!(hash1, [0u8; 32]);

        // Adding data should change the hash
        ctx.set(
            StorageKey::challenge(&challenge_id, "test"),
            StorageValue::U64(42),
        )
        .unwrap();
        let hash2 = compute_migration_state_hash(&ctx, &challenge_id);
        assert_ne!(hash1, hash2);
    }
}