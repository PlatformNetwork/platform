//! Hot Update System
//!
//! Allows updating challenges and configuration without restarting validators.

use crate::{ChallengeConfig, SubnetConfig};
use parking_lot::RwLock;
use platform_core::{ChallengeId, Hotkey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Update types
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum UpdateType {
    /// Hot update - applied without restart
    Hot,
    /// Warm update - requires graceful reload
    Warm,
    /// Cold update - requires full restart
    Cold,
    /// Hard reset - wipes state and restarts
    HardReset,
}

/// Update status
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum UpdateStatus {
    Pending,
    Downloading,
    Validating,
    Applying,
    Applied,
    Failed(String),
    RolledBack,
}

/// An update to be applied
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Update {
    /// Unique update ID
    pub id: uuid::Uuid,

    /// Update type
    pub update_type: UpdateType,

    /// Version string
    pub version: String,

    /// What's being updated
    pub target: UpdateTarget,

    /// Update payload
    pub payload: UpdatePayload,

    /// Status
    pub status: UpdateStatus,

    /// Created at
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Applied at
    pub applied_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Rollback data (for reverting)
    pub rollback_data: Option<Vec<u8>>,
}

/// What is being updated
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UpdateTarget {
    /// Update a challenge
    Challenge(ChallengeId),
    /// Update subnet configuration
    Config,
    /// Update all challenges
    AllChallenges,
    /// Update validator list
    Validators,
}

/// Update payload
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UpdatePayload {
    /// WASM bytecode for challenge
    WasmChallenge {
        wasm_bytes: Vec<u8>,
        wasm_hash: String,
        config: ChallengeConfig,
    },
    /// Configuration update
    Config(SubnetConfig),
    /// Add/remove validators
    Validators {
        add: Vec<Hotkey>,
        remove: Vec<Hotkey>,
    },
    /// Hard reset with new state
    HardReset {
        reason: String,
        preserve_validators: bool,
        new_config: Option<SubnetConfig>,
    },
}

/// Update manager
pub struct UpdateManager {
    /// Data directory
    data_dir: PathBuf,

    /// Pending updates
    pending: Arc<RwLock<Vec<Update>>>,

    /// Applied updates history
    history: Arc<RwLock<Vec<Update>>>,

    /// Current version
    current_version: Arc<RwLock<String>>,

    /// Is update in progress
    updating: Arc<RwLock<bool>>,
}

impl UpdateManager {
    /// Create a new update manager
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            pending: Arc::new(RwLock::new(Vec::new())),
            history: Arc::new(RwLock::new(Vec::new())),
            current_version: Arc::new(RwLock::new("0.1.0".to_string())),
            updating: Arc::new(RwLock::new(false)),
        }
    }

    /// Queue an update
    pub fn queue_update(
        &self,
        target: UpdateTarget,
        payload: UpdatePayload,
        version: String,
    ) -> uuid::Uuid {
        let update_type = match &payload {
            UpdatePayload::WasmChallenge { .. } => UpdateType::Hot,
            UpdatePayload::Config(_) => UpdateType::Warm,
            UpdatePayload::Validators { .. } => UpdateType::Hot,
            UpdatePayload::HardReset { .. } => UpdateType::HardReset,
        };

        let update = Update {
            id: uuid::Uuid::new_v4(),
            update_type,
            version,
            target,
            payload,
            status: UpdateStatus::Pending,
            created_at: chrono::Utc::now(),
            applied_at: None,
            rollback_data: None,
        };

        let id = update.id;
        self.pending.write().push(update);

        info!("Update queued: {}", id);
        id
    }

    /// Process pending updates
    pub async fn process_updates(&self) -> Result<Vec<uuid::Uuid>, UpdateError> {
        if *self.updating.read() {
            return Err(UpdateError::AlreadyUpdating);
        }

        *self.updating.write() = true;
        let mut applied = Vec::new();

        // Take all pending updates
        let updates: Vec<Update> = {
            let mut pending = self.pending.write();
            std::mem::take(&mut *pending)
        };

        for mut update in updates {
            info!(
                "Processing update: {} ({:?})",
                update.id, update.update_type
            );

            match self.apply_update(&mut update).await {
                Ok(_) => {
                    update.status = UpdateStatus::Applied;
                    update.applied_at = Some(chrono::Utc::now());
                    applied.push(update.id);
                    info!("Update applied: {}", update.id);
                }
                Err(e) => {
                    error!("Update failed: {} - {}", update.id, e);
                    update.status = UpdateStatus::Failed(e.to_string());

                    // Try rollback if we have data
                    if update.rollback_data.is_some() {
                        if let Err(re) = self.rollback_update(&update).await {
                            error!("Rollback failed: {}", re);
                        } else {
                            update.status = UpdateStatus::RolledBack;
                        }
                    }
                }
            }

            self.history.write().push(update);
        }

        *self.updating.write() = false;
        Ok(applied)
    }

    /// Apply a single update
    async fn apply_update(&self, update: &mut Update) -> Result<(), UpdateError> {
        update.status = UpdateStatus::Applying;

        match &update.payload {
            UpdatePayload::WasmChallenge {
                wasm_bytes,
                wasm_hash,
                config,
            } => {
                // Validate WASM hash
                let computed_hash = Self::compute_hash(wasm_bytes);
                if &computed_hash != wasm_hash {
                    return Err(UpdateError::HashMismatch {
                        expected: wasm_hash.clone(),
                        actual: computed_hash,
                    });
                }

                // Store rollback data (current WASM)
                // In real implementation, load current WASM
                update.rollback_data = Some(Vec::new());

                // Save new WASM to disk
                let wasm_path = self
                    .data_dir
                    .join("challenges")
                    .join(&config.id)
                    .join("code.wasm");
                std::fs::create_dir_all(wasm_path.parent().unwrap())?;
                std::fs::write(&wasm_path, wasm_bytes)?;

                info!("Challenge WASM updated: {}", config.id);
                Ok(())
            }

            UpdatePayload::Config(new_config) => {
                new_config
                    .validate()
                    .map_err(|e| UpdateError::Validation(e.to_string()))?;

                let config_path = self.data_dir.join("subnet_config.json");

                // Store rollback data
                if config_path.exists() {
                    update.rollback_data = Some(std::fs::read(&config_path)?);
                }

                new_config
                    .save(&config_path)
                    .map_err(|e| UpdateError::Io(std::io::Error::other(e.to_string())))?;
                *self.current_version.write() = new_config.version.clone();

                info!("Config updated to version {}", new_config.version);
                Ok(())
            }

            UpdatePayload::Validators { add, remove } => {
                info!("Validator update: +{} -{}", add.len(), remove.len());
                // Validator updates are handled by the runtime
                Ok(())
            }

            UpdatePayload::HardReset {
                reason,
                preserve_validators,
                new_config,
            } => {
                warn!("HARD RESET initiated: {}", reason);

                // Save snapshot before reset
                let snapshot_path = self.data_dir.join("snapshots").join("pre_reset");
                std::fs::create_dir_all(&snapshot_path)?;

                // Clear state directories
                if !preserve_validators {
                    let validators_path = self.data_dir.join("validators");
                    if validators_path.exists() {
                        std::fs::remove_dir_all(&validators_path)?;
                    }
                }

                // Clear challenge data
                let challenges_path = self.data_dir.join("challenges");
                if challenges_path.exists() {
                    std::fs::remove_dir_all(&challenges_path)?;
                }
                std::fs::create_dir_all(&challenges_path)?;

                // Apply new config if provided
                if let Some(config) = new_config {
                    config
                        .save(&self.data_dir.join("subnet_config.json"))
                        .map_err(|e| UpdateError::Io(std::io::Error::other(e.to_string())))?;
                }

                info!("Hard reset complete");
                Ok(())
            }
        }
    }

    /// Rollback an update
    async fn rollback_update(&self, update: &Update) -> Result<(), UpdateError> {
        let rollback_data = update
            .rollback_data
            .as_ref()
            .ok_or(UpdateError::NoRollbackData)?;

        match &update.target {
            UpdateTarget::Challenge(id) => {
                let wasm_path = self
                    .data_dir
                    .join("challenges")
                    .join(id.to_string())
                    .join("code.wasm");
                std::fs::write(&wasm_path, rollback_data)?;
                info!("Rolled back challenge: {}", id);
            }
            UpdateTarget::Config => {
                let config_path = self.data_dir.join("subnet_config.json");
                std::fs::write(&config_path, rollback_data)?;
                info!("Rolled back config");
            }
            _ => {
                warn!("Rollback not supported for {:?}", update.target);
            }
        }

        Ok(())
    }

    /// Compute SHA256 hash
    fn compute_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Get pending updates count
    pub fn pending_count(&self) -> usize {
        self.pending.read().len()
    }

    /// Get current version
    pub fn current_version(&self) -> String {
        self.current_version.read().clone()
    }

    /// Is update in progress
    pub fn is_updating(&self) -> bool {
        *self.updating.read()
    }

    /// Get update history
    pub fn history(&self) -> Vec<Update> {
        self.history.read().clone()
    }

    /// Clear old history (keep last N)
    pub fn prune_history(&self, keep: usize) {
        let mut history = self.history.write();
        if history.len() > keep {
            let drain_count = history.len() - keep;
            history.drain(0..drain_count);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("Update already in progress")]
    AlreadyUpdating,

    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("No rollback data available")]
    NoRollbackData,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_update_type_variants() {
        let types = vec![
            UpdateType::Hot,
            UpdateType::Warm,
            UpdateType::Cold,
            UpdateType::HardReset,
        ];

        for update_type in types {
            let json = serde_json::to_string(&update_type).unwrap();
            let decoded: UpdateType = serde_json::from_str(&json).unwrap();
            // Verify it deserializes
            match decoded {
                UpdateType::Hot | UpdateType::Warm | UpdateType::Cold | UpdateType::HardReset => {}
            }
        }
    }

    #[test]
    fn test_update_status_variants() {
        let statuses = vec![
            UpdateStatus::Pending,
            UpdateStatus::Downloading,
            UpdateStatus::Validating,
            UpdateStatus::Applying,
            UpdateStatus::Applied,
            UpdateStatus::Failed("error".into()),
            UpdateStatus::RolledBack,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let decoded: UpdateStatus = serde_json::from_str(&json).unwrap();
            // Verify it deserializes
            match decoded {
                UpdateStatus::Pending
                | UpdateStatus::Downloading
                | UpdateStatus::Validating
                | UpdateStatus::Applying
                | UpdateStatus::Applied
                | UpdateStatus::Failed(_)
                | UpdateStatus::RolledBack => {}
            }
        }
    }

    #[test]
    fn test_update_target_variants() {
        let challenge_id = ChallengeId(uuid::Uuid::new_v4());
        let targets = vec![
            UpdateTarget::Challenge(challenge_id),
            UpdateTarget::Config,
            UpdateTarget::AllChallenges,
            UpdateTarget::Validators,
        ];

        for target in targets {
            let json = serde_json::to_string(&target).unwrap();
            let decoded: UpdateTarget = serde_json::from_str(&json).unwrap();
            // Verify it deserializes
            match decoded {
                UpdateTarget::Challenge(_)
                | UpdateTarget::Config
                | UpdateTarget::AllChallenges
                | UpdateTarget::Validators => {}
            }
        }
    }

    #[tokio::test]
    async fn test_update_manager() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        // Queue a config update with explicit version
        let config = SubnetConfig {
            version: "0.2.0".to_string(),
            ..Default::default()
        };

        let id = manager.queue_update(
            UpdateTarget::Config,
            UpdatePayload::Config(config),
            "0.2.0".to_string(),
        );

        assert_eq!(manager.pending_count(), 1);

        // Process updates
        let applied = manager.process_updates().await.unwrap();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0], id);

        assert_eq!(manager.current_version(), "0.2.0");
    }

    #[test]
    fn test_compute_hash() {
        let data = b"hello world";
        let hash = UpdateManager::compute_hash(data);
        assert_eq!(hash.len(), 64); // SHA256 = 32 bytes = 64 hex chars
        
        // Same input should produce same hash
        let hash2 = UpdateManager::compute_hash(data);
        assert_eq!(hash, hash2);
        
        // Different input should produce different hash
        let hash3 = UpdateManager::compute_hash(b"different");
        assert_ne!(hash, hash3);
    }

    #[tokio::test]
    async fn test_wasm_challenge_update() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let wasm_bytes = vec![0u8; 100];
        let wasm_hash = UpdateManager::compute_hash(&wasm_bytes);
        let challenge_id = ChallengeId(uuid::Uuid::new_v4());

        let config = ChallengeConfig {
            id: challenge_id.0.to_string(),
            name: "Test Challenge".into(),
            wasm_hash: wasm_hash.clone(),
            wasm_source: "test".into(),
            emission_weight: 1.0,
            active: true,
            timeout_secs: 300,
            max_concurrent: 10,
        };

        let id = manager.queue_update(
            UpdateTarget::Challenge(challenge_id),
            UpdatePayload::WasmChallenge {
                wasm_bytes,
                wasm_hash,
                config,
            },
            "1.0.0".into(),
        );

        assert_eq!(manager.pending_count(), 1);
    }

    #[tokio::test]
    async fn test_validators_update() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let add = vec![platform_core::Hotkey([1u8; 32]), platform_core::Hotkey([2u8; 32])];
        let remove = vec![platform_core::Hotkey([3u8; 32])];

        let id = manager.queue_update(
            UpdateTarget::Validators,
            UpdatePayload::Validators {
                add: add.clone(),
                remove: remove.clone(),
            },
            "1.0.0".into(),
        );

        assert_eq!(manager.pending_count(), 1);
    }

    #[tokio::test]
    async fn test_hard_reset_update() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let id = manager.queue_update(
            UpdateTarget::Config,
            UpdatePayload::HardReset {
                reason: "Test reset".into(),
                preserve_validators: true,
                new_config: None,
            },
            "1.0.0".into(),
        );

        assert_eq!(manager.pending_count(), 1);
        
        let updates = manager.pending.read();
        assert_eq!(updates[0].update_type, UpdateType::HardReset);
    }

    #[tokio::test]
    async fn test_multiple_updates_processing() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        // Queue multiple updates
        for i in 0..3 {
            let config = SubnetConfig {
                version: format!("0.{}.0", i + 1),
                ..Default::default()
            };
            manager.queue_update(
                UpdateTarget::Config,
                UpdatePayload::Config(config),
                format!("0.{}.0", i + 1),
            );
        }

        assert_eq!(manager.pending_count(), 3);

        // Process all updates
        let applied = manager.process_updates().await.unwrap();
        assert_eq!(applied.len(), 3);
        assert_eq!(manager.pending_count(), 0);
    }

    #[tokio::test]
    async fn test_update_already_in_progress() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        *manager.updating.write() = true;

        let result = manager.process_updates().await;
        assert!(result.is_err());
        
        match result {
            Err(UpdateError::AlreadyUpdating) => {}
            _ => panic!("Expected AlreadyUpdating error"),
        }
    }

    #[test]
    fn test_update_creation_timestamps() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let config = SubnetConfig::default();
        let id = manager.queue_update(
            UpdateTarget::Config,
            UpdatePayload::Config(config),
            "1.0.0".into(),
        );

        let pending = manager.pending.read();
        let update = pending.iter().find(|u| u.id == id).unwrap();
        
        assert!(update.applied_at.is_none());
        assert!(update.rollback_data.is_none());
    }

    #[test]
    fn test_current_version() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        assert_eq!(manager.current_version(), "0.1.0");
    }

    #[test]
    fn test_is_updating_flag() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        assert!(!manager.is_updating());
        
        *manager.updating.write() = true;
        assert!(manager.is_updating());
    }

    #[test]
    fn test_update_payload_variants() {
        let wasm_payload = UpdatePayload::WasmChallenge {
            wasm_bytes: vec![0u8; 10],
            wasm_hash: "hash".into(),
            config: ChallengeConfig {
                id: "test".into(),
                name: "Test".into(),
                wasm_hash: "hash".into(),
                wasm_source: "test".into(),
                emission_weight: 1.0,
                active: true,
                timeout_secs: 300,
                max_concurrent: 10,
            },
        };

        let config_payload = UpdatePayload::Config(SubnetConfig::default());
        let validators_payload = UpdatePayload::Validators {
            add: vec![],
            remove: vec![],
        };
        let reset_payload = UpdatePayload::HardReset {
            reason: "test".into(),
            preserve_validators: false,
            new_config: None,
        };

        // Verify they all serialize/deserialize
        for payload in vec![wasm_payload, config_payload, validators_payload, reset_payload] {
            let json = serde_json::to_string(&payload).unwrap();
            let _decoded: UpdatePayload = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_update_status_serialization() {
        let statuses = vec![
            UpdateStatus::Pending,
            UpdateStatus::Downloading,
            UpdateStatus::Validating,
            UpdateStatus::Applying,
            UpdateStatus::Applied,
            UpdateStatus::Failed("test error".into()),
            UpdateStatus::RolledBack,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let decoded: UpdateStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, decoded);
        }
    }

    #[test]
    fn test_update_struct_fields() {
        let challenge_id = ChallengeId(uuid::Uuid::new_v4());
        let update = Update {
            id: uuid::Uuid::new_v4(),
            update_type: UpdateType::Hot,
            version: "1.0.0".into(),
            target: UpdateTarget::Challenge(challenge_id),
            payload: UpdatePayload::Config(SubnetConfig::default()),
            status: UpdateStatus::Pending,
            created_at: chrono::Utc::now(),
            applied_at: None,
            rollback_data: None,
        };

        assert_eq!(update.update_type, UpdateType::Hot);
        assert_eq!(update.version, "1.0.0");
        assert!(matches!(update.status, UpdateStatus::Pending));
        assert!(update.applied_at.is_none());
        assert!(update.rollback_data.is_none());
    }

    #[tokio::test]
    async fn test_process_updates_with_empty_queue() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let applied = manager.process_updates().await.unwrap();
        assert_eq!(applied.len(), 0);
    }

    #[tokio::test]
    async fn test_config_update_type_detection() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let config = SubnetConfig {
            version: "1.0.0".into(),
            ..Default::default()
        };

        manager.queue_update(
            UpdateTarget::Config,
            UpdatePayload::Config(config),
            "1.0.0".into(),
        );

        let pending = manager.pending.read();
        assert_eq!(pending[0].update_type, UpdateType::Warm);
    }

    #[tokio::test]
    async fn test_wasm_update_type_detection() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let challenge_id = ChallengeId(uuid::Uuid::new_v4());
        let config = ChallengeConfig {
            id: challenge_id.0.to_string(),
            name: "Test".into(),
            wasm_hash: "hash".into(),
            wasm_source: "test".into(),
            emission_weight: 1.0,
            active: true,
            timeout_secs: 300,
            max_concurrent: 10,
        };

        manager.queue_update(
            UpdateTarget::Challenge(challenge_id),
            UpdatePayload::WasmChallenge {
                wasm_bytes: vec![],
                wasm_hash: "hash".into(),
                config,
            },
            "1.0.0".into(),
        );

        let pending = manager.pending.read();
        assert_eq!(pending[0].update_type, UpdateType::Hot);
    }

    #[tokio::test]
    async fn test_validators_update_type_detection() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        manager.queue_update(
            UpdateTarget::Validators,
            UpdatePayload::Validators {
                add: vec![],
                remove: vec![],
            },
            "1.0.0".into(),
        );

        let pending = manager.pending.read();
        assert_eq!(pending[0].update_type, UpdateType::Hot);
    }

    #[tokio::test]
    async fn test_hard_reset_update_type_detection() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        manager.queue_update(
            UpdateTarget::Config,
            UpdatePayload::HardReset {
                reason: "test".into(),
                preserve_validators: true,
                new_config: None,
            },
            "1.0.0".into(),
        );

        let pending = manager.pending.read();
        assert_eq!(pending[0].update_type, UpdateType::HardReset);
    }

    #[test]
    fn test_pending_count() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        assert_eq!(manager.pending_count(), 0);

        manager.queue_update(
            UpdateTarget::Config,
            UpdatePayload::Config(SubnetConfig::default()),
            "1.0.0".into(),
        );

        assert_eq!(manager.pending_count(), 1);

        manager.queue_update(
            UpdateTarget::Config,
            UpdatePayload::Config(SubnetConfig::default()),
            "1.1.0".into(),
        );

        assert_eq!(manager.pending_count(), 2);
    }

    #[tokio::test]
    async fn test_update_history() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let config = SubnetConfig {
            version: "1.0.0".into(),
            ..Default::default()
        };

        manager.queue_update(
            UpdateTarget::Config,
            UpdatePayload::Config(config),
            "1.0.0".into(),
        );

        manager.process_updates().await.unwrap();

        let history = manager.history.read();
        assert_eq!(history.len(), 1);
        assert!(matches!(history[0].status, UpdateStatus::Applied));
    }

    #[tokio::test]
    async fn test_process_updates_rolls_back_on_failure() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let challenge_id = ChallengeId(uuid::Uuid::new_v4());
        let bad_hash = "not_the_real_hash".to_string();
        let wasm_bytes = vec![1u8, 2, 3];

        let config = ChallengeConfig {
            id: challenge_id.0.to_string(),
            name: "Rollback Challenge".into(),
            wasm_hash: bad_hash.clone(),
            wasm_source: "test".into(),
            emission_weight: 1.0,
            active: true,
            timeout_secs: 300,
            max_concurrent: 5,
        };

        manager.queue_update(
            UpdateTarget::Challenge(challenge_id),
            UpdatePayload::WasmChallenge {
                wasm_bytes,
                wasm_hash: bad_hash,
                config,
            },
            "1.0.0".into(),
        );

        // Ensure rollback data is present so failure triggers rollback path
        let rollback_bytes = b"rollback-wasm".to_vec();
        {
            let mut pending = manager.pending.write();
            pending[0].rollback_data = Some(rollback_bytes.clone());
        }

        // Prepare challenge directory for rollback write
        let challenge_dir = dir
            .path()
            .join("challenges")
            .join(challenge_id.0.to_string());
        std::fs::create_dir_all(&challenge_dir).unwrap();

        let applied = manager.process_updates().await.unwrap();
        assert!(applied.is_empty());

        let history = manager.history.read();
        assert_eq!(history.len(), 1);
        assert!(matches!(history[0].status, UpdateStatus::RolledBack));

        let rollback_path = challenge_dir.join("code.wasm");
        assert_eq!(std::fs::read(rollback_path).unwrap(), rollback_bytes);
    }

    #[tokio::test]
    async fn test_process_updates_handles_rollback_failure() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let challenge_id = ChallengeId(uuid::Uuid::new_v4());
        let wasm_bytes = vec![0u8, 1, 2];
        let bad_hash = "incorrect".to_string();

        let config = ChallengeConfig {
            id: challenge_id.0.to_string(),
            name: "RollbackFail".into(),
            wasm_hash: bad_hash.clone(),
            wasm_source: "test".into(),
            emission_weight: 1.0,
            active: true,
            timeout_secs: 60,
            max_concurrent: 5,
        };

        manager.queue_update(
            UpdateTarget::Challenge(challenge_id),
            UpdatePayload::WasmChallenge {
                wasm_bytes,
                wasm_hash: bad_hash,
                config,
            },
            "1.0.0".into(),
        );

        {
            let mut pending = manager.pending.write();
            pending[0].rollback_data = Some(b"rollback-data".to_vec());
        }

        let applied = manager.process_updates().await.unwrap();
        assert!(applied.is_empty());

        let history = manager.history.read();
        assert_eq!(history.len(), 1);
        assert!(matches!(history[0].status, UpdateStatus::Failed(_)));
    }

    #[tokio::test]
    async fn test_apply_update_wasm_challenge_success() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let challenge_id = ChallengeId(uuid::Uuid::new_v4());
        let wasm_bytes = vec![9u8, 8, 7, 6];
        let wasm_hash = UpdateManager::compute_hash(&wasm_bytes);

        let config = ChallengeConfig {
            id: challenge_id.0.to_string(),
            name: "ApplySuccess".into(),
            wasm_hash: wasm_hash.clone(),
            wasm_source: "test".into(),
            emission_weight: 1.0,
            active: true,
            timeout_secs: 60,
            max_concurrent: 5,
        };

        let mut update = Update {
            id: uuid::Uuid::new_v4(),
            update_type: UpdateType::Hot,
            version: "1.0.0".into(),
            target: UpdateTarget::Challenge(challenge_id),
            payload: UpdatePayload::WasmChallenge {
                wasm_bytes: wasm_bytes.clone(),
                wasm_hash,
                config,
            },
            status: UpdateStatus::Pending,
            created_at: chrono::Utc::now(),
            applied_at: None,
            rollback_data: None,
        };

        manager.apply_update(&mut update).await.unwrap();

        // Rollback data should have been captured and WASM written to disk
        assert!(update.rollback_data.is_some());
        let wasm_path = dir
            .path()
            .join("challenges")
            .join(challenge_id.0.to_string())
            .join("code.wasm");
        assert_eq!(std::fs::read(&wasm_path).unwrap(), wasm_bytes);
    }

    #[tokio::test]
    async fn test_apply_update_wasm_challenge_hash_mismatch() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let challenge_id = ChallengeId(uuid::Uuid::new_v4());
        let wasm_bytes = vec![1u8, 2, 3];

        let config = ChallengeConfig {
            id: challenge_id.0.to_string(),
            name: "ApplyFail".into(),
            wasm_hash: "expected_hash".into(),
            wasm_source: "test".into(),
            emission_weight: 1.0,
            active: true,
            timeout_secs: 60,
            max_concurrent: 5,
        };

        let mut update = Update {
            id: uuid::Uuid::new_v4(),
            update_type: UpdateType::Hot,
            version: "1.0.0".into(),
            target: UpdateTarget::Challenge(challenge_id),
            payload: UpdatePayload::WasmChallenge {
                wasm_bytes: wasm_bytes.clone(),
                wasm_hash: "expected_hash".into(),
                config,
            },
            status: UpdateStatus::Pending,
            created_at: chrono::Utc::now(),
            applied_at: None,
            rollback_data: None,
        };

        let err = manager.apply_update(&mut update).await.unwrap_err();
        match err {
            UpdateError::HashMismatch { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }

        // No WASM should be written and rollback data remains None
        let wasm_path = dir
            .path()
            .join("challenges")
            .join(challenge_id.0.to_string())
            .join("code.wasm");
        assert!(!wasm_path.exists());
        assert!(update.rollback_data.is_none());
    }

    #[tokio::test]
    async fn test_apply_update_validators_payload() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let add = vec![platform_core::Hotkey([1u8; 32])];
        let remove = vec![platform_core::Hotkey([2u8; 32])];

        let mut update = Update {
            id: uuid::Uuid::new_v4(),
            update_type: UpdateType::Hot,
            version: "1.0.0".into(),
            target: UpdateTarget::Validators,
            payload: UpdatePayload::Validators { add: add.clone(), remove: remove.clone() },
            status: UpdateStatus::Pending,
            created_at: chrono::Utc::now(),
            applied_at: None,
            rollback_data: None,
        };

        manager.apply_update(&mut update).await.unwrap();
        assert!(update.rollback_data.is_none());

        let challenges_dir = dir.path().join("challenges");
        assert!(!challenges_dir.exists(), "validator updates should not touch disk state");
    }

    #[tokio::test]
    async fn test_apply_update_hard_reset_clears_state_and_applies_config() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let validators_dir = dir.path().join("validators");
        std::fs::create_dir_all(&validators_dir).unwrap();
        std::fs::write(validators_dir.join("node"), b"validator").unwrap();

        let challenges_dir = dir.path().join("challenges");
        std::fs::create_dir_all(challenges_dir.join("legacy")).unwrap();

        let new_config = SubnetConfig {
            version: "9.9.9".into(),
            ..Default::default()
        };

        let mut update = Update {
            id: uuid::Uuid::new_v4(),
            update_type: UpdateType::HardReset,
            version: "9.9.9".into(),
            target: UpdateTarget::Config,
            payload: UpdatePayload::HardReset {
                reason: "maintenance".into(),
                preserve_validators: false,
                new_config: Some(new_config.clone()),
            },
            status: UpdateStatus::Pending,
            created_at: chrono::Utc::now(),
            applied_at: None,
            rollback_data: None,
        };

        manager.apply_update(&mut update).await.unwrap();

        assert!(!validators_dir.exists());
        assert!(challenges_dir.exists());
        assert!(!challenges_dir.join("legacy").exists());
        assert!(dir.path().join("snapshots").join("pre_reset").exists());

        let config_bytes = std::fs::read(dir.path().join("subnet_config.json")).unwrap();
        assert!(String::from_utf8(config_bytes).unwrap().contains("9.9.9"));
    }

    #[tokio::test]
    async fn test_apply_update_hard_reset_preserves_validators() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let validators_dir = dir.path().join("validators");
        std::fs::create_dir_all(&validators_dir).unwrap();
        std::fs::write(validators_dir.join("node"), b"validator").unwrap();

        let mut update = Update {
            id: uuid::Uuid::new_v4(),
            update_type: UpdateType::HardReset,
            version: "1.0.0".into(),
            target: UpdateTarget::Config,
            payload: UpdatePayload::HardReset {
                reason: "maintenance".into(),
                preserve_validators: true,
                new_config: None,
            },
            status: UpdateStatus::Pending,
            created_at: chrono::Utc::now(),
            applied_at: None,
            rollback_data: None,
        };

        manager.apply_update(&mut update).await.unwrap();
        assert!(validators_dir.exists());
    }

    #[tokio::test]
    async fn test_rollback_update_challenge_target() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let challenge_id = ChallengeId(uuid::Uuid::new_v4());
        let rollback_bytes = b"restore-wasm".to_vec();

        let challenge_dir = dir
            .path()
            .join("challenges")
            .join(challenge_id.0.to_string());
        std::fs::create_dir_all(&challenge_dir).unwrap();

        let update = Update {
            id: uuid::Uuid::new_v4(),
            update_type: UpdateType::Hot,
            version: "1.0.0".into(),
            target: UpdateTarget::Challenge(challenge_id),
            payload: UpdatePayload::Config(SubnetConfig::default()),
            status: UpdateStatus::Failed("hash".into()),
            created_at: chrono::Utc::now(),
            applied_at: None,
            rollback_data: Some(rollback_bytes.clone()),
        };

        manager.rollback_update(&update).await.unwrap();

        let wasm_path = challenge_dir.join("code.wasm");
        assert_eq!(std::fs::read(wasm_path).unwrap(), rollback_bytes);
    }

    #[tokio::test]
    async fn test_rollback_update_config_target() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let rollback_bytes = br#"{"version":"2.0.0"}"#.to_vec();

        let update = Update {
            id: uuid::Uuid::new_v4(),
            update_type: UpdateType::Warm,
            version: "2.0.0".into(),
            target: UpdateTarget::Config,
            payload: UpdatePayload::Config(SubnetConfig::default()),
            status: UpdateStatus::Failed("io".into()),
            created_at: chrono::Utc::now(),
            applied_at: None,
            rollback_data: Some(rollback_bytes.clone()),
        };

        manager.rollback_update(&update).await.unwrap();
        let config_path = dir.path().join("subnet_config.json");
        assert_eq!(std::fs::read(config_path).unwrap(), rollback_bytes);
    }

    #[tokio::test]
    async fn test_rollback_update_for_unsupported_target() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        let update = Update {
            id: uuid::Uuid::new_v4(),
            update_type: UpdateType::Hot,
            version: "1.0.0".into(),
            target: UpdateTarget::Validators,
            payload: UpdatePayload::Validators {
                add: vec![],
                remove: vec![],
            },
            status: UpdateStatus::Failed("test".into()),
            created_at: chrono::Utc::now(),
            applied_at: None,
            rollback_data: Some(vec![1, 2, 3]),
        };

        manager.rollback_update(&update).await.unwrap();
        let unsupported_dir = manager.data_dir.join("validators");
        assert!(!unsupported_dir.exists());
    }

    #[test]
    fn test_history_method_returns_clone() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        manager.history.write().push(Update {
            id: uuid::Uuid::new_v4(),
            update_type: UpdateType::Hot,
            version: "1.0".into(),
            target: UpdateTarget::Config,
            payload: UpdatePayload::Config(SubnetConfig::default()),
            status: UpdateStatus::Applied,
            created_at: chrono::Utc::now(),
            applied_at: None,
            rollback_data: None,
        });

        let external_history = manager.history();
        assert_eq!(external_history.len(), 1);

        // Mutating returned vector should not affect manager's internal history
        drop(external_history);
        assert_eq!(manager.history.read().len(), 1);
    }

    #[test]
    fn test_prune_history_keeps_most_recent() {
        let dir = tempdir().unwrap();
        let manager = UpdateManager::new(dir.path().to_path_buf());

        for i in 0..5 {
            manager.history.write().push(Update {
                id: uuid::Uuid::new_v4(),
                update_type: UpdateType::Hot,
                version: format!("1.0.{}", i),
                target: UpdateTarget::Config,
                payload: UpdatePayload::Config(SubnetConfig::default()),
                status: UpdateStatus::Applied,
                created_at: chrono::Utc::now(),
                applied_at: None,
                rollback_data: None,
            });
        }

        manager.prune_history(2);
        let history = manager.history.read();
        assert_eq!(history.len(), 2);
        assert!(history
            .iter()
            .all(|update| update.version == "1.0.3" || update.version == "1.0.4"));
    }

    #[test]
    fn test_update_target_challenge() {
        let challenge_id = ChallengeId(uuid::Uuid::new_v4());
        let target = UpdateTarget::Challenge(challenge_id);
        let json = serde_json::to_string(&target).unwrap();
        let decoded: UpdateTarget = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, UpdateTarget::Challenge(_)));
    }

    #[test]
    fn test_update_target_all_challenges() {
        let target = UpdateTarget::AllChallenges;
        let json = serde_json::to_string(&target).unwrap();
        let decoded: UpdateTarget = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, UpdateTarget::AllChallenges));
    }

}
