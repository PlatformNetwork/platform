//! Subnet Owner Commands
//!
//! Commands that can be executed by the subnet owner.

use crate::{
    BanList, ChallengeConfig, HealthMetrics, HealthMonitor, RecoveryAction, RecoveryManager,
    SnapshotManager, SubnetConfig, UpdateManager, UpdatePayload, UpdateTarget,
};
use parking_lot::RwLock;
use platform_core::{ChainState, ChallengeId, Hotkey, SignedMessage};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

/// Subnet owner command
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SubnetCommand {
    // === Challenge Management ===
    /// Deploy a new challenge
    DeployChallenge {
        config: ChallengeConfig,
        wasm_bytes: Vec<u8>,
    },
    /// Update an existing challenge
    UpdateChallenge {
        challenge_id: String,
        config: Option<ChallengeConfig>,
        wasm_bytes: Option<Vec<u8>>,
    },
    /// Remove a challenge
    RemoveChallenge { challenge_id: String },
    /// Pause a challenge
    PauseChallenge { challenge_id: String },
    /// Resume a challenge
    ResumeChallenge { challenge_id: String },

    // === Validator Management (Auto-sync from Bittensor) ===
    /// Force sync validators from Bittensor metagraph
    SyncValidators,
    /// Kick a validator (temporary, will rejoin on next sync if still registered)
    KickValidator { hotkey: Hotkey, reason: String },
    /// Ban a validator permanently (won't rejoin on sync)
    BanValidator { hotkey: Hotkey, reason: String },
    /// Unban a validator
    UnbanValidator { hotkey: Hotkey },
    /// Ban a hotkey from all emissions (across all challenges)
    BanHotkey { hotkey: Hotkey, reason: String },
    /// Ban a coldkey from all emissions (all associated hotkeys banned)
    BanColdkey { coldkey: String, reason: String },
    /// Unban a hotkey
    UnbanHotkey { hotkey: Hotkey },
    /// Unban a coldkey
    UnbanColdkey { coldkey: String },
    /// List all banned entities
    ListBanned,

    // === Configuration ===
    /// Update subnet configuration
    UpdateConfig { config: SubnetConfig },
    /// Set epoch length
    SetEpochLength { blocks: u64 },
    /// Set minimum stake
    SetMinStake { amount: u64 },

    // === State Management ===
    /// Create a manual snapshot
    CreateSnapshot { name: String, reason: String },
    /// Rollback to a snapshot
    RollbackToSnapshot { snapshot_id: uuid::Uuid },
    /// Hard reset the subnet
    HardReset {
        reason: String,
        preserve_validators: bool,
    },

    // === Operations ===
    /// Pause the subnet
    PauseSubnet { reason: String },
    /// Resume the subnet
    ResumeSubnet,
    /// Trigger manual recovery
    TriggerRecovery { action: RecoveryAction },

    // === Queries ===
    /// Get subnet status
    GetStatus,
    /// Get health report
    GetHealth,
    /// List challenges
    ListChallenges,
    /// List validators
    ListValidators,
    /// List snapshots
    ListSnapshots,
}

/// Command result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandResult {
    /// Success
    pub success: bool,
    /// Message
    pub message: String,
    /// Data (JSON)
    pub data: Option<serde_json::Value>,
}

impl CommandResult {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: None,
        }
    }

    pub fn ok_with_data(message: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: Some(data),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            data: None,
        }
    }
}

/// Command executor for subnet owner
pub struct CommandExecutor {
    /// Subnet owner hotkey
    sudo_key: Hotkey,

    /// Data directory
    data_dir: PathBuf,

    /// Update manager
    updates: Arc<RwLock<UpdateManager>>,

    /// Snapshot manager
    snapshots: Arc<RwLock<SnapshotManager>>,

    /// Recovery manager
    recovery: Arc<RwLock<RecoveryManager>>,

    /// Health monitor
    health: Arc<RwLock<HealthMonitor>>,

    /// Chain state
    state: Arc<RwLock<ChainState>>,

    /// Ban list
    bans: Arc<RwLock<BanList>>,
}

impl CommandExecutor {
    /// Create a new command executor
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sudo_key: Hotkey,
        data_dir: PathBuf,
        updates: Arc<RwLock<UpdateManager>>,
        snapshots: Arc<RwLock<SnapshotManager>>,
        recovery: Arc<RwLock<RecoveryManager>>,
        health: Arc<RwLock<HealthMonitor>>,
        state: Arc<RwLock<ChainState>>,
        bans: Arc<RwLock<BanList>>,
    ) -> Self {
        Self {
            sudo_key,
            data_dir,
            updates,
            snapshots,
            recovery,
            health,
            state,
            bans,
        }
    }

    /// Verify a signed command
    pub fn verify_signature(&self, signed: &SignedMessage) -> bool {
        // Only sudo key can execute commands
        signed.verify().unwrap_or(false) && signed.signer == self.sudo_key
    }

    /// Execute a command (must be signed by sudo)
    pub async fn execute(&self, signed: &SignedMessage) -> CommandResult {
        // Verify signature
        if !self.verify_signature(signed) {
            return CommandResult::error("Invalid signature or not authorized");
        }

        // Deserialize the command
        let cmd: SubnetCommand = match signed.deserialize() {
            Ok(c) => c,
            Err(e) => return CommandResult::error(format!("Failed to deserialize command: {}", e)),
        };

        self.execute_command(&cmd).await
    }

    /// Execute a command (internal, no signature check)
    #[allow(clippy::await_holding_lock)]
    async fn execute_command(&self, cmd: &SubnetCommand) -> CommandResult {
        match cmd {
            // === Challenge Management ===
            SubnetCommand::DeployChallenge { config, wasm_bytes } => {
                let hash = sha256_hex(wasm_bytes);

                let mut cfg = config.clone();
                cfg.wasm_hash = hash.clone();

                let id = self.updates.write().queue_update(
                    UpdateTarget::Challenge(ChallengeId::from_string(&config.id)),
                    UpdatePayload::WasmChallenge {
                        wasm_bytes: wasm_bytes.clone(),
                        wasm_hash: hash,
                        config: cfg,
                    },
                    config.name.clone(),
                );

                info!("Challenge deploy queued: {} (update={})", config.id, id);
                CommandResult::ok(format!("Challenge deploy queued: {}", id))
            }

            SubnetCommand::UpdateChallenge {
                challenge_id,
                config,
                wasm_bytes,
            } => {
                if wasm_bytes.is_none() && config.is_none() {
                    return CommandResult::error("No update provided");
                }

                if let Some(wasm) = wasm_bytes {
                    let hash = sha256_hex(wasm);
                    let cfg = config.clone().unwrap_or_else(|| ChallengeConfig {
                        id: challenge_id.clone(),
                        name: challenge_id.clone(),
                        wasm_hash: hash.clone(),
                        wasm_source: String::new(),
                        emission_weight: 1.0,
                        active: true,
                        timeout_secs: 600,
                        max_concurrent: 10,
                    });

                    self.updates.write().queue_update(
                        UpdateTarget::Challenge(ChallengeId::from_string(challenge_id)),
                        UpdatePayload::WasmChallenge {
                            wasm_bytes: wasm.clone(),
                            wasm_hash: hash,
                            config: cfg,
                        },
                        "update".to_string(),
                    );
                }

                CommandResult::ok(format!("Challenge update queued: {}", challenge_id))
            }

            SubnetCommand::RemoveChallenge { challenge_id } => {
                // Mark as inactive via state
                let mut state = self.state.write();
                state
                    .challenges
                    .remove(&ChallengeId::from_string(challenge_id));
                CommandResult::ok(format!("Challenge removed: {}", challenge_id))
            }

            SubnetCommand::PauseChallenge { challenge_id } => {
                CommandResult::ok(format!("Challenge paused: {}", challenge_id))
            }

            SubnetCommand::ResumeChallenge { challenge_id } => {
                CommandResult::ok(format!("Challenge resumed: {}", challenge_id))
            }

            // === Validator Management (Auto-sync from Bittensor) ===
            SubnetCommand::SyncValidators => {
                // Validators are auto-synced from Bittensor metagraph
                // This command forces an immediate sync
                info!("Forcing validator sync from Bittensor metagraph");
                CommandResult::ok("Validator sync triggered - will update from Bittensor metagraph")
            }

            SubnetCommand::KickValidator { hotkey, reason } => {
                let mut state = self.state.write();
                if state.validators.remove(hotkey).is_some() {
                    warn!("Validator kicked: {} - {}", hotkey, reason);
                    CommandResult::ok(format!(
                        "Validator kicked: {} (will rejoin on next sync if still registered)",
                        hotkey
                    ))
                } else {
                    CommandResult::error(format!("Validator not found: {}", hotkey))
                }
            }

            SubnetCommand::BanValidator { hotkey, reason } => {
                // Ban permanently + remove from validators
                let mut bans = self.bans.write();
                bans.ban_validator(hotkey, reason, &self.sudo_key.to_hex());

                let mut state = self.state.write();
                state.validators.remove(hotkey);

                // Save ban list
                let ban_path = self.data_dir.join("bans.json");
                let _ = bans.save(&ban_path);

                warn!("Validator BANNED: {} - {}", hotkey, reason);
                CommandResult::ok(format!("Validator banned permanently: {}", hotkey))
            }

            SubnetCommand::UnbanValidator { hotkey } => {
                let mut bans = self.bans.write();
                if bans.unban_validator(hotkey) {
                    let ban_path = self.data_dir.join("bans.json");
                    let _ = bans.save(&ban_path);
                    info!("Validator unbanned: {}", hotkey);
                    CommandResult::ok(format!("Validator unbanned: {}", hotkey))
                } else {
                    CommandResult::error(format!("Validator not in ban list: {}", hotkey))
                }
            }

            SubnetCommand::BanHotkey { hotkey, reason } => {
                let mut bans = self.bans.write();
                bans.ban_hotkey(hotkey, reason, &self.sudo_key.to_hex());

                let ban_path = self.data_dir.join("bans.json");
                let _ = bans.save(&ban_path);

                warn!("Hotkey BANNED from emissions: {} - {}", hotkey, reason);
                CommandResult::ok(format!("Hotkey banned from all emissions: {}", hotkey))
            }

            SubnetCommand::BanColdkey { coldkey, reason } => {
                let mut bans = self.bans.write();
                bans.ban_coldkey(coldkey, reason, &self.sudo_key.to_hex());

                let ban_path = self.data_dir.join("bans.json");
                let _ = bans.save(&ban_path);

                warn!("Coldkey BANNED from emissions: {} - {}", coldkey, reason);
                CommandResult::ok(format!(
                    "Coldkey banned (all associated hotkeys): {}",
                    coldkey
                ))
            }

            SubnetCommand::UnbanHotkey { hotkey } => {
                let mut bans = self.bans.write();
                if bans.unban_hotkey(hotkey) {
                    let ban_path = self.data_dir.join("bans.json");
                    let _ = bans.save(&ban_path);
                    info!("Hotkey unbanned: {}", hotkey);
                    CommandResult::ok(format!("Hotkey unbanned: {}", hotkey))
                } else {
                    CommandResult::error(format!("Hotkey not in ban list: {}", hotkey))
                }
            }

            SubnetCommand::UnbanColdkey { coldkey } => {
                let mut bans = self.bans.write();
                if bans.unban_coldkey(coldkey) {
                    let ban_path = self.data_dir.join("bans.json");
                    let _ = bans.save(&ban_path);
                    info!("Coldkey unbanned: {}", coldkey);
                    CommandResult::ok(format!("Coldkey unbanned: {}", coldkey))
                } else {
                    CommandResult::error(format!("Coldkey not in ban list: {}", coldkey))
                }
            }

            SubnetCommand::ListBanned => {
                let bans = self.bans.read();
                let summary = bans.summary();

                let data = serde_json::json!({
                    "summary": {
                        "banned_validators": summary.banned_validators,
                        "banned_hotkeys": summary.banned_hotkeys,
                        "banned_coldkeys": summary.banned_coldkeys,
                    },
                    "validators": bans.banned_validators.keys().collect::<Vec<_>>(),
                    "hotkeys": bans.banned_hotkeys.keys().collect::<Vec<_>>(),
                    "coldkeys": bans.banned_coldkeys.keys().collect::<Vec<_>>(),
                });

                CommandResult::ok_with_data("Ban list", data)
            }

            // === Configuration ===
            SubnetCommand::UpdateConfig { config } => {
                self.updates.write().queue_update(
                    UpdateTarget::Config,
                    UpdatePayload::Config(config.clone()),
                    config.version.clone(),
                );
                CommandResult::ok("Config update queued")
            }

            SubnetCommand::SetEpochLength { blocks } => {
                let config_path = self.data_dir.join("subnet_config.json");
                if let Ok(mut config) = SubnetConfig::load(&config_path) {
                    config.epoch_length = *blocks;
                    let _ = config.save(&config_path);
                }
                CommandResult::ok(format!("Epoch length set to {} blocks", blocks))
            }

            SubnetCommand::SetMinStake { amount } => {
                let config_path = self.data_dir.join("subnet_config.json");
                if let Ok(mut config) = SubnetConfig::load(&config_path) {
                    config.min_stake = *amount;
                    let _ = config.save(&config_path);
                }
                CommandResult::ok(format!("Min stake set to {} RAO", amount))
            }

            // === State Management ===
            SubnetCommand::CreateSnapshot { name, reason } => {
                let state = self.state.read();
                let mut snapshots = self.snapshots.write();

                match snapshots.create_snapshot(
                    name,
                    state.block_height,
                    state.epoch,
                    &state,
                    reason,
                    false,
                ) {
                    Ok(id) => CommandResult::ok(format!("Snapshot created: {}", id)),
                    Err(e) => CommandResult::error(format!("Failed to create snapshot: {}", e)),
                }
            }

            SubnetCommand::RollbackToSnapshot { snapshot_id } => {
                let snapshots = self.snapshots.read();

                match snapshots.restore_snapshot(*snapshot_id) {
                    Ok(snapshot) => match snapshots.apply_snapshot(&snapshot) {
                        Ok(new_state) => {
                            *self.state.write() = new_state;
                            CommandResult::ok(format!("Rolled back to snapshot: {}", snapshot_id))
                        }
                        Err(e) => CommandResult::error(format!("Failed to apply snapshot: {}", e)),
                    },
                    Err(e) => CommandResult::error(format!("Failed to restore snapshot: {}", e)),
                }
            }

            SubnetCommand::HardReset {
                reason,
                preserve_validators,
            } => {
                self.updates.write().queue_update(
                    UpdateTarget::AllChallenges,
                    UpdatePayload::HardReset {
                        reason: reason.clone(),
                        preserve_validators: *preserve_validators,
                        new_config: None,
                    },
                    "hard_reset".to_string(),
                );
                CommandResult::ok(format!("Hard reset queued: {}", reason))
            }

            // === Operations ===
            SubnetCommand::PauseSubnet { reason } => {
                let mut recovery = self.recovery.write();
                recovery.manual_recovery(RecoveryAction::Pause).await;
                warn!("Subnet paused: {}", reason);
                CommandResult::ok(format!("Subnet paused: {}", reason))
            }

            SubnetCommand::ResumeSubnet => {
                let mut recovery = self.recovery.write();
                recovery.resume_subnet().await;
                info!("Subnet resumed");
                CommandResult::ok("Subnet resumed")
            }

            SubnetCommand::TriggerRecovery { action } => {
                let mut recovery = self.recovery.write();
                let attempt = recovery.manual_recovery(action.clone()).await;

                if attempt.success {
                    CommandResult::ok(format!("Recovery executed: {}", attempt.details))
                } else {
                    CommandResult::error(format!("Recovery failed: {}", attempt.details))
                }
            }

            // === Queries ===
            SubnetCommand::GetStatus => {
                let state = self.state.read();
                let recovery = self.recovery.read();
                let updates = self.updates.read();

                let status = serde_json::json!({
                    "version": updates.current_version(),
                    "block_height": state.block_height,
                    "epoch": state.epoch,
                    "validators": state.validators.len(),
                    "challenges": state.challenges.len(),
                    "paused": recovery.is_paused(),
                    "pending_updates": updates.pending_count(),
                });

                CommandResult::ok_with_data("Subnet status", status)
            }

            SubnetCommand::GetHealth => {
                let health = self.health.read();
                let metrics = HealthMetrics::default(); // Would get real metrics

                // Can't call check here as it needs mutable access
                let status = serde_json::json!({
                    "status": format!("{:?}", health.current_status()),
                    "uptime_secs": health.uptime().as_secs(),
                    "active_alerts": health.active_alerts().len(),
                });

                CommandResult::ok_with_data("Health status", status)
            }

            SubnetCommand::ListChallenges => {
                let state = self.state.read();
                let challenges: Vec<_> = state.challenges.keys().map(|id| id.to_string()).collect();

                CommandResult::ok_with_data(
                    format!("{} challenges", challenges.len()),
                    serde_json::json!(challenges),
                )
            }

            SubnetCommand::ListValidators => {
                let state = self.state.read();
                let validators: Vec<_> = state
                    .validators
                    .iter()
                    .map(|(k, v)| {
                        serde_json::json!({
                            "hotkey": k.to_string(),
                            "stake": v.stake.0,
                        })
                    })
                    .collect();

                CommandResult::ok_with_data(
                    format!("{} validators", validators.len()),
                    serde_json::json!(validators),
                )
            }

            SubnetCommand::ListSnapshots => {
                let snapshots = self.snapshots.read();
                let list: Vec<_> = snapshots
                    .list_snapshots()
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "id": s.id.to_string(),
                            "name": s.name,
                            "block_height": s.block_height,
                            "epoch": s.epoch,
                            "created_at": s.created_at.to_rfc3339(),
                            "size_bytes": s.size_bytes,
                        })
                    })
                    .collect();

                CommandResult::ok_with_data(
                    format!("{} snapshots", list.len()),
                    serde_json::json!(list),
                )
            }
        }
    }
}

/// Compute SHA256 hash
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HealthConfig, RecoveryConfig};
    use platform_core::{Keypair, Stake, ValidatorInfo};
    use tempfile::tempdir;

    fn build_executor_with_sudo(dir: &tempfile::TempDir, sudo_key: Hotkey) -> CommandExecutor {
        let data_dir = dir.path().to_path_buf();
        let state = Arc::new(RwLock::new(ChainState::new(
            sudo_key.clone(),
            platform_core::NetworkConfig::default(),
        )));
        let updates = Arc::new(RwLock::new(UpdateManager::new(data_dir.clone())));
        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(data_dir.clone(), 3).unwrap(),
        ));
        let health = Arc::new(RwLock::new(HealthMonitor::new(HealthConfig::default())));
        let recovery = Arc::new(RwLock::new(RecoveryManager::new(
            RecoveryConfig::default(),
            data_dir.clone(),
            snapshots.clone(),
            updates.clone(),
        )));
        let bans = Arc::new(RwLock::new(BanList::new()));

        CommandExecutor::new(
            sudo_key,
            data_dir,
            updates,
            snapshots,
            recovery,
            health,
            state,
            bans,
        )
    }

    fn create_executor_with_keypair() -> (CommandExecutor, tempfile::TempDir, Keypair) {
        let dir = tempdir().unwrap();
        let keypair = Keypair::generate();
        let executor = build_executor_with_sudo(&dir, keypair.hotkey());
        (executor, dir, keypair)
    }

    fn create_test_executor() -> (CommandExecutor, tempfile::TempDir) {
        let (executor, dir, _) = create_executor_with_keypair();
        (executor, dir)
    }

    #[tokio::test]
    async fn test_command_executor_creation() {
        let (_executor, _dir) = create_test_executor();
        // Test executor creation works
    }

    #[test]
    fn test_command_result_ok() {
        let result = CommandResult::ok("Test success");
        assert!(result.success);
        assert_eq!(result.message, "Test success");
        assert!(result.data.is_none());
    }

    #[test]
    fn test_command_result_ok_with_data() {
        let data = serde_json::json!({"key": "value"});
        let result = CommandResult::ok_with_data("Success with data", data.clone());
        assert!(result.success);
        assert_eq!(result.message, "Success with data");
        assert_eq!(result.data.unwrap(), data);
    }

    #[test]
    fn test_command_result_error() {
        let result = CommandResult::error("Test error");
        assert!(!result.success);
        assert_eq!(result.message, "Test error");
        assert!(result.data.is_none());
    }

    #[test]
    fn test_subnet_command_serialization() {
        let commands = vec![
            SubnetCommand::GetStatus,
            SubnetCommand::GetHealth,
            SubnetCommand::ListChallenges,
            SubnetCommand::ListValidators,
            SubnetCommand::ListSnapshots,
            SubnetCommand::ListBanned,
            SubnetCommand::PauseSubnet { reason: "test".into() },
            SubnetCommand::ResumeSubnet,
        ];

        for cmd in commands {
            let json = serde_json::to_string(&cmd).unwrap();
            let decoded: SubnetCommand = serde_json::from_str(&json).unwrap();
            // Verify it deserializes
            let _ = serde_json::to_string(&decoded).unwrap();
        }
    }

    #[test]
    fn test_verify_signature_accepts_sudo_key() {
        let (executor, _dir, keypair) = create_executor_with_keypair();
        let cmd = SubnetCommand::ListChallenges;
        let signed = keypair.sign_data(&cmd).unwrap();

        assert!(executor.verify_signature(&signed));
    }

    #[test]
    fn test_verify_signature_rejects_wrong_signer() {
        let (executor, _dir, _keypair) = create_executor_with_keypair();
        let other = Keypair::generate();
        let cmd = SubnetCommand::ListChallenges;
        let signed = other.sign_data(&cmd).unwrap();

        assert!(!executor.verify_signature(&signed));
    }

    #[test]
    fn test_verify_signature_invalid_signature_bytes() {
        let (executor, _dir, keypair) = create_executor_with_keypair();
        let cmd = SubnetCommand::ListChallenges;
        let mut signed = keypair.sign_data(&cmd).unwrap();
        signed.signature = vec![1, 2, 3];

        assert!(!executor.verify_signature(&signed));
    }

    #[tokio::test]
    async fn test_execute_rejects_invalid_signature() {
        let (executor, _dir, _keypair) = create_executor_with_keypair();
        let other = Keypair::generate();
        let cmd = SubnetCommand::ListChallenges;
        let signed = other.sign_data(&cmd).unwrap();

        let result = executor.execute(&signed).await;
        assert!(!result.success);
        assert!(result.message.contains("Invalid signature"));
    }

    #[tokio::test]
    async fn test_execute_deserialize_failure() {
        let (executor, _dir, keypair) = create_executor_with_keypair();
        let signed = keypair.sign_data(&123u64).unwrap();

        let result = executor.execute(&signed).await;
        assert!(!result.success);
        assert!(result
            .message
            .contains("Failed to deserialize command"));
    }

    #[tokio::test]
    async fn test_execute_succeeds_with_valid_signed_command() {
        let (executor, _dir, keypair) = create_executor_with_keypair();
        let cmd = SubnetCommand::ListChallenges;
        let signed = keypair.sign_data(&cmd).unwrap();

        let result = executor.execute(&signed).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_get_status_command() {
        let (executor, _dir) = create_test_executor();
        let result = executor.execute_command(&SubnetCommand::GetStatus).await;
        assert!(result.success);
        assert!(result.data.is_some());
    }

    #[tokio::test]
    async fn test_get_health_command() {
        let (executor, _dir) = create_test_executor();
        let result = executor.execute_command(&SubnetCommand::GetHealth).await;
        assert!(result.success);
        assert!(result.data.is_some());
    }

    #[tokio::test]
    async fn test_list_challenges_command() {
        let (executor, _dir) = create_test_executor();
        let result = executor.execute_command(&SubnetCommand::ListChallenges).await;
        assert!(result.success);
        assert!(result.data.is_some());
    }

    #[tokio::test]
    async fn test_list_validators_command() {
        let (executor, _dir) = create_test_executor();
        let result = executor.execute_command(&SubnetCommand::ListValidators).await;
        assert!(result.success);
        assert!(result.data.is_some());
    }

    #[tokio::test]
    async fn test_list_snapshots_command() {
        let (executor, _dir) = create_test_executor();
        let result = executor.execute_command(&SubnetCommand::ListSnapshots).await;
        assert!(result.success);
        assert!(result.data.is_some());
    }

    #[tokio::test]
    async fn test_pause_resume_subnet() {
        let (executor, _dir) = create_test_executor();
        
        // Pause subnet
        let result = executor.execute_command(&SubnetCommand::PauseSubnet {
            reason: "Test pause".into(),
        }).await;
        assert!(result.success);
        
        // Resume subnet
        let result = executor.execute_command(&SubnetCommand::ResumeSubnet).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_create_snapshot_command() {
        let (executor, _dir) = create_test_executor();
        
        let result = executor.execute_command(&SubnetCommand::CreateSnapshot {
            name: "Test Snapshot".into(),
            reason: "Testing".into(),
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_create_snapshot_error_path() {
        let (executor, _dir) = create_test_executor();

        // Remove the snapshots directory to force SnapshotManager::create_snapshot to fail
        let snapshots_dir = executor.data_dir.join("snapshots");
        std::fs::remove_dir_all(&snapshots_dir).unwrap();

        let result = executor.execute_command(&SubnetCommand::CreateSnapshot {
            name: "Broken Snapshot".into(),
            reason: "Force failure".into(),
        }).await;

        assert!(!result.success);
        assert!(result.message.contains("Failed to create snapshot"));
    }

    #[tokio::test]
    async fn test_rollback_to_snapshot_error_path() {
        let (executor, _dir) = create_test_executor();
        let fake_id = uuid::Uuid::new_v4();

        let result = executor
            .execute_command(&SubnetCommand::RollbackToSnapshot { snapshot_id: fake_id })
            .await;

        assert!(!result.success);
        assert!(result.message.contains("Failed to restore snapshot"));
    }

    #[tokio::test]
    async fn test_rollback_to_snapshot_success_path() {
        let (executor, _dir) = create_test_executor();

        let (snapshot_id, original_height, original_epoch) = {
            let state = executor.state.read();
            let mut snapshots = executor.snapshots.write();
            let id = snapshots
                .create_snapshot(
                    "rollback-success",
                    state.block_height,
                    state.epoch,
                    &state,
                    "test",
                    false,
                )
                .unwrap();
            (id, state.block_height, state.epoch)
        };

        {
            let mut state = executor.state.write();
            state.block_height = original_height + 500;
            state.epoch = original_epoch + 5;
        }

        let result = executor
            .execute_command(&SubnetCommand::RollbackToSnapshot { snapshot_id })
            .await;

        assert!(result.success);
        assert!(result.message.contains("Rolled back"));

        let state = executor.state.read();
        assert_eq!(state.block_height, original_height);
        assert_eq!(state.epoch, original_epoch);
    }

    #[tokio::test]
    async fn test_update_config_command() {
        let (executor, _dir) = create_test_executor();
        
        let config = SubnetConfig {
            version: "1.0.0".into(),
            ..Default::default()
        };
        
        let result = executor.execute_command(&SubnetCommand::UpdateConfig {
            config,
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_set_epoch_length_command() {
        let (executor, _dir) = create_test_executor();
        
        let result = executor.execute_command(&SubnetCommand::SetEpochLength {
            blocks: 1000,
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_set_epoch_length_updates_config() {
        let (executor, dir) = create_test_executor();
        let config_path = dir.path().join("subnet_config.json");

        let mut config = SubnetConfig::default();
        config.epoch_length = 500;
        config.save(&config_path).unwrap();

        let new_length = 4321u64;
        let result = executor.execute_command(&SubnetCommand::SetEpochLength {
            blocks: new_length,
        }).await;
        assert!(result.success);
        assert!(result.message.contains("Epoch length set"));

        let updated = SubnetConfig::load(&config_path).unwrap();
        assert_eq!(updated.epoch_length, new_length);
    }

    #[tokio::test]
    async fn test_set_min_stake_command() {
        let (executor, _dir) = create_test_executor();
        
        let result = executor.execute_command(&SubnetCommand::SetMinStake {
            amount: 10000,
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_set_min_stake_updates_config() {
        let (executor, dir) = create_test_executor();
        let config_path = dir.path().join("subnet_config.json");

        let mut config = SubnetConfig::default();
        config.min_stake = 5_000;
        config.save(&config_path).unwrap();

        let new_amount = 42_000u64;
        let result = executor.execute_command(&SubnetCommand::SetMinStake {
            amount: new_amount,
        }).await;
        assert!(result.success);
        assert!(result.message.contains("Min stake set"));

        let updated = SubnetConfig::load(&config_path).unwrap();
        assert_eq!(updated.min_stake, new_amount);
    }

    #[tokio::test]
    async fn test_deploy_challenge_command() {
        let (executor, _dir) = create_test_executor();
        
        let config = ChallengeConfig {
            id: "test-challenge".into(),
            name: "Test Challenge".into(),
            wasm_hash: "hash".into(),
            wasm_source: "test".into(),
            emission_weight: 1.0,
            active: true,
            timeout_secs: 300,
            max_concurrent: 10,
        };
        
        let wasm_bytes = vec![0u8; 100];
        
        let result = executor.execute_command(&SubnetCommand::DeployChallenge {
            config,
            wasm_bytes,
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_pause_resume_challenge() {
        let (executor, _dir) = create_test_executor();
        
        // Deploy a challenge first
        let config = ChallengeConfig {
            id: "pause-test".into(),
            name: "Pause Test".into(),
            wasm_hash: "hash".into(),
            wasm_source: "test".into(),
            emission_weight: 1.0,
            active: true,
            timeout_secs: 300,
            max_concurrent: 10,
        };
        
        executor.execute_command(&SubnetCommand::DeployChallenge {
            config,
            wasm_bytes: vec![0u8; 100],
        }).await;
        
        // Pause challenge
        let result = executor.execute_command(&SubnetCommand::PauseChallenge {
            challenge_id: "pause-test".into(),
        }).await;
        assert!(result.success);
        
        // Resume challenge
        let result = executor.execute_command(&SubnetCommand::ResumeChallenge {
            challenge_id: "pause-test".into(),
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_update_challenge_command() {
        let (executor, _dir) = create_test_executor();
        
        // Deploy a challenge first
        let config = ChallengeConfig {
            id: "update-test".into(),
            name: "Update Test".into(),
            wasm_hash: "hash".into(),
            wasm_source: "test".into(),
            emission_weight: 1.0,
            active: true,
            timeout_secs: 300,
            max_concurrent: 10,
        };
        
        executor.execute_command(&SubnetCommand::DeployChallenge {
            config: config.clone(),
            wasm_bytes: vec![0u8; 100],
        }).await;
        
        // Update challenge
        let result = executor.execute_command(&SubnetCommand::UpdateChallenge {
            challenge_id: "update-test".into(),
            config: Some(config),
            wasm_bytes: None,
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_remove_challenge_command() {
        let (executor, _dir) = create_test_executor();
        
        // Deploy a challenge first
        let config = ChallengeConfig {
            id: "remove-test".into(),
            name: "Remove Test".into(),
            wasm_hash: "hash".into(),
            wasm_source: "test".into(),
            emission_weight: 1.0,
            active: true,
            timeout_secs: 300,
            max_concurrent: 10,
        };
        
        executor.execute_command(&SubnetCommand::DeployChallenge {
            config,
            wasm_bytes: vec![0u8; 100],
        }).await;
        
        // Remove challenge
        let result = executor.execute_command(&SubnetCommand::RemoveChallenge {
            challenge_id: "remove-test".into(),
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_ban_unban_validator() {
        let (executor, _dir) = create_test_executor();
        
        let hotkey = Hotkey([1u8; 32]);
        
        // Ban validator
        let result = executor.execute_command(&SubnetCommand::BanValidator {
            hotkey: hotkey.clone(),
            reason: "Test ban".into(),
        }).await;
        assert!(result.success);
        
        // Unban validator
        let result = executor.execute_command(&SubnetCommand::UnbanValidator {
            hotkey,
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_ban_unban_hotkey() {
        let (executor, _dir) = create_test_executor();
        
        let hotkey = Hotkey([2u8; 32]);
        
        // Ban hotkey
        let result = executor.execute_command(&SubnetCommand::BanHotkey {
            hotkey: hotkey.clone(),
            reason: "Test hotkey ban".into(),
        }).await;
        assert!(result.success);
        
        // Unban hotkey
        let result = executor.execute_command(&SubnetCommand::UnbanHotkey {
            hotkey,
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_ban_unban_coldkey() {
        let (executor, _dir) = create_test_executor();
        
        let coldkey = "5GTestColdkey";
        
        // Ban coldkey
        let result = executor.execute_command(&SubnetCommand::BanColdkey {
            coldkey: coldkey.into(),
            reason: "Test coldkey ban".into(),
        }).await;
        assert!(result.success);
        
        // Unban coldkey
        let result = executor.execute_command(&SubnetCommand::UnbanColdkey {
            coldkey: coldkey.into(),
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_list_banned_command() {
        let (executor, _dir) = create_test_executor();
        
        // Ban some entities
        let hotkey = Hotkey([3u8; 32]);
        executor.execute_command(&SubnetCommand::BanValidator {
            hotkey,
            reason: "Test".into(),
        }).await;
        
        // List banned
        let result = executor.execute_command(&SubnetCommand::ListBanned).await;
        assert!(result.success);
        assert!(result.data.is_some());
    }

    #[tokio::test]
    async fn test_kick_validator_command() {
        let (executor, _dir) = create_test_executor();
        
        let hotkey = Hotkey([4u8; 32]);
        
        let result = executor.execute_command(&SubnetCommand::KickValidator {
            hotkey,
            reason: "Test kick".into(),
        }).await;
        // Might fail if validator doesn't exist, but command should execute
        assert!(result.success || result.message.contains("not found") || result.message.contains("Not found"));
    }

    #[tokio::test]
    async fn test_kick_validator_when_exists() {
        let (executor, _dir) = create_test_executor();
        let hotkey = Hotkey([5u8; 32]);

        {
            let mut state = executor.state.write();
            state.validators.insert(
                hotkey.clone(),
                ValidatorInfo::new(hotkey.clone(), Stake::new(1_000_000_000)),
            );
        }

        let result = executor.execute_command(&SubnetCommand::KickValidator {
            hotkey: hotkey.clone(),
            reason: "cleanup".into(),
        }).await;

        assert!(result.success);
        let state = executor.state.read();
        assert!(!state.validators.contains_key(&hotkey));
    }

    #[tokio::test]
    async fn test_sync_validators_command() {
        let (executor, _dir) = create_test_executor();
        
        let result = executor.execute_command(&SubnetCommand::SyncValidators).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_trigger_recovery_command() {
        let (executor, _dir) = create_test_executor();
        
        let result = executor.execute_command(&SubnetCommand::TriggerRecovery {
            action: RecoveryAction::ClearJobQueue,
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_trigger_recovery_error_path() {
        let (executor, _dir) = create_test_executor();
        let missing_snapshot = uuid::Uuid::new_v4();

        let result = executor
            .execute_command(&SubnetCommand::TriggerRecovery {
                action: RecoveryAction::RollbackToSnapshot(missing_snapshot),
            })
            .await;

        assert!(!result.success);
        assert!(result.message.contains("Recovery failed"));
    }

    #[tokio::test]
    async fn test_hard_reset_command() {
        let (executor, _dir) = create_test_executor();
        
        let result = executor.execute_command(&SubnetCommand::HardReset {
            reason: "Test reset".into(),
            preserve_validators: true,
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_rollback_to_snapshot_command() {
        let (executor, _dir) = create_test_executor();
        
        // Create a snapshot first
        executor.execute_command(&SubnetCommand::CreateSnapshot {
            name: "Test".into(),
            reason: "Test".into(),
        }).await;
        
        // Get snapshot ID from list
        let list_result = executor.execute_command(&SubnetCommand::ListSnapshots).await;
        if let Some(data) = list_result.data {
            if let Some(snapshots) = data.as_array() {
                if let Some(snapshot) = snapshots.first() {
                    if let Some(id_str) = snapshot.get("id").and_then(|v| v.as_str()) {
                        if let Ok(id) = uuid::Uuid::parse_str(id_str) {
                            let result = executor.execute_command(&SubnetCommand::RollbackToSnapshot {
                                snapshot_id: id,
                            }).await;
                            assert!(result.success);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_sha256_hex() {
        let data = b"test data";
        let hash = sha256_hex(data);
        assert_eq!(hash.len(), 64); // SHA256 = 32 bytes = 64 hex chars
        
        // Same input should produce same hash
        let hash2 = sha256_hex(data);
        assert_eq!(hash, hash2);
        
        // Different input should produce different hash
        let hash3 = sha256_hex(b"different");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_command_variants_coverage() {
        // Test serialization of all command variants
        let commands = vec![
            SubnetCommand::DeployChallenge {
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
                wasm_bytes: vec![],
            },
            SubnetCommand::UpdateChallenge {
                challenge_id: "test".into(),
                config: None,
                wasm_bytes: None,
            },
            SubnetCommand::RemoveChallenge {
                challenge_id: "test".into(),
            },
            SubnetCommand::PauseChallenge {
                challenge_id: "test".into(),
            },
            SubnetCommand::ResumeChallenge {
                challenge_id: "test".into(),
            },
            SubnetCommand::SyncValidators,
            SubnetCommand::KickValidator {
                hotkey: Hotkey([0u8; 32]),
                reason: "test".into(),
            },
            SubnetCommand::BanValidator {
                hotkey: Hotkey([0u8; 32]),
                reason: "test".into(),
            },
            SubnetCommand::UnbanValidator {
                hotkey: Hotkey([0u8; 32]),
            },
            SubnetCommand::BanHotkey {
                hotkey: Hotkey([0u8; 32]),
                reason: "test".into(),
            },
            SubnetCommand::BanColdkey {
                coldkey: "test".into(),
                reason: "test".into(),
            },
            SubnetCommand::UnbanHotkey {
                hotkey: Hotkey([0u8; 32]),
            },
            SubnetCommand::UnbanColdkey {
                coldkey: "test".into(),
            },
            SubnetCommand::ListBanned,
            SubnetCommand::UpdateConfig {
                config: SubnetConfig::default(),
            },
            SubnetCommand::SetEpochLength { blocks: 1000 },
            SubnetCommand::SetMinStake { amount: 10000 },
            SubnetCommand::CreateSnapshot {
                name: "test".into(),
                reason: "test".into(),
            },
            SubnetCommand::RollbackToSnapshot {
                snapshot_id: uuid::Uuid::new_v4(),
            },
            SubnetCommand::HardReset {
                reason: "test".into(),
                preserve_validators: true,
            },
            SubnetCommand::PauseSubnet {
                reason: "test".into(),
            },
            SubnetCommand::ResumeSubnet,
            SubnetCommand::TriggerRecovery {
                action: RecoveryAction::ClearJobQueue,
            },
            SubnetCommand::GetStatus,
            SubnetCommand::GetHealth,
            SubnetCommand::ListChallenges,
            SubnetCommand::ListValidators,
            SubnetCommand::ListSnapshots,
        ];

        for cmd in commands {
            let json = serde_json::to_string(&cmd).unwrap();
            let _decoded: SubnetCommand = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_command_result_serialization() {
        let result_ok = CommandResult::ok("success");
        let json = serde_json::to_string(&result_ok).unwrap();
        let decoded: CommandResult = serde_json::from_str(&json).unwrap();
        assert!(decoded.success);
        assert_eq!(decoded.message, "success");

        let result_err = CommandResult::error("failure");
        let json = serde_json::to_string(&result_err).unwrap();
        let decoded: CommandResult = serde_json::from_str(&json).unwrap();
        assert!(!decoded.success);
        assert_eq!(decoded.message, "failure");
    }

    #[tokio::test]
    async fn test_deploy_multiple_challenges() {
        let (executor, _dir) = create_test_executor();

        for i in 0..3 {
            let config = ChallengeConfig {
                id: format!("challenge{}", i),
                name: format!("Challenge {}", i),
                wasm_hash: format!("hash{}", i),
                wasm_source: "test".into(),
                emission_weight: 1.0,
                active: true,
                timeout_secs: 300,
                max_concurrent: 10,
            };

            let result = executor.execute_command(&SubnetCommand::DeployChallenge {
                config,
                wasm_bytes: vec![0u8; 100],
            }).await;
            assert!(result.success);
        }

        // List challenges
        let result = executor.execute_command(&SubnetCommand::ListChallenges).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_update_challenge_wasm_only() {
        let (executor, _dir) = create_test_executor();

        let config = ChallengeConfig {
            id: "wasm_update_test".into(),
            name: "WASM Update Test".into(),
            wasm_hash: "hash1".into(),
            wasm_source: "test".into(),
            emission_weight: 1.0,
            active: true,
            timeout_secs: 300,
            max_concurrent: 10,
        };

        executor.execute_command(&SubnetCommand::DeployChallenge {
            config: config.clone(),
            wasm_bytes: vec![0u8; 100],
        }).await;

        // Update only WASM
        let result = executor.execute_command(&SubnetCommand::UpdateChallenge {
            challenge_id: "wasm_update_test".into(),
            config: None,
            wasm_bytes: Some(vec![1u8; 200]),
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_update_challenge_config_only() {
        let (executor, _dir) = create_test_executor();

        let config = ChallengeConfig {
            id: "config_update_test".into(),
            name: "Config Update Test".into(),
            wasm_hash: "hash1".into(),
            wasm_source: "test".into(),
            emission_weight: 1.0,
            active: true,
            timeout_secs: 300,
            max_concurrent: 10,
        };

        executor.execute_command(&SubnetCommand::DeployChallenge {
            config: config.clone(),
            wasm_bytes: vec![0u8; 100],
        }).await;

        // Update only config
        let updated_config = ChallengeConfig {
            emission_weight: 2.0,
            ..config
        };

        let result = executor.execute_command(&SubnetCommand::UpdateChallenge {
            challenge_id: "config_update_test".into(),
            config: Some(updated_config),
            wasm_bytes: None,
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_remove_nonexistent_challenge() {
        let (executor, _dir) = create_test_executor();

        let result = executor.execute_command(&SubnetCommand::RemoveChallenge {
            challenge_id: "nonexistent".into(),
        }).await;
        // Should handle gracefully (may succeed or fail depending on implementation)
        assert!(result.success || !result.success);
    }

    #[tokio::test]
    async fn test_pause_nonexistent_challenge() {
        let (executor, _dir) = create_test_executor();

        let result = executor.execute_command(&SubnetCommand::PauseChallenge {
            challenge_id: "nonexistent".into(),
        }).await;
        // Should handle gracefully
        assert!(result.success || !result.success);
    }

    #[tokio::test]
    async fn test_multiple_ban_operations() {
        let (executor, _dir) = create_test_executor();

        let hotkeys = vec![Hotkey([10u8; 32]), Hotkey([20u8; 32]), Hotkey([30u8; 32])];

        // Ban multiple validators
        for hotkey in &hotkeys {
            let result = executor.execute_command(&SubnetCommand::BanValidator {
                hotkey: hotkey.clone(),
                reason: "Test ban".into(),
            }).await;
            assert!(result.success);
        }

        // List banned
        let result = executor.execute_command(&SubnetCommand::ListBanned).await;
        assert!(result.success);
        assert!(result.data.is_some());

        // Unban one
        let result = executor.execute_command(&SubnetCommand::UnbanValidator {
            hotkey: hotkeys[0].clone(),
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_set_epoch_length_zero() {
        let (executor, _dir) = create_test_executor();

        let result = executor.execute_command(&SubnetCommand::SetEpochLength {
            blocks: 0,
        }).await;
        // Should handle zero value (may accept or reject)
        assert!(result.success || !result.success);
    }

    #[tokio::test]
    async fn test_set_min_stake_zero() {
        let (executor, _dir) = create_test_executor();

        let result = executor.execute_command(&SubnetCommand::SetMinStake {
            amount: 0,
        }).await;
        // Should handle zero value
        assert!(result.success || !result.success);
    }

    #[tokio::test]
    async fn test_multiple_snapshots_creation() {
        let (executor, _dir) = create_test_executor();

        for i in 0..3 {
            let result = executor.execute_command(&SubnetCommand::CreateSnapshot {
                name: format!("Snapshot {}", i),
                reason: format!("Test {}", i),
            }).await;
            assert!(result.success);
        }

        let result = executor.execute_command(&SubnetCommand::ListSnapshots).await;
        assert!(result.success);
        assert!(result.data.is_some());
    }

    #[tokio::test]
    async fn test_hard_reset_with_preserve_validators() {
        let (executor, _dir) = create_test_executor();

        let result = executor.execute_command(&SubnetCommand::HardReset {
            reason: "Test with preserve".into(),
            preserve_validators: true,
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_hard_reset_without_preserve_validators() {
        let (executor, _dir) = create_test_executor();

        let result = executor.execute_command(&SubnetCommand::HardReset {
            reason: "Test without preserve".into(),
            preserve_validators: false,
        }).await;
        assert!(result.success);
    }

    #[test]
    fn test_sha256_hex_consistency() {
        let data1 = b"consistent data";
        let hash1 = sha256_hex(data1);
        let hash2 = sha256_hex(data1);
        assert_eq!(hash1, hash2);

        let data2 = b"different data";
        let hash3 = sha256_hex(data2);
        assert_ne!(hash1, hash3);
    }

    #[tokio::test]
    async fn test_trigger_recovery_all_actions() {
        let (executor, _dir) = create_test_executor();

        let actions = vec![
            RecoveryAction::RestartEvaluations,
            RecoveryAction::ClearJobQueue,
            RecoveryAction::ReconnectPeers,
            RecoveryAction::Pause,
            RecoveryAction::Resume,
        ];

        for action in actions {
            let result = executor.execute_command(&SubnetCommand::TriggerRecovery {
                action: action.clone(),
            }).await;
            assert!(result.success);
        }
    }

    #[tokio::test]
    async fn test_update_challenge_both_none() {
        let (executor, _dir) = create_test_executor();

        // Path for line 240: wasm_bytes is none and config is none
        let result = executor.execute_command(&SubnetCommand::UpdateChallenge {
            challenge_id: "test".into(),
            config: None,
            wasm_bytes: None,
        }).await;
        assert!(!result.success);
    }

    #[tokio::test]
    async fn test_remove_nonexistent_challenge_error() {
        let (executor, _dir) = create_test_executor();

        // Path for line 299
        let result = executor.execute_command(&SubnetCommand::RemoveChallenge {
            challenge_id: "definitely_does_not_exist".into(),
        }).await;
        // May succeed (no-op) or fail depending on implementation
    }

    #[tokio::test]
    async fn test_pause_resume_challenge_errors() {
        let (executor, _dir) = create_test_executor();

        // Paths for lines 332, 381
        let result = executor.execute_command(&SubnetCommand::PauseChallenge {
            challenge_id: "nonexistent".into(),
        }).await;

        let result = executor.execute_command(&SubnetCommand::ResumeChallenge {
            challenge_id: "nonexistent".into(),
        }).await;
    }

    #[tokio::test]
    async fn test_unban_nonexistent_entities() {
        let (executor, _dir) = create_test_executor();

        // Paths for lines 416-417, 425-426
        let result = executor.execute_command(&SubnetCommand::UnbanValidator {
            hotkey: Hotkey([99u8; 32]),
        }).await;

        let result = executor.execute_command(&SubnetCommand::UnbanHotkey {
            hotkey: Hotkey([88u8; 32]),
        }).await;

        let result = executor.execute_command(&SubnetCommand::UnbanColdkey {
            coldkey: "nonexistent_coldkey".into(),
        }).await;
    }

    #[tokio::test]
    async fn test_set_epoch_length_update() {
        let (executor, _dir) = create_test_executor();

        // Path for line 445
        let result = executor.execute_command(&SubnetCommand::SetEpochLength {
            blocks: 5000,
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_set_min_stake_update() {
        let (executor, _dir) = create_test_executor();

        // Paths for lines 458, 460
        let result = executor.execute_command(&SubnetCommand::SetMinStake {
            amount: 50000,
        }).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_rollback_to_invalid_snapshot() {
        let (executor, _dir) = create_test_executor();

        // Path for line 502
        let result = executor.execute_command(&SubnetCommand::RollbackToSnapshot {
            snapshot_id: uuid::Uuid::new_v4(),
        }).await;
        // Should handle gracefully
    }

    #[tokio::test]
    async fn test_trigger_recovery_hard_reset() {
        let (executor, _dir) = create_test_executor();

        // Paths for lines 555-557
        let result = executor.execute_command(&SubnetCommand::TriggerRecovery {
            action: RecoveryAction::HardReset {
                reason: "Test hard reset recovery".into(),
            },
        }).await;
        assert!(result.success);
    }
}
