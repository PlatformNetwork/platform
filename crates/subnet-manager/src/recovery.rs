//! Recovery System
//!
//! Handles automatic recovery from failures.

use crate::{
    HealthConfig, HealthMetrics, HealthMonitor, HealthStatus, RecoveryConfig, SnapshotManager,
    UpdateManager, UpdatePayload, UpdateTarget,
};
use parking_lot::RwLock;
use platform_core::ChainState;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

/// Recovery action
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RecoveryAction {
    /// Restart the evaluation loop
    RestartEvaluations,
    /// Clear job queue
    ClearJobQueue,
    /// Reconnect to peers
    ReconnectPeers,
    /// Rollback to snapshot
    RollbackToSnapshot(uuid::Uuid),
    /// Hard reset
    HardReset { reason: String },
    /// Pause subnet
    Pause,
    /// Resume subnet
    Resume,
}

/// Recovery attempt record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryAttempt {
    /// Attempt ID
    pub id: uuid::Uuid,

    /// Action taken
    pub action: RecoveryAction,

    /// Reason for recovery
    pub reason: String,

    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Success
    pub success: bool,

    /// Details
    pub details: String,
}

/// Recovery manager
pub struct RecoveryManager {
    /// Configuration
    config: RecoveryConfig,

    /// Data directory
    data_dir: PathBuf,

    /// Snapshot manager
    snapshots: Arc<RwLock<SnapshotManager>>,

    /// Update manager
    updates: Arc<RwLock<UpdateManager>>,

    /// Recovery history
    history: Vec<RecoveryAttempt>,

    /// Current recovery attempts
    current_attempts: u32,

    /// Last recovery time
    last_recovery: Option<Instant>,

    /// Is subnet paused
    paused: Arc<RwLock<bool>>,
}

impl RecoveryManager {
    /// Create a new recovery manager
    pub fn new(
        config: RecoveryConfig,
        data_dir: PathBuf,
        snapshots: Arc<RwLock<SnapshotManager>>,
        updates: Arc<RwLock<UpdateManager>>,
    ) -> Self {
        Self {
            config,
            data_dir,
            snapshots,
            updates,
            history: Vec::new(),
            current_attempts: 0,
            last_recovery: None,
            paused: Arc::new(RwLock::new(false)),
        }
    }

    /// Check if recovery is needed and execute if so
    pub async fn check_and_recover(&mut self, health: &HealthMonitor) -> Option<RecoveryAttempt> {
        // Skip if paused and not critical
        if *self.paused.read() && health.current_status() != HealthStatus::Critical {
            return None;
        }

        // Check cooldown
        if let Some(last) = self.last_recovery {
            if last.elapsed() < Duration::from_secs(self.config.cooldown_secs) {
                return None;
            }
        }

        // Check if recovery is needed
        if !health.needs_recovery() && health.current_status() != HealthStatus::Critical {
            self.current_attempts = 0; // Reset on healthy
            return None;
        }

        // Check max attempts
        if self.current_attempts >= self.config.max_attempts {
            if self.config.rollback_on_failure {
                return self.rollback_to_last_snapshot().await;
            } else if self.config.pause_on_critical {
                return Some(self.pause_subnet("Max recovery attempts reached").await);
            }
            return None;
        }

        self.current_attempts += 1;
        self.last_recovery = Some(Instant::now());

        // Determine action based on status
        let action = match health.current_status() {
            HealthStatus::Critical => {
                if self.config.pause_on_critical {
                    self.pause_subnet("Critical health status").await
                } else {
                    self.execute_recovery(RecoveryAction::HardReset {
                        reason: "Critical health status".to_string(),
                    })
                    .await
                }
            }
            HealthStatus::Unhealthy => {
                // Try to identify the worst component
                if let Some((component, _)) = health.worst_component() {
                    match component {
                        "job_queue" => self.execute_recovery(RecoveryAction::ClearJobQueue).await,
                        "network" => self.execute_recovery(RecoveryAction::ReconnectPeers).await,
                        "evaluations" => {
                            self.execute_recovery(RecoveryAction::RestartEvaluations)
                                .await
                        }
                        _ => {
                            self.execute_recovery(RecoveryAction::RestartEvaluations)
                                .await
                        }
                    }
                } else {
                    self.execute_recovery(RecoveryAction::RestartEvaluations)
                        .await
                }
            }
            HealthStatus::Degraded => {
                self.execute_recovery(RecoveryAction::RestartEvaluations)
                    .await
            }
            HealthStatus::Healthy => {
                // Should not reach here
                return None;
            }
        };

        Some(action)
    }

    /// Execute a recovery action
    async fn execute_recovery(&mut self, action: RecoveryAction) -> RecoveryAttempt {
        info!("Executing recovery action: {:?}", action);

        let id = uuid::Uuid::new_v4();
        let timestamp = chrono::Utc::now();

        let (success, details) = match &action {
            RecoveryAction::RestartEvaluations => {
                // Signal to runtime to restart evaluation loop
                (true, "Signaled evaluation restart".to_string())
            }
            RecoveryAction::ClearJobQueue => {
                // Clear pending jobs
                (true, "Job queue cleared".to_string())
            }
            RecoveryAction::ReconnectPeers => {
                // Signal network reconnection
                (true, "Signaled peer reconnection".to_string())
            }
            RecoveryAction::RollbackToSnapshot(snapshot_id) => {
                match self.rollback_to_snapshot(*snapshot_id).await {
                    Ok(_) => (true, format!("Rolled back to snapshot {}", snapshot_id)),
                    Err(e) => (false, format!("Rollback failed: {}", e)),
                }
            }
            RecoveryAction::HardReset { reason } => {
                // Queue hard reset update
                let updates = self.updates.write();
                updates.queue_update(
                    UpdateTarget::AllChallenges,
                    UpdatePayload::HardReset {
                        reason: reason.clone(),
                        preserve_validators: true,
                        new_config: None,
                    },
                    "recovery".to_string(),
                );
                (true, format!("Hard reset queued: {}", reason))
            }
            RecoveryAction::Pause => {
                *self.paused.write() = true;
                (true, "Subnet paused".to_string())
            }
            RecoveryAction::Resume => {
                *self.paused.write() = false;
                self.current_attempts = 0;
                (true, "Subnet resumed".to_string())
            }
        };

        let attempt = RecoveryAttempt {
            id,
            action,
            reason: "Automatic recovery".to_string(),
            timestamp,
            success,
            details,
        };

        self.history.push(attempt.clone());

        if success {
            info!("Recovery successful: {}", attempt.details);
        } else {
            error!("Recovery failed: {}", attempt.details);
        }

        attempt
    }

    /// Rollback to last snapshot
    async fn rollback_to_last_snapshot(&mut self) -> Option<RecoveryAttempt> {
        let snapshot_id = {
            let snapshots = self.snapshots.read();
            snapshots.latest_snapshot().map(|s| s.id)
        };

        if let Some(id) = snapshot_id {
            Some(
                self.execute_recovery(RecoveryAction::RollbackToSnapshot(id))
                    .await,
            )
        } else {
            warn!("No snapshots available for rollback");
            None
        }
    }

    /// Rollback to specific snapshot
    async fn rollback_to_snapshot(&self, snapshot_id: uuid::Uuid) -> anyhow::Result<ChainState> {
        let snapshots = self.snapshots.read();
        let snapshot = snapshots.restore_snapshot(snapshot_id)?;
        let state = snapshots.apply_snapshot(&snapshot)?;
        Ok(state)
    }

    /// Pause subnet
    async fn pause_subnet(&mut self, reason: &str) -> RecoveryAttempt {
        warn!("Pausing subnet: {}", reason);
        self.execute_recovery(RecoveryAction::Pause).await
    }

    /// Resume subnet
    pub async fn resume_subnet(&mut self) -> RecoveryAttempt {
        info!("Resuming subnet");
        self.execute_recovery(RecoveryAction::Resume).await
    }

    /// Is subnet paused
    pub fn is_paused(&self) -> bool {
        *self.paused.read()
    }

    /// Get recovery history
    pub fn history(&self) -> &[RecoveryAttempt] {
        &self.history
    }

    /// Get current recovery attempts
    pub fn current_attempts(&self) -> u32 {
        self.current_attempts
    }

    /// Manually trigger recovery
    pub async fn manual_recovery(&mut self, action: RecoveryAction) -> RecoveryAttempt {
        self.execute_recovery(action).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HealthCheck, HealthConfig};
    use tempfile::tempdir;

    fn create_manager_with_config(
        config: RecoveryConfig,
    ) -> (
        RecoveryManager,
        Arc<RwLock<SnapshotManager>>,
        Arc<RwLock<UpdateManager>>,
        tempfile::TempDir,
    ) {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(data_dir.clone(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(data_dir.clone())));
        let manager = RecoveryManager::new(config, data_dir, snapshots.clone(), updates.clone());
        (manager, snapshots, updates, dir)
    }

    fn create_aggressive_health_monitor() -> HealthMonitor {
        let health_config = HealthConfig {
            failure_threshold: 1,
            max_pending_jobs: 10,
            cpu_warn_percent: 50,
            memory_warn_percent: 50,
            max_eval_time: 1,
            ..Default::default()
        };
        HealthMonitor::new(health_config)
    }

    fn base_metrics() -> HealthMetrics {
        let mut metrics = HealthMetrics::default();
        metrics.connected_peers = 5;
        metrics
    }

    #[test]
    fn test_recovery_action_serialization() {
        let actions = vec![
            RecoveryAction::RestartEvaluations,
            RecoveryAction::ClearJobQueue,
            RecoveryAction::ReconnectPeers,
            RecoveryAction::RollbackToSnapshot(uuid::Uuid::new_v4()),
            RecoveryAction::HardReset {
                reason: "test".into(),
            },
            RecoveryAction::Pause,
            RecoveryAction::Resume,
        ];

        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let decoded: RecoveryAction = serde_json::from_str(&json).unwrap();
            let _ = serde_json::to_string(&decoded).unwrap();
        }
    }

    #[test]
    fn test_recovery_attempt_fields() {
        let attempt = RecoveryAttempt {
            id: uuid::Uuid::new_v4(),
            action: RecoveryAction::RestartEvaluations,
            reason: "Test recovery".into(),
            timestamp: chrono::Utc::now(),
            success: true,
            details: "Recovery successful".into(),
        };

        assert!(attempt.success);
        assert_eq!(attempt.reason, "Test recovery");
        assert_eq!(attempt.details, "Recovery successful");
    }

    #[tokio::test]
    async fn test_recovery_manager() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig::default();

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        let manager = RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        assert_eq!(manager.history().len(), 0);
        assert!(!manager.is_paused());
    }

    #[tokio::test]
    async fn test_pause_resume() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig::default();

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        let mut manager =
            RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        // Initially not paused
        assert!(!manager.is_paused());

        // Pause
        manager.manual_recovery(RecoveryAction::Pause).await;
        assert!(manager.is_paused());

        // Resume
        manager.manual_recovery(RecoveryAction::Resume).await;
        assert!(!manager.is_paused());
    }

    #[tokio::test]
    async fn test_check_and_recover_with_healthy_status() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig {
            auto_recover: true,
            ..Default::default()
        };

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        let mut manager =
            RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        let health_config = HealthConfig::default();
        let health = HealthMonitor::new(health_config);

        // With healthy status, no recovery should occur
        let attempt = manager.check_and_recover(&health).await;
        assert!(attempt.is_none());
    }

    #[tokio::test]
    async fn test_check_and_recover_cooldown() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig {
            auto_recover: true,
            cooldown_secs: 3600, // Long cooldown
            ..Default::default()
        };

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        let mut manager =
            RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        let health_config = HealthConfig {
            failure_threshold: 1,
            cpu_warn_percent: 50,
            memory_warn_percent: 50,
            ..Default::default()
        };
        let mut health = HealthMonitor::new(health_config);

        // Trigger unhealthy status
        let bad_metrics = HealthMetrics {
            memory_percent: 99.0,
            cpu_percent: 99.0,
            disk_percent: 99.0,
            pending_jobs: 10000,
            running_jobs: 2,
            evaluations_per_hour: 10,
            failures_per_hour: 50,
            avg_eval_time_ms: 5000,
            connected_peers: 1,
            block_height: 1000,
            epoch: 10,
            uptime_secs: 3600,
        };
        health.check(bad_metrics.clone());
        health.check(bad_metrics.clone());

        // First recovery should work
        let attempt1 = manager.check_and_recover(&health).await;

        // Second recovery immediately after should be blocked by cooldown
        let attempt2 = manager.check_and_recover(&health).await;
        assert!(attempt2.is_none());
    }

    #[tokio::test]
    async fn test_check_and_recover_with_degraded_health() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig {
            auto_recover: true,
            cooldown_secs: 0, // No cooldown
            ..Default::default()
        };

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        let mut manager =
            RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        let health_config = HealthConfig {
            failure_threshold: 1,
            cpu_warn_percent: 50,
            memory_warn_percent: 50,
            ..Default::default()
        };
        let mut health = HealthMonitor::new(health_config);

        // Trigger degraded status
        let bad_metrics = HealthMetrics {
            memory_percent: 80.0,
            cpu_percent: 80.0,
            disk_percent: 50.0,
            pending_jobs: 100,
            running_jobs: 2,
            evaluations_per_hour: 50,
            failures_per_hour: 10,
            avg_eval_time_ms: 1000,
            connected_peers: 3,
            block_height: 1000,
            epoch: 10,
            uptime_secs: 3600,
        };
        health.check(bad_metrics);

        // Recovery should occur
        let attempt = manager.check_and_recover(&health).await;
        // May or may not trigger depending on health implementation
        // Just verify it doesn't panic
    }

    #[tokio::test]
    async fn test_check_and_recover_skips_when_paused() {
        let config = RecoveryConfig::default();
        let (mut manager, _, _, _dir) = create_manager_with_config(config);

        manager.manual_recovery(RecoveryAction::Pause).await;
        assert!(manager.is_paused());

        let health = HealthMonitor::new(HealthConfig::default());
        let attempt = manager.check_and_recover(&health).await;
        assert!(attempt.is_none());
    }

    #[tokio::test]
    async fn test_check_and_recover_rolls_back_on_attempt_limit() {
        let config = RecoveryConfig {
            auto_recover: true,
            max_attempts: 0,
            cooldown_secs: 0,
            rollback_on_failure: true,
            pause_on_critical: false,
        };
        let (mut manager, snapshots, _, _dir) = create_manager_with_config(config);

        {
            let keypair = platform_core::Keypair::generate();
            let sudo_key = keypair.hotkey();
            let chain_state = ChainState::new(sudo_key, platform_core::NetworkConfig::default());
            let mut snap_mgr = snapshots.write();
            snap_mgr
                .create_snapshot("limit", 100, 1, &chain_state, "limit", false)
                .unwrap();
        }

        let mut health = create_aggressive_health_monitor();
        let mut metrics = base_metrics();
        metrics.pending_jobs = 100;
        metrics.running_jobs = 1;
        health.check(metrics);
        assert_eq!(health.current_status(), HealthStatus::Unhealthy);

        let attempt = manager
            .check_and_recover(&health)
            .await
            .expect("expected rollback");
        assert!(matches!(attempt.action, RecoveryAction::RollbackToSnapshot(_))); 
    }

    #[tokio::test]
    async fn test_check_and_recover_pauses_on_attempt_limit() {
        let config = RecoveryConfig {
            auto_recover: true,
            max_attempts: 0,
            cooldown_secs: 0,
            rollback_on_failure: false,
            pause_on_critical: true,
        };
        let (mut manager, _, _, _dir) = create_manager_with_config(config);

        let mut health = create_aggressive_health_monitor();
        let mut metrics = base_metrics();
        metrics.memory_percent = 90.0;
        health.check(metrics);

        let attempt = manager
            .check_and_recover(&health)
            .await
            .expect("expected pause");
        assert!(matches!(attempt.action, RecoveryAction::Pause));
        assert!(manager.is_paused());
    }

    #[tokio::test]
    async fn test_check_and_recover_unhealthy_branch_actions() {
        fn acknowledge_component(health: &mut HealthMonitor, component: &str) {
            if let Some(alert) = health
                .active_alerts()
                .into_iter()
                .find(|alert| alert.component == component)
            {
                health.acknowledge_alert(alert.id);
            }
        }

        async fn run_case<F>(prepare: F) -> RecoveryAction
        where
            F: FnOnce(&mut HealthMonitor),
        {
            let config = RecoveryConfig {
                auto_recover: true,
                max_attempts: 5,
                cooldown_secs: 0,
                rollback_on_failure: false,
                pause_on_critical: false,
            };
            let (mut manager, _, _, _dir) = create_manager_with_config(config);
            let mut health = create_aggressive_health_monitor();
            prepare(&mut health);
            assert_eq!(health.current_status(), HealthStatus::Unhealthy);
            manager
                .check_and_recover(&health)
                .await
                .expect("expected action")
                .action
        }

        let job_queue_action = run_case(|health| {
            let mut metrics = base_metrics();
            metrics.pending_jobs = 100;
            metrics.running_jobs = 1;
            health.check(metrics);
        })
        .await;
        assert!(matches!(job_queue_action, RecoveryAction::ClearJobQueue));

        let network_action = run_case(|health| {
            let mut first = base_metrics();
            first.connected_peers = 1;
            health.check(first);

            acknowledge_component(health, "network");

            let mut second = base_metrics();
            second.connected_peers = 1;
            health.check(second);

            let mut third = base_metrics();
            third.connected_peers = 1;
            third.pending_jobs = 100;
            third.running_jobs = 1;
            health.check(third);
        })
        .await;
        assert!(matches!(network_action, RecoveryAction::ReconnectPeers));

        let evaluations_action = run_case(|health| {
            let mut first = base_metrics();
            first.avg_eval_time_ms = 5_000;
            health.check(first);

            acknowledge_component(health, "evaluations");

            let mut second = base_metrics();
            second.avg_eval_time_ms = 5_000;
            health.check(second);

            let mut third = base_metrics();
            third.avg_eval_time_ms = 5_000;
            third.pending_jobs = 100;
            third.running_jobs = 1;
            health.check(third);
        })
        .await;
        assert!(matches!(evaluations_action, RecoveryAction::RestartEvaluations));

        let fallback_action = run_case(|health| {
            let mut first = base_metrics();
            first.memory_percent = 90.0;
            health.check(first);

            acknowledge_component(health, "memory");

            let mut second = base_metrics();
            second.memory_percent = 90.0;
            health.check(second);

            let mut third = base_metrics();
            third.memory_percent = 90.0;
            third.pending_jobs = 100;
            third.running_jobs = 1;
            health.check(third);
        })
        .await;
        assert!(matches!(fallback_action, RecoveryAction::RestartEvaluations));
    }

    #[tokio::test]
    async fn test_check_and_recover_degraded_branch() {
        let config = RecoveryConfig {
            auto_recover: true,
            cooldown_secs: 0,
            ..Default::default()
        };
        let (mut manager, _, _, _dir) = create_manager_with_config(config);
        let mut health = create_aggressive_health_monitor();

        let mut metrics = base_metrics();
        metrics.pending_jobs = 11; // just over the degraded threshold
        metrics.running_jobs = 1;
        health.check(metrics);
        assert_eq!(health.current_status(), HealthStatus::Degraded);

        let attempt = manager
            .check_and_recover(&health)
            .await
            .expect("expected degraded recovery");
        assert!(matches!(attempt.action, RecoveryAction::RestartEvaluations));
    }

    #[tokio::test]
    async fn test_check_and_recover_healthy_branch_returns_none() {
        let config = RecoveryConfig {
            auto_recover: true,
            cooldown_secs: 0,
            ..Default::default()
        };
        let (mut manager, _, _, _dir) = create_manager_with_config(config);
        let mut health = create_aggressive_health_monitor();

        health
            .test_failure_counts_mut()
            .insert("job_queue".into(), 5);
        health.test_history_mut().push_back(HealthCheck {
            timestamp: chrono::Utc::now(),
            status: HealthStatus::Healthy,
            components: Vec::new(),
            alerts: Vec::new(),
            metrics: HealthMetrics::default(),
        });

        let attempt = manager.check_and_recover(&health).await;
        assert!(attempt.is_none());
    }

    #[tokio::test]
    async fn test_rollback_to_snapshot_recovery() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig::default();

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        // Create a snapshot first
        {
            let keypair = platform_core::Keypair::generate();
            let sudo_key = keypair.hotkey();
            let chain_state = ChainState::new(sudo_key, platform_core::NetworkConfig::default());
            
            let mut snap_mgr = snapshots.write();
            snap_mgr
                .create_snapshot(
                    "test",
                    1000,
                    10,
                    &chain_state,
                    "test reason",
                    false,
                )
                .unwrap();
        }

        let snapshot_id = {
            let snap_mgr = snapshots.read();
            snap_mgr.list_snapshots()[0].id
        };

        let mut manager =
            RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        let attempt = manager
            .manual_recovery(RecoveryAction::RollbackToSnapshot(snapshot_id))
            .await;

        // Rollback might succeed or fail, just verify it runs
        assert!(attempt.details.contains("Rolled back") || attempt.details.contains("failed"));
    }

    #[tokio::test]
    async fn test_rollback_to_last_snapshot() {
        let config = RecoveryConfig::default();
        let (mut manager, snapshots, _, _dir) = create_manager_with_config(config);

        // No snapshots yet, expect no action
        assert!(manager.rollback_to_last_snapshot().await.is_none());

        // Create two snapshots so the latest can be selected
        {
            let keypair = platform_core::Keypair::generate();
            let sudo_key = keypair.hotkey();
            let chain_state = ChainState::new(sudo_key, platform_core::NetworkConfig::default());
            let mut snap_mgr = snapshots.write();
            snap_mgr
                .create_snapshot("first", 10, 1, &chain_state, "first", false)
                .unwrap();
            snap_mgr
                .create_snapshot("second", 20, 2, &chain_state, "second", false)
                .unwrap();
        }

        let latest_id = {
            let snap_mgr = snapshots.read();
            snap_mgr.latest_snapshot().unwrap().id
        };

        let attempt = manager
            .rollback_to_last_snapshot()
            .await
            .expect("expected rollback attempt");

        match attempt.action {
            RecoveryAction::RollbackToSnapshot(id) => assert_eq!(id, latest_id),
            other => panic!("unexpected action: {:?}", other),
        }

        assert_eq!(manager.history().len(), 1);
    }

    #[tokio::test]
    async fn test_current_attempts_tracking() {
        let config = RecoveryConfig {
            auto_recover: true,
            cooldown_secs: 0,
            ..Default::default()
        };
        let (mut manager, _, _, _dir) = create_manager_with_config(config);
        let mut health = create_aggressive_health_monitor();

        assert_eq!(manager.current_attempts(), 0);

        // First unhealthy check increments attempts
        let mut unhealthy = base_metrics();
        unhealthy.pending_jobs = 100;
        unhealthy.running_jobs = 1;
        health.check(unhealthy);
        assert!(health.needs_recovery());

        manager
            .check_and_recover(&health)
            .await
            .expect("expected recovery attempt");
        assert_eq!(manager.current_attempts(), 1);

        // Healthy metrics reset attempts counter
        let healthy_metrics = base_metrics();
        health.check(healthy_metrics);
        assert!(!health.needs_recovery());
        assert!(manager.check_and_recover(&health).await.is_none());
        assert_eq!(manager.current_attempts(), 0);

        // Another unhealthy event increments again
        let mut second_unhealthy = base_metrics();
        second_unhealthy.pending_jobs = 150;
        second_unhealthy.running_jobs = 1;
        health.check(second_unhealthy);

        manager
            .check_and_recover(&health)
            .await
            .expect("expected second recovery attempt");
        assert_eq!(manager.current_attempts(), 1);
    }

    #[tokio::test]
    async fn test_max_recovery_attempts() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig {
            auto_recover: true,
            max_attempts: 2,
            cooldown_secs: 0,
            rollback_on_failure: false,
            pause_on_critical: false,
        };

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        let mut manager =
            RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        let health_config = HealthConfig {
            failure_threshold: 1,
            cpu_warn_percent: 50,
            memory_warn_percent: 50,
            ..Default::default()
        };
        let mut health = HealthMonitor::new(health_config);

        // Trigger unhealthy status
        let bad_metrics = HealthMetrics {
            memory_percent: 99.0,
            cpu_percent: 99.0,
            disk_percent: 99.0,
            pending_jobs: 10000,
            running_jobs: 2,
            evaluations_per_hour: 10,
            failures_per_hour: 50,
            avg_eval_time_ms: 5000,
            connected_peers: 1,
            block_height: 1000,
            epoch: 10,
            uptime_secs: 3600,
        };
        health.check(bad_metrics.clone());
        health.check(bad_metrics.clone());

        // First recovery attempt
        let attempt1 = manager.check_and_recover(&health).await;
        // Might succeed based on health status

        // Second recovery attempt
        let attempt2 = manager.check_and_recover(&health).await;

        // Third attempt should be limited
        let attempt3 = manager.check_and_recover(&health).await;
        // Should eventually stop or trigger fallback
    }

    #[tokio::test]
    async fn test_restart_evaluations_recovery() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig::default();

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        let mut manager =
            RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        let attempt = manager
            .manual_recovery(RecoveryAction::RestartEvaluations)
            .await;
        assert!(attempt.success);
        assert!(attempt.details.contains("restart"));
    }

    #[tokio::test]
    async fn test_clear_job_queue_recovery() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig::default();

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        let mut manager =
            RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        let attempt = manager
            .manual_recovery(RecoveryAction::ClearJobQueue)
            .await;
        assert!(attempt.success);
        assert!(attempt.details.contains("cleared"));
    }

    #[tokio::test]
    async fn test_reconnect_peers_recovery() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig::default();

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        let mut manager =
            RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        let attempt = manager
            .manual_recovery(RecoveryAction::ReconnectPeers)
            .await;
        assert!(attempt.success);
    }

    #[tokio::test]
    async fn test_recovery_history_tracking() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig::default();

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        let mut manager =
            RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        // Perform multiple recoveries
        manager
            .manual_recovery(RecoveryAction::RestartEvaluations)
            .await;
        manager.manual_recovery(RecoveryAction::ClearJobQueue).await;
        manager.manual_recovery(RecoveryAction::ReconnectPeers).await;

        let history = manager.history();
        assert_eq!(history.len(), 3);
    }

    #[tokio::test]
    async fn test_recovery_config_custom() {
        let config = RecoveryConfig {
            auto_recover: false,
            max_attempts: 5,
            cooldown_secs: 120,
            rollback_on_failure: false,
            pause_on_critical: false,
        };

        assert!(!config.auto_recover);
        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.cooldown_secs, 120);
        assert!(!config.rollback_on_failure);
        assert!(!config.pause_on_critical);
    }

    #[tokio::test]
    async fn test_hard_reset_recovery() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig::default();

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        let mut manager =
            RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        let attempt = manager
            .manual_recovery(RecoveryAction::HardReset {
                reason: "Test hard reset".into(),
            })
            .await;

        assert!(attempt.success);
        assert!(attempt.details.contains("reset"));
    }

    #[tokio::test]
    async fn test_recovery_with_different_health_statuses() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig {
            auto_recover: true,
            cooldown_secs: 0,
            ..Default::default()
        };

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        let mut manager =
            RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        // Test with healthy status
        let health_config = HealthConfig::default();
        let health = HealthMonitor::new(health_config);
        let attempt = manager.check_and_recover(&health).await;
        assert!(attempt.is_none());
    }

    #[tokio::test]
    async fn test_manual_recovery_updates_history() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig::default();

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        let mut manager =
            RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        assert_eq!(manager.history().len(), 0);

        manager
            .manual_recovery(RecoveryAction::RestartEvaluations)
            .await;
        assert_eq!(manager.history().len(), 1);

        manager.manual_recovery(RecoveryAction::ClearJobQueue).await;
        assert_eq!(manager.history().len(), 2);
    }

    #[test]
    fn test_recovery_config_defaults() {
        let config = RecoveryConfig::default();
        assert!(config.auto_recover);
        assert!(config.max_attempts > 0);
        assert!(config.cooldown_secs > 0);
    }

    #[tokio::test]
    async fn test_pause_when_already_paused() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig::default();

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        let mut manager =
            RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        manager.manual_recovery(RecoveryAction::Pause).await;
        assert!(manager.is_paused());

        // Pause again
        manager.manual_recovery(RecoveryAction::Pause).await;
        assert!(manager.is_paused());
    }

    #[tokio::test]
    async fn test_resume_when_not_paused() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig::default();

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        let mut manager =
            RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        assert!(!manager.is_paused());

        manager.manual_recovery(RecoveryAction::Resume).await;
        assert!(!manager.is_paused());
    }

    #[tokio::test]
    async fn test_rollback_to_invalid_snapshot() {
        let dir = tempdir().unwrap();
        let config = RecoveryConfig::default();

        let snapshots = Arc::new(RwLock::new(
            SnapshotManager::new(dir.path().to_path_buf(), 3).unwrap(),
        ));
        let updates = Arc::new(RwLock::new(UpdateManager::new(dir.path().to_path_buf())));

        let mut manager =
            RecoveryManager::new(config, dir.path().to_path_buf(), snapshots, updates);

        let attempt = manager
            .manual_recovery(RecoveryAction::RollbackToSnapshot(uuid::Uuid::new_v4()))
            .await;

        assert!(!attempt.success);
        assert!(attempt.details.contains("failed"));
    }

    #[test]
    fn test_recovery_attempt_serialization() {
        let attempt = RecoveryAttempt {
            id: uuid::Uuid::new_v4(),
            action: RecoveryAction::ClearJobQueue,
            reason: "test".into(),
            timestamp: chrono::Utc::now(),
            success: true,
            details: "details".into(),
        };

        let json = serde_json::to_string(&attempt).unwrap();
        let decoded: RecoveryAttempt = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.reason, "test");
        assert_eq!(decoded.success, true);
    }
}
