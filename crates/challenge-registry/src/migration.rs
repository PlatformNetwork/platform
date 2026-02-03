//! Challenge migration support
//!
//! Handles version migrations for challenges:
//! - Schema migrations
//! - State transformations
//! - Rollback support

use crate::error::{RegistryError, RegistryResult};
use crate::version::ChallengeVersion;
use platform_core::ChallengeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Status of a migration
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationStatus {
    /// Migration is pending
    Pending,
    /// Migration is in progress
    InProgress,
    /// Migration completed successfully
    Completed,
    /// Migration failed
    Failed(String),
    /// Migration was rolled back
    RolledBack,
}

/// A single migration step
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationStep {
    /// Step identifier
    pub id: String,
    /// Description of what this step does
    pub description: String,
    /// From version
    pub from_version: ChallengeVersion,
    /// To version
    pub to_version: ChallengeVersion,
    /// Whether this step is reversible
    pub reversible: bool,
    /// Estimated duration in seconds
    pub estimated_duration_secs: u64,
}

impl MigrationStep {
    /// Create a new migration step
    pub fn new(
        id: String,
        description: String,
        from: ChallengeVersion,
        to: ChallengeVersion,
    ) -> Self {
        Self {
            id,
            description,
            from_version: from,
            to_version: to,
            reversible: true,
            estimated_duration_secs: 60,
        }
    }

    /// Mark step as irreversible
    pub fn irreversible(mut self) -> Self {
        self.reversible = false;
        self
    }

    /// Set estimated duration
    pub fn with_duration(mut self, secs: u64) -> Self {
        self.estimated_duration_secs = secs;
        self
    }
}

/// A plan for migrating a challenge between versions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationPlan {
    /// Challenge being migrated
    pub challenge_id: ChallengeId,
    /// Challenge name
    pub challenge_name: String,
    /// Source version
    pub from_version: ChallengeVersion,
    /// Target version
    pub to_version: ChallengeVersion,
    /// Ordered list of migration steps
    pub steps: Vec<MigrationStep>,
    /// Current status
    pub status: MigrationStatus,
    /// Index of current step (0-based)
    pub current_step: usize,
    /// Plan creation timestamp
    pub created_at: i64,
    /// Plan start timestamp (if started)
    pub started_at: Option<i64>,
    /// Plan completion timestamp (if completed)
    pub completed_at: Option<i64>,
}

impl MigrationPlan {
    /// Create a new migration plan
    pub fn new(
        challenge_id: ChallengeId,
        challenge_name: String,
        from_version: ChallengeVersion,
        to_version: ChallengeVersion,
    ) -> Self {
        Self {
            challenge_id,
            challenge_name,
            from_version,
            to_version,
            steps: Vec::new(),
            status: MigrationStatus::Pending,
            current_step: 0,
            created_at: chrono::Utc::now().timestamp_millis(),
            started_at: None,
            completed_at: None,
        }
    }

    /// Add a migration step
    pub fn add_step(&mut self, step: MigrationStep) {
        self.steps.push(step);
    }

    /// Check if the plan has any steps
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Get total number of steps
    pub fn total_steps(&self) -> usize {
        self.steps.len()
    }

    /// Get estimated total duration
    pub fn estimated_duration_secs(&self) -> u64 {
        self.steps.iter().map(|s| s.estimated_duration_secs).sum()
    }

    /// Check if migration is complete
    pub fn is_complete(&self) -> bool {
        matches!(
            self.status,
            MigrationStatus::Completed | MigrationStatus::RolledBack
        )
    }

    /// Check if migration can be rolled back
    pub fn can_rollback(&self) -> bool {
        // Can rollback if all executed steps are reversible
        self.steps
            .iter()
            .take(self.current_step)
            .all(|s| s.reversible)
    }

    /// Get progress as percentage
    pub fn progress_percent(&self) -> f64 {
        if self.steps.is_empty() {
            return 100.0;
        }
        (self.current_step as f64 / self.steps.len() as f64) * 100.0
    }
}

/// Record of a completed migration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationRecord {
    /// Migration plan
    pub plan: MigrationPlan,
    /// Execution logs
    pub logs: Vec<MigrationLog>,
}

/// Log entry for migration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationLog {
    /// Timestamp
    pub timestamp: i64,
    /// Log level
    pub level: LogLevel,
    /// Message
    pub message: String,
    /// Associated step ID (if any)
    pub step_id: Option<String>,
}

/// Log level for migration logs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
}

/// Manages challenge migrations
pub struct ChallengeMigration {
    /// Active migration plans
    active_plans: parking_lot::RwLock<HashMap<ChallengeId, MigrationPlan>>,
    /// Migration history
    history: parking_lot::RwLock<Vec<MigrationRecord>>,
    /// Maximum history to retain
    max_history: usize,
}

impl ChallengeMigration {
    /// Create a new migration manager
    pub fn new() -> Self {
        Self {
            active_plans: parking_lot::RwLock::new(HashMap::new()),
            history: parking_lot::RwLock::new(Vec::new()),
            max_history: 100,
        }
    }

    /// Create a migration plan between versions
    pub fn create_plan(
        &self,
        challenge_id: ChallengeId,
        challenge_name: String,
        from_version: ChallengeVersion,
        to_version: ChallengeVersion,
    ) -> RegistryResult<MigrationPlan> {
        // Check if there's already an active migration
        if self.active_plans.read().contains_key(&challenge_id) {
            return Err(RegistryError::MigrationFailed(
                "Migration already in progress".to_string(),
            ));
        }

        let mut plan = MigrationPlan::new(
            challenge_id,
            challenge_name,
            from_version.clone(),
            to_version.clone(),
        );

        // Generate migration steps based on version difference
        // This is a simplified version - real implementation would analyze schemas
        if from_version.major != to_version.major {
            plan.add_step(
                MigrationStep::new(
                    "major_upgrade".to_string(),
                    format!(
                        "Major version upgrade from {} to {}",
                        from_version.major, to_version.major
                    ),
                    from_version.clone(),
                    to_version.clone(),
                )
                .irreversible()
                .with_duration(300),
            );
        } else if from_version.minor != to_version.minor {
            plan.add_step(
                MigrationStep::new(
                    "minor_upgrade".to_string(),
                    format!(
                        "Minor version upgrade from {} to {}",
                        from_version, to_version
                    ),
                    from_version.clone(),
                    to_version.clone(),
                )
                .with_duration(60),
            );
        } else if from_version.patch != to_version.patch {
            plan.add_step(
                MigrationStep::new(
                    "patch_upgrade".to_string(),
                    format!(
                        "Patch version upgrade from {} to {}",
                        from_version, to_version
                    ),
                    from_version,
                    to_version,
                )
                .with_duration(10),
            );
        }

        Ok(plan)
    }

    /// Start executing a migration plan
    pub fn start_migration(&self, plan: MigrationPlan) -> RegistryResult<()> {
        let challenge_id = plan.challenge_id;

        let mut plans = self.active_plans.write();
        if plans.contains_key(&challenge_id) {
            return Err(RegistryError::MigrationFailed(
                "Migration already in progress".to_string(),
            ));
        }

        let mut plan = plan;
        plan.status = MigrationStatus::InProgress;
        plan.started_at = Some(chrono::Utc::now().timestamp_millis());

        plans.insert(challenge_id, plan);
        Ok(())
    }

    /// Get active migration for a challenge
    pub fn get_active_migration(&self, challenge_id: &ChallengeId) -> Option<MigrationPlan> {
        self.active_plans.read().get(challenge_id).cloned()
    }

    /// Complete a migration step
    pub fn complete_step(&self, challenge_id: &ChallengeId) -> RegistryResult<bool> {
        let mut plans = self.active_plans.write();
        let plan = plans
            .get_mut(challenge_id)
            .ok_or_else(|| RegistryError::MigrationFailed("No active migration".to_string()))?;

        plan.current_step += 1;

        // Check if all steps complete
        if plan.current_step >= plan.steps.len() {
            plan.status = MigrationStatus::Completed;
            plan.completed_at = Some(chrono::Utc::now().timestamp_millis());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Fail a migration
    pub fn fail_migration(&self, challenge_id: &ChallengeId, reason: String) -> RegistryResult<()> {
        let mut plans = self.active_plans.write();
        let plan = plans
            .get_mut(challenge_id)
            .ok_or_else(|| RegistryError::MigrationFailed("No active migration".to_string()))?;

        plan.status = MigrationStatus::Failed(reason);
        plan.completed_at = Some(chrono::Utc::now().timestamp_millis());

        Ok(())
    }

    /// Finalize and archive a completed migration
    pub fn finalize_migration(&self, challenge_id: &ChallengeId) -> RegistryResult<MigrationPlan> {
        let plan = self
            .active_plans
            .write()
            .remove(challenge_id)
            .ok_or_else(|| RegistryError::MigrationFailed("No active migration".to_string()))?;

        if !plan.is_complete() {
            return Err(RegistryError::MigrationFailed(
                "Migration not complete".to_string(),
            ));
        }

        // Add to history
        let record = MigrationRecord {
            plan: plan.clone(),
            logs: Vec::new(),
        };

        let mut history = self.history.write();
        history.push(record);

        // Trim history
        while history.len() > self.max_history {
            history.remove(0);
        }

        Ok(plan)
    }

    /// Get migration history for a challenge
    pub fn get_history(&self, challenge_id: &ChallengeId) -> Vec<MigrationRecord> {
        self.history
            .read()
            .iter()
            .filter(|r| r.plan.challenge_id == *challenge_id)
            .cloned()
            .collect()
    }

    /// Get all migration history
    pub fn get_all_history(&self) -> Vec<MigrationRecord> {
        self.history.read().clone()
    }
}

impl Default for ChallengeMigration {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_plan_creation() {
        let migration = ChallengeMigration::new();
        let id = ChallengeId::new();

        let plan = migration
            .create_plan(
                id,
                "test".to_string(),
                ChallengeVersion::new(1, 0, 0),
                ChallengeVersion::new(1, 1, 0),
            )
            .unwrap();

        assert_eq!(plan.total_steps(), 1);
        assert!(!plan.is_complete());
        assert_eq!(plan.progress_percent(), 0.0);
    }

    #[test]
    fn test_migration_execution() {
        let migration = ChallengeMigration::new();
        let id = ChallengeId::new();

        let plan = migration
            .create_plan(
                id,
                "test".to_string(),
                ChallengeVersion::new(1, 0, 0),
                ChallengeVersion::new(1, 0, 1),
            )
            .unwrap();

        migration.start_migration(plan).unwrap();

        let active = migration.get_active_migration(&id);
        assert!(active.is_some());
        assert!(matches!(
            active.unwrap().status,
            MigrationStatus::InProgress
        ));

        let complete = migration.complete_step(&id).unwrap();
        assert!(complete);

        let finalized = migration.finalize_migration(&id).unwrap();
        assert!(matches!(finalized.status, MigrationStatus::Completed));
    }

    #[test]
    fn test_duplicate_migration_prevention() {
        let migration = ChallengeMigration::new();
        let id = ChallengeId::new();

        let plan = migration
            .create_plan(
                id,
                "test".to_string(),
                ChallengeVersion::new(1, 0, 0),
                ChallengeVersion::new(1, 1, 0),
            )
            .unwrap();

        migration.start_migration(plan.clone()).unwrap();
        let result = migration.start_migration(plan);
        assert!(result.is_err());
    }

    #[test]
    fn test_major_version_migration() {
        let migration = ChallengeMigration::new();
        let id = ChallengeId::new();

        let plan = migration
            .create_plan(
                id,
                "test".to_string(),
                ChallengeVersion::new(1, 0, 0),
                ChallengeVersion::new(2, 0, 0),
            )
            .unwrap();

        // Major version migrations are irreversible
        assert!(!plan.steps[0].reversible);
    }
}
