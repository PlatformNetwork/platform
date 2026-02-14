//! Challenge lifecycle management
//!
//! Handles state transitions for challenges:
//! Registered -> Starting -> Running -> Stopping -> Stopped

use crate::version::ChallengeVersion;
use platform_core::ChallengeId;
use serde::{Deserialize, Serialize};

/// State of a challenge in its lifecycle
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LifecycleState {
    /// Challenge is registered but not started
    #[default]
    Registered,
    /// Challenge is starting up
    Starting,
    /// Challenge is running and accepting evaluations
    Running,
    /// Challenge is being stopped gracefully
    Stopping,
    /// Challenge is stopped
    Stopped,
    /// Challenge failed to start or crashed
    Failed(String),
    /// Challenge is being migrated to a new version
    Migrating,
}

/// Events emitted during lifecycle transitions
#[derive(Clone, Debug)]
pub enum LifecycleEvent {
    /// Challenge was registered
    Registered { challenge_id: ChallengeId },
    /// Challenge was unregistered
    Unregistered { challenge_id: ChallengeId },
    /// Challenge state changed
    StateChanged {
        challenge_id: ChallengeId,
        old_state: LifecycleState,
        new_state: LifecycleState,
    },
    /// Challenge version changed (hot-reload)
    VersionChanged {
        challenge_id: ChallengeId,
        old_version: ChallengeVersion,
        new_version: ChallengeVersion,
    },
}

/// Manages challenge lifecycle transitions
pub struct ChallengeLifecycle {
    /// Whether to allow automatic restarts on failure
    auto_restart: bool,
    /// Maximum restart attempts
    max_restart_attempts: u32,
}

impl ChallengeLifecycle {
    /// Create a new lifecycle manager
    pub fn new() -> Self {
        Self {
            auto_restart: true,
            max_restart_attempts: 3,
        }
    }

    /// Configure auto-restart behavior
    pub fn with_auto_restart(mut self, enabled: bool, max_attempts: u32) -> Self {
        self.auto_restart = enabled;
        self.max_restart_attempts = max_attempts;
        self
    }

    /// Check if a state transition is valid
    pub fn is_valid_transition(&self, from: &LifecycleState, to: &LifecycleState) -> bool {
        match (from, to) {
            // From Registered
            (LifecycleState::Registered, LifecycleState::Starting) => true,
            (LifecycleState::Registered, LifecycleState::Stopped) => true,

            // From Starting
            (LifecycleState::Starting, LifecycleState::Running) => true,
            (LifecycleState::Starting, LifecycleState::Failed(_)) => true,

            // From Running
            (LifecycleState::Running, LifecycleState::Stopping) => true,
            (LifecycleState::Running, LifecycleState::Failed(_)) => true,
            (LifecycleState::Running, LifecycleState::Migrating) => true,

            // From Stopping
            (LifecycleState::Stopping, LifecycleState::Stopped) => true,

            // From Stopped
            (LifecycleState::Stopped, LifecycleState::Starting) => true,
            (LifecycleState::Stopped, LifecycleState::Registered) => true,

            // From Failed
            (LifecycleState::Failed(_), LifecycleState::Starting) => true,
            (LifecycleState::Failed(_), LifecycleState::Stopped) => true,

            // From Migrating
            (LifecycleState::Migrating, LifecycleState::Running) => true,
            (LifecycleState::Migrating, LifecycleState::Failed(_)) => true,

            _ => false,
        }
    }

    /// Check if auto-restart is enabled
    pub fn auto_restart_enabled(&self) -> bool {
        self.auto_restart
    }

    /// Get max restart attempts
    pub fn max_restart_attempts(&self) -> u32 {
        self.max_restart_attempts
    }
}

impl Default for ChallengeLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        let lifecycle = ChallengeLifecycle::new();

        assert!(
            lifecycle.is_valid_transition(&LifecycleState::Registered, &LifecycleState::Starting)
        );
        assert!(lifecycle.is_valid_transition(&LifecycleState::Starting, &LifecycleState::Running));
        assert!(lifecycle.is_valid_transition(&LifecycleState::Running, &LifecycleState::Stopping));
        assert!(lifecycle.is_valid_transition(&LifecycleState::Stopping, &LifecycleState::Stopped));
    }

    #[test]
    fn test_invalid_transitions() {
        let lifecycle = ChallengeLifecycle::new();

        assert!(
            !lifecycle.is_valid_transition(&LifecycleState::Registered, &LifecycleState::Running)
        );
        assert!(!lifecycle.is_valid_transition(&LifecycleState::Stopped, &LifecycleState::Running));
    }

    #[test]
    fn test_lifecycle_config() {
        let lifecycle = ChallengeLifecycle::new().with_auto_restart(false, 5);

        assert!(!lifecycle.auto_restart_enabled());
        assert_eq!(lifecycle.max_restart_attempts(), 5);
    }

    #[test]
    fn test_lifecycle_state_default() {
        let state = LifecycleState::default();
        assert_eq!(state, LifecycleState::Registered);
    }

    #[test]
    fn test_lifecycle_default() {
        let default_lifecycle = ChallengeLifecycle::default();
        let new_lifecycle = ChallengeLifecycle::new();

        assert_eq!(
            default_lifecycle.auto_restart_enabled(),
            new_lifecycle.auto_restart_enabled()
        );
        assert_eq!(
            default_lifecycle.max_restart_attempts(),
            new_lifecycle.max_restart_attempts()
        );
    }

    #[test]
    fn test_all_valid_transition_paths() {
        let lifecycle = ChallengeLifecycle::new();

        // From Registered
        assert!(
            lifecycle.is_valid_transition(&LifecycleState::Registered, &LifecycleState::Starting)
        );
        assert!(
            lifecycle.is_valid_transition(&LifecycleState::Registered, &LifecycleState::Stopped)
        );

        // From Starting
        assert!(lifecycle.is_valid_transition(&LifecycleState::Starting, &LifecycleState::Running));
        assert!(lifecycle.is_valid_transition(
            &LifecycleState::Starting,
            &LifecycleState::Failed("error".to_string())
        ));

        // From Running
        assert!(lifecycle.is_valid_transition(&LifecycleState::Running, &LifecycleState::Stopping));
        assert!(lifecycle.is_valid_transition(
            &LifecycleState::Running,
            &LifecycleState::Failed("crash".to_string())
        ));
        assert!(lifecycle.is_valid_transition(&LifecycleState::Running, &LifecycleState::Migrating));

        // From Stopping
        assert!(lifecycle.is_valid_transition(&LifecycleState::Stopping, &LifecycleState::Stopped));

        // From Stopped
        assert!(lifecycle.is_valid_transition(&LifecycleState::Stopped, &LifecycleState::Starting));
        assert!(
            lifecycle.is_valid_transition(&LifecycleState::Stopped, &LifecycleState::Registered)
        );

        // From Failed
        assert!(lifecycle.is_valid_transition(
            &LifecycleState::Failed("any error".to_string()),
            &LifecycleState::Starting
        ));
        assert!(lifecycle.is_valid_transition(
            &LifecycleState::Failed("any error".to_string()),
            &LifecycleState::Stopped
        ));

        // From Migrating
        assert!(lifecycle.is_valid_transition(&LifecycleState::Migrating, &LifecycleState::Running));
        assert!(lifecycle.is_valid_transition(
            &LifecycleState::Migrating,
            &LifecycleState::Failed("migration failed".to_string())
        ));
    }

    #[test]
    fn test_failed_state_with_message() {
        let error_message = "Connection timeout after 30s".to_string();
        let failed_state = LifecycleState::Failed(error_message.clone());

        match failed_state {
            LifecycleState::Failed(msg) => {
                assert_eq!(msg, error_message);
            }
            _ => panic!("Expected Failed state"),
        }
    }

    #[test]
    fn test_lifecycle_event_variants() {
        let challenge_id = ChallengeId::new();

        // Test Registered event
        let registered_event = LifecycleEvent::Registered { challenge_id };
        match registered_event {
            LifecycleEvent::Registered { challenge_id: id } => {
                assert_eq!(id, challenge_id);
            }
            _ => panic!("Expected Registered event"),
        }

        // Test Unregistered event
        let unregistered_event = LifecycleEvent::Unregistered { challenge_id };
        match unregistered_event {
            LifecycleEvent::Unregistered { challenge_id: id } => {
                assert_eq!(id, challenge_id);
            }
            _ => panic!("Expected Unregistered event"),
        }

        // Test StateChanged event
        let state_changed_event = LifecycleEvent::StateChanged {
            challenge_id,
            old_state: LifecycleState::Registered,
            new_state: LifecycleState::Starting,
        };
        match state_changed_event {
            LifecycleEvent::StateChanged {
                challenge_id: id,
                old_state,
                new_state,
            } => {
                assert_eq!(id, challenge_id);
                assert_eq!(old_state, LifecycleState::Registered);
                assert_eq!(new_state, LifecycleState::Starting);
            }
            _ => panic!("Expected StateChanged event"),
        }

        // Test VersionChanged event
        let old_version = ChallengeVersion::new(1, 0, 0);
        let new_version = ChallengeVersion::new(1, 1, 0);
        let version_changed_event = LifecycleEvent::VersionChanged {
            challenge_id,
            old_version: old_version.clone(),
            new_version: new_version.clone(),
        };
        match version_changed_event {
            LifecycleEvent::VersionChanged {
                challenge_id: id,
                old_version: old_v,
                new_version: new_v,
            } => {
                assert_eq!(id, challenge_id);
                assert_eq!(old_v, old_version);
                assert_eq!(new_v, new_version);
            }
            _ => panic!("Expected VersionChanged event"),
        }
    }

    #[test]
    fn test_auto_restart_default_values() {
        let lifecycle = ChallengeLifecycle::new();

        assert!(lifecycle.auto_restart_enabled());
        assert_eq!(lifecycle.max_restart_attempts(), 3);
    }

    #[test]
    fn test_with_auto_restart_builder() {
        // Test disabling auto-restart
        let lifecycle_disabled = ChallengeLifecycle::new().with_auto_restart(false, 0);
        assert!(!lifecycle_disabled.auto_restart_enabled());
        assert_eq!(lifecycle_disabled.max_restart_attempts(), 0);

        // Test custom max attempts
        let lifecycle_custom = ChallengeLifecycle::new().with_auto_restart(true, 10);
        assert!(lifecycle_custom.auto_restart_enabled());
        assert_eq!(lifecycle_custom.max_restart_attempts(), 10);

        // Test chaining after default
        let lifecycle_chained = ChallengeLifecycle::default().with_auto_restart(false, 1);
        assert!(!lifecycle_chained.auto_restart_enabled());
        assert_eq!(lifecycle_chained.max_restart_attempts(), 1);
    }

    #[test]
    fn test_migrating_transitions() {
        let lifecycle = ChallengeLifecycle::new();

        // Valid: Running -> Migrating
        assert!(lifecycle.is_valid_transition(&LifecycleState::Running, &LifecycleState::Migrating));

        // Valid: Migrating -> Running (successful migration)
        assert!(lifecycle.is_valid_transition(&LifecycleState::Migrating, &LifecycleState::Running));

        // Valid: Migrating -> Failed (migration failed)
        assert!(lifecycle.is_valid_transition(
            &LifecycleState::Migrating,
            &LifecycleState::Failed("migration error".to_string())
        ));

        // Invalid: Migrating -> Stopped (must go through Failed first)
        assert!(
            !lifecycle.is_valid_transition(&LifecycleState::Migrating, &LifecycleState::Stopped)
        );

        // Invalid: Migrating -> Starting
        assert!(
            !lifecycle.is_valid_transition(&LifecycleState::Migrating, &LifecycleState::Starting)
        );

        // Invalid: Registered -> Migrating (can't migrate without running first)
        assert!(
            !lifecycle.is_valid_transition(&LifecycleState::Registered, &LifecycleState::Migrating)
        );
    }
}