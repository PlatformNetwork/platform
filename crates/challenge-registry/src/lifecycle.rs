//! Challenge lifecycle management
//!
//! Handles state transitions for challenges:
//! Registered -> Starting -> Running -> Stopping -> Stopped

use crate::version::ChallengeVersion;
use platform_core::ChallengeId;
use serde::{Deserialize, Serialize};

/// State of a challenge in its lifecycle
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleState {
    /// Challenge is registered but not started
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

impl Default for LifecycleState {
    fn default() -> Self {
        Self::Registered
    }
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
}
