//! Health monitoring for challenges
//!
//! Monitors challenge health through:
//! - HTTP health endpoints
//! - Container status
//! - Resource usage

use parking_lot::RwLock;
use platform_core::ChallengeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Health status of a challenge
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Health status is unknown (not yet checked)
    Unknown,
    /// Challenge is healthy
    Healthy,
    /// Challenge is degraded but operational
    Degraded(String),
    /// Challenge is unhealthy
    Unhealthy(String),
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Detailed health information for a challenge
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeHealth {
    /// Challenge identifier
    pub challenge_id: ChallengeId,
    /// Current health status
    pub status: HealthStatus,
    /// Last successful health check timestamp (millis)
    pub last_check_at: i64,
    /// Number of consecutive failures
    pub consecutive_failures: u32,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Additional health metrics
    pub metrics: HashMap<String, f64>,
}

impl ChallengeHealth {
    /// Create new health info for a challenge
    pub fn new(challenge_id: ChallengeId) -> Self {
        Self {
            challenge_id,
            status: HealthStatus::Unknown,
            last_check_at: 0,
            consecutive_failures: 0,
            avg_response_time_ms: 0.0,
            metrics: HashMap::new(),
        }
    }

    /// Check if the challenge is considered healthy
    pub fn is_healthy(&self) -> bool {
        matches!(self.status, HealthStatus::Healthy)
    }

    /// Check if the challenge is operational (healthy or degraded)
    pub fn is_operational(&self) -> bool {
        matches!(
            self.status,
            HealthStatus::Healthy | HealthStatus::Degraded(_)
        )
    }

    /// Record a successful health check
    pub fn record_success(&mut self, response_time_ms: f64) {
        self.status = HealthStatus::Healthy;
        self.last_check_at = chrono::Utc::now().timestamp_millis();
        self.consecutive_failures = 0;

        // Exponential moving average for response time
        if self.avg_response_time_ms == 0.0 {
            self.avg_response_time_ms = response_time_ms;
        } else {
            self.avg_response_time_ms = self.avg_response_time_ms * 0.8 + response_time_ms * 0.2;
        }
    }

    /// Record a failed health check
    pub fn record_failure(&mut self, reason: String) {
        self.consecutive_failures += 1;
        self.last_check_at = chrono::Utc::now().timestamp_millis();

        if self.consecutive_failures >= 3 {
            self.status = HealthStatus::Unhealthy(reason);
        } else {
            self.status = HealthStatus::Degraded(reason);
        }
    }
}

/// Configuration for health monitoring
#[derive(Clone, Debug)]
pub struct HealthConfig {
    /// Interval between health checks
    pub check_interval: Duration,
    /// Timeout for health check requests
    pub check_timeout: Duration,
    /// Number of failures before marking unhealthy
    pub failure_threshold: u32,
    /// Number of successes to recover from unhealthy
    pub recovery_threshold: u32,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(30),
            check_timeout: Duration::from_secs(5),
            failure_threshold: 3,
            recovery_threshold: 2,
        }
    }
}

/// Monitors health of registered challenges
pub struct HealthMonitor {
    /// Health state for each challenge
    health_state: RwLock<HashMap<ChallengeId, ChallengeHealth>>,
    /// Configuration
    config: HealthConfig,
}

impl HealthMonitor {
    /// Create a new health monitor with default config
    pub fn new() -> Self {
        Self {
            health_state: RwLock::new(HashMap::new()),
            config: HealthConfig::default(),
        }
    }

    /// Create a health monitor with custom config
    pub fn with_config(config: HealthConfig) -> Self {
        Self {
            health_state: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Register a challenge for health monitoring
    pub fn register(&self, challenge_id: ChallengeId) {
        let mut state = self.health_state.write();
        state.insert(challenge_id, ChallengeHealth::new(challenge_id));
    }

    /// Unregister a challenge from health monitoring
    pub fn unregister(&self, challenge_id: &ChallengeId) {
        let mut state = self.health_state.write();
        state.remove(challenge_id);
    }

    /// Get health status for a challenge
    pub fn get_health(&self, challenge_id: &ChallengeId) -> Option<ChallengeHealth> {
        self.health_state.read().get(challenge_id).cloned()
    }

    /// Get health status for all challenges
    pub fn get_all_health(&self) -> Vec<ChallengeHealth> {
        self.health_state.read().values().cloned().collect()
    }

    /// Update health status after a check
    pub fn update_health(&self, challenge_id: &ChallengeId, status: HealthStatus) {
        let mut state = self.health_state.write();
        if let Some(health) = state.get_mut(challenge_id) {
            health.status = status;
            health.last_check_at = chrono::Utc::now().timestamp_millis();
        }
    }

    /// Record a successful health check
    pub fn record_success(&self, challenge_id: &ChallengeId, response_time_ms: f64) {
        let mut state = self.health_state.write();
        if let Some(health) = state.get_mut(challenge_id) {
            health.record_success(response_time_ms);
        }
    }

    /// Record a failed health check
    pub fn record_failure(&self, challenge_id: &ChallengeId, reason: String) {
        let mut state = self.health_state.write();
        if let Some(health) = state.get_mut(challenge_id) {
            health.record_failure(reason);
        }
    }

    /// Get the health config
    pub fn config(&self) -> &HealthConfig {
        &self.config
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status() {
        let mut health = ChallengeHealth::new(ChallengeId::new());

        assert_eq!(health.status, HealthStatus::Unknown);
        assert!(!health.is_healthy());

        health.record_success(50.0);
        assert!(health.is_healthy());
        assert!(health.is_operational());

        health.record_failure("timeout".to_string());
        assert!(!health.is_healthy());
        assert!(health.is_operational()); // Still degraded

        health.record_failure("timeout".to_string());
        health.record_failure("timeout".to_string());
        assert!(!health.is_operational()); // Now unhealthy
    }

    #[test]
    fn test_health_monitor() {
        let monitor = HealthMonitor::new();
        let id = ChallengeId::new();

        monitor.register(id);
        assert!(monitor.get_health(&id).is_some());

        monitor.record_success(&id, 100.0);
        let health = monitor.get_health(&id).unwrap();
        assert!(health.is_healthy());

        monitor.unregister(&id);
        assert!(monitor.get_health(&id).is_none());
    }

    #[test]
    fn test_response_time_averaging() {
        let mut health = ChallengeHealth::new(ChallengeId::new());

        health.record_success(100.0);
        assert_eq!(health.avg_response_time_ms, 100.0);

        health.record_success(200.0);
        // 100 * 0.8 + 200 * 0.2 = 80 + 40 = 120
        assert!((health.avg_response_time_ms - 120.0).abs() < 0.01);
    }
}
