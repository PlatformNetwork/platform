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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum HealthStatus {
    /// Health status is unknown (not yet checked)
    #[default]
    Unknown,
    /// Challenge is healthy
    Healthy,
    /// Challenge is degraded but operational
    Degraded(String),
    /// Challenge is unhealthy
    Unhealthy(String),
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

    #[test]
    fn test_health_status_default() {
        let status = HealthStatus::default();
        assert_eq!(status, HealthStatus::Unknown);
    }

    #[test]
    fn test_challenge_health_new() {
        let challenge_id = ChallengeId::new();
        let health = ChallengeHealth::new(challenge_id);

        assert_eq!(health.challenge_id, challenge_id);
        assert_eq!(health.status, HealthStatus::Unknown);
        assert_eq!(health.last_check_at, 0);
        assert_eq!(health.consecutive_failures, 0);
        assert_eq!(health.avg_response_time_ms, 0.0);
        assert!(health.metrics.is_empty());
    }

    #[test]
    fn test_challenge_health_metrics() {
        let mut health = ChallengeHealth::new(ChallengeId::new());

        health.metrics.insert("cpu_usage".to_string(), 45.5);
        health.metrics.insert("memory_mb".to_string(), 512.0);
        health
            .metrics
            .insert("requests_per_sec".to_string(), 1000.0);

        assert_eq!(health.metrics.len(), 3);
        assert_eq!(health.metrics.get("cpu_usage"), Some(&45.5));
        assert_eq!(health.metrics.get("memory_mb"), Some(&512.0));
        assert_eq!(health.metrics.get("requests_per_sec"), Some(&1000.0));
        assert_eq!(health.metrics.get("nonexistent"), None);
    }

    #[test]
    fn test_health_config_default() {
        let config = HealthConfig::default();

        assert_eq!(config.check_interval, Duration::from_secs(30));
        assert_eq!(config.check_timeout, Duration::from_secs(5));
        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.recovery_threshold, 2);
    }

    #[test]
    fn test_health_config_custom() {
        let config = HealthConfig {
            check_interval: Duration::from_secs(60),
            check_timeout: Duration::from_secs(10),
            failure_threshold: 5,
            recovery_threshold: 3,
        };

        assert_eq!(config.check_interval, Duration::from_secs(60));
        assert_eq!(config.check_timeout, Duration::from_secs(10));
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.recovery_threshold, 3);
    }

    #[test]
    fn test_health_monitor_with_config() {
        let config = HealthConfig {
            check_interval: Duration::from_secs(120),
            check_timeout: Duration::from_secs(15),
            failure_threshold: 10,
            recovery_threshold: 5,
        };

        let monitor = HealthMonitor::with_config(config);
        let monitor_config = monitor.config();

        assert_eq!(monitor_config.check_interval, Duration::from_secs(120));
        assert_eq!(monitor_config.check_timeout, Duration::from_secs(15));
        assert_eq!(monitor_config.failure_threshold, 10);
        assert_eq!(monitor_config.recovery_threshold, 5);
    }

    #[test]
    fn test_health_monitor_get_all_health() {
        let monitor = HealthMonitor::new();
        let id1 = ChallengeId::new();
        let id2 = ChallengeId::new();
        let id3 = ChallengeId::new();

        assert!(monitor.get_all_health().is_empty());

        monitor.register(id1);
        monitor.register(id2);
        monitor.register(id3);

        let all_health = monitor.get_all_health();
        assert_eq!(all_health.len(), 3);

        let ids: Vec<ChallengeId> = all_health.iter().map(|h| h.challenge_id).collect();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
        assert!(ids.contains(&id3));
    }

    #[test]
    fn test_health_monitor_update_health() {
        let monitor = HealthMonitor::new();
        let id = ChallengeId::new();

        monitor.register(id);
        let health = monitor.get_health(&id).expect("should be registered");
        assert_eq!(health.status, HealthStatus::Unknown);

        monitor.update_health(&id, HealthStatus::Healthy);
        let health = monitor.get_health(&id).expect("should be registered");
        assert_eq!(health.status, HealthStatus::Healthy);
        assert!(health.last_check_at > 0);

        monitor.update_health(&id, HealthStatus::Degraded("high latency".to_string()));
        let health = monitor.get_health(&id).expect("should be registered");
        assert_eq!(
            health.status,
            HealthStatus::Degraded("high latency".to_string())
        );

        monitor.update_health(&id, HealthStatus::Unhealthy("connection lost".to_string()));
        let health = monitor.get_health(&id).expect("should be registered");
        assert_eq!(
            health.status,
            HealthStatus::Unhealthy("connection lost".to_string())
        );
    }

    #[test]
    fn test_health_status_variants() {
        let unknown = HealthStatus::Unknown;
        let healthy = HealthStatus::Healthy;
        let degraded = HealthStatus::Degraded("slow response".to_string());
        let unhealthy = HealthStatus::Unhealthy("service down".to_string());

        assert_eq!(unknown, HealthStatus::Unknown);
        assert_eq!(healthy, HealthStatus::Healthy);
        assert_eq!(
            degraded,
            HealthStatus::Degraded("slow response".to_string())
        );
        assert_eq!(
            unhealthy,
            HealthStatus::Unhealthy("service down".to_string())
        );

        assert_ne!(unknown, healthy);
        assert_ne!(healthy, degraded);
        assert_ne!(degraded, unhealthy);

        let degraded_clone = degraded.clone();
        assert_eq!(degraded, degraded_clone);
    }

    #[test]
    fn test_challenge_health_consecutive_successes() {
        let mut health = ChallengeHealth::new(ChallengeId::new());

        health.record_failure("error 1".to_string());
        health.record_failure("error 2".to_string());
        assert_eq!(health.consecutive_failures, 2);
        assert!(matches!(health.status, HealthStatus::Degraded(_)));

        health.record_success(50.0);
        assert_eq!(health.consecutive_failures, 0);
        assert_eq!(health.status, HealthStatus::Healthy);

        health.record_failure("error 3".to_string());
        health.record_failure("error 4".to_string());
        health.record_failure("error 5".to_string());
        assert_eq!(health.consecutive_failures, 3);
        assert!(matches!(health.status, HealthStatus::Unhealthy(_)));

        health.record_success(75.0);
        assert_eq!(health.consecutive_failures, 0);
        assert_eq!(health.status, HealthStatus::Healthy);
    }
}