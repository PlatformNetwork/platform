//! Health check endpoints for validator coordination
//!
//! Provides:
//! - `/health` - Basic liveness check
//! - `/ready` - Readiness check (can accept traffic)
//! - `/live` - Kubernetes-style liveness probe
//!
//! These enable coordinated rolling updates across the validator network.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Health status of a component
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Component is healthy
    Healthy,
    /// Component is degraded but operational
    Degraded,
    /// Component is unhealthy
    Unhealthy,
    /// Component status is unknown
    #[default]
    Unknown,
}

/// Readiness status for traffic handling
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ReadinessStatus {
    /// Ready to accept traffic
    Ready,
    /// Not ready (initializing, draining, etc.)
    #[default]
    NotReady,
    /// Draining - finishing current work, not accepting new
    Draining,
}

/// Health check response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Overall health status
    pub status: HealthStatus,
    /// Readiness for traffic
    pub ready: ReadinessStatus,
    /// Version string
    pub version: String,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Current epoch
    pub epoch: u64,
    /// P2P connection count
    pub peer_count: u64,
    /// Active challenges count
    pub active_challenges: u64,
    /// Pending evaluations count
    pub pending_evaluations: u64,
    /// Last checkpoint sequence
    pub checkpoint_sequence: u64,
    /// Timestamp (Unix millis)
    pub timestamp: i64,
    /// Component statuses
    pub components: ComponentStatus,
}

/// Status of individual components
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ComponentStatus {
    /// P2P network status
    pub p2p: HealthStatus,
    /// Storage status
    pub storage: HealthStatus,
    /// Consensus status
    pub consensus: HealthStatus,
    /// Bittensor connection status
    pub bittensor: HealthStatus,
    /// Challenge containers status
    pub challenges: HealthStatus,
}

/// Health check manager
pub struct HealthCheck {
    /// Start time
    start_time: Instant,
    /// Version string
    version: String,
    /// Whether ready for traffic
    ready: AtomicBool,
    /// Whether draining
    draining: AtomicBool,
    /// Current epoch
    epoch: AtomicU64,
    /// Peer count
    peer_count: AtomicU64,
    /// Active challenges
    active_challenges: AtomicU64,
    /// Pending evaluations
    pending_evaluations: AtomicU64,
    /// Last checkpoint sequence
    checkpoint_sequence: AtomicU64,
    /// Component status (using interior mutability)
    components: parking_lot::RwLock<ComponentStatus>,
}

impl HealthCheck {
    /// Create a new health check manager
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            start_time: Instant::now(),
            version: version.into(),
            ready: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
            peer_count: AtomicU64::new(0),
            active_challenges: AtomicU64::new(0),
            pending_evaluations: AtomicU64::new(0),
            checkpoint_sequence: AtomicU64::new(0),
            components: parking_lot::RwLock::new(ComponentStatus::default()),
        }
    }

    /// Mark as ready for traffic
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::SeqCst);
        if ready {
            info!("Validator marked as ready for traffic");
        }
    }

    /// Start draining (preparing for shutdown)
    pub fn start_draining(&self) {
        self.draining.store(true, Ordering::SeqCst);
        self.ready.store(false, Ordering::SeqCst);
        info!("Validator entering drain mode");
    }

    /// Check if draining
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    /// Update epoch
    pub fn set_epoch(&self, epoch: u64) {
        self.epoch.store(epoch, Ordering::SeqCst);
    }

    /// Update peer count
    pub fn set_peer_count(&self, count: u64) {
        self.peer_count.store(count, Ordering::SeqCst);
    }

    /// Update active challenges
    pub fn set_active_challenges(&self, count: u64) {
        self.active_challenges.store(count, Ordering::SeqCst);
    }

    /// Update pending evaluations
    pub fn set_pending_evaluations(&self, count: u64) {
        self.pending_evaluations.store(count, Ordering::SeqCst);
    }

    /// Update checkpoint sequence
    pub fn set_checkpoint_sequence(&self, seq: u64) {
        self.checkpoint_sequence.store(seq, Ordering::SeqCst);
    }

    /// Update component status
    pub fn set_component_status(&self, component: &str, status: HealthStatus) {
        let mut components = self.components.write();
        match component {
            "p2p" => components.p2p = status,
            "storage" => components.storage = status,
            "consensus" => components.consensus = status,
            "bittensor" => components.bittensor = status,
            "challenges" => components.challenges = status,
            _ => warn!("Unknown component: {}", component),
        }
    }

    /// Get overall health status
    fn get_overall_status(&self) -> HealthStatus {
        let components = self.components.read();

        // If any component is unhealthy, overall is unhealthy
        if components.p2p == HealthStatus::Unhealthy
            || components.storage == HealthStatus::Unhealthy
            || components.consensus == HealthStatus::Unhealthy
        {
            return HealthStatus::Unhealthy;
        }

        // If any critical component is degraded, overall is degraded
        if components.p2p == HealthStatus::Degraded
            || components.storage == HealthStatus::Degraded
            || components.consensus == HealthStatus::Degraded
        {
            return HealthStatus::Degraded;
        }

        // If Bittensor is down but others are fine, degraded
        if components.bittensor == HealthStatus::Unhealthy {
            return HealthStatus::Degraded;
        }

        HealthStatus::Healthy
    }

    /// Get readiness status
    fn get_readiness(&self) -> ReadinessStatus {
        if self.draining.load(Ordering::SeqCst) {
            return ReadinessStatus::Draining;
        }
        if self.ready.load(Ordering::SeqCst) {
            return ReadinessStatus::Ready;
        }
        ReadinessStatus::NotReady
    }

    /// Get full health response
    pub fn get_health(&self) -> HealthResponse {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        HealthResponse {
            status: self.get_overall_status(),
            ready: self.get_readiness(),
            version: self.version.clone(),
            uptime_secs: self.start_time.elapsed().as_secs(),
            epoch: self.epoch.load(Ordering::SeqCst),
            peer_count: self.peer_count.load(Ordering::SeqCst),
            active_challenges: self.active_challenges.load(Ordering::SeqCst),
            pending_evaluations: self.pending_evaluations.load(Ordering::SeqCst),
            checkpoint_sequence: self.checkpoint_sequence.load(Ordering::SeqCst),
            timestamp,
            components: self.components.read().clone(),
        }
    }

    /// Basic liveness check (is the process running)
    pub fn is_live(&self) -> bool {
        // If we can respond, we're live
        true
    }

    /// Readiness check (can accept traffic)
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst) && !self.draining.load(Ordering::SeqCst)
    }
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self::new("unknown")
    }
}

/// Create a shared health check instance
pub fn create_health_check(version: &str) -> Arc<HealthCheck> {
    Arc::new(HealthCheck::new(version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_check_creation() {
        let health = HealthCheck::new("1.0.0");
        assert_eq!(health.version, "1.0.0");
        assert!(!health.is_ready());
        assert!(!health.is_draining());
    }

    #[test]
    fn test_ready_state() {
        let health = HealthCheck::new("1.0.0");

        assert!(!health.is_ready());
        health.set_ready(true);
        assert!(health.is_ready());

        let response = health.get_health();
        assert_eq!(response.ready, ReadinessStatus::Ready);
    }

    #[test]
    fn test_draining_state() {
        let health = HealthCheck::new("1.0.0");
        health.set_ready(true);

        health.start_draining();
        assert!(health.is_draining());
        assert!(!health.is_ready());

        let response = health.get_health();
        assert_eq!(response.ready, ReadinessStatus::Draining);
    }

    #[test]
    fn test_component_status() {
        let health = HealthCheck::new("1.0.0");

        health.set_component_status("p2p", HealthStatus::Healthy);
        health.set_component_status("storage", HealthStatus::Healthy);
        health.set_component_status("consensus", HealthStatus::Healthy);
        health.set_component_status("bittensor", HealthStatus::Healthy);

        let response = health.get_health();
        assert_eq!(response.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_unhealthy_component() {
        let health = HealthCheck::new("1.0.0");

        health.set_component_status("p2p", HealthStatus::Unhealthy);

        let response = health.get_health();
        assert_eq!(response.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_degraded_component() {
        let health = HealthCheck::new("1.0.0");

        health.set_component_status("p2p", HealthStatus::Healthy);
        health.set_component_status("storage", HealthStatus::Degraded);

        let response = health.get_health();
        assert_eq!(response.status, HealthStatus::Degraded);
    }

    #[test]
    fn test_metrics_update() {
        let health = HealthCheck::new("1.0.0");

        health.set_epoch(42);
        health.set_peer_count(10);
        health.set_active_challenges(3);
        health.set_pending_evaluations(5);
        health.set_checkpoint_sequence(100);

        let response = health.get_health();
        assert_eq!(response.epoch, 42);
        assert_eq!(response.peer_count, 10);
        assert_eq!(response.active_challenges, 3);
        assert_eq!(response.pending_evaluations, 5);
        assert_eq!(response.checkpoint_sequence, 100);
    }

    #[test]
    fn test_uptime() {
        let health = HealthCheck::new("1.0.0");

        // Just check uptime is a reasonable value (not negative, not huge)
        let response = health.get_health();
        assert!(response.uptime_secs < 10); // Should be very small in a test
    }

    #[test]
    fn test_bittensor_degraded() {
        let health = HealthCheck::new("1.0.0");

        health.set_component_status("p2p", HealthStatus::Healthy);
        health.set_component_status("storage", HealthStatus::Healthy);
        health.set_component_status("consensus", HealthStatus::Healthy);
        health.set_component_status("bittensor", HealthStatus::Unhealthy);

        // Bittensor unhealthy = degraded, not fully unhealthy
        let response = health.get_health();
        assert_eq!(response.status, HealthStatus::Degraded);
    }
}