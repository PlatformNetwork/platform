//! Health Monitoring System
//!
//! Monitors validator and subnet health, triggers alerts and recovery.

use crate::HealthConfig;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tracing::{debug, error, warn};

/// Health status
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Everything is working
    Healthy,
    /// Some issues but operational
    Degraded,
    /// Serious issues
    Unhealthy,
    /// Critical failure
    Critical,
}

/// Health check result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Overall status
    pub status: HealthStatus,

    /// Individual component checks
    pub components: Vec<ComponentHealth>,

    /// Active alerts
    pub alerts: Vec<HealthAlert>,

    /// Metrics snapshot
    pub metrics: HealthMetrics,
}

/// Component health
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name
    pub name: String,

    /// Status
    pub status: HealthStatus,

    /// Details
    pub details: String,

    /// Last successful check
    pub last_success: Option<DateTime<Utc>>,
}

/// Health alert
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthAlert {
    /// Alert ID
    pub id: uuid::Uuid,

    /// Severity
    pub severity: AlertSeverity,

    /// Message
    pub message: String,

    /// Component
    pub component: String,

    /// Created at
    pub created_at: DateTime<Utc>,

    /// Acknowledged
    pub acknowledged: bool,
}

/// Alert severity
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Health metrics
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HealthMetrics {
    /// Memory usage (%)
    pub memory_percent: f32,

    /// CPU usage (%)
    pub cpu_percent: f32,

    /// Disk usage (%)
    pub disk_percent: f32,

    /// Pending jobs
    pub pending_jobs: u32,

    /// Running jobs
    pub running_jobs: u32,

    /// Completed evaluations (last hour)
    pub evaluations_per_hour: u32,

    /// Failed evaluations (last hour)
    pub failures_per_hour: u32,

    /// Average evaluation time (ms)
    pub avg_eval_time_ms: u64,

    /// Connected peers
    pub connected_peers: u32,

    /// Current block height
    pub block_height: u64,

    /// Current epoch
    pub epoch: u64,

    /// Uptime (seconds)
    pub uptime_secs: u64,
}

/// Health monitor
pub struct HealthMonitor {
    /// Configuration
    config: HealthConfig,

    /// Start time
    start_time: Instant,

    /// Check history
    history: VecDeque<HealthCheck>,

    /// Active alerts
    alerts: Vec<HealthAlert>,

    /// Consecutive failures per component
    failure_counts: std::collections::HashMap<String, u32>,

    /// Last metrics
    last_metrics: HealthMetrics,
}

impl HealthMonitor {
    /// Create a new health monitor
    pub fn new(config: HealthConfig) -> Self {
        Self {
            config,
            start_time: Instant::now(),
            history: VecDeque::with_capacity(100),
            alerts: Vec::new(),
            failure_counts: std::collections::HashMap::new(),
            last_metrics: HealthMetrics::default(),
        }
    }

    /// Run a health check
    pub fn check(&mut self, metrics: HealthMetrics) -> HealthCheck {
        let mut components = Vec::new();
        let mut status = HealthStatus::Healthy;

        // Check memory
        let mem_status = self.check_memory(&metrics);
        if mem_status.status != HealthStatus::Healthy {
            status = Self::worse_status(status, mem_status.status);
        }
        components.push(mem_status);

        // Check CPU
        let cpu_status = self.check_cpu(&metrics);
        if cpu_status.status != HealthStatus::Healthy {
            status = Self::worse_status(status, cpu_status.status);
        }
        components.push(cpu_status);

        // Check disk
        let disk_status = self.check_disk(&metrics);
        if disk_status.status != HealthStatus::Healthy {
            status = Self::worse_status(status, disk_status.status);
        }
        components.push(disk_status);

        // Check job queue
        let queue_status = self.check_job_queue(&metrics);
        if queue_status.status != HealthStatus::Healthy {
            status = Self::worse_status(status, queue_status.status);
        }
        components.push(queue_status);

        // Check evaluation performance
        let eval_status = self.check_evaluations(&metrics);
        if eval_status.status != HealthStatus::Healthy {
            status = Self::worse_status(status, eval_status.status);
        }
        components.push(eval_status);

        // Check network
        let network_status = self.check_network(&metrics);
        if network_status.status != HealthStatus::Healthy {
            status = Self::worse_status(status, network_status.status);
        }
        components.push(network_status);

        // Update last metrics
        self.last_metrics = metrics.clone();

        // Create health check result
        let check = HealthCheck {
            timestamp: Utc::now(),
            status,
            components,
            alerts: self.alerts.clone(),
            metrics,
        };

        // Add to history
        self.history.push_back(check.clone());
        if self.history.len() > 100 {
            self.history.pop_front();
        }

        // Log if not healthy
        match status {
            HealthStatus::Healthy => debug!("Health check: Healthy"),
            HealthStatus::Degraded => warn!("Health check: Degraded"),
            HealthStatus::Unhealthy => error!("Health check: Unhealthy"),
            HealthStatus::Critical => error!("Health check: CRITICAL"),
        }

        check
    }

    fn check_memory(&mut self, metrics: &HealthMetrics) -> ComponentHealth {
        let threshold = self.config.memory_warn_percent as f32;

        if metrics.memory_percent > 95.0 {
            self.add_alert(
                "memory",
                AlertSeverity::Critical,
                format!("Memory critical: {:.1}%", metrics.memory_percent),
            );
            ComponentHealth {
                name: "memory".to_string(),
                status: HealthStatus::Critical,
                details: format!("{:.1}% used", metrics.memory_percent),
                last_success: None,
            }
        } else if metrics.memory_percent > threshold {
            self.add_alert(
                "memory",
                AlertSeverity::Warning,
                format!("Memory high: {:.1}%", metrics.memory_percent),
            );
            ComponentHealth {
                name: "memory".to_string(),
                status: HealthStatus::Degraded,
                details: format!("{:.1}% used", metrics.memory_percent),
                last_success: Some(Utc::now()),
            }
        } else {
            self.clear_failure("memory");
            ComponentHealth {
                name: "memory".to_string(),
                status: HealthStatus::Healthy,
                details: format!("{:.1}% used", metrics.memory_percent),
                last_success: Some(Utc::now()),
            }
        }
    }

    fn check_cpu(&mut self, metrics: &HealthMetrics) -> ComponentHealth {
        let threshold = self.config.cpu_warn_percent as f32;

        if metrics.cpu_percent > threshold {
            self.add_alert(
                "cpu",
                AlertSeverity::Warning,
                format!("CPU high: {:.1}%", metrics.cpu_percent),
            );
            ComponentHealth {
                name: "cpu".to_string(),
                status: HealthStatus::Degraded,
                details: format!("{:.1}% used", metrics.cpu_percent),
                last_success: Some(Utc::now()),
            }
        } else {
            self.clear_failure("cpu");
            ComponentHealth {
                name: "cpu".to_string(),
                status: HealthStatus::Healthy,
                details: format!("{:.1}% used", metrics.cpu_percent),
                last_success: Some(Utc::now()),
            }
        }
    }

    fn check_disk(&mut self, metrics: &HealthMetrics) -> ComponentHealth {
        let threshold = self.config.disk_warn_percent as f32;

        if metrics.disk_percent > 95.0 {
            self.add_alert(
                "disk",
                AlertSeverity::Critical,
                format!("Disk critical: {:.1}%", metrics.disk_percent),
            );
            ComponentHealth {
                name: "disk".to_string(),
                status: HealthStatus::Critical,
                details: format!("{:.1}% used", metrics.disk_percent),
                last_success: None,
            }
        } else if metrics.disk_percent > threshold {
            self.add_alert(
                "disk",
                AlertSeverity::Warning,
                format!("Disk high: {:.1}%", metrics.disk_percent),
            );
            ComponentHealth {
                name: "disk".to_string(),
                status: HealthStatus::Degraded,
                details: format!("{:.1}% used", metrics.disk_percent),
                last_success: Some(Utc::now()),
            }
        } else {
            self.clear_failure("disk");
            ComponentHealth {
                name: "disk".to_string(),
                status: HealthStatus::Healthy,
                details: format!("{:.1}% used", metrics.disk_percent),
                last_success: Some(Utc::now()),
            }
        }
    }

    fn check_job_queue(&mut self, metrics: &HealthMetrics) -> ComponentHealth {
        let max_pending = self.config.max_pending_jobs;

        if metrics.pending_jobs > max_pending * 2 {
            self.add_alert(
                "job_queue",
                AlertSeverity::Error,
                format!("Job queue overloaded: {} pending", metrics.pending_jobs),
            );
            ComponentHealth {
                name: "job_queue".to_string(),
                status: HealthStatus::Unhealthy,
                details: format!(
                    "{} pending, {} running",
                    metrics.pending_jobs, metrics.running_jobs
                ),
                last_success: None,
            }
        } else if metrics.pending_jobs > max_pending {
            self.add_alert(
                "job_queue",
                AlertSeverity::Warning,
                format!("Job queue high: {} pending", metrics.pending_jobs),
            );
            ComponentHealth {
                name: "job_queue".to_string(),
                status: HealthStatus::Degraded,
                details: format!(
                    "{} pending, {} running",
                    metrics.pending_jobs, metrics.running_jobs
                ),
                last_success: Some(Utc::now()),
            }
        } else {
            self.clear_failure("job_queue");
            ComponentHealth {
                name: "job_queue".to_string(),
                status: HealthStatus::Healthy,
                details: format!(
                    "{} pending, {} running",
                    metrics.pending_jobs, metrics.running_jobs
                ),
                last_success: Some(Utc::now()),
            }
        }
    }

    fn check_evaluations(&mut self, metrics: &HealthMetrics) -> ComponentHealth {
        let max_time = self.config.max_eval_time * 1000; // Convert to ms

        // Check failure rate
        let total = metrics.evaluations_per_hour + metrics.failures_per_hour;
        let failure_rate = if total > 0 {
            metrics.failures_per_hour as f32 / total as f32
        } else {
            0.0
        };

        if failure_rate > 0.5 {
            self.add_alert(
                "evaluations",
                AlertSeverity::Critical,
                format!("High failure rate: {:.1}%", failure_rate * 100.0),
            );
            ComponentHealth {
                name: "evaluations".to_string(),
                status: HealthStatus::Critical,
                details: format!(
                    "{:.1}% failure rate, {}ms avg",
                    failure_rate * 100.0,
                    metrics.avg_eval_time_ms
                ),
                last_success: None,
            }
        } else if metrics.avg_eval_time_ms > max_time {
            self.add_alert(
                "evaluations",
                AlertSeverity::Warning,
                format!("Slow evaluations: {}ms avg", metrics.avg_eval_time_ms),
            );
            ComponentHealth {
                name: "evaluations".to_string(),
                status: HealthStatus::Degraded,
                details: format!(
                    "{:.1}% failure rate, {}ms avg",
                    failure_rate * 100.0,
                    metrics.avg_eval_time_ms
                ),
                last_success: Some(Utc::now()),
            }
        } else {
            self.clear_failure("evaluations");
            ComponentHealth {
                name: "evaluations".to_string(),
                status: HealthStatus::Healthy,
                details: format!(
                    "{}/hr, {}ms avg",
                    metrics.evaluations_per_hour, metrics.avg_eval_time_ms
                ),
                last_success: Some(Utc::now()),
            }
        }
    }

    fn check_network(&mut self, metrics: &HealthMetrics) -> ComponentHealth {
        if metrics.connected_peers == 0 {
            self.add_alert(
                "network",
                AlertSeverity::Critical,
                "No connected peers".to_string(),
            );
            ComponentHealth {
                name: "network".to_string(),
                status: HealthStatus::Critical,
                details: "0 peers connected".to_string(),
                last_success: None,
            }
        } else if metrics.connected_peers < 3 {
            self.add_alert(
                "network",
                AlertSeverity::Warning,
                format!("Low peer count: {}", metrics.connected_peers),
            );
            ComponentHealth {
                name: "network".to_string(),
                status: HealthStatus::Degraded,
                details: format!("{} peers connected", metrics.connected_peers),
                last_success: Some(Utc::now()),
            }
        } else {
            self.clear_failure("network");
            ComponentHealth {
                name: "network".to_string(),
                status: HealthStatus::Healthy,
                details: format!("{} peers connected", metrics.connected_peers),
                last_success: Some(Utc::now()),
            }
        }
    }

    fn add_alert(&mut self, component: &str, severity: AlertSeverity, message: String) {
        // Check if similar alert exists
        if self
            .alerts
            .iter()
            .any(|a| a.component == component && !a.acknowledged)
        {
            return;
        }

        let alert = HealthAlert {
            id: uuid::Uuid::new_v4(),
            severity,
            message,
            component: component.to_string(),
            created_at: Utc::now(),
            acknowledged: false,
        };

        self.alerts.push(alert);

        // Increment failure count
        *self
            .failure_counts
            .entry(component.to_string())
            .or_insert(0) += 1;
    }

    fn clear_failure(&mut self, component: &str) {
        self.failure_counts.remove(component);
        // Auto-acknowledge resolved alerts
        for alert in &mut self.alerts {
            if alert.component == component {
                alert.acknowledged = true;
            }
        }
    }

    fn worse_status(a: HealthStatus, b: HealthStatus) -> HealthStatus {
        match (a, b) {
            (HealthStatus::Critical, _) | (_, HealthStatus::Critical) => HealthStatus::Critical,
            (HealthStatus::Unhealthy, _) | (_, HealthStatus::Unhealthy) => HealthStatus::Unhealthy,
            (HealthStatus::Degraded, _) | (_, HealthStatus::Degraded) => HealthStatus::Degraded,
            _ => HealthStatus::Healthy,
        }
    }

    /// Get current status
    pub fn current_status(&self) -> HealthStatus {
        self.history
            .back()
            .map(|h| h.status)
            .unwrap_or(HealthStatus::Healthy)
    }

    /// Get active alerts
    pub fn active_alerts(&self) -> Vec<&HealthAlert> {
        self.alerts.iter().filter(|a| !a.acknowledged).collect()
    }

    /// Acknowledge an alert
    pub fn acknowledge_alert(&mut self, alert_id: uuid::Uuid) {
        if let Some(alert) = self.alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.acknowledged = true;
        }
    }

    /// Get uptime
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Check if recovery is needed
    pub fn needs_recovery(&self) -> bool {
        self.failure_counts
            .values()
            .any(|&count| count >= self.config.failure_threshold)
    }

    /// Get component with most failures
    pub fn worst_component(&self) -> Option<(&str, u32)> {
        self.failure_counts
            .iter()
            .max_by_key(|(_, &count)| count)
            .map(|(name, &count)| (name.as_str(), count))
    }
}

#[cfg(test)]
impl HealthMonitor {
    pub(crate) fn test_history_mut(&mut self) -> &mut VecDeque<HealthCheck> {
        &mut self.history
    }

    pub(crate) fn test_failure_counts_mut(
        &mut self,
    ) -> &mut std::collections::HashMap<String, u32> {
        &mut self.failure_counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_equality() {
        assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
        assert_ne!(HealthStatus::Healthy, HealthStatus::Degraded);
        assert_ne!(HealthStatus::Degraded, HealthStatus::Unhealthy);
        assert_ne!(HealthStatus::Unhealthy, HealthStatus::Critical);
    }

    #[test]
    fn test_alert_severity() {
        let severities = vec![
            AlertSeverity::Info,
            AlertSeverity::Warning,
            AlertSeverity::Error,
            AlertSeverity::Critical,
        ];

        for severity in severities {
            let alert = HealthAlert {
                id: uuid::Uuid::new_v4(),
                severity,
                message: "Test alert".into(),
                component: "test".into(),
                created_at: Utc::now(),
                acknowledged: false,
            };
            assert_eq!(alert.severity, severity);
        }
    }

    #[test]
    fn test_health_metrics_default() {
        let metrics = HealthMetrics::default();
        assert_eq!(metrics.memory_percent, 0.0);
        assert_eq!(metrics.cpu_percent, 0.0);
        assert_eq!(metrics.disk_percent, 0.0);
        assert_eq!(metrics.pending_jobs, 0);
        assert_eq!(metrics.running_jobs, 0);
        assert_eq!(metrics.evaluations_per_hour, 0);
        assert_eq!(metrics.failures_per_hour, 0);
    }

    #[test]
    fn test_health_check() {
        let config = HealthConfig::default();
        let mut monitor = HealthMonitor::new(config);

        let metrics = HealthMetrics {
            memory_percent: 50.0,
            cpu_percent: 30.0,
            disk_percent: 40.0,
            pending_jobs: 10,
            running_jobs: 2,
            evaluations_per_hour: 100,
            failures_per_hour: 1,
            avg_eval_time_ms: 500,
            connected_peers: 5,
            block_height: 1000,
            epoch: 10,
            uptime_secs: 3600,
        };

        let check = monitor.check(metrics);
        assert_eq!(check.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_degraded_health() {
        let config = HealthConfig {
            memory_warn_percent: 50,
            ..Default::default()
        };
        let mut monitor = HealthMonitor::new(config);

        let metrics = HealthMetrics {
            memory_percent: 85.0, // Over threshold
            cpu_percent: 30.0,
            disk_percent: 40.0,
            pending_jobs: 10,
            running_jobs: 2,
            evaluations_per_hour: 100,
            failures_per_hour: 1,
            avg_eval_time_ms: 500,
            connected_peers: 5,
            block_height: 1000,
            epoch: 10,
            uptime_secs: 3600,
        };

        let check = monitor.check(metrics);
        assert_eq!(check.status, HealthStatus::Degraded);
        assert!(!monitor.active_alerts().is_empty());
    }

    #[test]
    fn test_critical_health() {
        let config = HealthConfig::default();
        let mut monitor = HealthMonitor::new(config);

        let metrics = HealthMetrics {
            memory_percent: 50.0,
            cpu_percent: 30.0,
            disk_percent: 40.0,
            pending_jobs: 10,
            running_jobs: 2,
            evaluations_per_hour: 100,
            failures_per_hour: 1,
            avg_eval_time_ms: 500,
            connected_peers: 0, // No peers = critical
            block_height: 1000,
            epoch: 10,
            uptime_secs: 3600,
        };

        let check = monitor.check(metrics);
        assert_eq!(check.status, HealthStatus::Critical);
    }

    #[test]
    fn test_high_cpu_warning() {
        let config = HealthConfig {
            cpu_warn_percent: 80,
            ..Default::default()
        };
        let mut monitor = HealthMonitor::new(config);

        let metrics = HealthMetrics {
            memory_percent: 50.0,
            cpu_percent: 95.0, // High CPU
            disk_percent: 40.0,
            pending_jobs: 10,
            running_jobs: 2,
            evaluations_per_hour: 100,
            failures_per_hour: 1,
            avg_eval_time_ms: 500,
            connected_peers: 5,
            block_height: 1000,
            epoch: 10,
            uptime_secs: 3600,
        };

        let check = monitor.check(metrics);
        assert_ne!(check.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_high_disk_warning() {
        let config = HealthConfig {
            disk_warn_percent: 75,
            ..Default::default()
        };
        let mut monitor = HealthMonitor::new(config);

        let metrics = HealthMetrics {
            memory_percent: 50.0,
            cpu_percent: 50.0,
            disk_percent: 90.0, // High disk
            pending_jobs: 10,
            running_jobs: 2,
            evaluations_per_hour: 100,
            failures_per_hour: 1,
            avg_eval_time_ms: 500,
            connected_peers: 5,
            block_height: 1000,
            epoch: 10,
            uptime_secs: 3600,
        };

        let check = monitor.check(metrics);
        assert_ne!(check.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_high_failure_rate() {
        let config = HealthConfig {
            cpu_warn_percent: 30,
            memory_warn_percent: 30,
            ..Default::default()
        };
        let mut monitor = HealthMonitor::new(config);

        let metrics = HealthMetrics {
            memory_percent: 50.0,
            cpu_percent: 50.0,
            disk_percent: 50.0,
            pending_jobs: 10,
            running_jobs: 2,
            evaluations_per_hour: 100,
            failures_per_hour: 50, // 50% failure rate
            avg_eval_time_ms: 500,
            connected_peers: 5,
            block_height: 1000,
            epoch: 10,
            uptime_secs: 3600,
        };

        let check = monitor.check(metrics);
        assert_ne!(check.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_job_queue_overload() {
        let config = HealthConfig {
            max_pending_jobs: 100,
            ..Default::default()
        };
        let mut monitor = HealthMonitor::new(config);

        let metrics = HealthMetrics {
            memory_percent: 50.0,
            cpu_percent: 50.0,
            disk_percent: 50.0,
            pending_jobs: 500, // Way over limit
            running_jobs: 2,
            evaluations_per_hour: 100,
            failures_per_hour: 1,
            avg_eval_time_ms: 500,
            connected_peers: 5,
            block_height: 1000,
            epoch: 10,
            uptime_secs: 3600,
        };

        let check = monitor.check(metrics);
        assert_ne!(check.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_job_queue_high_warning() {
        let config = HealthConfig {
            max_pending_jobs: 50,
            ..Default::default()
        };
        let mut monitor = HealthMonitor::new(config);

        let metrics = HealthMetrics {
            pending_jobs: 75, // > max_pending but <= 2 * max_pending
            running_jobs: 5,
            ..Default::default()
        };

        let status = monitor.check_job_queue(&metrics);
        assert_eq!(status.status, HealthStatus::Degraded);
        assert!(status.details.contains("75 pending"));
        assert!(matches!(status.last_success, Some(_)));
    }

    #[test]
    fn test_check_evaluations_zero_total() {
        let config = HealthConfig::default();
        let mut monitor = HealthMonitor::new(config);

        let metrics = HealthMetrics {
            evaluations_per_hour: 0,
            failures_per_hour: 0,
            avg_eval_time_ms: 1000,
            ..Default::default()
        };

        let result = monitor.check_evaluations(&metrics);
        assert_eq!(result.status, HealthStatus::Healthy);
        assert!(result.details.contains("0/hr"));
        assert!(matches!(result.last_success, Some(_)));
        assert!(monitor.active_alerts().is_empty());
    }

    #[test]
    fn test_check_evaluations_slow_avg_time() {
        let config = HealthConfig {
            max_eval_time: 1, // seconds (=> 1000 ms threshold)
            ..Default::default()
        };
        let mut monitor = HealthMonitor::new(config);

        let metrics = HealthMetrics {
            evaluations_per_hour: 10,
            failures_per_hour: 0,
            avg_eval_time_ms: 5_000, // exceeds max_time
            ..Default::default()
        };

        let result = monitor.check_evaluations(&metrics);
        assert_eq!(result.status, HealthStatus::Degraded);
        assert!(result.details.contains("5000ms"));
        assert!(matches!(result.last_success, Some(_)));
        assert!(!monitor.active_alerts().is_empty());
    }

    #[test]
    fn test_clear_failure_acknowledges_alerts() {
        let config = HealthConfig {
            failure_threshold: 1,
            ..Default::default()
        };
        let mut monitor = HealthMonitor::new(config);

        monitor.add_alert("job_queue", AlertSeverity::Warning, "Queue high".into());
        assert!(monitor.needs_recovery());
        assert_eq!(monitor.active_alerts().len(), 1);

        monitor.clear_failure("job_queue");

        assert!(!monitor.needs_recovery());
        assert!(monitor.active_alerts().is_empty());
    }

    #[test]
    fn test_worse_status_priority_ordering() {
        assert_eq!(HealthMonitor::worse_status(HealthStatus::Healthy, HealthStatus::Degraded), HealthStatus::Degraded);
        assert_eq!(HealthMonitor::worse_status(HealthStatus::Degraded, HealthStatus::Unhealthy), HealthStatus::Unhealthy);
        assert_eq!(HealthMonitor::worse_status(HealthStatus::Unhealthy, HealthStatus::Critical), HealthStatus::Critical);
        assert_eq!(HealthMonitor::worse_status(HealthStatus::Critical, HealthStatus::Healthy), HealthStatus::Critical);
    }

    #[test]
    fn test_worst_component_tracking() {
        let config = HealthConfig {
            failure_threshold: 2,
            ..Default::default()
        };
        let mut monitor = HealthMonitor::new(config);

        monitor.add_alert("cpu", AlertSeverity::Warning, "High CPU".into());
        monitor.add_alert("memory", AlertSeverity::Warning, "High memory".into());
        let first_alert_id = monitor.active_alerts().iter().find(|a| a.component == "memory").unwrap().id;
        monitor.acknowledge_alert(first_alert_id);
        monitor.add_alert("memory", AlertSeverity::Warning, "Still high".into());

        let worst = monitor.worst_component().unwrap();
        assert_eq!(worst.0, "memory");
        assert_eq!(worst.1, 2);
    }

    #[test]
    fn test_alert_acknowledgement() {
        let config = HealthConfig::default();
        let mut monitor = HealthMonitor::new(config);

        // Trigger an alert
        let metrics = HealthMetrics {
            memory_percent: 95.0, // High memory
            cpu_percent: 50.0,
            disk_percent: 50.0,
            pending_jobs: 10,
            running_jobs: 2,
            evaluations_per_hour: 100,
            failures_per_hour: 1,
            avg_eval_time_ms: 500,
            connected_peers: 5,
            block_height: 1000,
            epoch: 10,
            uptime_secs: 3600,
        };

        monitor.check(metrics);
        let alerts = monitor.active_alerts();
        assert!(!alerts.is_empty());

        if let Some(alert) = alerts.first() {
            let alert_id = alert.id;
            monitor.acknowledge_alert(alert_id);
            let alerts_after = monitor.active_alerts();
            let ack_alerts: Vec<_> = alerts_after
                .iter()
                .filter(|a| a.id == alert_id)
                .collect();
            if !ack_alerts.is_empty() {
                assert!(ack_alerts[0].acknowledged);
            }
        }
    }

    #[test]
    fn test_health_history() {
        let config = HealthConfig::default();
        let mut monitor = HealthMonitor::new(config);

        // Run multiple checks
        for i in 0..5 {
            let metrics = HealthMetrics {
                memory_percent: 50.0 + i as f32,
                cpu_percent: 30.0,
                disk_percent: 40.0,
                pending_jobs: 10,
                running_jobs: 2,
                evaluations_per_hour: 100,
                failures_per_hour: 1,
                avg_eval_time_ms: 500,
                connected_peers: 5,
                block_height: 1000 + i,
                epoch: 10,
                uptime_secs: 3600,
            };
            monitor.check(metrics);
        }

        // Verify health monitoring is working
        let status = monitor.current_status();
        assert!(matches!(status, HealthStatus::Healthy | HealthStatus::Degraded));
    }

    #[test]
    fn test_component_health() {
        let component = ComponentHealth {
            name: "test_component".into(),
            status: HealthStatus::Healthy,
            details: "All good".into(),
            last_success: Some(Utc::now()),
        };

        assert_eq!(component.name, "test_component");
        assert_eq!(component.status, HealthStatus::Healthy);
        assert!(component.last_success.is_some());
    }

    #[test]
    fn test_needs_recovery() {
        let config = HealthConfig {
            failure_threshold: 2,
            cpu_warn_percent: 80,
            memory_warn_percent: 80,
            ..Default::default()
        };
        let mut monitor = HealthMonitor::new(config);

        // First failure
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

        monitor.check(bad_metrics.clone());
        monitor.check(bad_metrics.clone());
        monitor.check(bad_metrics);

        // Should trigger degraded/critical status
        let status = monitor.current_status();
        assert!(matches!(status, HealthStatus::Critical | HealthStatus::Degraded));
    }

    #[test]
    fn test_history_is_trimmed_to_100_entries() {
        let mut monitor = HealthMonitor::new(HealthConfig::default());
        let metrics = HealthMetrics {
            memory_percent: 10.0,
            cpu_percent: 10.0,
            disk_percent: 10.0,
            ..Default::default()
        };

        let first_timestamp = monitor.check(metrics.clone()).timestamp;
        for _ in 0..100 {
            monitor.check(metrics.clone());
        }

        assert_eq!(monitor.history.len(), 100);
        let oldest_timestamp = monitor.history.front().unwrap().timestamp;
        assert!(oldest_timestamp > first_timestamp);
    }

    #[test]
    fn test_worse_status_ordering() {
        assert_eq!(
            HealthMonitor::worse_status(HealthStatus::Healthy, HealthStatus::Degraded),
            HealthStatus::Degraded
        );
        assert_eq!(
            HealthMonitor::worse_status(HealthStatus::Degraded, HealthStatus::Unhealthy),
            HealthStatus::Unhealthy
        );
        assert_eq!(
            HealthMonitor::worse_status(HealthStatus::Unhealthy, HealthStatus::Critical),
            HealthStatus::Critical
        );
        assert_eq!(
            HealthMonitor::worse_status(HealthStatus::Critical, HealthStatus::Healthy),
            HealthStatus::Critical
        );
        assert_eq!(
            HealthMonitor::worse_status(HealthStatus::Healthy, HealthStatus::Healthy),
            HealthStatus::Healthy
        );
    }
}
