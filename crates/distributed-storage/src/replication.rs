//! Replication policy and consistency
//!
//! This module defines replication strategies for distributed storage,
//! including quorum reads/writes, eventual consistency, and conflict resolution.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;

use crate::store::StoredValue;

/// Configuration for replication behavior
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Number of nodes that should store each piece of data
    pub replication_factor: usize,
    /// Minimum number of nodes that must confirm a write
    pub write_quorum: usize,
    /// Minimum number of nodes that must respond to a read
    pub read_quorum: usize,
    /// Time before retrying failed replication (in seconds)
    pub retry_interval_secs: u64,
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Time before considering a node as failed (in seconds)
    pub node_timeout_secs: u64,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            replication_factor: 3,
            write_quorum: 2,
            read_quorum: 2,
            retry_interval_secs: 30,
            max_retries: 3,
            node_timeout_secs: 10,
        }
    }
}

impl ReplicationConfig {
    /// Create a configuration optimized for consistency
    pub fn strong_consistency() -> Self {
        Self {
            replication_factor: 3,
            write_quorum: 3, // All nodes must confirm
            read_quorum: 2,
            retry_interval_secs: 10,
            max_retries: 5,
            node_timeout_secs: 5,
        }
    }

    /// Create a configuration optimized for availability
    pub fn high_availability() -> Self {
        Self {
            replication_factor: 3,
            write_quorum: 1, // Only one node needed
            read_quorum: 1,
            retry_interval_secs: 5,
            max_retries: 10,
            node_timeout_secs: 30,
        }
    }

    /// Create a configuration for single-node operation
    pub fn single_node() -> Self {
        Self {
            replication_factor: 1,
            write_quorum: 1,
            read_quorum: 1,
            retry_interval_secs: 0,
            max_retries: 0,
            node_timeout_secs: 0,
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.write_quorum > self.replication_factor {
            return Err(format!(
                "Write quorum ({}) cannot exceed replication factor ({})",
                self.write_quorum, self.replication_factor
            ));
        }
        if self.read_quorum > self.replication_factor {
            return Err(format!(
                "Read quorum ({}) cannot exceed replication factor ({})",
                self.read_quorum, self.replication_factor
            ));
        }
        if self.write_quorum == 0 {
            return Err("Write quorum must be at least 1".to_string());
        }
        if self.read_quorum == 0 {
            return Err("Read quorum must be at least 1".to_string());
        }
        Ok(())
    }
}

/// Strategy for resolving conflicts between divergent values
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ConflictResolution {
    /// Last write wins (based on timestamp)
    #[default]
    LastWriteWins,
    /// Highest version number wins
    HighestVersion,
    /// Custom merge function (caller provides)
    Custom,
}

/// Replication policy for a namespace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplicationPolicy {
    /// The configuration
    pub config: ReplicationConfig,
    /// How to resolve conflicts
    pub conflict_resolution: ConflictResolution,
    /// Whether to enable anti-entropy repair
    pub enable_anti_entropy: bool,
    /// Interval for anti-entropy sync (in seconds)
    pub anti_entropy_interval_secs: u64,
}

impl Default for ReplicationPolicy {
    fn default() -> Self {
        Self {
            config: ReplicationConfig::default(),
            conflict_resolution: ConflictResolution::LastWriteWins,
            enable_anti_entropy: true,
            anti_entropy_interval_secs: 300, // 5 minutes
        }
    }
}

impl ReplicationPolicy {
    /// Create a new policy with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the replication configuration
    pub fn with_config(mut self, config: ReplicationConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the conflict resolution strategy
    pub fn with_conflict_resolution(mut self, strategy: ConflictResolution) -> Self {
        self.conflict_resolution = strategy;
        self
    }

    /// Enable or disable anti-entropy
    pub fn with_anti_entropy(mut self, enabled: bool) -> Self {
        self.enable_anti_entropy = enabled;
        self
    }
}

/// Conflict resolver for handling divergent values
pub struct ConflictResolver {
    /// Resolution strategy
    strategy: ConflictResolution,
}

impl ConflictResolver {
    /// Create a new resolver
    pub fn new(strategy: ConflictResolution) -> Self {
        Self { strategy }
    }

    /// Resolve a conflict between multiple values
    pub fn resolve(&self, values: Vec<StoredValue>) -> Option<StoredValue> {
        if values.is_empty() {
            return None;
        }

        if values.len() == 1 {
            return Some(values.into_iter().next().unwrap());
        }

        match self.strategy {
            ConflictResolution::LastWriteWins => self.resolve_lww(values),
            ConflictResolution::HighestVersion => self.resolve_version(values),
            ConflictResolution::Custom => {
                // For custom, just return the latest by default
                self.resolve_lww(values)
            }
        }
    }

    /// Resolve using last-write-wins
    fn resolve_lww(&self, values: Vec<StoredValue>) -> Option<StoredValue> {
        values.into_iter().max_by_key(|v| v.metadata.updated_at)
    }

    /// Resolve using highest version
    fn resolve_version(&self, values: Vec<StoredValue>) -> Option<StoredValue> {
        values.into_iter().max_by_key(|v| v.metadata.version)
    }
}

/// Tracks replication state for a key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplicationState {
    /// Key being tracked
    pub key: String,
    /// Nodes that have acknowledged the value
    pub acknowledged_by: Vec<String>,
    /// Nodes that are pending acknowledgment
    pub pending: Vec<String>,
    /// Last replication attempt
    pub last_attempt: Option<DateTime<Utc>>,
    /// Number of attempts made
    pub attempt_count: u32,
    /// Whether replication is complete
    pub is_complete: bool,
}

impl ReplicationState {
    /// Create a new replication state
    pub fn new(key: impl Into<String>, target_nodes: Vec<String>) -> Self {
        Self {
            key: key.into(),
            acknowledged_by: Vec::new(),
            pending: target_nodes,
            last_attempt: None,
            attempt_count: 0,
            is_complete: false,
        }
    }

    /// Mark a node as having acknowledged
    pub fn acknowledge(&mut self, node_id: &str) {
        if let Some(pos) = self.pending.iter().position(|n| n == node_id) {
            self.pending.remove(pos);
            self.acknowledged_by.push(node_id.to_string());
        }
    }

    /// Mark a replication attempt
    pub fn mark_attempt(&mut self) {
        self.last_attempt = Some(Utc::now());
        self.attempt_count += 1;
    }

    /// Check if quorum is reached
    pub fn has_quorum(&self, quorum_size: usize) -> bool {
        self.acknowledged_by.len() >= quorum_size
    }

    /// Check if replication should be retried
    pub fn should_retry(&self, config: &ReplicationConfig) -> bool {
        if self.is_complete {
            return false;
        }

        if self.attempt_count >= config.max_retries {
            return false;
        }

        if self.pending.is_empty() {
            return false;
        }

        if let Some(last) = self.last_attempt {
            let elapsed = (Utc::now() - last).num_seconds();
            elapsed >= config.retry_interval_secs as i64
        } else {
            true
        }
    }

    /// Mark replication as complete
    pub fn complete(&mut self) {
        self.is_complete = true;
    }
}

/// Manager for tracking replication across multiple keys
pub struct ReplicationManager {
    /// Policy to use
    policy: ReplicationPolicy,
    /// Replication state per key
    states: HashMap<String, ReplicationState>,
    /// Conflict resolver
    resolver: ConflictResolver,
}

impl ReplicationManager {
    /// Create a new replication manager
    pub fn new(policy: ReplicationPolicy) -> Self {
        let resolver = ConflictResolver::new(policy.conflict_resolution.clone());
        Self {
            policy,
            states: HashMap::new(),
            resolver,
        }
    }

    /// Start tracking replication for a key
    pub fn track(&mut self, key: String, target_nodes: Vec<String>) {
        let state = ReplicationState::new(key.clone(), target_nodes);
        self.states.insert(key, state);
    }

    /// Stop tracking a key
    pub fn untrack(&mut self, key: &str) {
        self.states.remove(key);
    }

    /// Record an acknowledgment
    pub fn acknowledge(&mut self, key: &str, node_id: &str) {
        if let Some(state) = self.states.get_mut(key) {
            state.acknowledge(node_id);

            // Check if quorum is reached
            if state.has_quorum(self.policy.config.write_quorum) {
                debug!("Quorum reached for key {}", key);
                state.complete();
            }
        }
    }

    /// Get keys that need replication retries
    pub fn get_pending_retries(&self) -> Vec<String> {
        self.states
            .iter()
            .filter(|(_, state)| state.should_retry(&self.policy.config))
            .map(|(key, _)| key.clone())
            .collect()
    }

    /// Get the state for a key
    pub fn get_state(&self, key: &str) -> Option<&ReplicationState> {
        self.states.get(key)
    }

    /// Resolve conflicts between multiple values
    pub fn resolve_conflict(&self, values: Vec<StoredValue>) -> Option<StoredValue> {
        self.resolver.resolve(values)
    }

    /// Get the number of tracked keys
    pub fn tracked_count(&self) -> usize {
        self.states.len()
    }

    /// Get the number of complete replications
    pub fn completed_count(&self) -> usize {
        self.states.values().filter(|s| s.is_complete).count()
    }

    /// Get the number of pending replications
    pub fn pending_count(&self) -> usize {
        self.states.values().filter(|s| !s.is_complete).count()
    }

    /// Clean up completed replications older than a duration
    pub fn cleanup_completed(&mut self, max_age_secs: i64) {
        let now = Utc::now();
        self.states.retain(|_, state| {
            if !state.is_complete {
                return true;
            }
            if let Some(last) = state.last_attempt {
                (now - last).num_seconds() < max_age_secs
            } else {
                true
            }
        });
    }
}

/// Quorum calculator for dynamic quorum based on available nodes
pub struct QuorumCalculator {
    /// Minimum acceptable quorum
    min_quorum: usize,
    /// Target quorum (ideal case)
    target_quorum: usize,
    /// Total nodes in the cluster
    total_nodes: usize,
}

impl QuorumCalculator {
    /// Create a new quorum calculator
    pub fn new(min_quorum: usize, target_quorum: usize, total_nodes: usize) -> Self {
        Self {
            min_quorum,
            target_quorum,
            total_nodes,
        }
    }

    /// Calculate the quorum size based on available nodes
    pub fn calculate(&self, available_nodes: usize) -> usize {
        if available_nodes == 0 {
            return self.min_quorum;
        }

        // Use majority of available nodes, but at least min_quorum
        let majority = (available_nodes / 2) + 1;
        let effective = majority.min(self.target_quorum);

        effective.max(self.min_quorum)
    }

    /// Check if we have enough nodes for any quorum
    pub fn can_achieve_quorum(&self, available_nodes: usize) -> bool {
        available_nodes >= self.min_quorum
    }

    /// Get the minimum number of nodes needed
    pub fn min_nodes_required(&self) -> usize {
        self.min_quorum
    }

    /// Get the total nodes in the cluster
    pub fn total_nodes(&self) -> usize {
        self.total_nodes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ValueMetadata;

    fn create_test_value(data: &[u8], version: u64, timestamp: i64) -> StoredValue {
        let mut metadata = ValueMetadata::new(data, None);
        metadata.version = version;
        metadata.updated_at = timestamp;
        StoredValue {
            data: data.to_vec(),
            metadata,
        }
    }

    #[test]
    fn test_replication_config_default() {
        let config = ReplicationConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.replication_factor, 3);
        assert_eq!(config.write_quorum, 2);
        assert_eq!(config.read_quorum, 2);
    }

    #[test]
    fn test_replication_config_validation() {
        let config = ReplicationConfig {
            write_quorum: 10, // Exceeds replication factor
            ..Default::default()
        };
        assert!(config.validate().is_err());

        config.write_quorum = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_conflict_resolver_lww() {
        let resolver = ConflictResolver::new(ConflictResolution::LastWriteWins);

        let v1 = create_test_value(b"old", 1, 1000);
        let v2 = create_test_value(b"new", 1, 2000);

        let result = resolver.resolve(vec![v1, v2]).unwrap();
        assert_eq!(result.data, b"new");
    }

    #[test]
    fn test_conflict_resolver_version() {
        let resolver = ConflictResolver::new(ConflictResolution::HighestVersion);

        let v1 = create_test_value(b"v1", 1, 2000);
        let v2 = create_test_value(b"v2", 3, 1000);

        let result = resolver.resolve(vec![v1, v2]).unwrap();
        assert_eq!(result.data, b"v2"); // Higher version wins
    }

    #[test]
    fn test_replication_state() {
        let mut state = ReplicationState::new(
            "key1",
            vec![
                "node1".to_string(),
                "node2".to_string(),
                "node3".to_string(),
            ],
        );

        assert!(!state.has_quorum(2));

        state.acknowledge("node1");
        assert!(!state.has_quorum(2));

        state.acknowledge("node2");
        assert!(state.has_quorum(2));

        assert_eq!(state.pending.len(), 1);
        assert_eq!(state.acknowledged_by.len(), 2);
    }

    #[test]
    fn test_replication_state_retry() {
        let config = ReplicationConfig {
            retry_interval_secs: 1,
            max_retries: 3,
            ..Default::default()
        };

        let mut state = ReplicationState::new("key1", vec!["node1".to_string()]);

        // Should retry immediately
        assert!(state.should_retry(&config));

        state.mark_attempt();
        // Should not retry immediately after attempt
        assert!(!state.should_retry(&config));

        // After interval passes...
        state.last_attempt = Some(Utc::now() - chrono::Duration::seconds(2));
        assert!(state.should_retry(&config));

        // After max retries
        state.attempt_count = 3;
        assert!(!state.should_retry(&config));
    }

    #[test]
    fn test_replication_manager() {
        let policy = ReplicationPolicy::default();
        let mut manager = ReplicationManager::new(policy);

        manager.track(
            "key1".to_string(),
            vec!["node1".to_string(), "node2".to_string()],
        );

        assert_eq!(manager.tracked_count(), 1);
        assert_eq!(manager.pending_count(), 1);

        manager.acknowledge("key1", "node1");
        manager.acknowledge("key1", "node2");

        assert_eq!(manager.completed_count(), 1);
    }

    #[test]
    fn test_quorum_calculator() {
        let calc = QuorumCalculator::new(1, 3, 5);

        assert_eq!(calc.calculate(5), 3); // Use target
        assert_eq!(calc.calculate(3), 2); // Majority of 3
        assert_eq!(calc.calculate(1), 1); // Min quorum

        assert!(calc.can_achieve_quorum(1));
        assert!(!calc.can_achieve_quorum(0));
    }

    #[test]
    fn test_replication_policy_builder() {
        let policy = ReplicationPolicy::new()
            .with_config(ReplicationConfig::strong_consistency())
            .with_conflict_resolution(ConflictResolution::HighestVersion)
            .with_anti_entropy(false);

        assert_eq!(policy.config.write_quorum, 3);
        assert_eq!(
            policy.conflict_resolution,
            ConflictResolution::HighestVersion
        );
        assert!(!policy.enable_anti_entropy);
    }

    #[test]
    fn test_replication_manager_cleanup() {
        let policy = ReplicationPolicy::default();
        let mut manager = ReplicationManager::new(policy);

        manager.track("key1".to_string(), vec![]);
        manager.states.get_mut("key1").unwrap().complete();
        manager.states.get_mut("key1").unwrap().last_attempt =
            Some(Utc::now() - chrono::Duration::seconds(100));

        manager.cleanup_completed(50);
        assert_eq!(manager.tracked_count(), 0);
    }
}