//! Main challenge registry implementation

use crate::error::{RegistryError, RegistryResult};
use crate::health::{HealthMonitor, HealthStatus};
use crate::lifecycle::{ChallengeLifecycle, LifecycleEvent, LifecycleState};
use crate::state::StateStore;
use crate::version::ChallengeVersion;
use parking_lot::RwLock;
use platform_core::ChallengeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Entry for a registered challenge
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeEntry {
    /// Unique challenge ID
    pub id: ChallengeId,
    /// Challenge name
    pub name: String,
    /// Current version
    pub version: ChallengeVersion,
    /// Docker image for the challenge
    pub docker_image: String,
    /// HTTP endpoint for evaluation
    pub endpoint: Option<String>,
    /// Current lifecycle state
    pub lifecycle_state: LifecycleState,
    /// Health status
    pub health_status: HealthStatus,
    /// Registration timestamp
    pub registered_at: i64,
    /// Last updated timestamp
    pub updated_at: i64,
    /// Configuration metadata
    pub metadata: serde_json::Value,
}

impl ChallengeEntry {
    pub fn new(name: String, version: ChallengeVersion, docker_image: String) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            id: ChallengeId::new(),
            name,
            version,
            docker_image,
            endpoint: None,
            lifecycle_state: LifecycleState::Registered,
            health_status: HealthStatus::Unknown,
            registered_at: now,
            updated_at: now,
            metadata: serde_json::Value::Null,
        }
    }

    pub fn with_endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }
}

/// A registered challenge with its full state
#[derive(Clone, Debug)]
pub struct RegisteredChallenge {
    pub entry: ChallengeEntry,
    pub state_store: Arc<StateStore>,
}

type LifecycleListeners = Vec<Box<dyn Fn(LifecycleEvent) + Send + Sync>>;

/// Main challenge registry
pub struct ChallengeRegistry {
    /// Registered challenges by ID
    challenges: RwLock<HashMap<ChallengeId, RegisteredChallenge>>,
    /// Name to ID mapping for lookups
    name_index: RwLock<HashMap<String, ChallengeId>>,
    /// Lifecycle manager
    lifecycle: Arc<ChallengeLifecycle>,
    /// Health monitor
    health_monitor: Arc<HealthMonitor>,
    /// Event listeners
    event_listeners: RwLock<LifecycleListeners>,
}

impl ChallengeRegistry {
    /// Create a new challenge registry
    pub fn new() -> Self {
        Self {
            challenges: RwLock::new(HashMap::new()),
            name_index: RwLock::new(HashMap::new()),
            lifecycle: Arc::new(ChallengeLifecycle::new()),
            health_monitor: Arc::new(HealthMonitor::new()),
            event_listeners: RwLock::new(Vec::new()),
        }
    }

    /// Register a new challenge
    pub fn register(&self, entry: ChallengeEntry) -> RegistryResult<ChallengeId> {
        let mut challenges = self.challenges.write();
        let mut name_index = self.name_index.write();

        // Check if already registered by name
        if name_index.contains_key(&entry.name) {
            return Err(RegistryError::AlreadyRegistered(entry.name.clone()));
        }

        let id = entry.id;
        let name = entry.name.clone();

        let state_store = Arc::new(StateStore::new(id));
        let registered = RegisteredChallenge { entry, state_store };

        challenges.insert(id, registered);
        name_index.insert(name.clone(), id);

        info!(challenge_id = %id, name = %name, "Challenge registered");
        self.emit_event(LifecycleEvent::Registered { challenge_id: id });

        Ok(id)
    }

    /// Unregister a challenge
    pub fn unregister(&self, id: &ChallengeId) -> RegistryResult<ChallengeEntry> {
        let mut challenges = self.challenges.write();
        let mut name_index = self.name_index.write();

        let registered = challenges
            .remove(id)
            .ok_or_else(|| RegistryError::ChallengeNotFound(id.to_string()))?;

        name_index.remove(&registered.entry.name);

        info!(challenge_id = %id, "Challenge unregistered");
        self.emit_event(LifecycleEvent::Unregistered { challenge_id: *id });

        Ok(registered.entry)
    }

    /// Get a challenge by ID
    pub fn get(&self, id: &ChallengeId) -> Option<RegisteredChallenge> {
        self.challenges.read().get(id).cloned()
    }

    /// Get a challenge by name
    pub fn get_by_name(&self, name: &str) -> Option<RegisteredChallenge> {
        let name_index = self.name_index.read();
        let id = name_index.get(name)?;
        self.challenges.read().get(id).cloned()
    }

    /// List all registered challenges
    pub fn list(&self) -> Vec<ChallengeEntry> {
        self.challenges
            .read()
            .values()
            .map(|r| r.entry.clone())
            .collect()
    }

    /// List active challenges (running and healthy)
    pub fn list_active(&self) -> Vec<ChallengeEntry> {
        self.challenges
            .read()
            .values()
            .filter(|r| {
                r.entry.lifecycle_state == LifecycleState::Running
                    && r.entry.health_status == HealthStatus::Healthy
            })
            .map(|r| r.entry.clone())
            .collect()
    }

    /// Update challenge lifecycle state
    pub fn update_state(&self, id: &ChallengeId, new_state: LifecycleState) -> RegistryResult<()> {
        let mut challenges = self.challenges.write();
        let registered = challenges
            .get_mut(id)
            .ok_or_else(|| RegistryError::ChallengeNotFound(id.to_string()))?;

        let old_state = registered.entry.lifecycle_state.clone();
        registered.entry.lifecycle_state = new_state.clone();
        registered.entry.updated_at = chrono::Utc::now().timestamp_millis();

        debug!(
            challenge_id = %id,
            old_state = ?old_state,
            new_state = ?new_state,
            "Challenge state updated"
        );

        self.emit_event(LifecycleEvent::StateChanged {
            challenge_id: *id,
            old_state,
            new_state,
        });

        Ok(())
    }

    /// Update challenge health status
    pub fn update_health(&self, id: &ChallengeId, status: HealthStatus) -> RegistryResult<()> {
        let mut challenges = self.challenges.write();
        let registered = challenges
            .get_mut(id)
            .ok_or_else(|| RegistryError::ChallengeNotFound(id.to_string()))?;

        registered.entry.health_status = status;
        registered.entry.updated_at = chrono::Utc::now().timestamp_millis();

        Ok(())
    }

    /// Update challenge version (for hot-reload)
    pub fn update_version(
        &self,
        id: &ChallengeId,
        new_version: ChallengeVersion,
    ) -> RegistryResult<ChallengeVersion> {
        let mut challenges = self.challenges.write();
        let registered = challenges
            .get_mut(id)
            .ok_or_else(|| RegistryError::ChallengeNotFound(id.to_string()))?;

        let old_version = registered.entry.version.clone();

        if !new_version.is_compatible_with(&old_version) {
            warn!(
                challenge_id = %id,
                old = %old_version,
                new = %new_version,
                "Breaking version change detected"
            );
        }

        registered.entry.version = new_version.clone();
        registered.entry.updated_at = chrono::Utc::now().timestamp_millis();

        info!(
            challenge_id = %id,
            old_version = %old_version,
            new_version = %new_version,
            "Challenge version updated"
        );

        self.emit_event(LifecycleEvent::VersionChanged {
            challenge_id: *id,
            old_version: old_version.clone(),
            new_version,
        });

        Ok(old_version)
    }

    /// Get state store for a challenge
    pub fn state_store(&self, id: &ChallengeId) -> Option<Arc<StateStore>> {
        self.challenges
            .read()
            .get(id)
            .map(|r| r.state_store.clone())
    }

    /// Add event listener
    pub fn on_event<F>(&self, listener: F)
    where
        F: Fn(LifecycleEvent) + Send + Sync + 'static,
    {
        self.event_listeners.write().push(Box::new(listener));
    }

    /// Emit lifecycle event to all listeners
    fn emit_event(&self, event: LifecycleEvent) {
        for listener in self.event_listeners.read().iter() {
            listener(event.clone());
        }
    }

    /// Get lifecycle manager
    pub fn lifecycle(&self) -> Arc<ChallengeLifecycle> {
        self.lifecycle.clone()
    }

    /// Get health monitor
    pub fn health_monitor(&self) -> Arc<HealthMonitor> {
        self.health_monitor.clone()
    }

    /// Challenge count
    pub fn count(&self) -> usize {
        self.challenges.read().len()
    }
}

impl Default for ChallengeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_challenge() {
        let registry = ChallengeRegistry::new();
        let entry = ChallengeEntry::new(
            "test-challenge".to_string(),
            ChallengeVersion::new(1, 0, 0),
            "test:latest".to_string(),
        );

        let id = registry.register(entry).unwrap();
        assert!(registry.get(&id).is_some());
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn test_duplicate_registration() {
        let registry = ChallengeRegistry::new();
        let entry1 = ChallengeEntry::new(
            "test-challenge".to_string(),
            ChallengeVersion::new(1, 0, 0),
            "test:latest".to_string(),
        );
        let entry2 = ChallengeEntry::new(
            "test-challenge".to_string(),
            ChallengeVersion::new(2, 0, 0),
            "test:v2".to_string(),
        );

        registry.register(entry1).unwrap();
        let result = registry.register(entry2);
        assert!(matches!(result, Err(RegistryError::AlreadyRegistered(_))));
    }

    #[test]
    fn test_get_by_name() {
        let registry = ChallengeRegistry::new();
        let entry = ChallengeEntry::new(
            "my-challenge".to_string(),
            ChallengeVersion::new(1, 0, 0),
            "test:latest".to_string(),
        );

        registry.register(entry).unwrap();
        let found = registry.get_by_name("my-challenge");
        assert!(found.is_some());
        assert_eq!(found.unwrap().entry.name, "my-challenge");
    }

    #[test]
    fn test_unregister() {
        let registry = ChallengeRegistry::new();
        let entry = ChallengeEntry::new(
            "test".to_string(),
            ChallengeVersion::new(1, 0, 0),
            "test:latest".to_string(),
        );

        let id = registry.register(entry).unwrap();
        assert_eq!(registry.count(), 1);

        registry.unregister(&id).unwrap();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_update_state() {
        let registry = ChallengeRegistry::new();
        let entry = ChallengeEntry::new(
            "test".to_string(),
            ChallengeVersion::new(1, 0, 0),
            "test:latest".to_string(),
        );

        let id = registry.register(entry).unwrap();
        registry.update_state(&id, LifecycleState::Running).unwrap();

        let challenge = registry.get(&id).unwrap();
        assert_eq!(challenge.entry.lifecycle_state, LifecycleState::Running);
    }

    #[test]
    fn test_update_version() {
        let registry = ChallengeRegistry::new();
        let entry = ChallengeEntry::new(
            "test".to_string(),
            ChallengeVersion::new(1, 0, 0),
            "test:latest".to_string(),
        );

        let id = registry.register(entry).unwrap();
        let old = registry
            .update_version(&id, ChallengeVersion::new(1, 1, 0))
            .unwrap();

        assert_eq!(old, ChallengeVersion::new(1, 0, 0));

        let challenge = registry.get(&id).unwrap();
        assert_eq!(challenge.entry.version, ChallengeVersion::new(1, 1, 0));
    }

    #[test]
    fn test_list_active() {
        let registry = ChallengeRegistry::new();

        // Register two challenges
        let entry1 = ChallengeEntry::new(
            "active".to_string(),
            ChallengeVersion::new(1, 0, 0),
            "test:latest".to_string(),
        );
        let entry2 = ChallengeEntry::new(
            "inactive".to_string(),
            ChallengeVersion::new(1, 0, 0),
            "test:latest".to_string(),
        );

        let id1 = registry.register(entry1).unwrap();
        registry.register(entry2).unwrap();

        // Make first one active
        registry
            .update_state(&id1, LifecycleState::Running)
            .unwrap();
        registry.update_health(&id1, HealthStatus::Healthy).unwrap();

        let active = registry.list_active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].name, "active");
    }

    #[test]
    fn test_entry_builders() {
        let entry = ChallengeEntry::new(
            "test".to_string(),
            ChallengeVersion::new(1, 0, 0),
            "test:latest".to_string(),
        )
        .with_endpoint("http://localhost:8080".to_string())
        .with_metadata(serde_json::json!({"key": "value"}));

        assert_eq!(entry.endpoint, Some("http://localhost:8080".to_string()));
        assert_eq!(entry.metadata["key"], "value");
    }

    #[test]
    fn test_state_store_access() {
        let registry = ChallengeRegistry::new();
        let entry = ChallengeEntry::new(
            "test".to_string(),
            ChallengeVersion::new(1, 0, 0),
            "test:latest".to_string(),
        );

        let id = registry.register(entry).unwrap();
        let store = registry.state_store(&id);
        assert!(store.is_some());
    }
}