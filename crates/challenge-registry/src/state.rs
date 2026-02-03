//! State management for challenge hot-reload
//!
//! Provides state persistence and restoration to support
//! hot-reloading challenges without losing evaluation state.

use crate::error::{RegistryError, RegistryResult};
use parking_lot::RwLock;
use platform_core::ChallengeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Snapshot of challenge state at a point in time
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Challenge ID this snapshot belongs to
    pub challenge_id: ChallengeId,
    /// Version when snapshot was taken
    pub version: String,
    /// Timestamp when snapshot was created (millis)
    pub created_at: i64,
    /// Serialized state data
    pub data: Vec<u8>,
    /// Checksum for integrity verification
    pub checksum: String,
}

impl StateSnapshot {
    /// Create a new state snapshot
    pub fn new(challenge_id: ChallengeId, version: String, data: Vec<u8>) -> Self {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let checksum = hex::encode(hasher.finalize());

        Self {
            challenge_id,
            version,
            created_at: chrono::Utc::now().timestamp_millis(),
            data,
            checksum,
        }
    }

    /// Verify snapshot integrity
    pub fn verify(&self) -> bool {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&self.data);
        let computed = hex::encode(hasher.finalize());

        computed == self.checksum
    }

    /// Get the size of the snapshot data
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

/// State of a challenge that can be preserved across hot-reloads
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeState {
    /// Challenge ID
    pub challenge_id: ChallengeId,
    /// Active evaluations being tracked
    pub active_evaluations: HashMap<String, EvaluationState>,
    /// Completed evaluation count
    pub completed_count: u64,
    /// Last activity timestamp
    pub last_activity_at: i64,
    /// Custom state data from the challenge
    pub custom_data: serde_json::Value,
}

/// State of an in-progress evaluation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationState {
    /// Evaluation job ID
    pub job_id: String,
    /// When evaluation started (millis)
    pub started_at: i64,
    /// Current progress (0.0 - 1.0)
    pub progress: f64,
    /// Checkpoint data for resumption
    pub checkpoint: Option<Vec<u8>>,
}

impl ChallengeState {
    /// Create new empty state for a challenge
    pub fn new(challenge_id: ChallengeId) -> Self {
        Self {
            challenge_id,
            active_evaluations: HashMap::new(),
            completed_count: 0,
            last_activity_at: chrono::Utc::now().timestamp_millis(),
            custom_data: serde_json::Value::Null,
        }
    }

    /// Check if there are active evaluations
    pub fn has_active_evaluations(&self) -> bool {
        !self.active_evaluations.is_empty()
    }

    /// Get count of active evaluations
    pub fn active_evaluation_count(&self) -> usize {
        self.active_evaluations.len()
    }
}

/// Store for challenge state with persistence support
#[derive(Debug)]
pub struct StateStore {
    /// Challenge this store belongs to
    challenge_id: ChallengeId,
    /// In-memory state
    state: RwLock<ChallengeState>,
    /// Snapshots for recovery
    snapshots: RwLock<Vec<StateSnapshot>>,
    /// Maximum snapshots to retain
    max_snapshots: usize,
}

impl StateStore {
    /// Create a new state store for a challenge
    pub fn new(challenge_id: ChallengeId) -> Self {
        Self {
            challenge_id,
            state: RwLock::new(ChallengeState::new(challenge_id)),
            snapshots: RwLock::new(Vec::new()),
            max_snapshots: 5,
        }
    }

    /// Create a state store with custom snapshot limit
    pub fn with_max_snapshots(challenge_id: ChallengeId, max_snapshots: usize) -> Self {
        Self {
            challenge_id,
            state: RwLock::new(ChallengeState::new(challenge_id)),
            snapshots: RwLock::new(Vec::new()),
            max_snapshots,
        }
    }

    /// Get current state (read-only)
    pub fn get_state(&self) -> ChallengeState {
        self.state.read().clone()
    }

    /// Update state with a function
    pub fn update_state<F>(&self, f: F)
    where
        F: FnOnce(&mut ChallengeState),
    {
        let mut state = self.state.write();
        f(&mut state);
        state.last_activity_at = chrono::Utc::now().timestamp_millis();
    }

    /// Track a new evaluation
    pub fn track_evaluation(&self, job_id: String) {
        let mut state = self.state.write();
        state.active_evaluations.insert(
            job_id.clone(),
            EvaluationState {
                job_id,
                started_at: chrono::Utc::now().timestamp_millis(),
                progress: 0.0,
                checkpoint: None,
            },
        );
        state.last_activity_at = chrono::Utc::now().timestamp_millis();
    }

    /// Update evaluation progress
    pub fn update_evaluation_progress(&self, job_id: &str, progress: f64) {
        let mut state = self.state.write();
        if let Some(eval) = state.active_evaluations.get_mut(job_id) {
            eval.progress = progress.clamp(0.0, 1.0);
        }
        state.last_activity_at = chrono::Utc::now().timestamp_millis();
    }

    /// Complete an evaluation
    pub fn complete_evaluation(&self, job_id: &str) {
        let mut state = self.state.write();
        state.active_evaluations.remove(job_id);
        state.completed_count += 1;
        state.last_activity_at = chrono::Utc::now().timestamp_millis();
    }

    /// Create a snapshot of current state
    pub fn create_snapshot(&self, version: String) -> RegistryResult<StateSnapshot> {
        let state = self.state.read();
        // Use JSON for serialization since ChallengeState contains serde_json::Value
        let data = serde_json::to_vec(&*state)
            .map_err(|e| RegistryError::StatePersistence(e.to_string()))?;

        let snapshot = StateSnapshot::new(self.challenge_id, version, data);

        let mut snapshots = self.snapshots.write();
        snapshots.push(snapshot.clone());

        // Trim old snapshots
        while snapshots.len() > self.max_snapshots {
            snapshots.remove(0);
        }

        Ok(snapshot)
    }

    /// Restore state from a snapshot
    pub fn restore_snapshot(&self, snapshot: &StateSnapshot) -> RegistryResult<()> {
        if !snapshot.verify() {
            return Err(RegistryError::StateRestoration(
                "Snapshot checksum mismatch".to_string(),
            ));
        }

        // Use JSON for deserialization since ChallengeState contains serde_json::Value
        let restored: ChallengeState = serde_json::from_slice(&snapshot.data)
            .map_err(|e| RegistryError::StateRestoration(e.to_string()))?;

        let mut state = self.state.write();
        *state = restored;

        Ok(())
    }

    /// Get list of available snapshots
    pub fn list_snapshots(&self) -> Vec<StateSnapshot> {
        self.snapshots.read().clone()
    }

    /// Get the latest snapshot
    pub fn latest_snapshot(&self) -> Option<StateSnapshot> {
        self.snapshots.read().last().cloned()
    }

    /// Clear all state
    pub fn clear(&self) {
        let mut state = self.state.write();
        *state = ChallengeState::new(self.challenge_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_store() {
        let id = ChallengeId::new();
        let store = StateStore::new(id);

        store.track_evaluation("job1".to_string());
        let state = store.get_state();
        assert_eq!(state.active_evaluation_count(), 1);

        store.update_evaluation_progress("job1", 0.5);
        let state = store.get_state();
        let eval = state.active_evaluations.get("job1").unwrap();
        assert_eq!(eval.progress, 0.5);

        store.complete_evaluation("job1");
        let state = store.get_state();
        assert_eq!(state.active_evaluation_count(), 0);
        assert_eq!(state.completed_count, 1);
    }

    #[test]
    fn test_snapshot_creation() {
        let id = ChallengeId::new();
        let store = StateStore::new(id);

        store.track_evaluation("job1".to_string());
        let snapshot = store.create_snapshot("1.0.0".to_string()).unwrap();

        assert!(snapshot.verify());
        assert_eq!(snapshot.version, "1.0.0");
    }

    #[test]
    fn test_snapshot_restoration() {
        let id = ChallengeId::new();
        let store = StateStore::new(id);

        store.track_evaluation("job1".to_string());
        store.track_evaluation("job2".to_string());
        let snapshot = store.create_snapshot("1.0.0".to_string()).unwrap();

        // Clear and verify empty
        store.clear();
        assert_eq!(store.get_state().active_evaluation_count(), 0);

        // Restore and verify
        store.restore_snapshot(&snapshot).unwrap();
        assert_eq!(store.get_state().active_evaluation_count(), 2);
    }

    #[test]
    fn test_snapshot_limit() {
        let id = ChallengeId::new();
        let store = StateStore::with_max_snapshots(id, 3);

        for i in 0..5 {
            store.create_snapshot(format!("{}.0.0", i)).unwrap();
        }

        let snapshots = store.list_snapshots();
        assert_eq!(snapshots.len(), 3);
        assert_eq!(snapshots[0].version, "2.0.0");
    }
}
