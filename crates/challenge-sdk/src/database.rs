//! Challenge-specific database
//!
//! Each challenge gets its own isolated sled database.

use crate::{AgentInfo, ChallengeError, ChallengeId, EvaluationResult, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;

/// Challenge database (sled-based, isolated per challenge)
pub struct ChallengeDatabase {
    db: sled::Db,
    challenge_id: ChallengeId,

    // Pre-opened trees for common operations
    agents_tree: sled::Tree,
    results_tree: sled::Tree,
    kv_tree: sled::Tree,
    meta_tree: sled::Tree,
}

impl ChallengeDatabase {
    /// Open or create a database for a challenge
    pub fn open<P: AsRef<Path>>(base_path: P, challenge_id: ChallengeId) -> Result<Self> {
        let db_path = base_path
            .as_ref()
            .join(format!("challenge_{}", challenge_id));

        let db = sled::open(&db_path)
            .map_err(|e| ChallengeError::Database(format!("Failed to open database: {}", e)))?;

        let agents_tree = db
            .open_tree("agents")
            .map_err(|e| ChallengeError::Database(format!("Failed to open agents tree: {}", e)))?;

        let results_tree = db
            .open_tree("results")
            .map_err(|e| ChallengeError::Database(format!("Failed to open results tree: {}", e)))?;

        let kv_tree = db
            .open_tree("kv")
            .map_err(|e| ChallengeError::Database(format!("Failed to open kv tree: {}", e)))?;

        let meta_tree = db
            .open_tree("meta")
            .map_err(|e| ChallengeError::Database(format!("Failed to open meta tree: {}", e)))?;

        tracing::info!("Opened challenge database at {:?}", db_path);

        Ok(Self {
            db,
            challenge_id,
            agents_tree,
            results_tree,
            kv_tree,
            meta_tree,
        })
    }

    /// Get challenge ID
    pub fn challenge_id(&self) -> ChallengeId {
        self.challenge_id.clone()
    }

    // ==================== Agents ====================

    /// Save agent information
    pub fn save_agent(&self, agent: &AgentInfo) -> Result<()> {
        let data =
            bincode::serialize(agent).map_err(|e| ChallengeError::Serialization(e.to_string()))?;

        self.agents_tree
            .insert(agent.hash.as_bytes(), data)
            .map_err(|e| ChallengeError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get agent by hash
    pub fn get_agent(&self, hash: &str) -> Result<Option<AgentInfo>> {
        let data = self
            .agents_tree
            .get(hash.as_bytes())
            .map_err(|e| ChallengeError::Database(e.to_string()))?;

        match data {
            Some(bytes) => {
                let agent: AgentInfo = bincode::deserialize(&bytes)
                    .map_err(|e| ChallengeError::Serialization(e.to_string()))?;
                Ok(Some(agent))
            }
            None => Ok(None),
        }
    }

    /// List all agents
    pub fn list_agents(&self) -> Result<Vec<AgentInfo>> {
        let mut agents = Vec::new();

        for result in self.agents_tree.iter() {
            let (_, value) = result.map_err(|e| ChallengeError::Database(e.to_string()))?;

            let agent: AgentInfo = bincode::deserialize(&value)
                .map_err(|e| ChallengeError::Serialization(e.to_string()))?;

            agents.push(agent);
        }

        Ok(agents)
    }

    // ==================== Results ====================

    /// Save evaluation result
    pub fn save_result(&self, result: &EvaluationResult) -> Result<()> {
        // Key: agent_hash:job_id
        let key = format!("{}:{}", result.agent_hash, result.job_id);
        let data =
            bincode::serialize(result).map_err(|e| ChallengeError::Serialization(e.to_string()))?;

        self.results_tree
            .insert(key.as_bytes(), data)
            .map_err(|e| ChallengeError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get results for an agent
    pub fn get_results_for_agent(&self, agent_hash: &str) -> Result<Vec<EvaluationResult>> {
        let prefix = format!("{}:", agent_hash);
        let mut results = Vec::new();

        for item in self.results_tree.scan_prefix(prefix.as_bytes()) {
            let (_, value) = item.map_err(|e| ChallengeError::Database(e.to_string()))?;

            let result: EvaluationResult = bincode::deserialize(&value)
                .map_err(|e| ChallengeError::Serialization(e.to_string()))?;

            results.push(result);
        }

        Ok(results)
    }

    /// Get all results
    pub fn get_all_results(&self) -> Result<Vec<EvaluationResult>> {
        let mut results = Vec::new();

        for item in self.results_tree.iter() {
            let (_, value) = item.map_err(|e| ChallengeError::Database(e.to_string()))?;

            let result: EvaluationResult = bincode::deserialize(&value)
                .map_err(|e| ChallengeError::Serialization(e.to_string()))?;

            results.push(result);
        }

        Ok(results)
    }

    /// Get latest result for each agent
    pub fn get_latest_results(&self) -> Result<Vec<EvaluationResult>> {
        let mut latest: std::collections::HashMap<String, EvaluationResult> =
            std::collections::HashMap::new();

        for result in self.get_all_results()? {
            let existing = latest.get(&result.agent_hash);
            if existing.is_none() || existing.unwrap().timestamp < result.timestamp {
                latest.insert(result.agent_hash.clone(), result);
            }
        }

        Ok(latest.into_values().collect())
    }

    // ==================== Key-Value Store ====================

    /// Set a value in the KV store
    pub fn kv_set<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let data =
            bincode::serialize(value).map_err(|e| ChallengeError::Serialization(e.to_string()))?;

        self.kv_tree
            .insert(key.as_bytes(), data)
            .map_err(|e| ChallengeError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get a value from the KV store
    pub fn kv_get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let data = self
            .kv_tree
            .get(key.as_bytes())
            .map_err(|e| ChallengeError::Database(e.to_string()))?;

        match data {
            Some(bytes) => {
                let value: T = bincode::deserialize(&bytes)
                    .map_err(|e| ChallengeError::Serialization(e.to_string()))?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    /// Delete a value from the KV store
    pub fn kv_delete(&self, key: &str) -> Result<bool> {
        let removed = self
            .kv_tree
            .remove(key.as_bytes())
            .map_err(|e| ChallengeError::Database(e.to_string()))?;

        Ok(removed.is_some())
    }

    /// List all keys in the KV store
    pub fn kv_keys(&self) -> Result<Vec<String>> {
        let mut keys = Vec::new();

        for item in self.kv_tree.iter() {
            let (key, _) = item.map_err(|e| ChallengeError::Database(e.to_string()))?;

            if let Ok(key_str) = std::str::from_utf8(&key) {
                keys.push(key_str.to_string());
            }
        }

        Ok(keys)
    }

    // ==================== Metadata ====================

    /// Set metadata value
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.meta_tree
            .insert(key.as_bytes(), value.as_bytes())
            .map_err(|e| ChallengeError::Database(e.to_string()))?;
        Ok(())
    }

    /// Get metadata value
    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let data = self
            .meta_tree
            .get(key.as_bytes())
            .map_err(|e| ChallengeError::Database(e.to_string()))?;

        match data {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).to_string())),
            None => Ok(None),
        }
    }

    /// Get database version
    pub fn get_version(&self) -> Result<u32> {
        self.get_meta("db_version")?
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| ChallengeError::Database("No database version".to_string()))
            .or(Ok(0))
    }

    /// Set database version
    pub fn set_version(&self, version: u32) -> Result<()> {
        self.set_meta("db_version", &version.to_string())
    }

    // ==================== Custom Trees ====================

    /// Open a custom tree
    pub fn open_tree(&self, name: &str) -> Result<sled::Tree> {
        self.db
            .open_tree(name)
            .map_err(|e| ChallengeError::Database(format!("Failed to open tree '{}': {}", name, e)))
    }

    /// Flush to disk
    pub fn flush(&self) -> Result<()> {
        self.db
            .flush()
            .map_err(|e| ChallengeError::Database(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_database_open() {
        let dir = tempdir().unwrap();
        let db = ChallengeDatabase::open(dir.path(), ChallengeId::new("test-challenge"));
        assert!(db.is_ok());
    }

    #[test]
    fn test_challenge_id() {
        let dir = tempdir().unwrap();
        let challenge_id = ChallengeId::new("test-challenge");
        let db = ChallengeDatabase::open(dir.path(), challenge_id.clone()).unwrap();

        assert_eq!(db.challenge_id(), challenge_id);
    }

    #[test]
    fn test_agent_storage() {
        let dir = tempdir().unwrap();
        let db = ChallengeDatabase::open(dir.path(), ChallengeId::new("test-challenge")).unwrap();

        let agent = AgentInfo::new("test_hash_123".to_string());
        db.save_agent(&agent).unwrap();

        let loaded = db.get_agent("test_hash_123").unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().hash, "test_hash_123");
    }

    #[test]
    fn test_list_agents() {
        let dir = tempdir().unwrap();
        let db = ChallengeDatabase::open(dir.path(), ChallengeId::new("test-challenge")).unwrap();

        let agent1 = AgentInfo::new("hash1".to_string());
        let agent2 = AgentInfo::new("hash2".to_string());

        db.save_agent(&agent1).unwrap();
        db.save_agent(&agent2).unwrap();

        let agents = db.list_agents().unwrap();
        assert_eq!(agents.len(), 2);
    }

    #[test]
    fn test_result_storage() {
        let dir = tempdir().unwrap();
        let db = ChallengeDatabase::open(dir.path(), ChallengeId::new("test-challenge")).unwrap();

        let result = EvaluationResult::new(uuid::Uuid::new_v4(), "agent1".to_string(), 0.85);

        db.save_result(&result).unwrap();

        let results = db.get_results_for_agent("agent1").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].score, 0.85);
    }

    #[test]
    fn test_get_all_results() {
        let dir = tempdir().unwrap();
        let db = ChallengeDatabase::open(dir.path(), ChallengeId::new("test-challenge")).unwrap();

        let result1 = EvaluationResult::new(uuid::Uuid::new_v4(), "agent1".to_string(), 0.85);
        let result2 = EvaluationResult::new(uuid::Uuid::new_v4(), "agent2".to_string(), 0.90);

        db.save_result(&result1).unwrap();
        db.save_result(&result2).unwrap();

        let results = db.get_all_results().unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_get_latest_results() {
        let dir = tempdir().unwrap();
        let db = ChallengeDatabase::open(dir.path(), ChallengeId::new("test-challenge")).unwrap();

        // Save multiple results for same agent (agent1)
        let mut result1 = EvaluationResult::new(uuid::Uuid::new_v4(), "agent1".to_string(), 0.70);
        result1.timestamp = chrono::Utc::now() - chrono::Duration::hours(1);

        let result2 = EvaluationResult::new(uuid::Uuid::new_v4(), "agent1".to_string(), 0.90);

        db.save_result(&result1).unwrap();
        db.save_result(&result2).unwrap();

        // Add result for a different agent (agent2)
        let result3 = EvaluationResult::new(uuid::Uuid::new_v4(), "agent2".to_string(), 0.80);
        db.save_result(&result3).unwrap();

        let latest = db.get_latest_results().unwrap();
        // Should have one result per agent (agent1 and agent2)
        assert_eq!(latest.len(), 2);

        // Find results by agent
        let agent1_result = latest.iter().find(|r| r.agent_hash == "agent1").unwrap();
        let agent2_result = latest.iter().find(|r| r.agent_hash == "agent2").unwrap();

        // Verify agent1 has the latest score (0.90, not 0.70)
        assert_eq!(agent1_result.score, 0.90);
        // Verify agent2 has its only score
        assert_eq!(agent2_result.score, 0.80);
    }

    #[test]
    fn test_kv_store() {
        let dir = tempdir().unwrap();
        let db = ChallengeDatabase::open(dir.path(), ChallengeId::new("test-challenge")).unwrap();

        db.kv_set("my_key", &42i32).unwrap();

        let value: Option<i32> = db.kv_get("my_key").unwrap();
        assert_eq!(value, Some(42));
    }

    #[test]
    fn test_kv_delete() {
        let dir = tempdir().unwrap();
        let db = ChallengeDatabase::open(dir.path(), ChallengeId::new("test-challenge")).unwrap();

        db.kv_set("key_to_delete", &"value").unwrap();

        let deleted = db.kv_delete("key_to_delete").unwrap();
        assert!(deleted);

        let value: Option<String> = db.kv_get("key_to_delete").unwrap();
        assert!(value.is_none());

        // Delete non-existent key
        let deleted = db.kv_delete("non_existent").unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_kv_keys() {
        let dir = tempdir().unwrap();
        let db = ChallengeDatabase::open(dir.path(), ChallengeId::new("test-challenge")).unwrap();

        db.kv_set("key1", &1).unwrap();
        db.kv_set("key2", &2).unwrap();
        db.kv_set("key3", &3).unwrap();

        let keys = db.kv_keys().unwrap();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
        assert!(keys.contains(&"key3".to_string()));
    }

    #[test]
    fn test_set_meta() {
        let dir = tempdir().unwrap();
        let db = ChallengeDatabase::open(dir.path(), ChallengeId::new("test-challenge")).unwrap();

        db.set_meta("author", "test_author").unwrap();

        let value = db.get_meta("author").unwrap();
        assert_eq!(value, Some("test_author".to_string()));
    }

    #[test]
    fn test_get_meta() {
        let dir = tempdir().unwrap();
        let db = ChallengeDatabase::open(dir.path(), ChallengeId::new("test-challenge")).unwrap();

        let value = db.get_meta("non_existent").unwrap();
        assert!(value.is_none());

        db.set_meta("key", "value").unwrap();
        let value = db.get_meta("key").unwrap();
        assert_eq!(value, Some("value".to_string()));
    }

    #[test]
    fn test_get_version() {
        let dir = tempdir().unwrap();
        let db = ChallengeDatabase::open(dir.path(), ChallengeId::new("test-challenge")).unwrap();

        // Should return 0 for new database
        let version = db.get_version().unwrap();
        assert_eq!(version, 0);
    }

    #[test]
    fn test_set_version() {
        let dir = tempdir().unwrap();
        let db = ChallengeDatabase::open(dir.path(), ChallengeId::new("test-challenge")).unwrap();

        db.set_version(5).unwrap();

        let version = db.get_version().unwrap();
        assert_eq!(version, 5);
    }

    #[test]
    fn test_open_tree() {
        let dir = tempdir().unwrap();
        let db = ChallengeDatabase::open(dir.path(), ChallengeId::new("test-challenge")).unwrap();

        let custom_tree = db.open_tree("custom_data").unwrap();

        custom_tree.insert(b"key", b"value").unwrap();
        let value = custom_tree.get(b"key").unwrap();
        assert_eq!(value.as_ref().map(|v| v.as_ref()), Some(b"value".as_ref()));
    }

    #[test]
    fn test_flush() {
        let dir = tempdir().unwrap();
        let db = ChallengeDatabase::open(dir.path(), ChallengeId::new("test-challenge")).unwrap();

        db.kv_set("test_key", &"test_value").unwrap();

        // Flush should succeed
        let result = db.flush();
        assert!(result.is_ok());
    }

    #[test]
    fn test_data_persistence_across_reopens() {
        // Test that data persists after closing and reopening the database
        let dir = tempdir().unwrap();
        let challenge_id = ChallengeId::new("test-challenge");

        // First session: write data
        {
            let db = ChallengeDatabase::open(dir.path(), challenge_id.clone()).unwrap();

            // Save an agent
            let agent = AgentInfo::new("persistent_agent".to_string());
            db.save_agent(&agent).unwrap();

            // Save a result
            let result =
                EvaluationResult::new(uuid::Uuid::new_v4(), "persistent_agent".to_string(), 0.95);
            db.save_result(&result).unwrap();

            // Save KV data
            db.kv_set("persistent_key", &"persistent_value").unwrap();

            // Save metadata
            db.set_meta("test_meta", "meta_value").unwrap();
            db.set_version(42).unwrap();

            // Explicitly flush to disk
            db.flush().unwrap();

            // Drop db to close it
        }

        // Second session: verify data persists
        {
            let db = ChallengeDatabase::open(dir.path(), challenge_id.clone()).unwrap();

            // Verify agent persists
            let agent = db.get_agent("persistent_agent").unwrap();
            assert!(agent.is_some());
            assert_eq!(agent.unwrap().hash, "persistent_agent");

            // Verify results persist
            let results = db.get_results_for_agent("persistent_agent").unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].score, 0.95);

            // Verify KV data persists
            let value: Option<String> = db.kv_get("persistent_key").unwrap();
            assert_eq!(value, Some("persistent_value".to_string()));

            // Verify metadata persists
            let meta = db.get_meta("test_meta").unwrap();
            assert_eq!(meta, Some("meta_value".to_string()));

            let version = db.get_version().unwrap();
            assert_eq!(version, 42);
        }

        // Third session: verify data still persists (double check)
        {
            let db = ChallengeDatabase::open(dir.path(), challenge_id.clone()).unwrap();

            let agents = db.list_agents().unwrap();
            assert_eq!(agents.len(), 1);
            assert_eq!(agents[0].hash, "persistent_agent");

            let all_results = db.get_all_results().unwrap();
            assert_eq!(all_results.len(), 1);
        }
    }
}
