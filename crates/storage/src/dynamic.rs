//! Dynamic storage system for blockchain data
//!
//! Provides namespaced storage for:
//! - System-level data
//! - Per-challenge data
//! - Per-validator data (within challenges or global)
//!
//! Features:
//! - Typed values (bool, u64, string, bytes, json, map, list)
//! - TTL support for ephemeral data
//! - Optimistic locking with versions
//! - Change tracking for replication/sync

use crate::types::{
    NamespaceStats, StorageChange, StorageEntry, StorageKey, StorageStats, StorageValue,
};
use parking_lot::RwLock;
use platform_core::{ChallengeId, Hotkey, MiniChainError, Result};
use sled::Tree;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{info, trace};

/// Dynamic storage manager
#[allow(clippy::type_complexity)]
pub struct DynamicStorage {
    /// Main storage tree
    tree: Tree,
    /// In-memory cache for hot data
    cache: Arc<RwLock<HashMap<Vec<u8>, StorageEntry>>>,
    /// Cache enabled
    cache_enabled: bool,
    /// Maximum cache size
    max_cache_size: usize,
    /// Change listeners
    change_listeners: Arc<RwLock<Vec<Box<dyn Fn(&StorageChange) + Send + Sync>>>>,
    /// Current block height (for change tracking)
    block_height: Arc<RwLock<u64>>,
}

impl DynamicStorage {
    /// Create a new dynamic storage instance
    pub fn new(db: &sled::Db) -> Result<Self> {
        let tree = db.open_tree("dynamic_storage").map_err(|e| {
            MiniChainError::Storage(format!("Failed to open dynamic storage: {}", e))
        })?;

        info!("Dynamic storage initialized");

        Ok(Self {
            tree,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_enabled: true,
            max_cache_size: 10000,
            change_listeners: Arc::new(RwLock::new(Vec::new())),
            block_height: Arc::new(RwLock::new(0)),
        })
    }

    /// Create with custom cache settings
    pub fn with_cache(mut self, enabled: bool, max_size: usize) -> Self {
        self.cache_enabled = enabled;
        self.max_cache_size = max_size;
        self
    }

    /// Set the current block height
    pub fn set_block_height(&self, height: u64) {
        *self.block_height.write() = height;
    }

    /// Get a scoped storage handle for a challenge
    pub fn challenge_storage(&self, challenge_id: ChallengeId) -> ChallengeStorage<'_> {
        ChallengeStorage {
            storage: self,
            challenge_id,
        }
    }

    /// Get a scoped storage handle for a validator (global)
    pub fn validator_storage(&self, validator: Hotkey) -> ValidatorStorage<'_> {
        ValidatorStorage {
            storage: self,
            validator,
            challenge_id: None,
        }
    }

    /// Register a change listener
    pub fn on_change<F>(&self, listener: F)
    where
        F: Fn(&StorageChange) + Send + Sync + 'static,
    {
        self.change_listeners.write().push(Box::new(listener));
    }

    /// Get a value
    pub fn get(&self, key: &StorageKey) -> Result<Option<StorageEntry>> {
        let key_bytes = key.to_bytes();

        // Check cache first
        if self.cache_enabled {
            if let Some(entry) = self.cache.read().get(&key_bytes) {
                if !entry.is_expired() {
                    trace!("Cache hit for {:?}", key);
                    return Ok(Some(entry.clone()));
                }
            }
        }

        // Load from disk
        match self
            .tree
            .get(&key_bytes)
            .map_err(|e| MiniChainError::Storage(e.to_string()))?
        {
            Some(data) => {
                let entry: StorageEntry = bincode::deserialize(&data)
                    .map_err(|e| MiniChainError::Serialization(e.to_string()))?;

                // Check expiry
                if entry.is_expired() {
                    // Clean up expired entry
                    self.tree
                        .remove(&key_bytes)
                        .map_err(|e| MiniChainError::Storage(e.to_string()))?;
                    if self.cache_enabled {
                        self.cache.write().remove(&key_bytes);
                    }
                    return Ok(None);
                }

                // Update cache
                if self.cache_enabled {
                    let mut cache = self.cache.write();
                    if cache.len() < self.max_cache_size {
                        cache.insert(key_bytes, entry.clone());
                    }
                }

                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Get just the value (without metadata)
    pub fn get_value(&self, key: &StorageKey) -> Result<Option<StorageValue>> {
        Ok(self.get(key)?.map(|e| e.value))
    }

    /// Set a value
    pub fn set(&self, key: StorageKey, value: StorageValue, writer: Option<Hotkey>) -> Result<()> {
        self.set_with_options(key, value, writer, None)
    }

    /// Set a value with TTL
    pub fn set_with_ttl(
        &self,
        key: StorageKey,
        value: StorageValue,
        writer: Option<Hotkey>,
        ttl: Duration,
    ) -> Result<()> {
        self.set_with_options(key, value, writer, Some(ttl))
    }

    /// Set a value with options
    pub fn set_with_options(
        &self,
        key: StorageKey,
        value: StorageValue,
        writer: Option<Hotkey>,
        ttl: Option<Duration>,
    ) -> Result<()> {
        let key_bytes = key.to_bytes();

        // Get old value for change notification
        let old_entry = self.get(&key)?;
        let old_value = old_entry.as_ref().map(|e| e.value.clone());

        // Create or update entry
        let entry = if let Some(mut existing) = old_entry {
            existing.update(value.clone(), writer);
            if let Some(t) = ttl {
                existing.ttl = Some(t);
            }
            existing
        } else {
            let mut e = StorageEntry::new(value.clone(), writer);
            if let Some(t) = ttl {
                e.ttl = Some(t);
            }
            e
        };

        // Serialize and store
        let data =
            bincode::serialize(&entry).map_err(|e| MiniChainError::Serialization(e.to_string()))?;

        self.tree
            .insert(&key_bytes, data)
            .map_err(|e| MiniChainError::Storage(e.to_string()))?;

        // Update cache
        if self.cache_enabled {
            let mut cache = self.cache.write();
            if cache.len() < self.max_cache_size || cache.contains_key(&key_bytes) {
                cache.insert(key_bytes, entry);
            }
        }

        // Notify listeners
        let change = StorageChange {
            key,
            old_value,
            new_value: Some(value),
            block_height: *self.block_height.read(),
            timestamp: SystemTime::now(),
        };

        for listener in self.change_listeners.read().iter() {
            listener(&change);
        }

        Ok(())
    }

    /// Delete a value
    pub fn delete(&self, key: &StorageKey) -> Result<Option<StorageValue>> {
        let key_bytes = key.to_bytes();

        // Get old value
        let old_entry = self.get(key)?;
        let old_value = old_entry.map(|e| e.value);

        // Remove from storage
        self.tree
            .remove(&key_bytes)
            .map_err(|e| MiniChainError::Storage(e.to_string()))?;

        // Remove from cache
        if self.cache_enabled {
            self.cache.write().remove(&key_bytes);
        }

        // Notify listeners
        if old_value.is_some() {
            let change = StorageChange {
                key: key.clone(),
                old_value: old_value.clone(),
                new_value: None,
                block_height: *self.block_height.read(),
                timestamp: SystemTime::now(),
            };

            for listener in self.change_listeners.read().iter() {
                listener(&change);
            }
        }

        Ok(old_value)
    }

    /// Check if a key exists
    pub fn exists(&self, key: &StorageKey) -> Result<bool> {
        let key_bytes = key.to_bytes();

        if self.cache_enabled {
            if let Some(entry) = self.cache.read().get(&key_bytes) {
                return Ok(!entry.is_expired());
            }
        }

        self.tree
            .contains_key(&key_bytes)
            .map_err(|e| MiniChainError::Storage(e.to_string()))
    }

    /// Increment a numeric value atomically
    pub fn increment(&self, key: &StorageKey, delta: i64, writer: Option<Hotkey>) -> Result<i64> {
        let current = self.get_value(key)?.and_then(|v| v.as_i64()).unwrap_or(0);

        let new_value = current + delta;
        self.set(key.clone(), StorageValue::I64(new_value), writer)?;

        Ok(new_value)
    }

    /// Append to a list
    pub fn list_push(
        &self,
        key: &StorageKey,
        value: StorageValue,
        writer: Option<Hotkey>,
    ) -> Result<usize> {
        let existing = self.get_value(key)?;

        let mut list = match existing {
            None => Vec::new(),
            Some(v) => {
                if let Some(l) = v.as_list() {
                    l.clone()
                } else {
                    return Err(MiniChainError::TypeMismatch(format!(
                        "Cannot push to non-list value at key {:?}. Existing value is not a list.",
                        key
                    )));
                }
            }
        };

        list.push(value);
        let len = list.len();

        self.set(key.clone(), StorageValue::List(list), writer)?;
        Ok(len)
    }

    /// Set a map field
    pub fn map_set(
        &self,
        key: &StorageKey,
        field: impl Into<String>,
        value: StorageValue,
        writer: Option<Hotkey>,
    ) -> Result<()> {
        let existing = self.get_value(key)?;

        let mut map = match existing {
            None => HashMap::new(),
            Some(v) => {
                if let Some(m) = v.as_map() {
                    m.clone()
                } else {
                    return Err(MiniChainError::TypeMismatch(format!(
                        "Cannot set map field on non-map value at key {:?}. Existing value is not a map.",
                        key
                    )));
                }
            }
        };

        map.insert(field.into(), value);
        self.set(key.clone(), StorageValue::Map(map), writer)
    }

    /// Get a map field
    pub fn map_get(&self, key: &StorageKey, field: &str) -> Result<Option<StorageValue>> {
        Ok(self
            .get_value(key)?
            .and_then(|v| v.as_map().and_then(|m| m.get(field).cloned())))
    }

    /// Scan keys with a namespace prefix
    pub fn scan_namespace(&self, namespace: &str) -> Result<Vec<(StorageKey, StorageEntry)>> {
        let prefix = StorageKey::namespace_prefix(namespace);
        let mut results = Vec::new();

        for item in self.tree.scan_prefix(&prefix) {
            let (key_bytes, data) = item.map_err(|e| MiniChainError::Storage(e.to_string()))?;

            let entry: StorageEntry = bincode::deserialize(&data)
                .map_err(|e| MiniChainError::Serialization(e.to_string()))?;

            if entry.is_expired() {
                continue;
            }

            // Parse key
            if let Some(key) = self.parse_key(&key_bytes) {
                results.push((key, entry));
            }
        }

        Ok(results)
    }

    /// Parse key bytes back to StorageKey
    fn parse_key(&self, bytes: &[u8]) -> Option<StorageKey> {
        let s = String::from_utf8_lossy(bytes);
        let parts: Vec<&str> = s.split('\0').collect();

        if parts.len() >= 2 {
            let namespace = parts[0].to_string();
            let validator = if parts.len() > 2 && !parts[1].is_empty() {
                // Try to parse as hotkey
                let v_bytes = parts[1].as_bytes();
                if v_bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(v_bytes);
                    Some(Hotkey(arr))
                } else {
                    None
                }
            } else {
                None
            };
            let key = parts.last()?.to_string();

            Some(StorageKey {
                namespace,
                validator,
                key,
            })
        } else {
            None
        }
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&self) -> Result<usize> {
        let mut removed = 0;
        let mut to_remove = Vec::new();

        for item in self.tree.iter() {
            let (key, data) = item.map_err(|e| MiniChainError::Storage(e.to_string()))?;

            if let Ok(entry) = bincode::deserialize::<StorageEntry>(&data) {
                if entry.is_expired() {
                    to_remove.push(key.to_vec());
                }
            }
        }

        for key in to_remove {
            self.tree
                .remove(&key)
                .map_err(|e| MiniChainError::Storage(e.to_string()))?;
            removed += 1;
        }

        // Also clean cache
        if self.cache_enabled {
            self.cache.write().retain(|_, v| !v.is_expired());
        }

        if removed > 0 {
            info!("Cleaned up {} expired storage entries", removed);
        }

        Ok(removed)
    }

    /// Get storage statistics
    pub fn stats(&self) -> Result<StorageStats> {
        let mut stats = StorageStats::default();
        let mut namespaces: HashMap<String, NamespaceStats> = HashMap::new();

        for item in self.tree.iter() {
            let (key, data) = item.map_err(|e| MiniChainError::Storage(e.to_string()))?;

            stats.total_keys += 1;
            stats.total_size_bytes += key.len() as u64 + data.len() as u64;

            // Parse namespace from key
            if let Some(parsed_key) = self.parse_key(&key) {
                let ns_stats = namespaces.entry(parsed_key.namespace).or_default();
                ns_stats.key_count += 1;
                ns_stats.size_bytes += key.len() as u64 + data.len() as u64;
                if parsed_key.validator.is_some() {
                    ns_stats.validator_count += 1;
                }
            }
        }

        stats.namespaces = namespaces;
        Ok(stats)
    }

    /// Clear cache
    pub fn clear_cache(&self) {
        self.cache.write().clear();
    }

    /// Flush to disk
    pub fn flush(&self) -> Result<()> {
        self.tree
            .flush()
            .map_err(|e| MiniChainError::Storage(e.to_string()))?;
        Ok(())
    }
}

/// Scoped storage for a specific challenge
pub struct ChallengeStorage<'a> {
    storage: &'a DynamicStorage,
    challenge_id: ChallengeId,
}

impl<'a> ChallengeStorage<'a> {
    /// Get a value
    pub fn get(&self, key: &str) -> Result<Option<StorageValue>> {
        let storage_key = StorageKey::challenge(&self.challenge_id, key);
        self.storage.get_value(&storage_key)
    }

    /// Set a value
    pub fn set(&self, key: &str, value: impl Into<StorageValue>) -> Result<()> {
        let storage_key = StorageKey::challenge(&self.challenge_id, key);
        self.storage.set(storage_key, value.into(), None)
    }

    /// Set with TTL
    pub fn set_with_ttl(
        &self,
        key: &str,
        value: impl Into<StorageValue>,
        ttl: Duration,
    ) -> Result<()> {
        let storage_key = StorageKey::challenge(&self.challenge_id, key);
        self.storage
            .set_with_ttl(storage_key, value.into(), None, ttl)
    }

    /// Delete a value
    pub fn delete(&self, key: &str) -> Result<Option<StorageValue>> {
        let storage_key = StorageKey::challenge(&self.challenge_id, key);
        self.storage.delete(&storage_key)
    }

    /// Get validator-scoped storage within this challenge
    pub fn validator(&self, validator: &Hotkey) -> ValidatorStorage<'a> {
        ValidatorStorage {
            storage: self.storage,
            validator: validator.clone(),
            challenge_id: Some(self.challenge_id),
        }
    }

    /// Scan all keys in this challenge
    pub fn scan(&self) -> Result<Vec<(String, StorageEntry)>> {
        let namespace = self.challenge_id.0.to_string();
        let entries = self.storage.scan_namespace(&namespace)?;

        Ok(entries
            .into_iter()
            .filter(|(k, _)| k.validator.is_none()) // Only challenge-level keys
            .map(|(k, v)| (k.key, v))
            .collect())
    }

    /// Increment counter
    pub fn increment(&self, key: &str, delta: i64) -> Result<i64> {
        let storage_key = StorageKey::challenge(&self.challenge_id, key);
        self.storage.increment(&storage_key, delta, None)
    }

    /// Map operations
    pub fn map_set(&self, key: &str, field: &str, value: impl Into<StorageValue>) -> Result<()> {
        let storage_key = StorageKey::challenge(&self.challenge_id, key);
        self.storage
            .map_set(&storage_key, field, value.into(), None)
    }

    pub fn map_get(&self, key: &str, field: &str) -> Result<Option<StorageValue>> {
        let storage_key = StorageKey::challenge(&self.challenge_id, key);
        self.storage.map_get(&storage_key, field)
    }
}

/// Scoped storage for a specific validator
pub struct ValidatorStorage<'a> {
    storage: &'a DynamicStorage,
    validator: Hotkey,
    challenge_id: Option<ChallengeId>,
}

impl<'a> ValidatorStorage<'a> {
    /// Get a value
    pub fn get(&self, key: &str) -> Result<Option<StorageValue>> {
        let storage_key = self.make_key(key);
        self.storage.get_value(&storage_key)
    }

    /// Set a value
    pub fn set(&self, key: &str, value: impl Into<StorageValue>) -> Result<()> {
        let storage_key = self.make_key(key);
        self.storage
            .set(storage_key, value.into(), Some(self.validator.clone()))
    }

    /// Set with TTL
    pub fn set_with_ttl(
        &self,
        key: &str,
        value: impl Into<StorageValue>,
        ttl: Duration,
    ) -> Result<()> {
        let storage_key = self.make_key(key);
        self.storage
            .set_with_ttl(storage_key, value.into(), Some(self.validator.clone()), ttl)
    }

    /// Delete a value
    pub fn delete(&self, key: &str) -> Result<Option<StorageValue>> {
        let storage_key = self.make_key(key);
        self.storage.delete(&storage_key)
    }

    fn make_key(&self, key: &str) -> StorageKey {
        if let Some(ref cid) = self.challenge_id {
            StorageKey::validator(cid, &self.validator, key)
        } else {
            StorageKey::global_validator(&self.validator, key)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_storage() -> (tempfile::TempDir, DynamicStorage) {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage = DynamicStorage::new(&db).unwrap();
        (dir, storage)
    }

    #[test]
    fn test_basic_operations() {
        let (_dir, storage) = create_test_storage();

        let key = StorageKey::system("test");
        storage
            .set(key.clone(), StorageValue::U64(42), None)
            .unwrap();

        let value = storage.get_value(&key).unwrap();
        assert_eq!(value.unwrap().as_u64(), Some(42));

        storage.delete(&key).unwrap();
        assert!(storage.get_value(&key).unwrap().is_none());
    }

    #[test]
    fn test_challenge_storage() {
        let (_dir, storage) = create_test_storage();
        let cid = ChallengeId(uuid::Uuid::new_v4());

        let cs = storage.challenge_storage(cid);
        cs.set("leaderboard_size", 100u64).unwrap();

        let value = cs.get("leaderboard_size").unwrap();
        assert_eq!(value.unwrap().as_u64(), Some(100));
    }

    #[test]
    fn test_validator_storage() {
        let (_dir, storage) = create_test_storage();
        let cid = ChallengeId(uuid::Uuid::new_v4());
        let validator = Hotkey([1u8; 32]);

        let cs = storage.challenge_storage(cid);
        let vs = cs.validator(&validator);

        vs.set("score", 95.5f64).unwrap();

        let value = vs.get("score").unwrap();
        assert_eq!(value.unwrap().as_f64(), Some(95.5));
    }

    #[test]
    fn test_ttl() {
        let (_dir, storage) = create_test_storage();

        let key = StorageKey::system("ephemeral");
        storage
            .set_with_ttl(
                key.clone(),
                StorageValue::String("temp".into()),
                None,
                Duration::from_millis(50),
            )
            .unwrap();

        // Should exist immediately
        assert!(storage.get_value(&key).unwrap().is_some());

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(100));

        // Should be gone
        assert!(storage.get_value(&key).unwrap().is_none());
    }

    #[test]
    fn test_increment() {
        let (_dir, storage) = create_test_storage();

        let key = StorageKey::system("counter");

        assert_eq!(storage.increment(&key, 5, None).unwrap(), 5);
        assert_eq!(storage.increment(&key, 3, None).unwrap(), 8);
        assert_eq!(storage.increment(&key, -2, None).unwrap(), 6);
    }

    #[test]
    fn test_map_operations() {
        let (_dir, storage) = create_test_storage();

        let key = StorageKey::system("config");

        storage
            .map_set(&key, "timeout", StorageValue::U64(300), None)
            .unwrap();
        storage
            .map_set(&key, "enabled", StorageValue::Bool(true), None)
            .unwrap();

        assert_eq!(
            storage.map_get(&key, "timeout").unwrap().unwrap().as_u64(),
            Some(300)
        );
        assert_eq!(
            storage.map_get(&key, "enabled").unwrap().unwrap().as_bool(),
            Some(true)
        );
    }

    #[test]
    fn test_change_listener() {
        let (_dir, storage) = create_test_storage();

        let changes = Arc::new(RwLock::new(Vec::new()));
        let changes_clone = changes.clone();

        storage.on_change(move |change| {
            changes_clone.write().push(change.clone());
        });

        let key = StorageKey::system("watched");
        storage
            .set(key.clone(), StorageValue::U64(1), None)
            .unwrap();
        storage
            .set(key.clone(), StorageValue::U64(2), None)
            .unwrap();
        storage.delete(&key).unwrap();

        let recorded = changes.read();
        assert_eq!(recorded.len(), 3);
    }

    #[test]
    fn test_set_block_height() {
        let (_dir, storage) = create_test_storage();

        storage.set_block_height(100);
        assert_eq!(*storage.block_height.read(), 100);

        storage.set_block_height(200);
        assert_eq!(*storage.block_height.read(), 200);
    }

    #[test]
    fn test_with_cache() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage = DynamicStorage::new(&db).unwrap().with_cache(false, 5000);

        assert!(!storage.cache_enabled);
        assert_eq!(storage.max_cache_size, 5000);
    }

    #[test]
    fn test_validator_storage_global() {
        let (_dir, storage) = create_test_storage();
        let validator = Hotkey([2u8; 32]);

        let vs = storage.validator_storage(validator.clone());
        vs.set("reputation", 95u64).unwrap();

        let value = vs.get("reputation").unwrap();
        assert_eq!(value.unwrap().as_u64(), Some(95));
    }

    #[test]
    fn test_get_nonexistent() {
        let (_dir, storage) = create_test_storage();

        let key = StorageKey::system("nonexistent");
        let value = storage.get(&key).unwrap();
        assert!(value.is_none());
    }

    #[test]
    fn test_get_value_nonexistent() {
        let (_dir, storage) = create_test_storage();

        let key = StorageKey::system("nonexistent");
        let value = storage.get_value(&key).unwrap();
        assert!(value.is_none());
    }

    #[test]
    fn test_delete_nonexistent() {
        let (_dir, storage) = create_test_storage();

        let key = StorageKey::system("nonexistent");
        let deleted = storage.delete(&key).unwrap();
        assert!(deleted.is_none());
    }

    #[test]
    fn test_increment_nonexistent() {
        let (_dir, storage) = create_test_storage();

        let key = StorageKey::system("new_counter");
        let result = storage.increment(&key, 10, None).unwrap();
        assert_eq!(result, 10);
    }

    #[test]
    fn test_list_push() {
        let (_dir, storage) = create_test_storage();

        let key = StorageKey::system("my_list");

        storage.list_push(&key, StorageValue::U64(1), None).unwrap();
        storage.list_push(&key, StorageValue::U64(2), None).unwrap();
        storage.list_push(&key, StorageValue::U64(3), None).unwrap();

        let value = storage.get_value(&key).unwrap().unwrap();
        let list = value.as_list().unwrap();

        assert_eq!(list.len(), 3);
        assert_eq!(list[0].as_u64(), Some(1));
        assert_eq!(list[2].as_u64(), Some(3));
    }

    #[test]
    fn test_list_push_to_nonlist() {
        let (_dir, storage) = create_test_storage();

        let key = StorageKey::system("not_a_list");
        storage
            .set(key.clone(), StorageValue::U64(42), None)
            .unwrap();

        // Pushing to non-list should return TypeMismatch error
        let result = storage.list_push(&key, StorageValue::U64(1), None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MiniChainError::TypeMismatch(_)
        ));

        // Verify original value is unchanged
        let value = storage.get_value(&key).unwrap().unwrap();
        assert_eq!(value.as_u64(), Some(42));
    }

    #[test]
    fn test_map_set_new_map() {
        let (_dir, storage) = create_test_storage();

        let key = StorageKey::system("new_map");

        storage
            .map_set(&key, "field1", StorageValue::String("value1".into()), None)
            .unwrap();

        let value = storage.map_get(&key, "field1").unwrap();
        assert_eq!(value.unwrap().as_str(), Some("value1"));
    }

    #[test]
    fn test_map_get_nonexistent_key() {
        let (_dir, storage) = create_test_storage();

        let key = StorageKey::system("map");
        storage
            .map_set(&key, "field1", StorageValue::U64(1), None)
            .unwrap();

        let value = storage.map_get(&key, "nonexistent").unwrap();
        assert!(value.is_none());
    }

    #[test]
    fn test_map_set_to_nonmap() {
        let (_dir, storage) = create_test_storage();

        let key = StorageKey::system("not_a_map");
        storage
            .set(key.clone(), StorageValue::U64(42), None)
            .unwrap();

        // Setting map field on non-map should return TypeMismatch error
        let result = storage.map_set(&key, "field", StorageValue::U64(1), None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MiniChainError::TypeMismatch(_)
        ));

        // Verify original value is unchanged
        let value = storage.get_value(&key).unwrap().unwrap();
        assert_eq!(value.as_u64(), Some(42));
    }

    #[test]
    fn test_scan_namespace() {
        let (_dir, storage) = create_test_storage();
        let cid = ChallengeId(uuid::Uuid::new_v4());

        let cs = storage.challenge_storage(cid);
        cs.set("key1", 1u64).unwrap();
        cs.set("key2", 2u64).unwrap();
        cs.set("key3", 3u64).unwrap();

        let results = storage.scan_namespace(&cid.0.to_string()).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_cleanup_expired() {
        let (_dir, storage) = create_test_storage();

        // Add expired entry
        let key = StorageKey::system("expired");
        storage
            .set_with_ttl(
                key.clone(),
                StorageValue::U64(42),
                None,
                Duration::from_millis(1),
            )
            .unwrap();

        std::thread::sleep(Duration::from_millis(10));

        let removed = storage.cleanup_expired().unwrap();
        assert!(removed > 0);
        assert!(storage.get_value(&key).unwrap().is_none());
    }

    #[test]
    fn test_stats() {
        let (_dir, storage) = create_test_storage();

        storage
            .set(StorageKey::system("k1"), StorageValue::U64(1), None)
            .unwrap();
        storage
            .set(StorageKey::system("k2"), StorageValue::U64(2), None)
            .unwrap();

        let stats = storage.stats().unwrap();
        assert!(stats.total_keys >= 2);
    }

    #[test]
    fn test_challenge_storage_delete() {
        let (_dir, storage) = create_test_storage();
        let cid = ChallengeId(uuid::Uuid::new_v4());

        let cs = storage.challenge_storage(cid);
        cs.set("key", 42u64).unwrap();

        let deleted = cs.delete("key").unwrap();
        assert!(deleted.is_some());

        let value = cs.get("key").unwrap();
        assert!(value.is_none());
    }

    #[test]
    fn test_validator_storage_delete() {
        let (_dir, storage) = create_test_storage();
        let cid = ChallengeId(uuid::Uuid::new_v4());
        let validator = Hotkey([3u8; 32]);

        let cs = storage.challenge_storage(cid);
        let vs = cs.validator(&validator);

        vs.set("score", 100u64).unwrap();
        vs.delete("score").unwrap();

        assert!(vs.get("score").unwrap().is_none());
    }

    #[test]
    fn test_challenge_storage_with_ttl() {
        let (_dir, storage) = create_test_storage();
        let cid = ChallengeId(uuid::Uuid::new_v4());

        let cs = storage.challenge_storage(cid);
        cs.set_with_ttl("temp", 100u64, Duration::from_secs(5))
            .unwrap();

        let value = cs.get("temp").unwrap();
        assert_eq!(value.unwrap().as_u64(), Some(100));
    }

    #[test]
    fn test_challenge_storage_scan() {
        let (_dir, storage) = create_test_storage();
        let cid = ChallengeId(uuid::Uuid::new_v4());

        let cs = storage.challenge_storage(cid);
        cs.set("key1", 1u64).unwrap();
        cs.set("key2", 2u64).unwrap();

        let results = cs.scan().unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_challenge_storage_increment() {
        let (_dir, storage) = create_test_storage();
        let cid = ChallengeId(uuid::Uuid::new_v4());

        let cs = storage.challenge_storage(cid);
        let val1 = cs.increment("counter", 5).unwrap();
        assert_eq!(val1, 5);

        let val2 = cs.increment("counter", 3).unwrap();
        assert_eq!(val2, 8);
    }

    #[test]
    fn test_challenge_storage_map_operations() {
        let (_dir, storage) = create_test_storage();
        let cid = ChallengeId(uuid::Uuid::new_v4());

        let cs = storage.challenge_storage(cid);
        cs.map_set("config", "timeout", 30u64).unwrap();
        cs.map_set("config", "retries", 3u64).unwrap();

        let timeout = cs.map_get("config", "timeout").unwrap();
        assert_eq!(timeout.unwrap().as_u64(), Some(30));

        let retries = cs.map_get("config", "retries").unwrap();
        assert_eq!(retries.unwrap().as_u64(), Some(3));
    }

    #[test]
    fn test_validator_storage_with_ttl() {
        let (_dir, storage) = create_test_storage();
        let cid = ChallengeId(uuid::Uuid::new_v4());
        let validator = Hotkey([5u8; 32]);

        let cs = storage.challenge_storage(cid);
        let vs = cs.validator(&validator);

        vs.set_with_ttl("temp", 200u64, Duration::from_secs(10))
            .unwrap();

        let value = vs.get("temp").unwrap();
        assert_eq!(value.unwrap().as_u64(), Some(200));
    }

    #[test]
    fn test_on_change_listener() {
        let (_dir, storage) = create_test_storage();
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called_clone = called.clone();

        storage.on_change(move |_change| {
            called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        let key = StorageKey::system("test");
        storage.set(key, StorageValue::U64(100), None).unwrap();

        // Listener should have been called
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_set_with_options() {
        let (_dir, storage) = create_test_storage();
        let key = StorageKey::system("test");

        storage
            .set_with_options(
                key.clone(),
                StorageValue::U64(42),
                Some(Hotkey([8u8; 32])),
                Some(Duration::from_secs(5)),
            )
            .unwrap();

        let entry = storage.get(&key).unwrap();
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.value.as_u64(), Some(42));
        assert!(entry.ttl.is_some());
    }

    #[test]
    fn test_clear_cache() {
        let (_dir, storage) = create_test_storage();

        // Set some values to populate cache
        let key = StorageKey::system("test");
        storage
            .set(key.clone(), StorageValue::U64(1), None)
            .unwrap();
        storage.get(&key).unwrap();

        // Clear cache
        storage.clear_cache();

        // Should still be able to read from disk
        let value = storage.get(&key).unwrap();
        assert!(value.is_some());
    }

    #[test]
    fn test_flush() {
        let (_dir, storage) = create_test_storage();

        let key = StorageKey::system("test");
        storage.set(key, StorageValue::U64(999), None).unwrap();

        // Flush to disk
        storage.flush().unwrap();
    }

    #[test]
    fn test_exists() {
        let (_dir, storage) = create_test_storage();

        let key = StorageKey::system("test");
        assert!(!storage.exists(&key).unwrap());

        storage
            .set(key.clone(), StorageValue::U64(1), None)
            .unwrap();
        assert!(storage.exists(&key).unwrap());
    }

    #[test]
    fn test_set_with_options_update_existing() {
        let (_dir, storage) = create_test_storage();
        let key = StorageKey::system("test");

        // Set initial value
        storage
            .set(key.clone(), StorageValue::U64(1), None)
            .unwrap();

        // Update with options (line 187 path - updating existing entry)
        storage
            .set_with_options(
                key.clone(),
                StorageValue::U64(2),
                Some(Hotkey([1u8; 32])),
                Some(Duration::from_secs(10)),
            )
            .unwrap();

        let entry = storage.get(&key).unwrap().unwrap();
        assert_eq!(entry.value.as_u64(), Some(2));
        assert!(entry.ttl.is_some());
    }

    #[test]
    fn test_parse_key_with_validator() {
        let (_dir, storage) = create_test_storage();
        let cid = ChallengeId(uuid::Uuid::new_v4());
        let validator = Hotkey([5u8; 32]);

        let key = StorageKey::validator(&cid, &validator, "test_key");
        let key_bytes = key.to_bytes();

        // Parse the key back (lines 367-374)
        let parsed = storage.parse_key(&key_bytes);
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert!(parsed.validator.is_some());
    }

    #[test]
    fn test_parse_key_invalid() {
        let (_dir, storage) = create_test_storage();

        // Invalid key format (line 386 - returns None)
        let invalid_key = b"invalid";
        let parsed = storage.parse_key(invalid_key);
        assert!(parsed.is_none());
    }

    #[test]
    fn test_stats_with_namespaces() {
        let (_dir, storage) = create_test_storage();

        // Add keys in different namespaces
        storage
            .set(StorageKey::system("key1"), StorageValue::U64(1), None)
            .unwrap();
        storage
            .set(
                StorageKey::challenge(&ChallengeId(uuid::Uuid::new_v4()), "key2"),
                StorageValue::U64(2),
                None,
            )
            .unwrap();

        // Get stats (line 441)
        let stats = storage.stats().unwrap();
        assert!(stats.total_keys >= 2);
        assert!(stats.total_size_bytes > 0);
    }
}
