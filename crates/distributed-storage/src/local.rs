//! Local sled-based storage with replication markers
//!
//! This module provides a local storage implementation using sled as the backend.
//! It stores data with replication metadata to track which remote nodes have copies.

use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sled::{Db, Tree};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, trace};

use crate::error::{StorageError, StorageResult};
use crate::store::{
    DistributedStore, GetOptions, ListResult, PutOptions, StorageKey, StorageStats, StoredValue,
    ValueMetadata,
};

/// Replication metadata for tracking which nodes have copies of data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplicationInfo {
    /// Set of node IDs that have confirmed receipt of this value
    pub replicated_to: HashSet<String>,
    /// When the last replication attempt occurred
    pub last_replication_at: i64,
    /// Number of replication attempts
    pub replication_attempts: u32,
    /// Whether this value needs replication
    pub needs_replication: bool,
}

impl Default for ReplicationInfo {
    fn default() -> Self {
        Self {
            replicated_to: HashSet::new(),
            last_replication_at: 0,
            replication_attempts: 0,
            needs_replication: true,
        }
    }
}

impl ReplicationInfo {
    /// Mark that a node has received this value
    pub fn mark_replicated(&mut self, node_id: &str) {
        self.replicated_to.insert(node_id.to_string());
        self.last_replication_at = chrono::Utc::now().timestamp_millis();
    }

    /// Check if value is replicated to enough nodes
    pub fn meets_replication_factor(&self, factor: usize) -> bool {
        self.replicated_to.len() >= factor
    }
}

/// Entry stored in the local database
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LocalEntry {
    /// The stored value
    value: StoredValue,
    /// Replication tracking info
    replication: ReplicationInfo,
}

/// Local storage implementation using sled
pub struct LocalStorage {
    /// The underlying sled database (wrapped in Arc for spawn_blocking)
    db: Arc<Db>,
    /// Tree for storing key-value data
    data_tree: Tree,
    /// Tree for storing namespace indexes
    index_tree: Tree,
    /// Our node ID for tracking origin
    node_id: String,
    /// Cache for namespace entry counts
    namespace_counts: RwLock<HashMap<String, u64>>,
}

impl LocalStorage {
    /// Open or create a local storage at the given path
    pub fn open<P: AsRef<Path>>(path: P, node_id: String) -> StorageResult<Self> {
        let db = sled::open(path)?;
        let data_tree = db.open_tree("data")?;
        let index_tree = db.open_tree("index")?;

        let storage = Self {
            db: Arc::new(db),
            data_tree,
            index_tree,
            node_id,
            namespace_counts: RwLock::new(HashMap::new()),
        };

        // Initialize namespace counts
        storage.rebuild_namespace_counts()?;

        Ok(storage)
    }

    /// Create an in-memory local storage (for testing)
    pub fn in_memory(node_id: String) -> StorageResult<Self> {
        let db = sled::Config::new().temporary(true).open()?;
        let data_tree = db.open_tree("data")?;
        let index_tree = db.open_tree("index")?;

        Ok(Self {
            db: Arc::new(db),
            data_tree,
            index_tree,
            node_id,
            namespace_counts: RwLock::new(HashMap::new()),
        })
    }

    /// Get the node ID
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Rebuild namespace counts from the index
    fn rebuild_namespace_counts(&self) -> StorageResult<()> {
        let mut counts = HashMap::new();

        for result in self.index_tree.iter() {
            let (key, _) = result?;
            if let Ok(key_str) = std::str::from_utf8(&key) {
                if let Some(ns) = key_str.split(':').next() {
                    *counts.entry(ns.to_string()).or_insert(0) += 1;
                }
            }
        }

        *self.namespace_counts.write() = counts;
        Ok(())
    }

    /// Convert a StorageKey to a database key
    fn db_key(key: &StorageKey) -> Vec<u8> {
        key.to_bytes()
    }

    /// Get a raw entry from the database
    fn get_entry(&self, key: &StorageKey) -> StorageResult<Option<LocalEntry>> {
        let db_key = Self::db_key(key);

        match self.data_tree.get(&db_key)? {
            Some(bytes) => {
                let entry: LocalEntry = bincode::deserialize(&bytes)?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Put a raw entry to the database
    fn put_entry(&self, key: &StorageKey, entry: &LocalEntry) -> StorageResult<()> {
        let db_key = Self::db_key(key);
        let bytes = bincode::serialize(entry)?;

        self.data_tree.insert(&db_key, bytes)?;

        // Update index
        let index_key = format!("{}:{}", key.namespace, hex::encode(&key.key));
        self.index_tree
            .insert(index_key.as_bytes(), db_key.as_slice())?;

        // Update namespace count
        {
            let mut counts = self.namespace_counts.write();
            *counts.entry(key.namespace.clone()).or_insert(0) += 1;
        }

        Ok(())
    }

    /// Delete an entry from the database
    fn delete_entry(&self, key: &StorageKey) -> StorageResult<bool> {
        let db_key = Self::db_key(key);

        let existed = self.data_tree.remove(&db_key)?.is_some();

        if existed {
            // Update index
            let index_key = format!("{}:{}", key.namespace, hex::encode(&key.key));
            self.index_tree.remove(index_key.as_bytes())?;

            // Update namespace count
            {
                let mut counts = self.namespace_counts.write();
                if let Some(count) = counts.get_mut(&key.namespace) {
                    *count = count.saturating_sub(1);
                }
            }
        }

        Ok(existed)
    }

    /// Mark that this value has been replicated to a node
    pub async fn mark_replicated(&self, key: &StorageKey, node_id: &str) -> StorageResult<()> {
        if let Some(mut entry) = self.get_entry(key)? {
            entry.replication.mark_replicated(node_id);
            self.put_entry(key, &entry)?;
            self.flush_async().await?;
        }
        Ok(())
    }

    /// Get all keys that need replication
    pub fn keys_needing_replication(&self, limit: usize) -> StorageResult<Vec<StorageKey>> {
        let mut keys = Vec::new();

        for result in self.data_tree.iter() {
            let (key_bytes, value_bytes) = result?;

            let entry: LocalEntry = bincode::deserialize(&value_bytes)?;

            if entry.replication.needs_replication {
                // Parse the key back into a StorageKey
                if let Ok(key_str) = std::str::from_utf8(&key_bytes) {
                    if let Some((namespace, rest)) = key_str.split_once(':') {
                        keys.push(StorageKey::new(namespace, rest));

                        if keys.len() >= limit {
                            break;
                        }
                    }
                }
            }
        }

        Ok(keys)
    }

    /// Get replication info for a key
    pub fn get_replication_info(&self, key: &StorageKey) -> StorageResult<Option<ReplicationInfo>> {
        Ok(self.get_entry(key)?.map(|e| e.replication))
    }

    /// Flush all changes to disk synchronously (blocking)
    pub fn flush(&self) -> StorageResult<()> {
        self.db.flush()?;
        Ok(())
    }

    /// Flush all changes to disk asynchronously using spawn_blocking
    pub async fn flush_async(&self) -> StorageResult<()> {
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || db.flush())
            .await
            .map_err(|e| StorageError::Database(format!("flush task panicked: {}", e)))?
            .map_err(StorageError::from)?;
        Ok(())
    }

    /// Get the underlying database (for advanced operations)
    pub fn db(&self) -> &Db {
        &self.db
    }
}

#[async_trait]
impl DistributedStore for LocalStorage {
    async fn get(
        &self,
        key: &StorageKey,
        _options: GetOptions,
    ) -> StorageResult<Option<StoredValue>> {
        trace!("LocalStorage::get key={}", key);

        match self.get_entry(key)? {
            Some(entry) => {
                // Check if expired
                if entry.value.metadata.is_expired() {
                    debug!("Key {} has expired, deleting", key);
                    self.delete_entry(key)?;
                    return Ok(None);
                }
                Ok(Some(entry.value))
            }
            None => Ok(None),
        }
    }

    async fn put(
        &self,
        key: StorageKey,
        value: Vec<u8>,
        options: PutOptions,
    ) -> StorageResult<ValueMetadata> {
        trace!("LocalStorage::put key={} size={}", key, value.len());

        // Check for optimistic concurrency
        let existing = self.get_entry(&key)?;

        if let Some(expected_version) = options.expected_version {
            if let Some(ref existing_entry) = existing {
                if existing_entry.value.metadata.version != expected_version {
                    return Err(StorageError::Conflict(format!(
                        "Version mismatch: expected {}, found {}",
                        expected_version, existing_entry.value.metadata.version
                    )));
                }
            } else if expected_version != 0 {
                return Err(StorageError::Conflict(format!(
                    "Key does not exist but expected version {}",
                    expected_version
                )));
            }
        }

        // Create the stored value
        let mut stored_value = match existing {
            Some(existing_entry) => {
                let new_metadata = existing_entry
                    .value
                    .metadata
                    .update(&value, Some(self.node_id.clone()));
                StoredValue {
                    data: value,
                    metadata: new_metadata,
                }
            }
            None => StoredValue::new(value, Some(self.node_id.clone())),
        };

        // Apply TTL if specified
        if options.ttl_seconds > 0 {
            stored_value.metadata.ttl_seconds = options.ttl_seconds;
        }

        // Create entry with replication info
        let entry = LocalEntry {
            value: stored_value.clone(),
            replication: ReplicationInfo {
                needs_replication: !options.local_only,
                ..Default::default()
            },
        };

        self.put_entry(&key, &entry)?;
        self.flush_async().await?;

        debug!(
            "LocalStorage::put completed key={} version={}",
            key, stored_value.metadata.version
        );

        Ok(stored_value.metadata)
    }

    async fn delete(&self, key: &StorageKey) -> StorageResult<bool> {
        trace!("LocalStorage::delete key={}", key);
        let deleted = self.delete_entry(key)?;
        self.flush_async().await?;
        Ok(deleted)
    }

    async fn exists(&self, key: &StorageKey) -> StorageResult<bool> {
        let db_key = Self::db_key(key);
        Ok(self.data_tree.contains_key(&db_key)?)
    }

    async fn list_prefix(
        &self,
        namespace: &str,
        prefix: Option<&[u8]>,
        limit: usize,
        continuation_token: Option<&[u8]>,
    ) -> StorageResult<ListResult> {
        trace!(
            "LocalStorage::list_prefix namespace={} prefix={:?}",
            namespace,
            prefix
        );

        let mut items = Vec::new();
        let mut last_key: Option<Vec<u8>> = None;

        // Build the scan prefix
        let scan_prefix = match prefix {
            Some(p) => format!("{}:{}", namespace, hex::encode(p)),
            None => format!("{}:", namespace),
        };

        // Determine where to start scanning
        let start = match continuation_token {
            Some(token) => token.to_vec(),
            None => scan_prefix.as_bytes().to_vec(),
        };

        for result in self.index_tree.range(start..) {
            let (index_key, data_key) = result?;

            // Check if we're still in the right namespace
            if !index_key.starts_with(scan_prefix.as_bytes()) {
                break;
            }

            // Get the actual data
            if let Some(value_bytes) = self.data_tree.get(&data_key)? {
                let entry: LocalEntry = bincode::deserialize(&value_bytes)?;

                // Skip expired entries
                if entry.value.metadata.is_expired() {
                    continue;
                }

                // Parse the key
                if let Ok(key_str) = std::str::from_utf8(&data_key) {
                    if let Some((ns, rest)) = key_str.split_once(':') {
                        let key = StorageKey::new(ns, rest);
                        items.push((key, entry.value));
                        last_key = Some(index_key.to_vec());

                        if items.len() >= limit {
                            break;
                        }
                    }
                }
            }
        }

        let has_more = items.len() >= limit;
        let continuation_token = if has_more {
            last_key.map(|mut k| {
                // Increment the last byte to get the next key
                if let Some(last) = k.last_mut() {
                    *last = last.saturating_add(1);
                }
                k
            })
        } else {
            None
        };

        Ok(ListResult {
            items,
            has_more,
            continuation_token,
        })
    }

    async fn stats(&self) -> StorageResult<StorageStats> {
        let counts = self.namespace_counts.read().clone();

        let total_keys: u64 = counts.values().sum();

        // Calculate total bytes
        let mut total_bytes: u64 = 0;
        for result in self.data_tree.iter() {
            let (_, value) = result?;
            total_bytes += value.len() as u64;
        }

        Ok(StorageStats {
            total_keys,
            total_bytes,
            keys_per_namespace: counts,
            local_replicas: total_keys,
            remote_peers: 0, // Local storage doesn't know about remote peers
        })
    }
}

/// Builder for LocalStorage with configuration options
pub struct LocalStorageBuilder {
    path: Option<String>,
    node_id: String,
    in_memory: bool,
}

impl LocalStorageBuilder {
    /// Create a new builder
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            path: None,
            node_id: node_id.into(),
            in_memory: false,
        }
    }

    /// Set the storage path
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self.in_memory = false;
        self
    }

    /// Use in-memory storage
    pub fn in_memory(mut self) -> Self {
        self.in_memory = true;
        self.path = None;
        self
    }

    /// Build the storage
    pub fn build(self) -> StorageResult<LocalStorage> {
        if self.in_memory {
            LocalStorage::in_memory(self.node_id)
        } else if let Some(path) = self.path {
            LocalStorage::open(path, self.node_id)
        } else {
            Err(StorageError::InvalidData(
                "Must specify either path or in_memory".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_storage() -> LocalStorage {
        LocalStorage::in_memory("test-node".to_string()).expect("Failed to create storage")
    }

    #[tokio::test]
    async fn test_put_and_get() {
        let storage = create_test_storage();

        let key = StorageKey::new("test", "key1");
        let value = b"hello world".to_vec();

        let metadata = storage
            .put(key.clone(), value.clone(), PutOptions::default())
            .await
            .expect("put failed");

        assert_eq!(metadata.version, 1);
        assert_eq!(metadata.size, value.len());

        let result = storage
            .get(&key, GetOptions::default())
            .await
            .expect("get failed");

        assert!(result.is_some());
        let stored = result.unwrap();
        assert_eq!(stored.data, value);
    }

    #[tokio::test]
    async fn test_update_increments_version() {
        let storage = create_test_storage();

        let key = StorageKey::new("test", "key1");

        storage
            .put(key.clone(), b"v1".to_vec(), PutOptions::default())
            .await
            .expect("put 1 failed");

        let metadata = storage
            .put(key.clone(), b"v2".to_vec(), PutOptions::default())
            .await
            .expect("put 2 failed");

        assert_eq!(metadata.version, 2);
    }

    #[tokio::test]
    async fn test_optimistic_concurrency() {
        let storage = create_test_storage();

        let key = StorageKey::new("test", "key1");

        storage
            .put(key.clone(), b"v1".to_vec(), PutOptions::default())
            .await
            .expect("put 1 failed");

        // Should succeed with correct version
        let mut options = PutOptions::default();
        options.expected_version = Some(1);

        let result = storage.put(key.clone(), b"v2".to_vec(), options).await;
        assert!(result.is_ok());

        // Should fail with wrong version
        let mut options = PutOptions::default();
        options.expected_version = Some(1); // Still expecting 1, but it's now 2

        let result = storage.put(key.clone(), b"v3".to_vec(), options).await;
        assert!(matches!(result, Err(StorageError::Conflict(_))));
    }

    #[tokio::test]
    async fn test_delete() {
        let storage = create_test_storage();

        let key = StorageKey::new("test", "key1");

        storage
            .put(key.clone(), b"value".to_vec(), PutOptions::default())
            .await
            .expect("put failed");

        assert!(storage.delete(&key).await.expect("delete failed"));

        let result = storage
            .get(&key, GetOptions::default())
            .await
            .expect("get failed");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_exists() {
        let storage = create_test_storage();

        let key = StorageKey::new("test", "key1");

        assert!(!storage.exists(&key).await.expect("exists check failed"));

        storage
            .put(key.clone(), b"value".to_vec(), PutOptions::default())
            .await
            .expect("put failed");

        assert!(storage.exists(&key).await.expect("exists check failed"));
    }

    #[tokio::test]
    async fn test_list_prefix() {
        let storage = create_test_storage();

        // Add some keys
        for i in 0..5 {
            let key = StorageKey::new("test", format!("key{}", i));
            storage
                .put(
                    key,
                    format!("value{}", i).into_bytes(),
                    PutOptions::default(),
                )
                .await
                .expect("put failed");
        }

        // Also add a key in a different namespace
        storage
            .put(
                StorageKey::new("other", "key"),
                b"other".to_vec(),
                PutOptions::default(),
            )
            .await
            .expect("put failed");

        let result = storage
            .list_prefix("test", None, 10, None)
            .await
            .expect("list failed");

        assert_eq!(result.items.len(), 5);
        assert!(!result.has_more);
    }

    #[tokio::test]
    async fn test_list_prefix_pagination() {
        let storage = create_test_storage();

        // Add 10 keys
        for i in 0..10 {
            let key = StorageKey::new("test", format!("key{:02}", i));
            storage
                .put(
                    key,
                    format!("value{}", i).into_bytes(),
                    PutOptions::default(),
                )
                .await
                .expect("put failed");
        }

        // Get first page
        let result1 = storage
            .list_prefix("test", None, 5, None)
            .await
            .expect("list failed");

        assert_eq!(result1.items.len(), 5);
        assert!(result1.has_more);
        assert!(result1.continuation_token.is_some());

        // Get second page
        let result2 = storage
            .list_prefix("test", None, 5, result1.continuation_token.as_deref())
            .await
            .expect("list failed");

        assert_eq!(result2.items.len(), 5);
    }

    #[tokio::test]
    async fn test_stats() {
        let storage = create_test_storage();

        storage
            .put(
                StorageKey::new("ns1", "key1"),
                b"value1".to_vec(),
                PutOptions::default(),
            )
            .await
            .expect("put failed");

        storage
            .put(
                StorageKey::new("ns1", "key2"),
                b"value2".to_vec(),
                PutOptions::default(),
            )
            .await
            .expect("put failed");

        storage
            .put(
                StorageKey::new("ns2", "key1"),
                b"value3".to_vec(),
                PutOptions::default(),
            )
            .await
            .expect("put failed");

        let stats = storage.stats().await.expect("stats failed");

        assert_eq!(stats.total_keys, 3);
        assert_eq!(stats.keys_per_namespace.get("ns1"), Some(&2));
        assert_eq!(stats.keys_per_namespace.get("ns2"), Some(&1));
    }

    #[tokio::test]
    async fn test_replication_tracking() {
        let storage = create_test_storage();

        let key = StorageKey::new("test", "key1");

        storage
            .put(key.clone(), b"value".to_vec(), PutOptions::default())
            .await
            .expect("put failed");

        // Check initial replication info
        let info = storage
            .get_replication_info(&key)
            .expect("get replication info failed")
            .expect("should have replication info");

        assert!(info.needs_replication);
        assert!(info.replicated_to.is_empty());

        // Mark as replicated
        storage
            .mark_replicated(&key, "node2")
            .await
            .expect("mark replicated failed");

        let info = storage
            .get_replication_info(&key)
            .expect("get replication info failed")
            .expect("should have replication info");

        assert!(info.replicated_to.contains("node2"));
    }

    #[test]
    fn test_builder_in_memory() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("build failed");

        assert_eq!(storage.node_id(), "test-node");
    }

    #[test]
    fn test_builder_requires_path_or_in_memory() {
        let result = LocalStorageBuilder::new("test-node").build();
        assert!(matches!(result, Err(StorageError::InvalidData(_))));
    }
}
