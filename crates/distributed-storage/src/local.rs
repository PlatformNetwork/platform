//! Local sled-based storage with replication markers
//!
//! This module provides a local storage implementation using sled as the backend.
//! It stores data with replication metadata to track which remote nodes have copies.

use async_trait::async_trait;
use bincode::Options;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sled::{Db, Tree};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, trace};

/// Maximum size for deserializing storage entries (100MB).
/// This limit prevents DoS attacks from malformed data causing excessive memory allocation.
const MAX_ENTRY_SIZE: u64 = 100 * 1024 * 1024;

use crate::error::{StorageError, StorageResult};
use crate::query::{
    block_index_key, block_range_end, block_range_start, parse_block_index_key, QueryBuilder,
    QueryCursor, QueryFilter, QueryResult,
};
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
    /// Optional block_id for block-indexed queries
    #[serde(default)]
    block_id: Option<u64>,
}

/// Local storage implementation using sled
pub struct LocalStorage {
    /// The underlying sled database (wrapped in Arc for spawn_blocking)
    db: Arc<Db>,
    /// Tree for storing key-value data
    data_tree: Tree,
    /// Tree for storing namespace indexes
    index_tree: Tree,
    /// Tree for block-based secondary index (namespace:block_id:key_hash -> primary_key)
    block_index_tree: Tree,
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
        let block_index_tree = db.open_tree("block_index")?;

        let storage = Self {
            db: Arc::new(db),
            data_tree,
            index_tree,
            block_index_tree,
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
        let block_index_tree = db.open_tree("block_index")?;

        Ok(Self {
            db: Arc::new(db),
            data_tree,
            index_tree,
            block_index_tree,
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
                // Use options compatible with bincode::serialize (legacy format with fixint encoding)
                let entry: LocalEntry = bincode::options()
                    .with_limit(MAX_ENTRY_SIZE)
                    .with_fixint_encoding()
                    .allow_trailing_bytes()
                    .deserialize(&bytes)?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Put a raw entry to the database
    fn put_entry(&self, key: &StorageKey, entry: &LocalEntry) -> StorageResult<()> {
        let db_key = Self::db_key(key);
        let bytes = bincode::serialize(entry)?;

        // Check if this is an update (entry already exists)
        let existing = self.get_entry(key)?;
        let is_new = existing.is_none();

        // Remove old block index if updating with different block_id
        if let Some(ref old_entry) = existing {
            if old_entry.block_id != entry.block_id {
                if let Some(old_block_id) = old_entry.block_id {
                    let old_block_key = block_index_key(&key.namespace, old_block_id, key);
                    self.block_index_tree.remove(&old_block_key)?;
                }
            }
        }

        self.data_tree.insert(&db_key, bytes)?;

        // Update index
        let index_key = format!("{}:{}", key.namespace, hex::encode(&key.key));
        self.index_tree
            .insert(index_key.as_bytes(), db_key.as_slice())?;

        // Update block index if block_id is present
        if let Some(block_id) = entry.block_id {
            let block_key = block_index_key(&key.namespace, block_id, key);
            self.block_index_tree
                .insert(&block_key, db_key.as_slice())?;
        }

        // Update namespace count only for new entries
        if is_new {
            let mut counts = self.namespace_counts.write();
            *counts.entry(key.namespace.clone()).or_insert(0) += 1;
        }

        Ok(())
    }

    /// Delete an entry from the database
    fn delete_entry(&self, key: &StorageKey) -> StorageResult<bool> {
        let db_key = Self::db_key(key);

        // Get the entry first to find its block_id for index cleanup
        let entry = self.get_entry(key)?;

        let existed = self.data_tree.remove(&db_key)?.is_some();

        if existed {
            // Update index
            let index_key = format!("{}:{}", key.namespace, hex::encode(&key.key));
            self.index_tree.remove(index_key.as_bytes())?;

            // Remove from block index if block_id was present
            if let Some(ref entry) = entry {
                if let Some(block_id) = entry.block_id {
                    let block_key = block_index_key(&key.namespace, block_id, key);
                    self.block_index_tree.remove(&block_key)?;
                }
            }

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

            // Use options compatible with bincode::serialize (legacy format with fixint encoding)
            let entry: LocalEntry = bincode::options()
                .with_limit(MAX_ENTRY_SIZE)
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .deserialize(&value_bytes)?;

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

    /// Get the block_id associated with an entry
    pub fn get_block_id(&self, key: &StorageKey) -> StorageResult<Option<u64>> {
        Ok(self.get_entry(key)?.and_then(|e| e.block_id))
    }

    /// Internal method to put a value with an associated block_id
    fn put_entry_with_block_internal(
        &self,
        key: &StorageKey,
        value: Vec<u8>,
        block_id: u64,
        options: &PutOptions,
    ) -> StorageResult<ValueMetadata> {
        trace!(
            "LocalStorage::put_with_block key={} block_id={} size={}",
            key,
            block_id,
            value.len()
        );

        // Check for optimistic concurrency
        let existing = self.get_entry(key)?;

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

        // Create entry with replication info and block_id
        let entry = LocalEntry {
            value: stored_value.clone(),
            replication: ReplicationInfo {
                needs_replication: !options.local_only,
                ..Default::default()
            },
            block_id: Some(block_id),
        };

        self.put_entry(key, &entry)?;

        debug!(
            "LocalStorage::put_with_block completed key={} block_id={} version={}",
            key, block_id, stored_value.metadata.version
        );

        Ok(stored_value.metadata)
    }

    /// Determine the optimal scan range based on query filters
    fn determine_scan_range_from_query(&self, query: &QueryBuilder) -> (Vec<u8>, Option<Vec<u8>>) {
        let namespace = query.namespace();
        let mut min_block: Option<u64> = None;
        let mut max_block: Option<u64> = None;

        // Extract block range constraints from filters
        for filter in query.filters() {
            match filter {
                QueryFilter::BlockBefore(block) => {
                    max_block = Some(max_block.map_or(*block, |m| m.min(*block)));
                }
                QueryFilter::BlockAfter(block) => {
                    // For "after", we want block_id > block, so start at block + 1
                    let start = block.saturating_add(1);
                    min_block = Some(min_block.map_or(start, |m| m.max(start)));
                }
                QueryFilter::BlockRange { start, end } => {
                    min_block = Some(min_block.map_or(*start, |m| m.max(*start)));
                    max_block = Some(max_block.map_or(*end + 1, |m| m.min(*end + 1)));
                }
                QueryFilter::And(filters) => {
                    for f in filters {
                        match f {
                            QueryFilter::BlockBefore(block) => {
                                max_block = Some(max_block.map_or(*block, |m| m.min(*block)));
                            }
                            QueryFilter::BlockAfter(block) => {
                                let start = block.saturating_add(1);
                                min_block = Some(min_block.map_or(start, |m| m.max(start)));
                            }
                            QueryFilter::BlockRange { start, end } => {
                                min_block = Some(min_block.map_or(*start, |m| m.max(*start)));
                                max_block = Some(max_block.map_or(*end + 1, |m| m.min(*end + 1)));
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        let start_key = block_range_start(namespace, min_block.unwrap_or(0));
        let end_key = max_block.map(|b| block_range_start(namespace, b));

        (start_key, end_key)
    }

    /// Iterate over block index in a range and collect results
    fn query_block_index_range(
        &self,
        namespace: &str,
        start_key: Vec<u8>,
        end_key: Option<Vec<u8>>,
        limit: usize,
        filter: Option<&QueryFilter>,
    ) -> StorageResult<Vec<(StorageKey, StoredValue, u64)>> {
        let mut results = Vec::new();

        let range = match end_key {
            Some(ref end) => self.block_index_tree.range(start_key..end.clone()),
            None => self.block_index_tree.range(start_key..),
        };

        for result in range {
            let (block_index_key_bytes, data_key_bytes) = result?;

            // Parse the block index key to get namespace and block_id
            let parsed = match parse_block_index_key(&block_index_key_bytes) {
                Some(p) => p,
                None => continue,
            };
            let (parsed_namespace, block_id, _key_hash) = parsed;

            // Verify namespace matches
            if parsed_namespace != namespace {
                break;
            }

            // Get the actual data
            if let Some(value_bytes) = self.data_tree.get(&data_key_bytes)? {
                // Use options compatible with bincode::serialize (legacy format with fixint encoding)
                let entry: LocalEntry = bincode::options()
                    .with_limit(MAX_ENTRY_SIZE)
                    .with_fixint_encoding()
                    .allow_trailing_bytes()
                    .deserialize(&value_bytes)?;

                // Skip expired entries
                if entry.value.metadata.is_expired() {
                    continue;
                }

                // Apply filter if present
                if let Some(f) = filter {
                    // Parse the data key to get the actual key for filtering
                    if let Ok(key_str) = std::str::from_utf8(&data_key_bytes) {
                        if let Some((_ns, rest)) = key_str.split_once(':') {
                            if !f.matches(
                                entry.block_id,
                                entry.value.metadata.created_at,
                                rest.as_bytes(),
                            ) {
                                continue;
                            }
                        }
                    }
                }

                // Parse the data key back to StorageKey
                if let Ok(key_str) = std::str::from_utf8(&data_key_bytes) {
                    if let Some((ns, rest)) = key_str.split_once(':') {
                        let storage_key = StorageKey::new(ns, rest);
                        results.push((storage_key, entry.value, block_id));

                        if results.len() >= limit {
                            break;
                        }
                    }
                }
            }
        }

        Ok(results)
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

        // Create entry with replication info (no block_id for regular put)
        let entry = LocalEntry {
            value: stored_value.clone(),
            replication: ReplicationInfo {
                needs_replication: !options.local_only,
                ..Default::default()
            },
            block_id: None,
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
                // Use options compatible with bincode::serialize (legacy format with fixint encoding)
                let entry: LocalEntry = bincode::options()
                    .with_limit(MAX_ENTRY_SIZE)
                    .with_fixint_encoding()
                    .allow_trailing_bytes()
                    .deserialize(&value_bytes)?;

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

    async fn list_before_block(
        &self,
        namespace: &str,
        block_id: u64,
        limit: usize,
    ) -> StorageResult<QueryResult> {
        trace!(
            "LocalStorage::list_before_block namespace={} block_id={} limit={}",
            namespace,
            block_id,
            limit
        );

        // Start from the beginning of the namespace, end before the target block
        let start_key = block_range_start(namespace, 0);
        let end_key = block_range_start(namespace, block_id);

        let results =
            self.query_block_index_range(namespace, start_key, Some(end_key), limit, None)?;

        let items: Vec<(StorageKey, StoredValue)> =
            results.into_iter().map(|(k, v, _)| (k, v)).collect();

        let has_more = items.len() >= limit;
        let result = QueryResult::new(items, 0, limit, has_more);

        Ok(result)
    }

    async fn list_after_block(
        &self,
        namespace: &str,
        block_id: u64,
        limit: usize,
    ) -> StorageResult<QueryResult> {
        trace!(
            "LocalStorage::list_after_block namespace={} block_id={} limit={}",
            namespace,
            block_id,
            limit
        );

        // Start from the block after block_id
        let start_key = block_range_end(namespace, block_id);

        let results = self.query_block_index_range(namespace, start_key, None, limit, None)?;

        let items: Vec<(StorageKey, StoredValue)> =
            results.into_iter().map(|(k, v, _)| (k, v)).collect();

        let has_more = items.len() >= limit;
        let result = QueryResult::new(items, 0, limit, has_more);

        Ok(result)
    }

    async fn list_range(
        &self,
        namespace: &str,
        start_block: u64,
        end_block: u64,
        limit: usize,
    ) -> StorageResult<QueryResult> {
        trace!(
            "LocalStorage::list_range namespace={} start={} end={} limit={}",
            namespace,
            start_block,
            end_block,
            limit
        );

        let start_key = block_range_start(namespace, start_block);
        let end_key = block_range_end(namespace, end_block);

        let results =
            self.query_block_index_range(namespace, start_key, Some(end_key), limit, None)?;

        let items: Vec<(StorageKey, StoredValue)> =
            results.into_iter().map(|(k, v, _)| (k, v)).collect();

        let has_more = items.len() >= limit;
        let result = QueryResult::new(items, 0, limit, has_more);

        Ok(result)
    }

    async fn count_by_namespace(&self, namespace: &str) -> StorageResult<u64> {
        let counts = self.namespace_counts.read();
        Ok(*counts.get(namespace).unwrap_or(&0))
    }

    async fn query(&self, query: QueryBuilder) -> StorageResult<QueryResult> {
        trace!(
            "LocalStorage::query namespace={} limit={}",
            query.namespace(),
            query.get_limit()
        );

        let namespace = query.namespace();
        let limit = query.get_limit();
        let filter = query.build_filter();

        // Determine scan range based on filters
        let (start_key, end_key) = self.determine_scan_range_from_query(&query);

        // Handle cursor-based pagination
        let effective_start = if let Some(cursor) = query.get_cursor() {
            if let (Some(last_block), Some(last_hash)) =
                (cursor.last_block_id, cursor.last_key_hash.as_ref())
            {
                // Create a key that's just after the cursor position
                let mut cursor_key = Vec::new();
                cursor_key.extend_from_slice(namespace.as_bytes());
                cursor_key.push(b':');
                cursor_key.extend_from_slice(&last_block.to_be_bytes());
                cursor_key.push(b':');
                cursor_key.extend_from_slice(last_hash);
                // Increment to get next item
                if let Some(last) = cursor_key.last_mut() {
                    *last = last.saturating_add(1);
                }
                cursor_key
            } else {
                start_key
            }
        } else {
            start_key
        };

        let results = self.query_block_index_range(
            namespace,
            effective_start,
            end_key,
            limit + 1, // Fetch one extra to check has_more
            filter.as_ref(),
        )?;

        let has_more = results.len() > limit;
        let results: Vec<_> = results.into_iter().take(limit).collect();

        // Build cursor for next page
        let next_cursor = if has_more && !results.is_empty() {
            let (last_key, _, last_block) = results.last().expect("results not empty");
            Some(QueryCursor::from_last_item(
                namespace,
                *last_block,
                last_key,
            ))
        } else {
            None
        };

        let items: Vec<(StorageKey, StoredValue)> =
            results.into_iter().map(|(k, v, _)| (k, v)).collect();

        let mut result = QueryResult::new(items, query.get_offset(), limit, has_more);
        if let Some(cursor) = next_cursor {
            result = result.with_cursor(cursor);
        }

        // Include count if requested
        if query.should_include_count() {
            let count = self.count_by_namespace(namespace).await?;
            result = result.with_total_count(count);
        }

        Ok(result)
    }

    async fn put_with_block(
        &self,
        key: StorageKey,
        value: Vec<u8>,
        block_id: u64,
        options: PutOptions,
    ) -> StorageResult<ValueMetadata> {
        let metadata = self.put_entry_with_block_internal(&key, value, block_id, &options)?;
        self.flush_async().await?;
        Ok(metadata)
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
        let options = PutOptions {
            expected_version: Some(1),
            ..Default::default()
        };

        let result = storage.put(key.clone(), b"v2".to_vec(), options).await;
        assert!(result.is_ok());

        // Should fail with wrong version
        let options = PutOptions {
            expected_version: Some(1),
            ..Default::default()
        }; // Still expecting 1, but it's now 2

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

    #[tokio::test]
    async fn test_put_with_block() {
        let storage = create_test_storage();

        let key = StorageKey::new("submissions", "test-hash-1");
        let value = b"submission data".to_vec();

        let metadata = storage
            .put_with_block(key.clone(), value.clone(), 100, PutOptions::default())
            .await
            .expect("put_with_block failed");

        assert_eq!(metadata.version, 1);
        assert_eq!(metadata.size, value.len());

        // Verify we can retrieve it
        let result = storage
            .get(&key, GetOptions::default())
            .await
            .expect("get failed");

        assert!(result.is_some());
        assert_eq!(result.unwrap().data, value);

        // Verify block_id is stored
        let block_id = storage.get_block_id(&key).expect("get_block_id failed");
        assert_eq!(block_id, Some(100));
    }

    #[tokio::test]
    async fn test_list_before_block() {
        let storage = create_test_storage();

        // Add entries at different blocks
        for block in [50, 100, 150, 200, 250] {
            let key = StorageKey::new("submissions", format!("hash-block-{}", block));
            storage
                .put_with_block(
                    key,
                    format!("data-{}", block).into_bytes(),
                    block,
                    PutOptions::default(),
                )
                .await
                .expect("put_with_block failed");
        }

        // Query entries before block 150
        let result = storage
            .list_before_block("submissions", 150, 100)
            .await
            .expect("list_before_block failed");

        assert_eq!(result.items.len(), 2); // blocks 50 and 100
        assert!(!result.has_more);
    }

    #[tokio::test]
    async fn test_list_after_block() {
        let storage = create_test_storage();

        // Add entries at different blocks
        for block in [50, 100, 150, 200, 250] {
            let key = StorageKey::new("submissions", format!("hash-block-{}", block));
            storage
                .put_with_block(
                    key,
                    format!("data-{}", block).into_bytes(),
                    block,
                    PutOptions::default(),
                )
                .await
                .expect("put_with_block failed");
        }

        // Query entries after block 150
        let result = storage
            .list_after_block("submissions", 150, 100)
            .await
            .expect("list_after_block failed");

        assert_eq!(result.items.len(), 2); // blocks 200 and 250
        assert!(!result.has_more);
    }

    #[tokio::test]
    async fn test_list_range() {
        let storage = create_test_storage();

        // Add entries at different blocks
        for block in [50, 100, 150, 200, 250] {
            let key = StorageKey::new("submissions", format!("hash-block-{}", block));
            storage
                .put_with_block(
                    key,
                    format!("data-{}", block).into_bytes(),
                    block,
                    PutOptions::default(),
                )
                .await
                .expect("put_with_block failed");
        }

        // Query entries in range [100, 200]
        let result = storage
            .list_range("submissions", 100, 200, 100)
            .await
            .expect("list_range failed");

        assert_eq!(result.items.len(), 3); // blocks 100, 150, 200
        assert!(!result.has_more);
    }

    #[tokio::test]
    async fn test_count_by_namespace() {
        let storage = create_test_storage();

        // Add entries to different namespaces
        for i in 0..5 {
            let key = StorageKey::new("submissions", format!("hash-{}", i));
            storage
                .put_with_block(key, b"data".to_vec(), i * 10, PutOptions::default())
                .await
                .expect("put_with_block failed");
        }

        for i in 0..3 {
            let key = StorageKey::new("evaluations", format!("hash-{}", i));
            storage
                .put_with_block(key, b"data".to_vec(), i * 10, PutOptions::default())
                .await
                .expect("put_with_block failed");
        }

        let count = storage
            .count_by_namespace("submissions")
            .await
            .expect("count_by_namespace failed");
        assert_eq!(count, 5);

        let count = storage
            .count_by_namespace("evaluations")
            .await
            .expect("count_by_namespace failed");
        assert_eq!(count, 3);

        let count = storage
            .count_by_namespace("nonexistent")
            .await
            .expect("count_by_namespace failed");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_query_builder_with_filters() {
        let storage = create_test_storage();

        // Add entries at different blocks
        for block in [50, 100, 150, 200, 250, 300] {
            let key = StorageKey::new("submissions", format!("hash-block-{}", block));
            storage
                .put_with_block(
                    key,
                    format!("data-{}", block).into_bytes(),
                    block,
                    PutOptions::default(),
                )
                .await
                .expect("put_with_block failed");
        }

        // Query with range filter using QueryBuilder
        let query = QueryBuilder::new("submissions")
            .after_block(100)
            .before_block(300)
            .limit(10);

        let result = storage.query(query).await.expect("query failed");

        // Should match blocks 150, 200, 250 (after 100 AND before 300)
        assert_eq!(result.items.len(), 3);
    }

    #[tokio::test]
    async fn test_query_with_pagination() {
        let storage = create_test_storage();

        // Add 10 entries
        for block in 0..10 {
            let key = StorageKey::new("submissions", format!("hash-block-{:02}", block));
            storage
                .put_with_block(
                    key,
                    format!("data-{}", block).into_bytes(),
                    block * 10,
                    PutOptions::default(),
                )
                .await
                .expect("put_with_block failed");
        }

        // First page
        let query = QueryBuilder::new("submissions").limit(3);
        let result1 = storage.query(query).await.expect("query failed");

        assert_eq!(result1.items.len(), 3);
        assert!(result1.has_more);
        assert!(result1.next_cursor.is_some());

        // Second page using cursor
        let query = QueryBuilder::new("submissions")
            .limit(3)
            .cursor(result1.next_cursor.unwrap());
        let result2 = storage.query(query).await.expect("query failed");

        assert_eq!(result2.items.len(), 3);
        assert!(result2.has_more);

        // Verify no overlap between pages
        let keys1: Vec<_> = result1.items.iter().map(|(k, _)| k.to_string()).collect();
        let keys2: Vec<_> = result2.items.iter().map(|(k, _)| k.to_string()).collect();
        for k in &keys1 {
            assert!(!keys2.contains(k), "Key {} found in both pages", k);
        }
    }

    #[tokio::test]
    async fn test_query_with_count() {
        let storage = create_test_storage();

        // Add 5 entries
        for block in 0..5 {
            let key = StorageKey::new("submissions", format!("hash-{}", block));
            storage
                .put_with_block(key, b"data".to_vec(), block * 10, PutOptions::default())
                .await
                .expect("put_with_block failed");
        }

        let query = QueryBuilder::new("submissions").limit(2).with_count();
        let result = storage.query(query).await.expect("query failed");

        assert_eq!(result.items.len(), 2);
        assert_eq!(result.total_count, Some(5));
    }

    #[tokio::test]
    async fn test_block_index_update_on_reput() {
        let storage = create_test_storage();

        let key = StorageKey::new("submissions", "test-hash");

        // Put at block 100
        storage
            .put_with_block(key.clone(), b"v1".to_vec(), 100, PutOptions::default())
            .await
            .expect("put_with_block failed");

        // Verify it's at block 100
        let result = storage
            .list_range("submissions", 100, 100, 10)
            .await
            .expect("list_range failed");
        assert_eq!(result.items.len(), 1);

        // Re-put at block 200
        storage
            .put_with_block(key.clone(), b"v2".to_vec(), 200, PutOptions::default())
            .await
            .expect("put_with_block failed");

        // Should not be at block 100 anymore
        let result = storage
            .list_range("submissions", 100, 100, 10)
            .await
            .expect("list_range failed");
        assert_eq!(result.items.len(), 0);

        // Should be at block 200
        let result = storage
            .list_range("submissions", 200, 200, 10)
            .await
            .expect("list_range failed");
        assert_eq!(result.items.len(), 1);
    }

    #[tokio::test]
    async fn test_delete_removes_block_index() {
        let storage = create_test_storage();

        let key = StorageKey::new("submissions", "test-hash");

        storage
            .put_with_block(key.clone(), b"data".to_vec(), 100, PutOptions::default())
            .await
            .expect("put_with_block failed");

        // Verify it exists in block index
        let result = storage
            .list_range("submissions", 100, 100, 10)
            .await
            .expect("list_range failed");
        assert_eq!(result.items.len(), 1);

        // Delete
        storage.delete(&key).await.expect("delete failed");

        // Should no longer be in block index
        let result = storage
            .list_range("submissions", 100, 100, 10)
            .await
            .expect("list_range failed");
        assert_eq!(result.items.len(), 0);
    }

    #[tokio::test]
    async fn test_empty_namespace_queries() {
        let storage = create_test_storage();

        // Query empty namespace
        let result = storage
            .list_before_block("empty", 1000, 100)
            .await
            .expect("list_before_block failed");
        assert!(result.is_empty());

        let result = storage
            .list_after_block("empty", 0, 100)
            .await
            .expect("list_after_block failed");
        assert!(result.is_empty());

        let result = storage
            .list_range("empty", 0, 1000, 100)
            .await
            .expect("list_range failed");
        assert!(result.is_empty());
    }
}
