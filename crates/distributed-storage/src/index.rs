//! Index system for distributed storage
//!
//! Provides automatic indexing of stored values for efficient lookups.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{StorageError, StorageResult};
use crate::store::{DistributedStore, GetOptions, PutOptions, StorageKey};

/// Definition of an index
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexDefinition {
    /// Name of the index
    pub name: String,
    /// Namespace this index applies to
    pub namespace: String,
    /// Key extractor - JSON path or field name to extract the index key from values
    pub key_extractor: String,
    /// Whether this is a unique index (one value per key)
    pub unique: bool,
    /// Block number when this index was created
    pub created_block: u64,
}

/// A single entry in an index
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexEntry {
    /// The indexed value (extracted from the stored value)
    pub index_key: Vec<u8>,
    /// The storage key of the document
    pub storage_key: StorageKey,
    /// Block number when this entry was indexed
    pub block_number: u64,
}

/// Result of a paginated index query
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexPage {
    /// Items in this page
    pub items: Vec<StorageKey>,
    /// Total count of items matching the query
    pub total_count: u64,
    /// Whether there are more pages
    pub has_more: bool,
    /// Offset for next page
    pub next_offset: u32,
}

/// Index manager handles creation, maintenance and querying of indexes
pub struct IndexManager {
    /// Index definitions
    indexes: RwLock<HashMap<String, IndexDefinition>>,
    /// Storage backend
    storage: Arc<dyn DistributedStore>,
}

impl IndexManager {
    /// Create a new index manager
    pub fn new(storage: Arc<dyn DistributedStore>) -> Self {
        Self {
            indexes: RwLock::new(HashMap::new()),
            storage,
        }
    }

    /// Create a new index
    pub async fn create_index(&self, def: IndexDefinition) -> StorageResult<()> {
        let index_name = format!("{}:{}", def.namespace, def.name);

        // Store index definition
        let meta_key = StorageKey::new("idx_meta", &index_name);
        let data =
            bincode::serialize(&def).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.storage
            .put(meta_key, data, PutOptions::default())
            .await?;

        // Add to in-memory cache
        let mut indexes = self.indexes.write().await;
        indexes.insert(index_name, def);

        Ok(())
    }

    /// Get an index definition
    pub async fn get_index(
        &self,
        namespace: &str,
        name: &str,
    ) -> StorageResult<Option<IndexDefinition>> {
        let index_name = format!("{}:{}", namespace, name);

        // Check cache first
        {
            let indexes = self.indexes.read().await;
            if let Some(def) = indexes.get(&index_name) {
                return Ok(Some(def.clone()));
            }
        }

        // Load from storage
        let meta_key = StorageKey::new("idx_meta", &index_name);
        if let Some(stored) = self.storage.get(&meta_key, GetOptions::default()).await? {
            let def: IndexDefinition = bincode::deserialize(&stored.data)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;

            // Cache it
            let mut indexes = self.indexes.write().await;
            indexes.insert(index_name, def.clone());

            return Ok(Some(def));
        }

        Ok(None)
    }

    /// Find storage keys by index lookup
    pub async fn find_by_index(
        &self,
        namespace: &str,
        index_name: &str,
        key: &[u8],
    ) -> StorageResult<Vec<StorageKey>> {
        let idx_key = self.make_index_key(namespace, index_name, key);

        if let Some(stored) = self.storage.get(&idx_key, GetOptions::default()).await? {
            let entries: Vec<StorageKey> = bincode::deserialize(&stored.data)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            return Ok(entries);
        }

        Ok(Vec::new())
    }

    /// List entries by index with pagination
    pub async fn list_by_index(
        &self,
        namespace: &str,
        index_name: &str,
        prefix: &[u8],
        limit: u32,
        offset: u32,
    ) -> StorageResult<IndexPage> {
        // For now, get all entries and paginate in memory
        // TODO: Implement proper prefix scanning in storage
        let entries = self.find_by_index(namespace, index_name, prefix).await?;

        let total_count = entries.len() as u64;
        let start = offset as usize;
        let end = std::cmp::min(start + limit as usize, entries.len());

        let items = if start < entries.len() {
            entries[start..end].to_vec()
        } else {
            Vec::new()
        };

        let has_more = end < entries.len();

        Ok(IndexPage {
            items,
            total_count,
            has_more,
            next_offset: if has_more { end as u32 } else { 0 },
        })
    }

    /// Update indexes after a write operation
    pub async fn on_write(
        &self,
        key: &StorageKey,
        value: &[u8],
        block_number: u64,
    ) -> StorageResult<()> {
        // Get all indexes for this namespace
        let indexes = self.indexes.read().await;

        for (_, def) in indexes.iter() {
            if def.namespace != key.namespace {
                continue;
            }

            // Extract index key from value
            if let Some(index_value) = self.extract_index_key(&def.key_extractor, value) {
                self.add_to_index(&def.namespace, &def.name, &index_value, key, block_number)
                    .await?;
            }
        }

        Ok(())
    }

    /// Add a key to an index
    async fn add_to_index(
        &self,
        namespace: &str,
        index_name: &str,
        index_value: &[u8],
        storage_key: &StorageKey,
        _block_number: u64,
    ) -> StorageResult<()> {
        let idx_key = self.make_index_key(namespace, index_name, index_value);

        // Get existing entries
        let mut entries: Vec<StorageKey> =
            if let Some(stored) = self.storage.get(&idx_key, GetOptions::default()).await? {
                bincode::deserialize(&stored.data)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?
            } else {
                Vec::new()
            };

        // Add if not already present
        if !entries.iter().any(|k| k == storage_key) {
            entries.push(storage_key.clone());

            let data = bincode::serialize(&entries)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.storage
                .put(idx_key, data, PutOptions::default())
                .await?;
        }

        Ok(())
    }

    /// Remove a key from an index
    pub async fn remove_from_index(
        &self,
        namespace: &str,
        index_name: &str,
        index_value: &[u8],
        storage_key: &StorageKey,
    ) -> StorageResult<()> {
        let idx_key = self.make_index_key(namespace, index_name, index_value);

        if let Some(stored) = self.storage.get(&idx_key, GetOptions::default()).await? {
            let mut entries: Vec<StorageKey> = bincode::deserialize(&stored.data)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;

            entries.retain(|k| k != storage_key);

            if entries.is_empty() {
                self.storage.delete(&idx_key).await?;
            } else {
                let data = bincode::serialize(&entries)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.storage
                    .put(idx_key, data, PutOptions::default())
                    .await?;
            }
        }

        Ok(())
    }

    /// Make an index storage key
    fn make_index_key(&self, namespace: &str, index_name: &str, value: &[u8]) -> StorageKey {
        let key = format!("{}:{}:{}", namespace, index_name, hex::encode(value));
        StorageKey::new("idx", key)
    }

    /// Extract index key from a value using the key extractor
    fn extract_index_key(&self, extractor: &str, value: &[u8]) -> Option<Vec<u8>> {
        // Try to parse as JSON and extract field
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(value) {
            if let Some(field_value) = json.get(extractor) {
                return match field_value {
                    serde_json::Value::String(s) => Some(s.as_bytes().to_vec()),
                    serde_json::Value::Number(n) => Some(n.to_string().as_bytes().to_vec()),
                    _ => Some(field_value.to_string().as_bytes().to_vec()),
                };
            }
        }

        // Fall back: try to find the extractor as a prefix in the value
        None
    }
}

/// Atomic counter for tracking counts
pub struct AtomicCounter {
    storage: Arc<dyn DistributedStore>,
}

impl AtomicCounter {
    pub fn new(storage: Arc<dyn DistributedStore>) -> Self {
        Self { storage }
    }

    /// Get the current value of a counter
    pub async fn get(&self, namespace: &str, name: &str) -> StorageResult<u64> {
        let key = StorageKey::new("counter", format!("{}:{}", namespace, name));

        if let Some(stored) = self.storage.get(&key, GetOptions::default()).await? {
            if stored.data.len() >= 8 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&stored.data[..8]);
                return Ok(u64::from_le_bytes(buf));
            }
        }

        Ok(0)
    }

    /// Increment a counter and return the new value
    pub async fn increment(&self, namespace: &str, name: &str, delta: i64) -> StorageResult<i64> {
        let key = StorageKey::new("counter", format!("{}:{}", namespace, name));

        let current = self.get(namespace, name).await? as i64;
        let new_value = current.saturating_add(delta);

        let data = (new_value as u64).to_le_bytes().to_vec();
        self.storage.put(key, data, PutOptions::default()).await?;

        Ok(new_value)
    }

    /// Set a counter to a specific value
    pub async fn set(&self, namespace: &str, name: &str, value: u64) -> StorageResult<()> {
        let key = StorageKey::new("counter", format!("{}:{}", namespace, name));
        let data = value.to_le_bytes().to_vec();
        self.storage.put(key, data, PutOptions::default()).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_key_generation() {
        // Simple test for key generation
        let storage = crate::local::LocalStorage::in_memory("test".to_string()).unwrap();
        let manager = IndexManager {
            indexes: RwLock::new(HashMap::new()),
            storage: Arc::new(storage),
        };

        let key = manager.make_index_key("users", "by_github", b"testuser");
        assert!(key.namespace == "idx");
        assert!(key.key_string().unwrap().contains("users:by_github"));
    }
}
