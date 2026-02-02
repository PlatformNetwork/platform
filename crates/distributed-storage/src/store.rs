//! Distributed storage abstraction
//!
//! This module defines the core traits and types for distributed key-value storage.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

use crate::error::StorageResult;

/// Key for distributed storage
///
/// Keys are organized by namespace (e.g., "submissions", "evaluations", "weights")
/// and an arbitrary key within that namespace.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StorageKey {
    /// Namespace for the key (e.g., "submissions", "evaluations")
    pub namespace: String,
    /// Key data within the namespace
    pub key: Vec<u8>,
}

impl StorageKey {
    /// Create a new storage key
    pub fn new(namespace: &str, key: impl AsRef<[u8]>) -> Self {
        Self {
            namespace: namespace.to_string(),
            key: key.as_ref().to_vec(),
        }
    }

    /// Create a key for a submission
    pub fn submission(challenge_id: &str, hash: &str) -> Self {
        Self::new("submissions", format!("{}:{}", challenge_id, hash))
    }

    /// Create a key for an evaluation
    pub fn evaluation(challenge_id: &str, submission_hash: &str, validator: &str) -> Self {
        Self::new(
            "evaluations",
            format!("{}:{}:{}", challenge_id, submission_hash, validator),
        )
    }

    /// Create a key for weights
    pub fn weights(challenge_id: &str, epoch: u64) -> Self {
        Self::new("weights", format!("{}:{}", challenge_id, epoch))
    }

    /// Create a key for a challenge
    pub fn challenge(challenge_id: &str) -> Self {
        Self::new("challenges", challenge_id)
    }

    /// Convert key to bytes for storage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.namespace.len() + 1 + self.key.len());
        bytes.extend_from_slice(self.namespace.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(&self.key);
        bytes
    }

    /// Compute SHA256 hash of the key (for DHT routing)
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.to_bytes());
        hasher.finalize().into()
    }

    /// Get the key as a string if it's valid UTF-8
    pub fn key_string(&self) -> Option<String> {
        String::from_utf8(self.key.clone()).ok()
    }
}

impl fmt::Display for StorageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(key_str) = self.key_string() {
            write!(f, "{}:{}", self.namespace, key_str)
        } else {
            write!(f, "{}:{}", self.namespace, hex::encode(&self.key))
        }
    }
}

/// Metadata associated with stored values
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValueMetadata {
    /// When the value was created (Unix timestamp in milliseconds)
    pub created_at: i64,
    /// When the value was last updated (Unix timestamp in milliseconds)
    pub updated_at: i64,
    /// Version number for optimistic concurrency
    pub version: u64,
    /// Node that originally wrote this value
    pub origin_node: Option<String>,
    /// SHA256 hash of the value
    pub value_hash: [u8; 32],
    /// Size of the value in bytes
    pub size: usize,
    /// Time-to-live in seconds (0 = never expires)
    pub ttl_seconds: u64,
}

impl ValueMetadata {
    /// Create new metadata for a value
    pub fn new(value: &[u8], origin_node: Option<String>) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        let mut hasher = Sha256::new();
        hasher.update(value);

        Self {
            created_at: now,
            updated_at: now,
            version: 1,
            origin_node,
            value_hash: hasher.finalize().into(),
            size: value.len(),
            ttl_seconds: 0,
        }
    }

    /// Create metadata for an update
    pub fn update(&self, value: &[u8], origin_node: Option<String>) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        let mut hasher = Sha256::new();
        hasher.update(value);

        Self {
            created_at: self.created_at,
            updated_at: now,
            version: self.version + 1,
            origin_node,
            value_hash: hasher.finalize().into(),
            size: value.len(),
            ttl_seconds: self.ttl_seconds,
        }
    }

    /// Check if the value has expired
    pub fn is_expired(&self) -> bool {
        if self.ttl_seconds == 0 {
            return false;
        }
        let now = chrono::Utc::now().timestamp_millis();
        let expires_at = self.created_at + (self.ttl_seconds as i64 * 1000);
        now > expires_at
    }
}

/// Stored value with metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredValue {
    /// The actual value data
    pub data: Vec<u8>,
    /// Metadata about the value
    pub metadata: ValueMetadata,
}

impl StoredValue {
    /// Create a new stored value
    pub fn new(data: Vec<u8>, origin_node: Option<String>) -> Self {
        let metadata = ValueMetadata::new(&data, origin_node);
        Self { data, metadata }
    }

    /// Check if this value is newer than another
    pub fn is_newer_than(&self, other: &Self) -> bool {
        // First compare versions
        if self.metadata.version != other.metadata.version {
            return self.metadata.version > other.metadata.version;
        }
        // Fall back to timestamp comparison
        self.metadata.updated_at > other.metadata.updated_at
    }
}

/// Options for get operations
#[derive(Clone, Debug, Default)]
pub struct GetOptions {
    /// If true, only check local storage
    pub local_only: bool,
    /// If true, require quorum read
    pub quorum_read: bool,
    /// Custom quorum size (defaults to replication policy)
    pub quorum_size: Option<usize>,
}

/// Options for put operations
#[derive(Clone, Debug, Default)]
pub struct PutOptions {
    /// If true, only write to local storage
    pub local_only: bool,
    /// If true, require quorum write
    pub quorum_write: bool,
    /// Custom quorum size (defaults to replication policy)
    pub quorum_size: Option<usize>,
    /// Time-to-live in seconds (0 = never expires)
    pub ttl_seconds: u64,
    /// Expected version for optimistic concurrency (None = ignore)
    pub expected_version: Option<u64>,
}

/// Result of a list operation
#[derive(Clone, Debug)]
pub struct ListResult {
    /// Key-value pairs
    pub items: Vec<(StorageKey, StoredValue)>,
    /// Whether there are more results
    pub has_more: bool,
    /// Continuation token for pagination
    pub continuation_token: Option<Vec<u8>>,
}

/// Trait for distributed key-value storage
///
/// This trait defines the interface for a distributed storage system that can
/// operate in both local-only and DHT-backed modes.
#[async_trait]
pub trait DistributedStore: Send + Sync {
    /// Get a value by key
    ///
    /// # Arguments
    /// * `key` - The storage key
    /// * `options` - Options for the get operation
    ///
    /// # Returns
    /// The stored value if found, None otherwise
    async fn get(
        &self,
        key: &StorageKey,
        options: GetOptions,
    ) -> StorageResult<Option<StoredValue>>;

    /// Put a value
    ///
    /// # Arguments
    /// * `key` - The storage key
    /// * `value` - The value to store
    /// * `options` - Options for the put operation
    ///
    /// # Returns
    /// The metadata of the stored value
    async fn put(
        &self,
        key: StorageKey,
        value: Vec<u8>,
        options: PutOptions,
    ) -> StorageResult<ValueMetadata>;

    /// Delete a value
    ///
    /// # Arguments
    /// * `key` - The storage key
    ///
    /// # Returns
    /// true if the value was deleted, false if it didn't exist
    async fn delete(&self, key: &StorageKey) -> StorageResult<bool>;

    /// Check if a key exists
    ///
    /// # Arguments
    /// * `key` - The storage key
    ///
    /// # Returns
    /// true if the key exists
    async fn exists(&self, key: &StorageKey) -> StorageResult<bool>;

    /// List all key-value pairs with a given namespace prefix
    ///
    /// # Arguments
    /// * `namespace` - The namespace to list
    /// * `prefix` - Optional prefix within the namespace
    /// * `limit` - Maximum number of results
    /// * `continuation_token` - Token for pagination
    ///
    /// # Returns
    /// List of key-value pairs
    async fn list_prefix(
        &self,
        namespace: &str,
        prefix: Option<&[u8]>,
        limit: usize,
        continuation_token: Option<&[u8]>,
    ) -> StorageResult<ListResult>;

    /// Get statistics about the storage
    async fn stats(&self) -> StorageResult<StorageStats>;
}

/// Storage statistics
#[derive(Clone, Debug, Default)]
pub struct StorageStats {
    /// Total number of keys
    pub total_keys: u64,
    /// Total size in bytes
    pub total_bytes: u64,
    /// Number of keys per namespace
    pub keys_per_namespace: std::collections::HashMap<String, u64>,
    /// Number of local replicas
    pub local_replicas: u64,
    /// Number of remote peers (for DHT mode)
    pub remote_peers: u64,
}

/// Convenience methods for DistributedStore
#[async_trait]
pub trait DistributedStoreExt: DistributedStore {
    /// Get a value with default options
    async fn get_simple(&self, key: &StorageKey) -> StorageResult<Option<Vec<u8>>> {
        let result = self.get(key, GetOptions::default()).await?;
        Ok(result.map(|v| v.data))
    }

    /// Put a value with default options
    async fn put_simple(&self, key: StorageKey, value: Vec<u8>) -> StorageResult<ValueMetadata> {
        self.put(key, value, PutOptions::default()).await
    }

    /// Get and deserialize a value
    async fn get_json<T: serde::de::DeserializeOwned + Send>(
        &self,
        key: &StorageKey,
    ) -> StorageResult<Option<T>> {
        let result = self.get(key, GetOptions::default()).await?;
        match result {
            Some(stored) => {
                let value: T = serde_json::from_slice(&stored.data)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    /// Serialize and put a value
    async fn put_json<T: serde::Serialize + Send + Sync>(
        &self,
        key: StorageKey,
        value: &T,
    ) -> StorageResult<ValueMetadata> {
        let data = serde_json::to_vec(value)?;
        self.put(key, data, PutOptions::default()).await
    }
}

// Blanket implementation for all DistributedStore implementors
impl<T: DistributedStore + ?Sized> DistributedStoreExt for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_key_new() {
        let key = StorageKey::new("test", "mykey");
        assert_eq!(key.namespace, "test");
        assert_eq!(key.key, b"mykey");
    }

    #[test]
    fn test_storage_key_submission() {
        let key = StorageKey::submission("challenge1", "abc123");
        assert_eq!(key.namespace, "submissions");
        assert_eq!(key.key_string(), Some("challenge1:abc123".to_string()));
    }

    #[test]
    fn test_storage_key_evaluation() {
        let key = StorageKey::evaluation("challenge1", "sub123", "validator1");
        assert_eq!(key.namespace, "evaluations");
        assert_eq!(
            key.key_string(),
            Some("challenge1:sub123:validator1".to_string())
        );
    }

    #[test]
    fn test_storage_key_weights() {
        let key = StorageKey::weights("challenge1", 42);
        assert_eq!(key.namespace, "weights");
        assert_eq!(key.key_string(), Some("challenge1:42".to_string()));
    }

    #[test]
    fn test_storage_key_to_bytes() {
        let key = StorageKey::new("ns", "key");
        let bytes = key.to_bytes();
        assert_eq!(bytes, b"ns:key");
    }

    #[test]
    fn test_storage_key_hash() {
        let key1 = StorageKey::new("test", "key1");
        let key2 = StorageKey::new("test", "key1");
        let key3 = StorageKey::new("test", "key2");

        assert_eq!(key1.hash(), key2.hash());
        assert_ne!(key1.hash(), key3.hash());
    }

    #[test]
    fn test_storage_key_display() {
        let key = StorageKey::new("test", "mykey");
        assert_eq!(format!("{}", key), "test:mykey");
    }

    #[test]
    fn test_value_metadata_new() {
        let value = b"test value";
        let metadata = ValueMetadata::new(value, Some("node1".to_string()));

        assert_eq!(metadata.version, 1);
        assert_eq!(metadata.size, value.len());
        assert_eq!(metadata.origin_node, Some("node1".to_string()));
        assert_eq!(metadata.ttl_seconds, 0);
    }

    #[test]
    fn test_value_metadata_update() {
        let value1 = b"test value";
        let value2 = b"updated value";
        let metadata1 = ValueMetadata::new(value1, Some("node1".to_string()));
        let metadata2 = metadata1.update(value2, Some("node2".to_string()));

        assert_eq!(metadata2.version, 2);
        assert_eq!(metadata2.size, value2.len());
        assert_eq!(metadata2.created_at, metadata1.created_at);
        assert!(metadata2.updated_at >= metadata1.updated_at);
    }

    #[test]
    fn test_value_metadata_expiry() {
        let value = b"test";
        let mut metadata = ValueMetadata::new(value, None);

        // No TTL - never expires
        assert!(!metadata.is_expired());

        // Set TTL in the past
        metadata.ttl_seconds = 1;
        metadata.created_at = chrono::Utc::now().timestamp_millis() - 10000;
        assert!(metadata.is_expired());
    }

    #[test]
    fn test_stored_value_is_newer_than() {
        let value1 = StoredValue::new(b"v1".to_vec(), None);

        // Simulate time passing
        std::thread::sleep(std::time::Duration::from_millis(10));

        let value2 = StoredValue::new(b"v2".to_vec(), None);

        // value2 should be newer due to higher version
        let mut v1_modified = value1.clone();
        v1_modified.metadata.version = 1;
        let mut v2_modified = value2.clone();
        v2_modified.metadata.version = 2;

        assert!(v2_modified.is_newer_than(&v1_modified));
        assert!(!v1_modified.is_newer_than(&v2_modified));
    }
}
