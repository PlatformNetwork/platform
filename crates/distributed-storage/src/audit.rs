//! Audit log system for distributed storage
//!
//! Provides an immutable audit trail of all storage operations.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::error::{StorageError, StorageResult};
use crate::store::{DistributedStore, GetOptions, PutOptions, StorageKey};

/// Type of audit operation
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditOperation {
    /// Value was created
    Create,
    /// Value was updated
    Update,
    /// Value was deleted
    Delete,
    /// Value was migrated to a new schema
    Migrate,
}

/// A single audit log entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Block number when this operation occurred
    pub block_number: u64,
    /// Timestamp in milliseconds
    pub timestamp: i64,
    /// Type of operation
    pub operation: AuditOperation,
    /// Key that was affected
    pub key: StorageKey,
    /// Hash of the old value (None for creates)
    pub old_hash: Option<[u8; 32]>,
    /// Hash of the new value (None for deletes)
    pub new_hash: Option<[u8; 32]>,
    /// Validator that performed the operation
    pub validator: String,
    /// Signature of the validator
    pub signature: Vec<u8>,
}

impl AuditEntry {
    /// Create a new audit entry for a create operation
    pub fn create(
        block_number: u64,
        key: StorageKey,
        new_hash: [u8; 32],
        validator: String,
    ) -> Self {
        Self {
            block_number,
            timestamp: chrono::Utc::now().timestamp_millis(),
            operation: AuditOperation::Create,
            key,
            old_hash: None,
            new_hash: Some(new_hash),
            validator,
            signature: Vec::new(),
        }
    }

    /// Create a new audit entry for an update operation
    pub fn update(
        block_number: u64,
        key: StorageKey,
        old_hash: [u8; 32],
        new_hash: [u8; 32],
        validator: String,
    ) -> Self {
        Self {
            block_number,
            timestamp: chrono::Utc::now().timestamp_millis(),
            operation: AuditOperation::Update,
            key,
            old_hash: Some(old_hash),
            new_hash: Some(new_hash),
            validator,
            signature: Vec::new(),
        }
    }

    /// Create a new audit entry for a delete operation
    pub fn delete(
        block_number: u64,
        key: StorageKey,
        old_hash: [u8; 32],
        validator: String,
    ) -> Self {
        Self {
            block_number,
            timestamp: chrono::Utc::now().timestamp_millis(),
            operation: AuditOperation::Delete,
            key,
            old_hash: Some(old_hash),
            new_hash: None,
            validator,
            signature: Vec::new(),
        }
    }

    /// Set the signature
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }
}

/// Audit log for tracking all storage operations
pub struct AuditLog {
    storage: Arc<dyn DistributedStore>,
    /// Maximum entries per block (to limit storage size)
    max_entries_per_block: usize,
}

impl AuditLog {
    /// Create a new audit log
    pub fn new(storage: Arc<dyn DistributedStore>) -> Self {
        Self {
            storage,
            max_entries_per_block: 10_000,
        }
    }

    /// Append an audit entry
    pub async fn append(&self, entry: AuditEntry) -> StorageResult<()> {
        // Store by block number
        let block_key = StorageKey::new("audit_block", format!("{:016x}", entry.block_number));

        // Get existing entries for this block
        let mut entries: Vec<AuditEntry> =
            if let Some(stored) = self.storage.get(&block_key, GetOptions::default()).await? {
                bincode::deserialize(&stored.data)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?
            } else {
                Vec::new()
            };

        // Check limit
        if entries.len() >= self.max_entries_per_block {
            return Err(StorageError::QuotaExceeded(format!(
                "Max {} entries per block",
                self.max_entries_per_block
            )));
        }

        entries.push(entry.clone());

        // Store updated block entries
        let data =
            bincode::serialize(&entries).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.storage
            .put(block_key, data, PutOptions::default())
            .await?;

        // Also store by key for history lookups
        let key_audit_key = StorageKey::new(
            "audit_key",
            format!("{}:{}", entry.key.namespace, hex::encode(&entry.key.key)),
        );

        let mut key_entries: Vec<AuditEntry> = if let Some(stored) = self
            .storage
            .get(&key_audit_key, GetOptions::default())
            .await?
        {
            bincode::deserialize(&stored.data)
                .map_err(|e| StorageError::Serialization(e.to_string()))?
        } else {
            Vec::new()
        };

        key_entries.push(entry);

        let data = bincode::serialize(&key_entries)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.storage
            .put(key_audit_key, data, PutOptions::default())
            .await?;

        Ok(())
    }

    /// Get all audit entries for a specific key
    pub async fn get_history(
        &self,
        key: &StorageKey,
        from_block: u64,
    ) -> StorageResult<Vec<AuditEntry>> {
        let key_audit_key = StorageKey::new(
            "audit_key",
            format!("{}:{}", key.namespace, hex::encode(&key.key)),
        );

        if let Some(stored) = self
            .storage
            .get(&key_audit_key, GetOptions::default())
            .await?
        {
            let entries: Vec<AuditEntry> = bincode::deserialize(&stored.data)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;

            // Filter by block
            let filtered: Vec<AuditEntry> = entries
                .into_iter()
                .filter(|e| e.block_number >= from_block)
                .collect();

            return Ok(filtered);
        }

        Ok(Vec::new())
    }

    /// Get all audit entries for a specific block
    pub async fn get_block_writes(&self, block_number: u64) -> StorageResult<Vec<AuditEntry>> {
        let block_key = StorageKey::new("audit_block", format!("{:016x}", block_number));

        if let Some(stored) = self.storage.get(&block_key, GetOptions::default()).await? {
            let entries: Vec<AuditEntry> = bincode::deserialize(&stored.data)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            return Ok(entries);
        }

        Ok(Vec::new())
    }

    /// Get the latest audit entry for a key
    pub async fn get_latest(&self, key: &StorageKey) -> StorageResult<Option<AuditEntry>> {
        let entries = self.get_history(key, 0).await?;
        Ok(entries.into_iter().last())
    }

    /// Count total audit entries for a key
    pub async fn count_history(&self, key: &StorageKey) -> StorageResult<usize> {
        let entries = self.get_history(key, 0).await?;
        Ok(entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_creation() {
        let key = StorageKey::new("test", "key1");
        let entry = AuditEntry::create(100, key.clone(), [0u8; 32], "validator1".to_string());

        assert_eq!(entry.block_number, 100);
        assert_eq!(entry.operation, AuditOperation::Create);
        assert_eq!(entry.key, key);
        assert!(entry.old_hash.is_none());
        assert!(entry.new_hash.is_some());
    }
}
