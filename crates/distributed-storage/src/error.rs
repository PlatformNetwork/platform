//! Error types for distributed storage

use thiserror::Error;

/// Errors that can occur in distributed storage operations
#[derive(Debug, Error)]
pub enum StorageError {
    /// Error from the underlying sled database
    #[error("Database error: {0}")]
    Database(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Key not found
    #[error("Key not found: {namespace}:{key}")]
    NotFound { namespace: String, key: String },

    /// Namespace not found
    #[error("Namespace not found: {0}")]
    NamespaceNotFound(String),

    /// DHT operation error
    #[error("DHT error: {0}")]
    Dht(String),

    /// Replication error
    #[error("Replication error: {0}")]
    Replication(String),

    /// Quorum not reached for operation
    #[error("Quorum not reached: got {received} of {required} confirmations")]
    QuorumNotReached { required: usize, received: usize },

    /// Conflict detected during write
    #[error("Write conflict: {0}")]
    Conflict(String),

    /// Invalid data format
    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// Operation timeout
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Storage is not initialized
    #[error("Storage not initialized")]
    NotInitialized,

    /// Generic internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<sled::Error> for StorageError {
    fn from(err: sled::Error) -> Self {
        StorageError::Database(err.to_string())
    }
}

impl From<bincode::Error> for StorageError {
    fn from(err: bincode::Error) -> Self {
        StorageError::Serialization(err.to_string())
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> Self {
        StorageError::Serialization(err.to_string())
    }
}

/// Result type for storage operations
pub type StorageResult<T> = Result<T, StorageError>;
