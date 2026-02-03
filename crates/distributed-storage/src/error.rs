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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_error_display_database() {
        let err = StorageError::Database("connection failed".to_string());
        assert_eq!(err.to_string(), "Database error: connection failed");
    }

    #[test]
    fn test_storage_error_display_not_found() {
        let err = StorageError::NotFound {
            namespace: "users".to_string(),
            key: "user_123".to_string(),
        };
        assert_eq!(err.to_string(), "Key not found: users:user_123");
    }

    #[test]
    fn test_storage_error_display_quorum() {
        let err = StorageError::QuorumNotReached {
            required: 3,
            received: 1,
        };
        assert_eq!(
            err.to_string(),
            "Quorum not reached: got 1 of 3 confirmations"
        );
    }

    #[test]
    fn test_storage_error_display_all_variants() {
        // Test Database variant
        let database_err = StorageError::Database("db failure".to_string());
        assert_eq!(database_err.to_string(), "Database error: db failure");

        // Test Serialization variant
        let serialization_err = StorageError::Serialization("invalid format".to_string());
        assert_eq!(
            serialization_err.to_string(),
            "Serialization error: invalid format"
        );

        // Test NotFound variant
        let not_found_err = StorageError::NotFound {
            namespace: "config".to_string(),
            key: "setting_1".to_string(),
        };
        assert_eq!(not_found_err.to_string(), "Key not found: config:setting_1");

        // Test NamespaceNotFound variant
        let namespace_err = StorageError::NamespaceNotFound("missing_ns".to_string());
        assert_eq!(
            namespace_err.to_string(),
            "Namespace not found: missing_ns"
        );

        // Test Dht variant
        let dht_err = StorageError::Dht("peer unreachable".to_string());
        assert_eq!(dht_err.to_string(), "DHT error: peer unreachable");

        // Test Replication variant
        let replication_err = StorageError::Replication("sync failed".to_string());
        assert_eq!(replication_err.to_string(), "Replication error: sync failed");

        // Test QuorumNotReached variant
        let quorum_err = StorageError::QuorumNotReached {
            required: 5,
            received: 2,
        };
        assert_eq!(
            quorum_err.to_string(),
            "Quorum not reached: got 2 of 5 confirmations"
        );

        // Test Conflict variant
        let conflict_err = StorageError::Conflict("concurrent write detected".to_string());
        assert_eq!(
            conflict_err.to_string(),
            "Write conflict: concurrent write detected"
        );

        // Test InvalidData variant
        let invalid_data_err = StorageError::InvalidData("corrupted checksum".to_string());
        assert_eq!(
            invalid_data_err.to_string(),
            "Invalid data: corrupted checksum"
        );

        // Test Timeout variant
        let timeout_err = StorageError::Timeout("operation exceeded 30s".to_string());
        assert_eq!(
            timeout_err.to_string(),
            "Operation timed out: operation exceeded 30s"
        );

        // Test NotInitialized variant
        let not_initialized_err = StorageError::NotInitialized;
        assert_eq!(not_initialized_err.to_string(), "Storage not initialized");

        // Test Internal variant
        let internal_err = StorageError::Internal("unexpected state".to_string());
        assert_eq!(internal_err.to_string(), "Internal error: unexpected state");
    }

    #[test]
    fn test_from_sled_error() {
        // Create a sled error by opening an invalid path scenario
        // sled::Error doesn't have public constructors, so we trigger a real error
        let sled_result = sled::open("/\0invalid");
        if let Err(sled_err) = sled_result {
            let storage_err: StorageError = sled_err.into();
            let display = storage_err.to_string();
            assert!(
                display.starts_with("Database error:"),
                "Expected 'Database error:' prefix, got: {}",
                display
            );
        }
    }

    #[test]
    fn test_from_bincode_error() {
        // Create a bincode error by attempting to deserialize invalid data
        let invalid_data: &[u8] = &[0xff, 0xff, 0xff, 0xff];
        let bincode_result: Result<String, bincode::Error> =
            bincode::deserialize(invalid_data);
        if let Err(bincode_err) = bincode_result {
            let storage_err: StorageError = bincode_err.into();
            let display = storage_err.to_string();
            assert!(
                display.starts_with("Serialization error:"),
                "Expected 'Serialization error:' prefix, got: {}",
                display
            );
        }
    }

    #[test]
    fn test_from_serde_json_error() {
        // Create a serde_json error by parsing invalid JSON
        let invalid_json = "{invalid json}";
        let json_result: Result<serde_json::Value, serde_json::Error> =
            serde_json::from_str(invalid_json);
        if let Err(json_err) = json_result {
            let storage_err: StorageError = json_err.into();
            let display = storage_err.to_string();
            assert!(
                display.starts_with("Serialization error:"),
                "Expected 'Serialization error:' prefix, got: {}",
                display
            );
        }
    }

    #[test]
    fn test_storage_result_type() {
        // Test that StorageResult<T> works as expected
        fn returns_ok() -> StorageResult<i32> {
            Ok(42)
        }

        fn returns_err() -> StorageResult<i32> {
            Err(StorageError::NotInitialized)
        }

        // Test Ok case
        let ok_result = returns_ok();
        assert!(ok_result.is_ok());
        assert_eq!(ok_result.unwrap(), 42);

        // Test Err case
        let err_result = returns_err();
        assert!(err_result.is_err());
        assert_eq!(
            err_result.unwrap_err().to_string(),
            "Storage not initialized"
        );
    }

    #[test]
    fn test_storage_error_is_send_sync() {
        // Verify StorageError can be sent across threads
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<StorageError>();
        assert_sync::<StorageError>();
    }

    #[test]
    fn test_storage_error_debug_format() {
        // Verify Debug trait is implemented correctly
        let err = StorageError::Database("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(
            debug_str.contains("Database"),
            "Debug format should contain variant name"
        );
        assert!(
            debug_str.contains("test"),
            "Debug format should contain error message"
        );
    }
}
