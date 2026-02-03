//! Error types for challenge registry

use thiserror::Error;

/// Result type for registry operations
pub type RegistryResult<T> = Result<T, RegistryError>;

/// Errors that can occur in the challenge registry
#[derive(Error, Debug)]
pub enum RegistryError {
    #[error("Challenge not found: {0}")]
    ChallengeNotFound(String),

    #[error("Challenge already registered: {0}")]
    AlreadyRegistered(String),

    #[error("Version conflict: {0}")]
    VersionConflict(String),

    #[error("Migration failed: {0}")]
    MigrationFailed(String),

    #[error("Health check failed: {0}")]
    HealthCheckFailed(String),

    #[error("State persistence error: {0}")]
    StatePersistence(String),

    #[error("State restoration error: {0}")]
    StateRestoration(String),

    #[error("Invalid challenge configuration: {0}")]
    InvalidConfig(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<std::io::Error> for RegistryError {
    fn from(err: std::io::Error) -> Self {
        RegistryError::Internal(err.to_string())
    }
}

impl From<serde_json::Error> for RegistryError {
    fn from(err: serde_json::Error) -> Self {
        RegistryError::Serialization(err.to_string())
    }
}

impl From<bincode::Error> for RegistryError {
    fn from(err: bincode::Error) -> Self {
        RegistryError::Serialization(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error as IoError, ErrorKind};

    #[test]
    fn test_registry_error_display_challenge_not_found() {
        let err = RegistryError::ChallengeNotFound("test-challenge".to_string());
        assert_eq!(err.to_string(), "Challenge not found: test-challenge");
    }

    #[test]
    fn test_registry_error_display_already_registered() {
        let err = RegistryError::AlreadyRegistered("my-challenge".to_string());
        assert_eq!(
            err.to_string(),
            "Challenge already registered: my-challenge"
        );
    }

    #[test]
    fn test_registry_error_display_version_conflict() {
        let err = RegistryError::VersionConflict("v1.0.0 vs v2.0.0".to_string());
        assert_eq!(err.to_string(), "Version conflict: v1.0.0 vs v2.0.0");
    }

    #[test]
    fn test_registry_error_display_all_variants() {
        let test_cases = vec![
            (
                RegistryError::ChallengeNotFound("challenge-id".to_string()),
                "Challenge not found: challenge-id",
            ),
            (
                RegistryError::AlreadyRegistered("existing".to_string()),
                "Challenge already registered: existing",
            ),
            (
                RegistryError::VersionConflict("mismatch".to_string()),
                "Version conflict: mismatch",
            ),
            (
                RegistryError::MigrationFailed("migration error".to_string()),
                "Migration failed: migration error",
            ),
            (
                RegistryError::HealthCheckFailed("health issue".to_string()),
                "Health check failed: health issue",
            ),
            (
                RegistryError::StatePersistence("persist error".to_string()),
                "State persistence error: persist error",
            ),
            (
                RegistryError::StateRestoration("restore error".to_string()),
                "State restoration error: restore error",
            ),
            (
                RegistryError::InvalidConfig("bad config".to_string()),
                "Invalid challenge configuration: bad config",
            ),
            (
                RegistryError::Serialization("serde error".to_string()),
                "Serialization error: serde error",
            ),
            (
                RegistryError::Network("connection refused".to_string()),
                "Network error: connection refused",
            ),
            (
                RegistryError::Internal("unexpected".to_string()),
                "Internal error: unexpected",
            ),
        ];

        for (error, expected_message) in test_cases {
            assert_eq!(
                error.to_string(),
                expected_message,
                "Display mismatch for {:?}",
                error
            );
        }
    }

    #[test]
    fn test_from_io_error() {
        let io_err = IoError::new(ErrorKind::NotFound, "file not found");
        let registry_err: RegistryError = io_err.into();

        match registry_err {
            RegistryError::Internal(msg) => {
                assert!(
                    msg.contains("file not found"),
                    "Expected message to contain 'file not found', got: {}",
                    msg
                );
            }
            other => panic!("Expected Internal variant, got: {:?}", other),
        }
    }

    #[test]
    fn test_from_serde_json_error() {
        // Create an invalid JSON to trigger a parse error
        let invalid_json = "{ invalid json }";
        let serde_err = serde_json::from_str::<serde_json::Value>(invalid_json).unwrap_err();
        let registry_err: RegistryError = serde_err.into();

        match registry_err {
            RegistryError::Serialization(msg) => {
                assert!(
                    !msg.is_empty(),
                    "Serialization error message should not be empty"
                );
            }
            other => panic!("Expected Serialization variant, got: {:?}", other),
        }
    }

    #[test]
    fn test_from_bincode_error() {
        // Create invalid bincode data to trigger an error
        let invalid_data: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let bincode_err: bincode::Error = bincode::deserialize::<String>(invalid_data).unwrap_err();
        let registry_err: RegistryError = bincode_err.into();

        match registry_err {
            RegistryError::Serialization(msg) => {
                assert!(
                    !msg.is_empty(),
                    "Serialization error message should not be empty"
                );
            }
            other => panic!("Expected Serialization variant, got: {:?}", other),
        }
    }

    #[test]
    fn test_registry_result_type() {
        // Test that RegistryResult<T> works as expected with Ok
        fn returns_ok() -> RegistryResult<i32> {
            Ok(42)
        }
        assert_eq!(returns_ok().unwrap(), 42);

        // Test that RegistryResult<T> works as expected with Err
        fn returns_err() -> RegistryResult<i32> {
            Err(RegistryError::Internal("test error".to_string()))
        }
        assert!(returns_err().is_err());

        // Test with different types
        fn returns_string() -> RegistryResult<String> {
            Ok("success".to_string())
        }
        assert_eq!(returns_string().unwrap(), "success");
    }

    #[test]
    fn test_error_debug_impl() {
        let err = RegistryError::ChallengeNotFound("debug-test".to_string());
        let debug_str = format!("{:?}", err);

        // Debug format should contain the variant name and the inner value
        assert!(
            debug_str.contains("ChallengeNotFound"),
            "Debug should contain variant name, got: {}",
            debug_str
        );
        assert!(
            debug_str.contains("debug-test"),
            "Debug should contain inner value, got: {}",
            debug_str
        );

        // Test debug for another variant
        let err2 = RegistryError::Network("connection timeout".to_string());
        let debug_str2 = format!("{:?}", err2);
        assert!(
            debug_str2.contains("Network"),
            "Debug should contain variant name, got: {}",
            debug_str2
        );
    }
}
