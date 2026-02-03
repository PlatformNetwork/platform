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
