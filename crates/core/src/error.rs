//! Error types for platform

use thiserror::Error;

/// Result type alias
pub type Result<T> = std::result::Result<T, MiniChainError>;

/// Mini-chain error types
#[derive(Error, Debug)]
pub enum MiniChainError {
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Consensus error: {0}")]
    Consensus(String),

    #[error("WASM runtime error: {0}")]
    Wasm(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),
}

impl From<std::io::Error> for MiniChainError {
    fn from(err: std::io::Error) -> Self {
        MiniChainError::Internal(err.to_string())
    }
}

impl From<bincode::Error> for MiniChainError {
    fn from(err: bincode::Error) -> Self {
        MiniChainError::Serialization(err.to_string())
    }
}

impl From<serde_json::Error> for MiniChainError {
    fn from(err: serde_json::Error) -> Self {
        MiniChainError::Serialization(err.to_string())
    }
}
