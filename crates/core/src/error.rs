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

    #[error("Type mismatch: {0}")]
    TypeMismatch(String),

    #[error("Validation error: {0}")]
    Validation(String),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let chain_err: MiniChainError = io_err.into();
        assert!(matches!(chain_err, MiniChainError::Internal(_)));
        assert!(chain_err.to_string().contains("file not found"));
    }

    #[test]
    fn test_from_bincode_error() {
        // Create a bincode serialization error by writing to a fixed-size buffer that's too small
        let mut buffer = [0u8; 2]; // Fixed small buffer
        let large_data = vec![0u8; 1000]; // Data too large for buffer
        let result = bincode::serialize_into(&mut buffer[..], &large_data);
        let bincode_err = result.unwrap_err();
        let chain_err: MiniChainError = bincode_err.into();
        assert!(matches!(chain_err, MiniChainError::Serialization(_)));
    }

    #[test]
    fn test_from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("{invalid json").unwrap_err();
        let chain_err: MiniChainError = json_err.into();
        assert!(matches!(chain_err, MiniChainError::Serialization(_)));
    }

    #[test]
    fn test_error_display() {
        let err = MiniChainError::Crypto("bad key".to_string());
        assert_eq!(err.to_string(), "Cryptographic error: bad key");

        let err = MiniChainError::InvalidSignature;
        assert_eq!(err.to_string(), "Invalid signature");

        let err = MiniChainError::NotFound("block 123".to_string());
        assert_eq!(err.to_string(), "Not found: block 123");
    }
}
