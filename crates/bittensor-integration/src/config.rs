//! Bittensor configuration

use serde::{Deserialize, Serialize};

/// Default NETUID for the platform
pub const DEFAULT_NETUID: u16 = 100;

/// Bittensor network configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BittensorConfig {
    /// Subtensor WebSocket endpoint
    pub endpoint: String,

    /// Subnet UID (netuid) - default is 100
    pub netuid: u16,

    /// Use commit-reveal for weights (vs direct set_weights)
    pub use_commit_reveal: bool,

    /// Version key for weight submissions
    pub version_key: u64,
}

impl Default for BittensorConfig {
    fn default() -> Self {
        Self {
            endpoint: "wss://entrypoint-finney.opentensor.ai:443".to_string(),
            netuid: DEFAULT_NETUID,
            use_commit_reveal: true,
            version_key: 1,
        }
    }
}

impl BittensorConfig {
    /// Create config for testnet
    pub fn testnet(netuid: u16) -> Self {
        Self {
            endpoint: "wss://test.finney.opentensor.ai:443".to_string(),
            netuid,
            use_commit_reveal: true,
            version_key: 1,
        }
    }

    /// Create config for local network
    pub fn local(netuid: u16) -> Self {
        Self {
            endpoint: "ws://127.0.0.1:9944".to_string(),
            netuid,
            use_commit_reveal: false,
            version_key: 1,
        }
    }

    /// Create config for mainnet with default NETUID (100)
    pub fn mainnet() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_returns_default_config() {
        let cfg = BittensorConfig::mainnet();
        let default = BittensorConfig::default();
        assert_eq!(cfg.endpoint, default.endpoint);
        assert_eq!(cfg.netuid, DEFAULT_NETUID);
        assert_eq!(cfg.use_commit_reveal, default.use_commit_reveal);
        assert_eq!(cfg.version_key, default.version_key);
    }
}
