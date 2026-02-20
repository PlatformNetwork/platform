//! P2P network configuration
//!
//! Provides configuration for the decentralized P2P network including
//! listen addresses, bootstrap peers, and consensus parameters.

use serde::{Deserialize, Serialize};

/// Bootstrap nodes for the Platform P2P network.
///
/// Each entry should be a multiaddr in the format:
/// `/ip4/<IP>/tcp/<PORT>/p2p/<PEER_ID>`
///
/// Configure your bootstrap peers via the BOOTSTRAP_PEERS environment variable
/// or add them here for your deployment.
pub const DEFAULT_BOOTSTRAP_NODES: &[&str] = &[
    // Add your bootstrap peers here
];

/// P2P network configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2PConfig {
    /// Listen addresses (multiaddr format)
    pub listen_addrs: Vec<String>,
    /// Bootstrap peers (multiaddr format)
    pub bootstrap_peers: Vec<String>,
    /// Gossipsub topic for consensus messages
    pub consensus_topic: String,
    /// Gossipsub topic for challenge messages
    pub challenge_topic: String,
    /// Netuid for the subnet
    pub netuid: u16,
    /// Minimum validator stake in RAO
    pub min_stake: u64,
    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    /// Maximum number of peers to maintain
    pub max_peers: usize,
    /// Whether this node is a bootnode
    pub is_bootnode: bool,
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/9000".to_string()],
            bootstrap_peers: vec![],
            consensus_topic: "platform/consensus/1.0.0".to_string(),
            challenge_topic: "platform/challenge/1.0.0".to_string(),
            netuid: 100,
            min_stake: 10_000_000_000_000, // 10000 TAO
            heartbeat_interval_secs: 30,
            max_message_size: 16 * 1024 * 1024, // 16 MB
            connection_timeout_secs: 30,
            max_peers: 64,
            is_bootnode: false,
        }
    }
}

impl P2PConfig {
    /// Create a new P2P config with custom listen address
    pub fn with_listen_addr(mut self, addr: &str) -> Self {
        self.listen_addrs = vec![addr.to_string()];
        self
    }

    /// Add bootstrap peers
    pub fn with_bootstrap_peers(mut self, peers: Vec<String>) -> Self {
        self.bootstrap_peers = peers;
        self
    }

    /// Set the netuid
    pub fn with_netuid(mut self, netuid: u16) -> Self {
        self.netuid = netuid;
        self
    }

    /// Set minimum stake requirement
    pub fn with_min_stake(mut self, min_stake: u64) -> Self {
        self.min_stake = min_stake;
        self
    }

    /// Set whether this node is a bootnode
    pub fn with_bootnode(mut self, is_bootnode: bool) -> Self {
        self.is_bootnode = is_bootnode;
        self
    }

    /// Create a development config with relaxed settings
    pub fn development() -> Self {
        Self {
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
            bootstrap_peers: vec![],
            consensus_topic: "platform/consensus/dev".to_string(),
            challenge_topic: "platform/challenge/dev".to_string(),
            netuid: 100,
            min_stake: 0, // No stake requirement in dev
            heartbeat_interval_secs: 5,
            max_message_size: 16 * 1024 * 1024,
            connection_timeout_secs: 10,
            max_peers: 32,
            is_bootnode: false,
        }
    }

    /// Create a production config with default bootstrap nodes
    pub fn production() -> Self {
        Self {
            listen_addrs: vec![
                "/ip4/0.0.0.0/tcp/9000".to_string(),
                "/ip6/::/tcp/9000".to_string(),
            ],
            bootstrap_peers: DEFAULT_BOOTSTRAP_NODES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            consensus_topic: "platform/consensus/1.0.0".to_string(),
            challenge_topic: "platform/challenge/1.0.0".to_string(),
            netuid: 100,
            min_stake: 10_000_000_000_000, // 10000 TAO
            heartbeat_interval_secs: 30,
            max_message_size: 16 * 1024 * 1024,
            connection_timeout_secs: 30,
            max_peers: 64,
            is_bootnode: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = P2PConfig::default();
        assert_eq!(config.netuid, 100);
        assert_eq!(config.min_stake, 10_000_000_000_000);
        assert!(!config.listen_addrs.is_empty());
    }

    #[test]
    fn test_with_listen_addr() {
        let config = P2PConfig::default().with_listen_addr("/ip4/127.0.0.1/tcp/8000");
        assert_eq!(config.listen_addrs, vec!["/ip4/127.0.0.1/tcp/8000"]);
    }

    #[test]
    fn test_with_bootstrap_peers() {
        let peers = vec!["/ip4/1.2.3.4/tcp/9000".to_string()];
        let config = P2PConfig::default().with_bootstrap_peers(peers.clone());
        assert_eq!(config.bootstrap_peers, peers);
    }

    #[test]
    fn test_development_config() {
        let config = P2PConfig::development();
        assert_eq!(config.min_stake, 0);
        assert_eq!(config.heartbeat_interval_secs, 5);
    }

    #[test]
    fn test_production_config() {
        let config = P2PConfig::production();
        assert_eq!(config.min_stake, 10_000_000_000_000);
        assert_eq!(config.listen_addrs.len(), 2);
    }
}
