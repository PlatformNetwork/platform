//! Challenge discovery and auto-registration
//!
//! Discovers challenges from:
//! - Docker registry
//! - File system (local development)
//! - Network announcements (P2P)

use crate::error::{RegistryError, RegistryResult};
use crate::version::ChallengeVersion;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A discovered challenge that can be registered
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveredChallenge {
    /// Challenge name
    pub name: String,
    /// Challenge version
    pub version: ChallengeVersion,
    /// Docker image (if available)
    pub docker_image: Option<String>,
    /// Local path (for development)
    pub local_path: Option<PathBuf>,
    /// Health endpoint URL
    pub health_endpoint: Option<String>,
    /// Evaluation endpoint URL
    pub evaluation_endpoint: Option<String>,
    /// Challenge metadata
    pub metadata: ChallengeMetadata,
    /// Source of discovery
    pub source: DiscoverySource,
}

/// Metadata about a challenge
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ChallengeMetadata {
    /// Human-readable description
    pub description: Option<String>,
    /// Challenge author
    pub author: Option<String>,
    /// Repository URL
    pub repository: Option<String>,
    /// License
    pub license: Option<String>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Minimum platform version required
    pub min_platform_version: Option<ChallengeVersion>,
}

/// Source where a challenge was discovered
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiscoverySource {
    /// Discovered from Docker registry
    DockerRegistry(String),
    /// Discovered from local filesystem
    LocalFilesystem(PathBuf),
    /// Discovered from WASM module directory
    WasmDirectory(PathBuf),
    /// Announced via P2P network
    P2PNetwork(String),
    /// Manually configured
    Manual,
}

/// Configuration for challenge discovery
#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    /// Docker registries to scan
    pub docker_registries: Vec<String>,
    /// Local paths to scan
    pub local_paths: Vec<PathBuf>,
    /// WASM module directories to scan
    pub wasm_paths: Vec<PathBuf>,
    /// Enable P2P discovery
    pub enable_p2p: bool,
    /// Auto-register discovered challenges
    pub auto_register: bool,
    /// Scan interval in seconds
    pub scan_interval_secs: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            docker_registries: vec![],
            local_paths: vec![],
            wasm_paths: vec![],
            enable_p2p: true,
            auto_register: false,
            scan_interval_secs: 300, // 5 minutes
        }
    }
}

/// Discovers challenges from various sources
pub struct ChallengeDiscovery {
    /// Configuration
    config: DiscoveryConfig,
    /// Discovered but not yet registered challenges
    discovered: parking_lot::RwLock<Vec<DiscoveredChallenge>>,
}

impl ChallengeDiscovery {
    /// Create a new discovery service with default config
    pub fn new() -> Self {
        Self {
            config: DiscoveryConfig::default(),
            discovered: parking_lot::RwLock::new(Vec::new()),
        }
    }

    /// Create with custom config
    pub fn with_config(config: DiscoveryConfig) -> Self {
        Self {
            config,
            discovered: parking_lot::RwLock::new(Vec::new()),
        }
    }

    /// Get the current configuration
    pub fn config(&self) -> &DiscoveryConfig {
        &self.config
    }

    /// Discover challenges from all configured sources
    pub fn discover_all(&self) -> RegistryResult<Vec<DiscoveredChallenge>> {
        let mut all_discovered = Vec::new();

        // Discover from local paths
        for path in &self.config.local_paths {
            match self.discover_from_local(path) {
                Ok(challenges) => all_discovered.extend(challenges),
                Err(e) => {
                    tracing::warn!(path = ?path, error = %e, "Failed to discover from local path");
                }
            }
        }

        // Discover from WASM directories
        for path in &self.config.wasm_paths {
            match self.discover_from_wasm_dir(path) {
                Ok(challenges) => all_discovered.extend(challenges),
                Err(e) => {
                    tracing::warn!(path = ?path, error = %e, "Failed to discover from WASM directory");
                }
            }
        }

        // Deprecation warning for Docker registries
        if !self.config.docker_registries.is_empty() {
            tracing::warn!(
                "Docker registry discovery is deprecated; prefer WASM module directories via wasm_paths"
            );
        }

        // Update internal state
        let mut discovered = self.discovered.write();
        *discovered = all_discovered.clone();

        Ok(all_discovered)
    }

    /// Discover challenges from a local path
    pub fn discover_from_local(&self, path: &PathBuf) -> RegistryResult<Vec<DiscoveredChallenge>> {
        if !path.exists() {
            return Err(RegistryError::InvalidConfig(format!(
                "Path does not exist: {:?}",
                path
            )));
        }

        let mut challenges = Vec::new();

        // Look for challenge.toml or Cargo.toml with challenge metadata
        if path.is_dir() {
            let challenge_toml = path.join("challenge.toml");
            let cargo_toml = path.join("Cargo.toml");

            if challenge_toml.exists() {
                // In a real implementation, parse challenge.toml
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                challenges.push(DiscoveredChallenge {
                    name,
                    version: ChallengeVersion::default(),
                    docker_image: None,
                    local_path: Some(path.clone()),
                    health_endpoint: None,
                    evaluation_endpoint: None,
                    metadata: ChallengeMetadata::default(),
                    source: DiscoverySource::LocalFilesystem(path.clone()),
                });
            } else if cargo_toml.exists() {
                // Extract name from Cargo.toml
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                challenges.push(DiscoveredChallenge {
                    name,
                    version: ChallengeVersion::default(),
                    docker_image: None,
                    local_path: Some(path.clone()),
                    health_endpoint: None,
                    evaluation_endpoint: None,
                    metadata: ChallengeMetadata::default(),
                    source: DiscoverySource::LocalFilesystem(path.clone()),
                });
            }
        }

        Ok(challenges)
    }

    /// Discover challenges from a WASM module directory
    pub fn discover_from_wasm_dir(
        &self,
        path: &PathBuf,
    ) -> RegistryResult<Vec<DiscoveredChallenge>> {
        if !path.exists() {
            return Err(RegistryError::InvalidConfig(format!(
                "WASM directory does not exist: {:?}",
                path
            )));
        }

        let mut challenges = Vec::new();

        if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    if entry_path.extension().and_then(|e| e.to_str()) == Some("wasm") {
                        let name = entry_path
                            .file_stem()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                            .to_string();

                        challenges.push(DiscoveredChallenge {
                            name,
                            version: ChallengeVersion::default(),
                            docker_image: None,
                            local_path: Some(entry_path.clone()),
                            health_endpoint: None,
                            evaluation_endpoint: None,
                            metadata: ChallengeMetadata::default(),
                            source: DiscoverySource::WasmDirectory(entry_path),
                        });
                    }
                }
            }
        }

        Ok(challenges)
    }

    /// Manually add a discovered challenge
    pub fn add_discovered(&self, challenge: DiscoveredChallenge) {
        let mut discovered = self.discovered.write();
        discovered.push(challenge);
    }

    /// Get all discovered challenges
    pub fn get_discovered(&self) -> Vec<DiscoveredChallenge> {
        self.discovered.read().clone()
    }

    /// Clear discovered challenges
    pub fn clear_discovered(&self) {
        self.discovered.write().clear();
    }

    /// Check if auto-registration is enabled
    pub fn auto_register_enabled(&self) -> bool {
        self.config.auto_register
    }
}

impl Default for ChallengeDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_source_equality() {
        assert_eq!(DiscoverySource::Manual, DiscoverySource::Manual);
        assert_ne!(
            DiscoverySource::Manual,
            DiscoverySource::P2PNetwork("test".to_string())
        );
    }

    #[test]
    fn test_discovered_challenge() {
        let challenge = DiscoveredChallenge {
            name: "test-challenge".to_string(),
            version: ChallengeVersion::new(1, 0, 0),
            docker_image: Some("test:latest".to_string()),
            local_path: None,
            health_endpoint: Some("http://localhost:8080/health".to_string()),
            evaluation_endpoint: Some("http://localhost:8080/evaluate".to_string()),
            metadata: ChallengeMetadata {
                description: Some("A test challenge".to_string()),
                author: Some("Platform".to_string()),
                ..Default::default()
            },
            source: DiscoverySource::Manual,
        };

        assert_eq!(challenge.name, "test-challenge");
        assert!(challenge.docker_image.is_some());
    }

    #[test]
    fn test_discovery_service() {
        let discovery = ChallengeDiscovery::new();

        assert!(discovery.get_discovered().is_empty());

        discovery.add_discovered(DiscoveredChallenge {
            name: "manual".to_string(),
            version: ChallengeVersion::new(1, 0, 0),
            docker_image: None,
            local_path: None,
            health_endpoint: None,
            evaluation_endpoint: None,
            metadata: ChallengeMetadata::default(),
            source: DiscoverySource::Manual,
        });

        assert_eq!(discovery.get_discovered().len(), 1);

        discovery.clear_discovered();
        assert!(discovery.get_discovered().is_empty());
    }

    #[test]
    fn test_discovery_config() {
        let config = DiscoveryConfig {
            docker_registries: vec!["registry.example.com".to_string()],
            local_paths: vec![PathBuf::from("/challenges")],
            wasm_paths: vec![],
            enable_p2p: false,
            auto_register: true,
            scan_interval_secs: 60,
        };

        let discovery = ChallengeDiscovery::with_config(config);
        assert!(discovery.auto_register_enabled());
        assert_eq!(discovery.config().scan_interval_secs, 60);
    }
}
