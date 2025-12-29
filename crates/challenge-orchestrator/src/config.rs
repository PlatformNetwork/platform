//! Configuration types for challenge orchestrator

use serde::{Deserialize, Serialize};
use std::time::Duration;

// Re-export ChallengeContainerConfig from core for unified type
pub use platform_core::ChallengeContainerConfig;

/// Orchestrator configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrchestratorConfig {
    /// Docker network name for challenge containers
    pub network_name: String,
    /// Health check interval
    #[serde(with = "humantime_serde")]
    pub health_check_interval: Duration,
    /// Container stop timeout
    #[serde(with = "humantime_serde")]
    pub stop_timeout: Duration,
    /// Docker registry (optional, for private registries)
    pub registry: Option<RegistryConfig>,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            network_name: "platform-network".to_string(),
            health_check_interval: Duration::from_secs(30),
            stop_timeout: Duration::from_secs(30),
            registry: None,
        }
    }
}

/// Docker registry configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryConfig {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Humantime serde helper
mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = OrchestratorConfig::default();
        assert_eq!(config.network_name, "platform-network");
        assert_eq!(config.health_check_interval, Duration::from_secs(30));
    }
}
