//! Challenge definition and management

use crate::{hash, ChallengeId, Hotkey, Result};
use serde::{Deserialize, Serialize};

/// Challenge definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Challenge {
    /// Unique identifier
    pub id: ChallengeId,

    /// Challenge name
    pub name: String,

    /// Description
    pub description: String,

    /// WASM bytecode for evaluation
    pub wasm_code: Vec<u8>,

    /// Hash of the WASM code
    pub code_hash: String,

    /// Challenge owner
    pub owner: Hotkey,

    /// Configuration
    pub config: ChallengeConfig,

    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Last update timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,

    /// Is active
    pub is_active: bool,
}

impl Challenge {
    /// Create a new challenge
    pub fn new(
        name: String,
        description: String,
        wasm_code: Vec<u8>,
        owner: Hotkey,
        config: ChallengeConfig,
    ) -> Self {
        let code_hash = hex::encode(hash(&wasm_code));
        let now = chrono::Utc::now();

        Self {
            id: ChallengeId::new(),
            name,
            description,
            wasm_code,
            code_hash,
            owner,
            config,
            created_at: now,
            updated_at: now,
            is_active: true,
        }
    }

    /// Update the WASM code
    pub fn update_code(&mut self, wasm_code: Vec<u8>) {
        self.code_hash = hex::encode(hash(&wasm_code));
        self.wasm_code = wasm_code;
        self.updated_at = chrono::Utc::now();
    }

    /// Verify code hash
    pub fn verify_code(&self) -> bool {
        let computed_hash = hex::encode(hash(&self.wasm_code));
        computed_hash == self.code_hash
    }
}

/// Challenge configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeConfig {
    /// Mechanism ID on Bittensor (1, 2, 3... - 0 is reserved for default)
    /// Each challenge has its own mechanism for weight setting
    pub mechanism_id: u8,

    /// Timeout for evaluation in seconds
    pub timeout_secs: u64,

    /// Maximum memory for WASM execution (in MB)
    pub max_memory_mb: u64,

    /// Maximum CPU time (in seconds)
    pub max_cpu_secs: u64,

    /// Weight in emissions
    pub emission_weight: f64,

    /// Required validators for consensus
    pub min_validators: usize,

    /// Custom parameters (passed to WASM) - stored as JSON string
    pub params_json: String,
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            mechanism_id: 1, // Default to mechanism 1
            timeout_secs: 300,
            max_memory_mb: 512,
            max_cpu_secs: 60,
            emission_weight: 1.0,
            min_validators: 1,
            params_json: "{}".to_string(),
        }
    }
}

impl ChallengeConfig {
    /// Create config with specific mechanism ID
    pub fn with_mechanism(mechanism_id: u8) -> Self {
        Self {
            mechanism_id,
            ..Default::default()
        }
    }
}

/// Challenge metadata (without WASM code, for listing)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeMeta {
    pub id: ChallengeId,
    pub name: String,
    pub description: String,
    pub code_hash: String,
    pub owner: Hotkey,
    pub config: ChallengeConfig,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub is_active: bool,
}

impl From<&Challenge> for ChallengeMeta {
    fn from(c: &Challenge) -> Self {
        Self {
            id: c.id,
            name: c.name.clone(),
            description: c.description.clone(),
            code_hash: c.code_hash.clone(),
            owner: c.owner.clone(),
            config: c.config.clone(),
            created_at: c.created_at,
            updated_at: c.updated_at,
            is_active: c.is_active,
        }
    }
}

/// WASM function interface that challenges must implement
///
/// The WASM module must export these functions:
/// - `evaluate(agent_ptr: i32, agent_len: i32) -> i64` - Returns score as fixed-point (0-1000000)
/// - `validate(agent_ptr: i32, agent_len: i32) -> i32` - Returns 1 if valid, 0 if not
/// - `get_name() -> i32` - Returns pointer to name string
/// - `get_version() -> i32` - Returns version number
pub trait ChallengeInterface {
    fn evaluate(&self, agent_data: &[u8]) -> Result<f64>;
    fn validate(&self, agent_data: &[u8]) -> Result<bool>;
    fn name(&self) -> &str;
    fn version(&self) -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keypair;

    #[test]
    fn test_challenge_creation() {
        let owner = Keypair::generate();
        let wasm = vec![0u8; 100]; // Dummy WASM

        let challenge = Challenge::new(
            "Test Challenge".into(),
            "A test challenge".into(),
            wasm.clone(),
            owner.hotkey(),
            ChallengeConfig::default(),
        );

        assert!(challenge.verify_code());
        assert!(challenge.is_active);
    }

    #[test]
    fn test_code_update() {
        let owner = Keypair::generate();
        let wasm1 = vec![1u8; 100];
        let wasm2 = vec![2u8; 100];

        let mut challenge = Challenge::new(
            "Test".into(),
            "Test".into(),
            wasm1,
            owner.hotkey(),
            ChallengeConfig::default(),
        );

        let hash1 = challenge.code_hash.clone();
        challenge.update_code(wasm2);
        let hash2 = challenge.code_hash.clone();

        assert_ne!(hash1, hash2);
        assert!(challenge.verify_code());
    }

    #[test]
    fn test_challenge_meta() {
        let owner = Keypair::generate();
        let challenge = Challenge::new(
            "Test".into(),
            "Test".into(),
            vec![0u8; 50],
            owner.hotkey(),
            ChallengeConfig::default(),
        );

        let meta: ChallengeMeta = (&challenge).into();
        assert_eq!(meta.name, challenge.name);
        assert_eq!(meta.code_hash, challenge.code_hash);
    }

    #[test]
    fn test_challenge_config_with_mechanism() {
        let config = ChallengeConfig::with_mechanism(5);
        assert_eq!(config.mechanism_id, 5);
        assert_eq!(config.timeout_secs, 300); // Should have other defaults
        assert_eq!(config.max_memory_mb, 512);
        assert_eq!(config.emission_weight, 1.0);
    }
}
