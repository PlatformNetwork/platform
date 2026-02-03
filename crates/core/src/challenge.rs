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

    #[test]
    fn test_challenge_config_default() {
        let config = ChallengeConfig::default();
        assert_eq!(config.mechanism_id, 1);
        assert_eq!(config.timeout_secs, 300);
        assert_eq!(config.max_memory_mb, 512);
        assert_eq!(config.max_cpu_secs, 60);
        assert_eq!(config.emission_weight, 1.0);
        assert_eq!(config.min_validators, 1);
        assert_eq!(config.params_json, "{}");
    }

    #[test]
    fn test_challenge_verify_code_tampered() {
        let owner = Keypair::generate();
        let wasm = vec![0u8; 100];

        let mut challenge = Challenge::new(
            "Test".into(),
            "Test".into(),
            wasm,
            owner.hotkey(),
            ChallengeConfig::default(),
        );

        // Tamper with the code without updating the hash
        challenge.wasm_code[0] = 255;

        // verify_code should return false since hash doesn't match
        assert!(!challenge.verify_code());
    }

    #[test]
    fn test_challenge_is_active_default() {
        let owner = Keypair::generate();
        let wasm = vec![0u8; 50];

        let challenge = Challenge::new(
            "Test".into(),
            "Test".into(),
            wasm,
            owner.hotkey(),
            ChallengeConfig::default(),
        );

        assert!(challenge.is_active);
    }

    #[test]
    fn test_challenge_id_uniqueness() {
        let owner = Keypair::generate();
        let wasm = vec![0u8; 50];

        let challenge1 = Challenge::new(
            "Test 1".into(),
            "Test".into(),
            wasm.clone(),
            owner.hotkey(),
            ChallengeConfig::default(),
        );

        let challenge2 = Challenge::new(
            "Test 2".into(),
            "Test".into(),
            wasm,
            owner.hotkey(),
            ChallengeConfig::default(),
        );

        assert_ne!(challenge1.id, challenge2.id);
    }

    #[test]
    fn test_challenge_timestamps() {
        let owner = Keypair::generate();
        let wasm = vec![0u8; 50];

        let before = chrono::Utc::now();
        let challenge = Challenge::new(
            "Test".into(),
            "Test".into(),
            wasm,
            owner.hotkey(),
            ChallengeConfig::default(),
        );
        let after = chrono::Utc::now();

        // created_at and updated_at should be within the time bounds
        assert!(challenge.created_at >= before);
        assert!(challenge.created_at <= after);
        assert!(challenge.updated_at >= before);
        assert!(challenge.updated_at <= after);
        // For a new challenge, created_at equals updated_at
        assert_eq!(challenge.created_at, challenge.updated_at);
    }

    #[test]
    fn test_challenge_update_code_changes_timestamp() {
        let owner = Keypair::generate();
        let wasm1 = vec![1u8; 50];
        let wasm2 = vec![2u8; 50];

        let mut challenge = Challenge::new(
            "Test".into(),
            "Test".into(),
            wasm1,
            owner.hotkey(),
            ChallengeConfig::default(),
        );

        let original_updated_at = challenge.updated_at;
        let original_created_at = challenge.created_at;

        // Small sleep to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_millis(10));

        challenge.update_code(wasm2);

        // created_at should not change
        assert_eq!(challenge.created_at, original_created_at);
        // updated_at should change
        assert!(challenge.updated_at > original_updated_at);
    }

    #[test]
    fn test_challenge_meta_preserves_fields() {
        let owner = Keypair::generate();
        let wasm = vec![42u8; 75];
        let config = ChallengeConfig::with_mechanism(3);

        let challenge = Challenge::new(
            "Meta Test".into(),
            "Description for meta".into(),
            wasm,
            owner.hotkey(),
            config,
        );

        let meta: ChallengeMeta = (&challenge).into();

        assert_eq!(meta.id, challenge.id);
        assert_eq!(meta.name, challenge.name);
        assert_eq!(meta.description, challenge.description);
        assert_eq!(meta.code_hash, challenge.code_hash);
        assert_eq!(meta.owner, challenge.owner);
        assert_eq!(meta.config.mechanism_id, challenge.config.mechanism_id);
        assert_eq!(meta.config.timeout_secs, challenge.config.timeout_secs);
        assert_eq!(meta.created_at, challenge.created_at);
        assert_eq!(meta.updated_at, challenge.updated_at);
        assert_eq!(meta.is_active, challenge.is_active);
    }

    #[test]
    fn test_challenge_config_params_json() {
        let config = ChallengeConfig::default();
        assert_eq!(config.params_json, "{}");

        let config_mechanism = ChallengeConfig::with_mechanism(2);
        assert_eq!(config_mechanism.params_json, "{}");
    }

    #[test]
    fn test_challenge_empty_wasm() {
        let owner = Keypair::generate();
        let empty_wasm: Vec<u8> = vec![];

        let challenge = Challenge::new(
            "Empty WASM".into(),
            "Challenge with empty wasm".into(),
            empty_wasm,
            owner.hotkey(),
            ChallengeConfig::default(),
        );

        // Should still create successfully and verify
        assert!(challenge.verify_code());
        assert!(challenge.wasm_code.is_empty());
        assert!(!challenge.code_hash.is_empty()); // Hash should still be computed
    }

    #[test]
    fn test_challenge_large_wasm() {
        let owner = Keypair::generate();
        let large_wasm = vec![0xABu8; 10 * 1024]; // 10KB

        let challenge = Challenge::new(
            "Large WASM".into(),
            "Challenge with 10KB wasm".into(),
            large_wasm.clone(),
            owner.hotkey(),
            ChallengeConfig::default(),
        );

        assert!(challenge.verify_code());
        assert_eq!(challenge.wasm_code.len(), 10 * 1024);
        assert_eq!(challenge.wasm_code, large_wasm);
    }
}
