//! Core types for the platform

use serde::{Deserialize, Serialize};
use std::fmt;

/// Validator hotkey (32 bytes ed25519 public key)
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hotkey(pub [u8; 32]);

impl Hotkey {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Some(Self(arr))
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        hex::decode(s).ok().and_then(|b| Self::from_bytes(&b))
    }

    /// Convert to SS58 format (Substrate address format)
    /// Uses network prefix 42 (generic Substrate)
    pub fn to_ss58(&self) -> String {
        use sp_core::crypto::Ss58Codec;

        // Use sp_core's SS58 encoding (proper blake2b checksum)
        let public = sp_core::sr25519::Public::from_raw(self.0);
        public.to_ss58check()
    }

    /// Parse from SS58 address
    pub fn from_ss58(address: &str) -> Option<Self> {
        use sp_core::crypto::Ss58Codec;

        sp_core::sr25519::Public::from_ss58check(address)
            .ok()
            .map(|p| Hotkey(p.0))
    }
}

impl fmt::Debug for Hotkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hotkey({}...)", &self.to_hex()[..8])
    }
}

impl fmt::Display for Hotkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}...{}", &self.to_hex()[..8], &self.to_hex()[56..])
    }
}

/// Challenge ID
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChallengeId(pub uuid::Uuid);

impl ChallengeId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn from_uuid(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }

    pub fn from_string(s: &str) -> Self {
        match uuid::Uuid::parse_str(s) {
            Ok(uuid) => Self(uuid),
            Err(_) => {
                // If not a valid UUID, create one from hash of string
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                std::hash::Hash::hash(&s, &mut hasher);
                let hash = std::hash::Hasher::finish(&hasher);
                Self(uuid::Uuid::from_u64_pair(hash, hash.wrapping_mul(31)))
            }
        }
    }
}

impl Default for ChallengeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ChallengeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Challenge({})", &self.0.to_string()[..8])
    }
}

impl fmt::Display for ChallengeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Block height
pub type BlockHeight = u64;

/// Stake amount (in TAO units, with 9 decimals)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct Stake(pub u64);

impl Stake {
    pub fn new(amount: u64) -> Self {
        Self(amount)
    }

    pub fn as_tao(&self) -> f64 {
        self.0 as f64 / 1_000_000_000.0
    }
}

/// Validator information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub hotkey: Hotkey,
    pub stake: Stake,
    pub is_active: bool,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub peer_id: Option<String>,
    /// X25519 public key for API key encryption (hex, 32 bytes)
    #[serde(default)]
    pub x25519_pubkey: Option<String>,
}

impl ValidatorInfo {
    pub fn new(hotkey: Hotkey, stake: Stake) -> Self {
        Self {
            hotkey,
            stake,
            is_active: true,
            last_seen: chrono::Utc::now(),
            peer_id: None,
            x25519_pubkey: None,
        }
    }
}

/// Network configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub subnet_id: u16,
    pub min_stake: Stake,
    pub consensus_threshold: f64, // 0.50 for 50%+1
    pub block_time_ms: u64,
    pub max_validators: usize,
    pub evaluation_timeout_secs: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            subnet_id: 100,
            min_stake: Stake::new(1_000_000_000), // 1 TAO minimum
            consensus_threshold: 0.50,
            block_time_ms: 12_000, // 12 seconds
            max_validators: 64,
            evaluation_timeout_secs: 300,
        }
    }
}

impl NetworkConfig {
    /// Production network configuration
    pub fn production() -> Self {
        Self {
            subnet_id: 100,                           // Terminal Benchmark subnet
            min_stake: Stake::new(1_000_000_000_000), // 1000 TAO minimum
            consensus_threshold: 0.50,
            block_time_ms: 12_000, // 12 seconds (Bittensor block time)
            max_validators: 64,
            evaluation_timeout_secs: 3600, // 1 hour for long evaluations
        }
    }
}

/// Score from challenge evaluation
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Score {
    pub value: f64,
    pub weight: f64,
}

impl Score {
    pub fn new(value: f64, weight: f64) -> Self {
        Self {
            value: value.clamp(0.0, 1.0),
            weight: weight.clamp(0.0, 1.0),
        }
    }

    pub fn weighted_value(&self) -> f64 {
        self.value * self.weight
    }
}

/// Job status
///
/// IMPORTANT: Never reorder or remove variants! Add new ones at the end only.
/// Use explicit discriminants to ensure stable serialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum JobStatus {
    Pending = 0,
    Running = 1,
    Completed = 2,
    Failed = 3,
    Timeout = 4,
    // Add new variants here with next number
}

/// Evaluation job
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    pub id: uuid::Uuid,
    pub challenge_id: ChallengeId,
    pub agent_hash: String,
    pub status: JobStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub assigned_validator: Option<Hotkey>,
    pub result: Option<Score>,
}

impl Job {
    pub fn new(challenge_id: ChallengeId, agent_hash: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            challenge_id,
            agent_hash,
            status: JobStatus::Pending,
            created_at: chrono::Utc::now(),
            assigned_validator: None,
            result: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hotkey() {
        let bytes = [1u8; 32];
        let hotkey = Hotkey(bytes);
        let hex = hotkey.to_hex();
        let recovered = Hotkey::from_hex(&hex).unwrap();
        assert_eq!(hotkey, recovered);
    }

    #[test]
    fn test_hotkey_from_bytes() {
        let bytes = [42u8; 32];
        let hotkey = Hotkey::from_bytes(&bytes).unwrap();
        assert_eq!(hotkey.as_bytes(), &bytes);
    }

    #[test]
    fn test_hotkey_from_bytes_invalid() {
        let short = [1u8; 16];
        assert!(Hotkey::from_bytes(&short).is_none());
    }

    #[test]
    fn test_hotkey_from_hex_invalid() {
        assert!(Hotkey::from_hex("invalid").is_none());
        assert!(Hotkey::from_hex("0102").is_none()); // too short
    }

    #[test]
    fn test_hotkey_display() {
        let hotkey = Hotkey([0xab; 32]);
        let display = format!("{}", hotkey);
        assert!(display.contains("abababab"));
    }

    #[test]
    fn test_hotkey_debug() {
        let hotkey = Hotkey([0xcd; 32]);
        let debug = format!("{:?}", hotkey);
        assert!(debug.contains("Hotkey"));
    }

    #[test]
    fn test_stake() {
        let stake = Stake::new(1_500_000_000);
        assert_eq!(stake.as_tao(), 1.5);
    }

    #[test]
    fn test_stake_ordering() {
        let s1 = Stake::new(100);
        let s2 = Stake::new(200);
        assert!(s1 < s2);
        assert!(s2 > s1);
        assert_eq!(s1, Stake::new(100));
    }

    #[test]
    fn test_score() {
        let score = Score::new(0.8, 0.5);
        assert_eq!(score.weighted_value(), 0.4);
    }

    #[test]
    fn test_score_clamping() {
        let score = Score::new(1.5, 2.0);
        assert_eq!(score.value, 1.0);
        assert_eq!(score.weight, 1.0);

        let score2 = Score::new(-0.5, -1.0);
        assert_eq!(score2.value, 0.0);
        assert_eq!(score2.weight, 0.0);
    }

    #[test]
    fn test_challenge_id() {
        let id1 = ChallengeId::new();
        let id2 = ChallengeId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_challenge_id_from_string() {
        let id = ChallengeId::from_string("test-challenge");
        let id2 = ChallengeId::from_string("test-challenge");
        assert_eq!(id, id2);
    }

    #[test]
    fn test_challenge_id_from_uuid_string() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let id = ChallengeId::from_string(uuid_str);
        assert_eq!(format!("{}", id), uuid_str);
    }

    #[test]
    fn test_challenge_id_display() {
        let id = ChallengeId::new();
        let display = format!("{}", id);
        assert!(!display.is_empty());
    }

    #[test]
    fn test_validator_info() {
        let hotkey = Hotkey([1u8; 32]);
        let info = ValidatorInfo::new(hotkey.clone(), Stake::new(1000));
        assert_eq!(info.hotkey, hotkey);
        assert!(info.is_active);
        assert!(info.peer_id.is_none());
    }

    #[test]
    fn test_network_config_default() {
        let config = NetworkConfig::default();
        assert_eq!(config.subnet_id, 100);
        assert_eq!(config.consensus_threshold, 0.50);
    }

    #[test]
    fn test_network_config_production() {
        let config = NetworkConfig::production();
        assert_eq!(config.subnet_id, 100);
        assert_eq!(config.min_stake.0, 1_000_000_000_000);
    }

    #[test]
    fn test_job_creation() {
        let challenge_id = ChallengeId::new();
        let job = Job::new(challenge_id, "agent123".to_string());
        assert_eq!(job.status, JobStatus::Pending);
        assert!(job.assigned_validator.is_none());
        assert!(job.result.is_none());
    }

    #[test]
    fn test_job_status_equality() {
        assert_eq!(JobStatus::Pending, JobStatus::Pending);
        assert_ne!(JobStatus::Pending, JobStatus::Running);
    }

    #[test]
    fn test_hotkey_ss58() {
        let hotkey = Hotkey([0xab; 32]);
        let ss58 = hotkey.to_ss58();
        assert!(!ss58.is_empty());
        assert!(ss58.starts_with('5')); // Substrate generic prefix
    }

    #[test]
    fn test_challenge_id_debug() {
        let id = ChallengeId::new();
        let debug = format!("{:?}", id);
        // Debug contains the UUID string
        assert!(!debug.is_empty());
        assert!(debug.len() > 10); // UUID is at least 36 chars
    }

    #[test]
    fn test_stake_conversion() {
        // 2.5 TAO = 2_500_000_000 (9 decimals)
        let stake = Stake::new(2_500_000_000);
        assert_eq!(stake.as_tao(), 2.5);
        assert_eq!(stake.0, 2_500_000_000);
    }

    #[test]
    fn test_stake_zero() {
        let stake = Stake::new(0);
        assert_eq!(stake.as_tao(), 0.0);
        assert!(stake <= Stake::new(1));
    }

    #[test]
    fn test_all_job_statuses() {
        let statuses = vec![
            JobStatus::Pending,
            JobStatus::Running,
            JobStatus::Completed,
            JobStatus::Failed,
            JobStatus::Timeout,
        ];

        for status in statuses {
            let debug = format!("{:?}", status);
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn test_validator_info_peer_id() {
        let hotkey = Hotkey([1u8; 32]);
        let mut info = ValidatorInfo::new(hotkey.clone(), Stake::new(1000));
        assert!(info.peer_id.is_none());

        info.peer_id = Some("peer123".to_string());
        assert_eq!(info.peer_id.as_ref().unwrap(), "peer123");
    }

    #[test]
    fn test_hotkey_equality() {
        let h1 = Hotkey([1u8; 32]);
        let h2 = Hotkey([1u8; 32]);
        let h3 = Hotkey([2u8; 32]);

        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_challenge_id_hash() {
        use std::collections::HashMap;

        let id1 = ChallengeId::new();
        let id2 = ChallengeId::new();

        let mut map: HashMap<ChallengeId, i32> = HashMap::new();
        map.insert(id1, 1);
        map.insert(id2, 2);

        assert_eq!(map.get(&id1), Some(&1));
        assert_eq!(map.get(&id2), Some(&2));
    }

    #[test]
    fn test_score_edge_cases() {
        let max_score = Score::new(1.0, 1.0);
        assert_eq!(max_score.weighted_value(), 1.0);

        let min_score = Score::new(0.0, 0.0);
        assert_eq!(min_score.weighted_value(), 0.0);

        let half = Score::new(0.5, 0.5);
        assert_eq!(half.weighted_value(), 0.25);
    }

    #[test]
    fn test_hotkey_from_ss58() {
        // Test with a valid SS58 address
        let original = Hotkey([0x42; 32]);
        let ss58 = original.to_ss58();
        let recovered = Hotkey::from_ss58(&ss58);
        assert!(recovered.is_some());
        assert_eq!(recovered.unwrap(), original);
    }

    #[test]
    fn test_hotkey_from_ss58_invalid() {
        assert!(Hotkey::from_ss58("invalid-address").is_none());
        assert!(Hotkey::from_ss58("").is_none());
    }

    #[test]
    fn test_challenge_id_from_uuid() {
        let uuid = uuid::Uuid::new_v4();
        let challenge_id = ChallengeId::from_uuid(uuid);
        assert_eq!(challenge_id.0, uuid);
        assert_eq!(format!("{}", challenge_id), format!("{}", uuid));
    }

    #[test]
    fn test_challenge_id_default() {
        let id1 = ChallengeId::default();
        let id2 = ChallengeId::default();
        // Each default should be unique
        assert_ne!(id1, id2);
    }
}
