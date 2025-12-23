//! Chain state management

use crate::{
    hash_data, BlockHeight, Challenge, ChallengeContainerConfig, ChallengeId,
    ChallengeWeightAllocation, Hotkey, Job, MechanismWeightConfig, NetworkConfig, Result, Stake,
    ValidatorInfo,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Required validator version (set by Sudo)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequiredVersion {
    pub min_version: String,
    pub recommended_version: String,
    pub docker_image: String,
    pub mandatory: bool,
    pub deadline_block: Option<u64>,
}

/// The complete chain state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainState {
    /// Current block height
    pub block_height: BlockHeight,

    /// Current epoch
    pub epoch: u64,

    /// Network configuration
    pub config: NetworkConfig,

    /// Subnet owner (has sudo privileges)
    pub sudo_key: Hotkey,

    /// Active validators
    pub validators: HashMap<Hotkey, ValidatorInfo>,

    /// Active challenges (legacy, for SDK-based challenges)
    pub challenges: HashMap<ChallengeId, Challenge>,

    /// Challenge container configs (for Docker-based challenges)
    pub challenge_configs: HashMap<ChallengeId, ChallengeContainerConfig>,

    /// Mechanism weight configurations (mechanism_id -> config)
    pub mechanism_configs: HashMap<u8, MechanismWeightConfig>,

    /// Challenge weight allocations (challenge_id -> allocation)
    pub challenge_weights: HashMap<ChallengeId, ChallengeWeightAllocation>,

    /// Required validator version
    pub required_version: Option<RequiredVersion>,

    /// Pending jobs
    pub pending_jobs: Vec<Job>,

    /// State hash (for verification)
    pub state_hash: [u8; 32],

    /// Last update timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,

    /// All registered hotkeys from metagraph (miners + validators)
    /// Updated during metagraph sync, used for submission verification
    #[serde(default)]
    pub registered_hotkeys: std::collections::HashSet<Hotkey>,
}

impl ChainState {
    /// Create a new chain state with a custom sudo key
    pub fn new(sudo_key: Hotkey, config: NetworkConfig) -> Self {
        let mut state = Self {
            block_height: 0,
            epoch: 0,
            config,
            sudo_key,
            validators: HashMap::new(),
            challenges: HashMap::new(),
            challenge_configs: HashMap::new(),
            mechanism_configs: HashMap::new(),
            challenge_weights: HashMap::new(),
            required_version: None,
            pending_jobs: Vec::new(),
            state_hash: [0u8; 32],
            last_updated: chrono::Utc::now(),
            registered_hotkeys: std::collections::HashSet::new(),
        };
        state.update_hash();
        state
    }

    /// Create a new chain state with the production sudo key
    /// (Coldkey: 5GziQCcRpN8NCJktX343brnfuVe3w6gUYieeStXPD1Dag2At)
    pub fn new_production(config: NetworkConfig) -> Self {
        Self::new(crate::production_sudo_key(), config)
    }

    /// Create a new chain state with production defaults
    pub fn production_default() -> Self {
        Self::new_production(NetworkConfig::production())
    }

    /// Update the state hash
    pub fn update_hash(&mut self) {
        #[derive(Serialize)]
        struct HashInput<'a> {
            block_height: BlockHeight,
            sudo_key: &'a Hotkey,
            validator_count: usize,
            challenge_count: usize,
            pending_jobs: usize,
        }

        let input = HashInput {
            block_height: self.block_height,
            sudo_key: &self.sudo_key,
            validator_count: self.validators.len(),
            challenge_count: self.challenges.len(),
            pending_jobs: self.pending_jobs.len(),
        };

        self.state_hash = hash_data(&input).unwrap_or([0u8; 32]);
        self.last_updated = chrono::Utc::now();
    }

    /// Check if a hotkey is the sudo key
    pub fn is_sudo(&self, hotkey: &Hotkey) -> bool {
        self.sudo_key == *hotkey
    }

    /// Add a validator
    pub fn add_validator(&mut self, info: ValidatorInfo) -> Result<()> {
        if self.validators.len() >= self.config.max_validators {
            return Err(crate::MiniChainError::Consensus(
                "Max validators reached".into(),
            ));
        }
        if info.stake < self.config.min_stake {
            return Err(crate::MiniChainError::Consensus(
                "Insufficient stake".into(),
            ));
        }
        self.validators.insert(info.hotkey.clone(), info);
        self.update_hash();
        Ok(())
    }

    /// Remove a validator
    pub fn remove_validator(&mut self, hotkey: &Hotkey) -> Option<ValidatorInfo> {
        let removed = self.validators.remove(hotkey);
        if removed.is_some() {
            self.update_hash();
        }
        removed
    }

    /// Get validator by hotkey
    pub fn get_validator(&self, hotkey: &Hotkey) -> Option<&ValidatorInfo> {
        self.validators.get(hotkey)
    }

    /// Get active validators
    pub fn active_validators(&self) -> Vec<&ValidatorInfo> {
        self.validators.values().filter(|v| v.is_active).collect()
    }

    /// Total stake of active validators
    pub fn total_stake(&self) -> Stake {
        Stake(self.active_validators().iter().map(|v| v.stake.0).sum())
    }

    /// Calculate consensus threshold (number of validators needed)
    pub fn consensus_threshold(&self) -> usize {
        let active = self.active_validators().len();
        ((active as f64) * self.config.consensus_threshold).ceil() as usize
    }

    /// Add a challenge
    pub fn add_challenge(&mut self, challenge: Challenge) {
        self.challenges.insert(challenge.id, challenge);
        self.update_hash();
    }

    /// Remove a challenge
    pub fn remove_challenge(&mut self, id: &ChallengeId) -> Option<Challenge> {
        let removed = self.challenges.remove(id);
        if removed.is_some() {
            self.update_hash();
        }
        removed
    }

    /// Get challenge by ID
    pub fn get_challenge(&self, id: &ChallengeId) -> Option<&Challenge> {
        self.challenges.get(id)
    }

    /// Add a pending job
    pub fn add_job(&mut self, job: Job) {
        self.pending_jobs.push(job);
        self.update_hash();
    }

    /// Get next pending job for a validator
    pub fn claim_job(&mut self, validator: &Hotkey) -> Option<Job> {
        if let Some(pos) = self
            .pending_jobs
            .iter()
            .position(|j| j.assigned_validator.is_none())
        {
            let mut job = self.pending_jobs.remove(pos);
            job.assigned_validator = Some(validator.clone());
            job.status = crate::JobStatus::Running;
            self.update_hash();
            Some(job)
        } else {
            None
        }
    }

    /// Increment block height
    pub fn increment_block(&mut self) {
        self.block_height += 1;
        self.update_hash();
    }

    /// Create a snapshot of the state
    pub fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            block_height: self.block_height,
            state_hash: self.state_hash,
            validator_count: self.validators.len(),
            challenge_count: self.challenges.len(),
            pending_jobs: self.pending_jobs.len(),
            timestamp: self.last_updated,
        }
    }
}

/// Lightweight state snapshot for sync
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub block_height: BlockHeight,
    pub state_hash: [u8; 32],
    pub validator_count: usize,
    pub challenge_count: usize,
    pub pending_jobs: usize,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChallengeConfig, Keypair};

    fn create_test_state() -> ChainState {
        let sudo = Keypair::generate();
        ChainState::new(sudo.hotkey(), NetworkConfig::default())
    }

    #[test]
    fn test_new_state() {
        let state = create_test_state();
        assert_eq!(state.block_height, 0);
        assert!(state.validators.is_empty());
        assert!(state.challenges.is_empty());
    }

    #[test]
    fn test_add_validator() {
        let mut state = create_test_state();
        let kp = Keypair::generate();
        let info = ValidatorInfo::new(kp.hotkey(), Stake::new(10_000_000_000));

        state.add_validator(info.clone()).unwrap();
        assert_eq!(state.validators.len(), 1);
        assert!(state.get_validator(&kp.hotkey()).is_some());
    }

    #[test]
    fn test_insufficient_stake() {
        let mut state = create_test_state();
        let kp = Keypair::generate();
        let info = ValidatorInfo::new(kp.hotkey(), Stake::new(100)); // Too low

        assert!(state.add_validator(info).is_err());
    }

    #[test]
    fn test_consensus_threshold() {
        let mut state = create_test_state();

        // Add 8 validators
        for _ in 0..8 {
            let kp = Keypair::generate();
            let info = ValidatorInfo::new(kp.hotkey(), Stake::new(10_000_000_000));
            state.add_validator(info).unwrap();
        }

        // 50% of 8 = 4
        assert_eq!(state.consensus_threshold(), 4);
    }

    #[test]
    fn test_state_hash_changes() {
        let mut state = create_test_state();
        let hash1 = state.state_hash;

        state.increment_block();
        let hash2 = state.state_hash;

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_remove_validator() {
        let mut state = create_test_state();
        let kp = Keypair::generate();
        let info = ValidatorInfo::new(kp.hotkey(), Stake::new(10_000_000_000));

        state.add_validator(info).unwrap();
        assert_eq!(state.validators.len(), 1);

        state.remove_validator(&kp.hotkey());
        assert_eq!(state.validators.len(), 0);
    }

    #[test]
    fn test_add_challenge() {
        let mut state = create_test_state();
        let challenge = Challenge::new(
            "Test Challenge".to_string(),
            "Description".to_string(),
            vec![0u8; 100],
            Keypair::generate().hotkey(),
            ChallengeConfig::default(),
        );

        let id = challenge.id;
        state.add_challenge(challenge);
        assert!(state.get_challenge(&id).is_some());
    }

    #[test]
    fn test_remove_challenge() {
        let mut state = create_test_state();
        let challenge = Challenge::new(
            "Test".to_string(),
            "Desc".to_string(),
            vec![0u8; 50],
            Keypair::generate().hotkey(),
            ChallengeConfig::default(),
        );

        let id = challenge.id;
        state.add_challenge(challenge);

        let removed = state.remove_challenge(&id);
        assert!(removed.is_some());
        assert!(state.get_challenge(&id).is_none());
    }

    #[test]
    fn test_add_job() {
        let mut state = create_test_state();
        let job = Job::new(ChallengeId::new(), "agent1".to_string());

        state.add_job(job);
        assert_eq!(state.pending_jobs.len(), 1);
    }

    #[test]
    fn test_claim_job() {
        let mut state = create_test_state();
        let job = Job::new(ChallengeId::new(), "agent1".to_string());
        state.add_job(job);

        let kp = Keypair::generate();
        let claimed = state.claim_job(&kp.hotkey());
        assert!(claimed.is_some());
        assert_eq!(claimed.unwrap().assigned_validator, Some(kp.hotkey()));
        assert_eq!(state.pending_jobs.len(), 0);
    }

    #[test]
    fn test_snapshot() {
        let mut state = create_test_state();
        state.increment_block();

        let snapshot = state.snapshot();
        assert_eq!(snapshot.block_height, 1);
        assert_eq!(snapshot.validator_count, 0);
        assert_eq!(snapshot.challenge_count, 0);
    }

    #[test]
    fn test_production_state() {
        let state = ChainState::new_production(NetworkConfig::production());
        // Production sudo key should be set
        assert!(!state.sudo_key.0.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_is_sudo() {
        let sudo_kp = Keypair::generate();
        let state = ChainState::new(sudo_kp.hotkey(), NetworkConfig::default());

        assert!(state.is_sudo(&sudo_kp.hotkey()));

        let other_kp = Keypair::generate();
        assert!(!state.is_sudo(&other_kp.hotkey()));
    }
}
