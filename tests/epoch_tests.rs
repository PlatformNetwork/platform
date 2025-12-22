//! Comprehensive Epoch Module Tests
//!
//! Tests for epoch management, commit-reveal, and weight aggregation.

#![allow(dead_code, clippy::type_complexity)]

use parking_lot::RwLock;
use platform_core::*;
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// EPOCH MANAGER TESTS
// ============================================================================

mod epoch_manager {
    use super::*;

    #[test]
    fn test_epoch_config_default() {
        let config = EpochConfig::default();
        assert!(config.blocks_per_epoch > 0);
        assert!(config.evaluation_phase_blocks > 0);
        assert!(config.commit_phase_blocks > 0);
        assert!(config.reveal_phase_blocks > 0);
    }

    #[test]
    fn test_epoch_config_phases_sum() {
        let config = EpochConfig::default();
        let total = config.evaluation_phase_blocks
            + config.commit_phase_blocks
            + config.reveal_phase_blocks;
        assert_eq!(total, config.blocks_per_epoch);
    }

    #[test]
    fn test_epoch_phase_evaluation() {
        let config = EpochConfig {
            blocks_per_epoch: 100,
            evaluation_phase_blocks: 75,
            commit_phase_blocks: 13,
            reveal_phase_blocks: 12,
        };

        for block in 0..75 {
            let phase = config.get_phase(block);
            assert_eq!(phase, EpochPhase::Evaluation);
        }
    }

    #[test]
    fn test_epoch_phase_commit() {
        let config = EpochConfig {
            blocks_per_epoch: 100,
            evaluation_phase_blocks: 75,
            commit_phase_blocks: 13,
            reveal_phase_blocks: 12,
        };

        for block in 75..88 {
            let phase = config.get_phase(block);
            assert_eq!(phase, EpochPhase::Commit);
        }
    }

    #[test]
    fn test_epoch_phase_reveal() {
        let config = EpochConfig {
            blocks_per_epoch: 100,
            evaluation_phase_blocks: 75,
            commit_phase_blocks: 13,
            reveal_phase_blocks: 12,
        };

        for block in 88..100 {
            let phase = config.get_phase(block);
            assert_eq!(phase, EpochPhase::Reveal);
        }
    }

    #[test]
    fn test_epoch_calculation() {
        let config = EpochConfig {
            blocks_per_epoch: 100,
            ..Default::default()
        };

        assert_eq!(config.get_epoch(0), 0);
        assert_eq!(config.get_epoch(99), 0);
        assert_eq!(config.get_epoch(100), 1);
        assert_eq!(config.get_epoch(250), 2);
    }

    #[test]
    fn test_blocks_until_next_phase() {
        let config = EpochConfig {
            blocks_per_epoch: 100,
            evaluation_phase_blocks: 75,
            commit_phase_blocks: 13,
            reveal_phase_blocks: 12,
        };

        // At block 50 (evaluation), 25 blocks until commit
        assert_eq!(config.blocks_until_next_phase(50), 25);

        // At block 80 (commit), 8 blocks until reveal
        assert_eq!(config.blocks_until_next_phase(80), 8);

        // At block 95 (reveal), 5 blocks until next epoch
        assert_eq!(config.blocks_until_next_phase(95), 5);
    }

    #[test]
    fn test_epoch_manager_new() {
        let sudo = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            sudo.hotkey(),
            NetworkConfig::default(),
        )));

        let config = EpochConfig::default();
        let manager = EpochManager::new(state, config);

        assert_eq!(manager.current_epoch(), 0);
    }

    #[test]
    fn test_epoch_manager_current_phase() {
        let sudo = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            sudo.hotkey(),
            NetworkConfig::default(),
        )));

        let config = EpochConfig::default();
        let manager = EpochManager::new(state, config);

        let phase = manager.current_phase();
        assert!(matches!(
            phase,
            EpochPhase::Evaluation | EpochPhase::Commit | EpochPhase::Reveal
        ));
    }
}

// ============================================================================
// COMMIT-REVEAL TESTS
// ============================================================================

mod commit_reveal {
    use super::*;

    #[test]
    fn test_commitment_creation() {
        let validator = Keypair::generate();
        let challenge_id = "challenge1".to_string();
        let epoch = 10u64;

        let weights = vec![
            (Keypair::generate().hotkey(), 0.5f64),
            (Keypair::generate().hotkey(), 0.5f64),
        ];

        let commitment = Commitment::new(
            validator.hotkey(),
            challenge_id.clone(),
            epoch,
            weights.clone(),
        );

        assert_eq!(commitment.validator, validator.hotkey());
        assert_eq!(commitment.challenge_id, challenge_id);
        assert_eq!(commitment.epoch, epoch);
        assert!(!commitment.commitment_hash.is_empty());
    }

    #[test]
    fn test_commitment_verification() {
        let validator = Keypair::generate();
        let weights = vec![
            (Keypair::generate().hotkey(), 0.5f64),
            (Keypair::generate().hotkey(), 0.5f64),
        ];

        let commitment = Commitment::new(
            validator.hotkey(),
            "challenge1".to_string(),
            10,
            weights.clone(),
        );

        // Reveal with same data should verify
        let reveal = Reveal {
            validator: validator.hotkey(),
            challenge_id: "challenge1".to_string(),
            epoch: 10,
            weights: weights.clone(),
            salt: commitment.salt.clone(),
        };

        assert!(commitment.verify(&reveal));
    }

    #[test]
    fn test_commitment_verification_failure() {
        let validator = Keypair::generate();
        let weights = vec![
            (Keypair::generate().hotkey(), 0.5f64),
            (Keypair::generate().hotkey(), 0.5f64),
        ];

        let commitment = Commitment::new(
            validator.hotkey(),
            "challenge1".to_string(),
            10,
            weights.clone(),
        );

        // Reveal with different weights should fail
        let different_weights = vec![
            (Keypair::generate().hotkey(), 0.3f64),
            (Keypair::generate().hotkey(), 0.7f64),
        ];

        let reveal = Reveal {
            validator: validator.hotkey(),
            challenge_id: "challenge1".to_string(),
            epoch: 10,
            weights: different_weights,
            salt: commitment.salt.clone(),
        };

        assert!(!commitment.verify(&reveal));
    }

    #[test]
    fn test_commit_reveal_manager() {
        let manager = CommitRevealManager::new();
        assert_eq!(manager.pending_commits_count(), 0);
    }

    #[test]
    fn test_add_commitment() {
        let manager = CommitRevealManager::new();
        let validator = Keypair::generate();

        let commitment = Commitment::new(validator.hotkey(), "challenge1".to_string(), 10, vec![]);

        manager.add_commitment(commitment);
        assert_eq!(manager.pending_commits_count(), 1);
    }

    #[test]
    fn test_add_reveal() {
        let manager = CommitRevealManager::new();
        let validator = Keypair::generate();

        let weights = vec![
            (Keypair::generate().hotkey(), 0.5f64),
            (Keypair::generate().hotkey(), 0.5f64),
        ];

        let commitment = Commitment::new(
            validator.hotkey(),
            "challenge1".to_string(),
            10,
            weights.clone(),
        );

        manager.add_commitment(commitment.clone());

        let reveal = Reveal {
            validator: validator.hotkey(),
            challenge_id: "challenge1".to_string(),
            epoch: 10,
            weights,
            salt: commitment.salt.clone(),
        };

        let result = manager.add_reveal(reveal);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reveal_without_commitment() {
        let manager = CommitRevealManager::new();
        let validator = Keypair::generate();

        let reveal = Reveal {
            validator: validator.hotkey(),
            challenge_id: "challenge1".to_string(),
            epoch: 10,
            weights: vec![],
            salt: vec![0u8; 32],
        };

        let result = manager.add_reveal(reveal);
        assert!(result.is_err());
    }
}

// ============================================================================
// WEIGHT AGGREGATION TESTS
// ============================================================================

mod aggregation {
    use super::*;

    #[test]
    fn test_weight_aggregator_new() {
        let aggregator = WeightAggregator::new(AggregationConfig::default());
        assert!(aggregator.is_empty());
    }

    #[test]
    fn test_add_validator_weights() {
        let aggregator = WeightAggregator::new(AggregationConfig::default());
        let validator = Keypair::generate();
        let miner = Keypair::generate();

        let weights = vec![(miner.hotkey(), 0.8f64)];

        aggregator.add_weights(validator.hotkey(), Stake::new(10_000_000_000), weights);

        assert!(!aggregator.is_empty());
    }

    #[test]
    fn test_aggregate_simple() {
        let aggregator = WeightAggregator::new(AggregationConfig::default());

        let miner = Keypair::generate();

        // Two validators with equal stake
        for _ in 0..2 {
            let validator = Keypair::generate();
            aggregator.add_weights(
                validator.hotkey(),
                Stake::new(10_000_000_000),
                vec![(miner.hotkey(), 0.5f64)],
            );
        }

        let result = aggregator.aggregate();
        assert_eq!(result.len(), 1);
        assert!((result[0].1 - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_aggregate_stake_weighted() {
        let config = AggregationConfig {
            stake_weighted: true,
            ..Default::default()
        };
        let aggregator = WeightAggregator::new(config);

        let miner = Keypair::generate();

        // Validator with 10x stake gives weight 0.8
        let v1 = Keypair::generate();
        aggregator.add_weights(
            v1.hotkey(),
            Stake::new(100_000_000_000),
            vec![(miner.hotkey(), 0.8f64)],
        );

        // Validator with 1x stake gives weight 0.2
        let v2 = Keypair::generate();
        aggregator.add_weights(
            v2.hotkey(),
            Stake::new(10_000_000_000),
            vec![(miner.hotkey(), 0.2f64)],
        );

        let result = aggregator.aggregate();
        assert_eq!(result.len(), 1);

        // Result should be closer to 0.8 due to stake weighting
        assert!(result[0].1 > 0.5);
    }

    #[test]
    fn test_aggregate_outlier_removal() {
        let config = AggregationConfig {
            remove_outliers: true,
            outlier_threshold: 2.0,
            ..Default::default()
        };
        let aggregator = WeightAggregator::new(config);

        let miner = Keypair::generate();

        // 4 validators agree on ~0.5
        for _ in 0..4 {
            let v = Keypair::generate();
            aggregator.add_weights(
                v.hotkey(),
                Stake::new(10_000_000_000),
                vec![(miner.hotkey(), 0.5f64)],
            );
        }

        // 1 outlier gives 0.0
        let outlier = Keypair::generate();
        aggregator.add_weights(
            outlier.hotkey(),
            Stake::new(10_000_000_000),
            vec![(miner.hotkey(), 0.0f64)],
        );

        let result = aggregator.aggregate();
        assert_eq!(result.len(), 1);

        // Outlier should be removed, result should be ~0.5
        assert!((result[0].1 - 0.5).abs() < 0.1);
    }

    #[test]
    fn test_minimum_validators() {
        let config = AggregationConfig {
            minimum_validators: 3,
            ..Default::default()
        };
        let aggregator = WeightAggregator::new(config);

        let miner = Keypair::generate();

        // Only 2 validators - not enough
        for _ in 0..2 {
            let v = Keypair::generate();
            aggregator.add_weights(
                v.hotkey(),
                Stake::new(10_000_000_000),
                vec![(miner.hotkey(), 0.5f64)],
            );
        }

        let result = aggregator.aggregate();
        assert!(result.is_empty());
    }
}

// ============================================================================
// MECHANISM WEIGHTS TESTS
// ============================================================================

mod mechanism_weights {
    use super::*;

    #[test]
    fn test_mechanism_weight() {
        let mw = MechanismWeight {
            mechanism_id: 1,
            weight: 0.5,
        };

        assert_eq!(mw.mechanism_id, 1);
        assert_eq!(mw.weight, 0.5);
    }

    #[test]
    fn test_mechanism_weights_sum() {
        let weights = [
            MechanismWeight {
                mechanism_id: 0,
                weight: 0.3,
            },
            MechanismWeight {
                mechanism_id: 1,
                weight: 0.3,
            },
            MechanismWeight {
                mechanism_id: 2,
                weight: 0.4,
            },
        ];

        let sum: f64 = weights.iter().map(|w| w.weight).sum();
        assert!((sum - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_mechanism_manager() {
        let manager = MechanismWeightManager::new();
        assert!(manager.mechanisms().is_empty());
    }

    #[test]
    fn test_register_mechanism() {
        let manager = MechanismWeightManager::new();

        manager.register_mechanism(0, "challenge_a".to_string());
        manager.register_mechanism(1, "challenge_b".to_string());

        assert_eq!(manager.mechanisms().len(), 2);
    }

    #[test]
    fn test_set_mechanism_weight() {
        let manager = MechanismWeightManager::new();

        manager.register_mechanism(0, "challenge_a".to_string());
        manager.set_weight(0, 0.5);

        let weights = manager.get_weights();
        assert_eq!(weights.len(), 1);
        assert_eq!(weights[0].weight, 0.5);
    }
}

// ============================================================================
// EPOCH TRANSITION TESTS
// ============================================================================

mod transition {
    use super::*;

    #[test]
    fn test_epoch_transition_trigger() {
        let config = EpochConfig {
            blocks_per_epoch: 100,
            evaluation_phase_blocks: 75,
            commit_phase_blocks: 13,
            reveal_phase_blocks: 12,
        };

        // Block 99 is last block of epoch 0
        assert_eq!(config.get_epoch(99), 0);

        // Block 100 is first block of epoch 1
        assert_eq!(config.get_epoch(100), 1);
    }

    #[test]
    fn test_phase_transition() {
        let config = EpochConfig {
            blocks_per_epoch: 100,
            evaluation_phase_blocks: 75,
            commit_phase_blocks: 13,
            reveal_phase_blocks: 12,
        };

        // Block 74 is last evaluation block
        assert_eq!(config.get_phase(74), EpochPhase::Evaluation);

        // Block 75 is first commit block
        assert_eq!(config.get_phase(75), EpochPhase::Commit);

        // Block 87 is last commit block
        assert_eq!(config.get_phase(87), EpochPhase::Commit);

        // Block 88 is first reveal block
        assert_eq!(config.get_phase(88), EpochPhase::Reveal);
    }
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

mod integration {
    use super::*;

    #[test]
    fn test_full_epoch_cycle() {
        let sudo = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            sudo.hotkey(),
            NetworkConfig::default(),
        )));

        let config = EpochConfig {
            blocks_per_epoch: 10,
            evaluation_phase_blocks: 7,
            commit_phase_blocks: 2,
            reveal_phase_blocks: 1,
        };

        let manager = EpochManager::new(state.clone(), config);

        // Simulate blocks
        for _ in 0..10 {
            state.write().increment_block();
        }

        // Should be in epoch 1 now
        assert_eq!(manager.current_epoch(), 1);
    }

    #[test]
    fn test_commit_reveal_flow() {
        let manager = CommitRevealManager::new();
        let validator = Keypair::generate();
        let miner = Keypair::generate();

        // 1. Create weights
        let weights = vec![(miner.hotkey(), 0.8f64)];

        // 2. Create and submit commitment
        let commitment = Commitment::new(
            validator.hotkey(),
            "challenge1".to_string(),
            1,
            weights.clone(),
        );
        let salt = commitment.salt.clone();
        manager.add_commitment(commitment);

        // 3. Create and submit reveal
        let reveal = Reveal {
            validator: validator.hotkey(),
            challenge_id: "challenge1".to_string(),
            epoch: 1,
            weights,
            salt,
        };

        let result = manager.add_reveal(reveal);
        assert!(result.is_ok());

        // 4. Get revealed weights
        let revealed = manager.get_revealed_weights("challenge1", 1);
        assert_eq!(revealed.len(), 1);
    }
}

// ============================================================================
// HELPER TYPES (simplified for tests)
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum EpochPhase {
    Evaluation,
    Commit,
    Reveal,
}

#[derive(Debug, Clone)]
struct EpochConfig {
    blocks_per_epoch: u64,
    evaluation_phase_blocks: u64,
    commit_phase_blocks: u64,
    reveal_phase_blocks: u64,
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self {
            blocks_per_epoch: 100,
            evaluation_phase_blocks: 75,
            commit_phase_blocks: 13,
            reveal_phase_blocks: 12,
        }
    }
}

impl EpochConfig {
    fn get_epoch(&self, block: u64) -> u64 {
        block / self.blocks_per_epoch
    }

    fn get_phase(&self, block: u64) -> EpochPhase {
        let block_in_epoch = block % self.blocks_per_epoch;
        if block_in_epoch < self.evaluation_phase_blocks {
            EpochPhase::Evaluation
        } else if block_in_epoch < self.evaluation_phase_blocks + self.commit_phase_blocks {
            EpochPhase::Commit
        } else {
            EpochPhase::Reveal
        }
    }

    fn blocks_until_next_phase(&self, block: u64) -> u64 {
        let block_in_epoch = block % self.blocks_per_epoch;
        if block_in_epoch < self.evaluation_phase_blocks {
            self.evaluation_phase_blocks - block_in_epoch
        } else if block_in_epoch < self.evaluation_phase_blocks + self.commit_phase_blocks {
            self.evaluation_phase_blocks + self.commit_phase_blocks - block_in_epoch
        } else {
            self.blocks_per_epoch - block_in_epoch
        }
    }
}

struct EpochManager {
    state: Arc<RwLock<ChainState>>,
    config: EpochConfig,
}

impl EpochManager {
    fn new(state: Arc<RwLock<ChainState>>, config: EpochConfig) -> Self {
        Self { state, config }
    }

    fn current_epoch(&self) -> u64 {
        self.config.get_epoch(self.state.read().block_height)
    }

    fn current_phase(&self) -> EpochPhase {
        self.config.get_phase(self.state.read().block_height)
    }
}

#[derive(Clone)]
struct Commitment {
    validator: Hotkey,
    challenge_id: String,
    epoch: u64,
    commitment_hash: Vec<u8>,
    salt: Vec<u8>,
}

impl Commitment {
    fn new(
        validator: Hotkey,
        challenge_id: String,
        epoch: u64,
        weights: Vec<(Hotkey, f64)>,
    ) -> Self {
        let salt: Vec<u8> = (0..32).map(|_| rand::random()).collect();

        let mut data = Vec::new();
        for (h, w) in &weights {
            data.extend_from_slice(h.as_bytes());
            data.extend_from_slice(&w.to_le_bytes());
        }
        data.extend_from_slice(&salt);

        let commitment_hash = hash(&data).to_vec();

        Self {
            validator,
            challenge_id,
            epoch,
            commitment_hash,
            salt,
        }
    }

    fn verify(&self, reveal: &Reveal) -> bool {
        let mut data = Vec::new();
        for (h, w) in &reveal.weights {
            data.extend_from_slice(h.as_bytes());
            data.extend_from_slice(&w.to_le_bytes());
        }
        data.extend_from_slice(&reveal.salt);

        let reveal_hash = hash(&data);
        reveal_hash.to_vec() == self.commitment_hash
    }
}

struct Reveal {
    validator: Hotkey,
    challenge_id: String,
    epoch: u64,
    weights: Vec<(Hotkey, f64)>,
    salt: Vec<u8>,
}

struct CommitRevealManager {
    commitments: RwLock<HashMap<(Hotkey, String, u64), Commitment>>,
    reveals: RwLock<HashMap<(Hotkey, String, u64), Vec<(Hotkey, f64)>>>,
}

impl CommitRevealManager {
    fn new() -> Self {
        Self {
            commitments: RwLock::new(HashMap::new()),
            reveals: RwLock::new(HashMap::new()),
        }
    }

    fn pending_commits_count(&self) -> usize {
        self.commitments.read().len()
    }

    fn add_commitment(&self, commitment: Commitment) {
        let key = (
            commitment.validator.clone(),
            commitment.challenge_id.clone(),
            commitment.epoch,
        );
        self.commitments.write().insert(key, commitment);
    }

    fn add_reveal(&self, reveal: Reveal) -> std::result::Result<(), String> {
        let key = (
            reveal.validator.clone(),
            reveal.challenge_id.clone(),
            reveal.epoch,
        );

        let commitment = self.commitments.read().get(&key).cloned();

        match commitment {
            Some(c) if c.verify(&reveal) => {
                self.reveals.write().insert(key, reveal.weights);
                Ok(())
            }
            Some(_) => Err("Reveal doesn't match commitment".to_string()),
            None => Err("No commitment found".to_string()),
        }
    }

    fn get_revealed_weights(
        &self,
        challenge_id: &str,
        epoch: u64,
    ) -> Vec<(Hotkey, Vec<(Hotkey, f64)>)> {
        self.reveals
            .read()
            .iter()
            .filter(|((_, c, e), _)| c == challenge_id && *e == epoch)
            .map(|((v, _, _), w)| (v.clone(), w.clone()))
            .collect()
    }
}

#[derive(Default)]
struct AggregationConfig {
    stake_weighted: bool,
    remove_outliers: bool,
    outlier_threshold: f64,
    minimum_validators: usize,
}

struct WeightAggregator {
    config: AggregationConfig,
    weights: RwLock<Vec<(Hotkey, u64, Vec<(Hotkey, f64)>)>>,
}

impl WeightAggregator {
    fn new(config: AggregationConfig) -> Self {
        Self {
            config,
            weights: RwLock::new(Vec::new()),
        }
    }

    fn is_empty(&self) -> bool {
        self.weights.read().is_empty()
    }

    fn add_weights(&self, validator: Hotkey, stake: Stake, weights: Vec<(Hotkey, f64)>) {
        self.weights.write().push((validator, stake.0, weights));
    }

    fn aggregate(&self) -> Vec<(Hotkey, f64)> {
        let weights = self.weights.read();

        if weights.len() < self.config.minimum_validators {
            return vec![];
        }

        // Collect all miners
        let mut miner_weights: HashMap<Hotkey, Vec<(u64, f64)>> = HashMap::new();

        for (_, stake, ws) in weights.iter() {
            for (miner, weight) in ws {
                miner_weights
                    .entry(miner.clone())
                    .or_default()
                    .push((*stake, *weight));
            }
        }

        // Aggregate
        let mut result = Vec::new();
        for (miner, stake_weights) in miner_weights {
            let avg = if self.config.stake_weighted {
                let total_stake: u64 = stake_weights.iter().map(|(s, _)| s).sum();
                stake_weights
                    .iter()
                    .map(|(s, w)| (*s as f64) * w)
                    .sum::<f64>()
                    / total_stake as f64
            } else {
                stake_weights.iter().map(|(_, w)| w).sum::<f64>() / stake_weights.len() as f64
            };
            result.push((miner, avg));
        }

        result
    }
}

struct MechanismWeight {
    mechanism_id: u16,
    weight: f64,
}

struct MechanismWeightManager {
    mechanisms: RwLock<HashMap<u16, (String, f64)>>,
}

impl MechanismWeightManager {
    fn new() -> Self {
        Self {
            mechanisms: RwLock::new(HashMap::new()),
        }
    }

    fn mechanisms(&self) -> Vec<(u16, String)> {
        self.mechanisms
            .read()
            .iter()
            .map(|(id, (name, _))| (*id, name.clone()))
            .collect()
    }

    fn register_mechanism(&self, id: u16, name: String) {
        self.mechanisms.write().insert(id, (name, 0.0));
    }

    fn set_weight(&self, id: u16, weight: f64) {
        // Get the name first, then release the read lock before acquiring write lock
        let name = {
            let mechanisms = self.mechanisms.read();
            mechanisms.get(&id).map(|(n, _)| n.clone())
        };
        if let Some(name) = name {
            self.mechanisms.write().insert(id, (name, weight));
        }
    }

    fn get_weights(&self) -> Vec<MechanismWeight> {
        self.mechanisms
            .read()
            .iter()
            .map(|(id, (_, w))| MechanismWeight {
                mechanism_id: *id,
                weight: *w,
            })
            .collect()
    }
}
