//! Mock implementations for Bittensor integration tests
//!
//! Provides mock structures that can simulate Bittensor metagraph state
//! without connecting to the real network.

use bittensor_rs::metagraph::Metagraph;
use bittensor_rs::types::NeuronInfo;
use sp_core::crypto::AccountId32;
use std::collections::HashMap;

/// Builder for creating mock neurons with configurable parameters
#[derive(Clone, Debug)]
pub struct MockNeuronBuilder {
    uid: u64,
    netuid: u16,
    hotkey: [u8; 32],
    coldkey: [u8; 32],
    stake: u128,
    root_stake: u128,
    incentive: f64,
    trust: f64,
    consensus: f64,
    dividends: f64,
    emission: f64,
    validator_permit: bool,
    last_update: u64,
    pruning_score: u64,
    validator_trust: f64,
    rank: f64,
    active: bool,
}

impl MockNeuronBuilder {
    /// Create a new neuron builder with default values
    pub fn new(uid: u64) -> Self {
        let mut hotkey = [0u8; 32];
        hotkey[0..8].copy_from_slice(&uid.to_le_bytes());

        Self {
            uid,
            netuid: 1,
            hotkey,
            coldkey: [0u8; 32],
            stake: 0,
            root_stake: 0,
            incentive: 0.0,
            trust: 0.0,
            consensus: 0.0,
            dividends: 0.0,
            emission: 0.0,
            validator_permit: false,
            last_update: 0,
            pruning_score: 0,
            validator_trust: 0.0,
            rank: 0.0,
            active: true,
        }
    }

    /// Set the netuid
    pub fn netuid(mut self, netuid: u16) -> Self {
        self.netuid = netuid;
        self
    }

    /// Set the hotkey bytes
    pub fn hotkey(mut self, hotkey: [u8; 32]) -> Self {
        self.hotkey = hotkey;
        self
    }

    /// Set the coldkey bytes
    pub fn coldkey(mut self, coldkey: [u8; 32]) -> Self {
        self.coldkey = coldkey;
        self
    }

    /// Set the stake in RAO (1 TAO = 1e9 RAO)
    pub fn stake(mut self, stake: u128) -> Self {
        self.stake = stake;
        self
    }

    /// Set stake in TAO (convenience method)
    pub fn stake_tao(mut self, tao: f64) -> Self {
        self.stake = (tao * 1_000_000_000.0) as u128;
        self
    }

    /// Set root stake in RAO
    pub fn root_stake(mut self, root_stake: u128) -> Self {
        self.root_stake = root_stake;
        self
    }

    /// Set root stake in TAO (convenience method)
    pub fn root_stake_tao(mut self, tao: f64) -> Self {
        self.root_stake = (tao * 1_000_000_000.0) as u128;
        self
    }

    /// Set incentive score (0.0 - 1.0 normalized, stored as f64)
    pub fn incentive(mut self, incentive: f64) -> Self {
        self.incentive = incentive * u16::MAX as f64;
        self
    }

    /// Set trust score (0.0 - 1.0 normalized, stored as f64)
    pub fn trust(mut self, trust: f64) -> Self {
        self.trust = trust * u16::MAX as f64;
        self
    }

    /// Set consensus score (0.0 - 1.0 normalized, stored as f64)
    pub fn consensus(mut self, consensus: f64) -> Self {
        self.consensus = consensus * u16::MAX as f64;
        self
    }

    /// Set dividends
    pub fn dividends(mut self, dividends: f64) -> Self {
        self.dividends = dividends * u16::MAX as f64;
        self
    }

    /// Set emission
    pub fn emission(mut self, emission: f64) -> Self {
        self.emission = emission;
        self
    }

    /// Set validator permit
    pub fn validator_permit(mut self, permit: bool) -> Self {
        self.validator_permit = permit;
        self
    }

    /// Set last update block
    pub fn last_update(mut self, block: u64) -> Self {
        self.last_update = block;
        self
    }

    /// Set pruning score
    pub fn pruning_score(mut self, score: u64) -> Self {
        self.pruning_score = score;
        self
    }

    /// Set validator trust
    pub fn validator_trust(mut self, trust: f64) -> Self {
        self.validator_trust = trust * u16::MAX as f64;
        self
    }

    /// Set rank
    pub fn rank(mut self, rank: f64) -> Self {
        self.rank = rank * u16::MAX as f64;
        self
    }

    /// Set active status
    pub fn active(mut self, active: bool) -> Self {
        self.active = active;
        self
    }

    /// Get the uid
    pub fn get_uid(&self) -> u64 {
        self.uid
    }

    /// Get the hotkey bytes
    pub fn get_hotkey(&self) -> [u8; 32] {
        self.hotkey
    }

    /// Build the neuron and return data needed to add to metagraph
    pub fn build(self) -> MockNeuronData {
        MockNeuronData {
            uid: self.uid,
            netuid: self.netuid,
            hotkey: self.hotkey,
            coldkey: self.coldkey,
            stake: self.stake,
            root_stake: self.root_stake,
            incentive: self.incentive,
            trust: self.trust,
            consensus: self.consensus,
            dividends: self.dividends,
            emission: self.emission,
            validator_permit: self.validator_permit,
            last_update: self.last_update,
            pruning_score: self.pruning_score,
            validator_trust: self.validator_trust,
            rank: self.rank,
            active: self.active,
        }
    }
}

/// Data for a mock neuron
#[derive(Clone, Debug)]
pub struct MockNeuronData {
    pub uid: u64,
    pub netuid: u16,
    pub hotkey: [u8; 32],
    pub coldkey: [u8; 32],
    pub stake: u128,
    pub root_stake: u128,
    pub incentive: f64,
    pub trust: f64,
    pub consensus: f64,
    pub dividends: f64,
    pub emission: f64,
    pub validator_permit: bool,
    pub last_update: u64,
    pub pruning_score: u64,
    pub validator_trust: f64,
    pub rank: f64,
    pub active: bool,
}

impl MockNeuronData {
    /// Convert to NeuronInfo for use in Metagraph
    pub fn to_neuron_info(&self) -> NeuronInfo {
        let hotkey = AccountId32::new(self.hotkey);
        let coldkey = AccountId32::new(self.coldkey);

        NeuronInfo {
            uid: self.uid,
            netuid: self.netuid,
            hotkey,
            coldkey,
            stake: self.stake,
            stake_dict: HashMap::new(),
            total_stake: self.stake,
            root_stake: self.root_stake,
            stake_weight: 0,
            rank: self.rank,
            trust: self.trust,
            consensus: self.consensus,
            validator_trust: self.validator_trust,
            incentive: self.incentive,
            emission: self.emission,
            dividends: self.dividends,
            active: self.active,
            last_update: self.last_update,
            validator_permit: self.validator_permit,
            version: 0,
            weights: Vec::new(),
            bonds: Vec::new(),
            pruning_score: self.pruning_score,
            prometheus_info: None,
            axon_info: None,
            is_null: false,
        }
    }
}

/// Builder for creating mock metagraphs
#[derive(Clone, Debug)]
pub struct MockMetagraphBuilder {
    netuid: u16,
    neurons: Vec<MockNeuronData>,
    block: u64,
    version: u64,
}

impl MockMetagraphBuilder {
    /// Create a new metagraph builder for the given netuid
    pub fn new(netuid: u16) -> Self {
        Self {
            netuid,
            neurons: Vec::new(),
            block: 0,
            version: 1,
        }
    }

    /// Set the current block number
    pub fn block(mut self, block: u64) -> Self {
        self.block = block;
        self
    }

    /// Set the version
    pub fn version(mut self, version: u64) -> Self {
        self.version = version;
        self
    }

    /// Add a neuron using the builder pattern
    pub fn add_neuron(mut self, neuron: MockNeuronData) -> Self {
        self.neurons.push(neuron);
        self
    }

    /// Add multiple neurons
    pub fn add_neurons(mut self, neurons: Vec<MockNeuronData>) -> Self {
        self.neurons.extend(neurons);
        self
    }

    /// Add a validator with specified parameters (convenience method)
    pub fn add_validator(self, uid: u64, hotkey: [u8; 32], stake_tao: f64) -> Self {
        let neuron = MockNeuronBuilder::new(uid)
            .netuid(self.netuid)
            .hotkey(hotkey)
            .stake_tao(stake_tao)
            .validator_permit(true)
            .active(true)
            .build();
        self.add_neuron(neuron)
    }

    /// Add a miner with specified parameters (convenience method)
    pub fn add_miner(self, uid: u64, hotkey: [u8; 32]) -> Self {
        let neuron = MockNeuronBuilder::new(uid)
            .netuid(self.netuid)
            .hotkey(hotkey)
            .stake(0)
            .active(true)
            .build();
        self.add_neuron(neuron)
    }

    /// Build the mock metagraph
    pub fn build(self) -> Metagraph {
        let mut neurons = HashMap::new();

        for data in &self.neurons {
            let neuron_info = data.to_neuron_info();
            neurons.insert(data.uid, neuron_info);
        }

        Metagraph {
            netuid: self.netuid,
            n: neurons.len() as u64,
            block: self.block,
            neurons,
            axons: HashMap::new(),
            version: self.version,
        }
    }
}

/// Helper function to create a random hotkey
pub fn random_hotkey() -> [u8; 32] {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut hotkey = [0u8; 32];
    rng.fill(&mut hotkey);
    hotkey
}

/// Helper function to create a hotkey from a deterministic seed
pub fn hotkey_from_seed(seed: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(seed.to_le_bytes());
    let result = hasher.finalize();
    let mut hotkey = [0u8; 32];
    hotkey.copy_from_slice(&result[..]);
    hotkey
}

/// Helper function to create multiple validators with sequential UIDs
pub fn create_validators(
    count: u16,
    min_stake_tao: f64,
    max_stake_tao: f64,
) -> Vec<MockNeuronData> {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    (0..count)
        .map(|uid| {
            let stake_tao = rng.gen_range(min_stake_tao..=max_stake_tao);
            MockNeuronBuilder::new(uid as u64)
                .hotkey(hotkey_from_seed(uid as u64))
                .stake_tao(stake_tao)
                .validator_permit(true)
                .active(true)
                .incentive(rng.gen_range(0.0..1.0))
                .trust(rng.gen_range(0.0..1.0))
                .consensus(rng.gen_range(0.0..1.0))
                .build()
        })
        .collect()
}

/// Helper function to create a metagraph with a specified number of validators
pub fn create_test_metagraph(netuid: u16, validator_count: u16, min_stake_tao: f64) -> Metagraph {
    let validators = create_validators(validator_count, min_stake_tao, min_stake_tao * 10.0);
    MockMetagraphBuilder::new(netuid)
        .add_neurons(validators)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_neuron_builder_defaults() {
        let neuron = MockNeuronBuilder::new(5).build();

        assert_eq!(neuron.uid, 5);
        assert_eq!(neuron.stake, 0);
        assert_eq!(neuron.root_stake, 0);
        assert_eq!(neuron.incentive, 0.0);
    }

    #[test]
    fn test_mock_neuron_builder_stake_tao() {
        let neuron = MockNeuronBuilder::new(1)
            .stake_tao(100.0)
            .root_stake_tao(50.0)
            .build();

        assert_eq!(neuron.stake, 100_000_000_000); // 100 TAO in RAO
        assert_eq!(neuron.root_stake, 50_000_000_000); // 50 TAO in RAO
    }

    #[test]
    fn test_mock_neuron_builder_scores() {
        let neuron = MockNeuronBuilder::new(1)
            .incentive(0.5)
            .trust(0.8)
            .consensus(0.9)
            .build();

        // Scores are stored as f64 * u16::MAX
        let expected_incentive = 0.5 * u16::MAX as f64;
        let expected_trust = 0.8 * u16::MAX as f64;
        let expected_consensus = 0.9 * u16::MAX as f64;

        assert!((neuron.incentive - expected_incentive).abs() < 0.001);
        assert!((neuron.trust - expected_trust).abs() < 0.001);
        assert!((neuron.consensus - expected_consensus).abs() < 0.001);
    }

    #[test]
    fn test_mock_metagraph_builder() {
        let hotkey1 = [1u8; 32];
        let hotkey2 = [2u8; 32];

        let metagraph = MockMetagraphBuilder::new(100)
            .block(5000)
            .add_validator(0, hotkey1, 1000.0)
            .add_validator(1, hotkey2, 500.0)
            .build();

        assert_eq!(metagraph.netuid, 100);
        assert_eq!(metagraph.n, 2);
        assert_eq!(metagraph.block, 5000);
        assert_eq!(metagraph.neurons.len(), 2);

        let neuron0 = metagraph.neurons.get(&0).expect("neuron 0 exists");
        let neuron1 = metagraph.neurons.get(&1).expect("neuron 1 exists");

        assert_eq!(neuron0.stake, 1_000_000_000_000);
        assert_eq!(neuron1.stake, 500_000_000_000);
    }

    #[test]
    fn test_mock_metagraph_add_miner() {
        let metagraph = MockMetagraphBuilder::new(1)
            .add_miner(0, [10u8; 32])
            .add_miner(1, [11u8; 32])
            .build();

        assert_eq!(metagraph.n, 2);

        for neuron in metagraph.neurons.values() {
            assert_eq!(neuron.stake, 0);
        }
    }

    #[test]
    fn test_hotkey_from_seed_deterministic() {
        let hotkey1 = hotkey_from_seed(42);
        let hotkey2 = hotkey_from_seed(42);
        let hotkey3 = hotkey_from_seed(43);

        assert_eq!(hotkey1, hotkey2);
        assert_ne!(hotkey1, hotkey3);
    }

    #[test]
    fn test_create_validators() {
        let validators = create_validators(5, 100.0, 1000.0);

        assert_eq!(validators.len(), 5);

        for (i, v) in validators.iter().enumerate() {
            assert_eq!(v.uid, i as u64);
            assert!(v.validator_permit);
            // Stake should be between 100 and 1000 TAO
            let stake_tao = v.stake as f64 / 1_000_000_000.0;
            assert!((100.0..=1000.0).contains(&stake_tao));
        }
    }

    #[test]
    fn test_create_test_metagraph() {
        let metagraph = create_test_metagraph(100, 10, 500.0);

        assert_eq!(metagraph.netuid, 100);
        assert_eq!(metagraph.n, 10);
        assert_eq!(metagraph.neurons.len(), 10);
    }

    #[test]
    fn test_metagraph_neuron_hotkey_conversion() {
        use sp_core::crypto::Ss58Codec;

        let hotkey_bytes = [1u8; 32];
        let metagraph = MockMetagraphBuilder::new(1)
            .add_validator(0, hotkey_bytes, 100.0)
            .build();

        let neuron = metagraph.neurons.get(&0).expect("neuron exists");

        // Verify the hotkey can be converted to SS58
        let ss58 = neuron.hotkey.to_ss58check();
        assert!(!ss58.is_empty());

        // Verify we can get the bytes back
        let hotkey_ref: &[u8; 32] = neuron.hotkey.as_ref();
        assert_eq!(hotkey_ref, &hotkey_bytes);
    }

    #[test]
    fn test_metagraph_has_required_fields() {
        let metagraph = MockMetagraphBuilder::new(100)
            .block(1000)
            .version(2)
            .add_validator(0, [1u8; 32], 500.0)
            .build();

        assert_eq!(metagraph.netuid, 100);
        assert_eq!(metagraph.block, 1000);
        assert_eq!(metagraph.version, 2);
        assert!(metagraph.axons.is_empty()); // No axons by default
    }

    #[test]
    fn test_neuron_info_conversion() {
        let data = MockNeuronBuilder::new(5)
            .netuid(100)
            .hotkey([1u8; 32])
            .stake_tao(1000.0)
            .root_stake_tao(500.0)
            .incentive(0.8)
            .trust(0.7)
            .consensus(0.9)
            .validator_permit(true)
            .active(true)
            .build();

        let neuron_info = data.to_neuron_info();

        assert_eq!(neuron_info.uid, 5);
        assert_eq!(neuron_info.netuid, 100);
        assert_eq!(neuron_info.stake, 1_000_000_000_000);
        assert_eq!(neuron_info.root_stake, 500_000_000_000);
        assert!(neuron_info.validator_permit);
        assert!(neuron_info.active);
        assert!(!neuron_info.is_null);
    }
}