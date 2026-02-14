//! Tests for Bittensor integration

#[cfg(test)]
mod mock_metagraph_tests {
    use crate::mock::{
        create_test_metagraph, create_validators, hotkey_from_seed, MockMetagraphBuilder,
        MockNeuronBuilder,
    };
    use crate::validator_sync::{MetagraphValidator, ValidatorSync};
    use platform_core::{ChainState, Hotkey, Stake, ValidatorInfo};
    use sp_core::crypto::Ss58Codec;
    use std::collections::HashSet;
    use std::sync::Arc;

    #[test]
    fn test_mock_metagraph_with_validators() {
        let metagraph = MockMetagraphBuilder::new(100)
            .block(1000)
            .add_neuron(
                MockNeuronBuilder::new(0)
                    .hotkey(hotkey_from_seed(0))
                    .stake_tao(1000.0)
                    .root_stake_tao(500.0)
                    .incentive(0.8)
                    .trust(0.9)
                    .consensus(0.85)
                    .validator_permit(true)
                    .build(),
            )
            .add_neuron(
                MockNeuronBuilder::new(1)
                    .hotkey(hotkey_from_seed(1))
                    .stake_tao(500.0)
                    .incentive(0.6)
                    .trust(0.7)
                    .consensus(0.65)
                    .validator_permit(true)
                    .build(),
            )
            .add_neuron(
                MockNeuronBuilder::new(2)
                    .hotkey(hotkey_from_seed(2))
                    .stake(0) // Miner with no stake
                    .build(),
            )
            .build();

        assert_eq!(metagraph.netuid, 100);
        assert_eq!(metagraph.block, 1000);
        assert_eq!(metagraph.n, 3);
        assert_eq!(metagraph.neurons.len(), 3);

        // Verify validator 0
        let v0 = metagraph.neurons.get(&0).expect("validator 0");
        assert_eq!(v0.stake, 1_000_000_000_000); // 1000 TAO
        assert_eq!(v0.root_stake, 500_000_000_000); // 500 TAO

        // Verify validator 1
        let v1 = metagraph.neurons.get(&1).expect("validator 1");
        assert_eq!(v1.stake, 500_000_000_000); // 500 TAO

        // Verify miner has no stake
        let miner = metagraph.neurons.get(&2).expect("miner");
        assert_eq!(miner.stake, 0);
    }

    #[test]
    fn test_mock_metagraph_hotkey_is_valid_ss58() {
        let hotkey = hotkey_from_seed(42);
        let metagraph = MockMetagraphBuilder::new(1)
            .add_validator(0, hotkey, 100.0)
            .build();

        let neuron = metagraph.neurons.get(&0).expect("neuron");
        let ss58 = neuron.hotkey.to_ss58check();

        // Should be a valid SS58 address
        assert!(ss58.starts_with('5')); // Substrate addresses start with 5
        assert!(ss58.len() > 40);
    }

    #[test]
    fn test_create_validators_with_varying_stakes() {
        let validators = create_validators(10, 100.0, 1000.0);

        assert_eq!(validators.len(), 10);

        for (i, v) in validators.iter().enumerate() {
            assert_eq!(v.uid, i as u64);
            let stake_tao = v.stake as f64 / 1_000_000_000.0;
            assert!(
                (100.0..=1000.0).contains(&stake_tao),
                "Validator {} stake {} TAO out of range",
                i,
                stake_tao
            );
        }
    }

    #[test]
    fn test_parse_metagraph_extracts_validators_above_min_stake() {
        // Create metagraph with mix of high and low stake validators
        let metagraph = MockMetagraphBuilder::new(100)
            .add_neuron(
                MockNeuronBuilder::new(0)
                    .hotkey(hotkey_from_seed(0))
                    .stake_tao(2000.0) // Above min
                    .build(),
            )
            .add_neuron(
                MockNeuronBuilder::new(1)
                    .hotkey(hotkey_from_seed(1))
                    .stake_tao(500.0) // Below min
                    .build(),
            )
            .add_neuron(
                MockNeuronBuilder::new(2)
                    .hotkey(hotkey_from_seed(2))
                    .stake_tao(1500.0) // Above min
                    .build(),
            )
            .build();

        // Parse with min_stake of 1000 TAO
        let min_stake: u64 = 1_000_000_000_000; // 1000 TAO in RAO
        let mut above_min = Vec::new();

        for (uid, neuron) in &metagraph.neurons {
            let effective_stake = neuron.stake.saturating_add(neuron.root_stake);
            let stake = effective_stake.min(u64::MAX as u128) as u64;
            if stake >= min_stake {
                above_min.push(*uid);
            }
        }

        assert_eq!(above_min.len(), 2);
        assert!(above_min.contains(&0));
        assert!(above_min.contains(&2));
        assert!(!above_min.contains(&1));
    }

    #[test]
    fn test_metagraph_iteration_for_validator_sync() {
        let metagraph = create_test_metagraph(100, 5, 500.0);

        let mut validators = Vec::new();
        let min_stake: u64 = 100_000_000_000; // 100 TAO

        for (uid, neuron) in &metagraph.neurons {
            let hotkey_bytes: &[u8; 32] = neuron.hotkey.as_ref();
            let hotkey = Hotkey(*hotkey_bytes);

            let effective_stake = neuron.stake.saturating_add(neuron.root_stake);
            let stake = effective_stake.min(u64::MAX as u128) as u64;

            if stake >= min_stake {
                let incentive = neuron.incentive / u16::MAX as f64;
                let trust = neuron.trust / u16::MAX as f64;
                let consensus = neuron.consensus / u16::MAX as f64;

                validators.push(MetagraphValidator {
                    hotkey,
                    uid: *uid as u16,
                    stake,
                    active: stake > 0,
                    incentive,
                    trust,
                    consensus,
                });
            }
        }

        assert_eq!(validators.len(), 5);
        for v in &validators {
            assert!(v.active);
            assert!(v.stake >= min_stake);
        }
    }

    #[test]
    fn test_mock_metagraph_supports_removing_validators() {
        // Simulate metagraph state at block 1000
        let metagraph_t1 = MockMetagraphBuilder::new(100)
            .block(1000)
            .add_validator(0, hotkey_from_seed(0), 1000.0)
            .add_validator(1, hotkey_from_seed(1), 800.0)
            .add_validator(2, hotkey_from_seed(2), 600.0)
            .build();

        // Simulate metagraph state at block 2000 (validator 1 removed)
        let metagraph_t2 = MockMetagraphBuilder::new(100)
            .block(2000)
            .add_validator(0, hotkey_from_seed(0), 1000.0)
            .add_validator(2, hotkey_from_seed(2), 600.0)
            .build();

        assert_eq!(metagraph_t1.neurons.len(), 3);
        assert_eq!(metagraph_t2.neurons.len(), 2);

        // Verify validator 1 was removed
        assert!(metagraph_t1.neurons.contains_key(&1));
        assert!(!metagraph_t2.neurons.contains_key(&1));
    }

    #[test]
    fn test_mock_metagraph_supports_stake_changes() {
        // Initial state
        let metagraph_t1 = MockMetagraphBuilder::new(100)
            .block(1000)
            .add_neuron(
                MockNeuronBuilder::new(0)
                    .hotkey(hotkey_from_seed(0))
                    .stake_tao(1000.0)
                    .build(),
            )
            .build();

        // After stake increase
        let metagraph_t2 = MockMetagraphBuilder::new(100)
            .block(2000)
            .add_neuron(
                MockNeuronBuilder::new(0)
                    .hotkey(hotkey_from_seed(0))
                    .stake_tao(2000.0) // Stake doubled
                    .build(),
            )
            .build();

        let v0_t1 = metagraph_t1.neurons.get(&0).expect("validator at t1");
        let v0_t2 = metagraph_t2.neurons.get(&0).expect("validator at t2");

        assert_eq!(v0_t1.stake, 1_000_000_000_000);
        assert_eq!(v0_t2.stake, 2_000_000_000_000);
    }

    #[test]
    fn test_mock_metagraph_with_incentive_scores() {
        let metagraph = MockMetagraphBuilder::new(100)
            .add_neuron(
                MockNeuronBuilder::new(0)
                    .hotkey(hotkey_from_seed(0))
                    .stake_tao(1000.0)
                    .incentive(0.9) // 90% incentive
                    .trust(0.8) // 80% trust
                    .consensus(0.85) // 85% consensus
                    .build(),
            )
            .build();

        let neuron = metagraph.neurons.get(&0).expect("neuron");

        // Extract normalized scores as ValidatorSync does
        let incentive = neuron.incentive / u16::MAX as f64;
        let trust = neuron.trust / u16::MAX as f64;
        let consensus = neuron.consensus / u16::MAX as f64;

        assert!((incentive - 0.9).abs() < 0.001);
        assert!((trust - 0.8).abs() < 0.001);
        assert!((consensus - 0.85).abs() < 0.001);
    }

    #[test]
    fn test_hotkey_from_seed_is_deterministic_across_calls() {
        let hotkey1 = hotkey_from_seed(12345);
        let hotkey2 = hotkey_from_seed(12345);

        assert_eq!(hotkey1, hotkey2);

        // Build two metagraphs with same seed
        let mg1 = MockMetagraphBuilder::new(1)
            .add_validator(0, hotkey_from_seed(100), 500.0)
            .build();
        let mg2 = MockMetagraphBuilder::new(1)
            .add_validator(0, hotkey_from_seed(100), 500.0)
            .build();

        let n1 = mg1.neurons.get(&0).expect("neuron 1");
        let n2 = mg2.neurons.get(&0).expect("neuron 2");

        // Hotkeys should match
        let hk1: &[u8; 32] = n1.hotkey.as_ref();
        let hk2: &[u8; 32] = n2.hotkey.as_ref();
        assert_eq!(hk1, hk2);
    }

    #[test]
    fn test_effective_stake_combines_alpha_and_root() {
        let metagraph = MockMetagraphBuilder::new(100)
            .add_neuron(
                MockNeuronBuilder::new(0)
                    .hotkey(hotkey_from_seed(0))
                    .stake_tao(1000.0) // Alpha stake
                    .root_stake_tao(500.0) // Root stake
                    .build(),
            )
            .build();

        let neuron = metagraph.neurons.get(&0).expect("neuron");

        let effective_stake = neuron.stake.saturating_add(neuron.root_stake);
        let effective_tao = effective_stake as f64 / 1_000_000_000.0;

        assert!((effective_tao - 1500.0).abs() < 0.001);
    }
}

#[cfg(test)]
mod bittensor_tests {
    use crate::{BittensorConfig, SubtensorClient, WeightSubmitter, DEFAULT_NETUID};
    use platform_challenge_sdk::WeightAssignment;

    #[test]
    fn test_config_default() {
        let config = BittensorConfig::default();
        assert_eq!(config.netuid, DEFAULT_NETUID); // NETUID 100 by default
        assert!(config.use_commit_reveal);
        assert!(config.endpoint.contains("finney"));
    }

    #[test]
    fn test_config_testnet() {
        let config = BittensorConfig::testnet(42);
        assert_eq!(config.netuid, 42);
        assert!(config.endpoint.contains("test"));
    }

    #[test]
    fn test_config_local() {
        let config = BittensorConfig::local(1);
        assert_eq!(config.netuid, 1);
        assert!(!config.use_commit_reveal);
        assert!(config.endpoint.contains("127.0.0.1"));
    }

    #[test]
    fn test_client_creation() {
        let config = BittensorConfig::local(1);
        let client = SubtensorClient::new(config);
        assert_eq!(client.netuid(), 1);
        assert!(!client.use_commit_reveal());
    }

    #[test]
    fn test_submitter_creation() {
        let config = BittensorConfig::local(1);
        let client = SubtensorClient::new(config);
        let submitter = WeightSubmitter::new(client, None);
        assert!(!submitter.has_pending_commit());
    }

    #[test]
    fn test_normalize_to_u16() {
        use crate::weights::normalize_to_u16;

        let weights = vec![0.5, 0.3, 0.2];
        let normalized = normalize_to_u16(&weights);

        // Should sum to ~65535
        let sum: u32 = normalized.iter().map(|&w| w as u32).sum();
        assert!(sum > 65000 && sum <= 65535);

        // First should be largest
        assert!(normalized[0] > normalized[1]);
        assert!(normalized[1] > normalized[2]);
    }

    #[test]
    fn test_normalize_to_u16_zero() {
        use crate::weights::normalize_to_u16;

        let weights = vec![0.0, 0.0, 0.0];
        let normalized = normalize_to_u16(&weights);

        assert_eq!(normalized, vec![0, 0, 0]);
    }

    #[test]
    fn test_weight_assignment_conversion() {
        // Test that WeightAssignment can be created
        let assignment = WeightAssignment::new(
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
            0.5,
        );
        assert_eq!(assignment.weight, 0.5);
    }

    // Integration tests (require network)
    #[tokio::test]
    #[ignore] // Run with: cargo test -- --ignored
    async fn test_connect_to_testnet() {
        let config = BittensorConfig::testnet(1);
        let mut client = SubtensorClient::new(config);

        let result = client.connect().await;
        assert!(result.is_ok(), "Failed to connect to testnet");
    }

    #[tokio::test]
    #[ignore]
    async fn test_sync_metagraph() {
        let config = BittensorConfig::testnet(1);
        let mut client = SubtensorClient::new(config);

        client.connect().await.expect("Failed to connect");
        let metagraph = client.sync_metagraph().await;

        assert!(metagraph.is_ok(), "Failed to sync metagraph");
        let mg = metagraph.unwrap();
        assert!(mg.n > 0, "Metagraph should have neurons");
    }
}