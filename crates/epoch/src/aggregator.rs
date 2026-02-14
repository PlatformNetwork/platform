//! Weight aggregator
//!
//! Aggregates weights from multiple validators and challenges.

use crate::{AgentEmission, EmissionDistribution, EpochConfig, FinalizedWeights};
use platform_challenge_sdk::{ChallengeId, ChallengeMetadata};
use platform_core::Hotkey;
use std::collections::HashMap;
use tracing::{info, warn};

/// Aggregates weights across all challenges for emission distribution
///
/// Finalized weights already represent validator consensus output from the
/// commit-reveal flow. Challenge evaluation scores incorporate validator stake
/// and outlier filtering before reaching this aggregator.
pub struct WeightAggregator {
    config: EpochConfig,
}

impl WeightAggregator {
    pub fn new(config: EpochConfig) -> Self {
        Self { config }
    }

    /// Calculate emissions for an epoch
    ///
    /// Takes finalized weights from all challenges and distributes emissions
    /// according to each challenge's emission weight.
    pub fn calculate_emissions(
        &self,
        epoch: u64,
        total_emission: u64,
        challenges: &[ChallengeMetadata],
        finalized_weights: &HashMap<ChallengeId, FinalizedWeights>,
    ) -> EmissionDistribution {
        let mut distributions = Vec::new();

        // Normalize challenge emission weights
        let total_challenge_weight: f64 = challenges
            .iter()
            .filter(|c| c.is_active)
            .map(|c| c.emission_weight)
            .sum();

        if total_challenge_weight == 0.0 {
            warn!("No active challenges with emission weight");
            return EmissionDistribution {
                epoch,
                total_emission,
                distributions: vec![],
                timestamp: chrono::Utc::now(),
            };
        }

        for challenge in challenges {
            if !challenge.is_active {
                continue;
            }

            // Get finalized weights for this challenge
            let weights = match finalized_weights.get(&challenge.id) {
                Some(fw) => &fw.weights,
                None => {
                    warn!("No finalized weights for challenge {:?}", challenge.id);
                    continue;
                }
            };

            // Calculate challenge's share of total emission
            let challenge_share = challenge.emission_weight / total_challenge_weight;
            let challenge_emission = (total_emission as f64 * challenge_share) as u64;

            info!(
                "Challenge {} gets {}% ({} units) of emission",
                challenge.name,
                challenge_share * 100.0,
                challenge_emission
            );

            // Distribute to miners based on weights
            for weight in weights {
                let miner_emission = (challenge_emission as f64 * weight.weight) as u64;

                distributions.push(AgentEmission {
                    hotkey: weight.hotkey.clone(),
                    weight: weight.weight,
                    emission: miner_emission,
                    challenge_id: challenge.id,
                });
            }
        }

        // Merge emissions for same agent across challenges
        let merged = self.merge_agent_emissions(distributions);

        info!(
            "Epoch {} emission distribution: {} agents, {} total",
            epoch,
            merged.len(),
            total_emission
        );

        EmissionDistribution {
            epoch,
            total_emission,
            distributions: merged,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Merge emissions for same miner across multiple challenges
    fn merge_agent_emissions(&self, distributions: Vec<AgentEmission>) -> Vec<AgentEmission> {
        let mut by_miner: HashMap<String, Vec<AgentEmission>> = HashMap::new();

        for dist in distributions {
            by_miner.entry(dist.hotkey.clone()).or_default().push(dist);
        }

        by_miner
            .into_iter()
            .map(|(hotkey, emissions)| {
                let total_emission: u64 = emissions.iter().map(|e| e.emission).sum();
                let total_weight: f64 = emissions.iter().map(|e| e.weight).sum();

                // Use the first challenge_id (or could aggregate differently)
                let challenge_id = emissions
                    .first()
                    .map(|e| e.challenge_id)
                    .unwrap_or_else(ChallengeId::new);

                AgentEmission {
                    hotkey,
                    weight: total_weight / emissions.len() as f64,
                    emission: total_emission,
                    challenge_id,
                }
            })
            .collect()
    }

    /// Detect validators with suspicious weight patterns
    pub fn detect_suspicious_validators(
        &self,
        finalized_weights: &[FinalizedWeights],
    ) -> Vec<SuspiciousValidator> {
        let mut suspicious = Vec::new();

        for fw in finalized_weights {
            // Check for validators who were excluded
            for validator in &fw.excluded_validators {
                suspicious.push(SuspiciousValidator {
                    hotkey: validator.clone(),
                    reason: SuspicionReason::ExcludedFromConsensus,
                    challenge_id: fw.challenge_id,
                    epoch: fw.epoch,
                });
            }
        }

        suspicious
    }

    /// Calculate validator performance metrics
    pub fn validator_metrics(
        &self,
        validator: &Hotkey,
        history: &[FinalizedWeights],
    ) -> ValidatorMetrics {
        let mut participated = 0;
        let mut excluded = 0;

        for fw in history {
            if fw.participating_validators.contains(validator) {
                participated += 1;
            } else if fw.excluded_validators.contains(validator) {
                excluded += 1;
            }
        }

        let total = participated + excluded;
        let participation_rate = if total > 0 {
            participated as f64 / total as f64
        } else {
            0.0
        };

        ValidatorMetrics {
            hotkey: validator.clone(),
            epochs_participated: participated,
            epochs_excluded: excluded,
            participation_rate,
        }
    }
}

/// Suspicious validator report
#[derive(Clone, Debug)]
pub struct SuspiciousValidator {
    pub hotkey: Hotkey,
    pub reason: SuspicionReason,
    pub challenge_id: ChallengeId,
    pub epoch: u64,
}

/// Reason for suspicion
#[derive(Clone, Debug)]
pub enum SuspicionReason {
    /// Validator was excluded from consensus
    ExcludedFromConsensus,
    /// Validator's weights deviated significantly
    WeightDeviation { deviation: f64 },
    /// Validator didn't participate
    NoParticipation,
}

/// Validator performance metrics
#[derive(Clone, Debug)]
pub struct ValidatorMetrics {
    pub hotkey: Hotkey,
    pub epochs_participated: usize,
    pub epochs_excluded: usize,
    pub participation_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WeightAssignment;
    use platform_core::Keypair;

    fn create_test_challenge(name: &str, weight: f64) -> ChallengeMetadata {
        ChallengeMetadata {
            id: ChallengeId::new(),
            name: name.to_string(),
            description: "Test".to_string(),
            version: "1.0".to_string(),
            owner: Keypair::generate().hotkey(),
            emission_weight: weight,
            config: platform_challenge_sdk::ChallengeConfig::default(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            is_active: true,
        }
    }

    #[test]
    fn test_emission_distribution() {
        let aggregator = WeightAggregator::new(EpochConfig::default());

        let challenge1 = create_test_challenge("Challenge1", 0.6);
        let challenge2 = create_test_challenge("Challenge2", 0.4);

        let mut finalized = HashMap::new();

        finalized.insert(
            challenge1.id,
            FinalizedWeights {
                challenge_id: challenge1.id,
                epoch: 0,
                weights: vec![
                    WeightAssignment::new("agent1".to_string(), 0.7),
                    WeightAssignment::new("agent2".to_string(), 0.3),
                ],
                participating_validators: vec![],
                excluded_validators: vec![],
                smoothing_applied: 0.3,
                finalized_at: chrono::Utc::now(),
            },
        );

        finalized.insert(
            challenge2.id,
            FinalizedWeights {
                challenge_id: challenge2.id,
                epoch: 0,
                weights: vec![
                    WeightAssignment::new("agent1".to_string(), 0.5),
                    WeightAssignment::new("agent3".to_string(), 0.5),
                ],
                participating_validators: vec![],
                excluded_validators: vec![],
                smoothing_applied: 0.3,
                finalized_at: chrono::Utc::now(),
            },
        );

        let distribution =
            aggregator.calculate_emissions(0, 1000, &[challenge1, challenge2], &finalized);

        assert_eq!(distribution.epoch, 0);
        assert!(!distribution.distributions.is_empty());

        // Total emissions should approximately equal total_emission
        let total: u64 = distribution.distributions.iter().map(|d| d.emission).sum();
        assert!(total <= 1000);
    }

    #[test]
    fn test_no_active_challenges() {
        let aggregator = WeightAggregator::new(EpochConfig::default());

        let mut challenge = create_test_challenge("Challenge", 0.5);
        challenge.is_active = false;

        let distribution = aggregator.calculate_emissions(0, 1000, &[challenge], &HashMap::new());

        assert_eq!(distribution.distributions.len(), 0);
    }

    #[test]
    fn test_zero_emission_weight() {
        let aggregator = WeightAggregator::new(EpochConfig::default());

        let challenge = create_test_challenge("Challenge", 0.0);

        let distribution = aggregator.calculate_emissions(0, 1000, &[challenge], &HashMap::new());

        assert_eq!(distribution.distributions.len(), 0);
    }

    #[test]
    fn test_missing_finalized_weights() {
        let aggregator = WeightAggregator::new(EpochConfig::default());

        let challenge = create_test_challenge("Challenge", 0.5);

        // No finalized weights for this challenge
        let distribution = aggregator.calculate_emissions(0, 1000, &[challenge], &HashMap::new());

        assert_eq!(distribution.distributions.len(), 0);
    }

    #[test]
    fn test_merge_agent_emissions() {
        let aggregator = WeightAggregator::new(EpochConfig::default());

        let challenge1 = create_test_challenge("Challenge1", 0.5);
        let challenge2 = create_test_challenge("Challenge2", 0.5);

        let mut finalized = HashMap::new();

        // Same agent in both challenges
        finalized.insert(
            challenge1.id,
            FinalizedWeights {
                challenge_id: challenge1.id,
                epoch: 0,
                weights: vec![WeightAssignment::new("agent1".to_string(), 1.0)],
                participating_validators: vec![],
                excluded_validators: vec![],
                smoothing_applied: 0.0,
                finalized_at: chrono::Utc::now(),
            },
        );

        finalized.insert(
            challenge2.id,
            FinalizedWeights {
                challenge_id: challenge2.id,
                epoch: 0,
                weights: vec![WeightAssignment::new("agent1".to_string(), 1.0)],
                participating_validators: vec![],
                excluded_validators: vec![],
                smoothing_applied: 0.0,
                finalized_at: chrono::Utc::now(),
            },
        );

        let distribution =
            aggregator.calculate_emissions(0, 1000, &[challenge1, challenge2], &finalized);

        // agent1 should have merged emissions from both challenges
        assert_eq!(distribution.distributions.len(), 1);
        assert_eq!(distribution.distributions[0].hotkey, "agent1");
        assert!(distribution.distributions[0].emission > 0);
    }

    #[test]
    fn test_detect_suspicious_validators() {
        let aggregator = WeightAggregator::new(EpochConfig::default());

        let validator1 = Keypair::generate().hotkey();
        let validator2 = Keypair::generate().hotkey();

        let finalized = vec![FinalizedWeights {
            challenge_id: ChallengeId::new(),
            epoch: 0,
            weights: vec![],
            participating_validators: vec![],
            excluded_validators: vec![validator1.clone(), validator2.clone()],
            smoothing_applied: 0.0,
            finalized_at: chrono::Utc::now(),
        }];

        let suspicious = aggregator.detect_suspicious_validators(&finalized);
        assert_eq!(suspicious.len(), 2);
        assert!(suspicious.iter().any(|s| s.hotkey == validator1));
        assert!(suspicious.iter().any(|s| s.hotkey == validator2));
    }

    #[test]
    fn test_validator_metrics_full_participation() {
        let aggregator = WeightAggregator::new(EpochConfig::default());

        let validator = Keypair::generate().hotkey();

        let history = vec![
            FinalizedWeights {
                challenge_id: ChallengeId::new(),
                epoch: 0,
                weights: vec![],
                participating_validators: vec![validator.clone()],
                excluded_validators: vec![],
                smoothing_applied: 0.0,
                finalized_at: chrono::Utc::now(),
            },
            FinalizedWeights {
                challenge_id: ChallengeId::new(),
                epoch: 1,
                weights: vec![],
                participating_validators: vec![validator.clone()],
                excluded_validators: vec![],
                smoothing_applied: 0.0,
                finalized_at: chrono::Utc::now(),
            },
        ];

        let metrics = aggregator.validator_metrics(&validator, &history);
        assert_eq!(metrics.epochs_participated, 2);
        assert_eq!(metrics.epochs_excluded, 0);
        assert_eq!(metrics.participation_rate, 1.0);
    }

    #[test]
    fn test_validator_metrics_partial_participation() {
        let aggregator = WeightAggregator::new(EpochConfig::default());

        let validator = Keypair::generate().hotkey();

        let history = vec![
            FinalizedWeights {
                challenge_id: ChallengeId::new(),
                epoch: 0,
                weights: vec![],
                participating_validators: vec![validator.clone()],
                excluded_validators: vec![],
                smoothing_applied: 0.0,
                finalized_at: chrono::Utc::now(),
            },
            FinalizedWeights {
                challenge_id: ChallengeId::new(),
                epoch: 1,
                weights: vec![],
                participating_validators: vec![],
                excluded_validators: vec![validator.clone()],
                smoothing_applied: 0.0,
                finalized_at: chrono::Utc::now(),
            },
        ];

        let metrics = aggregator.validator_metrics(&validator, &history);
        assert_eq!(metrics.epochs_participated, 1);
        assert_eq!(metrics.epochs_excluded, 1);
        assert_eq!(metrics.participation_rate, 0.5);
    }

    #[test]
    fn test_validator_metrics_no_history() {
        let aggregator = WeightAggregator::new(EpochConfig::default());

        let validator = Keypair::generate().hotkey();
        let metrics = aggregator.validator_metrics(&validator, &[]);

        assert_eq!(metrics.epochs_participated, 0);
        assert_eq!(metrics.epochs_excluded, 0);
        assert_eq!(metrics.participation_rate, 0.0);
    }

    #[test]
    fn test_suspicion_reason_variants() {
        let reason1 = SuspicionReason::ExcludedFromConsensus;
        let reason2 = SuspicionReason::WeightDeviation { deviation: 0.5 };
        let reason3 = SuspicionReason::NoParticipation;

        // Just verify we can create all variants
        assert!(matches!(reason1, SuspicionReason::ExcludedFromConsensus));
        assert!(matches!(reason2, SuspicionReason::WeightDeviation { .. }));
        assert!(matches!(reason3, SuspicionReason::NoParticipation));
    }

    #[test]
    fn test_emission_with_multiple_weights() {
        let aggregator = WeightAggregator::new(EpochConfig::default());

        let challenge1 = create_test_challenge("Challenge1", 0.3);
        let challenge2 = create_test_challenge("Challenge2", 0.7);

        let mut finalized = HashMap::new();

        finalized.insert(
            challenge1.id,
            FinalizedWeights {
                challenge_id: challenge1.id,
                epoch: 0,
                weights: vec![
                    WeightAssignment::new("agent1".to_string(), 0.8),
                    WeightAssignment::new("agent2".to_string(), 0.2),
                ],
                participating_validators: vec![],
                excluded_validators: vec![],
                smoothing_applied: 0.3,
                finalized_at: chrono::Utc::now(),
            },
        );

        finalized.insert(
            challenge2.id,
            FinalizedWeights {
                challenge_id: challenge2.id,
                epoch: 0,
                weights: vec![
                    WeightAssignment::new("agent3".to_string(), 0.4),
                    WeightAssignment::new("agent4".to_string(), 0.6),
                ],
                participating_validators: vec![],
                excluded_validators: vec![],
                smoothing_applied: 0.3,
                finalized_at: chrono::Utc::now(),
            },
        );

        let distribution =
            aggregator.calculate_emissions(0, 10000, &[challenge1, challenge2], &finalized);

        assert_eq!(distribution.epoch, 0);
        assert!(!distribution.distributions.is_empty());

        // Verify distribution proportions
        let total: u64 = distribution.distributions.iter().map(|d| d.emission).sum();
        assert!(total <= 10000);
    }

    #[test]
    fn test_empty_finalized_weights() {
        let aggregator = WeightAggregator::new(EpochConfig::default());

        let challenge = create_test_challenge("Challenge", 0.5);

        let mut finalized = HashMap::new();
        finalized.insert(
            challenge.id,
            FinalizedWeights {
                challenge_id: challenge.id,
                epoch: 0,
                weights: vec![], // Empty weights
                participating_validators: vec![],
                excluded_validators: vec![],
                smoothing_applied: 0.0,
                finalized_at: chrono::Utc::now(),
            },
        );

        let distribution = aggregator.calculate_emissions(0, 1000, &[challenge], &finalized);

        // Should handle empty weights gracefully
        assert_eq!(distribution.epoch, 0);
    }
}
