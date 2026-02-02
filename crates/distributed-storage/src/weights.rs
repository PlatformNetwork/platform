//! Weight aggregation storage
//!
//! Types for storing and managing weight calculations and validator votes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Stored weights for an epoch
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredWeights {
    /// Challenge ID
    pub challenge_id: String,
    /// Epoch number
    pub epoch: u64,
    /// Final aggregated weights: (hotkey, weight)
    pub weights: Vec<(String, f64)>,
    /// Individual validator votes
    pub validator_votes: Vec<ValidatorWeightVote>,
    /// When the weights were aggregated
    pub aggregated_at: DateTime<Utc>,
    /// Hash of the weights (for verification)
    pub weights_hash: [u8; 32],
    /// Whether these weights have been submitted to Bittensor
    pub submitted_to_chain: bool,
    /// Block number when submitted (if applicable)
    pub submission_block: Option<u64>,
}

impl StoredWeights {
    /// Create new stored weights
    pub fn new(
        challenge_id: impl Into<String>,
        epoch: u64,
        weights: Vec<(String, f64)>,
        validator_votes: Vec<ValidatorWeightVote>,
    ) -> Self {
        let weights_hash = Self::compute_hash(&weights);

        Self {
            challenge_id: challenge_id.into(),
            epoch,
            weights,
            validator_votes,
            aggregated_at: Utc::now(),
            weights_hash,
            submitted_to_chain: false,
            submission_block: None,
        }
    }

    /// Compute hash of weights for verification
    fn compute_hash(weights: &[(String, f64)]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for (hotkey, weight) in weights {
            hasher.update(hotkey.as_bytes());
            hasher.update(weight.to_le_bytes());
        }
        hasher.finalize().into()
    }

    /// Mark weights as submitted to chain
    pub fn mark_submitted(&mut self, block: u64) {
        self.submitted_to_chain = true;
        self.submission_block = Some(block);
    }

    /// Verify the weights hash
    pub fn verify_hash(&self) -> bool {
        Self::compute_hash(&self.weights) == self.weights_hash
    }

    /// Get the weight for a specific hotkey
    pub fn get_weight(&self, hotkey: &str) -> Option<f64> {
        self.weights
            .iter()
            .find(|(h, _)| h == hotkey)
            .map(|(_, w)| *w)
    }

    /// Get top N weights
    pub fn top_n(&self, n: usize) -> Vec<(String, f64)> {
        let mut sorted = self.weights.clone();
        sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        sorted.truncate(n);
        sorted
    }

    /// Normalize weights to sum to 1.0
    pub fn normalize(&mut self) {
        let total: f64 = self.weights.iter().map(|(_, w)| *w).sum();
        if total > 0.0 {
            for (_, weight) in &mut self.weights {
                *weight /= total;
            }
        }
        self.weights_hash = Self::compute_hash(&self.weights);
    }

    /// Apply softmax normalization
    pub fn apply_softmax(&mut self, temperature: f64) {
        if self.weights.is_empty() {
            return;
        }

        // Find max for numerical stability
        let max_weight = self
            .weights
            .iter()
            .map(|(_, w)| *w)
            .fold(f64::NEG_INFINITY, f64::max);

        // Compute exp(w/T) for each weight
        let exp_weights: Vec<f64> = self
            .weights
            .iter()
            .map(|(_, w)| ((w - max_weight) / temperature).exp())
            .collect();

        let sum_exp: f64 = exp_weights.iter().sum();

        // Normalize
        for (i, (_, weight)) in self.weights.iter_mut().enumerate() {
            *weight = exp_weights[i] / sum_exp;
        }

        self.weights_hash = Self::compute_hash(&self.weights);
    }

    /// Serialize to bincode for storage
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from bincode
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// A validator's vote on weights for an epoch
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorWeightVote {
    /// Validator's hotkey (SS58 address)
    pub validator_hotkey: String,
    /// The weights this validator computed
    pub weights: Vec<(String, f64)>,
    /// Signature over the weights
    pub signature: Vec<u8>,
    /// When the vote was cast
    pub timestamp: DateTime<Utc>,
    /// Epoch this vote is for
    pub epoch: u64,
    /// Challenge ID
    pub challenge_id: String,
    /// Validator's stake at time of voting (for weighted aggregation)
    pub stake: u64,
}

impl ValidatorWeightVote {
    /// Create a new weight vote
    pub fn new(
        validator_hotkey: impl Into<String>,
        challenge_id: impl Into<String>,
        epoch: u64,
        weights: Vec<(String, f64)>,
        signature: Vec<u8>,
        stake: u64,
    ) -> Self {
        Self {
            validator_hotkey: validator_hotkey.into(),
            challenge_id: challenge_id.into(),
            epoch,
            weights,
            signature,
            timestamp: Utc::now(),
            stake,
        }
    }

    /// Get the message that should be signed
    pub fn signing_message(&self) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(self.challenge_id.as_bytes());
        message.extend_from_slice(&self.epoch.to_le_bytes());
        for (hotkey, weight) in &self.weights {
            message.extend_from_slice(hotkey.as_bytes());
            message.extend_from_slice(&weight.to_le_bytes());
        }
        message
    }

    /// Compute hash of the vote (for deduplication)
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.signing_message());
        hasher.update(&self.timestamp.timestamp_millis().to_le_bytes());
        hasher.finalize().into()
    }

    /// Get the weight for a specific hotkey
    pub fn get_weight(&self, hotkey: &str) -> Option<f64> {
        self.weights
            .iter()
            .find(|(h, _)| h == hotkey)
            .map(|(_, w)| *w)
    }
}

/// Aggregator for combining multiple validator votes into final weights
#[derive(Debug)]
pub struct WeightAggregator {
    /// Challenge ID
    challenge_id: String,
    /// Epoch
    epoch: u64,
    /// Collected votes
    votes: Vec<ValidatorWeightVote>,
}

impl WeightAggregator {
    /// Create a new aggregator
    pub fn new(challenge_id: impl Into<String>, epoch: u64) -> Self {
        Self {
            challenge_id: challenge_id.into(),
            epoch,
            votes: Vec::new(),
        }
    }

    /// Add a vote
    pub fn add_vote(&mut self, vote: ValidatorWeightVote) {
        // Only add if for the correct challenge and epoch
        if vote.challenge_id == self.challenge_id && vote.epoch == self.epoch {
            // Check for duplicate
            let exists = self
                .votes
                .iter()
                .any(|v| v.validator_hotkey == vote.validator_hotkey);
            if !exists {
                self.votes.push(vote);
            }
        }
    }

    /// Get the number of votes
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    /// Check if we have enough votes for quorum
    pub fn has_quorum(&self, required: usize) -> bool {
        self.votes.len() >= required
    }

    /// Aggregate votes using stake-weighted averaging
    pub fn aggregate_stake_weighted(&self) -> StoredWeights {
        if self.votes.is_empty() {
            return StoredWeights::new(
                self.challenge_id.clone(),
                self.epoch,
                Vec::new(),
                Vec::new(),
            );
        }

        // Collect all unique hotkeys
        let mut all_hotkeys: std::collections::HashSet<String> = std::collections::HashSet::new();
        for vote in &self.votes {
            for (hotkey, _) in &vote.weights {
                all_hotkeys.insert(hotkey.clone());
            }
        }

        // Compute stake-weighted average for each hotkey
        let total_stake: u64 = self.votes.iter().map(|v| v.stake).sum();

        let mut final_weights: Vec<(String, f64)> = Vec::new();

        for hotkey in all_hotkeys {
            let mut weighted_sum = 0.0;

            for vote in &self.votes {
                if let Some(weight) = vote.get_weight(&hotkey) {
                    weighted_sum += weight * (vote.stake as f64);
                }
            }

            if total_stake > 0 {
                final_weights.push((hotkey, weighted_sum / total_stake as f64));
            } else {
                // Equal weighting if no stakes
                let count = self.votes.len() as f64;
                let avg: f64 = self
                    .votes
                    .iter()
                    .filter_map(|v| v.get_weight(&hotkey))
                    .sum::<f64>()
                    / count;
                final_weights.push((hotkey, avg));
            }
        }

        // Sort by weight descending
        final_weights.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        StoredWeights::new(
            self.challenge_id.clone(),
            self.epoch,
            final_weights,
            self.votes.clone(),
        )
    }

    /// Aggregate votes using median (more outlier-resistant)
    pub fn aggregate_median(&self) -> StoredWeights {
        if self.votes.is_empty() {
            return StoredWeights::new(
                self.challenge_id.clone(),
                self.epoch,
                Vec::new(),
                Vec::new(),
            );
        }

        // Collect all unique hotkeys
        let mut all_hotkeys: std::collections::HashSet<String> = std::collections::HashSet::new();
        for vote in &self.votes {
            for (hotkey, _) in &vote.weights {
                all_hotkeys.insert(hotkey.clone());
            }
        }

        let mut final_weights: Vec<(String, f64)> = Vec::new();

        for hotkey in all_hotkeys {
            let mut weights: Vec<f64> = self
                .votes
                .iter()
                .filter_map(|v| v.get_weight(&hotkey))
                .collect();

            if weights.is_empty() {
                continue;
            }

            weights.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

            let len = weights.len();
            let median = if len % 2 == 0 {
                (weights[len / 2 - 1] + weights[len / 2]) / 2.0
            } else {
                weights[len / 2]
            };

            final_weights.push((hotkey, median));
        }

        // Sort by weight descending
        final_weights.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        StoredWeights::new(
            self.challenge_id.clone(),
            self.epoch,
            final_weights,
            self.votes.clone(),
        )
    }
}

/// Historical weight record for trend analysis
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightHistory {
    /// Challenge ID
    pub challenge_id: String,
    /// Miner hotkey
    pub hotkey: String,
    /// Weight values per epoch
    pub weights_by_epoch: Vec<(u64, f64)>,
}

impl WeightHistory {
    /// Create a new weight history
    pub fn new(challenge_id: impl Into<String>, hotkey: impl Into<String>) -> Self {
        Self {
            challenge_id: challenge_id.into(),
            hotkey: hotkey.into(),
            weights_by_epoch: Vec::new(),
        }
    }

    /// Add a weight for an epoch
    pub fn add_weight(&mut self, epoch: u64, weight: f64) {
        // Keep sorted by epoch
        let pos = self
            .weights_by_epoch
            .binary_search_by_key(&epoch, |(e, _)| *e)
            .unwrap_or_else(|p| p);

        if pos < self.weights_by_epoch.len() && self.weights_by_epoch[pos].0 == epoch {
            self.weights_by_epoch[pos].1 = weight;
        } else {
            self.weights_by_epoch.insert(pos, (epoch, weight));
        }
    }

    /// Get the latest weight
    pub fn latest_weight(&self) -> Option<(u64, f64)> {
        self.weights_by_epoch.last().copied()
    }

    /// Get the weight at a specific epoch
    pub fn weight_at_epoch(&self, epoch: u64) -> Option<f64> {
        self.weights_by_epoch
            .iter()
            .find(|(e, _)| *e == epoch)
            .map(|(_, w)| *w)
    }

    /// Calculate the moving average over the last N epochs
    pub fn moving_average(&self, n: usize) -> Option<f64> {
        if self.weights_by_epoch.is_empty() {
            return None;
        }

        let start = self.weights_by_epoch.len().saturating_sub(n);
        let weights: Vec<f64> = self.weights_by_epoch[start..]
            .iter()
            .map(|(_, w)| *w)
            .collect();

        if weights.is_empty() {
            return None;
        }

        Some(weights.iter().sum::<f64>() / weights.len() as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stored_weights_creation() {
        let weights = vec![
            ("miner1".to_string(), 0.5),
            ("miner2".to_string(), 0.3),
            ("miner3".to_string(), 0.2),
        ];

        let stored = StoredWeights::new("challenge1", 10, weights.clone(), vec![]);

        assert_eq!(stored.challenge_id, "challenge1");
        assert_eq!(stored.epoch, 10);
        assert_eq!(stored.weights.len(), 3);
        assert!(!stored.submitted_to_chain);
        assert!(stored.verify_hash());
    }

    #[test]
    fn test_stored_weights_normalize() {
        let weights = vec![
            ("m1".to_string(), 1.0),
            ("m2".to_string(), 2.0),
            ("m3".to_string(), 2.0),
        ];

        let mut stored = StoredWeights::new("c", 1, weights, vec![]);
        stored.normalize();

        let total: f64 = stored.weights.iter().map(|(_, w)| *w).sum();
        assert!((total - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_stored_weights_softmax() {
        let weights = vec![
            ("m1".to_string(), 1.0),
            ("m2".to_string(), 2.0),
            ("m3".to_string(), 3.0),
        ];

        let mut stored = StoredWeights::new("c", 1, weights, vec![]);
        stored.apply_softmax(1.0);

        let total: f64 = stored.weights.iter().map(|(_, w)| *w).sum();
        assert!((total - 1.0).abs() < 0.001);

        // Higher scores should have higher weights
        assert!(stored.get_weight("m3").unwrap() > stored.get_weight("m2").unwrap());
        assert!(stored.get_weight("m2").unwrap() > stored.get_weight("m1").unwrap());
    }

    #[test]
    fn test_stored_weights_top_n() {
        let weights = vec![
            ("m1".to_string(), 0.1),
            ("m2".to_string(), 0.5),
            ("m3".to_string(), 0.3),
            ("m4".to_string(), 0.1),
        ];

        let stored = StoredWeights::new("c", 1, weights, vec![]);
        let top2 = stored.top_n(2);

        assert_eq!(top2.len(), 2);
        assert_eq!(top2[0].0, "m2");
        assert_eq!(top2[1].0, "m3");
    }

    #[test]
    fn test_stored_weights_serialization() {
        let weights = vec![("m1".to_string(), 0.5)];
        let stored = StoredWeights::new("c", 1, weights, vec![]);

        let bytes = stored.to_bytes().expect("serialization failed");
        let decoded = StoredWeights::from_bytes(&bytes).expect("deserialization failed");

        assert_eq!(decoded.epoch, stored.epoch);
        assert!(decoded.verify_hash());
    }

    #[test]
    fn test_validator_vote_creation() {
        let vote = ValidatorWeightVote::new(
            "validator1",
            "challenge1",
            5,
            vec![("m1".to_string(), 0.7), ("m2".to_string(), 0.3)],
            vec![1, 2, 3, 4],
            1000,
        );

        assert_eq!(vote.validator_hotkey, "validator1");
        assert_eq!(vote.epoch, 5);
        assert_eq!(vote.stake, 1000);
        assert!(vote.get_weight("m1").is_some());
    }

    #[test]
    fn test_weight_aggregator_stake_weighted() {
        let mut aggregator = WeightAggregator::new("challenge1", 1);

        // Vote 1: 100 stake, gives m1=0.6, m2=0.4
        aggregator.add_vote(ValidatorWeightVote::new(
            "v1",
            "challenge1",
            1,
            vec![("m1".to_string(), 0.6), ("m2".to_string(), 0.4)],
            vec![],
            100,
        ));

        // Vote 2: 300 stake, gives m1=0.8, m2=0.2
        aggregator.add_vote(ValidatorWeightVote::new(
            "v2",
            "challenge1",
            1,
            vec![("m1".to_string(), 0.8), ("m2".to_string(), 0.2)],
            vec![],
            300,
        ));

        let result = aggregator.aggregate_stake_weighted();

        // m1: (0.6*100 + 0.8*300) / 400 = 0.75
        // m2: (0.4*100 + 0.2*300) / 400 = 0.25
        let m1_weight = result.get_weight("m1").unwrap();
        let m2_weight = result.get_weight("m2").unwrap();

        assert!((m1_weight - 0.75).abs() < 0.001);
        assert!((m2_weight - 0.25).abs() < 0.001);
    }

    #[test]
    fn test_weight_aggregator_median() {
        let mut aggregator = WeightAggregator::new("challenge1", 1);

        aggregator.add_vote(ValidatorWeightVote::new(
            "v1",
            "challenge1",
            1,
            vec![("m1".to_string(), 0.1)],
            vec![],
            100,
        ));

        aggregator.add_vote(ValidatorWeightVote::new(
            "v2",
            "challenge1",
            1,
            vec![("m1".to_string(), 0.5)],
            vec![],
            100,
        ));

        aggregator.add_vote(ValidatorWeightVote::new(
            "v3",
            "challenge1",
            1,
            vec![("m1".to_string(), 0.9)],
            vec![],
            100,
        ));

        let result = aggregator.aggregate_median();
        let m1_weight = result.get_weight("m1").unwrap();

        // Median of 0.1, 0.5, 0.9 = 0.5
        assert!((m1_weight - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_weight_aggregator_deduplicates() {
        let mut aggregator = WeightAggregator::new("challenge1", 1);

        let vote = ValidatorWeightVote::new(
            "v1",
            "challenge1",
            1,
            vec![("m1".to_string(), 0.5)],
            vec![],
            100,
        );

        aggregator.add_vote(vote.clone());
        aggregator.add_vote(vote);

        assert_eq!(aggregator.vote_count(), 1);
    }

    #[test]
    fn test_weight_aggregator_ignores_wrong_epoch() {
        let mut aggregator = WeightAggregator::new("challenge1", 1);

        aggregator.add_vote(ValidatorWeightVote::new(
            "v1",
            "challenge1",
            2, // Wrong epoch
            vec![("m1".to_string(), 0.5)],
            vec![],
            100,
        ));

        assert_eq!(aggregator.vote_count(), 0);
    }

    #[test]
    fn test_weight_history() {
        let mut history = WeightHistory::new("challenge1", "miner1");

        history.add_weight(1, 0.1);
        history.add_weight(2, 0.2);
        history.add_weight(3, 0.3);

        assert_eq!(history.latest_weight(), Some((3, 0.3)));
        assert_eq!(history.weight_at_epoch(2), Some(0.2));

        // Moving average of last 2
        let ma = history.moving_average(2).unwrap();
        assert!((ma - 0.25).abs() < 0.001);
    }

    #[test]
    fn test_weight_history_updates() {
        let mut history = WeightHistory::new("c", "m");

        history.add_weight(1, 0.1);
        history.add_weight(1, 0.5); // Update

        assert_eq!(history.weights_by_epoch.len(), 1);
        assert_eq!(history.weight_at_epoch(1), Some(0.5));
    }
}
