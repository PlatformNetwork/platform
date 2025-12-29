//! Mechanism Weight Manager
//!
//! Groups weights from multiple challenges by mechanism_id for batch submission to Bittensor.
//! Each challenge is mapped to a mechanism (1:1 relationship).
//!
//! Weight Distribution:
//! - Each challenge has an emission_weight (0.0 - 1.0) defining its share of total emissions
//! - Challenge scores are passed through as-is (no normalization/manipulation)
//! - Remaining weight (1.0 - emission_weight) goes to UID 0 (burn address)

use parking_lot::RwLock;
use platform_challenge_sdk::{ChallengeId, WeightAssignment};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// UID 0 is the burn address - receives unused emission weight
pub const BURN_UID: u16 = 0;

/// Maximum weight value for Bittensor
pub const MAX_WEIGHT: u16 = 65535;

/// Weight data for a single mechanism
#[derive(Clone, Debug)]
pub struct MechanismWeights {
    /// Mechanism ID (u8 as per Bittensor)
    pub mechanism_id: u8,
    /// Challenge that produced these weights
    pub challenge_id: ChallengeId,
    /// Agent UIDs (converted from hashes)
    pub uids: Vec<u16>,
    /// Normalized weights (u16 format for Bittensor)
    pub weights: Vec<u16>,
    /// Original float weights for reference
    pub raw_weights: Vec<WeightAssignment>,
    /// Emission weight for this challenge (0.0 - 1.0)
    pub emission_weight: f64,
}

/// Hotkey to UID mapping from metagraph
pub type HotkeyUidMap = HashMap<String, u16>;

impl MechanismWeights {
    /// Create new MechanismWeights with emission-based distribution
    ///
    /// WARNING: This method creates weights without hotkey->UID mapping.
    /// All weights will go to UID 0 (burn) since no hotkeys can be resolved.
    /// For production use, prefer `with_hotkey_mapping()` with metagraph data.
    ///
    /// - emission_weight: fraction of total emissions this challenge controls (0.0 - 1.0)
    /// - assignments: raw scores from challenge (will be scaled by emission_weight)
    /// - Remaining weight goes to UID 0 (burn)
    pub fn new(
        mechanism_id: u8,
        challenge_id: ChallengeId,
        assignments: Vec<WeightAssignment>,
        emission_weight: f64,
    ) -> Self {
        warn!(
            "MechanismWeights::new() called without hotkey mapping - \
             all weights will go to UID 0 (burn). Use with_hotkey_mapping() in production."
        );
        Self::with_hotkey_mapping(
            mechanism_id,
            challenge_id,
            assignments,
            emission_weight,
            &HashMap::new(),
        )
    }

    /// Create with hotkey to UID mapping from metagraph
    pub fn with_hotkey_mapping(
        mechanism_id: u8,
        challenge_id: ChallengeId,
        assignments: Vec<WeightAssignment>,
        emission_weight: f64,
        hotkey_to_uid: &HotkeyUidMap,
    ) -> Self {
        let emission_weight = emission_weight.clamp(0.0, 1.0);
        let (uids, weights) =
            Self::convert_to_bittensor_format(&assignments, emission_weight, hotkey_to_uid);
        Self {
            mechanism_id,
            challenge_id,
            uids,
            weights,
            raw_weights: assignments,
            emission_weight,
        }
    }

    /// Convert WeightAssignment to Bittensor format with emission scaling
    ///
    /// Example: emission_weight = 0.1 (10%)
    /// - Challenge returns [Agent A (hotkey1): 0.6, Agent B (hotkey2): 0.4]
    /// - Look up UIDs from metagraph: hotkey1 -> UID 5, hotkey2 -> UID 12
    /// - After scaling: UID 5: 6%, UID 12: 4%, UID 0: 90%
    fn convert_to_bittensor_format(
        assignments: &[WeightAssignment],
        emission_weight: f64,
        hotkey_to_uid: &HotkeyUidMap,
    ) -> (Vec<u16>, Vec<u16>) {
        if assignments.is_empty() || emission_weight <= 0.0 {
            // No challenge weights - all to UID 0
            return (vec![BURN_UID], vec![MAX_WEIGHT]);
        }

        // Normalize challenge scores to sum to 1.0
        let total: f64 = assignments.iter().map(|a| a.weight).sum();
        if total <= 0.0 {
            return (vec![BURN_UID], vec![MAX_WEIGHT]);
        }

        let mut uids = Vec::with_capacity(assignments.len() + 1);
        let mut weights = Vec::with_capacity(assignments.len() + 1);
        let mut used_weight: u64 = 0;
        let mut skipped_no_uid = 0;

        // Add challenge agent weights (scaled by emission_weight)
        for assignment in assignments.iter() {
            // Look up UID from hotkey via metagraph
            let uid = if let Some(&uid) = hotkey_to_uid.get(&assignment.hotkey) {
                uid
            } else {
                // Hotkey not found in metagraph - skip this assignment
                debug!(
                    "Hotkey {} not found in metagraph, skipping weight assignment",
                    assignment.hotkey
                );
                skipped_no_uid += 1;
                continue;
            };

            // Skip UID 0 as it's reserved for burn
            if uid == BURN_UID {
                debug!("Skipping UID 0 assignment (reserved for burn)");
                continue;
            }

            // Scale: (score / total) * emission_weight * MAX_WEIGHT
            let normalized_score = assignment.weight / total;
            let scaled_weight =
                (normalized_score * emission_weight * MAX_WEIGHT as f64).round() as u16;

            if scaled_weight > 0 {
                uids.push(uid);
                weights.push(scaled_weight);
                used_weight += scaled_weight as u64;
            }
        }

        // Remaining weight goes to UID 0 (burn)
        let burn_weight = MAX_WEIGHT.saturating_sub(used_weight as u16);
        if burn_weight > 0 {
            uids.insert(0, BURN_UID);
            weights.insert(0, burn_weight);
        }

        info!(
            "Weight distribution: {}% to {} agents, {}% to UID 0 (burn){}",
            (emission_weight * 100.0).round(),
            uids.len().saturating_sub(1), // Exclude UID 0 from count
            ((burn_weight as f64 / MAX_WEIGHT as f64) * 100.0).round(),
            if skipped_no_uid > 0 {
                format!(", {} skipped (no UID)", skipped_no_uid)
            } else {
                String::new()
            }
        );

        (uids, weights)
    }

    /// Get weights as tuple for batch submission
    pub fn as_batch_tuple(&self) -> (u8, Vec<u16>, Vec<u16>) {
        (self.mechanism_id, self.uids.clone(), self.weights.clone())
    }
}

/// Manages weights grouped by mechanism for an epoch
pub struct MechanismWeightManager {
    /// Epoch number
    epoch: u64,
    /// Weights per mechanism (mechanism_id -> MechanismWeights)
    weights: RwLock<HashMap<u8, MechanismWeights>>,
    /// Challenge to mechanism mapping
    challenge_mechanism_map: RwLock<HashMap<ChallengeId, u8>>,
}

impl MechanismWeightManager {
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            weights: RwLock::new(HashMap::new()),
            challenge_mechanism_map: RwLock::new(HashMap::new()),
        }
    }

    /// Register a challenge with its mechanism
    pub fn register_challenge(&self, challenge_id: ChallengeId, mechanism_id: u8) {
        self.challenge_mechanism_map
            .write()
            .insert(challenge_id, mechanism_id);
        debug!(
            "Registered challenge {:?} with mechanism {}",
            challenge_id, mechanism_id
        );
    }

    /// Submit weights from a challenge
    ///
    /// - emission_weight: fraction of total emissions this challenge controls (0.0 - 1.0)
    /// - hotkey_to_uid: mapping from hotkey (SS58) to UID from metagraph
    /// - Remaining weight (1.0 - emission_weight) automatically goes to UID 0 (burn)
    pub fn submit_weights(
        &self,
        challenge_id: ChallengeId,
        mechanism_id: u8,
        weights: Vec<WeightAssignment>,
        emission_weight: f64,
    ) {
        // No hotkey mapping - use fallback UIDs
        self.submit_weights_with_metagraph(
            challenge_id,
            mechanism_id,
            weights,
            emission_weight,
            &HashMap::new(),
        )
    }

    /// Submit weights with hotkey to UID mapping from metagraph
    pub fn submit_weights_with_metagraph(
        &self,
        challenge_id: ChallengeId,
        mechanism_id: u8,
        weights: Vec<WeightAssignment>,
        emission_weight: f64,
        hotkey_to_uid: &HotkeyUidMap,
    ) {
        let mech_weights = MechanismWeights::with_hotkey_mapping(
            mechanism_id,
            challenge_id,
            weights,
            emission_weight,
            hotkey_to_uid,
        );
        self.weights.write().insert(mechanism_id, mech_weights);

        info!(
            "Submitted weights for mechanism {} from challenge {:?}: {} UIDs, {}% emission",
            mechanism_id,
            challenge_id,
            self.weights
                .read()
                .get(&mechanism_id)
                .map(|w| w.uids.len().saturating_sub(1)) // Exclude UID 0
                .unwrap_or(0),
            (emission_weight * 100.0).round()
        );
    }

    /// Get all mechanism weights for batch submission
    pub fn get_all_mechanism_weights(&self) -> Vec<(u8, Vec<u16>, Vec<u16>)> {
        self.weights
            .read()
            .values()
            .map(|w| w.as_batch_tuple())
            .collect()
    }

    /// Get weights for a specific mechanism
    pub fn get_mechanism_weights(&self, mechanism_id: u8) -> Option<MechanismWeights> {
        self.weights.read().get(&mechanism_id).cloned()
    }

    /// Get mechanism ID for a challenge
    pub fn get_mechanism_for_challenge(&self, challenge_id: &ChallengeId) -> Option<u8> {
        self.challenge_mechanism_map
            .read()
            .get(challenge_id)
            .copied()
    }

    /// Get all registered mechanisms
    pub fn list_mechanisms(&self) -> Vec<u8> {
        self.weights.read().keys().copied().collect()
    }

    /// Clear all weights (for new epoch)
    pub fn clear(&self) {
        self.weights.write().clear();
    }

    /// Get epoch
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Get number of mechanisms with weights
    pub fn mechanism_count(&self) -> usize {
        self.weights.read().len()
    }
}

/// Commit data for a mechanism
#[derive(Clone, Debug)]
pub struct MechanismCommitment {
    pub mechanism_id: u8,
    pub epoch: u64,
    pub commit_hash: [u8; 32],
    pub salt: Vec<u8>,
}

impl MechanismCommitment {
    pub fn new(mechanism_id: u8, epoch: u64, weights: &MechanismWeights, salt: &[u8]) -> Self {
        let commit_hash = Self::compute_hash(&weights.uids, &weights.weights, salt);
        Self {
            mechanism_id,
            epoch,
            commit_hash,
            salt: salt.to_vec(),
        }
    }

    /// Compute commit hash for commit-reveal
    fn compute_hash(uids: &[u16], weights: &[u16], salt: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        // Hash UIDs
        for uid in uids {
            hasher.update(uid.to_le_bytes());
        }

        // Hash weights
        for w in weights {
            hasher.update(w.to_le_bytes());
        }

        // Hash salt
        hasher.update(salt);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Get commit hash as hex string
    pub fn hash_hex(&self) -> String {
        hex::encode(self.commit_hash)
    }
}

/// Manages commit-reveal per mechanism
pub struct MechanismCommitRevealManager {
    /// Current epoch
    epoch: RwLock<u64>,
    /// Commitments per mechanism
    commitments: RwLock<HashMap<u8, MechanismCommitment>>,
    /// Revealed weights per mechanism
    revealed: RwLock<HashMap<u8, MechanismWeights>>,
}

impl MechanismCommitRevealManager {
    pub fn new() -> Self {
        Self {
            epoch: RwLock::new(0),
            commitments: RwLock::new(HashMap::new()),
            revealed: RwLock::new(HashMap::new()),
        }
    }

    /// Start new epoch
    pub fn new_epoch(&self, epoch: u64) {
        *self.epoch.write() = epoch;
        self.commitments.write().clear();
        self.revealed.write().clear();
        info!("MechanismCommitReveal: new epoch {}", epoch);
    }

    /// Commit weights for a mechanism
    pub fn commit(&self, commitment: MechanismCommitment) {
        debug!(
            "Committing weights for mechanism {} epoch {}: hash={}",
            commitment.mechanism_id,
            commitment.epoch,
            commitment.hash_hex()
        );
        self.commitments
            .write()
            .insert(commitment.mechanism_id, commitment);
    }

    /// Reveal weights for a mechanism
    pub fn reveal(&self, mechanism_id: u8, weights: MechanismWeights) -> Result<(), String> {
        let commitment = self
            .commitments
            .read()
            .get(&mechanism_id)
            .cloned()
            .ok_or_else(|| format!("No commitment for mechanism {}", mechanism_id))?;

        // Verify hash matches
        let expected_hash =
            MechanismCommitment::compute_hash(&weights.uids, &weights.weights, &commitment.salt);

        if expected_hash != commitment.commit_hash {
            return Err(format!(
                "Commitment mismatch for mechanism {}: expected {}, got {}",
                mechanism_id,
                hex::encode(commitment.commit_hash),
                hex::encode(expected_hash)
            ));
        }

        debug!(
            "Revealed weights for mechanism {}: {} weights",
            mechanism_id,
            weights.weights.len()
        );
        self.revealed.write().insert(mechanism_id, weights);
        Ok(())
    }

    /// Get all revealed weights for batch submission
    pub fn get_revealed_weights(&self) -> Vec<(u8, Vec<u16>, Vec<u16>)> {
        self.revealed
            .read()
            .values()
            .map(|w| w.as_batch_tuple())
            .collect()
    }

    /// Check if all committed mechanisms have been revealed
    pub fn all_revealed(&self) -> bool {
        let commitments = self.commitments.read();
        let revealed = self.revealed.read();
        commitments.keys().all(|m| revealed.contains_key(m))
    }

    /// Get commitment for a mechanism
    pub fn get_commitment(&self, mechanism_id: u8) -> Option<MechanismCommitment> {
        self.commitments.read().get(&mechanism_id).cloned()
    }

    /// Get all commitments
    pub fn get_all_commitments(&self) -> Vec<MechanismCommitment> {
        self.commitments.read().values().cloned().collect()
    }
}

impl Default for MechanismCommitRevealManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mechanism_weights_with_emission() {
        let assignments = vec![
            WeightAssignment::new("hotkey1".to_string(), 0.6),
            WeightAssignment::new("hotkey2".to_string(), 0.4),
        ];

        // Create hotkey -> UID mapping
        let mut hotkey_to_uid: HotkeyUidMap = HashMap::new();
        hotkey_to_uid.insert("hotkey1".to_string(), 1);
        hotkey_to_uid.insert("hotkey2".to_string(), 2);

        // 10% emission weight - challenge controls 10% of total emissions
        let mech_weights = MechanismWeights::with_hotkey_mapping(
            1,
            ChallengeId::new(),
            assignments,
            0.1,
            &hotkey_to_uid,
        );

        // Should have 3 UIDs: UID 0 (burn) + 2 miners
        assert_eq!(mech_weights.uids.len(), 3);
        assert_eq!(mech_weights.weights.len(), 3);

        // UID 0 should be first (burn address)
        assert_eq!(mech_weights.uids[0], BURN_UID);

        // Weights should sum to MAX_WEIGHT (65535)
        let sum: u32 = mech_weights.weights.iter().map(|w| *w as u32).sum();
        assert!(
            (65530..=65540).contains(&sum),
            "Sum should be ~65535, got {}",
            sum
        );

        // UID 0 should get ~90% (since emission_weight is 10%)
        let burn_weight = mech_weights.weights[0] as f64 / MAX_WEIGHT as f64;
        assert!(
            burn_weight > 0.89 && burn_weight < 0.91,
            "Burn should be ~90%, got {}",
            burn_weight * 100.0
        );
    }

    #[test]
    fn test_mechanism_weights_full_emission() {
        let assignments = vec![
            WeightAssignment::new("hotkey1".to_string(), 0.6),
            WeightAssignment::new("hotkey2".to_string(), 0.4),
        ];

        // Create hotkey -> UID mapping
        let mut hotkey_to_uid: HotkeyUidMap = HashMap::new();
        hotkey_to_uid.insert("hotkey1".to_string(), 1);
        hotkey_to_uid.insert("hotkey2".to_string(), 2);

        // 100% emission weight - challenge controls all emissions
        let mech_weights = MechanismWeights::with_hotkey_mapping(
            1,
            ChallengeId::new(),
            assignments,
            1.0,
            &hotkey_to_uid,
        );

        // Should have 2 UIDs (no burn needed when emission is 100%)
        assert!(mech_weights.uids.len() >= 2);

        // Weights should sum to MAX_WEIGHT
        let sum: u32 = mech_weights.weights.iter().map(|w| *w as u32).sum();
        assert!(
            (65530..=65540).contains(&sum),
            "Sum should be ~65535, got {}",
            sum
        );
    }

    #[test]
    fn test_mechanism_weight_manager() {
        let manager = MechanismWeightManager::new(1);

        let challenge1 = ChallengeId::new();
        let challenge2 = ChallengeId::new();

        manager.register_challenge(challenge1, 1);
        manager.register_challenge(challenge2, 2);

        let weights1 = vec![WeightAssignment::new("a".to_string(), 0.5)];
        let weights2 = vec![WeightAssignment::new("b".to_string(), 0.5)];

        // Each challenge gets 50% emission
        manager.submit_weights(challenge1, 1, weights1, 0.5);
        manager.submit_weights(challenge2, 2, weights2, 0.5);

        let all_weights = manager.get_all_mechanism_weights();
        assert_eq!(all_weights.len(), 2);
    }

    #[test]
    fn test_commit_reveal() {
        let manager = MechanismCommitRevealManager::new();
        manager.new_epoch(1);

        let weights = MechanismWeights::new(
            1,
            ChallengeId::new(),
            vec![WeightAssignment::new("agent".to_string(), 1.0)],
            1.0, // 100% emission
        );

        let salt = b"test_salt".to_vec();
        let commitment = MechanismCommitment::new(1, 1, &weights, &salt);

        manager.commit(commitment);
        assert!(manager.reveal(1, weights).is_ok());
        assert!(manager.all_revealed());
    }

    #[test]
    fn test_empty_weights_go_to_burn() {
        let mech_weights = MechanismWeights::new(1, ChallengeId::new(), vec![], 0.5);

        // All weight should go to UID 0
        assert_eq!(mech_weights.uids.len(), 1);
        assert_eq!(mech_weights.uids[0], BURN_UID);
        assert_eq!(mech_weights.weights[0], MAX_WEIGHT);
    }
}
