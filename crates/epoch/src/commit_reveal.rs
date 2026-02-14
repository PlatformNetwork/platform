//! Commit-Reveal scheme for weight submissions
//!
//! Prevents validators from seeing others' weights before committing their own.

use crate::{FinalizedWeights, WeightCommitment, WeightReveal};
use parking_lot::RwLock;
use platform_challenge_sdk::{weights, ChallengeId, WeightAssignment};
use platform_core::Hotkey;
use std::collections::{HashMap, HashSet};
use tracing::{debug, error, info, warn};

/// Commit-reveal state for a single epoch
pub struct CommitRevealState {
    epoch: u64,
    challenge_id: ChallengeId,

    /// Commitments by validator
    commitments: HashMap<Hotkey, WeightCommitment>,

    /// Reveals by validator (after reveal phase)
    reveals: HashMap<Hotkey, WeightReveal>,

    /// Validators who committed but didn't reveal (penalized)
    missing_reveals: Vec<Hotkey>,

    /// Validators whose reveal didn't match commitment
    mismatched_reveals: Vec<Hotkey>,
}

impl CommitRevealState {
    pub fn new(epoch: u64, challenge_id: ChallengeId) -> Self {
        Self {
            epoch,
            challenge_id,
            commitments: HashMap::new(),
            reveals: HashMap::new(),
            missing_reveals: Vec::new(),
            mismatched_reveals: Vec::new(),
        }
    }

    /// Submit a commitment
    pub fn submit_commitment(
        &mut self,
        commitment: WeightCommitment,
    ) -> Result<(), CommitRevealError> {
        if commitment.epoch != self.epoch {
            return Err(CommitRevealError::WrongEpoch {
                expected: self.epoch,
                got: commitment.epoch,
            });
        }

        if commitment.challenge_id != self.challenge_id {
            return Err(CommitRevealError::WrongChallenge);
        }

        if self.commitments.contains_key(&commitment.validator) {
            return Err(CommitRevealError::AlreadyCommitted);
        }

        debug!(
            "Validator {:?} committed weights for epoch {}",
            commitment.validator, self.epoch
        );

        self.commitments
            .insert(commitment.validator.clone(), commitment);
        Ok(())
    }

    /// Submit a reveal
    pub fn submit_reveal(&mut self, reveal: WeightReveal) -> Result<(), CommitRevealError> {
        if reveal.epoch != self.epoch {
            return Err(CommitRevealError::WrongEpoch {
                expected: self.epoch,
                got: reveal.epoch,
            });
        }

        // Check that validator committed
        let commitment = self
            .commitments
            .get(&reveal.validator)
            .ok_or(CommitRevealError::NoCommitment)?;

        // Verify reveal matches commitment
        let computed_hash = weights::create_commitment(&reveal.weights, &reveal.secret);
        if computed_hash != commitment.commitment_hash {
            warn!(
                "Validator {:?} reveal doesn't match commitment",
                reveal.validator
            );
            self.mismatched_reveals.push(reveal.validator.clone());
            return Err(CommitRevealError::CommitmentMismatch);
        }

        if self.reveals.contains_key(&reveal.validator) {
            return Err(CommitRevealError::AlreadyRevealed);
        }

        debug!(
            "Validator {:?} revealed weights for epoch {}",
            reveal.validator, self.epoch
        );

        self.reveals.insert(reveal.validator.clone(), reveal);
        Ok(())
    }

    /// Finalize weights after reveal phase
    ///
    /// The commit-reveal step verifies that validators used the same challenge
    /// evaluation output. The resulting weight vector is the consensus payload
    /// that later drives stake-weighted PBFT and on-chain weight voting.
    pub fn finalize(
        &mut self,
        smoothing: f64,
        min_validators: usize,
    ) -> Result<FinalizedWeights, CommitRevealError> {
        // Find validators who committed but didn't reveal
        for validator in self.commitments.keys() {
            if !self.reveals.contains_key(validator) && !self.mismatched_reveals.contains(validator)
            {
                self.missing_reveals.push(validator.clone());
            }
        }

        if !self.missing_reveals.is_empty() {
            warn!(
                "Epoch {}: {} validators committed but didn't reveal",
                self.epoch,
                self.missing_reveals.len()
            );
        }

        // Collect valid submissions
        let submissions: Vec<Vec<WeightAssignment>> =
            self.reveals.values().map(|r| r.weights.clone()).collect();

        if submissions.len() < min_validators {
            return Err(CommitRevealError::InsufficientValidators {
                required: min_validators,
                got: submissions.len(),
            });
        }

        // Validate that all submissions are consistent
        // All validators read from shared chain DB, so submissions should be identical
        let first = &submissions[0];
        let divergence_detected = self.check_submission_divergence(&submissions);

        if divergence_detected {
            error!(
                "Epoch {}: Weight submissions diverged across {} validators! Using first submission.",
                self.epoch,
                submissions.len()
            );
        }

        let aggregated = weights::normalize_weights(first.clone());

        let participating: Vec<Hotkey> = self.reveals.keys().cloned().collect();
        let mut excluded = self.missing_reveals.clone();
        excluded.extend(self.mismatched_reveals.clone());

        info!(
            "Epoch {} finalized: {} validators, {} excluded, {} agents",
            self.epoch,
            participating.len(),
            excluded.len(),
            aggregated.len()
        );

        Ok(FinalizedWeights {
            challenge_id: self.challenge_id,
            epoch: self.epoch,
            weights: aggregated,
            participating_validators: participating,
            excluded_validators: excluded,
            smoothing_applied: 0.0,
            finalized_at: chrono::Utc::now(),
        })
    }

    /// Get number of commitments
    pub fn commitment_count(&self) -> usize {
        self.commitments.len()
    }

    /// Get number of reveals
    pub fn reveal_count(&self) -> usize {
        self.reveals.len()
    }

    /// Check if validator has committed
    pub fn has_committed(&self, validator: &Hotkey) -> bool {
        self.commitments.contains_key(validator)
    }

    /// Check if validator has revealed
    pub fn has_revealed(&self, validator: &Hotkey) -> bool {
        self.reveals.contains_key(validator)
    }

    /// Check if submissions from different validators have diverged.
    /// Returns true if divergence is detected.
    fn check_submission_divergence(&self, submissions: &[Vec<WeightAssignment>]) -> bool {
        if submissions.len() <= 1 {
            return false;
        }

        let first = &submissions[0];

        // Build a map of hotkey -> weight for the first submission
        let first_weights: HashMap<&str, f64> = first
            .iter()
            .map(|w| (w.hotkey.as_str(), w.weight))
            .collect();

        // Tolerance for floating-point comparison (0.1% difference allowed)
        const WEIGHT_TOLERANCE: f64 = 0.001;

        for (idx, submission) in submissions.iter().enumerate().skip(1) {
            // Check if same number of weight assignments
            if submission.len() != first.len() {
                warn!(
                    "Epoch {}: Submission {} has {} weights, first has {}",
                    self.epoch,
                    idx,
                    submission.len(),
                    first.len()
                );
                return true;
            }

            // Check if same hotkeys with similar weights
            for weight in submission {
                match first_weights.get(weight.hotkey.as_str()) {
                    None => {
                        warn!(
                            "Epoch {}: Submission {} has hotkey {} not in first submission",
                            self.epoch,
                            idx,
                            &weight.hotkey[..16.min(weight.hotkey.len())]
                        );
                        return true;
                    }
                    Some(&first_weight) => {
                        let diff = (weight.weight - first_weight).abs();
                        if diff > WEIGHT_TOLERANCE {
                            warn!(
                                "Epoch {}: Weight divergence for hotkey {}: {} vs {} (diff: {:.4})",
                                self.epoch,
                                &weight.hotkey[..16.min(weight.hotkey.len())],
                                first_weight,
                                weight.weight,
                                diff
                            );
                            return true;
                        }
                    }
                }
            }
        }

        false
    }
}

/// Errors for commit-reveal
#[derive(Debug, thiserror::Error)]
pub enum CommitRevealError {
    #[error("Wrong epoch: expected {expected}, got {got}")]
    WrongEpoch { expected: u64, got: u64 },

    #[error("Wrong challenge")]
    WrongChallenge,

    #[error("Already committed")]
    AlreadyCommitted,

    #[error("Already revealed")]
    AlreadyRevealed,

    #[error("No commitment found")]
    NoCommitment,

    #[error("Reveal doesn't match commitment")]
    CommitmentMismatch,

    #[error("Insufficient validators: required {required}, got {got}")]
    InsufficientValidators { required: usize, got: usize },

    #[error("Aggregation failed: {0}")]
    AggregationFailed(String),
}

/// Manager for multiple challenges' commit-reveal states
pub struct CommitRevealManager {
    states: RwLock<HashMap<(u64, ChallengeId), CommitRevealState>>,
}

impl CommitRevealManager {
    pub fn new() -> Self {
        Self {
            states: RwLock::new(HashMap::new()),
        }
    }

    /// Get or create state for an epoch/challenge
    pub fn get_or_create(
        &self,
        epoch: u64,
        challenge_id: ChallengeId,
    ) -> parking_lot::RwLockWriteGuard<'_, HashMap<(u64, ChallengeId), CommitRevealState>> {
        let mut states = self.states.write();
        let key = (epoch, challenge_id);

        states
            .entry(key)
            .or_insert_with(|| CommitRevealState::new(epoch, challenge_id));

        states
    }

    /// Submit commitment
    pub fn commit(
        &self,
        epoch: u64,
        challenge_id: ChallengeId,
        commitment: WeightCommitment,
    ) -> Result<(), CommitRevealError> {
        let mut states = self.states.write();
        let key = (epoch, challenge_id);

        let state = states
            .entry(key)
            .or_insert_with(|| CommitRevealState::new(epoch, challenge_id));

        state.submit_commitment(commitment)
    }

    /// Submit reveal
    pub fn reveal(
        &self,
        epoch: u64,
        challenge_id: ChallengeId,
        reveal: WeightReveal,
    ) -> Result<(), CommitRevealError> {
        let mut states = self.states.write();
        let key = (epoch, challenge_id);

        let state = states
            .get_mut(&key)
            .ok_or(CommitRevealError::NoCommitment)?;

        state.submit_reveal(reveal)
    }

    /// Finalize epoch
    pub fn finalize(
        &self,
        epoch: u64,
        challenge_id: ChallengeId,
        smoothing: f64,
        min_validators: usize,
    ) -> Result<FinalizedWeights, CommitRevealError> {
        let mut states = self.states.write();
        let key = (epoch, challenge_id);

        let state = states
            .get_mut(&key)
            .ok_or(CommitRevealError::InsufficientValidators {
                required: min_validators,
                got: 0,
            })?;

        state.finalize(smoothing, min_validators)
    }

    /// Clean up old epochs
    pub fn cleanup_old_epochs(&self, current_epoch: u64, keep_epochs: u64) {
        let mut states = self.states.write();
        let cutoff = current_epoch.saturating_sub(keep_epochs);

        states.retain(|(epoch, _), _| *epoch >= cutoff);
    }
}

impl Default for CommitRevealManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_core::Keypair;

    fn create_test_commitment(
        validator: &Keypair,
        epoch: u64,
        challenge_id: ChallengeId,
    ) -> (WeightCommitment, WeightReveal) {
        let weights = vec![
            WeightAssignment::new("agent1".to_string(), 0.6),
            WeightAssignment::new("agent2".to_string(), 0.4),
        ];
        let secret = b"test_secret".to_vec();
        let hash = weights::create_commitment(&weights, &secret);

        let commitment = WeightCommitment {
            validator: validator.hotkey(),
            challenge_id,
            epoch,
            commitment_hash: hash,
            timestamp: chrono::Utc::now(),
        };

        let reveal = WeightReveal {
            validator: validator.hotkey(),
            challenge_id,
            epoch,
            weights,
            secret,
            timestamp: chrono::Utc::now(),
        };

        (commitment, reveal)
    }

    #[test]
    fn test_commit_reveal_flow() {
        let challenge_id = ChallengeId::new();
        let mut state = CommitRevealState::new(0, challenge_id);

        let validator = Keypair::generate();
        let (commitment, reveal) = create_test_commitment(&validator, 0, challenge_id);

        // Submit commitment
        state.submit_commitment(commitment).unwrap();
        assert!(state.has_committed(&validator.hotkey()));

        // Submit reveal
        state.submit_reveal(reveal).unwrap();
        assert!(state.has_revealed(&validator.hotkey()));
    }

    #[test]
    fn test_commitment_mismatch() {
        let challenge_id = ChallengeId::new();
        let mut state = CommitRevealState::new(0, challenge_id);

        let validator = Keypair::generate();
        let (commitment, mut reveal) = create_test_commitment(&validator, 0, challenge_id);

        state.submit_commitment(commitment).unwrap();

        // Modify reveal to not match commitment
        reveal.secret = b"wrong_secret".to_vec();

        let result = state.submit_reveal(reveal);
        assert!(matches!(result, Err(CommitRevealError::CommitmentMismatch)));
    }

    #[test]
    fn test_wrong_epoch_commitment() {
        let challenge_id = ChallengeId::new();
        let mut state = CommitRevealState::new(0, challenge_id);

        let validator = Keypair::generate();
        let (mut commitment, _) = create_test_commitment(&validator, 1, challenge_id);
        commitment.epoch = 1; // Wrong epoch

        let result = state.submit_commitment(commitment);
        assert!(matches!(
            result,
            Err(CommitRevealError::WrongEpoch {
                expected: 0,
                got: 1
            })
        ));
    }

    #[test]
    fn test_wrong_challenge() {
        let challenge_id = ChallengeId::new();
        let different_challenge = ChallengeId::new();
        let mut state = CommitRevealState::new(0, challenge_id);

        let validator = Keypair::generate();
        let (commitment, _) = create_test_commitment(&validator, 0, different_challenge);

        let result = state.submit_commitment(commitment);
        assert!(matches!(result, Err(CommitRevealError::WrongChallenge)));
    }

    #[test]
    fn test_already_committed() {
        let challenge_id = ChallengeId::new();
        let mut state = CommitRevealState::new(0, challenge_id);

        let validator = Keypair::generate();
        let (commitment, _) = create_test_commitment(&validator, 0, challenge_id);

        state.submit_commitment(commitment.clone()).unwrap();
        let result = state.submit_commitment(commitment);
        assert!(matches!(result, Err(CommitRevealError::AlreadyCommitted)));
    }

    #[test]
    fn test_already_revealed() {
        let challenge_id = ChallengeId::new();
        let mut state = CommitRevealState::new(0, challenge_id);

        let validator = Keypair::generate();
        let (commitment, reveal) = create_test_commitment(&validator, 0, challenge_id);

        state.submit_commitment(commitment).unwrap();
        state.submit_reveal(reveal.clone()).unwrap();

        let result = state.submit_reveal(reveal);
        assert!(matches!(result, Err(CommitRevealError::AlreadyRevealed)));
    }

    #[test]
    fn test_reveal_no_commitment() {
        let challenge_id = ChallengeId::new();
        let mut state = CommitRevealState::new(0, challenge_id);

        let validator = Keypair::generate();
        let (_, reveal) = create_test_commitment(&validator, 0, challenge_id);

        let result = state.submit_reveal(reveal);
        assert!(matches!(result, Err(CommitRevealError::NoCommitment)));
    }

    #[test]
    fn test_reveal_wrong_epoch() {
        let challenge_id = ChallengeId::new();
        let mut state = CommitRevealState::new(0, challenge_id);

        let validator = Keypair::generate();
        let (commitment, mut reveal) = create_test_commitment(&validator, 0, challenge_id);

        state.submit_commitment(commitment).unwrap();
        reveal.epoch = 1; // Wrong epoch

        let result = state.submit_reveal(reveal);
        assert!(matches!(
            result,
            Err(CommitRevealError::WrongEpoch {
                expected: 0,
                got: 1
            })
        ));
    }

    #[test]
    fn test_finalize_insufficient_validators() {
        let challenge_id = ChallengeId::new();
        let mut state = CommitRevealState::new(0, challenge_id);

        let validator = Keypair::generate();
        let (commitment, reveal) = create_test_commitment(&validator, 0, challenge_id);

        state.submit_commitment(commitment).unwrap();
        state.submit_reveal(reveal).unwrap();

        // Require more validators than we have
        let result = state.finalize(0.3, 5);
        assert!(matches!(
            result,
            Err(CommitRevealError::InsufficientValidators {
                required: 5,
                got: 1
            })
        ));
    }

    #[test]
    fn test_finalize_success() {
        let challenge_id = ChallengeId::new();
        let mut state = CommitRevealState::new(0, challenge_id);

        let validator1 = Keypair::generate();
        let validator2 = Keypair::generate();
        let validator3 = Keypair::generate();

        let (c1, r1) = create_test_commitment(&validator1, 0, challenge_id);
        let (c2, r2) = create_test_commitment(&validator2, 0, challenge_id);
        let (c3, r3) = create_test_commitment(&validator3, 0, challenge_id);

        state.submit_commitment(c1).unwrap();
        state.submit_commitment(c2).unwrap();
        state.submit_commitment(c3).unwrap();

        state.submit_reveal(r1).unwrap();
        state.submit_reveal(r2).unwrap();
        state.submit_reveal(r3).unwrap();

        let finalized = state.finalize(0.3, 3).unwrap();
        assert_eq!(finalized.epoch, 0);
        assert_eq!(finalized.challenge_id, challenge_id);
        assert_eq!(finalized.participating_validators.len(), 3);
        assert_eq!(finalized.excluded_validators.len(), 0);
    }

    #[test]
    fn test_finalize_missing_reveals() {
        let challenge_id = ChallengeId::new();
        let mut state = CommitRevealState::new(0, challenge_id);

        let validator1 = Keypair::generate();
        let validator2 = Keypair::generate();
        let validator3 = Keypair::generate();

        let (c1, r1) = create_test_commitment(&validator1, 0, challenge_id);
        let (c2, _r2) = create_test_commitment(&validator2, 0, challenge_id);
        let (c3, r3) = create_test_commitment(&validator3, 0, challenge_id);

        state.submit_commitment(c1).unwrap();
        state.submit_commitment(c2).unwrap();
        state.submit_commitment(c3).unwrap();

        state.submit_reveal(r1).unwrap();
        // validator2 doesn't reveal
        state.submit_reveal(r3).unwrap();

        let finalized = state.finalize(0.3, 2).unwrap();
        assert_eq!(finalized.participating_validators.len(), 2);
        assert_eq!(finalized.excluded_validators.len(), 1);
        assert!(finalized.excluded_validators.contains(&validator2.hotkey()));
    }

    #[test]
    fn test_commitment_count() {
        let challenge_id = ChallengeId::new();
        let mut state = CommitRevealState::new(0, challenge_id);

        assert_eq!(state.commitment_count(), 0);

        let validator = Keypair::generate();
        let (commitment, _) = create_test_commitment(&validator, 0, challenge_id);
        state.submit_commitment(commitment).unwrap();

        assert_eq!(state.commitment_count(), 1);
    }

    #[test]
    fn test_reveal_count() {
        let challenge_id = ChallengeId::new();
        let mut state = CommitRevealState::new(0, challenge_id);

        assert_eq!(state.reveal_count(), 0);

        let validator = Keypair::generate();
        let (commitment, reveal) = create_test_commitment(&validator, 0, challenge_id);
        state.submit_commitment(commitment).unwrap();
        state.submit_reveal(reveal).unwrap();

        assert_eq!(state.reveal_count(), 1);
    }

    #[test]
    fn test_commit_reveal_manager() {
        let manager = CommitRevealManager::new();
        let challenge_id = ChallengeId::new();
        let epoch = 1;

        let validator = Keypair::generate();
        let (commitment, reveal) = create_test_commitment(&validator, epoch, challenge_id);

        manager.commit(epoch, challenge_id, commitment).unwrap();
        manager.reveal(epoch, challenge_id, reveal).unwrap();

        let finalized = manager.finalize(epoch, challenge_id, 0.3, 1).unwrap();
        assert_eq!(finalized.epoch, epoch);
    }

    #[test]
    fn test_commit_reveal_manager_default() {
        let manager = CommitRevealManager::default();
        // Verify initial state
        let result = manager.finalize(0, ChallengeId::new(), 0.3, 1);
        assert!(result.is_err()); // No commits exist
    }

    #[test]
    fn test_cleanup_old_epochs() {
        let manager = CommitRevealManager::new();
        let challenge_id = ChallengeId::new();

        let validator = Keypair::generate();

        // Create states for epochs 0, 1, 2
        for epoch in 0..3 {
            let (commitment, _) = create_test_commitment(&validator, epoch, challenge_id);
            manager.commit(epoch, challenge_id, commitment).unwrap();
        }

        // Cleanup, keeping only last 1 epoch
        manager.cleanup_old_epochs(2, 1);

        // Should only have epoch 2 remaining (current 2 - keep 1 = cutoff 1)
        // Verify old epochs were removed by checking that get_or_create returns empty for epoch 0
        {
            let states_map = manager.get_or_create(0, challenge_id);
            let state = states_map.get(&(0, challenge_id)).unwrap();
            assert_eq!(state.commitment_count(), 0);
        }

        // Verify epoch 2 still exists with commitment
        {
            let states_map = manager.get_or_create(2, challenge_id);
            let state = states_map.get(&(2, challenge_id)).unwrap();
            assert_eq!(state.commitment_count(), 1);
        }
    }

    #[test]
    fn test_manager_get_or_create() {
        let manager = CommitRevealManager::new();
        let challenge_id = ChallengeId::new();
        let epoch = 0;

        // First call creates the state
        {
            let states = manager.get_or_create(epoch, challenge_id);
            assert!(states.contains_key(&(epoch, challenge_id)));
        }

        // Second call retrieves existing - verify by checking it exists
        {
            let states = manager.get_or_create(epoch, challenge_id);
            let state = states.get(&(epoch, challenge_id)).unwrap();
            assert_eq!(state.epoch, epoch);
            assert_eq!(state.challenge_id, challenge_id);
        }
    }

    #[test]
    fn test_finalize_manager_no_state() {
        let manager = CommitRevealManager::new();
        let challenge_id = ChallengeId::new();

        // Try to finalize without any commits
        let result = manager.finalize(0, challenge_id, 0.3, 1);
        assert!(matches!(
            result,
            Err(CommitRevealError::InsufficientValidators { .. })
        ));
    }

    #[test]
    fn test_multiple_challenges_same_epoch() {
        let manager = CommitRevealManager::new();
        let challenge1 = ChallengeId::new();
        let challenge2 = ChallengeId::new();
        let epoch = 0;

        let validator1 = Keypair::generate();
        let validator2 = Keypair::generate();

        let (c1_1, r1_1) = create_test_commitment(&validator1, epoch, challenge1);
        let (c2_1, r2_1) = create_test_commitment(&validator2, epoch, challenge1);
        let (c1_2, r1_2) = create_test_commitment(&validator1, epoch, challenge2);

        // Submit to challenge1
        manager.commit(epoch, challenge1, c1_1).unwrap();
        manager.commit(epoch, challenge1, c2_1).unwrap();
        manager.reveal(epoch, challenge1, r1_1).unwrap();
        manager.reveal(epoch, challenge1, r2_1).unwrap();

        // Submit to challenge2
        manager.commit(epoch, challenge2, c1_2).unwrap();
        manager.reveal(epoch, challenge2, r1_2).unwrap();

        // Finalize both
        let finalized1 = manager.finalize(epoch, challenge1, 0.3, 2).unwrap();
        let finalized2 = manager.finalize(epoch, challenge2, 0.3, 1).unwrap();

        assert_eq!(finalized1.challenge_id, challenge1);
        assert_eq!(finalized2.challenge_id, challenge2);
    }

    #[test]
    fn test_commit_reveal_error_display() {
        let err1 = CommitRevealError::WrongEpoch {
            expected: 1,
            got: 2,
        };
        let err2 = CommitRevealError::WrongChallenge;
        let err3 = CommitRevealError::AlreadyCommitted;
        let err4 = CommitRevealError::AlreadyRevealed;
        let err5 = CommitRevealError::NoCommitment;
        let err6 = CommitRevealError::CommitmentMismatch;
        let err7 = CommitRevealError::InsufficientValidators {
            required: 3,
            got: 1,
        };
        let err8 = CommitRevealError::AggregationFailed("test".to_string());

        // Verify error messages can be formatted
        assert!(!format!("{}", err1).is_empty());
        assert!(!format!("{}", err2).is_empty());
        assert!(!format!("{}", err3).is_empty());
        assert!(!format!("{}", err4).is_empty());
        assert!(!format!("{}", err5).is_empty());
        assert!(!format!("{}", err6).is_empty());
        assert!(!format!("{}", err7).is_empty());
        assert!(!format!("{}", err8).is_empty());
    }
}
