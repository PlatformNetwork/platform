//! Validator management for P2P consensus
//!
//! Tracks active validators, their stakes, and handles leader election
//! using round-robin based on stake-weighted ordering.

use crate::messages::{SequenceNumber, ViewNumber};
use parking_lot::RwLock;
use platform_core::{Hotkey, Keypair, SignedMessage};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors related to validator operations
#[derive(Error, Debug)]
pub enum ValidatorError {
    #[error("Validator not found: {0}")]
    NotFound(String),
    #[error("Insufficient stake: required {required}, has {actual}")]
    InsufficientStake { required: u64, actual: u64 },
    #[error("Invalid signature from validator")]
    InvalidSignature,
    #[error("Validator already registered")]
    AlreadyRegistered,
    #[error("Not authorized: {0}")]
    NotAuthorized(String),
}

/// Information about a validator in the P2P network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorRecord {
    /// Validator's hotkey
    pub hotkey: Hotkey,
    /// Current stake in RAO
    pub stake: u64,
    /// libp2p peer ID
    pub peer_id: Option<String>,
    /// Multiaddresses where validator can be reached
    pub addresses: Vec<String>,
    /// Last heartbeat timestamp (unix millis)
    pub last_seen: i64,
    /// Current state hash reported by validator
    pub state_hash: [u8; 32],
    /// Last sequence number seen
    pub last_sequence: SequenceNumber,
    /// Whether validator is currently active (responding to heartbeats)
    pub is_active: bool,
    /// Protocol version
    pub protocol_version: String,
}

impl ValidatorRecord {
    /// Create a new validator record
    pub fn new(hotkey: Hotkey, stake: u64) -> Self {
        Self {
            hotkey,
            stake,
            peer_id: None,
            addresses: vec![],
            last_seen: chrono::Utc::now().timestamp_millis(),
            state_hash: [0u8; 32],
            last_sequence: 0,
            is_active: true,
            protocol_version: String::new(),
        }
    }

    /// Update from heartbeat
    pub fn update_from_heartbeat(
        &mut self,
        state_hash: [u8; 32],
        sequence: SequenceNumber,
        stake: u64,
    ) {
        self.state_hash = state_hash;
        self.last_sequence = sequence;
        self.stake = stake;
        self.last_seen = chrono::Utc::now().timestamp_millis();
        self.is_active = true;
    }

    /// Check if validator is stale (no heartbeat in threshold)
    pub fn is_stale(&self, threshold_ms: i64) -> bool {
        let now = chrono::Utc::now().timestamp_millis();
        (now - self.last_seen) > threshold_ms
    }
}

/// Manages the validator set for consensus
pub struct ValidatorSet {
    /// Map of hotkey to validator record
    validators: RwLock<HashMap<Hotkey, ValidatorRecord>>,
    /// Minimum stake required (in RAO)
    min_stake: u64,
    /// Our own keypair
    local_keypair: Keypair,
    /// Stale threshold in milliseconds
    stale_threshold_ms: i64,
    /// Verified stakes from on-chain data (set by caller who queries chain)
    /// Key: validator hotkey, Value: verified stake amount in RAO
    /// The caller is responsible for periodically querying on-chain data
    /// (e.g., via Bittensor metagraph) and updating these values.
    verified_stakes: RwLock<HashMap<Hotkey, u64>>,
}

impl ValidatorSet {
    /// Create a new validator set
    pub fn new(local_keypair: Keypair, min_stake: u64) -> Self {
        Self {
            validators: RwLock::new(HashMap::new()),
            min_stake,
            local_keypair,
            stale_threshold_ms: 90_000, // 90 seconds (3x heartbeat interval)
            verified_stakes: RwLock::new(HashMap::new()),
        }
    }

    /// Set verified stake for a validator from on-chain data
    ///
    /// This should be called by the caller (e.g., validator node) after
    /// querying on-chain data (Bittensor metagraph) to establish trusted
    /// stake values. Self-reported stakes from heartbeats are only accepted
    /// if they match the verified stake or if no verified stake exists yet.
    pub fn set_verified_stake(&self, hotkey: &Hotkey, stake: u64) {
        self.verified_stakes.write().insert(hotkey.clone(), stake);
        debug!(hotkey = %hotkey.to_hex(), stake, "Set verified stake from on-chain data");
    }

    /// Get verified stake for a validator
    pub fn get_verified_stake(&self, hotkey: &Hotkey) -> Option<u64> {
        self.verified_stakes.read().get(hotkey).copied()
    }

    /// Clear all verified stakes (useful when re-syncing from chain)
    pub fn clear_verified_stakes(&self) {
        self.verified_stakes.write().clear();
    }

    /// Get our local hotkey
    pub fn local_hotkey(&self) -> Hotkey {
        self.local_keypair.hotkey()
    }

    /// Sign a message with our local keypair
    pub fn sign(&self, message: &[u8]) -> SignedMessage {
        self.local_keypair.sign(message)
    }

    /// Sign arbitrary bytes and return signature
    pub fn sign_bytes(&self, data: &[u8]) -> Result<Vec<u8>, platform_core::MiniChainError> {
        self.local_keypair.sign_bytes(data)
    }

    /// Register or update a validator
    pub fn register_validator(&self, record: ValidatorRecord) -> Result<(), ValidatorError> {
        if record.stake < self.min_stake {
            return Err(ValidatorError::InsufficientStake {
                required: self.min_stake,
                actual: record.stake,
            });
        }

        let mut validators = self.validators.write();
        let hotkey_str = record.hotkey.to_hex();

        if let Some(existing) = validators.get_mut(&record.hotkey) {
            debug!(hotkey = %hotkey_str, "Updating existing validator");
            existing.stake = record.stake;
            existing.peer_id = record.peer_id.or(existing.peer_id.clone());
            if !record.addresses.is_empty() {
                existing.addresses = record.addresses;
            }
            existing.last_seen = record.last_seen;
            existing.is_active = true;
        } else {
            info!(hotkey = %hotkey_str, stake = record.stake, "Registering new validator");
            validators.insert(record.hotkey.clone(), record);
        }

        Ok(())
    }

    /// Remove a validator
    pub fn remove_validator(&self, hotkey: &Hotkey) {
        let mut validators = self.validators.write();
        if validators.remove(hotkey).is_some() {
            info!(hotkey = %hotkey.to_hex(), "Removed validator");
        }
    }

    /// Get a validator by hotkey
    pub fn get_validator(&self, hotkey: &Hotkey) -> Option<ValidatorRecord> {
        self.validators.read().get(hotkey).cloned()
    }

    /// Check if a hotkey is a registered validator
    pub fn is_validator(&self, hotkey: &Hotkey) -> bool {
        self.validators.read().contains_key(hotkey)
    }

    /// Get all active validators
    pub fn active_validators(&self) -> Vec<ValidatorRecord> {
        self.validators
            .read()
            .values()
            .filter(|v| v.is_active && !v.is_stale(self.stale_threshold_ms))
            .cloned()
            .collect()
    }

    /// Get count of active validators
    pub fn active_count(&self) -> usize {
        self.validators
            .read()
            .values()
            .filter(|v| v.is_active && !v.is_stale(self.stale_threshold_ms))
            .count()
    }

    /// Get total stake of active validators
    pub fn total_active_stake(&self) -> u64 {
        self.validators
            .read()
            .values()
            .filter(|v| v.is_active && !v.is_stale(self.stale_threshold_ms))
            .map(|v| v.stake)
            .sum()
    }

    /// Check if a given stake meets the minimum requirement
    pub fn is_stake_sufficient(&self, stake: u64) -> bool {
        stake >= self.min_stake
    }

    /// Get stake for a validator (0 if unknown or inactive)
    pub fn stake_for(&self, hotkey: &Hotkey) -> u64 {
        self.validators
            .read()
            .get(hotkey)
            .filter(|v| v.is_active && !v.is_stale(self.stale_threshold_ms))
            .map(|v| v.stake)
            .unwrap_or(0)
    }

    /// Calculate stake-weighted quorum threshold (2/3 of total stake + 1)
    pub fn stake_quorum_threshold(&self) -> u64 {
        let total = self.total_active_stake();
        if total == 0 {
            0
        } else {
            (total.saturating_mul(2) / 3).saturating_add(1)
        }
    }

    /// Update validator from heartbeat
    ///
    /// Self-reported stake is only accepted if it matches the verified stake
    /// (set via `set_verified_stake`) or if no verified stake exists yet.
    /// This prevents validators from falsely inflating their stake in heartbeats.
    pub fn update_from_heartbeat(
        &self,
        hotkey: &Hotkey,
        state_hash: [u8; 32],
        sequence: SequenceNumber,
        reported_stake: u64,
    ) -> Result<(), ValidatorError> {
        // Determine the stake to use: prefer verified stake over self-reported
        let stake_to_use = {
            let verified = self.verified_stakes.read();
            if let Some(&verified_stake) = verified.get(hotkey) {
                // Only accept self-reported stake if it matches verified stake
                if reported_stake != verified_stake {
                    warn!(
                        hotkey = %hotkey.to_hex(),
                        reported = reported_stake,
                        verified = verified_stake,
                        "Heartbeat stake mismatch, using verified stake"
                    );
                }
                verified_stake
            } else {
                // No verified stake yet, accept self-reported for now
                // Caller should eventually verify this against on-chain data
                reported_stake
            }
        };

        let mut validators = self.validators.write();
        if let Some(validator) = validators.get_mut(hotkey) {
            validator.update_from_heartbeat(state_hash, sequence, stake_to_use);
            Ok(())
        } else {
            // Auto-register if stake meets minimum
            if stake_to_use >= self.min_stake {
                let mut record = ValidatorRecord::new(hotkey.clone(), stake_to_use);
                record.update_from_heartbeat(state_hash, sequence, stake_to_use);
                drop(validators);
                return self.register_validator(record);
            }
            Err(ValidatorError::NotFound(hotkey.to_hex()))
        }
    }

    /// Mark stale validators as inactive
    pub fn mark_stale_validators(&self) {
        let mut validators = self.validators.write();
        for validator in validators.values_mut() {
            if validator.is_stale(self.stale_threshold_ms) && validator.is_active {
                warn!(
                    hotkey = %validator.hotkey.to_hex(),
                    last_seen = validator.last_seen,
                    "Marking validator as inactive (stale)"
                );
                validator.is_active = false;
            }
        }
    }

    /// Get sorted validators by stake (descending) for leader election
    pub fn validators_by_stake(&self) -> Vec<ValidatorRecord> {
        let mut validators: Vec<_> = self
            .validators
            .read()
            .values()
            .filter(|v| v.is_active && !v.is_stale(self.stale_threshold_ms))
            .cloned()
            .collect();
        validators.sort_by(|a, b| {
            b.stake
                .cmp(&a.stake)
                .then_with(|| a.hotkey.0.cmp(&b.hotkey.0))
        });
        validators
    }

    /// Calculate PBFT fault tolerance threshold (f)
    /// Byzantine fault tolerance: n = 3f + 1, so f = (n - 1) / 3
    pub fn fault_tolerance(&self) -> usize {
        let n = self.active_count();
        if n == 0 {
            return 0;
        }
        (n - 1) / 3
    }

    /// Calculate quorum size for consensus (2f + 1)
    pub fn quorum_size(&self) -> usize {
        let f = self.fault_tolerance();
        2 * f + 1
    }

    /// Verify a signature from a validator
    pub fn verify_signature(
        &self,
        hotkey: &Hotkey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, ValidatorError> {
        // Verify the validator is registered
        if !self.is_validator(hotkey) {
            return Err(ValidatorError::NotFound(hotkey.to_hex()));
        }

        let signed_msg = SignedMessage {
            message: message.to_vec(),
            signature: signature.to_vec(),
            signer: hotkey.clone(),
        };

        match signed_msg.verify() {
            Ok(valid) => Ok(valid),
            Err(_) => Err(ValidatorError::InvalidSignature),
        }
    }
}

/// Leader election based on round-robin with stake ordering
pub struct LeaderElection {
    /// Reference to validator set
    validator_set: Arc<ValidatorSet>,
}

impl LeaderElection {
    /// Create new leader election
    pub fn new(validator_set: Arc<ValidatorSet>) -> Self {
        Self { validator_set }
    }

    /// Get the leader for a given view number
    pub fn leader_for_view(&self, view: ViewNumber) -> Option<Hotkey> {
        let validators = self.validator_set.validators_by_stake();
        if validators.is_empty() {
            return None;
        }
        let index = (view as usize) % validators.len();
        Some(validators[index].hotkey.clone())
    }

    /// Check if a hotkey is the leader for a given view
    pub fn is_leader(&self, hotkey: &Hotkey, view: ViewNumber) -> bool {
        self.leader_for_view(view)
            .map(|leader| leader == *hotkey)
            .unwrap_or(false)
    }

    /// Check if we are the leader for a given view
    pub fn am_i_leader(&self, view: ViewNumber) -> bool {
        self.is_leader(&self.validator_set.local_hotkey(), view)
    }

    /// Get the next view number where we would be leader
    pub fn next_leader_view(&self, current_view: ViewNumber) -> Option<ViewNumber> {
        let validators = self.validator_set.validators_by_stake();
        let local_hotkey = self.validator_set.local_hotkey();

        let our_position = validators.iter().position(|v| v.hotkey == local_hotkey)?;

        let validator_count = validators.len();
        let current_position = (current_view as usize) % validator_count;

        if our_position >= current_position {
            Some(current_view + (our_position - current_position) as u64)
        } else {
            Some(current_view + (validator_count - current_position + our_position) as u64)
        }
    }
}

/// Stake-weighted voting for consensus
pub struct StakeWeightedVoting {
    /// Reference to validator set
    validator_set: Arc<ValidatorSet>,
}

impl StakeWeightedVoting {
    /// Create new stake-weighted voting
    pub fn new(validator_set: Arc<ValidatorSet>) -> Self {
        Self { validator_set }
    }

    /// Calculate the voting power of a validator (normalized 0-1)
    pub fn voting_power(&self, hotkey: &Hotkey) -> f64 {
        let total_stake = self.validator_set.total_active_stake();
        if total_stake == 0 {
            return 0.0;
        }

        self.validator_set
            .get_validator(hotkey)
            .filter(|v| v.is_active)
            .map(|v| v.stake as f64 / total_stake as f64)
            .unwrap_or(0.0)
    }

    /// Calculate total voting power for a set of validators
    pub fn total_voting_power(&self, hotkeys: &[Hotkey]) -> f64 {
        let total_stake = self.validator_set.total_active_stake();
        if total_stake == 0 {
            return 0.0;
        }

        let voters_stake: u64 = hotkeys
            .iter()
            .filter_map(|h| self.validator_set.get_validator(h))
            .filter(|v| v.is_active)
            .map(|v| v.stake)
            .sum();

        voters_stake as f64 / total_stake as f64
    }

    /// Check if votes meet the required threshold
    pub fn meets_threshold(&self, voters: &[Hotkey], threshold: f64) -> bool {
        self.total_voting_power(voters) >= threshold
    }

    /// Check if votes meet 2f+1 quorum (by count, not stake)
    pub fn meets_quorum(&self, voter_count: usize) -> bool {
        voter_count >= self.validator_set.quorum_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_keypair() -> Keypair {
        Keypair::generate()
    }

    fn create_validator_set() -> ValidatorSet {
        let keypair = create_test_keypair();
        ValidatorSet::new(keypair, 1000)
    }

    #[test]
    fn test_validator_record_creation() {
        let hotkey = Hotkey([1u8; 32]);
        let record = ValidatorRecord::new(hotkey.clone(), 1_000_000);
        assert_eq!(record.hotkey, hotkey);
        assert_eq!(record.stake, 1_000_000);
        assert!(record.is_active);
    }

    #[test]
    fn test_validator_set_registration() {
        let set = create_validator_set();
        let record = ValidatorRecord::new(Hotkey([1u8; 32]), 10_000);

        set.register_validator(record.clone()).unwrap();
        assert!(set.is_validator(&record.hotkey));
    }

    #[test]
    fn test_insufficient_stake() {
        let set = create_validator_set();
        let record = ValidatorRecord::new(Hotkey([1u8; 32]), 500); // Below min_stake

        let result = set.register_validator(record);
        assert!(matches!(
            result,
            Err(ValidatorError::InsufficientStake { .. })
        ));
    }

    #[test]
    fn test_fault_tolerance() {
        let set = create_validator_set();

        // Add 4 validators (n=4, f=1)
        for i in 0..4 {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            let record = ValidatorRecord::new(Hotkey(bytes), 10_000);
            set.register_validator(record).unwrap();
        }

        assert_eq!(set.fault_tolerance(), 1);
        assert_eq!(set.quorum_size(), 3);
    }

    #[test]
    fn test_leader_election() {
        let keypair = create_test_keypair();
        let set = Arc::new(ValidatorSet::new(keypair, 1000));

        // Add validators with different stakes
        for i in 0..3 {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            let record = ValidatorRecord::new(Hotkey(bytes), 10_000 - i as u64 * 1000);
            set.register_validator(record).unwrap();
        }

        let election = LeaderElection::new(set);

        // Leader should cycle through validators
        let leader0 = election.leader_for_view(0).unwrap();
        let leader1 = election.leader_for_view(1).unwrap();
        let leader3 = election.leader_for_view(3).unwrap();

        // View 0 and View 3 should have same leader (3 validators)
        assert_eq!(leader0, leader3);
        assert_ne!(leader0, leader1);
    }

    #[test]
    fn test_stake_weighted_voting() {
        let keypair = create_test_keypair();
        let set = Arc::new(ValidatorSet::new(keypair, 1000));

        // Add validators: one with 7000 stake, one with 3000
        let mut bytes1 = [0u8; 32];
        bytes1[0] = 1;
        let record1 = ValidatorRecord::new(Hotkey(bytes1), 7000);
        set.register_validator(record1.clone()).unwrap();

        let mut bytes2 = [0u8; 32];
        bytes2[0] = 2;
        let record2 = ValidatorRecord::new(Hotkey(bytes2), 3000);
        set.register_validator(record2.clone()).unwrap();

        let voting = StakeWeightedVoting::new(set);

        // Validator 1 should have 70% voting power
        let power1 = voting.voting_power(&record1.hotkey);
        assert!((power1 - 0.7).abs() < 0.01);

        // Validator 2 should have 30% voting power
        let power2 = voting.voting_power(&record2.hotkey);
        assert!((power2 - 0.3).abs() < 0.01);

        // Together they have 100%
        assert!(voting.meets_threshold(&[record1.hotkey, record2.hotkey], 0.99));
    }

    #[test]
    fn test_validator_staleness() {
        let record = ValidatorRecord::new(Hotkey([1u8; 32]), 10_000);

        // New record should not be stale
        assert!(!record.is_stale(90_000));

        // Record with old timestamp should be stale
        let mut old_record = record;
        old_record.last_seen = chrono::Utc::now().timestamp_millis() - 100_000;
        assert!(old_record.is_stale(90_000));
    }

    #[test]
    fn test_update_from_heartbeat() {
        let set = create_validator_set();
        let hotkey = Hotkey([1u8; 32]);
        let record = ValidatorRecord::new(hotkey.clone(), 10_000);
        set.register_validator(record).unwrap();

        let new_hash = [42u8; 32];
        set.update_from_heartbeat(&hotkey, new_hash, 100, 15_000)
            .unwrap();

        let updated = set.get_validator(&hotkey).unwrap();
        assert_eq!(updated.state_hash, new_hash);
        assert_eq!(updated.last_sequence, 100);
        assert_eq!(updated.stake, 15_000);
    }
}
