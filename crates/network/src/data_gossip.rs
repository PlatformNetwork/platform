//! Challenge Data Gossip Protocol
//!
//! Enables validators to submit and sync challenge-specific data.
//!
//! # Data Flow
//!
//! 1. Validator executes challenge code
//! 2. Challenge code produces data to store
//! 3. Validator signs and broadcasts data
//! 4. Other validators verify via challenge code
//! 5. Verified data is stored locally
//!
//! # Verification
//!
//! Each challenge defines its own verification rules:
//! - Data format validation
//! - Business logic validation
//! - Signature verification
//! - Quorum requirements

use parking_lot::RwLock;
use platform_core::{Hotkey, Keypair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp_core::{crypto::Pair as _, sr25519};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Data submission from a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorDataSubmission {
    /// Challenge this data belongs to
    pub challenge_id: String,
    /// Submitting validator's hotkey
    pub validator: String,
    /// Data key (namespaced within challenge)
    pub key: String,
    /// Data value (JSON or binary)
    pub value: Vec<u8>,
    /// Block height when submitted
    pub block_height: u64,
    /// Epoch when submitted
    pub epoch: u64,
    /// Timestamp (unix millis)
    pub timestamp: u64,
    /// Nonce to prevent replay
    pub nonce: u64,
    /// Signature over the above fields
    pub signature: Vec<u8>,
    /// Optional metadata (challenge-specific)
    pub metadata: Option<serde_json::Value>,
}

impl ValidatorDataSubmission {
    /// Create a new submission
    pub fn new(
        challenge_id: String,
        validator: String,
        key: String,
        value: Vec<u8>,
        block_height: u64,
        epoch: u64,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Self {
            challenge_id,
            validator,
            key,
            value,
            block_height,
            epoch,
            timestamp,
            nonce: rand::random(),
            signature: vec![],
            metadata: None,
        }
    }

    /// Sign the submission
    pub fn sign(&mut self, keypair: &Keypair) -> Result<(), String> {
        let message = self.signing_message();
        let signed = keypair.sign(&message);
        self.signature = signed.signature;
        Ok(())
    }

    /// Verify the sr25519 signature against the claimed hotkey
    pub fn verify(&self) -> bool {
        if self.signature.len() != 64 {
            return false;
        }

        let hotkey = match Hotkey::from_hex(&self.validator) {
            Some(h) => h,
            None => return false,
        };

        // Parse the sr25519 signature
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);
        let signature = sr25519::Signature::from_raw(sig_bytes);

        // Get the public key from the claimed hotkey
        let public = sr25519::Public::from_raw(hotkey.0);

        // Verify: signature must match the message signed by the claimed hotkey
        let message = self.signing_message();
        sr25519::Pair::verify(&signature, &message, &public)
    }

    /// Get the message to sign
    fn signing_message(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.challenge_id);
        hasher.update(&self.validator);
        hasher.update(&self.key);
        hasher.update(&self.value);
        hasher.update(self.block_height.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        hasher.finalize().to_vec()
    }

    /// Get unique ID for this submission
    pub fn id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.challenge_id);
        hasher.update(&self.validator);
        hasher.update(&self.key);
        hasher.update(self.nonce.to_le_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Verification result from challenge code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataVerificationResult {
    /// Whether data is valid
    pub valid: bool,
    /// Error message if invalid
    pub error: Option<String>,
    /// Should this data be stored?
    pub should_store: bool,
    /// Optional transformed value (challenge can modify before storing)
    pub transformed_value: Option<Vec<u8>>,
    /// Expiration (blocks from now, 0 = permanent)
    pub expires_in_blocks: u64,
}

impl DataVerificationResult {
    pub fn valid() -> Self {
        Self {
            valid: true,
            error: None,
            should_store: true,
            transformed_value: None,
            expires_in_blocks: 0,
        }
    }

    pub fn invalid(error: impl Into<String>) -> Self {
        Self {
            valid: false,
            error: Some(error.into()),
            should_store: false,
            transformed_value: None,
            expires_in_blocks: 0,
        }
    }

    pub fn with_expiration(mut self, blocks: u64) -> Self {
        self.expires_in_blocks = blocks;
        self
    }

    pub fn with_transformed(mut self, value: Vec<u8>) -> Self {
        self.transformed_value = Some(value);
        self
    }
}

/// Callback for challenge to verify data
pub type DataVerifier =
    Arc<dyn Fn(&ValidatorDataSubmission) -> DataVerificationResult + Send + Sync>;

/// Data gossip message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataGossipMessage {
    /// New data submission
    Submit(ValidatorDataSubmission),
    /// Request data by key
    Request { challenge_id: String, key: String },
    /// Response to data request
    Response {
        challenge_id: String,
        key: String,
        submissions: Vec<ValidatorDataSubmission>,
    },
    /// Data accepted notification
    Accepted {
        submission_id: String,
        by_validator: String,
    },
    /// Data rejected notification
    Rejected {
        submission_id: String,
        by_validator: String,
        reason: String,
    },
}

/// Stored data entry with consensus info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredDataEntry {
    pub submission: ValidatorDataSubmission,
    /// Validators who accepted this data
    pub accepted_by: HashSet<String>,
    /// Validators who rejected this data
    pub rejected_by: HashMap<String, String>,
    /// Block when first seen
    pub first_seen_block: u64,
    /// Block when reached consensus (quorum)
    pub consensus_block: Option<u64>,
    /// Expiration block (if set)
    pub expires_at: Option<u64>,
}

impl StoredDataEntry {
    pub fn new(submission: ValidatorDataSubmission, current_block: u64) -> Self {
        Self {
            submission,
            accepted_by: HashSet::new(),
            rejected_by: HashMap::new(),
            first_seen_block: current_block,
            consensus_block: None,
            expires_at: None,
        }
    }

    /// Check if we have consensus (2/3 of validators)
    pub fn has_consensus(&self, total_validators: usize) -> bool {
        let required = (total_validators * 2) / 3 + 1;
        self.accepted_by.len() >= required
    }

    /// Check if expired
    pub fn is_expired(&self, current_block: u64) -> bool {
        self.expires_at.map(|e| current_block >= e).unwrap_or(false)
    }
}

/// Configuration for data gossip
#[derive(Debug, Clone)]
pub struct DataGossipConfig {
    /// Maximum pending submissions
    pub max_pending: usize,
    /// Maximum data size per submission (bytes)
    pub max_data_size: usize,
    /// TTL for pending submissions (blocks)
    pub pending_ttl_blocks: u64,
    /// Require consensus before storing
    pub require_consensus: bool,
    /// Minimum validators for consensus
    pub min_consensus_validators: usize,
}

impl Default for DataGossipConfig {
    fn default() -> Self {
        Self {
            max_pending: 10000,
            max_data_size: 1024 * 1024, // 1MB
            pending_ttl_blocks: 100,
            require_consensus: true,
            min_consensus_validators: 3,
        }
    }
}

/// Data gossip manager
pub struct DataGossip {
    config: DataGossipConfig,
    /// Pending submissions awaiting consensus
    pending: Arc<RwLock<HashMap<String, StoredDataEntry>>>,
    /// Accepted data
    accepted: Arc<RwLock<HashMap<String, HashMap<String, StoredDataEntry>>>>,
    /// Challenge verifiers
    verifiers: Arc<RwLock<HashMap<String, DataVerifier>>>,
    /// Our validator hotkey
    local_validator: String,
    /// Current block height
    block_height: Arc<RwLock<u64>>,
    /// Total validator count
    validator_count: Arc<RwLock<usize>>,
}

impl DataGossip {
    /// Create a new data gossip manager
    pub fn new(config: DataGossipConfig, local_validator: String) -> Self {
        Self {
            config,
            pending: Arc::new(RwLock::new(HashMap::new())),
            accepted: Arc::new(RwLock::new(HashMap::new())),
            verifiers: Arc::new(RwLock::new(HashMap::new())),
            local_validator,
            block_height: Arc::new(RwLock::new(0)),
            validator_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Register a verifier for a challenge
    pub fn register_verifier(&self, challenge_id: &str, verifier: DataVerifier) {
        self.verifiers
            .write()
            .insert(challenge_id.to_string(), verifier);
        info!("Registered data verifier for challenge {}", challenge_id);
    }

    /// Unregister a verifier
    pub fn unregister_verifier(&self, challenge_id: &str) {
        self.verifiers.write().remove(challenge_id);
    }

    /// Set current block height
    pub fn set_block_height(&self, height: u64) {
        *self.block_height.write() = height;
    }

    /// Set validator count
    pub fn set_validator_count(&self, count: usize) {
        *self.validator_count.write() = count;
    }

    /// Submit data (returns message to broadcast)
    pub fn submit(&self, submission: ValidatorDataSubmission) -> Result<DataGossipMessage, String> {
        // Validate size
        if submission.value.len() > self.config.max_data_size {
            return Err(format!(
                "Data too large: {} > {}",
                submission.value.len(),
                self.config.max_data_size
            ));
        }

        // Verify our own submission
        let verifiers = self.verifiers.read();
        if let Some(verifier) = verifiers.get(&submission.challenge_id) {
            let result = verifier(&submission);
            if !result.valid {
                return Err(result.error.unwrap_or_else(|| "Invalid data".to_string()));
            }
        }
        drop(verifiers);

        // Add to pending
        let id = submission.id();
        let block_height = *self.block_height.read();
        let mut entry = StoredDataEntry::new(submission.clone(), block_height);
        entry.accepted_by.insert(self.local_validator.clone());

        self.pending.write().insert(id.clone(), entry);

        info!(
            "Submitted data: challenge={}, key={}, id={}",
            submission.challenge_id, submission.key, id
        );

        Ok(DataGossipMessage::Submit(submission))
    }

    /// Handle incoming data submission
    pub fn handle_submission(
        &self,
        submission: ValidatorDataSubmission,
    ) -> Option<DataGossipMessage> {
        let id = submission.id();

        // Check if already processed
        if self.pending.read().contains_key(&id) {
            return None;
        }

        // Validate signature
        if !submission.verify() {
            warn!("Invalid signature on submission {}", id);
            return Some(DataGossipMessage::Rejected {
                submission_id: id,
                by_validator: self.local_validator.clone(),
                reason: "Invalid signature".to_string(),
            });
        }

        // Validate size
        if submission.value.len() > self.config.max_data_size {
            return Some(DataGossipMessage::Rejected {
                submission_id: id,
                by_validator: self.local_validator.clone(),
                reason: "Data too large".to_string(),
            });
        }

        // Run challenge verifier
        let verifiers = self.verifiers.read();
        let verification = if let Some(verifier) = verifiers.get(&submission.challenge_id) {
            verifier(&submission)
        } else {
            // No verifier = accept by default (challenge will handle on its own)
            DataVerificationResult::valid()
        };
        drop(verifiers);

        if !verification.valid {
            return Some(DataGossipMessage::Rejected {
                submission_id: id.clone(),
                by_validator: self.local_validator.clone(),
                reason: verification
                    .error
                    .unwrap_or_else(|| "Verification failed".to_string()),
            });
        }

        // Add to pending
        let block_height = *self.block_height.read();
        let mut entry = StoredDataEntry::new(submission.clone(), block_height);

        if verification.expires_in_blocks > 0 {
            entry.expires_at = Some(block_height + verification.expires_in_blocks);
        }

        entry.accepted_by.insert(self.local_validator.clone());
        self.pending.write().insert(id.clone(), entry);

        debug!(
            "Accepted submission {} for challenge {}",
            id, submission.challenge_id
        );

        Some(DataGossipMessage::Accepted {
            submission_id: id,
            by_validator: self.local_validator.clone(),
        })
    }

    /// Handle acceptance notification
    pub fn handle_accepted(&self, submission_id: &str, by_validator: &str) {
        let mut pending = self.pending.write();
        if let Some(entry) = pending.get_mut(submission_id) {
            entry.accepted_by.insert(by_validator.to_string());

            // Check for consensus
            let validator_count = *self.validator_count.read();
            if entry.has_consensus(validator_count) && entry.consensus_block.is_none() {
                let block_height = *self.block_height.read();
                entry.consensus_block = Some(block_height);

                // Move to accepted
                let challenge_id = entry.submission.challenge_id.clone();
                let key = entry.submission.key.clone();
                let entry_clone = entry.clone();

                drop(pending);

                let mut accepted = self.accepted.write();
                let challenge_data = accepted.entry(challenge_id.clone()).or_default();
                challenge_data.insert(key.clone(), entry_clone);

                info!(
                    "Data reached consensus: challenge={}, key={}",
                    challenge_id, key
                );
            }
        }
    }

    /// Handle rejection notification
    pub fn handle_rejected(&self, submission_id: &str, by_validator: &str, reason: &str) {
        let mut pending = self.pending.write();
        if let Some(entry) = pending.get_mut(submission_id) {
            entry
                .rejected_by
                .insert(by_validator.to_string(), reason.to_string());
        }
    }

    /// Get data for a challenge/key
    pub fn get(&self, challenge_id: &str, key: &str) -> Option<StoredDataEntry> {
        self.accepted
            .read()
            .get(challenge_id)
            .and_then(|m| m.get(key))
            .cloned()
    }

    /// Get all data for a challenge
    pub fn get_challenge_data(&self, challenge_id: &str) -> Vec<StoredDataEntry> {
        self.accepted
            .read()
            .get(challenge_id)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Cleanup expired entries
    pub fn cleanup(&self) {
        let block_height = *self.block_height.read();

        // Clean pending
        self.pending.write().retain(|_, entry| {
            !entry.is_expired(block_height)
                && block_height - entry.first_seen_block < self.config.pending_ttl_blocks
        });

        // Clean accepted
        let mut accepted = self.accepted.write();
        for challenge_data in accepted.values_mut() {
            challenge_data.retain(|_, entry| !entry.is_expired(block_height));
        }
    }

    /// Get stats
    pub fn stats(&self) -> DataGossipStats {
        DataGossipStats {
            pending_count: self.pending.read().len(),
            accepted_challenges: self.accepted.read().len(),
            total_accepted: self.accepted.read().values().map(|m| m.len()).sum(),
            verifiers_count: self.verifiers.read().len(),
        }
    }
}

/// Statistics for data gossip
#[derive(Debug, Clone)]
pub struct DataGossipStats {
    pub pending_count: usize,
    pub accepted_challenges: usize,
    pub total_accepted: usize,
    pub verifiers_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submission_id() {
        let sub1 = ValidatorDataSubmission::new(
            "challenge1".to_string(),
            "validator1".to_string(),
            "key1".to_string(),
            vec![1, 2, 3],
            100,
            1,
        );

        let sub2 = ValidatorDataSubmission::new(
            "challenge1".to_string(),
            "validator1".to_string(),
            "key1".to_string(),
            vec![1, 2, 3],
            100,
            1,
        );

        // Different nonces = different IDs
        assert_ne!(sub1.id(), sub2.id());
    }

    #[test]
    fn test_verification_result() {
        let valid = DataVerificationResult::valid();
        assert!(valid.valid);
        assert!(valid.should_store);

        let invalid = DataVerificationResult::invalid("Bad data");
        assert!(!invalid.valid);
        assert!(!invalid.should_store);
    }

    #[test]
    fn test_consensus() {
        let sub = ValidatorDataSubmission::new(
            "c1".to_string(),
            "v1".to_string(),
            "k1".to_string(),
            vec![],
            1,
            1,
        );

        let mut entry = StoredDataEntry::new(sub, 1);

        // 5 validators, need 4 for consensus (2/3 + 1)
        assert!(!entry.has_consensus(5));

        entry.accepted_by.insert("v1".to_string());
        entry.accepted_by.insert("v2".to_string());
        entry.accepted_by.insert("v3".to_string());
        assert!(!entry.has_consensus(5));

        entry.accepted_by.insert("v4".to_string());
        assert!(entry.has_consensus(5));
    }

    #[test]
    fn test_submission_sign_and_verify() {
        let keypair = Keypair::generate();
        let mut sub = ValidatorDataSubmission::new(
            "test-challenge".to_string(),
            keypair.hotkey().to_hex(),
            "test-key".to_string(),
            vec![1, 2, 3, 4, 5],
            100,
            1,
        );

        assert!(sub.sign(&keypair).is_ok());
        assert!(!sub.signature.is_empty());
        assert!(sub.verify());
    }

    #[test]
    fn test_submission_invalid_signature() {
        let keypair = Keypair::generate();
        let mut sub = ValidatorDataSubmission::new(
            "test-challenge".to_string(),
            keypair.hotkey().to_hex(),
            "test-key".to_string(),
            vec![1, 2, 3],
            100,
            1,
        );

        // Invalid signature length
        sub.signature = vec![0; 32];
        assert!(!sub.verify());

        // Empty signature
        sub.signature = vec![];
        assert!(!sub.verify());
    }

    #[test]
    fn test_submission_with_metadata() {
        let mut sub = ValidatorDataSubmission::new(
            "challenge".to_string(),
            "validator".to_string(),
            "key".to_string(),
            vec![],
            100,
            1,
        );

        assert!(sub.metadata.is_none());
        sub.metadata = Some(serde_json::json!({"score": 85}));
        assert!(sub.metadata.is_some());
    }

    #[test]
    fn test_stored_data_entry_creation() {
        let sub = ValidatorDataSubmission::new(
            "c1".to_string(),
            "v1".to_string(),
            "k1".to_string(),
            vec![1, 2, 3],
            100,
            1,
        );

        let entry = StoredDataEntry::new(sub.clone(), 100);

        assert_eq!(entry.first_seen_block, 100);
        assert_eq!(entry.submission.challenge_id, "c1");
        assert_eq!(entry.submission.validator, "v1");
        assert!(entry.accepted_by.is_empty());
    }

    #[test]
    fn test_data_gossip_config_default() {
        let config = DataGossipConfig::default();
        assert!(config.min_consensus_validators > 0);
        assert!(config.pending_ttl_blocks > 0);
        assert!(config.max_pending > 0);
        assert!(config.max_data_size > 0);
    }

    #[test]
    fn test_verification_result_error_message() {
        let result = DataVerificationResult::invalid("Test error message");
        assert!(!result.valid);
        assert_eq!(result.error, Some("Test error message".to_string()));
    }

    #[test]
    fn test_submission_id_deterministic() {
        let sub = ValidatorDataSubmission {
            challenge_id: "c1".to_string(),
            validator: "v1".to_string(),
            key: "k1".to_string(),
            value: vec![1, 2, 3],
            block_height: 100,
            epoch: 1,
            timestamp: 12345,
            nonce: 99999,
            signature: vec![],
            metadata: None,
        };

        let id1 = sub.id();
        let id2 = sub.id();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // SHA256 hex = 64 chars
    }

    #[test]
    fn test_verification_result_with_expiration() {
        let result = DataVerificationResult::valid().with_expiration(1000);
        assert!(result.valid);
        assert_eq!(result.expires_in_blocks, 1000);
    }

    #[test]
    fn test_verification_result_with_transformed() {
        let transformed = vec![9, 8, 7];
        let result = DataVerificationResult::valid().with_transformed(transformed.clone());
        assert!(result.valid);
        assert_eq!(result.transformed_value, Some(transformed));
    }

    #[test]
    fn test_signing_message_consistency() {
        let sub1 = ValidatorDataSubmission {
            challenge_id: "c1".to_string(),
            validator: "v1".to_string(),
            key: "k1".to_string(),
            value: vec![1, 2, 3],
            block_height: 100,
            epoch: 1,
            timestamp: 12345,
            nonce: 99999,
            signature: vec![],
            metadata: None,
        };

        let sub2 = ValidatorDataSubmission {
            challenge_id: "c1".to_string(),
            validator: "v1".to_string(),
            key: "k1".to_string(),
            value: vec![1, 2, 3],
            block_height: 100,
            epoch: 1,
            timestamp: 12345,
            nonce: 99999,
            signature: vec![],
            metadata: None,
        };

        assert_eq!(sub1.signing_message(), sub2.signing_message());
    }

    #[test]
    fn test_stored_entry_accepted_by() {
        let sub = ValidatorDataSubmission::new(
            "c1".to_string(),
            "v1".to_string(),
            "k1".to_string(),
            vec![],
            1,
            1,
        );

        let mut entry = StoredDataEntry::new(sub, 1);
        assert!(entry.accepted_by.is_empty());

        entry.accepted_by.insert("validator1".to_string());
        entry.accepted_by.insert("validator2".to_string());
        assert_eq!(entry.accepted_by.len(), 2);

        // Duplicate doesn't increase count
        entry.accepted_by.insert("validator1".to_string());
        assert_eq!(entry.accepted_by.len(), 2);
    }
}
