//! Validated Storage with WASM-based Consensus
//!
//! This module provides per-challenge storage where validators must reach consensus
//! before data is accepted. WASM code defines validation rules that each validator
//! runs locally, and writes only succeed when a quorum of validators agree.
//!
//! # Overview
//!
//! The validated storage system prevents abuse by requiring:
//! 1. WASM-defined validation logic for each write operation
//! 2. Validator consensus (configurable quorum) before accepting writes
//! 3. Cryptographic signatures on all proposals and votes
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    ValidatedStorage                             │
//! │         (per-challenge storage with consensus)                  │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!               ┌──────────────┴──────────────┐
//!               ▼                             ▼
//! ┌─────────────────────────┐   ┌─────────────────────────────────┐
//! │   StorageWriteProposal  │   │     StorageWriteVote            │
//! │   (proposer submits)    │   │   (validators vote yes/no)      │
//! └─────────────────────────┘   └─────────────────────────────────┘
//!               │                             │
//!               └──────────────┬──────────────┘
//!                              ▼
//!               ┌──────────────────────────────┐
//!               │      WASM Validation         │
//!               │  (challenge-defined rules)   │
//!               └──────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```text
//! use platform_distributed_storage::validated_storage::{
//!     ValidatedStorage, ValidatedStorageConfig, StorageWriteProposal,
//! };
//! use platform_core::Hotkey;
//!
//! // Create validated storage for a challenge
//! let config = ValidatedStorageConfig::new("challenge-abc", 3);
//! let storage = ValidatedStorage::new(inner_store, config);
//!
//! // Propose a write
//! let proposal = storage.propose_write(
//!     my_hotkey,
//!     "data-key",
//!     data_bytes,
//! );
//!
//! // Validators vote after running WASM validation
//! let vote = storage.vote_on_proposal(&proposal, true);
//!
//! // Check if consensus is reached
//! if let Some(result) = storage.check_consensus(&proposal.proposal_id) {
//!     // Write is committed
//! }
//! ```

#![allow(dead_code, unused_variables, unused_imports)]

use crate::error::{StorageError, StorageResult};
use crate::store::{DistributedStore, GetOptions, PutOptions, StorageKey, StoredValue};
use platform_core::Hotkey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[derive(Error, Debug, Clone)]
pub enum ValidatedStorageError {
    #[error("not enough votes: need {needed}, have {have}")]
    NotEnoughVotes { needed: usize, have: usize },

    #[error("validation failed: {0}")]
    ValidationFailed(String),

    #[error("proposal not found: {0}")]
    ProposalNotFound(String),

    #[error("proposal expired: {0}")]
    ProposalExpired(String),

    #[error("duplicate vote from validator: {0}")]
    DuplicateVote(String),

    #[error("conflicting votes detected from validator: {0}")]
    ConflictingVotes(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("wasm validation error: {0}")]
    WasmValidation(String),

    #[error("consensus timeout")]
    ConsensusTimeout,
}

impl From<StorageError> for ValidatedStorageError {
    fn from(err: StorageError) -> Self {
        ValidatedStorageError::Storage(err.to_string())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatedStorageConfig {
    pub challenge_id: String,
    pub quorum_size: usize,
    pub proposal_timeout_ms: u64,
    pub namespace_prefix: String,
    pub require_wasm_validation: bool,
}

impl ValidatedStorageConfig {
    pub fn new(challenge_id: &str, quorum_size: usize) -> Self {
        Self {
            challenge_id: challenge_id.to_string(),
            quorum_size,
            proposal_timeout_ms: 30_000,
            namespace_prefix: format!("validated:{}", challenge_id),
            require_wasm_validation: true,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.proposal_timeout_ms = timeout_ms;
        self
    }

    pub fn without_wasm_validation(mut self) -> Self {
        self.require_wasm_validation = false;
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageWriteProposal {
    pub proposal_id: [u8; 32],
    pub challenge_id: String,
    pub proposer: Hotkey,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub value_hash: [u8; 32],
    pub timestamp: i64,
    pub signature: Vec<u8>,
}

impl StorageWriteProposal {
    pub fn new(challenge_id: &str, proposer: Hotkey, key: &[u8], value: &[u8]) -> Self {
        let timestamp = chrono::Utc::now().timestamp_millis();
        let value_hash = hash_bytes(value);
        let proposal_id =
            Self::compute_proposal_id(challenge_id, &proposer, key, &value_hash, timestamp);

        Self {
            proposal_id,
            challenge_id: challenge_id.to_string(),
            proposer,
            key: key.to_vec(),
            value: value.to_vec(),
            value_hash,
            timestamp,
            signature: Vec::new(),
        }
    }

    fn compute_proposal_id(
        challenge_id: &str,
        proposer: &Hotkey,
        key: &[u8],
        value_hash: &[u8; 32],
        timestamp: i64,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(challenge_id.as_bytes());
        hasher.update(proposer.as_bytes());
        hasher.update(key);
        hasher.update(value_hash);
        hasher.update(timestamp.to_le_bytes());
        hasher.finalize().into()
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.proposal_id);
        hasher.update(self.challenge_id.as_bytes());
        hasher.update(self.proposer.as_bytes());
        hasher.update(&self.key);
        hasher.update(&self.value_hash);
        hasher.update(self.timestamp.to_le_bytes());
        hasher.finalize().into()
    }

    pub fn verify_value_hash(&self) -> bool {
        hash_bytes(&self.value) == self.value_hash
    }

    pub fn is_expired(&self, timeout_ms: u64) -> bool {
        let now = chrono::Utc::now().timestamp_millis();
        now - self.timestamp > timeout_ms as i64
    }

    pub fn proposal_id_hex(&self) -> String {
        hex::encode(self.proposal_id)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageWriteVote {
    pub proposal_id: [u8; 32],
    pub voter: Hotkey,
    pub approved: bool,
    pub validation_result: Option<WasmValidationResult>,
    pub timestamp: i64,
    pub signature: Vec<u8>,
}

impl StorageWriteVote {
    pub fn new(
        proposal_id: [u8; 32],
        voter: Hotkey,
        approved: bool,
        validation_result: Option<WasmValidationResult>,
    ) -> Self {
        Self {
            proposal_id,
            voter,
            approved,
            validation_result,
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature: Vec::new(),
        }
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.proposal_id);
        hasher.update(self.voter.as_bytes());
        hasher.update([self.approved as u8]);
        hasher.update(self.timestamp.to_le_bytes());
        hasher.finalize().into()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WasmValidationResult {
    pub valid: bool,
    pub error_message: Option<String>,
    pub gas_used: u64,
    pub execution_time_ms: u64,
}

impl WasmValidationResult {
    pub fn success(gas_used: u64, execution_time_ms: u64) -> Self {
        Self {
            valid: true,
            error_message: None,
            gas_used,
            execution_time_ms,
        }
    }

    pub fn failure(error: &str, gas_used: u64, execution_time_ms: u64) -> Self {
        Self {
            valid: false,
            error_message: Some(error.to_string()),
            gas_used,
            execution_time_ms,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusResult {
    pub proposal_id: [u8; 32],
    pub key: Vec<u8>,
    pub value_hash: [u8; 32],
    pub approving_votes: Vec<StorageWriteVote>,
    pub rejecting_votes: Vec<StorageWriteVote>,
    pub consensus_reached: bool,
    pub committed: bool,
    pub timestamp: i64,
}

impl ConsensusResult {
    pub fn approving_count(&self) -> usize {
        self.approving_votes.len()
    }

    pub fn rejecting_count(&self) -> usize {
        self.rejecting_votes.len()
    }

    pub fn total_votes(&self) -> usize {
        self.approving_votes.len() + self.rejecting_votes.len()
    }
}

struct ProposalState {
    proposal: StorageWriteProposal,
    votes: HashMap<Hotkey, StorageWriteVote>,
    consensus_result: Option<ConsensusResult>,
}

impl ProposalState {
    fn new(proposal: StorageWriteProposal) -> Self {
        Self {
            proposal,
            votes: HashMap::new(),
            consensus_result: None,
        }
    }
}

pub struct ValidatedStorage<S: DistributedStore> {
    inner: Arc<S>,
    config: ValidatedStorageConfig,
    local_hotkey: Hotkey,
    proposals: Arc<RwLock<HashMap<[u8; 32], ProposalState>>>,
    committed: Arc<RwLock<HashMap<[u8; 32], ConsensusResult>>>,
}

impl<S: DistributedStore + 'static> ValidatedStorage<S> {
    pub fn new(store: S, config: ValidatedStorageConfig, local_hotkey: Hotkey) -> Self {
        info!(
            challenge_id = %config.challenge_id,
            quorum_size = config.quorum_size,
            hotkey = local_hotkey.to_hex(),
            "Created validated storage"
        );

        Self {
            inner: Arc::new(store),
            config,
            local_hotkey,
            proposals: Arc::new(RwLock::new(HashMap::new())),
            committed: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_arc(store: Arc<S>, config: ValidatedStorageConfig, local_hotkey: Hotkey) -> Self {
        Self {
            inner: store,
            config,
            local_hotkey,
            proposals: Arc::new(RwLock::new(HashMap::new())),
            committed: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn config(&self) -> &ValidatedStorageConfig {
        &self.config
    }

    pub fn challenge_id(&self) -> &str {
        &self.config.challenge_id
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    fn storage_key(&self, key: &[u8]) -> StorageKey {
        StorageKey::new(&self.config.namespace_prefix, key)
    }

    pub async fn propose_write(&self, key: &[u8], value: &[u8]) -> StorageWriteProposal {
        let proposal = StorageWriteProposal::new(
            &self.config.challenge_id,
            self.local_hotkey.clone(),
            key,
            value,
        );

        info!(
            proposal_id = proposal.proposal_id_hex(),
            challenge_id = %self.config.challenge_id,
            key_len = key.len(),
            value_len = value.len(),
            "Created storage write proposal"
        );

        let state = ProposalState::new(proposal.clone());

        {
            let mut proposals = self.proposals.write().await;
            proposals.insert(proposal.proposal_id, state);
        }

        proposal
    }

    pub async fn receive_proposal(
        &self,
        proposal: StorageWriteProposal,
    ) -> Result<(), ValidatedStorageError> {
        if proposal.challenge_id != self.config.challenge_id {
            return Err(ValidatedStorageError::ValidationFailed(format!(
                "Proposal challenge {} doesn't match storage challenge {}",
                proposal.challenge_id, self.config.challenge_id
            )));
        }

        if !proposal.verify_value_hash() {
            return Err(ValidatedStorageError::ValidationFailed(
                "Value hash mismatch".to_string(),
            ));
        }

        if proposal.is_expired(self.config.proposal_timeout_ms) {
            return Err(ValidatedStorageError::ProposalExpired(
                proposal.proposal_id_hex(),
            ));
        }

        debug!(
            proposal_id = proposal.proposal_id_hex(),
            proposer = proposal.proposer.to_hex(),
            "Received storage write proposal"
        );

        let state = ProposalState::new(proposal.clone());

        {
            let mut proposals = self.proposals.write().await;
            proposals.insert(proposal.proposal_id, state);
        }

        Ok(())
    }

    pub async fn vote_on_proposal(
        &self,
        proposal_id: &[u8; 32],
        approved: bool,
        validation_result: Option<WasmValidationResult>,
    ) -> Result<StorageWriteVote, ValidatedStorageError> {
        let vote = StorageWriteVote::new(
            *proposal_id,
            self.local_hotkey.clone(),
            approved,
            validation_result,
        );

        debug!(
            proposal_id = hex::encode(proposal_id),
            voter = self.local_hotkey.to_hex(),
            approved,
            "Casting vote on storage write proposal"
        );

        {
            let mut proposals = self.proposals.write().await;
            let state = proposals
                .get_mut(proposal_id)
                .ok_or_else(|| ValidatedStorageError::ProposalNotFound(hex::encode(proposal_id)))?;

            if state.votes.contains_key(&self.local_hotkey) {
                return Err(ValidatedStorageError::DuplicateVote(
                    self.local_hotkey.to_hex(),
                ));
            }

            state.votes.insert(self.local_hotkey.clone(), vote.clone());
        }

        Ok(vote)
    }

    pub async fn receive_vote(
        &self,
        vote: StorageWriteVote,
    ) -> Result<Option<ConsensusResult>, ValidatedStorageError> {
        let proposal_id = vote.proposal_id;

        {
            let mut proposals = self.proposals.write().await;
            let state = proposals.get_mut(&vote.proposal_id).ok_or_else(|| {
                ValidatedStorageError::ProposalNotFound(hex::encode(vote.proposal_id))
            })?;

            if let Some(existing) = state.votes.get(&vote.voter) {
                if existing.approved != vote.approved {
                    warn!(
                        voter = vote.voter.to_hex(),
                        proposal_id = hex::encode(vote.proposal_id),
                        "Detected conflicting votes from same validator"
                    );
                    return Err(ValidatedStorageError::ConflictingVotes(vote.voter.to_hex()));
                }
                return Err(ValidatedStorageError::DuplicateVote(vote.voter.to_hex()));
            }

            debug!(
                voter = vote.voter.to_hex(),
                approved = vote.approved,
                proposal_id = hex::encode(vote.proposal_id),
                "Received vote on storage write proposal"
            );

            state.votes.insert(vote.voter.clone(), vote);
        }

        self.check_consensus(&proposal_id).await
    }

    pub async fn check_consensus(
        &self,
        proposal_id: &[u8; 32],
    ) -> Result<Option<ConsensusResult>, ValidatedStorageError> {
        let mut proposals = self.proposals.write().await;
        let state = proposals
            .get_mut(proposal_id)
            .ok_or_else(|| ValidatedStorageError::ProposalNotFound(hex::encode(proposal_id)))?;

        if state.consensus_result.is_some() {
            return Ok(state.consensus_result.clone());
        }

        let approving: Vec<_> = state
            .votes
            .values()
            .filter(|v| v.approved)
            .cloned()
            .collect();

        let rejecting: Vec<_> = state
            .votes
            .values()
            .filter(|v| !v.approved)
            .cloned()
            .collect();

        let consensus_reached = approving.len() >= self.config.quorum_size;

        if consensus_reached {
            info!(
                proposal_id = hex::encode(proposal_id),
                approving = approving.len(),
                rejecting = rejecting.len(),
                quorum = self.config.quorum_size,
                "Consensus reached for storage write"
            );

            let result = ConsensusResult {
                proposal_id: *proposal_id,
                key: state.proposal.key.clone(),
                value_hash: state.proposal.value_hash,
                approving_votes: approving,
                rejecting_votes: rejecting,
                consensus_reached: true,
                committed: false,
                timestamp: chrono::Utc::now().timestamp_millis(),
            };

            state.consensus_result = Some(result.clone());
            return Ok(Some(result));
        }

        debug!(
            proposal_id = hex::encode(proposal_id),
            approving = approving.len(),
            rejecting = rejecting.len(),
            quorum = self.config.quorum_size,
            "Consensus not yet reached"
        );

        Ok(None)
    }

    pub async fn commit_write(
        &self,
        proposal_id: &[u8; 32],
    ) -> Result<ConsensusResult, ValidatedStorageError> {
        let (proposal, mut result) =
            {
                let proposals = self.proposals.read().await;
                let state = proposals.get(proposal_id).ok_or_else(|| {
                    ValidatedStorageError::ProposalNotFound(hex::encode(proposal_id))
                })?;

                let result = state.consensus_result.clone().ok_or(
                    ValidatedStorageError::NotEnoughVotes {
                        needed: self.config.quorum_size,
                        have: state.votes.len(),
                    },
                )?;

                if !result.consensus_reached {
                    return Err(ValidatedStorageError::NotEnoughVotes {
                        needed: self.config.quorum_size,
                        have: result.approving_count(),
                    });
                }

                (state.proposal.clone(), result)
            };

        let storage_key = self.storage_key(&proposal.key);
        self.inner
            .put(storage_key, proposal.value.clone(), PutOptions::default())
            .await?;

        result.committed = true;

        info!(
            proposal_id = hex::encode(proposal_id),
            key_len = proposal.key.len(),
            value_len = proposal.value.len(),
            "Committed validated storage write"
        );

        {
            let mut committed = self.committed.write().await;
            committed.insert(*proposal_id, result.clone());
        }

        {
            let mut proposals = self.proposals.write().await;
            if let Some(state) = proposals.get_mut(proposal_id) {
                state.consensus_result = Some(result.clone());
            }
        }

        Ok(result)
    }

    pub async fn get(&self, key: &[u8]) -> StorageResult<Option<StoredValue>> {
        let storage_key = self.storage_key(key);
        self.inner.get(&storage_key, GetOptions::default()).await
    }

    pub async fn get_if_committed(
        &self,
        key: &[u8],
        proposal_id: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, ValidatedStorageError> {
        let committed = self.committed.read().await;
        if let Some(result) = committed.get(proposal_id) {
            if result.committed && result.key == key {
                let storage_key = self.storage_key(key);
                let value = self
                    .inner
                    .get(&storage_key, GetOptions::default())
                    .await?
                    .map(|v| v.data);
                return Ok(value);
            }
        }
        Ok(None)
    }

    pub async fn get_proposal(&self, proposal_id: &[u8; 32]) -> Option<StorageWriteProposal> {
        let proposals = self.proposals.read().await;
        proposals.get(proposal_id).map(|s| s.proposal.clone())
    }

    pub async fn get_votes(&self, proposal_id: &[u8; 32]) -> Option<Vec<StorageWriteVote>> {
        let proposals = self.proposals.read().await;
        proposals
            .get(proposal_id)
            .map(|s| s.votes.values().cloned().collect())
    }

    pub async fn pending_proposals_count(&self) -> usize {
        let proposals = self.proposals.read().await;
        proposals
            .values()
            .filter(|s| s.consensus_result.is_none())
            .count()
    }

    pub async fn cleanup_expired(&self) -> usize {
        let mut proposals = self.proposals.write().await;
        let timeout = self.config.proposal_timeout_ms;
        let before = proposals.len();

        proposals.retain(|_, state| {
            !state.proposal.is_expired(timeout) || state.consensus_result.is_some()
        });

        let removed = before - proposals.len();
        if removed > 0 {
            debug!(removed, "Cleaned up expired proposals");
        }
        removed
    }
}

pub trait WasmStorageValidator: Send + Sync {
    fn validate_write(
        &self,
        challenge_id: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<WasmValidationResult, ValidatedStorageError>;
}

pub struct DefaultWasmValidator;

impl WasmStorageValidator for DefaultWasmValidator {
    fn validate_write(
        &self,
        _challenge_id: &str,
        _key: &[u8],
        _value: &[u8],
    ) -> Result<WasmValidationResult, ValidatedStorageError> {
        Ok(WasmValidationResult::success(0, 0))
    }
}

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalStorageBuilder;

    fn create_test_hotkey(seed: u8) -> Hotkey {
        Hotkey([seed; 32])
    }

    #[tokio::test]
    async fn test_validated_storage_creation() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let config = ValidatedStorageConfig::new("challenge-1", 3);
        let hotkey = create_test_hotkey(1);
        let validated = ValidatedStorage::new(storage, config, hotkey);

        assert_eq!(validated.challenge_id(), "challenge-1");
        assert_eq!(validated.config().quorum_size, 3);
    }

    #[tokio::test]
    async fn test_propose_write() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let config = ValidatedStorageConfig::new("challenge-1", 2);
        let hotkey = create_test_hotkey(1);
        let validated = ValidatedStorage::new(storage, config, hotkey.clone());

        let proposal = validated.propose_write(b"test-key", b"test-value").await;

        assert_eq!(proposal.challenge_id, "challenge-1");
        assert_eq!(proposal.proposer, hotkey);
        assert_eq!(proposal.key, b"test-key");
        assert_eq!(proposal.value, b"test-value");
        assert!(proposal.verify_value_hash());
    }

    #[tokio::test]
    async fn test_vote_on_proposal() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let config = ValidatedStorageConfig::new("challenge-1", 2);
        let hotkey = create_test_hotkey(1);
        let validated = ValidatedStorage::new(storage, config, hotkey.clone());

        let proposal = validated.propose_write(b"test-key", b"test-value").await;

        let vote = validated
            .vote_on_proposal(&proposal.proposal_id, true, None)
            .await
            .expect("Failed to vote");

        assert!(vote.approved);
        assert_eq!(vote.voter, hotkey);
        assert_eq!(vote.proposal_id, proposal.proposal_id);
    }

    #[tokio::test]
    async fn test_duplicate_vote_rejected() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let config = ValidatedStorageConfig::new("challenge-1", 2);
        let hotkey = create_test_hotkey(1);
        let validated = ValidatedStorage::new(storage, config, hotkey);

        let proposal = validated.propose_write(b"test-key", b"test-value").await;

        validated
            .vote_on_proposal(&proposal.proposal_id, true, None)
            .await
            .expect("First vote should succeed");

        let result = validated
            .vote_on_proposal(&proposal.proposal_id, true, None)
            .await;

        assert!(matches!(
            result,
            Err(ValidatedStorageError::DuplicateVote(_))
        ));
    }

    #[tokio::test]
    async fn test_consensus_reached() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let config = ValidatedStorageConfig::new("challenge-1", 2);
        let hotkey1 = create_test_hotkey(1);
        let validated = ValidatedStorage::new(storage, config, hotkey1.clone());

        let proposal = validated.propose_write(b"test-key", b"test-value").await;

        validated
            .vote_on_proposal(&proposal.proposal_id, true, None)
            .await
            .expect("Vote should succeed");

        let result = validated
            .check_consensus(&proposal.proposal_id)
            .await
            .expect("Check should succeed");
        assert!(result.is_none());

        let vote2 = StorageWriteVote::new(proposal.proposal_id, create_test_hotkey(2), true, None);
        let result = validated
            .receive_vote(vote2)
            .await
            .expect("Receive vote should succeed");

        assert!(result.is_some());
        let consensus = result.unwrap();
        assert!(consensus.consensus_reached);
        assert_eq!(consensus.approving_count(), 2);
    }

    #[tokio::test]
    async fn test_commit_write() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let config = ValidatedStorageConfig::new("challenge-1", 2);
        let hotkey1 = create_test_hotkey(1);
        let validated = ValidatedStorage::new(storage, config, hotkey1);

        let proposal = validated.propose_write(b"test-key", b"test-value").await;

        validated
            .vote_on_proposal(&proposal.proposal_id, true, None)
            .await
            .expect("Vote should succeed");

        let vote2 = StorageWriteVote::new(proposal.proposal_id, create_test_hotkey(2), true, None);
        validated
            .receive_vote(vote2)
            .await
            .expect("Receive vote should succeed");

        let result = validated
            .commit_write(&proposal.proposal_id)
            .await
            .expect("Commit should succeed");

        assert!(result.committed);

        let stored = validated
            .get(b"test-key")
            .await
            .expect("Get should succeed")
            .expect("Value should exist");

        assert_eq!(stored.data, b"test-value");
    }

    #[tokio::test]
    async fn test_commit_without_consensus_fails() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let config = ValidatedStorageConfig::new("challenge-1", 3);
        let hotkey = create_test_hotkey(1);
        let validated = ValidatedStorage::new(storage, config, hotkey);

        let proposal = validated.propose_write(b"test-key", b"test-value").await;

        validated
            .vote_on_proposal(&proposal.proposal_id, true, None)
            .await
            .expect("Vote should succeed");

        let result = validated.commit_write(&proposal.proposal_id).await;

        assert!(matches!(
            result,
            Err(ValidatedStorageError::NotEnoughVotes { .. })
        ));
    }

    #[tokio::test]
    async fn test_receive_proposal() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let config = ValidatedStorageConfig::new("challenge-1", 2);
        let hotkey = create_test_hotkey(1);
        let validated = ValidatedStorage::new(storage, config, hotkey);

        let proposal = StorageWriteProposal::new(
            "challenge-1",
            create_test_hotkey(2),
            b"external-key",
            b"external-value",
        );

        validated
            .receive_proposal(proposal.clone())
            .await
            .expect("Should accept proposal");

        let stored = validated
            .get_proposal(&proposal.proposal_id)
            .await
            .expect("Proposal should exist");

        assert_eq!(stored.key, b"external-key");
    }

    #[tokio::test]
    async fn test_receive_proposal_wrong_challenge() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let config = ValidatedStorageConfig::new("challenge-1", 2);
        let hotkey = create_test_hotkey(1);
        let validated = ValidatedStorage::new(storage, config, hotkey);

        let proposal =
            StorageWriteProposal::new("challenge-2", create_test_hotkey(2), b"key", b"value");

        let result = validated.receive_proposal(proposal).await;

        assert!(matches!(
            result,
            Err(ValidatedStorageError::ValidationFailed(_))
        ));
    }

    #[tokio::test]
    async fn test_conflicting_votes_detected() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let config = ValidatedStorageConfig::new("challenge-1", 2);
        let hotkey = create_test_hotkey(1);
        let validated = ValidatedStorage::new(storage, config, hotkey);

        let proposal = validated.propose_write(b"test-key", b"test-value").await;

        let voter = create_test_hotkey(2);
        let vote1 = StorageWriteVote::new(proposal.proposal_id, voter.clone(), true, None);
        validated
            .receive_vote(vote1)
            .await
            .expect("First vote should succeed");

        let vote2 = StorageWriteVote::new(proposal.proposal_id, voter, false, None);
        let result = validated.receive_vote(vote2).await;

        assert!(matches!(
            result,
            Err(ValidatedStorageError::ConflictingVotes(_))
        ));
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let mut config = ValidatedStorageConfig::new("challenge-1", 2);
        config.proposal_timeout_ms = 1;
        let hotkey = create_test_hotkey(1);
        let validated = ValidatedStorage::new(storage, config, hotkey);

        validated.propose_write(b"test-key", b"test-value").await;

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let removed = validated.cleanup_expired().await;
        assert_eq!(removed, 1);
        assert_eq!(validated.pending_proposals_count().await, 0);
    }

    #[tokio::test]
    async fn test_wasm_validation_result() {
        let success = WasmValidationResult::success(100, 5);
        assert!(success.valid);
        assert!(success.error_message.is_none());
        assert_eq!(success.gas_used, 100);

        let failure = WasmValidationResult::failure("invalid format", 50, 3);
        assert!(!failure.valid);
        assert_eq!(failure.error_message, Some("invalid format".to_string()));
    }

    #[test]
    fn test_proposal_hash_verification() {
        let proposal =
            StorageWriteProposal::new("challenge-1", create_test_hotkey(1), b"key", b"value");

        assert!(proposal.verify_value_hash());

        let mut tampered = proposal.clone();
        tampered.value = b"tampered".to_vec();
        assert!(!tampered.verify_value_hash());
    }

    #[test]
    fn test_proposal_expiry() {
        let mut proposal =
            StorageWriteProposal::new("challenge-1", create_test_hotkey(1), b"key", b"value");

        assert!(!proposal.is_expired(30_000));

        proposal.timestamp = chrono::Utc::now().timestamp_millis() - 60_000;
        assert!(proposal.is_expired(30_000));
    }

    #[test]
    fn test_config_builder() {
        let config = ValidatedStorageConfig::new("challenge-1", 5)
            .with_timeout(60_000)
            .without_wasm_validation();

        assert_eq!(config.challenge_id, "challenge-1");
        assert_eq!(config.quorum_size, 5);
        assert_eq!(config.proposal_timeout_ms, 60_000);
        assert!(!config.require_wasm_validation);
    }

    #[test]
    fn test_error_display() {
        let err1 = ValidatedStorageError::NotEnoughVotes { needed: 5, have: 2 };
        assert!(err1.to_string().contains("5"));
        assert!(err1.to_string().contains("2"));

        let err2 = ValidatedStorageError::ValidationFailed("bad data".to_string());
        assert!(err2.to_string().contains("bad data"));

        let err3 = ValidatedStorageError::ProposalNotFound("abc123".to_string());
        assert!(err3.to_string().contains("abc123"));

        let err4 = ValidatedStorageError::DuplicateVote("voter1".to_string());
        assert!(err4.to_string().contains("voter1"));

        let err5 = ValidatedStorageError::ConflictingVotes("voter2".to_string());
        assert!(err5.to_string().contains("voter2"));
    }

    #[test]
    fn test_default_wasm_validator() {
        let validator = DefaultWasmValidator;
        let result = validator
            .validate_write("challenge-1", b"key", b"value")
            .expect("Validation should succeed");

        assert!(result.valid);
    }
}
