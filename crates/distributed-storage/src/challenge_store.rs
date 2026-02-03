//! Challenge-specific namespaced storage
//!
//! This module provides per-challenge dedicated storage with verifiable merkle proofs.
//! Each challenge gets its own namespace, ensuring data isolation and providing
//! cryptographic verification of all stored data.
//!
//! # Features
//!
//! - **Namespace Isolation**: Each challenge's data is stored in its own namespace,
//!   preventing cross-challenge data access.
//! - **Merkle Proofs**: All write operations return a merkle proof for verification.
//! - **State Root**: Compute a deterministic state root hash for the entire challenge.
//!
//! # Usage
//!
//! ```ignore
//! use platform_distributed_storage::{ChallengeStore, LocalStorageBuilder};
//!
//! let storage = LocalStorageBuilder::new("node-1")
//!     .in_memory()
//!     .build()?;
//!
//! let challenge_store = ChallengeStore::new(storage, "challenge-abc123");
//!
//! // Store a submission
//! let proof = challenge_store.store_submission("hash123", &submission).await?;
//!
//! // Verify the submission is in the store
//! assert!(challenge_store.verify_submission("hash123", &proof));
//! ```

use crate::error::{StorageError, StorageResult};
use crate::store::{DistributedStore, GetOptions, PutOptions, StorageKey};
use crate::submission::{StoredEvaluation, StoredSubmission};
use crate::weights::StoredWeights;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Merkle proof for verifying data inclusion in the challenge store.
///
/// This proof allows verification that a specific piece of data is part
/// of the challenge's state without needing access to the entire state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Root hash of the merkle tree
    pub root: [u8; 32],
    /// Path from leaf to root
    pub path: Vec<MerkleNode>,
    /// Index of the leaf in the tree
    pub leaf_index: usize,
    /// Hash of the leaf data
    pub leaf_hash: [u8; 32],
}

impl MerkleProof {
    /// Verify that this proof is valid for the given data
    pub fn verify(&self, data: &[u8]) -> bool {
        // Compute leaf hash
        let computed_leaf = hash_bytes(data);
        if computed_leaf != self.leaf_hash {
            return false;
        }

        // Walk up the tree
        let mut current = self.leaf_hash;
        for node in &self.path {
            current = if node.is_left {
                hash_pair(&node.sibling_hash, &current)
            } else {
                hash_pair(&current, &node.sibling_hash)
            };
        }

        current == self.root
    }
}

/// A node in the merkle proof path
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleNode {
    /// Hash of the sibling node
    pub sibling_hash: [u8; 32],
    /// Whether the sibling is on the left side
    pub is_left: bool,
}

/// Challenge-specific storage wrapper that provides namespace isolation
/// and merkle proof generation for all stored data.
///
/// This wrapper ensures:
/// - All data is stored in challenge-specific namespaces
/// - All write operations return merkle proofs
/// - State can be verified cryptographically
pub struct ChallengeStore<S: DistributedStore> {
    /// The underlying distributed store
    inner: Arc<S>,
    /// Challenge identifier for namespace isolation
    challenge_id: String,
    /// Cache for merkle tree leaves (key hash -> data hash)
    /// Used for computing state root and generating proofs
    leaf_cache: Arc<RwLock<LeafCache>>,
}

/// Internal cache for tracking merkle tree leaves
struct LeafCache {
    /// Submissions: key -> data hash
    submissions: BTreeMap<String, [u8; 32]>,
    /// Evaluations: key -> data hash
    evaluations: BTreeMap<String, [u8; 32]>,
    /// Weights: epoch -> data hash
    weights: BTreeMap<u64, [u8; 32]>,
}

impl LeafCache {
    fn new() -> Self {
        Self {
            submissions: BTreeMap::new(),
            evaluations: BTreeMap::new(),
            weights: BTreeMap::new(),
        }
    }

    /// Get all leaves in deterministic order
    fn all_leaves(&self) -> Vec<[u8; 32]> {
        let mut leaves = Vec::new();

        // Add submissions (sorted by key)
        for hash in self.submissions.values() {
            leaves.push(*hash);
        }

        // Add evaluations (sorted by key)
        for hash in self.evaluations.values() {
            leaves.push(*hash);
        }

        // Add weights (sorted by epoch)
        for hash in self.weights.values() {
            leaves.push(*hash);
        }

        leaves
    }

    /// Find the index of a submission leaf
    fn submission_index(&self, key: &str) -> Option<usize> {
        self.submissions.keys().position(|k| k == key)
    }

    /// Find the index of an evaluation leaf
    fn evaluation_index(&self, key: &str) -> Option<usize> {
        let submissions_count = self.submissions.len();
        self.evaluations
            .keys()
            .position(|k| k == key)
            .map(|idx| submissions_count + idx)
    }

    /// Find the index of a weights leaf
    fn weights_index(&self, epoch: u64) -> Option<usize> {
        let base = self.submissions.len() + self.evaluations.len();
        self.weights
            .keys()
            .position(|e| *e == epoch)
            .map(|idx| base + idx)
    }
}

impl<S: DistributedStore> ChallengeStore<S> {
    /// Create a new challenge store wrapping the given distributed store.
    ///
    /// # Arguments
    ///
    /// * `store` - The underlying distributed store
    /// * `challenge_id` - Unique identifier for this challenge
    ///
    /// # Returns
    ///
    /// A new `ChallengeStore` instance with namespace isolation for the challenge.
    pub fn new(store: S, challenge_id: &str) -> Self {
        Self {
            inner: Arc::new(store),
            challenge_id: challenge_id.to_string(),
            leaf_cache: Arc::new(RwLock::new(LeafCache::new())),
        }
    }

    /// Create a challenge store with an Arc-wrapped store (for sharing)
    pub fn with_arc(store: Arc<S>, challenge_id: &str) -> Self {
        Self {
            inner: store,
            challenge_id: challenge_id.to_string(),
            leaf_cache: Arc::new(RwLock::new(LeafCache::new())),
        }
    }

    /// Get the challenge ID
    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    /// Get the inner store reference
    pub fn inner(&self) -> &S {
        &self.inner
    }

    // ========================================================================
    // Namespace helpers
    // ========================================================================

    /// Create a namespaced namespace string
    fn namespace(&self, category: &str) -> String {
        format!("{}:{}", category, self.challenge_id)
    }

    /// Create a storage key for a submission
    fn submission_key(&self, hash: &str) -> StorageKey {
        StorageKey::new(&self.namespace("submissions"), hash)
    }

    /// Create a storage key for evaluations of a submission
    fn evaluation_key(&self, submission_hash: &str, validator: &str) -> StorageKey {
        StorageKey::new(
            &self.namespace("evaluations"),
            format!("{}:{}", submission_hash, validator),
        )
    }

    /// Create a storage key for evaluations list prefix
    fn evaluations_prefix(&self, submission_hash: &str) -> String {
        format!("{}:", submission_hash)
    }

    /// Create a storage key for weights at an epoch
    fn weights_key(&self, epoch: u64) -> StorageKey {
        StorageKey::new(&self.namespace("weights"), epoch.to_string())
    }

    // ========================================================================
    // Submission operations
    // ========================================================================

    /// Store a submission and return a merkle proof.
    ///
    /// # Arguments
    ///
    /// * `hash` - Unique hash identifier for the submission
    /// * `data` - The submission data to store
    ///
    /// # Returns
    ///
    /// A merkle proof that can be used to verify the submission's inclusion.
    pub async fn store_submission(
        &self,
        hash: &str,
        data: &StoredSubmission,
    ) -> StorageResult<MerkleProof> {
        let key = self.submission_key(hash);
        let bytes = data
            .to_bytes()
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let data_hash = hash_bytes(&bytes);

        // Store the data
        self.inner
            .put(key, bytes.clone(), PutOptions::default())
            .await?;

        // Update the leaf cache
        {
            let mut cache = self.leaf_cache.write().await;
            cache.submissions.insert(hash.to_string(), data_hash);
        }

        // Generate and return the merkle proof
        self.generate_proof_for_submission(hash, &bytes).await
    }

    /// Get a submission by hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The submission hash to look up
    ///
    /// # Returns
    ///
    /// The stored submission if found, None otherwise.
    pub async fn get_submission(&self, hash: &str) -> StorageResult<Option<StoredSubmission>> {
        let key = self.submission_key(hash);
        let result = self.inner.get(&key, GetOptions::default()).await?;

        match result {
            Some(stored) => {
                let submission = StoredSubmission::from_bytes(&stored.data)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(submission))
            }
            None => Ok(None),
        }
    }

    /// List submissions in this challenge.
    ///
    /// # Arguments
    ///
    /// * `limit` - Maximum number of submissions to return
    ///
    /// # Returns
    ///
    /// A vector of stored submissions.
    pub async fn list_submissions(&self, limit: usize) -> StorageResult<Vec<StoredSubmission>> {
        let namespace = self.namespace("submissions");
        let result = self
            .inner
            .list_prefix(&namespace, None, limit, None)
            .await?;

        let mut submissions = Vec::with_capacity(result.items.len());
        for (_, stored) in result.items {
            if let Ok(submission) = StoredSubmission::from_bytes(&stored.data) {
                submissions.push(submission);
            }
        }

        Ok(submissions)
    }

    // ========================================================================
    // Evaluation operations
    // ========================================================================

    /// Store an evaluation result and return a merkle proof.
    ///
    /// # Arguments
    ///
    /// * `submission_hash` - Hash of the submission being evaluated
    /// * `validator` - Validator hotkey who performed the evaluation
    /// * `eval` - The evaluation data to store
    ///
    /// # Returns
    ///
    /// A merkle proof for the evaluation.
    pub async fn store_evaluation(
        &self,
        submission_hash: &str,
        validator: &str,
        eval: &StoredEvaluation,
    ) -> StorageResult<MerkleProof> {
        let key = self.evaluation_key(submission_hash, validator);
        let bytes = eval
            .to_bytes()
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let data_hash = hash_bytes(&bytes);

        // Store the data
        self.inner
            .put(key, bytes.clone(), PutOptions::default())
            .await?;

        // Update the leaf cache
        let cache_key = format!("{}:{}", submission_hash, validator);
        {
            let mut cache = self.leaf_cache.write().await;
            cache.evaluations.insert(cache_key.clone(), data_hash);
        }

        // Generate and return the merkle proof
        self.generate_proof_for_evaluation(&cache_key, &bytes).await
    }

    /// Get all evaluations for a submission.
    ///
    /// # Arguments
    ///
    /// * `submission_hash` - Hash of the submission
    ///
    /// # Returns
    ///
    /// A vector of evaluations for the submission.
    pub async fn get_evaluations(
        &self,
        submission_hash: &str,
    ) -> StorageResult<Vec<StoredEvaluation>> {
        let namespace = self.namespace("evaluations");
        let prefix = self.evaluations_prefix(submission_hash);
        let result = self
            .inner
            .list_prefix(&namespace, Some(prefix.as_bytes()), 1000, None)
            .await?;

        let mut evaluations = Vec::with_capacity(result.items.len());
        for (_, stored) in result.items {
            if let Ok(eval) = StoredEvaluation::from_bytes(&stored.data) {
                evaluations.push(eval);
            }
        }

        Ok(evaluations)
    }

    // ========================================================================
    // Weights operations
    // ========================================================================

    /// Store weights for an epoch and return a merkle proof.
    ///
    /// # Arguments
    ///
    /// * `epoch` - The epoch number
    /// * `weights` - The weights data to store
    ///
    /// # Returns
    ///
    /// A merkle proof for the weights.
    pub async fn store_weights(
        &self,
        epoch: u64,
        weights: &StoredWeights,
    ) -> StorageResult<MerkleProof> {
        let key = self.weights_key(epoch);
        let bytes = weights
            .to_bytes()
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let data_hash = hash_bytes(&bytes);

        // Store the data
        self.inner
            .put(key, bytes.clone(), PutOptions::default())
            .await?;

        // Update the leaf cache
        {
            let mut cache = self.leaf_cache.write().await;
            cache.weights.insert(epoch, data_hash);
        }

        // Generate and return the merkle proof
        self.generate_proof_for_weights(epoch, &bytes).await
    }

    /// Get weights for a specific epoch.
    ///
    /// # Arguments
    ///
    /// * `epoch` - The epoch number
    ///
    /// # Returns
    ///
    /// The stored weights if found, None otherwise.
    pub async fn get_weights(&self, epoch: u64) -> StorageResult<Option<StoredWeights>> {
        let key = self.weights_key(epoch);
        let result = self.inner.get(&key, GetOptions::default()).await?;

        match result {
            Some(stored) => {
                let weights = StoredWeights::from_bytes(&stored.data)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(weights))
            }
            None => Ok(None),
        }
    }

    // ========================================================================
    // Verification and state root
    // ========================================================================

    /// Verify that a submission is included in the challenge state.
    ///
    /// # Arguments
    ///
    /// * `hash` - The submission hash
    /// * `proof` - The merkle proof to verify
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid for the current state root.
    pub async fn verify_submission(&self, hash: &str, proof: &MerkleProof) -> bool {
        // Get the submission data
        let key = self.submission_key(hash);
        let result = self.inner.get(&key, GetOptions::default()).await;

        match result {
            Ok(Some(stored)) => proof.verify(&stored.data),
            _ => false,
        }
    }

    /// Verify that data matches a merkle proof against a specific root.
    ///
    /// This is a static verification that doesn't require the current state.
    pub fn verify_proof(data: &[u8], proof: &MerkleProof) -> bool {
        proof.verify(data)
    }

    /// Compute the current state root hash for this challenge.
    ///
    /// The state root is computed as a merkle root of all data in the challenge,
    /// ordered deterministically (submissions, then evaluations, then weights,
    /// each sorted by their keys).
    ///
    /// # Returns
    ///
    /// A 32-byte hash representing the current state.
    pub async fn compute_state_root(&self) -> [u8; 32] {
        let cache = self.leaf_cache.read().await;
        let leaves = cache.all_leaves();

        if leaves.is_empty() {
            return [0u8; 32];
        }

        compute_merkle_root(&leaves)
    }

    /// Rebuild the leaf cache from storage.
    ///
    /// This should be called on startup to restore the merkle tree state
    /// from the persisted data.
    pub async fn rebuild_cache(&self) -> StorageResult<()> {
        let mut cache = self.leaf_cache.write().await;
        cache.submissions.clear();
        cache.evaluations.clear();
        cache.weights.clear();

        // Load submissions
        let submissions_ns = self.namespace("submissions");
        let submissions = self
            .inner
            .list_prefix(&submissions_ns, None, 10000, None)
            .await?;
        for (key, stored) in submissions.items {
            if let Some(hash) = key.key_string() {
                cache.submissions.insert(hash, hash_bytes(&stored.data));
            }
        }

        // Load evaluations
        let evaluations_ns = self.namespace("evaluations");
        let evaluations = self
            .inner
            .list_prefix(&evaluations_ns, None, 100000, None)
            .await?;
        for (key, stored) in evaluations.items {
            if let Some(k) = key.key_string() {
                cache.evaluations.insert(k, hash_bytes(&stored.data));
            }
        }

        // Load weights
        let weights_ns = self.namespace("weights");
        let weights = self
            .inner
            .list_prefix(&weights_ns, None, 10000, None)
            .await?;
        for (key, stored) in weights.items {
            if let Some(epoch_str) = key.key_string() {
                if let Ok(epoch) = epoch_str.parse::<u64>() {
                    cache.weights.insert(epoch, hash_bytes(&stored.data));
                }
            }
        }

        Ok(())
    }

    // ========================================================================
    // Internal merkle proof generation
    // ========================================================================

    async fn generate_proof_for_submission(
        &self,
        hash: &str,
        data: &[u8],
    ) -> StorageResult<MerkleProof> {
        let cache = self.leaf_cache.read().await;
        let leaves = cache.all_leaves();
        let leaf_index = cache
            .submission_index(hash)
            .ok_or_else(|| StorageError::Internal("Submission not in cache".to_string()))?;

        Ok(build_merkle_proof(&leaves, leaf_index, data))
    }

    async fn generate_proof_for_evaluation(
        &self,
        cache_key: &str,
        data: &[u8],
    ) -> StorageResult<MerkleProof> {
        let cache = self.leaf_cache.read().await;
        let leaves = cache.all_leaves();
        let leaf_index = cache
            .evaluation_index(cache_key)
            .ok_or_else(|| StorageError::Internal("Evaluation not in cache".to_string()))?;

        Ok(build_merkle_proof(&leaves, leaf_index, data))
    }

    async fn generate_proof_for_weights(
        &self,
        epoch: u64,
        data: &[u8],
    ) -> StorageResult<MerkleProof> {
        let cache = self.leaf_cache.read().await;
        let leaves = cache.all_leaves();
        let leaf_index = cache
            .weights_index(epoch)
            .ok_or_else(|| StorageError::Internal("Weights not in cache".to_string()))?;

        Ok(build_merkle_proof(&leaves, leaf_index, data))
    }
}

// ============================================================================
// Multi-challenge store management
// ============================================================================

/// Registry for managing multiple challenge stores.
///
/// Provides a unified way to access challenge-specific stores and
/// list all challenges with data.
pub struct ChallengeStoreRegistry<S: DistributedStore> {
    /// Underlying store shared by all challenges
    inner: Arc<S>,
    /// Active challenge stores
    stores: Arc<RwLock<BTreeMap<String, Arc<ChallengeStore<S>>>>>,
}

impl<S: DistributedStore + 'static> ChallengeStoreRegistry<S> {
    /// Create a new registry wrapping the given store.
    pub fn new(store: S) -> Self {
        Self {
            inner: Arc::new(store),
            stores: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    /// Get or create a challenge store for the given challenge ID.
    pub async fn get_or_create(&self, challenge_id: &str) -> Arc<ChallengeStore<S>> {
        {
            let stores = self.stores.read().await;
            if let Some(store) = stores.get(challenge_id) {
                return Arc::clone(store);
            }
        }

        // Create a new store
        let store = Arc::new(ChallengeStore::with_arc(
            Arc::clone(&self.inner),
            challenge_id,
        ));

        {
            let mut stores = self.stores.write().await;
            stores.insert(challenge_id.to_string(), Arc::clone(&store));
        }

        store
    }

    /// List all challenge IDs that have data in the store.
    pub async fn list_challenges(&self) -> StorageResult<Vec<String>> {
        let stores = self.stores.read().await;
        Ok(stores.keys().cloned().collect())
    }

    /// Get the inner distributed store.
    pub fn inner(&self) -> &Arc<S> {
        &self.inner
    }
}

// ============================================================================
// Merkle tree utilities
// ============================================================================

/// Hash bytes using SHA-256
fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash two nodes together
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute merkle root from leaves
fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut level: Vec<[u8; 32]> = leaves.to_vec();

    while level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in level.chunks(2) {
            let combined = if chunk.len() == 2 {
                hash_pair(&chunk[0], &chunk[1])
            } else {
                // Odd number of nodes - duplicate the last one
                hash_pair(&chunk[0], &chunk[0])
            };
            next_level.push(combined);
        }

        level = next_level;
    }

    level[0]
}

/// Build a merkle proof for a leaf at the given index
fn build_merkle_proof(leaves: &[[u8; 32]], leaf_index: usize, data: &[u8]) -> MerkleProof {
    if leaves.is_empty() || leaf_index >= leaves.len() {
        return MerkleProof {
            root: [0u8; 32],
            path: Vec::new(),
            leaf_index,
            leaf_hash: hash_bytes(data),
        };
    }

    let leaf_hash = leaves[leaf_index];
    let root = compute_merkle_root(leaves);
    let mut path = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut index = leaf_index;

    while level.len() > 1 {
        let sibling_index = if index.is_multiple_of(2) {
            if index + 1 < level.len() {
                index + 1
            } else {
                index
            }
        } else {
            index - 1
        };

        path.push(MerkleNode {
            sibling_hash: level[sibling_index],
            is_left: sibling_index < index,
        });

        // Build next level
        let mut next_level = Vec::new();
        for chunk in level.chunks(2) {
            let combined = if chunk.len() == 2 {
                hash_pair(&chunk[0], &chunk[1])
            } else {
                hash_pair(&chunk[0], &chunk[0])
            };
            next_level.push(combined);
        }

        level = next_level;
        index /= 2;
    }

    MerkleProof {
        root,
        path,
        leaf_index,
        leaf_hash,
    }
}

// ============================================================================
// Trait for async operations
// ============================================================================

/// Async trait for challenge-specific storage operations.
///
/// This trait can be implemented by different storage backends
/// while providing the same challenge-namespaced interface.
#[async_trait]
pub trait ChallengeStorage: Send + Sync {
    /// Get the challenge ID
    fn challenge_id(&self) -> &str;

    /// Store a submission
    async fn store_submission(
        &self,
        hash: &str,
        data: &StoredSubmission,
    ) -> StorageResult<MerkleProof>;

    /// Get a submission
    async fn get_submission(&self, hash: &str) -> StorageResult<Option<StoredSubmission>>;

    /// List submissions
    async fn list_submissions(&self, limit: usize) -> StorageResult<Vec<StoredSubmission>>;

    /// Store an evaluation
    async fn store_evaluation(
        &self,
        submission_hash: &str,
        validator: &str,
        eval: &StoredEvaluation,
    ) -> StorageResult<MerkleProof>;

    /// Get evaluations for a submission
    async fn get_evaluations(&self, submission_hash: &str) -> StorageResult<Vec<StoredEvaluation>>;

    /// Store weights
    async fn store_weights(
        &self,
        epoch: u64,
        weights: &StoredWeights,
    ) -> StorageResult<MerkleProof>;

    /// Get weights for an epoch
    async fn get_weights(&self, epoch: u64) -> StorageResult<Option<StoredWeights>>;

    /// Compute the state root
    async fn compute_state_root(&self) -> [u8; 32];
}

#[async_trait]
impl<S: DistributedStore + 'static> ChallengeStorage for ChallengeStore<S> {
    fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    async fn store_submission(
        &self,
        hash: &str,
        data: &StoredSubmission,
    ) -> StorageResult<MerkleProof> {
        ChallengeStore::store_submission(self, hash, data).await
    }

    async fn get_submission(&self, hash: &str) -> StorageResult<Option<StoredSubmission>> {
        ChallengeStore::get_submission(self, hash).await
    }

    async fn list_submissions(&self, limit: usize) -> StorageResult<Vec<StoredSubmission>> {
        ChallengeStore::list_submissions(self, limit).await
    }

    async fn store_evaluation(
        &self,
        submission_hash: &str,
        validator: &str,
        eval: &StoredEvaluation,
    ) -> StorageResult<MerkleProof> {
        ChallengeStore::store_evaluation(self, submission_hash, validator, eval).await
    }

    async fn get_evaluations(&self, submission_hash: &str) -> StorageResult<Vec<StoredEvaluation>> {
        ChallengeStore::get_evaluations(self, submission_hash).await
    }

    async fn store_weights(
        &self,
        epoch: u64,
        weights: &StoredWeights,
    ) -> StorageResult<MerkleProof> {
        ChallengeStore::store_weights(self, epoch, weights).await
    }

    async fn get_weights(&self, epoch: u64) -> StorageResult<Option<StoredWeights>> {
        ChallengeStore::get_weights(self, epoch).await
    }

    async fn compute_state_root(&self) -> [u8; 32] {
        ChallengeStore::compute_state_root(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalStorageBuilder;

    fn create_test_submission(challenge_id: &str, miner: &str) -> StoredSubmission {
        StoredSubmission::new(
            challenge_id,
            miner,
            Some("def solve(): pass".to_string()),
            serde_json::json!({"language": "python"}),
        )
    }

    fn create_test_evaluation(
        challenge_id: &str,
        submission_hash: &str,
        validator: &str,
        score: f64,
    ) -> StoredEvaluation {
        StoredEvaluation::new(
            challenge_id,
            submission_hash,
            validator,
            score,
            1000,
            serde_json::json!({"tasks": 10}),
            vec![1, 2, 3, 4],
        )
    }

    fn create_test_weights(challenge_id: &str, epoch: u64) -> StoredWeights {
        StoredWeights::new(
            challenge_id,
            epoch,
            vec![("miner1".to_string(), 0.6), ("miner2".to_string(), 0.4)],
            vec![],
        )
    }

    #[tokio::test]
    async fn test_store_and_retrieve_submission() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let store = ChallengeStore::new(storage, "challenge-1");

        let submission = create_test_submission("challenge-1", "miner-abc");
        let hash = submission.submission_hash.clone();

        // Store
        let proof = store
            .store_submission(&hash, &submission)
            .await
            .expect("Failed to store submission");

        // Verify proof structure
        assert_ne!(proof.root, [0u8; 32]);

        // Retrieve
        let retrieved = store
            .get_submission(&hash)
            .await
            .expect("Failed to get submission")
            .expect("Submission not found");

        assert_eq!(retrieved.challenge_id, submission.challenge_id);
        assert_eq!(retrieved.miner_hotkey, submission.miner_hotkey);
    }

    #[tokio::test]
    async fn test_list_submissions() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let store = ChallengeStore::new(storage, "challenge-1");

        // Store multiple submissions
        for i in 0..5 {
            let submission = create_test_submission("challenge-1", &format!("miner-{}", i));
            store
                .store_submission(&submission.submission_hash, &submission)
                .await
                .expect("Failed to store");
        }

        // List
        let submissions = store.list_submissions(10).await.expect("Failed to list");

        assert_eq!(submissions.len(), 5);
    }

    #[tokio::test]
    async fn test_store_and_retrieve_evaluations() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let store = ChallengeStore::new(storage, "challenge-1");

        let submission_hash = "submission-abc123";

        // Store evaluations from multiple validators
        for i in 0..3 {
            let eval = create_test_evaluation(
                "challenge-1",
                submission_hash,
                &format!("validator-{}", i),
                0.5 + (i as f64 * 0.1),
            );
            store
                .store_evaluation(submission_hash, &format!("validator-{}", i), &eval)
                .await
                .expect("Failed to store evaluation");
        }

        // Retrieve all evaluations for the submission
        let evals = store
            .get_evaluations(submission_hash)
            .await
            .expect("Failed to get evaluations");

        assert_eq!(evals.len(), 3);
    }

    #[tokio::test]
    async fn test_store_and_retrieve_weights() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let store = ChallengeStore::new(storage, "challenge-1");

        let weights = create_test_weights("challenge-1", 42);

        // Store
        let proof = store
            .store_weights(42, &weights)
            .await
            .expect("Failed to store weights");

        assert_ne!(proof.root, [0u8; 32]);

        // Retrieve
        let retrieved = store
            .get_weights(42)
            .await
            .expect("Failed to get weights")
            .expect("Weights not found");

        assert_eq!(retrieved.epoch, 42);
        assert_eq!(retrieved.weights.len(), 2);
    }

    #[tokio::test]
    async fn test_namespace_isolation() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let store = Arc::new(storage);

        let store1 = ChallengeStore::with_arc(Arc::clone(&store), "challenge-1");
        let store2 = ChallengeStore::with_arc(Arc::clone(&store), "challenge-2");

        // Store submissions in different challenges
        let sub1 = create_test_submission("challenge-1", "miner-a");
        let sub2 = create_test_submission("challenge-2", "miner-b");

        store1
            .store_submission(&sub1.submission_hash, &sub1)
            .await
            .expect("Failed to store");
        store2
            .store_submission(&sub2.submission_hash, &sub2)
            .await
            .expect("Failed to store");

        // Each store should only see its own submissions
        let list1 = store1.list_submissions(10).await.expect("Failed to list");
        let list2 = store2.list_submissions(10).await.expect("Failed to list");

        assert_eq!(list1.len(), 1);
        assert_eq!(list2.len(), 1);
        assert_eq!(list1[0].challenge_id, "challenge-1");
        assert_eq!(list2[0].challenge_id, "challenge-2");
    }

    #[tokio::test]
    async fn test_state_root_computation() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let store = ChallengeStore::new(storage, "challenge-1");

        // Empty state should have zero root
        let root1 = store.compute_state_root().await;
        assert_eq!(root1, [0u8; 32]);

        // Add some data
        let sub = create_test_submission("challenge-1", "miner-a");
        store
            .store_submission(&sub.submission_hash, &sub)
            .await
            .expect("Failed to store");

        // Non-zero root after adding data
        let root2 = store.compute_state_root().await;
        assert_ne!(root2, [0u8; 32]);

        // Adding more data changes the root
        let sub2 = create_test_submission("challenge-1", "miner-b");
        store
            .store_submission(&sub2.submission_hash, &sub2)
            .await
            .expect("Failed to store");

        let root3 = store.compute_state_root().await;
        assert_ne!(root3, root2);
    }

    #[tokio::test]
    async fn test_merkle_proof_verification() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let store = ChallengeStore::new(storage, "challenge-1");

        let submission = create_test_submission("challenge-1", "miner-abc");
        let hash = submission.submission_hash.clone();

        // Store and get proof
        let proof = store
            .store_submission(&hash, &submission)
            .await
            .expect("Failed to store");

        // Verify the proof
        let is_valid = store.verify_submission(&hash, &proof).await;
        assert!(is_valid);

        // Tampered proof should fail
        let mut bad_proof = proof.clone();
        bad_proof.root[0] ^= 1;
        let is_valid = store.verify_submission(&hash, &bad_proof).await;
        assert!(!is_valid);
    }

    #[tokio::test]
    async fn test_merkle_proof_static_verification() {
        let data = b"test data";
        let hash = hash_bytes(data);

        let leaves = vec![hash, [1u8; 32], [2u8; 32], [3u8; 32]];
        let proof = build_merkle_proof(&leaves, 0, data);

        // Valid proof should pass
        assert!(proof.verify(data));

        // Wrong data should fail
        assert!(!proof.verify(b"wrong data"));
    }

    #[tokio::test]
    async fn test_challenge_store_registry() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let registry = ChallengeStoreRegistry::new(storage);

        // Get or create stores
        let store1 = registry.get_or_create("challenge-1").await;
        let store2 = registry.get_or_create("challenge-2").await;
        let store1_again = registry.get_or_create("challenge-1").await;

        // Same store should be returned for same challenge
        assert_eq!(store1.challenge_id(), store1_again.challenge_id());

        // Different challenges should have different stores
        assert_ne!(store1.challenge_id(), store2.challenge_id());

        // List challenges
        let challenges = registry.list_challenges().await.expect("Failed to list");
        assert_eq!(challenges.len(), 2);
        assert!(challenges.contains(&"challenge-1".to_string()));
        assert!(challenges.contains(&"challenge-2".to_string()));
    }

    #[tokio::test]
    async fn test_rebuild_cache() {
        // Create and populate a store
        let storage = LocalStorageBuilder::new("test-node")
            .path("/tmp/test-rebuild-cache")
            .build()
            .expect("Failed to create storage");

        let store = ChallengeStore::new(storage, "challenge-1");

        let sub = create_test_submission("challenge-1", "miner-a");
        store
            .store_submission(&sub.submission_hash, &sub)
            .await
            .expect("Failed to store");

        let root_before = store.compute_state_root().await;

        // Rebuild cache (simulating restart)
        store
            .rebuild_cache()
            .await
            .expect("Failed to rebuild cache");

        let root_after = store.compute_state_root().await;

        // State root should be the same after rebuild
        assert_eq!(root_before, root_after);

        // Cleanup
        let _ = std::fs::remove_dir_all("/tmp/test-rebuild-cache");
    }

    #[test]
    fn test_merkle_utilities() {
        // Test hash_bytes
        let hash1 = hash_bytes(b"test");
        let hash2 = hash_bytes(b"test");
        let hash3 = hash_bytes(b"different");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);

        // Test compute_merkle_root with various sizes
        let empty: Vec<[u8; 32]> = vec![];
        assert_eq!(compute_merkle_root(&empty), [0u8; 32]);

        let single = vec![[1u8; 32]];
        assert_eq!(compute_merkle_root(&single), [1u8; 32]);

        let two = vec![[1u8; 32], [2u8; 32]];
        let root2 = compute_merkle_root(&two);
        assert_ne!(root2, [0u8; 32]);
        assert_ne!(root2, [1u8; 32]);
        assert_ne!(root2, [2u8; 32]);

        // Three leaves (odd number)
        let three = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let root3 = compute_merkle_root(&three);
        assert_ne!(root3, root2);
    }
}
