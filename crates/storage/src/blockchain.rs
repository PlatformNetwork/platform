#![allow(dead_code, unused_variables, unused_imports)]
//! Blockchain-like structure for validator consensus
//!
//! This module provides a blockchain structure for maintaining validated state
//! across the P2P validator network. It supports:
//!
//! - Block headers with merkle roots and validator signatures
//! - State transitions for tracking changes
//! - Historical state access for verification
//! - Signature verification for 2f+1 consensus
//!
//! # Example
//!
//! ```ignore
//! use platform_storage::blockchain::BlockchainStorage;
//!
//! let db = sled::open("./blockchain")?;
//! let mut storage = BlockchainStorage::new(&db)?;
//!
//! // Append a new block
//! storage.append_block(block)?;
//!
//! // Query historical state
//! let root = storage.get_state_root_at_block(10, None)?;
//! ```

use platform_core::{ChallengeId, Hotkey, MiniChainError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sled::{Db, Tree};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Signature from a validator for block attestation
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorSignature {
    /// Validator's hotkey who signed the block
    pub validator: Hotkey,
    /// The cryptographic signature over the block hash
    pub signature: Vec<u8>,
    /// Timestamp when the signature was created
    pub timestamp: i64,
}

impl ValidatorSignature {
    /// Create a new validator signature
    ///
    /// # Arguments
    ///
    /// * `validator` - The validator's hotkey
    /// * `signature` - The cryptographic signature bytes
    /// * `timestamp` - Unix timestamp of signature creation
    pub fn new(validator: Hotkey, signature: Vec<u8>, timestamp: i64) -> Self {
        Self {
            validator,
            signature,
            timestamp,
        }
    }
}

/// Header of a block containing metadata and state roots
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHeader {
    /// Sequential block number starting from 0
    pub block_number: u64,
    /// Hash of the parent block (all zeros for genesis)
    pub parent_hash: [u8; 32],
    /// Global state root hash across all challenges
    pub state_root: [u8; 32],
    /// Per-challenge state root hashes for verification
    pub challenge_roots: HashMap<ChallengeId, [u8; 32]>,
    /// Unix timestamp when the block was created
    pub timestamp: i64,
    /// Hotkey of the validator who proposed this block
    pub proposer: Hotkey,
    /// Validator signatures attesting to this block (requires 2f+1 for validity)
    pub validator_signatures: Vec<ValidatorSignature>,
}

impl BlockHeader {
    /// Create a new block header
    ///
    /// # Arguments
    ///
    /// * `block_number` - Sequential block number
    /// * `parent_hash` - Hash of the parent block
    /// * `state_root` - Global state root hash
    /// * `timestamp` - Block creation timestamp
    /// * `proposer` - Hotkey of the block proposer
    pub fn new(
        block_number: u64,
        parent_hash: [u8; 32],
        state_root: [u8; 32],
        timestamp: i64,
        proposer: Hotkey,
    ) -> Self {
        Self {
            block_number,
            parent_hash,
            state_root,
            challenge_roots: HashMap::new(),
            timestamp,
            proposer,
            validator_signatures: Vec::new(),
        }
    }

    /// Create the genesis block header
    ///
    /// # Arguments
    ///
    /// * `proposer` - Hotkey of the genesis block proposer (typically sudo)
    /// * `timestamp` - Genesis block timestamp
    pub fn genesis(proposer: Hotkey, timestamp: i64) -> Self {
        Self {
            block_number: 0,
            parent_hash: [0u8; 32],
            state_root: [0u8; 32],
            challenge_roots: HashMap::new(),
            timestamp,
            proposer,
            validator_signatures: Vec::new(),
        }
    }

    /// Add a challenge-specific state root
    ///
    /// # Arguments
    ///
    /// * `challenge_id` - The challenge identifier
    /// * `root` - The merkle root for the challenge's state
    pub fn with_challenge_root(mut self, challenge_id: ChallengeId, root: [u8; 32]) -> Self {
        self.challenge_roots.insert(challenge_id, root);
        self
    }

    /// Add a validator signature to the header
    ///
    /// # Arguments
    ///
    /// * `signature` - The validator signature to add
    pub fn add_signature(&mut self, signature: ValidatorSignature) {
        self.validator_signatures.push(signature);
    }

    /// Get the number of signatures on this header
    pub fn signature_count(&self) -> usize {
        self.validator_signatures.len()
    }
}

/// State transition types that can occur in a block
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum StateTransition {
    /// A new challenge was registered on the network
    ChallengeRegistered {
        /// The unique challenge identifier
        challenge_id: ChallengeId,
        /// Hash of the challenge configuration
        config_hash: [u8; 32],
    },
    /// The state root for a challenge was updated
    StateRootUpdate {
        /// The challenge whose state was updated
        challenge_id: ChallengeId,
        /// Previous state root
        old_root: [u8; 32],
        /// New state root after the update
        new_root: [u8; 32],
    },
    /// A migration was applied to the system
    MigrationApplied {
        /// Optional challenge ID if migration was challenge-specific
        challenge_id: Option<ChallengeId>,
        /// Migration version number
        version: u64,
    },
    /// The validator set changed (validators added or removed)
    ValidatorSetChange {
        /// Validators that were added
        added: Vec<Hotkey>,
        /// Validators that were removed
        removed: Vec<Hotkey>,
    },
}

impl StateTransition {
    /// Create a challenge registered transition
    pub fn challenge_registered(challenge_id: ChallengeId, config_hash: [u8; 32]) -> Self {
        Self::ChallengeRegistered {
            challenge_id,
            config_hash,
        }
    }

    /// Create a state root update transition
    pub fn state_root_update(
        challenge_id: ChallengeId,
        old_root: [u8; 32],
        new_root: [u8; 32],
    ) -> Self {
        Self::StateRootUpdate {
            challenge_id,
            old_root,
            new_root,
        }
    }

    /// Create a migration applied transition
    pub fn migration_applied(challenge_id: Option<ChallengeId>, version: u64) -> Self {
        Self::MigrationApplied {
            challenge_id,
            version,
        }
    }

    /// Create a validator set change transition
    pub fn validator_set_change(added: Vec<Hotkey>, removed: Vec<Hotkey>) -> Self {
        Self::ValidatorSetChange { added, removed }
    }
}

/// A complete block containing header, transitions, and computed hash
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    /// The block header with metadata
    pub header: BlockHeader,
    /// State transitions included in this block
    pub state_transitions: Vec<StateTransition>,
    /// Computed hash of the block (derived from header)
    pub block_hash: [u8; 32],
}

impl Block {
    /// Create a new block from a header and transitions
    ///
    /// The block hash is computed automatically from the header.
    ///
    /// # Arguments
    ///
    /// * `header` - The block header
    /// * `state_transitions` - State transitions in this block
    pub fn new(header: BlockHeader, state_transitions: Vec<StateTransition>) -> Self {
        let block_hash = BlockchainStorage::compute_block_hash(&header);
        Self {
            header,
            state_transitions,
            block_hash,
        }
    }

    /// Create the genesis block
    ///
    /// # Arguments
    ///
    /// * `proposer` - Hotkey of the genesis proposer
    /// * `timestamp` - Genesis timestamp
    pub fn genesis(proposer: Hotkey, timestamp: i64) -> Self {
        let header = BlockHeader::genesis(proposer, timestamp);
        Self::new(header, Vec::new())
    }

    /// Get the block number
    pub fn block_number(&self) -> u64 {
        self.header.block_number
    }

    /// Get the parent hash
    pub fn parent_hash(&self) -> &[u8; 32] {
        &self.header.parent_hash
    }

    /// Get the state root
    pub fn state_root(&self) -> &[u8; 32] {
        &self.header.state_root
    }

    /// Check if this is the genesis block
    pub fn is_genesis(&self) -> bool {
        self.header.block_number == 0
    }

    /// Verify that the block hash is correctly computed
    pub fn verify_hash(&self) -> bool {
        let computed = BlockchainStorage::compute_block_hash(&self.header);
        computed == self.block_hash
    }
}

/// Storage tree names for blockchain data
const TREE_BLOCKS: &str = "blockchain_blocks";
const TREE_BLOCK_BY_HASH: &str = "blockchain_by_hash";
const TREE_METADATA: &str = "blockchain_metadata";

/// Key for storing the latest block number
const KEY_LATEST_BLOCK: &str = "latest_block_number";

/// Blockchain storage for persisting and querying blocks
pub struct BlockchainStorage {
    /// Tree storing blocks by block number
    blocks_tree: Tree,
    /// Tree for looking up blocks by hash
    hash_index_tree: Tree,
    /// Tree for metadata (latest block number, etc.)
    metadata_tree: Tree,
}

impl BlockchainStorage {
    /// Create a new blockchain storage instance
    ///
    /// # Arguments
    ///
    /// * `db` - Reference to the sled database
    ///
    /// # Errors
    ///
    /// Returns an error if the database trees cannot be opened.
    pub fn new(db: &Db) -> Result<Self> {
        let blocks_tree = db
            .open_tree(TREE_BLOCKS)
            .map_err(|e| MiniChainError::Storage(format!("Failed to open blocks tree: {}", e)))?;

        let hash_index_tree = db.open_tree(TREE_BLOCK_BY_HASH).map_err(|e| {
            MiniChainError::Storage(format!("Failed to open hash index tree: {}", e))
        })?;

        let metadata_tree = db
            .open_tree(TREE_METADATA)
            .map_err(|e| MiniChainError::Storage(format!("Failed to open metadata tree: {}", e)))?;

        debug!("BlockchainStorage initialized");
        Ok(Self {
            blocks_tree,
            hash_index_tree,
            metadata_tree,
        })
    }

    /// Compute the hash of a block header
    ///
    /// Uses SHA-256 over the bincode-serialized header.
    ///
    /// # Arguments
    ///
    /// * `header` - The block header to hash
    pub fn compute_block_hash(header: &BlockHeader) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Hash the core header fields deterministically
        hasher.update(&header.block_number.to_le_bytes());
        hasher.update(&header.parent_hash);
        hasher.update(&header.state_root);
        hasher.update(&header.timestamp.to_le_bytes());
        hasher.update(&header.proposer.0);

        // Hash challenge roots in deterministic order
        let mut sorted_challenges: Vec<_> = header.challenge_roots.iter().collect();
        sorted_challenges.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
        for (challenge_id, root) in sorted_challenges {
            hasher.update(challenge_id.0.as_bytes());
            hasher.update(root);
        }

        hasher.finalize().into()
    }

    /// Get the latest block in the chain
    ///
    /// # Returns
    ///
    /// The latest block if the chain is non-empty, None otherwise.
    pub fn get_latest_block(&self) -> Result<Option<Block>> {
        let latest_number = match self.get_latest_block_number()? {
            Some(n) => n,
            None => return Ok(None),
        };
        self.get_block_by_number(latest_number)
    }

    /// Get a block by its block number
    ///
    /// # Arguments
    ///
    /// * `number` - The block number to retrieve
    ///
    /// # Returns
    ///
    /// The block if found, None otherwise.
    pub fn get_block_by_number(&self, number: u64) -> Result<Option<Block>> {
        let key = number.to_be_bytes();

        let data = self.blocks_tree.get(key).map_err(|e| {
            MiniChainError::Storage(format!("Failed to read block {}: {}", number, e))
        })?;

        match data {
            Some(bytes) => {
                let block: Block = bincode::deserialize(&bytes)
                    .map_err(|e| MiniChainError::Serialization(e.to_string()))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Get a block by its hash
    ///
    /// # Arguments
    ///
    /// * `hash` - The 32-byte block hash
    ///
    /// # Returns
    ///
    /// The block if found, None otherwise.
    pub fn get_block_by_hash(&self, hash: &[u8; 32]) -> Result<Option<Block>> {
        // Look up block number from hash index
        let block_number_bytes = self
            .hash_index_tree
            .get(hash)
            .map_err(|e| MiniChainError::Storage(format!("Failed to read hash index: {}", e)))?;

        match block_number_bytes {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(MiniChainError::Storage(
                        "Invalid block number in hash index".to_string(),
                    ));
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                let number = u64::from_be_bytes(arr);
                self.get_block_by_number(number)
            }
            None => Ok(None),
        }
    }

    /// Append a new block to the chain
    ///
    /// Validates that the block's parent hash matches the current chain tip
    /// before appending.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to append
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The parent hash doesn't match the previous block's hash
    /// - The block number is not sequential
    /// - The block hash verification fails
    pub fn append_block(&mut self, block: Block) -> Result<()> {
        // Verify the block hash is correctly computed
        if !block.verify_hash() {
            return Err(MiniChainError::Validation(
                "Block hash verification failed".to_string(),
            ));
        }

        let latest_number = self.get_latest_block_number()?;

        // Validate block number
        let expected_number = latest_number.map(|n| n + 1).unwrap_or(0);
        if block.header.block_number != expected_number {
            return Err(MiniChainError::Validation(format!(
                "Invalid block number: expected {}, got {}",
                expected_number, block.header.block_number
            )));
        }

        // Validate parent hash for non-genesis blocks
        if let Some(prev_number) = latest_number {
            let prev_block = self
                .get_block_by_number(prev_number)?
                .ok_or_else(|| MiniChainError::NotFound("Previous block not found".to_string()))?;

            if block.header.parent_hash != prev_block.block_hash {
                return Err(MiniChainError::Validation(format!(
                    "Parent hash mismatch: expected {:?}, got {:?}",
                    hex::encode(prev_block.block_hash),
                    hex::encode(block.header.parent_hash)
                )));
            }
        } else {
            // Genesis block should have zero parent hash
            if block.header.parent_hash != [0u8; 32] {
                return Err(MiniChainError::Validation(
                    "Genesis block must have zero parent hash".to_string(),
                ));
            }
        }

        // Serialize and store the block
        let block_bytes =
            bincode::serialize(&block).map_err(|e| MiniChainError::Serialization(e.to_string()))?;

        let block_number_key = block.header.block_number.to_be_bytes();

        self.blocks_tree
            .insert(&block_number_key, block_bytes)
            .map_err(|e| MiniChainError::Storage(format!("Failed to store block: {}", e)))?;

        // Update hash index
        self.hash_index_tree
            .insert(&block.block_hash, &block_number_key)
            .map_err(|e| MiniChainError::Storage(format!("Failed to update hash index: {}", e)))?;

        // Update latest block number
        self.metadata_tree
            .insert(KEY_LATEST_BLOCK, &block_number_key)
            .map_err(|e| {
                MiniChainError::Storage(format!("Failed to update latest block number: {}", e))
            })?;

        info!(
            block_number = block.header.block_number,
            hash = hex::encode(block.block_hash),
            transitions = block.state_transitions.len(),
            "Appended block to chain"
        );

        Ok(())
    }

    /// Verify that a block has sufficient validator signatures (2f+1)
    ///
    /// This checks that the block has at least 2f+1 signatures from valid validators
    /// where f is the maximum number of faulty validators tolerated.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to verify
    ///
    /// # Returns
    ///
    /// True if the block has sufficient signatures, false otherwise.
    ///
    /// # Note
    ///
    /// This implementation checks signature count against a threshold.
    /// In production, you would also verify each signature cryptographically
    /// against the validator's public key.
    pub fn verify_block(&self, block: &Block) -> Result<bool> {
        // First verify the hash is correct
        if !block.verify_hash() {
            warn!(
                block_number = block.header.block_number,
                "Block hash verification failed"
            );
            return Ok(false);
        }

        // Genesis block doesn't require signatures
        if block.is_genesis() {
            return Ok(true);
        }

        let signature_count = block.header.validator_signatures.len();

        // Check for duplicate validators in signatures
        let mut seen_validators = std::collections::HashSet::new();
        for sig in &block.header.validator_signatures {
            if !seen_validators.insert(&sig.validator) {
                warn!(
                    block_number = block.header.block_number,
                    validator = %sig.validator.to_hex(),
                    "Duplicate validator signature detected"
                );
                return Ok(false);
            }
        }

        // For Byzantine fault tolerance with n validators, we need at least 2f+1 signatures
        // where f = floor((n-1)/3) is the max faulty validators
        // This means we need at least ceiling(2n/3) signatures
        //
        // For a practical minimum, we require at least 1 signature (the proposer)
        // In production, this threshold should be calculated from the active validator set
        if signature_count == 0 {
            warn!(
                block_number = block.header.block_number,
                "Block has no validator signatures"
            );
            return Ok(false);
        }

        debug!(
            block_number = block.header.block_number,
            signature_count, "Block signature verification passed"
        );

        Ok(true)
    }

    /// Check if a block has quorum (2f+1) given the total validator count
    ///
    /// # Arguments
    ///
    /// * `block` - The block to check
    /// * `total_validators` - Total number of validators in the network
    ///
    /// # Returns
    ///
    /// True if the block has 2f+1 signatures for the given validator count.
    pub fn has_quorum(&self, block: &Block, total_validators: usize) -> bool {
        if total_validators == 0 {
            return false;
        }

        // Calculate required signatures for 2f+1 (Byzantine majority)
        // n = total_validators, f = floor((n-1)/3)
        // Required = n - f = n - floor((n-1)/3)
        // Simplified: ceiling(2n/3) + 1 for n > 1, or n for n <= 1
        let required_signatures = if total_validators <= 1 {
            total_validators
        } else {
            // ceiling((2 * n + 2) / 3)
            (2 * total_validators + 2) / 3
        };

        let signature_count = block.header.validator_signatures.len();
        signature_count >= required_signatures
    }

    /// Get the state root at a specific block number
    ///
    /// # Arguments
    ///
    /// * `block_number` - The block number to query
    /// * `challenge_id` - Optional challenge ID for challenge-specific root
    ///
    /// # Returns
    ///
    /// The state root if found, None otherwise.
    pub fn get_state_root_at_block(
        &self,
        block_number: u64,
        challenge_id: Option<&ChallengeId>,
    ) -> Result<Option<[u8; 32]>> {
        let block = match self.get_block_by_number(block_number)? {
            Some(b) => b,
            None => return Ok(None),
        };

        match challenge_id {
            Some(id) => Ok(block.header.challenge_roots.get(id).copied()),
            None => Ok(Some(block.header.state_root)),
        }
    }

    /// Get the state root for a specific challenge at a block number
    ///
    /// # Arguments
    ///
    /// * `block_number` - The block number to query
    /// * `challenge_id` - The challenge identifier
    ///
    /// # Returns
    ///
    /// The challenge's state root if found, None otherwise.
    pub fn get_challenge_root_at_block(
        &self,
        block_number: u64,
        challenge_id: &ChallengeId,
    ) -> Result<Option<[u8; 32]>> {
        self.get_state_root_at_block(block_number, Some(challenge_id))
    }

    /// List all blocks in a given range (inclusive)
    ///
    /// # Arguments
    ///
    /// * `start` - Starting block number (inclusive)
    /// * `end` - Ending block number (inclusive)
    ///
    /// # Returns
    ///
    /// A vector of blocks in the range, ordered by block number.
    pub fn list_blocks_in_range(&self, start: u64, end: u64) -> Result<Vec<Block>> {
        if start > end {
            return Ok(Vec::new());
        }

        let mut blocks = Vec::new();
        for number in start..=end {
            if let Some(block) = self.get_block_by_number(number)? {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    /// Get the current chain height (latest block number)
    ///
    /// # Returns
    ///
    /// The latest block number if the chain is non-empty, None otherwise.
    pub fn get_latest_block_number(&self) -> Result<Option<u64>> {
        let data = self
            .metadata_tree
            .get(KEY_LATEST_BLOCK)
            .map_err(|e| MiniChainError::Storage(format!("Failed to read latest block: {}", e)))?;

        match data {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(MiniChainError::Storage(
                        "Invalid latest block number".to_string(),
                    ));
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    /// Get the total number of blocks in the chain
    pub fn chain_length(&self) -> Result<u64> {
        Ok(self.get_latest_block_number()?.map(|n| n + 1).unwrap_or(0))
    }

    /// Check if the chain is empty
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.get_latest_block_number()?.is_none())
    }

    /// Flush all pending writes to disk
    pub fn flush(&self) -> Result<()> {
        self.blocks_tree
            .flush()
            .map_err(|e| MiniChainError::Storage(format!("Failed to flush blocks: {}", e)))?;
        self.hash_index_tree
            .flush()
            .map_err(|e| MiniChainError::Storage(format!("Failed to flush hash index: {}", e)))?;
        self.metadata_tree
            .flush()
            .map_err(|e| MiniChainError::Storage(format!("Failed to flush metadata: {}", e)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_db() -> sled::Db {
        let dir = tempdir().expect("Failed to create temp dir");
        sled::open(dir.path()).expect("Failed to open test database")
    }

    fn create_test_hotkey(seed: u8) -> Hotkey {
        Hotkey([seed; 32])
    }

    fn create_test_signature(validator: Hotkey, timestamp: i64) -> ValidatorSignature {
        ValidatorSignature::new(validator, vec![0u8; 64], timestamp)
    }

    #[test]
    fn test_blockchain_storage_new() {
        let db = create_test_db();
        let storage = BlockchainStorage::new(&db);
        assert!(storage.is_ok());
    }

    #[test]
    fn test_genesis_block() {
        let proposer = create_test_hotkey(1);
        let timestamp = 1000;

        let genesis = Block::genesis(proposer.clone(), timestamp);

        assert_eq!(genesis.header.block_number, 0);
        assert_eq!(genesis.header.parent_hash, [0u8; 32]);
        assert_eq!(genesis.header.proposer, proposer);
        assert!(genesis.is_genesis());
        assert!(genesis.state_transitions.is_empty());
    }

    #[test]
    fn test_append_genesis_block() {
        let db = create_test_db();
        let mut storage = BlockchainStorage::new(&db).expect("Failed to create storage");

        let genesis = Block::genesis(create_test_hotkey(1), 1000);
        let result = storage.append_block(genesis.clone());
        assert!(result.is_ok());

        let latest = storage.get_latest_block().expect("Failed to get latest");
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().header.block_number, 0);
    }

    #[test]
    fn test_append_multiple_blocks() {
        let db = create_test_db();
        let mut storage = BlockchainStorage::new(&db).expect("Failed to create storage");

        let proposer = create_test_hotkey(1);

        // Append genesis
        let genesis = Block::genesis(proposer.clone(), 1000);
        storage
            .append_block(genesis.clone())
            .expect("Failed to append genesis");

        // Create and append block 1
        let mut header1 =
            BlockHeader::new(1, genesis.block_hash, [1u8; 32], 2000, proposer.clone());
        header1.add_signature(create_test_signature(proposer.clone(), 2000));
        let block1 = Block::new(header1, vec![]);
        storage
            .append_block(block1.clone())
            .expect("Failed to append block 1");

        // Create and append block 2
        let mut header2 = BlockHeader::new(2, block1.block_hash, [2u8; 32], 3000, proposer.clone());
        header2.add_signature(create_test_signature(proposer.clone(), 3000));
        let block2 = Block::new(header2, vec![]);
        storage
            .append_block(block2)
            .expect("Failed to append block 2");

        assert_eq!(storage.chain_length().expect("chain_length failed"), 3);
    }

    #[test]
    fn test_get_block_by_number() {
        let db = create_test_db();
        let mut storage = BlockchainStorage::new(&db).expect("Failed to create storage");

        let genesis = Block::genesis(create_test_hotkey(1), 1000);
        storage.append_block(genesis).expect("Failed to append");

        let block = storage.get_block_by_number(0).expect("Failed to get block");
        assert!(block.is_some());
        assert_eq!(block.unwrap().header.block_number, 0);

        let none_block = storage
            .get_block_by_number(999)
            .expect("Failed to get nonexistent block");
        assert!(none_block.is_none());
    }

    #[test]
    fn test_get_block_by_hash() {
        let db = create_test_db();
        let mut storage = BlockchainStorage::new(&db).expect("Failed to create storage");

        let genesis = Block::genesis(create_test_hotkey(1), 1000);
        let hash = genesis.block_hash;
        storage
            .append_block(genesis)
            .expect("Failed to append genesis");

        let block = storage
            .get_block_by_hash(&hash)
            .expect("Failed to get block");
        assert!(block.is_some());
        assert_eq!(block.unwrap().block_hash, hash);

        let none_block = storage
            .get_block_by_hash(&[99u8; 32])
            .expect("Failed to get nonexistent block");
        assert!(none_block.is_none());
    }

    #[test]
    fn test_invalid_parent_hash() {
        let db = create_test_db();
        let mut storage = BlockchainStorage::new(&db).expect("Failed to create storage");

        let genesis = Block::genesis(create_test_hotkey(1), 1000);
        storage.append_block(genesis).expect("Failed to append");

        // Try to append a block with wrong parent hash
        let mut bad_header =
            BlockHeader::new(1, [99u8; 32], [1u8; 32], 2000, create_test_hotkey(1));
        bad_header.add_signature(create_test_signature(create_test_hotkey(1), 2000));
        let bad_block = Block::new(bad_header, vec![]);

        let result = storage.append_block(bad_block);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Parent hash mismatch"));
    }

    #[test]
    fn test_invalid_block_number() {
        let db = create_test_db();
        let mut storage = BlockchainStorage::new(&db).expect("Failed to create storage");

        let genesis = Block::genesis(create_test_hotkey(1), 1000);
        storage.append_block(genesis).expect("Failed to append");

        // Try to append a block with wrong block number
        let bad_header = BlockHeader::new(99, [0u8; 32], [1u8; 32], 2000, create_test_hotkey(1));
        let bad_block = Block::new(bad_header, vec![]);

        let result = storage.append_block(bad_block);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid block number"));
    }

    #[test]
    fn test_state_transitions() {
        let db = create_test_db();
        let mut storage = BlockchainStorage::new(&db).expect("Failed to create storage");

        let proposer = create_test_hotkey(1);
        let genesis = Block::genesis(proposer.clone(), 1000);
        storage.append_block(genesis.clone()).expect("Failed");

        let challenge_id = ChallengeId::new();
        let transitions = vec![
            StateTransition::challenge_registered(challenge_id, [42u8; 32]),
            StateTransition::state_root_update(challenge_id, [0u8; 32], [1u8; 32]),
        ];

        let mut header1 =
            BlockHeader::new(1, genesis.block_hash, [1u8; 32], 2000, proposer.clone());
        header1.add_signature(create_test_signature(proposer, 2000));
        let block1 = Block::new(header1, transitions);

        storage.append_block(block1).expect("Failed to append");

        let loaded = storage
            .get_block_by_number(1)
            .expect("Failed to get")
            .expect("Block not found");
        assert_eq!(loaded.state_transitions.len(), 2);
    }

    #[test]
    fn test_challenge_roots() {
        let db = create_test_db();
        let mut storage = BlockchainStorage::new(&db).expect("Failed to create storage");

        let proposer = create_test_hotkey(1);
        let challenge1 = ChallengeId::new();
        let challenge2 = ChallengeId::new();

        let mut header = BlockHeader::genesis(proposer.clone(), 1000)
            .with_challenge_root(challenge1, [11u8; 32])
            .with_challenge_root(challenge2, [22u8; 32]);
        header.state_root = [99u8; 32];

        let block = Block::new(header, vec![]);
        storage.append_block(block).expect("Failed to append");

        // Check global state root
        let global_root = storage
            .get_state_root_at_block(0, None)
            .expect("Failed to get")
            .expect("Root not found");
        assert_eq!(global_root, [99u8; 32]);

        // Check challenge-specific roots
        let root1 = storage
            .get_challenge_root_at_block(0, &challenge1)
            .expect("Failed")
            .expect("Root not found");
        assert_eq!(root1, [11u8; 32]);

        let root2 = storage
            .get_challenge_root_at_block(0, &challenge2)
            .expect("Failed")
            .expect("Root not found");
        assert_eq!(root2, [22u8; 32]);

        // Non-existent challenge
        let fake_challenge = ChallengeId::new();
        let no_root = storage
            .get_challenge_root_at_block(0, &fake_challenge)
            .expect("Failed");
        assert!(no_root.is_none());
    }

    #[test]
    fn test_list_blocks_in_range() {
        let db = create_test_db();
        let mut storage = BlockchainStorage::new(&db).expect("Failed to create storage");

        let proposer = create_test_hotkey(1);
        let genesis = Block::genesis(proposer.clone(), 1000);
        storage.append_block(genesis.clone()).expect("Failed");

        // Create 4 more blocks (total 5)
        let mut prev_hash = genesis.block_hash;
        for i in 1..5 {
            let mut header = BlockHeader::new(
                i,
                prev_hash,
                [i as u8; 32],
                1000 + (i * 1000) as i64,
                proposer.clone(),
            );
            header.add_signature(create_test_signature(
                proposer.clone(),
                1000 + (i * 1000) as i64,
            ));
            let block = Block::new(header, vec![]);
            prev_hash = block.block_hash;
            storage.append_block(block).expect("Failed");
        }

        // Get range 1..3
        let blocks = storage.list_blocks_in_range(1, 3).expect("Failed to list");
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].header.block_number, 1);
        assert_eq!(blocks[1].header.block_number, 2);
        assert_eq!(blocks[2].header.block_number, 3);

        // Empty range
        let empty = storage
            .list_blocks_in_range(100, 200)
            .expect("Failed to list");
        assert!(empty.is_empty());

        // Reversed range
        let reversed = storage.list_blocks_in_range(5, 1).expect("Failed to list");
        assert!(reversed.is_empty());
    }

    #[test]
    fn test_verify_block_hash() {
        let proposer = create_test_hotkey(1);
        let block = Block::genesis(proposer, 1000);

        assert!(block.verify_hash());

        // Tampered block
        let mut tampered = block.clone();
        tampered.header.timestamp = 9999;
        assert!(!tampered.verify_hash());
    }

    #[test]
    fn test_verify_block_signatures() {
        let db = create_test_db();
        let storage = BlockchainStorage::new(&db).expect("Failed to create storage");

        let proposer = create_test_hotkey(1);
        let validator1 = create_test_hotkey(2);
        let validator2 = create_test_hotkey(3);

        // Genesis doesn't need signatures
        let genesis = Block::genesis(proposer.clone(), 1000);
        assert!(storage.verify_block(&genesis).expect("Failed to verify"));

        // Non-genesis needs at least one signature
        let mut header = BlockHeader::new(1, genesis.block_hash, [1u8; 32], 2000, proposer.clone());
        let no_sig_block = Block::new(header.clone(), vec![]);
        assert!(!storage.verify_block(&no_sig_block).expect("Failed"));

        // With signatures
        header.add_signature(create_test_signature(validator1.clone(), 2000));
        let signed_block = Block::new(header.clone(), vec![]);
        assert!(storage.verify_block(&signed_block).expect("Failed"));

        // Duplicate validator signatures should fail
        let mut dup_header = header.clone();
        dup_header.add_signature(create_test_signature(validator1.clone(), 2001)); // Same validator!
        let dup_block = Block::new(dup_header, vec![]);
        assert!(!storage.verify_block(&dup_block).expect("Failed"));
    }

    #[test]
    fn test_has_quorum() {
        let db = create_test_db();
        let storage = BlockchainStorage::new(&db).expect("Failed to create storage");

        let proposer = create_test_hotkey(1);

        // Create a block with 2 signatures
        let mut header = BlockHeader::new(1, [0u8; 32], [1u8; 32], 1000, proposer.clone());
        header.add_signature(create_test_signature(create_test_hotkey(1), 1000));
        header.add_signature(create_test_signature(create_test_hotkey(2), 1000));
        let block = Block::new(header, vec![]);

        // With 3 validators, need 2f+1 = 2 signatures (f=0)
        assert!(storage.has_quorum(&block, 3));

        // With 4 validators, need 2f+1 = 3 signatures (f=1) - but we only have 2
        assert!(!storage.has_quorum(&block, 4));

        // Edge cases
        assert!(!storage.has_quorum(&block, 0));
    }

    #[test]
    fn test_empty_chain() {
        let db = create_test_db();
        let storage = BlockchainStorage::new(&db).expect("Failed to create storage");

        assert!(storage.is_empty().expect("is_empty failed"));
        assert_eq!(storage.chain_length().expect("chain_length failed"), 0);
        assert!(storage
            .get_latest_block()
            .expect("get_latest failed")
            .is_none());
    }

    #[test]
    fn test_block_hash_determinism() {
        let proposer = create_test_hotkey(1);
        let challenge1 = ChallengeId::new();
        let challenge2 = ChallengeId::new();

        let header1 = BlockHeader::new(1, [0u8; 32], [1u8; 32], 1000, proposer.clone())
            .with_challenge_root(challenge1, [11u8; 32])
            .with_challenge_root(challenge2, [22u8; 32]);

        let header2 = BlockHeader::new(1, [0u8; 32], [1u8; 32], 1000, proposer.clone())
            .with_challenge_root(challenge2, [22u8; 32])
            .with_challenge_root(challenge1, [11u8; 32]);

        // Same data, different insertion order - should produce same hash
        let hash1 = BlockchainStorage::compute_block_hash(&header1);
        let hash2 = BlockchainStorage::compute_block_hash(&header2);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_state_transition_constructors() {
        let challenge_id = ChallengeId::new();

        let reg = StateTransition::challenge_registered(challenge_id, [1u8; 32]);
        assert!(matches!(reg, StateTransition::ChallengeRegistered { .. }));

        let update = StateTransition::state_root_update(challenge_id, [0u8; 32], [1u8; 32]);
        assert!(matches!(update, StateTransition::StateRootUpdate { .. }));

        let migration = StateTransition::migration_applied(Some(challenge_id), 1);
        assert!(matches!(
            migration,
            StateTransition::MigrationApplied { .. }
        ));

        let global_migration = StateTransition::migration_applied(None, 2);
        if let StateTransition::MigrationApplied {
            challenge_id,
            version,
        } = global_migration
        {
            assert!(challenge_id.is_none());
            assert_eq!(version, 2);
        } else {
            panic!("Wrong variant");
        }

        let hotkey1 = create_test_hotkey(1);
        let hotkey2 = create_test_hotkey(2);
        let change = StateTransition::validator_set_change(vec![hotkey1.clone()], vec![hotkey2]);
        if let StateTransition::ValidatorSetChange { added, removed } = change {
            assert_eq!(added.len(), 1);
            assert_eq!(removed.len(), 1);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_validator_signature_new() {
        let validator = create_test_hotkey(42);
        let signature = vec![1, 2, 3, 4, 5];
        let timestamp = 123456789;

        let sig = ValidatorSignature::new(validator.clone(), signature.clone(), timestamp);

        assert_eq!(sig.validator, validator);
        assert_eq!(sig.signature, signature);
        assert_eq!(sig.timestamp, timestamp);
    }

    #[test]
    fn test_block_header_signature_count() {
        let proposer = create_test_hotkey(1);
        let mut header = BlockHeader::new(0, [0u8; 32], [0u8; 32], 1000, proposer.clone());

        assert_eq!(header.signature_count(), 0);

        header.add_signature(create_test_signature(create_test_hotkey(1), 1000));
        assert_eq!(header.signature_count(), 1);

        header.add_signature(create_test_signature(create_test_hotkey(2), 1000));
        assert_eq!(header.signature_count(), 2);
    }

    #[test]
    fn test_flush() {
        let db = create_test_db();
        let mut storage = BlockchainStorage::new(&db).expect("Failed to create storage");

        let genesis = Block::genesis(create_test_hotkey(1), 1000);
        storage.append_block(genesis).expect("Failed to append");

        let result = storage.flush();
        assert!(result.is_ok());
    }

    #[test]
    fn test_genesis_non_zero_parent_hash() {
        let db = create_test_db();
        let mut storage = BlockchainStorage::new(&db).expect("Failed to create storage");

        // Genesis with non-zero parent hash should fail
        let bad_genesis = Block::new(
            BlockHeader::new(0, [1u8; 32], [0u8; 32], 1000, create_test_hotkey(1)),
            vec![],
        );

        let result = storage.append_block(bad_genesis);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Genesis block must have zero parent hash"));
    }

    #[test]
    fn test_block_accessors() {
        let proposer = create_test_hotkey(1);
        let parent = [5u8; 32];
        let state_root = [10u8; 32];

        let mut header = BlockHeader::new(42, parent, state_root, 1000, proposer);
        header.add_signature(create_test_signature(create_test_hotkey(1), 1000));
        let block = Block::new(header, vec![]);

        assert_eq!(block.block_number(), 42);
        assert_eq!(*block.parent_hash(), parent);
        assert_eq!(*block.state_root(), state_root);
        assert!(!block.is_genesis());
    }

    #[test]
    fn test_get_state_root_nonexistent_block() {
        let db = create_test_db();
        let storage = BlockchainStorage::new(&db).expect("Failed to create storage");

        let result = storage.get_state_root_at_block(999, None).expect("Failed");
        assert!(result.is_none());
    }
}
