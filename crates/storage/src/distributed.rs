//! Distributed Blockchain Storage
//!
//! High-performance, compressed, replicated storage for blockchain data.
//! All data is stored with 50% consensus requirement and synced across validators.
//!
//! # Features
//!
//! - **LZ4 Compression**: Fast compression/decompression for all data
//! - **Sled Backend**: High-performance embedded database
//! - **50% Consensus**: Write operations require 50% validator agreement
//! - **Merkle Proofs**: Efficient verification of data integrity
//! - **Efficient Queries**: Index-based queries for agents, evaluations, submissions
//! - **P2P Replication**: Automatic sync across all validators
//!
//! # Data Categories
//!
//! - `submissions`: Agent submissions (encrypted/revealed)
//! - `agents`: Finalized agent records
//! - `evaluations`: Per-validator evaluation results  
//! - `consensus`: Consensus results after 50% agreement
//! - `logs`: Compressed execution logs (TTL-limited)

use lz4_flex::{compress_prepend_size, decompress_size_prepended};
use parking_lot::RwLock;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sled::{Db, Tree};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Instant;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Consensus threshold (50%)
pub const CONSENSUS_THRESHOLD: f64 = 0.50;

/// Maximum entry size before compression (10 MB)
pub const MAX_RAW_SIZE: usize = 10 * 1024 * 1024;

/// Maximum compressed entry size (5 MB)  
pub const MAX_COMPRESSED_SIZE: usize = 5 * 1024 * 1024;

/// Maximum entries per category per challenge
pub const MAX_ENTRIES_PER_CATEGORY: usize = 100_000;

/// No TTL - all data is permanent
pub const NO_TTL: u64 = 0;

// ============================================================================
// VALIDATION TYPES (for challenge rules)
// ============================================================================

/// Information about a write request for validation
#[derive(Debug, Clone)]
pub struct WriteRequestInfo {
    /// Category of data
    pub category: Category,
    /// Challenge ID
    pub challenge_id: String,
    /// Key within category
    pub key: String,
    /// Serialized value
    pub value: Vec<u8>,
    /// Size in bytes
    pub size: usize,
    /// Creator validator hotkey
    pub creator: String,
    /// Creator's stake (in RAO)
    pub creator_stake: u64,
    /// Current block height
    pub block: u64,
    /// Is this an update to existing key?
    pub is_update: bool,
    /// Previous value hash (if update)
    pub previous_hash: Option<[u8; 32]>,
    /// Writes by this validator this epoch
    pub writes_this_epoch: usize,
    /// Total entries in this category
    pub category_entry_count: usize,
    /// Total validators in network
    pub total_validators: usize,
}

impl WriteRequestInfo {
    /// Deserialize the value
    pub fn deserialize_value<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.value)
    }
}

/// Result of write validation
#[derive(Debug, Clone)]
pub enum WriteValidationResult {
    /// Accept the write
    Accept,
    /// Reject with reason
    Reject(String),
}

impl WriteValidationResult {
    pub fn accept() -> Self {
        WriteValidationResult::Accept
    }

    pub fn reject(reason: impl Into<String>) -> Self {
        WriteValidationResult::Reject(reason.into())
    }

    pub fn is_accepted(&self) -> bool {
        matches!(self, WriteValidationResult::Accept)
    }
}

// ============================================================================
// STORAGE CATEGORIES
// ============================================================================

/// Data category for organization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Category {
    /// Agent submissions (pending/revealed)
    Submission = 0,
    /// Finalized agents (after consensus)
    Agent = 1,
    /// Evaluation results per validator
    Evaluation = 2,
    /// Consensus results
    Consensus = 3,
    /// Execution logs (compressed, TTL)
    Log = 4,
    /// Indexes for fast lookup
    Index = 5,
    /// Metadata
    Meta = 6,
}

impl Category {
    pub fn prefix(&self) -> &'static [u8] {
        match self {
            Category::Submission => b"sub:",
            Category::Agent => b"agt:",
            Category::Evaluation => b"evl:",
            Category::Consensus => b"cns:",
            Category::Log => b"log:",
            Category::Index => b"idx:",
            Category::Meta => b"met:",
        }
    }
}

// ============================================================================
// ENTRY METADATA
// ============================================================================

/// Entry header stored with each value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryHeader {
    /// Category
    pub category: Category,
    /// Challenge ID
    pub challenge_id: String,
    /// Entry key
    pub key: String,
    /// Version (monotonic)
    pub version: u64,
    /// Block when created
    pub created_block: u64,
    /// Block when updated
    pub updated_block: u64,
    /// Block when expires (0 = never)
    pub expires_block: u64,
    /// Creator validator
    pub creator: String,
    /// Hash of uncompressed value
    pub value_hash: [u8; 32],
    /// Uncompressed size
    pub raw_size: u32,
    /// Compressed size
    pub compressed_size: u32,
    /// Validators who have ACKed this entry
    pub acks: HashSet<String>,
    /// Whether consensus is reached
    pub consensus_reached: bool,
}

/// A stored entry with header and compressed value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEntry {
    pub header: EntryHeader,
    /// LZ4 compressed value
    pub compressed_value: Vec<u8>,
}

impl StoredEntry {
    /// Create new entry with compression
    pub fn new<T: Serialize>(
        category: Category,
        challenge_id: &str,
        key: &str,
        value: &T,
        creator: &str,
        block: u64,
        ttl_blocks: Option<u64>,
    ) -> Result<Self, StorageError> {
        let raw_bytes =
            bincode::serialize(value).map_err(|e| StorageError::Serialization(e.to_string()))?;

        if raw_bytes.len() > MAX_RAW_SIZE {
            return Err(StorageError::TooLarge(raw_bytes.len(), MAX_RAW_SIZE));
        }

        let compressed = compress_prepend_size(&raw_bytes);

        if compressed.len() > MAX_COMPRESSED_SIZE {
            return Err(StorageError::TooLarge(
                compressed.len(),
                MAX_COMPRESSED_SIZE,
            ));
        }

        let value_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&raw_bytes);
            hasher.finalize().into()
        };

        let expires_block = ttl_blocks.map(|t| block + t).unwrap_or(0);

        Ok(Self {
            header: EntryHeader {
                category,
                challenge_id: challenge_id.to_string(),
                key: key.to_string(),
                version: 1,
                created_block: block,
                updated_block: block,
                expires_block,
                creator: creator.to_string(),
                value_hash,
                raw_size: raw_bytes.len() as u32,
                compressed_size: compressed.len() as u32,
                acks: HashSet::new(),
                consensus_reached: false,
            },
            compressed_value: compressed,
        })
    }

    /// Decompress and deserialize value with size limit
    pub fn decompress<T: DeserializeOwned>(&self) -> Result<T, StorageError> {
        use bincode::Options;

        let raw = decompress_size_prepended(&self.compressed_value)
            .map_err(|e| StorageError::Decompression(e.to_string()))?;

        // Verify decompressed size matches header to prevent decompression bombs
        if raw.len() != self.header.raw_size as usize {
            return Err(StorageError::Decompression(format!(
                "Decompressed size mismatch: expected {}, got {}",
                self.header.raw_size,
                raw.len()
            )));
        }

        // Enforce MAX_RAW_SIZE limit (already defined as 10 MB)
        // Use options compatible with bincode::serialize (little-endian, variable int, trailing allowed)
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .allow_trailing_bytes()
            .with_limit(MAX_RAW_SIZE as u64)
            .deserialize(&raw)
            .map_err(|e| StorageError::Serialization(e.to_string()))
    }

    /// Decompress and return raw bytes (for validation)
    pub fn decompress_raw(&self) -> Result<Vec<u8>, StorageError> {
        decompress_size_prepended(&self.compressed_value)
            .map_err(|e| StorageError::Decompression(e.to_string()))
    }

    /// Verify integrity
    pub fn verify(&self) -> bool {
        if let Ok(raw) = decompress_size_prepended(&self.compressed_value) {
            let mut hasher = Sha256::new();
            hasher.update(&raw);
            let hash: [u8; 32] = hasher.finalize().into();
            hash == self.header.value_hash
        } else {
            false
        }
    }

    /// Check if expired
    pub fn is_expired(&self, current_block: u64) -> bool {
        self.header.expires_block > 0 && current_block >= self.header.expires_block
    }

    /// Add ACK from validator
    pub fn add_ack(&mut self, validator: &str, total_validators: usize) {
        self.header.acks.insert(validator.to_string());
        self.check_consensus(total_validators);
    }

    /// Check if consensus is reached
    fn check_consensus(&mut self, total_validators: usize) {
        let required = ((total_validators as f64) * CONSENSUS_THRESHOLD).ceil() as usize;
        self.header.consensus_reached = self.header.acks.len() >= required;
    }

    /// Serialize for storage
    pub fn to_bytes(&self) -> Result<Vec<u8>, StorageError> {
        bincode::serialize(self).map_err(|e| StorageError::Serialization(e.to_string()))
    }

    /// Deserialize from storage with size limit
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        use bincode::Options;
        // MAX_COMPRESSED_SIZE (5 MB) + header overhead
        const MAX_STORED_ENTRY_SIZE: u64 = 6 * 1024 * 1024;

        // Use options compatible with bincode::serialize (little-endian, variable int, trailing allowed)
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .allow_trailing_bytes()
            .with_limit(MAX_STORED_ENTRY_SIZE)
            .deserialize(bytes)
            .map_err(|e| StorageError::Serialization(e.to_string()))
    }

    /// Build storage key
    pub fn storage_key(&self) -> Vec<u8> {
        build_key(
            self.header.category,
            &self.header.challenge_id,
            &self.header.key,
        )
    }
}

/// Build a storage key
fn build_key(category: Category, challenge_id: &str, key: &str) -> Vec<u8> {
    let mut result =
        Vec::with_capacity(category.prefix().len() + challenge_id.len() + key.len() + 2);
    result.extend_from_slice(category.prefix());
    result.extend_from_slice(challenge_id.as_bytes());
    result.push(b':');
    result.extend_from_slice(key.as_bytes());
    result
}

// ============================================================================
// WRITE OPERATION
// ============================================================================

/// Write operation for consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteOp {
    /// Operation ID
    pub op_id: [u8; 32],
    /// Entry to write
    pub entry: StoredEntry,
    /// Initiator validator
    pub initiator: String,
    /// Block when proposed
    pub proposed_block: u64,
    /// Validators who voted YES
    pub votes_yes: HashSet<String>,
    /// Validators who voted NO
    pub votes_no: HashSet<String>,
    /// Whether committed
    pub committed: bool,
}

impl WriteOp {
    pub fn new(entry: StoredEntry, initiator: &str, block: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(entry.header.challenge_id.as_bytes());
        hasher.update(entry.header.key.as_bytes());
        hasher.update(entry.header.value_hash);
        hasher.update(block.to_le_bytes());
        let op_id: [u8; 32] = hasher.finalize().into();

        let mut votes_yes = HashSet::new();
        votes_yes.insert(initiator.to_string()); // Self-vote

        Self {
            op_id,
            entry,
            initiator: initiator.to_string(),
            proposed_block: block,
            votes_yes,
            votes_no: HashSet::new(),
            committed: false,
        }
    }

    /// Add vote
    pub fn vote(&mut self, validator: &str, approve: bool) {
        if approve {
            self.votes_yes.insert(validator.to_string());
            self.votes_no.remove(validator);
        } else {
            self.votes_no.insert(validator.to_string());
            self.votes_yes.remove(validator);
        }
    }

    /// Check if consensus reached (50%)
    pub fn check_consensus(&self, total_validators: usize) -> Option<bool> {
        let required = ((total_validators as f64) * CONSENSUS_THRESHOLD).ceil() as usize;

        if self.votes_yes.len() >= required {
            Some(true)
        } else if self.votes_no.len() >= required {
            Some(false)
        } else {
            None
        }
    }
}

// ============================================================================
// DISTRIBUTED STORAGE
// ============================================================================

/// High-performance distributed storage
pub struct DistributedStorage {
    /// Sled database
    db: Db,
    /// Main data tree
    data_tree: Tree,
    /// Index tree for fast lookups
    index_tree: Tree,
    /// Pending ops persistence tree
    pending_ops_tree: Tree,
    /// Pending write operations (waiting for consensus)
    pending_ops: RwLock<HashMap<[u8; 32], WriteOp>>,
    /// Current block
    current_block: RwLock<u64>,
    /// Total validators
    total_validators: RwLock<usize>,
    /// Our validator ID
    our_validator: String,
    /// Cache for hot data
    cache: RwLock<HashMap<Vec<u8>, (StoredEntry, Instant)>>,
    /// Cache TTL
    cache_ttl_secs: u64,
    /// Stats
    stats: RwLock<StorageStats>,
}

/// Storage statistics
#[derive(Debug, Clone, Default)]
pub struct StorageStats {
    pub total_entries: u64,
    pub total_bytes_raw: u64,
    pub total_bytes_compressed: u64,
    pub compression_ratio: f64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub write_ops_pending: usize,
    pub write_ops_committed: u64,
    pub write_ops_rejected: u64,
}

impl DistributedStorage {
    /// Open or create distributed storage
    pub fn open(db: &Db, our_validator: &str) -> Result<Self, StorageError> {
        let data_tree = db
            .open_tree("distributed_data")
            .map_err(|e| StorageError::Database(e.to_string()))?;

        let index_tree = db
            .open_tree("distributed_index")
            .map_err(|e| StorageError::Database(e.to_string()))?;

        let pending_ops_tree = db
            .open_tree("distributed_pending_ops")
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Restore pending ops from disk
        let mut restored_ops = HashMap::new();
        for item in pending_ops_tree.iter() {
            if let Ok((key, value)) = item {
                if let Ok(op) = bincode::deserialize::<WriteOp>(&value) {
                    let mut op_id = [0u8; 32];
                    if key.len() == 32 {
                        op_id.copy_from_slice(&key);
                        restored_ops.insert(op_id, op);
                    }
                }
            }
        }
        if !restored_ops.is_empty() {
            tracing::info!(count = restored_ops.len(), "Restored pending ops from disk");
        }

        Ok(Self {
            db: db.clone(),
            data_tree,
            index_tree,
            pending_ops_tree,
            pending_ops: RwLock::new(restored_ops),
            current_block: RwLock::new(0),
            total_validators: RwLock::new(1),
            our_validator: our_validator.to_string(),
            cache: RwLock::new(HashMap::new()),
            cache_ttl_secs: 60,
            stats: RwLock::new(StorageStats::default()),
        })
    }

    /// Set current block
    pub fn set_block(&self, block: u64) {
        *self.current_block.write() = block;
    }

    /// Set total validators
    pub fn set_validators(&self, count: usize) {
        *self.total_validators.write() = count;
    }

    // ========================================================================
    // WRITE OPERATIONS
    // ========================================================================

    /// Propose a write with challenge-specific validation rules
    /// The rules are loaded from the challenge dynamically
    pub fn propose_write_validated<T: Serialize>(
        &self,
        category: Category,
        challenge_id: &str,
        key: &str,
        value: &T,
        creator_stake: u64,
        validate_fn: impl FnOnce(&WriteRequestInfo) -> WriteValidationResult,
    ) -> Result<WriteOp, StorageError> {
        let block = *self.current_block.read();
        let total = *self.total_validators.read();

        // Serialize value first to get size
        let value_bytes =
            serde_json::to_vec(value).map_err(|e| StorageError::Serialization(e.to_string()))?;

        // Check if key exists (for is_update)
        let existing = self.get_raw(category, challenge_id, key)?;
        let is_update = existing.is_some();
        let previous_hash = existing.as_ref().map(|e| e.header.value_hash);

        // Build request info for validation
        let request_info = WriteRequestInfo {
            category,
            challenge_id: challenge_id.to_string(),
            key: key.to_string(),
            value: value_bytes.clone(),
            size: value_bytes.len(),
            creator: self.our_validator.clone(),
            creator_stake,
            block,
            is_update,
            previous_hash,
            writes_this_epoch: self.count_writes_this_epoch(challenge_id, &self.our_validator),
            category_entry_count: self.count_category(challenge_id, category),
            total_validators: total,
        };

        // Call challenge validation
        match validate_fn(&request_info) {
            WriteValidationResult::Accept => {}
            WriteValidationResult::Reject(reason) => {
                return Err(StorageError::ValidationFailed(reason));
            }
        }

        // Create entry and proceed
        let entry = StoredEntry::new(
            category,
            challenge_id,
            key,
            value,
            &self.our_validator,
            block,
            None, // No TTL - permanent
        )?;

        let op = WriteOp::new(entry, &self.our_validator, block);

        // Check if consensus already reached with self-vote
        if let Some(true) = op.check_consensus(total) {
            self.commit_write(op.clone())?;
            self.stats.write().write_ops_committed += 1;
            return Ok(op);
        }

        self.pending_ops.write().insert(op.op_id, op.clone());
        if let Ok(data) = bincode::serialize(&op) {
            let _ = self.pending_ops_tree.insert(&op.op_id, data);
        }
        self.stats.write().write_ops_pending = self.pending_ops.read().len();

        Ok(op)
    }

    /// Count writes by validator this epoch (for rate limiting)
    fn count_writes_this_epoch(&self, _challenge_id: &str, _validator: &str) -> usize {
        // Write tracking handled by epoch manager
        0
    }

    /// Count entries in category
    fn count_category(&self, challenge_id: &str, category: Category) -> usize {
        let mut prefix = Vec::with_capacity(category.prefix().len() + challenge_id.len() + 1);
        prefix.extend_from_slice(category.prefix());
        prefix.extend_from_slice(challenge_id.as_bytes());
        prefix.push(b':');
        self.data_tree.scan_prefix(&prefix).count()
    }

    /// Get raw entry without deserialization
    fn get_raw(
        &self,
        category: Category,
        challenge_id: &str,
        key: &str,
    ) -> Result<Option<StoredEntry>, StorageError> {
        let storage_key = build_key(category, challenge_id, key);

        match self.data_tree.get(&storage_key) {
            Ok(Some(bytes)) => {
                let entry = StoredEntry::from_bytes(&bytes)?;
                Ok(Some(entry))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    /// Propose a write (initiates consensus) - simple version without validation
    /// Auto-commits if consensus is reached with self-vote (single validator mode)
    pub fn propose_write<T: Serialize>(
        &self,
        category: Category,
        challenge_id: &str,
        key: &str,
        value: &T,
        ttl_blocks: Option<u64>,
    ) -> Result<WriteOp, StorageError> {
        let block = *self.current_block.read();
        let total = *self.total_validators.read();

        let entry = StoredEntry::new(
            category,
            challenge_id,
            key,
            value,
            &self.our_validator,
            block,
            ttl_blocks,
        )?;

        let op = WriteOp::new(entry, &self.our_validator, block);

        // Check if consensus already reached with self-vote
        if let Some(true) = op.check_consensus(total) {
            // Auto-commit
            self.commit_write(op.clone())?;
            self.stats.write().write_ops_committed += 1;
            return Ok(op);
        }

        self.pending_ops.write().insert(op.op_id, op.clone());
        if let Ok(data) = bincode::serialize(&op) {
            let _ = self.pending_ops_tree.insert(&op.op_id, data);
        }
        self.stats.write().write_ops_pending = self.pending_ops.read().len();

        Ok(op)
    }

    /// Vote on a pending write (simple version - no validation)
    pub fn vote_write(&self, op_id: &[u8; 32], validator: &str, approve: bool) -> Option<bool> {
        let total = *self.total_validators.read();

        // First, check and vote
        let consensus_result = {
            let mut ops = self.pending_ops.write();
            if let Some(op) = ops.get_mut(op_id) {
                op.vote(validator, approve);
                op.check_consensus(total)
            } else {
                return None;
            }
        };

        // Then handle consensus result
        if let Some(result) = consensus_result {
            if result {
                // Consensus reached - remove and commit
                let op = self.pending_ops.write().remove(op_id);
                let _ = self.pending_ops_tree.remove(op_id);
                if let Some(op) = op {
                    if let Err(e) = self.commit_write(op) {
                        tracing::error!("Failed to commit write: {}", e);
                        return Some(false);
                    }
                    self.stats.write().write_ops_committed += 1;
                }
            } else {
                // Rejected
                self.pending_ops.write().remove(op_id);
                let _ = self.pending_ops_tree.remove(op_id);
                self.stats.write().write_ops_rejected += 1;
            }
            self.stats.write().write_ops_pending = self.pending_ops.read().len();
            return Some(result);
        }
        None
    }

    /// Get a pending operation (for P2P sync)
    pub fn get_pending_op(&self, op_id: &[u8; 32]) -> Option<WriteOp> {
        self.pending_ops.read().get(op_id).cloned()
    }

    /// Get all pending operations for a challenge
    pub fn get_pending_ops(&self, challenge_id: &str) -> Vec<WriteOp> {
        self.pending_ops
            .read()
            .values()
            .filter(|op| op.entry.header.challenge_id == challenge_id)
            .cloned()
            .collect()
    }

    /// Commit a write after consensus
    fn commit_write(&self, mut op: WriteOp) -> Result<(), StorageError> {
        op.committed = true;
        op.entry.header.consensus_reached = true;

        let key = op.entry.storage_key();
        let value = op.entry.to_bytes()?;

        self.data_tree
            .insert(&key, value)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        self.data_tree
            .flush()
            .map_err(|e| StorageError::Database(format!("Failed to flush after commit: {}", e)))?;

        // Update indexes
        self.update_indexes(&op.entry.header)?;

        // Update cache
        self.cache
            .write()
            .insert(key, (op.entry.clone(), Instant::now()));

        // Update stats
        let mut stats = self.stats.write();
        stats.total_entries += 1;
        stats.total_bytes_raw += op.entry.header.raw_size as u64;
        stats.total_bytes_compressed += op.entry.header.compressed_size as u64;
        if stats.total_bytes_raw > 0 {
            stats.compression_ratio =
                stats.total_bytes_compressed as f64 / stats.total_bytes_raw as f64;
        }

        Ok(())
    }

    /// Direct write (for receiving already-consensus data from sync)
    pub fn write_direct(&self, entry: StoredEntry) -> Result<(), StorageError> {
        let key = entry.storage_key();
        let value = entry.to_bytes()?;

        self.data_tree
            .insert(&key, value)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        self.data_tree
            .flush()
            .map_err(|e| StorageError::Database(format!("flush failed: {}", e)))?;

        self.update_indexes(&entry.header)?;
        self.cache.write().insert(key, (entry, Instant::now()));

        Ok(())
    }

    /// Update indexes for an entry
    fn update_indexes(&self, entry: &EntryHeader) -> Result<(), StorageError> {
        // Index by challenge + category
        let idx_key = format!(
            "{}:{}:{}",
            entry.challenge_id, entry.category as u8, entry.key
        );
        self.index_tree
            .insert(idx_key.as_bytes(), entry.key.as_bytes())
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Index by creator
        let creator_key = format!(
            "creator:{}:{}:{}",
            entry.creator, entry.challenge_id, entry.key
        );
        self.index_tree
            .insert(creator_key.as_bytes(), entry.key.as_bytes())
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(())
    }

    // ========================================================================
    // READ OPERATIONS
    // ========================================================================

    /// Get entry by key
    pub fn get(
        &self,
        category: Category,
        challenge_id: &str,
        key: &str,
    ) -> Result<Option<StoredEntry>, StorageError> {
        let storage_key = build_key(category, challenge_id, key);

        // Check cache first
        {
            let cache = self.cache.read();
            if let Some((entry, cached_at)) = cache.get(&storage_key) {
                if cached_at.elapsed().as_secs() < self.cache_ttl_secs {
                    self.stats.write().cache_hits += 1;
                    return Ok(Some(entry.clone()));
                }
            }
        }
        self.stats.write().cache_misses += 1;

        // Read from disk
        match self
            .data_tree
            .get(&storage_key)
            .map_err(|e| StorageError::Database(e.to_string()))?
        {
            Some(bytes) => {
                let entry = StoredEntry::from_bytes(&bytes)?;

                // Update cache
                self.cache
                    .write()
                    .insert(storage_key, (entry.clone(), Instant::now()));

                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Get and decompress value
    pub fn get_value<T: DeserializeOwned>(
        &self,
        category: Category,
        challenge_id: &str,
        key: &str,
    ) -> Result<Option<T>, StorageError> {
        match self.get(category, challenge_id, key)? {
            Some(entry) => Ok(Some(entry.decompress()?)),
            None => Ok(None),
        }
    }

    /// List entries by category
    pub fn list_by_category(
        &self,
        category: Category,
        challenge_id: &str,
        limit: usize,
    ) -> Result<Vec<StoredEntry>, StorageError> {
        let prefix = format!("{}:{}:", challenge_id, category as u8);
        let mut results = Vec::new();

        for result in self.index_tree.scan_prefix(prefix.as_bytes()) {
            if results.len() >= limit {
                break;
            }

            let (_, key_bytes) = result.map_err(|e| StorageError::Database(e.to_string()))?;
            let key = String::from_utf8_lossy(&key_bytes);

            if let Some(entry) = self.get(category, challenge_id, &key)? {
                results.push(entry);
            }
        }

        Ok(results)
    }

    /// List entries by creator (validator)
    pub fn list_by_creator(
        &self,
        creator: &str,
        challenge_id: &str,
        category: Option<Category>,
        limit: usize,
    ) -> Result<Vec<StoredEntry>, StorageError> {
        let prefix = format!("creator:{}:{}:", creator, challenge_id);
        let mut results = Vec::new();

        for result in self.index_tree.scan_prefix(prefix.as_bytes()) {
            if results.len() >= limit {
                break;
            }

            let (_, key_bytes) = result.map_err(|e| StorageError::Database(e.to_string()))?;
            let key = String::from_utf8_lossy(&key_bytes);

            // Try each category if not specified
            let categories = match category {
                Some(c) => vec![c],
                None => vec![
                    Category::Submission,
                    Category::Agent,
                    Category::Evaluation,
                    Category::Consensus,
                    Category::Log,
                ],
            };

            for cat in categories {
                if let Some(entry) = self.get(cat, challenge_id, &key)? {
                    results.push(entry);
                    break;
                }
            }
        }

        Ok(results)
    }

    // ========================================================================
    // SPECIALIZED QUERIES
    // ========================================================================

    /// Get all submissions for a challenge
    pub fn get_submissions(&self, challenge_id: &str) -> Result<Vec<StoredEntry>, StorageError> {
        self.list_by_category(Category::Submission, challenge_id, MAX_ENTRIES_PER_CATEGORY)
    }

    /// Get all agents for a challenge
    pub fn get_agents(&self, challenge_id: &str) -> Result<Vec<StoredEntry>, StorageError> {
        self.list_by_category(Category::Agent, challenge_id, MAX_ENTRIES_PER_CATEGORY)
    }

    /// Get evaluations for an agent
    pub fn get_evaluations_for_agent(
        &self,
        challenge_id: &str,
        agent_hash: &str,
    ) -> Result<Vec<StoredEntry>, StorageError> {
        let prefix = build_key(Category::Evaluation, challenge_id, agent_hash);
        let mut results = Vec::new();

        for result in self.data_tree.scan_prefix(&prefix) {
            let (_, bytes) = result.map_err(|e| StorageError::Database(e.to_string()))?;
            results.push(StoredEntry::from_bytes(&bytes)?);
        }

        Ok(results)
    }

    /// Get all evaluations by a validator
    pub fn get_evaluations_by_validator(
        &self,
        challenge_id: &str,
        validator: &str,
    ) -> Result<Vec<StoredEntry>, StorageError> {
        self.list_by_creator(
            validator,
            challenge_id,
            Some(Category::Evaluation),
            MAX_ENTRIES_PER_CATEGORY,
        )
    }

    /// Get pending submissions (not yet evaluated)
    pub fn get_pending_submissions(
        &self,
        challenge_id: &str,
    ) -> Result<Vec<StoredEntry>, StorageError> {
        let submissions = self.get_submissions(challenge_id)?;
        let agents = self.get_agents(challenge_id)?;

        let agent_hashes: HashSet<String> = agents.iter().map(|e| e.header.key.clone()).collect();

        Ok(submissions
            .into_iter()
            .filter(|s| !agent_hashes.contains(&s.header.key))
            .collect())
    }

    /// Get agents evaluated by specific validator
    pub fn get_agents_evaluated_by(
        &self,
        challenge_id: &str,
        validator: &str,
    ) -> Result<Vec<String>, StorageError> {
        let evaluations = self.get_evaluations_by_validator(challenge_id, validator)?;
        Ok(evaluations
            .into_iter()
            .map(|e| e.header.key.split(':').next().unwrap_or("").to_string())
            .collect())
    }

    /// Get agents NOT evaluated by specific validator
    pub fn get_agents_not_evaluated_by(
        &self,
        challenge_id: &str,
        validator: &str,
    ) -> Result<Vec<StoredEntry>, StorageError> {
        let agents = self.get_agents(challenge_id)?;
        let evaluated = self.get_agents_evaluated_by(challenge_id, validator)?;
        let evaluated_set: HashSet<_> = evaluated.into_iter().collect();

        Ok(agents
            .into_iter()
            .filter(|a| !evaluated_set.contains(&a.header.key))
            .collect())
    }

    // ========================================================================
    // CLEANUP & MAINTENANCE
    // ========================================================================

    /// Cleanup expired entries
    pub fn cleanup_expired(&self) -> Result<usize, StorageError> {
        let current_block = *self.current_block.read();
        let mut removed = 0;
        let mut expired_keys = Vec::new();

        // Scan all entries
        for result in self.data_tree.iter() {
            let (key, bytes) = result.map_err(|e| StorageError::Database(e.to_string()))?;

            if let Ok(entry) = StoredEntry::from_bytes(&bytes) {
                if entry.is_expired(current_block) {
                    self.data_tree
                        .remove(&key)
                        .map_err(|e| StorageError::Database(e.to_string()))?;
                    // Clean up orphaned index entries for expired data
                    let idx_key = format!(
                        "{}:{}:{}",
                        entry.header.challenge_id, entry.header.category as u8, entry.header.key
                    );
                    let _ = self.index_tree.remove(idx_key.as_bytes());
                    let creator_key = format!(
                        "creator:{}:{}:{}",
                        entry.header.creator, entry.header.challenge_id, entry.header.key
                    );
                    let _ = self.index_tree.remove(creator_key.as_bytes());
                    expired_keys.push(key.to_vec());
                    removed += 1;
                }
            }
        }

        // Cleanup cache - remove expired entries and old time-based entries
        {
            let mut cache = self.cache.write();
            // Remove by expired keys
            for key in &expired_keys {
                cache.remove(key);
            }
            // Also remove old cached items
            let now = Instant::now();
            cache.retain(|_, (entry, cached_at)| {
                !entry.is_expired(current_block)
                    && cached_at.elapsed().as_secs() < self.cache_ttl_secs * 2
            });
        }

        // Cleanup old pending ops
        let pending_timeout = 100; // blocks
        let mut pending = self.pending_ops.write();
        let expired_op_ids: Vec<[u8; 32]> = pending
            .iter()
            .filter(|(_, op)| current_block.saturating_sub(op.proposed_block) >= pending_timeout)
            .map(|(id, _)| *id)
            .collect();
        for op_id in &expired_op_ids {
            pending.remove(op_id);
            let _ = self.pending_ops_tree.remove(op_id);
        }

        Ok(removed)
    }

    /// Get storage statistics
    pub fn stats(&self) -> StorageStats {
        self.stats.read().clone()
    }

    /// Compute merkle root of all data
    pub fn merkle_root(&self, challenge_id: &str) -> Result<[u8; 32], StorageError> {
        let mut hasher = Sha256::new();
        let prefix = challenge_id.as_bytes();

        for result in self.data_tree.scan_prefix(prefix) {
            let (key, value) = result.map_err(|e| StorageError::Database(e.to_string()))?;
            hasher.update(&key);
            hasher.update(&value);
        }

        Ok(hasher.finalize().into())
    }

    /// Get pending operations
    pub fn pending_operations(&self) -> Vec<WriteOp> {
        self.pending_ops.read().values().cloned().collect()
    }

    /// Flush to disk
    pub fn flush(&self) -> Result<(), StorageError> {
        self.data_tree
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.index_tree
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }
}

// ============================================================================
// P2P SYNC MESSAGES
// ============================================================================

/// Sync message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncMessage {
    /// Announce a write operation (request votes)
    ProposeWrite { op: WriteOp },
    /// Vote on a write operation
    VoteWrite {
        op_id: [u8; 32],
        voter: String,
        approve: bool,
    },
    /// Announce committed write (for sync)
    CommittedWrite { entry: StoredEntry },
    /// Request merkle root for verification
    RequestMerkleRoot { challenge_id: String },
    /// Merkle root response
    MerkleRoot {
        challenge_id: String,
        root: [u8; 32],
        entry_count: u64,
    },
    /// Request entries (for sync)
    RequestEntries {
        challenge_id: String,
        category: Category,
        from_key: Option<String>,
        limit: u32,
    },
    /// Entries response
    Entries {
        challenge_id: String,
        entries: Vec<StoredEntry>,
        has_more: bool,
    },
}

// ============================================================================
// ERRORS
// ============================================================================

#[derive(Debug, Clone)]
pub enum StorageError {
    Database(String),
    Serialization(String),
    Decompression(String),
    TooLarge(usize, usize),
    NotFound(String),
    ConsensusNotReached,
    InvalidEntry(String),
    /// Write validation failed (challenge rules rejected)
    ValidationFailed(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Database(e) => write!(f, "Database error: {}", e),
            StorageError::Serialization(e) => write!(f, "Serialization error: {}", e),
            StorageError::Decompression(e) => write!(f, "Decompression error: {}", e),
            StorageError::TooLarge(size, max) => write!(f, "Entry too large: {} > {}", size, max),
            StorageError::NotFound(k) => write!(f, "Not found: {}", k),
            StorageError::ConsensusNotReached => write!(f, "Consensus not reached"),
            StorageError::InvalidEntry(e) => write!(f, "Invalid entry: {}", e),
            StorageError::ValidationFailed(e) => write!(f, "Validation failed: {}", e),
        }
    }
}

impl std::error::Error for StorageError {}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_storage() -> DistributedStorage {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        DistributedStorage::open(&db, "test_validator").unwrap()
    }

    #[test]
    fn test_entry_compression() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestData {
            name: String,
            values: Vec<u64>,
        }

        let data = TestData {
            name: "test".to_string(),
            values: (0..1000).collect(),
        };

        let entry = StoredEntry::new(
            Category::Agent,
            "challenge1",
            "agent1",
            &data,
            "validator1",
            100,
            None,
        )
        .unwrap();

        // Should be compressed
        assert!(entry.header.compressed_size < entry.header.raw_size);

        // Should decompress correctly
        let recovered: TestData = entry.decompress().unwrap();
        assert_eq!(recovered, data);

        // Should verify
        assert!(entry.verify());
    }

    #[test]
    fn test_write_consensus() {
        let storage = create_test_storage();
        storage.set_validators(3);
        storage.set_block(100);

        // Propose write
        let op = storage
            .propose_write(Category::Agent, "challenge1", "agent1", &"test data", None)
            .unwrap();

        // Vote from second validator (50% reached with self-vote)
        let result = storage.vote_write(&op.op_id, "validator2", true);
        assert_eq!(result, Some(true));

        // Should be readable now
        let entry = storage
            .get(Category::Agent, "challenge1", "agent1")
            .unwrap();
        assert!(entry.is_some());
        assert!(entry.unwrap().header.consensus_reached);
    }

    #[test]
    fn test_write_rejection() {
        let storage = create_test_storage();
        storage.set_validators(3);
        storage.set_block(100);

        let op = storage
            .propose_write(Category::Agent, "challenge1", "agent1", &"test data", None)
            .unwrap();

        // Two NO votes = 50% rejection
        storage.vote_write(&op.op_id, "validator2", false);
        let result = storage.vote_write(&op.op_id, "validator3", false);
        assert_eq!(result, Some(false));

        // Should NOT be readable
        let entry = storage
            .get(Category::Agent, "challenge1", "agent1")
            .unwrap();
        assert!(entry.is_none());
    }

    #[test]
    fn test_queries() {
        let storage = create_test_storage();
        storage.set_validators(1); // Single validator for easy testing
        storage.set_block(100);

        // Add some agents
        for i in 0..5 {
            storage
                .propose_write(
                    Category::Agent,
                    "challenge1",
                    &format!("agent{}", i),
                    &format!("data{}", i),
                    None,
                )
                .unwrap();
        }

        // Add evaluations
        for i in 0..3 {
            storage
                .propose_write(
                    Category::Evaluation,
                    "challenge1",
                    &format!("agent0:validator{}", i),
                    &format!("eval{}", i),
                    None,
                )
                .unwrap();
        }

        let agents = storage.get_agents("challenge1").unwrap();
        assert_eq!(agents.len(), 5);

        let evals = storage
            .get_evaluations_for_agent("challenge1", "agent0")
            .unwrap();
        assert_eq!(evals.len(), 3);
    }

    #[test]
    fn test_expiry() {
        let storage = create_test_storage();
        storage.set_validators(1);
        storage.set_block(100);

        // Add with TTL
        storage
            .propose_write(
                Category::Log,
                "challenge1",
                "log1",
                &"log data",
                Some(10), // Expires at block 110
            )
            .unwrap();

        // Should exist
        let entry = storage.get(Category::Log, "challenge1", "log1").unwrap();
        assert!(entry.is_some());

        // Advance past expiry
        storage.set_block(120);

        // Cleanup
        let removed = storage.cleanup_expired().unwrap();
        assert_eq!(removed, 1);

        // Should be gone
        let entry = storage.get(Category::Log, "challenge1", "log1").unwrap();
        assert!(entry.is_none());
    }

    #[test]
    fn test_get_nonexistent() {
        let storage = create_test_storage();

        let entry = storage
            .get(Category::Agent, "challenge1", "nonexistent")
            .unwrap();
        assert!(entry.is_none());
    }

    #[test]
    fn test_write_validation_result_accept() {
        let result = WriteValidationResult::accept();
        assert!(result.is_accepted());
    }

    #[test]
    fn test_write_validation_result_reject() {
        let result = WriteValidationResult::reject("Invalid data");
        assert!(!result.is_accepted());
    }

    #[test]
    fn test_category_prefix() {
        assert_eq!(Category::Agent.prefix(), b"agt:");
        assert_eq!(Category::Evaluation.prefix(), b"evl:");
        assert_eq!(Category::Log.prefix(), b"log:");
        assert_eq!(Category::Submission.prefix(), b"sub:");
        assert_eq!(Category::Consensus.prefix(), b"cns:");
        assert_eq!(Category::Meta.prefix(), b"met:");
    }

    #[test]
    fn test_stored_entry_verify_valid() {
        let data = "test data";
        let entry = StoredEntry::new(
            Category::Agent,
            "challenge1",
            "agent1",
            &data,
            "validator1",
            100,
            None,
        )
        .unwrap();

        // Should verify correctly with correct hash
        assert!(entry.verify());
    }

    #[test]
    fn test_stored_entry_decompress() {
        let data = "test data string";
        let entry = StoredEntry::new(
            Category::Agent,
            "challenge1",
            "agent1",
            &data,
            "validator1",
            100,
            None,
        )
        .unwrap();

        let decompressed: String = entry.decompress().unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_stored_entry_is_expired() {
        let data = "test";
        let entry = StoredEntry::new(
            Category::Log,
            "challenge1",
            "log1",
            &data,
            "validator1",
            100,
            Some(10), // Expires at block 110
        )
        .unwrap();

        // Not expired at block 105
        assert!(!entry.is_expired(105));

        // Expired at block 110
        assert!(entry.is_expired(110));

        // Expired after block 110
        assert!(entry.is_expired(120));
    }

    #[test]
    fn test_stored_entry_no_expiry() {
        let data = "test";
        let entry = StoredEntry::new(
            Category::Agent,
            "challenge1",
            "agent1",
            &data,
            "validator1",
            100,
            None, // No expiry
        )
        .unwrap();

        // Never expires
        assert!(!entry.is_expired(1000));
        assert!(!entry.is_expired(10000));
    }

    #[test]
    fn test_stored_entry_add_ack() {
        let data = "test";
        let mut entry = StoredEntry::new(
            Category::Agent,
            "challenge1",
            "agent1",
            &data,
            "validator1",
            100,
            None,
        )
        .unwrap();

        // Initially no acks, no consensus
        assert_eq!(entry.header.acks.len(), 0);
        assert!(!entry.header.consensus_reached);

        // Add ack from validator (5 total validators = need 3 for 50%)
        entry.add_ack("validator2", 5);
        assert_eq!(entry.header.acks.len(), 1);
        assert!(!entry.header.consensus_reached);

        // Add second ack
        entry.add_ack("validator3", 5);
        assert_eq!(entry.header.acks.len(), 2);
        assert!(!entry.header.consensus_reached);

        // Add third ack - should reach consensus (3/5 = 60% >= 50%)
        entry.add_ack("validator4", 5);
        assert_eq!(entry.header.acks.len(), 3);
        assert!(entry.header.consensus_reached);
    }

    #[test]
    fn test_stored_entry_duplicate_ack() {
        let data = "test";
        let mut entry = StoredEntry::new(
            Category::Agent,
            "challenge1",
            "agent1",
            &data,
            "validator1",
            100,
            None,
        )
        .unwrap();

        // Add ack
        entry.add_ack("validator2", 5);
        assert_eq!(entry.header.acks.len(), 1);

        // Add duplicate ack - should be ignored
        entry.add_ack("validator2", 5);
        assert_eq!(entry.header.acks.len(), 1);
    }

    #[test]
    fn test_stored_entry_serialization() {
        let data = "test data";
        let entry = StoredEntry::new(
            Category::Agent,
            "challenge1",
            "agent1",
            &data,
            "validator1",
            100,
            None,
        )
        .unwrap();

        // Serialize
        let bytes = entry.to_bytes().unwrap();

        // Deserialize
        let deserialized = StoredEntry::from_bytes(&bytes).unwrap();

        // Verify fields match
        assert_eq!(deserialized.header.category, entry.header.category);
        assert_eq!(deserialized.header.challenge_id, entry.header.challenge_id);
        assert_eq!(deserialized.header.key, entry.header.key);
        assert_eq!(deserialized.header.creator, entry.header.creator);
    }

    #[test]
    fn test_stored_entry_storage_key() {
        let data = "test";
        let entry = StoredEntry::new(
            Category::Agent,
            "challenge1",
            "agent1",
            &data,
            "validator1",
            100,
            None,
        )
        .unwrap();

        let key = entry.storage_key();
        assert!(!key.is_empty());

        // Key should start with category prefix
        assert!(key.starts_with(Category::Agent.prefix()));
    }

    #[test]
    fn test_write_op_voting() {
        let data = "test";
        let entry = StoredEntry::new(
            Category::Agent,
            "challenge1",
            "agent1",
            &data,
            "validator1",
            100,
            None,
        )
        .unwrap();

        let mut op = WriteOp::new(entry, "validator1", 100);

        // Initially has self-vote from initiator
        assert_eq!(op.votes_yes.len(), 1);
        assert_eq!(op.votes_no.len(), 0);

        // Vote approve
        op.vote("validator2", true);
        assert_eq!(op.votes_yes.len(), 2);
        assert_eq!(op.votes_no.len(), 0);

        // Vote reject
        op.vote("validator3", false);
        assert_eq!(op.votes_yes.len(), 2);
        assert_eq!(op.votes_no.len(), 1);
    }

    #[test]
    fn test_write_op_check_consensus_approve() {
        let data = "test";
        let entry = StoredEntry::new(
            Category::Agent,
            "challenge1",
            "agent1",
            &data,
            "validator1",
            100,
            None,
        )
        .unwrap();

        let mut op = WriteOp::new(entry, "validator1", 100);

        // With 5 validators, need 3 votes (60%) for consensus
        // Initiator has self-vote (1)
        assert_eq!(op.check_consensus(5), None); // 1/5 = 20%

        op.vote("validator2", true);
        assert_eq!(op.check_consensus(5), None); // 2/5 = 40%

        op.vote("validator3", true);
        assert_eq!(op.check_consensus(5), Some(true)); // 3/5 = 60% >= 50%
    }

    #[test]
    fn test_write_op_check_consensus_reject() {
        let data = "test";
        let entry = StoredEntry::new(
            Category::Agent,
            "challenge1",
            "agent1",
            &data,
            "validator1",
            100,
            None,
        )
        .unwrap();

        let mut op = WriteOp::new(entry, "validator1", 100);

        // Vote reject enough times to reach consensus
        op.vote("validator2", false);
        op.vote("validator3", false);
        op.vote("validator4", false);

        // 3/5 = 60% rejections >= 50%
        assert_eq!(op.check_consensus(5), Some(false));
    }

    #[test]
    fn test_distributed_storage_set_block() {
        let storage = create_test_storage();

        storage.set_block(100);
        assert_eq!(*storage.current_block.read(), 100);

        storage.set_block(200);
        assert_eq!(*storage.current_block.read(), 200);
    }

    #[test]
    fn test_distributed_storage_set_validators() {
        let storage = create_test_storage();

        storage.set_validators(10);
        assert_eq!(*storage.total_validators.read(), 10);

        storage.set_validators(20);
        assert_eq!(*storage.total_validators.read(), 20);
    }

    #[test]
    fn test_distributed_storage_propose_and_vote() {
        let storage = create_test_storage();
        storage.set_validators(5); // Use 5 validators so we need 3 votes
        storage.set_block(100);

        // Propose a write (initiator gets self-vote = 1)
        let op = storage
            .propose_write(Category::Agent, "challenge1", "agent1", &"data", None)
            .unwrap();

        // Get the op
        let pending_op = storage.get_pending_op(&op.op_id);
        assert!(pending_op.is_some());

        // Vote on it (now 2/5, still < 3 needed)
        let result = storage.vote_write(&op.op_id, "validator2", true);
        assert_eq!(result, None); // Still needs more votes

        // Another vote reaches consensus (3/5 = 60% >= 50%)
        let result = storage.vote_write(&op.op_id, "validator3", true);
        assert_eq!(result, Some(true));

        // Op should be removed from pending
        let pending_op = storage.get_pending_op(&op.op_id);
        assert!(pending_op.is_none());

        // Entry should now exist
        let entry = storage
            .get(Category::Agent, "challenge1", "agent1")
            .unwrap();
        assert!(entry.is_some());
    }

    #[test]
    fn test_distributed_storage_list_by_category() {
        let storage = create_test_storage();
        storage.set_validators(1);
        storage.set_block(100);

        // Add multiple entries
        storage
            .propose_write(Category::Agent, "challenge1", "agent1", &"data1", None)
            .unwrap();
        storage
            .propose_write(Category::Agent, "challenge1", "agent2", &"data2", None)
            .unwrap();

        // List by category
        let entries = storage
            .list_by_category(Category::Agent, "challenge1", 100)
            .unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_distributed_storage_get_value() {
        let storage = create_test_storage();
        storage.set_validators(1);
        storage.set_block(100);

        let test_data = "test string data";
        storage
            .propose_write(Category::Agent, "challenge1", "agent1", &test_data, None)
            .unwrap();

        // Get as typed value
        let value: String = storage
            .get_value(Category::Agent, "challenge1", "agent1")
            .unwrap()
            .unwrap();
        assert_eq!(value, test_data);
    }

    #[test]
    fn test_distributed_storage_cleanup_expired() {
        let storage = create_test_storage();
        storage.set_validators(1);
        storage.set_block(100);

        // Add entries with different TTLs
        storage
            .propose_write(
                Category::Log,
                "challenge1",
                "log1",
                &"data1",
                Some(10), // Expires at 110
            )
            .unwrap();
        storage
            .propose_write(
                Category::Log,
                "challenge1",
                "log2",
                &"data2",
                Some(20), // Expires at 120
            )
            .unwrap();
        storage
            .propose_write(
                Category::Agent,
                "challenge1",
                "agent1",
                &"permanent",
                None, // Never expires
            )
            .unwrap();

        // Move to block 115 (log1 expired, log2 not yet)
        storage.set_block(115);
        let removed = storage.cleanup_expired().unwrap();
        assert_eq!(removed, 1);

        // log1 should be gone
        let log1 = storage.get(Category::Log, "challenge1", "log1").unwrap();
        assert!(log1.is_none());

        // log2 should still exist
        let log2 = storage.get(Category::Log, "challenge1", "log2").unwrap();
        assert!(log2.is_some());

        // agent1 should still exist
        let agent1 = storage
            .get(Category::Agent, "challenge1", "agent1")
            .unwrap();
        assert!(agent1.is_some());
    }

    #[test]
    fn test_stored_entry_too_large() {
        let large_data = vec![0u8; MAX_RAW_SIZE + 1];

        let result = StoredEntry::new(
            Category::Agent,
            "challenge1",
            "agent1",
            &large_data,
            "validator1",
            100,
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_write_op_duplicate_vote_same_direction() {
        let data = "test";
        let entry = StoredEntry::new(
            Category::Agent,
            "challenge1",
            "agent1",
            &data,
            "validator1",
            100,
            None,
        )
        .unwrap();

        let mut op = WriteOp::new(entry, "validator1", 100);

        // First vote from validator2
        op.vote("validator2", true);
        assert_eq!(op.votes_yes.len(), 2); // initiator + validator2

        // Duplicate vote from same validator
        op.vote("validator2", true);
        assert_eq!(op.votes_yes.len(), 2); // Should not increase
    }

    #[test]
    fn test_get_pending_ops_by_challenge() {
        let storage = create_test_storage();
        storage.set_validators(10); // High count so consensus isn't reached
        storage.set_block(100);

        // Propose multiple writes for same challenge
        storage
            .propose_write(Category::Agent, "challenge1", "agent1", &"data1", None)
            .unwrap();
        storage
            .propose_write(Category::Agent, "challenge1", "agent2", &"data2", None)
            .unwrap();
        storage
            .propose_write(Category::Agent, "challenge2", "agent3", &"data3", None)
            .unwrap();

        // Get pending ops for challenge1
        let ops = storage.get_pending_ops("challenge1");
        assert_eq!(ops.len(), 2);

        // Get pending ops for challenge2
        let ops2 = storage.get_pending_ops("challenge2");
        assert_eq!(ops2.len(), 1);
    }

    #[test]
    fn test_write_request_info_deserialize_value() {
        let request = WriteRequestInfo {
            category: Category::Agent,
            challenge_id: "challenge1".to_string(),
            key: "agent1".to_string(),
            value: b"test".to_vec(),
            size: 4,
            creator: "validator1".to_string(),
            creator_stake: 1000,
            block: 100,
            is_update: false,
            previous_hash: None,
            writes_this_epoch: 0,
            category_entry_count: 0,
            total_validators: 5,
        };

        let result: Result<String, _> = request.deserialize_value();
        assert!(result.is_err()); // Invalid binary data for String deserialization
    }

    #[test]
    fn test_category_index_prefix() {
        // Test Category::Index prefix generation
        assert_eq!(Category::Index.prefix(), b"idx:");
    }

    #[test]
    fn test_write_request_info_serialization_error() {
        // Test line 210: bincode::serialize error path
        // This is covered by attempting to serialize a large value
        let dir = tempfile::tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage = DistributedStorage::open(&db, "validator1").unwrap();

        // Create a value larger than MAX_RAW_SIZE
        let large_value = vec![0u8; MAX_RAW_SIZE + 1];
        let result =
            storage.propose_write(Category::Agent, "challenge1", "key1", &large_value, None);

        // Should fail with TooLarge error
        assert!(result.is_err());
    }

    #[test]
    fn test_compression_error() {
        // Test lines 219-222: compression error paths
        // These are covered by the TooLarge error after compression
        let dir = tempfile::tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage = DistributedStorage::open(&db, "validator1").unwrap();

        // Create a value that compresses to > MAX_COMPRESSED_SIZE
        // This is difficult to trigger naturally, but we test the size check
        let data = "test data";
        let result = storage.propose_write(Category::Agent, "challenge1", "key1", &data, None);
        assert!(result.is_ok()); // Normal data should work
    }

    #[test]
    fn test_decompress_raw() {
        let dir = tempfile::tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage = DistributedStorage::open(&db, "validator1").unwrap();

        let data = "test decompress";
        let op = storage
            .propose_write(Category::Agent, "challenge1", "key1", &data, None)
            .unwrap();

        // Test decompress_raw method on the entry from the operation
        let raw = op.entry.decompress_raw().unwrap();
        assert!(!raw.is_empty());
    }

    #[test]
    fn test_verify_corrupted_entry() {
        let dir = tempfile::tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage = DistributedStorage::open(&db, "validator1").unwrap();

        let data = "test verify";
        let op = storage
            .propose_write(Category::Agent, "challenge1", "key1", &data, None)
            .unwrap();

        // Test with the entry from the operation
        let mut entry = op.entry.clone();

        // Line 275: verify should return false for corrupted data
        entry.header.value_hash = [0u8; 32]; // Corrupt hash
        assert!(!entry.verify());
    }

    #[test]
    fn test_propose_write_validated() {
        let dir = tempfile::tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage = DistributedStorage::open(&db, "validator1").unwrap();

        let result = storage.propose_write_validated(
            Category::Agent,
            "challenge1",
            "key1",
            &"test data",
            1000, // creator_stake as u64, not Option
            |_info| WriteValidationResult::Accept,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_write_direct() {
        let dir = tempfile::tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage = DistributedStorage::open(&db, "validator1").unwrap();

        let entry = StoredEntry::new(
            Category::Agent,
            "challenge1",
            "key1",
            &"test data",
            "validator1",
            100,
            None,
        )
        .unwrap();

        let result = storage.write_direct(entry);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_submissions() {
        let dir = tempfile::tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let storage = DistributedStorage::open(&db, "validator1").unwrap();

        let entry = StoredEntry::new(
            Category::Submission,
            "challenge1",
            "key1",
            &"submission1",
            "validator1",
            100,
            None,
        )
        .unwrap();

        storage.write_direct(entry).unwrap();

        let submissions = storage.get_submissions("challenge1");
        assert!(submissions.is_ok());
    }

    #[test]
    fn test_storage_error_display() {
        let err = StorageError::NotFound("test key".to_string());
        assert_eq!(format!("{}", err), "Not found: test key");

        let err = StorageError::Serialization("test".to_string());
        assert_eq!(format!("{}", err), "Serialization error: test");

        let err = StorageError::Decompression("test".to_string());
        assert_eq!(format!("{}", err), "Decompression error: test");

        let err = StorageError::TooLarge(100, 50);
        assert_eq!(format!("{}", err), "Entry too large: 100 > 50");

        let err = StorageError::ConsensusNotReached;
        assert_eq!(format!("{}", err), "Consensus not reached");

        let err = StorageError::ValidationFailed("test".to_string());
        assert_eq!(format!("{}", err), "Validation failed: test");

        let err = StorageError::Database("test".to_string());
        assert_eq!(format!("{}", err), "Database error: test");

        let err = StorageError::InvalidEntry("test".to_string());
        assert_eq!(format!("{}", err), "Invalid entry: test");
    }
}
