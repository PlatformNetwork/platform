use platform_core::{ChallengeId, Keypair};
use platform_distributed_storage::{
    DistributedStore, GetOptions as DGetOptions, PutOptions as DPutOptions,
    StorageKey as DStorageKey,
};
use platform_p2p_consensus::{P2PCommand, P2PMessage, StorageProposal, StorageProposalMessage};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use wasm_runtime_interface::storage::{StorageBackend, StorageHostError};

/// Channel for local storage proposals (proposer adds to own state)
pub type LocalProposalSender = mpsc::Sender<StorageProposal>;

/// Pending write value: Some(data) = write, None = delete
type PendingValue = Option<Vec<u8>>;

pub struct ChallengeStorageBackend {
    storage: Arc<dyn DistributedStore>,
    p2p_tx: Option<mpsc::Sender<P2PCommand>>,
    local_proposal_tx: Option<LocalProposalSender>,
    keypair: Option<Keypair>,
    /// Write-through cache for read-your-own-writes during a sync cycle.
    /// Key: (challenge_id, hex-encoded key). Value: pending data (None = delete).
    /// Cleared via `clear_pending_writes()` after each sync cycle completes.
    pending_writes: parking_lot::RwLock<HashMap<(String, String), PendingValue>>,
}

impl ChallengeStorageBackend {
    #[allow(dead_code)]
    pub fn new(storage: Arc<dyn DistributedStore>) -> Self {
        Self {
            storage,
            p2p_tx: None,
            local_proposal_tx: None,
            keypair: None,
            pending_writes: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    pub fn with_p2p(
        storage: Arc<dyn DistributedStore>,
        p2p_tx: mpsc::Sender<P2PCommand>,
        local_proposal_tx: LocalProposalSender,
        keypair: Keypair,
    ) -> Self {
        Self {
            storage,
            p2p_tx: Some(p2p_tx),
            local_proposal_tx: Some(local_proposal_tx),
            keypair: Some(keypair),
            pending_writes: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    /// Clear the pending writes cache. Call after each sync cycle completes
    /// so that subsequent reads go through consensus-confirmed storage.
    pub fn clear_pending_writes(&self) {
        self.pending_writes.write().clear();
    }

    /// Clear pending writes for a specific challenge only, leaving other
    /// challenges' caches intact to avoid race conditions.
    pub fn clear_pending_writes_for_challenge(&self, challenge_id: &str) {
        self.pending_writes
            .write()
            .retain(|(cid, _), _| cid != challenge_id);
    }
}

/// Build a standardized storage key for challenge data.
/// Format: namespace = challenge_id, key = hex-encoded key bytes.
/// This MUST match the format used in consensus writes (main.rs StorageVote handler).
fn build_challenge_storage_key(challenge_id: &str, key: &[u8]) -> DStorageKey {
    DStorageKey::new(challenge_id, hex::encode(key))
}

impl StorageBackend for ChallengeStorageBackend {
    fn get(&self, challenge_id: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StorageHostError> {
        // Check pending writes cache first (read-your-own-writes during sync)
        let cache_key = (challenge_id.to_string(), hex::encode(key));
        if let Some(pending) = self.pending_writes.read().get(&cache_key) {
            return Ok(pending.clone());
        }

        let storage_key = build_challenge_storage_key(challenge_id, key);
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(self.storage.get(&storage_key, DGetOptions::default()))
        })
        .map_err(|e| StorageHostError::StorageError(e.to_string()))?;
        Ok(result.map(|v| v.data))
    }

    fn propose_write(
        &self,
        challenge_id: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<[u8; 32], StorageHostError> {
        // Compute proposal ID from content
        let mut hasher = Sha256::new();
        hasher.update(challenge_id.as_bytes());
        hasher.update(key);
        hasher.update(value);
        let proposal_id: [u8; 32] = hasher.finalize().into();

        // Cache the write locally so WASM can read-its-own-writes during the
        // current sync cycle. This cache is NOT persisted to storage and does NOT
        // affect other validators. Actual storage write happens after P2P consensus.
        // The cache is cleared after each sync cycle via clear_pending_writes().
        {
            let cache_key = (challenge_id.to_string(), hex::encode(key));
            let cache_value = if value.is_empty() {
                None // delete
            } else {
                Some(value.to_vec())
            };
            self.pending_writes.write().insert(cache_key, cache_value);
        }

        // Broadcast via P2P for consensus
        if let (Some(tx), Some(kp)) = (&self.p2p_tx, &self.keypair) {
            let challenge_uuid = uuid::Uuid::parse_str(challenge_id).unwrap_or_else(|_| {
                // Derive a deterministic UUID from the challenge_id string
                let mut id_hash = [0u8; 16];
                let full_hash = <Sha256 as Digest>::digest(challenge_id.as_bytes());
                id_hash.copy_from_slice(&full_hash[..16]);
                uuid::Uuid::from_bytes(id_hash)
            });
            let timestamp = chrono::Utc::now().timestamp_millis();

            let sign_data =
                bincode::serialize(&(&proposal_id, challenge_id, timestamp)).unwrap_or_default();
            let signature = kp.sign_bytes(&sign_data).unwrap_or_default();

            let msg = P2PMessage::StorageProposal(StorageProposalMessage {
                proposal_id,
                challenge_id: ChallengeId(challenge_uuid),
                proposer: kp.hotkey(),
                key: key.to_vec(),
                value: value.to_vec(),
                timestamp,
                signature,
            });

            // Write locally first so WASM can read-your-own-writes during sync
            let storage_key = build_challenge_storage_key(challenge_id, key);
            if let Err(e) = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(self.storage.put(
                    storage_key,
                    value.to_vec(),
                    DPutOptions::default(),
                ))
            }) {
                tracing::warn!(error = %e, "Failed to write locally before P2P broadcast");
            }

            // Broadcast via P2P so other validators also apply the write
            tracing::debug!(
                proposal_id = %hex::encode(&proposal_id[..8]),
                challenge_id = %challenge_id,
                key_len = key.len(),
                value_len = value.len(),
                "Broadcasting storage proposal via P2P"
            );
            if let Err(e) = tx.try_send(P2PCommand::Broadcast(msg)) {
                tracing::warn!(
                    proposal_id = %hex::encode(&proposal_id[..8]),
                    error = %e,
                    "P2P broadcast channel full or closed, proposal may not reach consensus"
                );
            }

            // Also add the proposal to our local state for vote tracking
            if let Some(local_tx) = &self.local_proposal_tx {
                let local_proposal = StorageProposal {
                    proposal_id,
                    challenge_id: ChallengeId(challenge_uuid),
                    proposer: kp.hotkey(),
                    key: key.to_vec(),
                    value: value.to_vec(),
                    timestamp,
                    votes: std::collections::HashMap::new(),
                    finalized: false,
                };
                if let Err(e) = local_tx.try_send(local_proposal) {
                    tracing::warn!(
                        proposal_id = %hex::encode(&proposal_id[..8]),
                        error = %e,
                        "Local proposal channel full, vote tracking may be incomplete"
                    );
                }
            }
        } else {
            // No P2P configured - write locally for single-node/test mode
            let storage_key = build_challenge_storage_key(challenge_id, key);
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(self.storage.put(
                    storage_key,
                    value.to_vec(),
                    DPutOptions::default(),
                ))
            })
            .map_err(|e| StorageHostError::StorageError(e.to_string()))?;
        }

        Ok(proposal_id)
    }

    fn delete(&self, challenge_id: &str, key: &[u8]) -> Result<bool, StorageHostError> {
        // Route deletes through P2P consensus by proposing an empty value.
        // The StorageVote handler in main.rs checks for empty value and calls delete.
        if self.p2p_tx.is_some() {
            self.propose_write(challenge_id, key, &[])?;
            Ok(true)
        } else {
            let storage_key = build_challenge_storage_key(challenge_id, key);
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(self.storage.delete(&storage_key))
            })
            .map_err(|e| StorageHostError::StorageError(e.to_string()))
        }
    }

    fn get_cross(
        &self,
        challenge_id: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, StorageHostError> {
        let storage_key = build_challenge_storage_key(challenge_id, key);
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(self.storage.get(&storage_key, DGetOptions::default()))
        })
        .map_err(|e| StorageHostError::StorageError(e.to_string()))?;
        Ok(result.map(|v| v.data))
    }

    fn list_prefix(
        &self,
        challenge_id: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageHostError> {
        // Keys are stored hex-encoded (see build_challenge_storage_key),
        // so the prefix must also be hex-encoded for the scan to match.
        let hex_prefix = hex::encode(prefix);
        let prefix_filter: Option<&[u8]> = if prefix.is_empty() {
            None
        } else {
            Some(hex_prefix.as_bytes())
        };

        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.storage.list_prefix(
                challenge_id,
                prefix_filter,
                limit as usize,
                None,
            ))
        })
        .map_err(|e| StorageHostError::StorageError(e.to_string()))?;

        // Convert StorageKey back to the raw key bytes the WASM expects.
        // The key stored in DStorageKey is hex-encoded, so decode it back.
        let mut items: HashMap<Vec<u8>, Vec<u8>> = result
            .items
            .into_iter()
            .map(|(storage_key, stored_value)| {
                let raw_key = hex::decode(storage_key.key_string().unwrap_or_default())
                    .unwrap_or_else(|_| storage_key.key.clone());
                (raw_key, stored_value.data)
            })
            .collect();

        // Overlay pending_writes cache so reads within the same sync cycle
        // see newly written data (fixes stale leaderboard issue).
        {
            let cache = self.pending_writes.read();
            for ((cid, hex_key), pending_value) in cache.iter() {
                if cid != challenge_id {
                    continue;
                }
                // Check if this key matches the requested prefix
                let matches = if prefix.is_empty() {
                    true
                } else {
                    hex_key.starts_with(&hex_prefix)
                };
                if !matches {
                    continue;
                }
                let raw_key = hex::decode(hex_key).unwrap_or_else(|_| hex_key.as_bytes().to_vec());
                match pending_value {
                    Some(data) if !data.is_empty() => {
                        items.insert(raw_key, data.clone());
                    }
                    _ => {
                        // None or empty = delete
                        items.remove(&raw_key);
                    }
                }
            }
        }

        // Sort by key for deterministic ordering across calls
        let mut result: Vec<(Vec<u8>, Vec<u8>)> = items.into_iter().collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        let limited = if result.len() > limit as usize {
            result[..limit as usize].to_vec()
        } else {
            result
        };

        Ok(limited)
    }

    fn count_prefix(&self, challenge_id: &str, prefix: &[u8]) -> Result<u64, StorageHostError> {
        if prefix.is_empty() {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(self.storage.count_by_namespace(challenge_id))
            })
            .map_err(|e| StorageHostError::StorageError(e.to_string()))
        } else {
            // Paginated counting to avoid materializing all data at once
            let hex_prefix = hex::encode(prefix);
            let page_size = 1000usize;
            let mut total = 0u64;
            let mut continuation: Option<Vec<u8>> = None;

            loop {
                let result = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(self.storage.list_prefix(
                        challenge_id,
                        Some(hex_prefix.as_bytes()),
                        page_size,
                        continuation.as_deref(),
                    ))
                })
                .map_err(|e| StorageHostError::StorageError(e.to_string()))?;

                let count = result.items.len() as u64;
                total += count;

                if count < page_size as u64 || result.continuation_token.is_none() {
                    break;
                }
                continuation = result.continuation_token;
            }

            Ok(total)
        }
    }
}
