use platform_core::{ChallengeId, Keypair};
use platform_distributed_storage::{
    DistributedStore, GetOptions as DGetOptions, PutOptions as DPutOptions,
    StorageKey as DStorageKey,
};
use platform_p2p_consensus::{P2PCommand, P2PMessage, StorageProposal, StorageProposalMessage};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::mpsc;
use wasm_runtime_interface::storage::{StorageBackend, StorageHostError};

/// Channel for local storage proposals (proposer adds to own state)
pub type LocalProposalSender = mpsc::Sender<StorageProposal>;

pub struct ChallengeStorageBackend {
    storage: Arc<dyn DistributedStore>,
    p2p_tx: Option<mpsc::Sender<P2PCommand>>,
    local_proposal_tx: Option<LocalProposalSender>,
    keypair: Option<Keypair>,
}

impl ChallengeStorageBackend {
    #[allow(dead_code)]
    pub fn new(storage: Arc<dyn DistributedStore>) -> Self {
        Self {
            storage,
            p2p_tx: None,
            local_proposal_tx: None,
            keypair: None,
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
        }
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

        // DO NOT write locally here - data is only written after P2P consensus is reached.
        // All validators (including the proposer) write in the StorageVote handler when
        // 2f+1 votes approve. This ensures consistency across all nodes.

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

            // DO NOT write locally before consensus - this causes state divergence.
            // The proposer's get_weights would read uncommitted data that other validators
            // don't have yet. All nodes (including proposer) write only after P2P consensus.

            // Broadcast via P2P so all validators apply the write after consensus
            tracing::debug!(
                proposal_id = %hex::encode(&proposal_id[..8]),
                challenge_id = %challenge_id,
                key_len = key.len(),
                value_len = value.len(),
                "Broadcasting storage proposal via P2P"
            );
            let _ = tx.try_send(P2PCommand::Broadcast(msg));

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
                let _ = local_tx.try_send(local_proposal);
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
        let storage_key = build_challenge_storage_key(challenge_id, key);
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.storage.delete(&storage_key))
        })
        .map_err(|e| StorageHostError::StorageError(e.to_string()))
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
        let items: Vec<(Vec<u8>, Vec<u8>)> = result
            .items
            .into_iter()
            .map(|(storage_key, stored_value)| {
                let raw_key = hex::decode(storage_key.key_string().unwrap_or_default())
                    .unwrap_or_else(|_| storage_key.key.clone());
                (raw_key, stored_value.data)
            })
            .collect();

        Ok(items)
    }

    fn count_prefix(&self, challenge_id: &str, _prefix: &[u8]) -> Result<u64, StorageHostError> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(self.storage.count_by_namespace(challenge_id))
        })
        .map_err(|e| StorageHostError::StorageError(e.to_string()))
    }
}
