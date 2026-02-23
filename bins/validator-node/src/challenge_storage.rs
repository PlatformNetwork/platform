use platform_core::{ChallengeId, Keypair};
use platform_distributed_storage::{
    DistributedStore, GetOptions as DGetOptions, LocalStorage, PutOptions as DPutOptions,
    StorageKey as DStorageKey,
};
use platform_p2p_consensus::{P2PCommand, P2PMessage, StorageProposalMessage};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::mpsc;
use wasm_runtime_interface::storage::{StorageBackend, StorageHostError};

pub struct ChallengeStorageBackend {
    storage: Arc<LocalStorage>,
    p2p_tx: Option<mpsc::Sender<P2PCommand>>,
    keypair: Option<Keypair>,
}

impl ChallengeStorageBackend {
    pub fn new(storage: Arc<LocalStorage>) -> Self {
        Self {
            storage,
            p2p_tx: None,
            keypair: None,
        }
    }

    pub fn with_p2p(
        storage: Arc<LocalStorage>,
        p2p_tx: mpsc::Sender<P2PCommand>,
        keypair: Keypair,
    ) -> Self {
        Self {
            storage,
            p2p_tx: Some(p2p_tx),
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

            // Fire and forget - don't block WASM execution on P2P
            let _ = tx.try_send(P2PCommand::Broadcast(msg));
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
}
