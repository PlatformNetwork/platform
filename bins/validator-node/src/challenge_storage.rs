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

impl StorageBackend for ChallengeStorageBackend {
    fn get(&self, challenge_id: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StorageHostError> {
        let storage_key = DStorageKey::new(challenge_id, hex::encode(key));
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
        let storage_key = DStorageKey::new(challenge_id, hex::encode(key));
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.storage.put(
                storage_key,
                value.to_vec(),
                DPutOptions::default(),
            ))
        })
        .map_err(|e| StorageHostError::StorageError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(challenge_id.as_bytes());
        hasher.update(key);
        hasher.update(value);
        let proposal_id: [u8; 32] = hasher.finalize().into();

        // Broadcast via P2P if configured
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
        }

        Ok(proposal_id)
    }

    fn delete(&self, challenge_id: &str, key: &[u8]) -> Result<bool, StorageHostError> {
        let storage_key = DStorageKey::new(challenge_id, hex::encode(key));
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
        let storage_key = DStorageKey::new(challenge_id, hex::encode(key));
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(self.storage.get(&storage_key, DGetOptions::default()))
        })
        .map_err(|e| StorageHostError::StorageError(e.to_string()))?;
        Ok(result.map(|v| v.data))
    }
}
