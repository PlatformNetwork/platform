use platform_distributed_storage::{
    DistributedStore, GetOptions as DGetOptions, LocalStorage, PutOptions as DPutOptions,
    StorageKey as DStorageKey,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use wasm_runtime_interface::storage::{StorageBackend, StorageHostError};

#[allow(dead_code)]
pub struct ChallengeStorageBackend {
    storage: Arc<LocalStorage>,
}

impl ChallengeStorageBackend {
    #[allow(dead_code)]
    pub fn new(storage: Arc<LocalStorage>) -> Self {
        Self { storage }
    }
}

impl StorageBackend for ChallengeStorageBackend {
    fn get(&self, challenge_id: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StorageHostError> {
        let storage_key = DStorageKey::new(challenge_id, hex::encode(key));
        let result = tokio::runtime::Handle::current()
            .block_on(self.storage.get(&storage_key, DGetOptions::default()))
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
        tokio::runtime::Handle::current()
            .block_on(
                self.storage
                    .put(storage_key, value.to_vec(), DPutOptions::default()),
            )
            .map_err(|e| StorageHostError::StorageError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(challenge_id.as_bytes());
        hasher.update(key);
        hasher.update(value);
        Ok(hasher.finalize().into())
    }

    fn delete(&self, challenge_id: &str, key: &[u8]) -> Result<bool, StorageHostError> {
        let storage_key = DStorageKey::new(challenge_id, hex::encode(key));
        tokio::runtime::Handle::current()
            .block_on(self.storage.delete(&storage_key))
            .map_err(|e| StorageHostError::StorageError(e.to_string()))
    }

    fn get_cross(
        &self,
        challenge_id: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, StorageHostError> {
        self.get(challenge_id, key)
    }
}
