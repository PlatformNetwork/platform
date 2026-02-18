//! Storage Host Functions for WASM Challenges
//!
//! This module provides host functions that allow WASM code to interact with
//! validated storage. All write operations go through consensus to prevent abuse.
//!
//! # Host Functions
//!
//! - `storage_get(key_ptr, key_len, value_ptr) -> i32` - Read from storage
//! - `storage_set(key_ptr, key_len, value_ptr, value_len) -> i32` - Write to storage
//! - `storage_propose_write(key_ptr, key_len, value_ptr, value_len) -> i64` - Propose a write
//! - `storage_delete(key_ptr, key_len) -> i32` - Delete from storage (requires consensus)
//!
//! # Memory Layout
//!
//! Return values use a packed i64 format:
//! - High 32 bits: status code (0 = success, negative = error)
//! - Low 32 bits: result pointer or length
//!
//! For `storage_get`:
//! - Success: returns pointer to result buffer in WASM memory
//! - Not found: returns 0
//! - Error: returns negative status code

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::warn;
use wasmtime::{Caller, Linker, Memory};

use crate::runtime::{HostFunctionRegistrar, RuntimeState, WasmRuntimeError};

pub const HOST_STORAGE_NAMESPACE: &str = "platform_storage";
pub const HOST_STORAGE_GET: &str = "storage_get";
pub const HOST_STORAGE_SET: &str = "storage_set";
pub const HOST_STORAGE_PROPOSE_WRITE: &str = "storage_propose_write";
pub const HOST_STORAGE_DELETE: &str = "storage_delete";
pub const HOST_STORAGE_GET_RESULT: &str = "storage_get_result";
pub const HOST_STORAGE_ALLOC: &str = "storage_alloc";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum StorageHostStatus {
    Success = 0,
    NotFound = 1,
    KeyTooLarge = -1,
    ValueTooLarge = -2,
    InvalidKey = -3,
    InvalidValue = -4,
    StorageError = -5,
    ConsensusRequired = -6,
    PermissionDenied = -7,
    QuotaExceeded = -8,
    InternalError = -100,
}

impl StorageHostStatus {
    pub fn to_i32(self) -> i32 {
        self as i32
    }

    pub fn from_i32(code: i32) -> Self {
        match code {
            0 => Self::Success,
            1 => Self::NotFound,
            -1 => Self::KeyTooLarge,
            -2 => Self::ValueTooLarge,
            -3 => Self::InvalidKey,
            -4 => Self::InvalidValue,
            -5 => Self::StorageError,
            -6 => Self::ConsensusRequired,
            -7 => Self::PermissionDenied,
            -8 => Self::QuotaExceeded,
            _ => Self::InternalError,
        }
    }
}

#[derive(Debug, Error)]
pub enum StorageHostError {
    #[error("key too large: {0} bytes (max {1})")]
    KeyTooLarge(usize, usize),

    #[error("value too large: {0} bytes (max {1})")]
    ValueTooLarge(usize, usize),

    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("invalid value: {0}")]
    InvalidValue(String),

    #[error("storage error: {0}")]
    StorageError(String),

    #[error("consensus required for write")]
    ConsensusRequired,

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("quota exceeded: {0}")]
    QuotaExceeded(String),

    #[error("memory error: {0}")]
    MemoryError(String),

    #[error("internal error: {0}")]
    InternalError(String),
}

impl From<StorageHostError> for StorageHostStatus {
    fn from(err: StorageHostError) -> Self {
        match err {
            StorageHostError::KeyTooLarge(_, _) => Self::KeyTooLarge,
            StorageHostError::ValueTooLarge(_, _) => Self::ValueTooLarge,
            StorageHostError::InvalidKey(_) => Self::InvalidKey,
            StorageHostError::InvalidValue(_) => Self::InvalidValue,
            StorageHostError::StorageError(_) => Self::StorageError,
            StorageHostError::ConsensusRequired => Self::ConsensusRequired,
            StorageHostError::PermissionDenied(_) => Self::PermissionDenied,
            StorageHostError::QuotaExceeded(_) => Self::QuotaExceeded,
            StorageHostError::MemoryError(_) => Self::InternalError,
            StorageHostError::InternalError(_) => Self::InternalError,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageHostConfig {
    pub max_key_size: usize,
    pub max_value_size: usize,
    pub max_total_storage: usize,
    pub max_keys_per_challenge: usize,
    pub allow_direct_writes: bool,
    pub require_consensus: bool,
}

impl Default for StorageHostConfig {
    fn default() -> Self {
        Self {
            max_key_size: 1024,
            max_value_size: 1024 * 1024,
            max_total_storage: 100 * 1024 * 1024,
            max_keys_per_challenge: 10_000,
            allow_direct_writes: false,
            require_consensus: true,
        }
    }
}

impl StorageHostConfig {
    pub fn permissive() -> Self {
        Self {
            max_key_size: 4096,
            max_value_size: 10 * 1024 * 1024,
            max_total_storage: 1024 * 1024 * 1024,
            max_keys_per_challenge: 100_000,
            allow_direct_writes: true,
            require_consensus: false,
        }
    }

    pub fn validate_key(&self, key: &[u8]) -> Result<(), StorageHostError> {
        if key.is_empty() {
            return Err(StorageHostError::InvalidKey(
                "key cannot be empty".to_string(),
            ));
        }
        if key.len() > self.max_key_size {
            return Err(StorageHostError::KeyTooLarge(key.len(), self.max_key_size));
        }
        Ok(())
    }

    pub fn validate_value(&self, value: &[u8]) -> Result<(), StorageHostError> {
        if value.len() > self.max_value_size {
            return Err(StorageHostError::ValueTooLarge(
                value.len(),
                self.max_value_size,
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageGetRequest {
    pub challenge_id: String,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageGetResponse {
    pub found: bool,
    pub value: Option<Vec<u8>>,
    pub version: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProposeWriteRequest {
    pub challenge_id: String,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProposeWriteResponse {
    pub proposal_id: [u8; 32],
    pub status: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageDeleteRequest {
    pub challenge_id: String,
    pub key: Vec<u8>,
}

pub struct StorageHostState {
    pub config: StorageHostConfig,
    pub challenge_id: String,
    pub backend: Arc<dyn StorageBackend>,
    pub pending_results: HashMap<u32, Vec<u8>>,
    pub next_result_id: u32,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub operations_count: u32,
}

impl StorageHostState {
    pub fn new(
        challenge_id: String,
        config: StorageHostConfig,
        backend: Arc<dyn StorageBackend>,
    ) -> Self {
        Self {
            config,
            challenge_id,
            backend,
            pending_results: HashMap::new(),
            next_result_id: 1,
            bytes_read: 0,
            bytes_written: 0,
            operations_count: 0,
        }
    }

    pub fn store_result(&mut self, data: Vec<u8>) -> u32 {
        let id = self.next_result_id;
        self.next_result_id = self.next_result_id.wrapping_add(1);
        self.pending_results.insert(id, data);
        id
    }

    pub fn take_result(&mut self, id: u32) -> Option<Vec<u8>> {
        self.pending_results.remove(&id)
    }

    pub fn reset_counters(&mut self) {
        self.bytes_read = 0;
        self.bytes_written = 0;
        self.operations_count = 0;
    }
}

pub fn pack_result(status: StorageHostStatus, value: u32) -> i64 {
    let status_bits = (status.to_i32() as i64) << 32;
    let value_bits = value as i64;
    status_bits | value_bits
}

pub fn unpack_result(packed: i64) -> (StorageHostStatus, u32) {
    let status = StorageHostStatus::from_i32((packed >> 32) as i32);
    let value = (packed & 0xFFFFFFFF) as u32;
    (status, value)
}

pub trait StorageBackend: Send + Sync {
    fn get(&self, challenge_id: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StorageHostError>;

    fn propose_write(
        &self,
        challenge_id: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<[u8; 32], StorageHostError>;

    fn delete(&self, challenge_id: &str, key: &[u8]) -> Result<bool, StorageHostError>;
}

pub struct NoopStorageBackend;

impl StorageBackend for NoopStorageBackend {
    fn get(&self, _challenge_id: &str, _key: &[u8]) -> Result<Option<Vec<u8>>, StorageHostError> {
        Ok(None)
    }

    fn propose_write(
        &self,
        _challenge_id: &str,
        _key: &[u8],
        _value: &[u8],
    ) -> Result<[u8; 32], StorageHostError> {
        Err(StorageHostError::ConsensusRequired)
    }

    fn delete(&self, _challenge_id: &str, _key: &[u8]) -> Result<bool, StorageHostError> {
        Ok(false)
    }
}

type StorageMap = HashMap<String, HashMap<Vec<u8>, Vec<u8>>>;

pub struct InMemoryStorageBackend {
    data: RwLock<StorageMap>,
}

impl InMemoryStorageBackend {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryStorageBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for InMemoryStorageBackend {
    fn get(&self, challenge_id: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StorageHostError> {
        let data = self
            .data
            .read()
            .map_err(|e| StorageHostError::InternalError(format!("lock poisoned: {}", e)))?;
        Ok(data
            .get(challenge_id)
            .and_then(|challenge_data: &HashMap<Vec<u8>, Vec<u8>>| {
                challenge_data.get(key).cloned()
            }))
    }

    fn propose_write(
        &self,
        challenge_id: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<[u8; 32], StorageHostError> {
        let mut data = self
            .data
            .write()
            .map_err(|e| StorageHostError::InternalError(format!("lock poisoned: {}", e)))?;
        let challenge_data: &mut HashMap<Vec<u8>, Vec<u8>> =
            data.entry(challenge_id.to_string()).or_default();
        challenge_data.insert(key.to_vec(), value.to_vec());

        let mut hasher = Sha256::new();
        hasher.update(challenge_id.as_bytes());
        hasher.update(key);
        hasher.update(value);
        Ok(hasher.finalize().into())
    }

    fn delete(&self, challenge_id: &str, key: &[u8]) -> Result<bool, StorageHostError> {
        let mut data = self
            .data
            .write()
            .map_err(|e| StorageHostError::InternalError(format!("lock poisoned: {}", e)))?;
        if let Some(challenge_data) = data.get_mut(challenge_id) {
            Ok(challenge_data.remove(key).is_some())
        } else {
            Ok(false)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAuditEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub challenge_id: String,
    pub validator_id: String,
    pub operation: StorageOperation,
    pub key_hash: [u8; 32],
    pub value_size: Option<usize>,
    pub status: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageOperation {
    Get,
    Set,
    ProposeWrite,
    Delete,
}

pub trait StorageAuditLogger: Send + Sync {
    fn record(&self, entry: StorageAuditEntry);
}

pub struct NoopStorageAuditLogger;

impl StorageAuditLogger for NoopStorageAuditLogger {
    fn record(&self, _entry: StorageAuditEntry) {}
}

#[derive(Clone, Debug)]
pub struct StorageHostFunctions;

impl StorageHostFunctions {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StorageHostFunctions {
    fn default() -> Self {
        Self::new()
    }
}

impl HostFunctionRegistrar for StorageHostFunctions {
    fn register(&self, linker: &mut Linker<RuntimeState>) -> Result<(), WasmRuntimeError> {
        linker
            .func_wrap(
                HOST_STORAGE_NAMESPACE,
                HOST_STORAGE_GET,
                |mut caller: Caller<RuntimeState>,
                 key_ptr: i32,
                 key_len: i32,
                 value_ptr: i32|
                 -> i32 {
                    handle_storage_get(&mut caller, key_ptr, key_len, value_ptr)
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_STORAGE_NAMESPACE,
                HOST_STORAGE_SET,
                |mut caller: Caller<RuntimeState>,
                 key_ptr: i32,
                 key_len: i32,
                 value_ptr: i32,
                 value_len: i32|
                 -> i32 {
                    handle_storage_set(&mut caller, key_ptr, key_len, value_ptr, value_len)
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_STORAGE_NAMESPACE,
                HOST_STORAGE_DELETE,
                |mut caller: Caller<RuntimeState>, key_ptr: i32, key_len: i32| -> i32 {
                    handle_storage_delete(&mut caller, key_ptr, key_len)
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_STORAGE_NAMESPACE,
                HOST_STORAGE_PROPOSE_WRITE,
                |mut caller: Caller<RuntimeState>,
                 key_ptr: i32,
                 key_len: i32,
                 value_ptr: i32,
                 value_len: i32|
                 -> i64 {
                    handle_storage_propose_write(
                        &mut caller,
                        key_ptr,
                        key_len,
                        value_ptr,
                        value_len,
                    )
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        Ok(())
    }
}

fn handle_storage_get(
    caller: &mut Caller<RuntimeState>,
    key_ptr: i32,
    key_len: i32,
    value_ptr: i32,
) -> i32 {
    let key = match read_wasm_memory(caller, key_ptr, key_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "storage_get: failed to read key from wasm memory");
            return StorageHostStatus::InternalError.to_i32();
        }
    };

    let storage = &caller.data().storage_state;
    if let Err(err) = storage.config.validate_key(&key) {
        warn!(error = %err, "storage_get: key validation failed");
        return StorageHostStatus::from(err).to_i32();
    }

    let challenge_id = storage.challenge_id.clone();
    let backend = Arc::clone(&storage.backend);

    let value = match backend.get(&challenge_id, &key) {
        Ok(Some(v)) => v,
        Ok(None) => return 0,
        Err(err) => {
            warn!(error = %err, "storage_get: backend read failed");
            return StorageHostStatus::from(err).to_i32();
        }
    };

    caller.data_mut().storage_state.bytes_read += value.len() as u64;
    caller.data_mut().storage_state.operations_count += 1;

    if let Err(err) = write_wasm_memory(caller, value_ptr, &value) {
        warn!(error = %err, "storage_get: failed to write value to wasm memory");
        return StorageHostStatus::InternalError.to_i32();
    }

    value.len() as i32
}

fn handle_storage_set(
    caller: &mut Caller<RuntimeState>,
    key_ptr: i32,
    key_len: i32,
    value_ptr: i32,
    value_len: i32,
) -> i32 {
    let key = match read_wasm_memory(caller, key_ptr, key_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "storage_set: failed to read key from wasm memory");
            return StorageHostStatus::InternalError.to_i32();
        }
    };

    let value = match read_wasm_memory(caller, value_ptr, value_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "storage_set: failed to read value from wasm memory");
            return StorageHostStatus::InternalError.to_i32();
        }
    };

    let storage = &caller.data().storage_state;
    if let Err(err) = storage.config.validate_key(&key) {
        warn!(error = %err, "storage_set: key validation failed");
        return StorageHostStatus::from(err).to_i32();
    }
    if let Err(err) = storage.config.validate_value(&value) {
        warn!(error = %err, "storage_set: value validation failed");
        return StorageHostStatus::from(err).to_i32();
    }

    if storage.config.require_consensus && !storage.config.allow_direct_writes {
        warn!("storage_set: direct writes require consensus or allow_direct_writes");
        return StorageHostStatus::ConsensusRequired.to_i32();
    }

    let challenge_id = storage.challenge_id.clone();
    let backend = Arc::clone(&storage.backend);

    match backend.propose_write(&challenge_id, &key, &value) {
        Ok(_proposal_id) => {
            caller.data_mut().storage_state.bytes_written += value.len() as u64;
            caller.data_mut().storage_state.operations_count += 1;
            StorageHostStatus::Success.to_i32()
        }
        Err(err) => {
            warn!(error = %err, "storage_set: backend write failed");
            StorageHostStatus::from(err).to_i32()
        }
    }
}

fn handle_storage_delete(caller: &mut Caller<RuntimeState>, key_ptr: i32, key_len: i32) -> i32 {
    let key = match read_wasm_memory(caller, key_ptr, key_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "storage_delete: failed to read key from wasm memory");
            return StorageHostStatus::InternalError.to_i32();
        }
    };

    let storage = &caller.data().storage_state;
    if let Err(err) = storage.config.validate_key(&key) {
        warn!(error = %err, "storage_delete: key validation failed");
        return StorageHostStatus::from(err).to_i32();
    }

    if storage.config.require_consensus && !storage.config.allow_direct_writes {
        warn!("storage_delete: direct deletes require consensus or allow_direct_writes");
        return StorageHostStatus::ConsensusRequired.to_i32();
    }

    let challenge_id = storage.challenge_id.clone();
    let backend = Arc::clone(&storage.backend);

    match backend.delete(&challenge_id, &key) {
        Ok(_deleted) => {
            caller.data_mut().storage_state.operations_count += 1;
            StorageHostStatus::Success.to_i32()
        }
        Err(err) => {
            warn!(error = %err, "storage_delete: backend delete failed");
            StorageHostStatus::from(err).to_i32()
        }
    }
}

fn handle_storage_propose_write(
    caller: &mut Caller<RuntimeState>,
    key_ptr: i32,
    key_len: i32,
    value_ptr: i32,
    value_len: i32,
) -> i64 {
    let key = match read_wasm_memory(caller, key_ptr, key_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "storage_propose_write: failed to read key from wasm memory");
            return pack_result(StorageHostStatus::InternalError, 0);
        }
    };

    let value = match read_wasm_memory(caller, value_ptr, value_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "storage_propose_write: failed to read value from wasm memory");
            return pack_result(StorageHostStatus::InternalError, 0);
        }
    };

    let storage = &caller.data().storage_state;
    if let Err(err) = storage.config.validate_key(&key) {
        warn!(error = %err, "storage_propose_write: key validation failed");
        return pack_result(StorageHostStatus::from(err), 0);
    }
    if let Err(err) = storage.config.validate_value(&value) {
        warn!(error = %err, "storage_propose_write: value validation failed");
        return pack_result(StorageHostStatus::from(err), 0);
    }

    let challenge_id = storage.challenge_id.clone();
    let backend = Arc::clone(&storage.backend);

    match backend.propose_write(&challenge_id, &key, &value) {
        Ok(proposal_id) => {
            caller.data_mut().storage_state.bytes_written += value.len() as u64;
            caller.data_mut().storage_state.operations_count += 1;
            let result_id = caller
                .data_mut()
                .storage_state
                .store_result(proposal_id.to_vec());
            pack_result(StorageHostStatus::Success, result_id)
        }
        Err(err) => {
            warn!(error = %err, "storage_propose_write: backend write failed");
            pack_result(StorageHostStatus::from(err), 0)
        }
    }
}

fn read_wasm_memory(
    caller: &mut Caller<RuntimeState>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, String> {
    if ptr < 0 || len < 0 {
        return Err("negative pointer/length".to_string());
    }
    let ptr = ptr as usize;
    let len = len as usize;
    let memory = get_memory(caller).ok_or_else(|| "memory export not found".to_string())?;
    let data = memory.data(caller);
    let end = ptr
        .checked_add(len)
        .ok_or_else(|| "pointer overflow".to_string())?;
    if end > data.len() {
        return Err("memory read out of bounds".to_string());
    }
    Ok(data[ptr..end].to_vec())
}

fn write_wasm_memory(
    caller: &mut Caller<RuntimeState>,
    ptr: i32,
    bytes: &[u8],
) -> Result<(), String> {
    if ptr < 0 {
        return Err("negative pointer".to_string());
    }
    let ptr = ptr as usize;
    let memory = get_memory(caller).ok_or_else(|| "memory export not found".to_string())?;
    let end = ptr
        .checked_add(bytes.len())
        .ok_or_else(|| "pointer overflow".to_string())?;
    let data = memory.data_mut(caller);
    if end > data.len() {
        return Err("memory write out of bounds".to_string());
    }
    data[ptr..end].copy_from_slice(bytes);
    Ok(())
}

fn get_memory(caller: &mut Caller<RuntimeState>) -> Option<Memory> {
    let memory_export = caller.data().memory_export.clone();
    caller
        .get_export(&memory_export)
        .and_then(|export| export.into_memory())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_unpack_result() {
        let status = StorageHostStatus::Success;
        let value = 12345u32;
        let packed = pack_result(status, value);
        let (unpacked_status, unpacked_value) = unpack_result(packed);
        assert_eq!(unpacked_status, status);
        assert_eq!(unpacked_value, value);
    }

    #[test]
    fn test_pack_unpack_error() {
        let status = StorageHostStatus::KeyTooLarge;
        let value = 0u32;
        let packed = pack_result(status, value);
        let (unpacked_status, unpacked_value) = unpack_result(packed);
        assert_eq!(unpacked_status, status);
        assert_eq!(unpacked_value, value);
    }

    #[test]
    fn test_storage_host_config_validate_key() {
        let config = StorageHostConfig::default();

        assert!(config.validate_key(b"valid-key").is_ok());
        assert!(config.validate_key(b"").is_err());

        let large_key = vec![0u8; 2000];
        assert!(config.validate_key(&large_key).is_err());
    }

    #[test]
    fn test_storage_host_config_validate_value() {
        let config = StorageHostConfig::default();

        assert!(config.validate_value(b"valid-value").is_ok());
        assert!(config.validate_value(b"").is_ok());

        let large_value = vec![0u8; 2 * 1024 * 1024];
        assert!(config.validate_value(&large_value).is_err());
    }

    #[test]
    fn test_storage_host_state() {
        let backend = Arc::new(InMemoryStorageBackend::new());
        let mut state = StorageHostState::new(
            "challenge-1".to_string(),
            StorageHostConfig::default(),
            backend,
        );

        let id1 = state.store_result(b"result1".to_vec());
        let id2 = state.store_result(b"result2".to_vec());

        assert_ne!(id1, id2);

        let result1 = state.take_result(id1);
        assert_eq!(result1, Some(b"result1".to_vec()));

        let result1_again = state.take_result(id1);
        assert_eq!(result1_again, None);

        let result2 = state.take_result(id2);
        assert_eq!(result2, Some(b"result2".to_vec()));
    }

    #[test]
    fn test_in_memory_storage_backend() {
        let backend = InMemoryStorageBackend::new();

        let result = backend.get("challenge-1", b"key1").unwrap();
        assert!(result.is_none());

        let proposal_id = backend
            .propose_write("challenge-1", b"key1", b"value1")
            .unwrap();
        assert_ne!(proposal_id, [0u8; 32]);

        let result = backend.get("challenge-1", b"key1").unwrap();
        assert_eq!(result, Some(b"value1".to_vec()));

        let deleted = backend.delete("challenge-1", b"key1").unwrap();
        assert!(deleted);

        let result = backend.get("challenge-1", b"key1").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_noop_storage_backend() {
        let backend = NoopStorageBackend;

        let result = backend.get("challenge-1", b"key1").unwrap();
        assert!(result.is_none());

        let result = backend.propose_write("challenge-1", b"key1", b"value1");
        assert!(matches!(result, Err(StorageHostError::ConsensusRequired)));

        let deleted = backend.delete("challenge-1", b"key1").unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_storage_host_status_conversion() {
        assert_eq!(StorageHostStatus::Success.to_i32(), 0);
        assert_eq!(StorageHostStatus::NotFound.to_i32(), 1);
        assert_eq!(StorageHostStatus::KeyTooLarge.to_i32(), -1);
        assert_eq!(StorageHostStatus::InternalError.to_i32(), -100);

        assert_eq!(StorageHostStatus::from_i32(0), StorageHostStatus::Success);
        assert_eq!(StorageHostStatus::from_i32(1), StorageHostStatus::NotFound);
        assert_eq!(
            StorageHostStatus::from_i32(-1),
            StorageHostStatus::KeyTooLarge
        );
        assert_eq!(
            StorageHostStatus::from_i32(-999),
            StorageHostStatus::InternalError
        );
    }

    #[test]
    fn test_storage_host_error_to_status() {
        let err = StorageHostError::KeyTooLarge(2000, 1024);
        assert_eq!(StorageHostStatus::from(err), StorageHostStatus::KeyTooLarge);

        let err = StorageHostError::ValueTooLarge(10_000_000, 1_000_000);
        assert_eq!(
            StorageHostStatus::from(err),
            StorageHostStatus::ValueTooLarge
        );

        let err = StorageHostError::ConsensusRequired;
        assert_eq!(
            StorageHostStatus::from(err),
            StorageHostStatus::ConsensusRequired
        );
    }

    #[test]
    fn test_permissive_config() {
        let config = StorageHostConfig::permissive();
        assert!(config.allow_direct_writes);
        assert!(!config.require_consensus);
        assert!(config.max_value_size > StorageHostConfig::default().max_value_size);
    }
}
