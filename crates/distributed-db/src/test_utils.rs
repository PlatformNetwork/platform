//! Shared test utilities for distributed-db tests
//!
//! This module provides common test helpers to reduce duplication
//! across test modules.

#![cfg(test)]

use crate::{DistributedDB, IndexManager, Operation, RocksStorage, Transaction};
use platform_core::Hotkey;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};

/// Create a test Hotkey/validator with a specific byte value
pub fn create_test_hotkey(val: u8) -> Hotkey {
    Hotkey::from_bytes(&[val; 32]).unwrap()
}

/// Create a test DistributedDB instance with temporary storage
pub fn create_test_db() -> (TempDir, DistributedDB) {
    let dir = tempdir().unwrap();
    let validator = create_test_hotkey(1);
    let db = DistributedDB::open(dir.path(), validator).unwrap();
    (dir, db)
}

/// Create a test IndexManager with temporary storage
pub fn create_test_index_manager() -> (IndexManager, Arc<RocksStorage>, TempDir) {
    let dir = tempdir().unwrap();
    let storage = Arc::new(RocksStorage::open(dir.path()).unwrap());
    let indexes = IndexManager::new(storage.clone()).unwrap();
    (indexes, storage, dir)
}

/// Create a test Transaction with a Put operation
pub fn create_test_tx() -> Transaction {
    let hotkey = create_test_hotkey(1);
    Transaction::new(
        hotkey,
        Operation::Put {
            collection: "test".to_string(),
            key: b"key".to_vec(),
            value: b"value".to_vec(),
        },
    )
}
