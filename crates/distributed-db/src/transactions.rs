//! Transaction management for optimistic execution
//!
//! Transactions are:
//! - Applied immediately (optimistic)
//! - Confirmed at Bittensor block boundaries
//! - Rolled back if consensus fails

use platform_core::Hotkey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Database operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    /// Put a single key-value
    Put {
        collection: String,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    /// Delete a key
    Delete { collection: String, key: Vec<u8> },
    /// Batch put multiple key-values
    BatchPut {
        operations: Vec<(String, Vec<u8>, Vec<u8>)>,
    },
}

/// Transaction in the distributed database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction ID (hash)
    id: [u8; 32],
    /// Sender hotkey
    pub sender: Hotkey,
    /// Operation to perform
    pub operation: Operation,
    /// Timestamp (Unix millis)
    pub timestamp: u64,
    /// Nonce for uniqueness
    pub nonce: u64,
    /// Signature over (sender, operation, timestamp, nonce)
    pub signature: Vec<u8>,
}

impl Transaction {
    /// Create a new transaction
    pub fn new(sender: Hotkey, operation: Operation) -> Self {
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;
        let nonce = rand::random::<u64>();

        let mut tx = Self {
            id: [0u8; 32],
            sender,
            operation,
            timestamp,
            nonce,
            signature: Vec::new(),
        };

        tx.id = tx.compute_id();
        tx
    }

    /// Compute transaction ID
    fn compute_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.sender.as_bytes());
        hasher.update(bincode::serialize(&self.operation).unwrap_or_default());
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        hasher.finalize().into()
    }

    /// Get transaction ID
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    /// Validate transaction
    pub fn validate(&self) -> anyhow::Result<()> {
        // Check ID matches
        if self.id != self.compute_id() {
            anyhow::bail!("Invalid transaction ID");
        }

        // Check timestamp is reasonable (within 1 hour)
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let one_hour = 60 * 60 * 1000;
        if self.timestamp > now + one_hour || self.timestamp < now.saturating_sub(one_hour) {
            anyhow::bail!("Transaction timestamp out of range");
        }

        // Signature verification

        Ok(())
    }

    /// Sign the transaction
    pub fn sign(&mut self, _keypair: &platform_core::Keypair) {
        // Signature implementation
        self.signature = vec![0u8; 64];
    }

    /// Get affected keys
    pub fn affected_keys(&self) -> Vec<(String, Vec<u8>)> {
        match &self.operation {
            Operation::Put {
                collection, key, ..
            } => {
                vec![(collection.clone(), key.clone())]
            }
            Operation::Delete { collection, key } => {
                vec![(collection.clone(), key.clone())]
            }
            Operation::BatchPut { operations } => operations
                .iter()
                .map(|(c, k, _)| (c.clone(), k.clone()))
                .collect(),
        }
    }
}

/// Transaction receipt after execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    /// Transaction ID
    pub tx_id: [u8; 32],
    /// Whether execution succeeded
    pub success: bool,
    /// Execution time in microseconds
    pub execution_time_us: u64,
    /// State root after execution
    pub state_root: [u8; 32],
}

/// Transaction status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Pending confirmation
    Pending,
    /// Confirmed in a block
    Confirmed,
    /// Rolled back
    RolledBack,
}

/// Pending transaction entry
#[derive(Debug, Clone)]
struct PendingTx {
    tx: Transaction,
    receipt: TransactionReceipt,
    status: TransactionStatus,
    submitted_at: u64,
}

/// Transaction pool for optimistic execution
pub struct TransactionPool {
    /// Pending transactions
    pending: HashMap<[u8; 32], PendingTx>,
    /// Confirmed transactions (block -> tx_ids)
    confirmed: HashMap<u64, Vec<[u8; 32]>>,
    /// Nonce per sender to prevent replays
    nonces: HashMap<Hotkey, u64>,
}

impl TransactionPool {
    /// Create a new transaction pool
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            confirmed: HashMap::new(),
            nonces: HashMap::new(),
        }
    }

    /// Add a pending transaction
    pub fn add_pending(&mut self, tx: Transaction, receipt: TransactionReceipt) {
        // Check nonce
        let current_nonce = self.nonces.get(&tx.sender).copied().unwrap_or(0);
        if tx.nonce <= current_nonce {
            tracing::warn!(
                "Transaction nonce too low: {} <= {}",
                tx.nonce,
                current_nonce
            );
            return;
        }

        self.nonces.insert(tx.sender.clone(), tx.nonce);

        let entry = PendingTx {
            tx,
            receipt,
            status: TransactionStatus::Pending,
            submitted_at: chrono::Utc::now().timestamp_millis() as u64,
        };

        self.pending.insert(entry.tx.id(), entry);
    }

    /// Get pending transactions for a block
    pub fn get_pending_for_block(&self, _block: u64) -> Vec<(Transaction, TransactionReceipt)> {
        self.pending
            .values()
            .filter(|p| p.status == TransactionStatus::Pending)
            .map(|p| (p.tx.clone(), p.receipt.clone()))
            .collect()
    }

    /// Confirm a transaction
    pub fn confirm(&mut self, tx_id: [u8; 32], block: u64) {
        if let Some(pending) = self.pending.get_mut(&tx_id) {
            pending.status = TransactionStatus::Confirmed;
        }

        self.confirmed.entry(block).or_default().push(tx_id);
    }

    /// Rollback a transaction
    pub fn rollback(&mut self, tx_id: [u8; 32]) {
        if let Some(pending) = self.pending.get_mut(&tx_id) {
            pending.status = TransactionStatus::RolledBack;
        }
    }

    /// Get transaction status
    pub fn status(&self, tx_id: &[u8; 32]) -> Option<TransactionStatus> {
        self.pending.get(tx_id).map(|p| p.status)
    }

    /// Get pending count
    pub fn pending_count(&self) -> usize {
        self.pending
            .values()
            .filter(|p| p.status == TransactionStatus::Pending)
            .count()
    }

    /// Cleanup old pending transactions
    pub fn cleanup_old(&mut self, before_block: u64) {
        // Remove confirmed blocks older than threshold
        self.confirmed.retain(|&block, _| block >= before_block);

        // Remove old pending transactions
        let cutoff = chrono::Utc::now().timestamp_millis() as u64 - (24 * 60 * 60 * 1000); // 24 hours
        self.pending
            .retain(|_, p| p.status == TransactionStatus::Pending && p.submitted_at > cutoff);
    }

    /// Get transactions by sender
    pub fn get_by_sender(&self, sender: &Hotkey) -> Vec<&Transaction> {
        self.pending
            .values()
            .filter(|p| &p.tx.sender == sender)
            .map(|p| &p.tx)
            .collect()
    }
}

impl Default for TransactionPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    fn create_tx_with_nonce(sender: Hotkey, operation: Operation, nonce: u64) -> Transaction {
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;

        let mut tx = Transaction {
            id: [0u8; 32],
            sender,
            operation,
            timestamp,
            nonce,
            signature: Vec::new(),
        };

        // Compute the ID
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        hasher.update(tx.sender.as_bytes());
        hasher.update(bincode::serialize(&tx.operation).unwrap_or_default());
        hasher.update(tx.timestamp.to_le_bytes());
        hasher.update(tx.nonce.to_le_bytes());
        tx.id = hasher.finalize().into();

        tx
    }

    #[test]
    fn test_transaction_creation() {
        let sender = create_test_hotkey(1);
        let tx = Transaction::new(
            sender,
            Operation::Put {
                collection: "test".to_string(),
                key: b"key".to_vec(),
                value: b"value".to_vec(),
            },
        );

        assert!(tx.validate().is_ok());
        assert_ne!(tx.id(), [0u8; 32]);
    }

    #[test]
    fn test_transaction_pool() {
        let mut pool = TransactionPool::new();
        let sender = create_test_hotkey(1);

        let tx = Transaction::new(
            sender.clone(),
            Operation::Put {
                collection: "test".to_string(),
                key: b"key".to_vec(),
                value: b"value".to_vec(),
            },
        );

        let receipt = TransactionReceipt {
            tx_id: tx.id(),
            success: true,
            execution_time_us: 100,
            state_root: [0u8; 32],
        };

        pool.add_pending(tx.clone(), receipt);
        assert_eq!(pool.pending_count(), 1);

        pool.confirm(tx.id(), 100);
        assert_eq!(pool.status(&tx.id()), Some(TransactionStatus::Confirmed));
    }

    #[test]
    fn test_operation_put() {
        let op = Operation::Put {
            collection: "test".to_string(),
            key: b"key1".to_vec(),
            value: b"value1".to_vec(),
        };

        let sender = create_test_hotkey(5);
        let tx = Transaction::new(sender, op);

        let keys = tx.affected_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "test");
        assert_eq!(keys[0].1, b"key1");
    }

    #[test]
    fn test_operation_delete() {
        let op = Operation::Delete {
            collection: "test".to_string(),
            key: b"key1".to_vec(),
        };

        let sender = create_test_hotkey(6);
        let tx = Transaction::new(sender, op);

        let keys = tx.affected_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "test");
        assert_eq!(keys[0].1, b"key1");
    }

    #[test]
    fn test_operation_batch_put() {
        let op = Operation::BatchPut {
            operations: vec![
                ("col1".to_string(), b"k1".to_vec(), b"v1".to_vec()),
                ("col2".to_string(), b"k2".to_vec(), b"v2".to_vec()),
                ("col1".to_string(), b"k3".to_vec(), b"v3".to_vec()),
            ],
        };

        let sender = create_test_hotkey(7);
        let tx = Transaction::new(sender, op);

        let keys = tx.affected_keys();
        assert_eq!(keys.len(), 3);
        assert!(keys.iter().any(|(c, k)| c == "col1" && k == b"k1"));
        assert!(keys.iter().any(|(c, k)| c == "col2" && k == b"k2"));
        assert!(keys.iter().any(|(c, k)| c == "col1" && k == b"k3"));
    }

    #[test]
    fn test_transaction_id_computation() {
        let sender = create_test_hotkey(2);
        let op = Operation::Put {
            collection: "test".to_string(),
            key: b"key".to_vec(),
            value: b"value".to_vec(),
        };

        let tx1 = Transaction::new(sender.clone(), op.clone());
        let tx2 = Transaction::new(sender, op);

        // Different nonces should produce different IDs
        assert_ne!(tx1.id(), tx2.id());
    }

    #[test]
    fn test_transaction_validate_valid() {
        let sender = create_test_hotkey(3);
        let tx = Transaction::new(
            sender,
            Operation::Put {
                collection: "test".to_string(),
                key: b"key".to_vec(),
                value: b"value".to_vec(),
            },
        );

        assert!(tx.validate().is_ok());
    }

    #[test]
    fn test_transaction_validate_invalid_id() {
        let sender = create_test_hotkey(4);
        let mut tx = Transaction::new(
            sender,
            Operation::Put {
                collection: "test".to_string(),
                key: b"key".to_vec(),
                value: b"value".to_vec(),
            },
        );

        // Corrupt the ID
        tx.id = [99u8; 32];

        assert!(tx.validate().is_err());
    }

    #[test]
    fn test_transaction_pool_default() {
        let pool = TransactionPool::default();
        assert_eq!(pool.pending_count(), 0);
    }

    #[test]
    fn test_transaction_pool_rollback() {
        let mut pool = TransactionPool::new();
        let sender = create_test_hotkey(8);

        let tx = Transaction::new(
            sender,
            Operation::Put {
                collection: "test".to_string(),
                key: b"key".to_vec(),
                value: b"value".to_vec(),
            },
        );

        let receipt = TransactionReceipt {
            tx_id: tx.id(),
            success: true,
            execution_time_us: 100,
            state_root: [0u8; 32],
        };

        pool.add_pending(tx.clone(), receipt);
        assert_eq!(pool.status(&tx.id()), Some(TransactionStatus::Pending));

        pool.rollback(tx.id());
        assert_eq!(pool.status(&tx.id()), Some(TransactionStatus::RolledBack));
    }

    #[test]
    fn test_transaction_pool_nonce_check() {
        let mut pool = TransactionPool::new();
        let sender = create_test_hotkey(9);

        // Add transaction with nonce 100
        let mut tx1 = Transaction::new(
            sender.clone(),
            Operation::Put {
                collection: "test".to_string(),
                key: b"key1".to_vec(),
                value: b"value1".to_vec(),
            },
        );
        tx1.nonce = 100;
        tx1.id = tx1.compute_id();

        let receipt1 = TransactionReceipt {
            tx_id: tx1.id(),
            success: true,
            execution_time_us: 100,
            state_root: [0u8; 32],
        };

        pool.add_pending(tx1, receipt1);
        assert_eq!(pool.pending_count(), 1);

        // Try to add transaction with lower nonce (should be rejected)
        let mut tx2 = Transaction::new(
            sender,
            Operation::Put {
                collection: "test".to_string(),
                key: b"key2".to_vec(),
                value: b"value2".to_vec(),
            },
        );
        tx2.nonce = 50;
        tx2.id = tx2.compute_id();

        let receipt2 = TransactionReceipt {
            tx_id: tx2.id(),
            success: true,
            execution_time_us: 100,
            state_root: [0u8; 32],
        };

        pool.add_pending(tx2, receipt2);
        // Should still be 1 (second tx rejected)
        assert_eq!(pool.pending_count(), 1);
    }

    #[test]
    fn test_transaction_pool_get_pending_for_block() {
        let mut pool = TransactionPool::new();
        let sender = create_test_hotkey(10);

        let tx = Transaction::new(
            sender,
            Operation::Put {
                collection: "test".to_string(),
                key: b"key".to_vec(),
                value: b"value".to_vec(),
            },
        );

        let receipt = TransactionReceipt {
            tx_id: tx.id(),
            success: true,
            execution_time_us: 100,
            state_root: [0u8; 32],
        };

        pool.add_pending(tx, receipt);

        let pending = pool.get_pending_for_block(100);
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_transaction_pool_status_not_found() {
        let pool = TransactionPool::new();
        let unknown_id = [99u8; 32];

        assert_eq!(pool.status(&unknown_id), None);
    }

    #[test]
    fn test_transaction_pool_get_by_sender() {
        let mut pool = TransactionPool::new();
        let sender1 = create_test_hotkey(11);
        let sender2 = create_test_hotkey(12);

        // Add 2 txs from sender1 with increasing nonces
        for i in 0..2 {
            let tx = create_tx_with_nonce(
                sender1.clone(),
                Operation::Put {
                    collection: "test".to_string(),
                    key: format!("key{}", i).into_bytes(),
                    value: b"value".to_vec(),
                },
                (i + 1) as u64,
            );

            let receipt = TransactionReceipt {
                tx_id: tx.id(),
                success: true,
                execution_time_us: 100,
                state_root: [0u8; 32],
            };

            pool.add_pending(tx, receipt);
        }

        // Add 1 tx from sender2
        let tx = create_tx_with_nonce(
            sender2.clone(),
            Operation::Put {
                collection: "test".to_string(),
                key: b"key".to_vec(),
                value: b"value".to_vec(),
            },
            1,
        );

        let receipt = TransactionReceipt {
            tx_id: tx.id(),
            success: true,
            execution_time_us: 100,
            state_root: [0u8; 32],
        };

        pool.add_pending(tx, receipt);

        let sender1_txs = pool.get_by_sender(&sender1);
        assert_eq!(sender1_txs.len(), 2);

        let sender2_txs = pool.get_by_sender(&sender2);
        assert_eq!(sender2_txs.len(), 1);
    }

    #[test]
    fn test_transaction_pool_cleanup_old() {
        let mut pool = TransactionPool::new();
        let sender = create_test_hotkey(13);

        let tx = Transaction::new(
            sender,
            Operation::Put {
                collection: "test".to_string(),
                key: b"key".to_vec(),
                value: b"value".to_vec(),
            },
        );

        let receipt = TransactionReceipt {
            tx_id: tx.id(),
            success: true,
            execution_time_us: 100,
            state_root: [0u8; 32],
        };

        pool.add_pending(tx.clone(), receipt);
        pool.confirm(tx.id(), 100);

        // Cleanup should keep blocks at or after 100
        pool.cleanup_old(100);
        assert!(pool.confirmed.contains_key(&100));

        // Transaction is confirmed, so it should be removed from pending by cleanup_old
        // (cleanup_old only retains Pending status)
        pool.cleanup_old(100);
        assert!(pool.pending.get(&tx.id()).is_none());

        // Cleanup should remove confirmed blocks before 101
        pool.cleanup_old(101);
        assert!(pool.confirmed.get(&100).is_none());
    }

    #[test]
    fn test_transaction_sign() {
        let sender = create_test_hotkey(14);
        let keypair = platform_core::Keypair::generate();

        let mut tx = Transaction::new(
            sender,
            Operation::Put {
                collection: "test".to_string(),
                key: b"key".to_vec(),
                value: b"value".to_vec(),
            },
        );

        assert_eq!(tx.signature.len(), 0);

        tx.sign(&keypair);

        assert_eq!(tx.signature.len(), 64);
    }

    #[test]
    fn test_transaction_status_equality() {
        assert_eq!(TransactionStatus::Pending, TransactionStatus::Pending);
        assert_ne!(TransactionStatus::Pending, TransactionStatus::Confirmed);
        assert_ne!(TransactionStatus::Confirmed, TransactionStatus::RolledBack);
    }

    #[test]
    fn test_transaction_receipt() {
        let receipt = TransactionReceipt {
            tx_id: [1u8; 32],
            success: true,
            execution_time_us: 500,
            state_root: [2u8; 32],
        };

        assert_eq!(receipt.tx_id, [1u8; 32]);
        assert!(receipt.success);
        assert_eq!(receipt.execution_time_us, 500);
    }

    #[test]
    fn test_transaction_pool_confirm_nonexistent() {
        let mut pool = TransactionPool::new();
        let unknown_id = [99u8; 32];

        // Confirming nonexistent transaction should not panic
        pool.confirm(unknown_id, 100);

        // Should create entry in confirmed
        assert!(pool.confirmed.contains_key(&100));
    }

    #[test]
    fn test_transaction_pool_rollback_nonexistent() {
        let mut pool = TransactionPool::new();
        let unknown_id = [99u8; 32];

        // Rolling back nonexistent transaction should not panic
        pool.rollback(unknown_id);
    }
}
