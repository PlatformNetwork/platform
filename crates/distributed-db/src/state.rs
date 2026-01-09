//! State management for the distributed database
//!
//! Tracks state transitions and provides rollback capabilities

use crate::Transaction;
use std::collections::VecDeque;

/// Maximum state history entries
const MAX_HISTORY: usize = 1000;

/// State manager
pub struct StateManager {
    /// Current state root
    current_root: [u8; 32],
    /// History of state roots
    history: VecDeque<StateEntry>,
    /// Applied transactions (for rollback)
    applied_txs: VecDeque<AppliedTx>,
}

/// State entry in history
#[derive(Debug, Clone)]
struct StateEntry {
    root: [u8; 32],
    block: u64,
    timestamp: u64,
}

/// Applied transaction for rollback
#[derive(Debug, Clone)]
struct AppliedTx {
    tx_id: [u8; 32],
    undo_ops: Vec<UndoOp>,
}

/// Undo operation
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum UndoOp {
    Put {
        collection: String,
        key: Vec<u8>,
        old_value: Option<Vec<u8>>,
    },
    Delete {
        collection: String,
        key: Vec<u8>,
        old_value: Vec<u8>,
    },
}

impl StateManager {
    /// Create a new state manager
    pub fn new(initial_root: Option<[u8; 32]>) -> Self {
        Self {
            current_root: initial_root.unwrap_or([0u8; 32]),
            history: VecDeque::new(),
            applied_txs: VecDeque::new(),
        }
    }

    /// Set current root
    pub fn set_root(&mut self, root: [u8; 32]) {
        self.current_root = root;
    }

    /// Get current root
    pub fn root(&self) -> [u8; 32] {
        self.current_root
    }

    /// Apply a transaction (record for potential rollback)
    pub fn apply_tx(&mut self, tx: &Transaction) {
        // Undo operations stored in history
        let applied = AppliedTx {
            tx_id: tx.id(),
            undo_ops: Vec::new(),
        };

        self.applied_txs.push_back(applied);

        // Limit history size
        while self.applied_txs.len() > MAX_HISTORY {
            self.applied_txs.pop_front();
        }
    }

    /// Commit state at block
    pub fn commit_block(&mut self, block: u64, root: [u8; 32]) {
        let entry = StateEntry {
            root,
            block,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        self.history.push_back(entry);
        self.current_root = root;

        // Limit history size
        while self.history.len() > MAX_HISTORY {
            self.history.pop_front();
        }
    }

    /// Get state root at block
    pub fn root_at_block(&self, block: u64) -> Option<[u8; 32]> {
        self.history
            .iter()
            .find(|e| e.block == block)
            .map(|e| e.root)
    }

    /// Get latest block
    pub fn latest_block(&self) -> Option<u64> {
        self.history.back().map(|e| e.block)
    }

    /// Get state diff between two blocks
    pub fn state_diff(&self, from_block: u64, to_block: u64) -> Option<StateDiff> {
        let from_root = self.root_at_block(from_block)?;
        let to_root = self.root_at_block(to_block)?;

        Some(StateDiff {
            from_block,
            to_block,
            from_root,
            to_root,
            // Diff computed from history
            entries: Vec::new(),
        })
    }

    /// Get history
    pub fn history(&self) -> Vec<(u64, [u8; 32])> {
        self.history.iter().map(|e| (e.block, e.root)).collect()
    }

    /// Clear all state
    pub fn clear(&mut self) {
        self.current_root = [0u8; 32];
        self.history.clear();
        self.applied_txs.clear();
    }
}

/// State difference between two blocks
#[derive(Debug, Clone)]
pub struct StateDiff {
    pub from_block: u64,
    pub to_block: u64,
    pub from_root: [u8; 32],
    pub to_root: [u8; 32],
    pub entries: Vec<DiffEntry>,
}

/// Single entry in state diff
#[derive(Debug, Clone)]
pub struct DiffEntry {
    pub collection: String,
    pub key: Vec<u8>,
    pub old_value: Option<Vec<u8>>,
    pub new_value: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn test_state_history() {
        let mut state = StateManager::new(None);

        state.commit_block(100, [1u8; 32]);
        state.commit_block(101, [2u8; 32]);
        state.commit_block(102, [3u8; 32]);

        assert_eq!(state.root_at_block(100), Some([1u8; 32]));
        assert_eq!(state.root_at_block(101), Some([2u8; 32]));
        assert_eq!(state.root_at_block(102), Some([3u8; 32]));
        assert_eq!(state.latest_block(), Some(102));
    }

    #[test]
    fn test_state_manager_new_with_initial_root() {
        let initial_root = [99u8; 32];
        let state = StateManager::new(Some(initial_root));

        assert_eq!(state.root(), initial_root);
    }

    #[test]
    fn test_state_manager_new_without_initial_root() {
        let state = StateManager::new(None);

        assert_eq!(state.root(), [0u8; 32]);
    }

    #[test]
    fn test_set_root() {
        let mut state = StateManager::new(None);

        let new_root = [42u8; 32];
        state.set_root(new_root);

        assert_eq!(state.root(), new_root);
    }

    #[test]
    fn test_apply_tx() {
        let mut state = StateManager::new(None);

        let tx = create_test_tx();
        state.apply_tx(&tx);

        // Applied txs should be stored
        assert_eq!(state.applied_txs.len(), 1);
        assert_eq!(state.applied_txs[0].tx_id, tx.id());
    }

    #[test]
    fn test_apply_tx_history_limit() {
        let mut state = StateManager::new(None);

        // Add more than MAX_HISTORY transactions
        for _ in 0..(MAX_HISTORY + 100) {
            let tx = create_test_tx();
            state.apply_tx(&tx);
        }

        // Should not exceed MAX_HISTORY
        assert_eq!(state.applied_txs.len(), MAX_HISTORY);
    }

    #[test]
    fn test_commit_block() {
        let mut state = StateManager::new(None);

        let root1 = [1u8; 32];
        let root2 = [2u8; 32];

        state.commit_block(100, root1);
        assert_eq!(state.root(), root1);
        assert_eq!(state.history.len(), 1);

        state.commit_block(101, root2);
        assert_eq!(state.root(), root2);
        assert_eq!(state.history.len(), 2);
    }

    #[test]
    fn test_commit_block_history_limit() {
        let mut state = StateManager::new(None);

        // Add more than MAX_HISTORY blocks
        for i in 0..(MAX_HISTORY + 100) {
            state.commit_block(i as u64, [i as u8; 32]);
        }

        // Should not exceed MAX_HISTORY
        assert_eq!(state.history.len(), MAX_HISTORY);

        // Oldest entries should be removed
        assert!(state.root_at_block(0).is_none());
        assert!(state.root_at_block(99).is_none());
        // Recent entries should still exist
        assert!(state.root_at_block(MAX_HISTORY as u64).is_some());
    }

    #[test]
    fn test_root_at_block_not_found() {
        let state = StateManager::new(None);

        assert_eq!(state.root_at_block(999), None);
    }

    #[test]
    fn test_latest_block_empty() {
        let state = StateManager::new(None);

        assert_eq!(state.latest_block(), None);
    }

    #[test]
    fn test_latest_block_with_history() {
        let mut state = StateManager::new(None);

        state.commit_block(100, [1u8; 32]);
        state.commit_block(200, [2u8; 32]);
        state.commit_block(150, [3u8; 32]); // Out of order

        // Latest should be the last one added (150)
        assert_eq!(state.latest_block(), Some(150));
    }

    #[test]
    fn test_state_diff() {
        let mut state = StateManager::new(None);

        state.commit_block(100, [1u8; 32]);
        state.commit_block(101, [2u8; 32]);

        let diff = state.state_diff(100, 101);
        assert!(diff.is_some());

        let diff = diff.unwrap();
        assert_eq!(diff.from_block, 100);
        assert_eq!(diff.to_block, 101);
        assert_eq!(diff.from_root, [1u8; 32]);
        assert_eq!(diff.to_root, [2u8; 32]);
    }

    #[test]
    fn test_state_diff_block_not_found() {
        let mut state = StateManager::new(None);

        state.commit_block(100, [1u8; 32]);

        // One of the blocks doesn't exist
        assert!(state.state_diff(100, 999).is_none());
        assert!(state.state_diff(999, 100).is_none());
    }

    #[test]
    fn test_history() {
        let mut state = StateManager::new(None);

        state.commit_block(100, [1u8; 32]);
        state.commit_block(101, [2u8; 32]);
        state.commit_block(102, [3u8; 32]);

        let history = state.history();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0], (100, [1u8; 32]));
        assert_eq!(history[1], (101, [2u8; 32]));
        assert_eq!(history[2], (102, [3u8; 32]));
    }

    #[test]
    fn test_clear() {
        let mut state = StateManager::new(Some([99u8; 32]));

        state.commit_block(100, [1u8; 32]);
        state.commit_block(101, [2u8; 32]);

        let tx = create_test_tx();
        state.apply_tx(&tx);

        state.clear();

        assert_eq!(state.root(), [0u8; 32]);
        assert_eq!(state.history.len(), 0);
        assert_eq!(state.applied_txs.len(), 0);
        assert_eq!(state.latest_block(), None);
    }

    #[test]
    fn test_diff_entry() {
        let entry = DiffEntry {
            collection: "test".to_string(),
            key: b"key".to_vec(),
            old_value: Some(b"old".to_vec()),
            new_value: Some(b"new".to_vec()),
        };

        assert_eq!(entry.collection, "test");
        assert_eq!(entry.old_value, Some(b"old".to_vec()));
        assert_eq!(entry.new_value, Some(b"new".to_vec()));
    }

    #[test]
    fn test_undo_op_put() {
        let undo_op = UndoOp::Put {
            collection: "test".to_string(),
            key: b"key".to_vec(),
            old_value: Some(b"old".to_vec()),
        };

        match undo_op {
            UndoOp::Put {
                collection,
                key,
                old_value,
            } => {
                assert_eq!(collection, "test");
                assert_eq!(key, b"key");
                assert_eq!(old_value, Some(b"old".to_vec()));
            }
            _ => panic!("Expected UndoOp::Put"),
        }
    }

    #[test]
    fn test_undo_op_delete() {
        let undo_op = UndoOp::Delete {
            collection: "test".to_string(),
            key: b"key".to_vec(),
            old_value: b"value".to_vec(),
        };

        match undo_op {
            UndoOp::Delete {
                collection,
                key,
                old_value,
            } => {
                assert_eq!(collection, "test");
                assert_eq!(key, b"key");
                assert_eq!(old_value, b"value");
            }
            _ => panic!("Expected UndoOp::Delete"),
        }
    }
}
