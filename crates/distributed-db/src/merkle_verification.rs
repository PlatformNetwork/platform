//! Merkle Proof Verification for State Sync
//!
//! This module provides cryptographic verification of state sync data using
//! Merkle trees. Each entry received during sync must have a valid proof
//! that connects it to the announced state root.
//!
//! # Security
//! - Prevents malicious peers from injecting corrupted data
//! - Verifies each entry belongs to the claimed state root
//! - Detects tampering during transmission

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Merkle node hash
pub type MerkleHash = [u8; 32];

/// Direction in merkle path
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofDirection {
    Left,
    Right,
}

/// Single element in a merkle proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofElement {
    pub hash: MerkleHash,
    pub direction: ProofDirection,
}

/// Merkle proof for a single entry (used in state sync verification)
/// Named differently from merkle::MerkleProof to avoid conflicts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMerkleProof {
    /// Leaf hash (hash of the entry)
    pub leaf_hash: MerkleHash,
    /// Path from leaf to root
    pub path: Vec<ProofElement>,
}

/// Entry with merkle proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedEntry {
    pub collection: String,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub proof: SyncMerkleProof,
}

/// Result of merkle verification
#[derive(Debug, Clone)]
pub enum VerificationResult {
    /// Proof is valid
    Valid,
    /// Proof is invalid
    Invalid { reason: String },
    /// Entry hash doesn't match leaf
    LeafMismatch {
        expected: MerkleHash,
        got: MerkleHash,
    },
    /// Computed root doesn't match expected
    RootMismatch {
        expected: MerkleHash,
        computed: MerkleHash,
    },
}

impl VerificationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, VerificationResult::Valid)
    }
}

/// Hash a single entry (collection + key + value)
pub fn hash_entry(collection: &str, key: &[u8], value: &[u8]) -> MerkleHash {
    let mut hasher = Sha256::new();
    hasher.update(collection.as_bytes());
    hasher.update(b":");
    hasher.update(key);
    hasher.update(b":");
    hasher.update(value);
    hasher.finalize().into()
}

/// Hash two nodes together
pub fn hash_nodes(left: &MerkleHash, right: &MerkleHash) -> MerkleHash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Verify a merkle proof against a state root
pub fn verify_proof(entry: &VerifiedEntry, expected_root: &MerkleHash) -> VerificationResult {
    // 1. Compute leaf hash
    let computed_leaf = hash_entry(&entry.collection, &entry.key, &entry.value);

    // 2. Verify leaf hash matches
    if computed_leaf != entry.proof.leaf_hash {
        return VerificationResult::LeafMismatch {
            expected: entry.proof.leaf_hash,
            got: computed_leaf,
        };
    }

    // 3. Traverse path to compute root
    let mut current_hash = computed_leaf;

    for element in &entry.proof.path {
        current_hash = match element.direction {
            ProofDirection::Left => hash_nodes(&element.hash, &current_hash),
            ProofDirection::Right => hash_nodes(&current_hash, &element.hash),
        };
    }

    // 4. Verify computed root matches expected
    if current_hash != *expected_root {
        return VerificationResult::RootMismatch {
            expected: *expected_root,
            computed: current_hash,
        };
    }

    VerificationResult::Valid
}

/// Build a merkle tree from entries and return root + proofs
pub struct MerkleTreeBuilder {
    /// Entries by full key (collection:key)
    entries: BTreeMap<Vec<u8>, (String, Vec<u8>, Vec<u8>)>,
}

impl MerkleTreeBuilder {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Add an entry
    pub fn add_entry(&mut self, collection: &str, key: &[u8], value: &[u8]) {
        let full_key = format!("{}:{}", collection, hex::encode(key)).into_bytes();
        self.entries.insert(
            full_key,
            (collection.to_string(), key.to_vec(), value.to_vec()),
        );
    }

    /// Build tree and get root
    pub fn build(&self) -> (MerkleHash, Vec<VerifiedEntry>) {
        if self.entries.is_empty() {
            return ([0u8; 32], vec![]);
        }

        // Hash all leaves
        let leaves: Vec<(Vec<u8>, MerkleHash)> = self
            .entries
            .iter()
            .map(|(full_key, (collection, key, value))| {
                (full_key.clone(), hash_entry(collection, key, value))
            })
            .collect();

        // Build tree layer by layer, tracking paths
        let mut paths: Vec<Vec<ProofElement>> = vec![vec![]; leaves.len()];

        let mut current_level: Vec<MerkleHash> = leaves.iter().map(|(_, h)| *h).collect();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            let mut new_paths = paths.clone();

            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    left // Odd number: duplicate last node
                };

                let parent = hash_nodes(&left, &right);
                next_level.push(parent);

                // Update paths for affected leaves
                let left_indices: Vec<usize> = (0..leaves.len())
                    .filter(|&j| {
                        let level_index = j / (1 << paths[j].len());
                        level_index / 2 == i / 2 && level_index.is_multiple_of(2)
                    })
                    .collect();

                let right_indices: Vec<usize> = (0..leaves.len())
                    .filter(|&j| {
                        let level_index = j / (1 << paths[j].len());
                        level_index / 2 == i / 2 && !level_index.is_multiple_of(2)
                    })
                    .collect();

                // Add sibling to path
                for &idx in &left_indices {
                    if i + 1 < current_level.len() {
                        new_paths[idx].push(ProofElement {
                            hash: right,
                            direction: ProofDirection::Right,
                        });
                    }
                }

                for &idx in &right_indices {
                    new_paths[idx].push(ProofElement {
                        hash: left,
                        direction: ProofDirection::Left,
                    });
                }
            }

            paths = new_paths;
            current_level = next_level;
        }

        let root = current_level[0];

        // Build verified entries
        let verified_entries: Vec<VerifiedEntry> = self
            .entries
            .iter()
            .enumerate()
            .map(|(i, (_, (collection, key, value)))| VerifiedEntry {
                collection: collection.clone(),
                key: key.clone(),
                value: value.clone(),
                proof: SyncMerkleProof {
                    leaf_hash: hash_entry(collection, key, value),
                    path: paths[i].clone(),
                },
            })
            .collect();

        (root, verified_entries)
    }
}

impl Default for MerkleTreeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Verifier for incoming state sync data
pub struct StateSyncVerifier {
    expected_root: MerkleHash,
    verified_count: usize,
    rejected_count: usize,
}

impl StateSyncVerifier {
    pub fn new(expected_root: MerkleHash) -> Self {
        Self {
            expected_root,
            verified_count: 0,
            rejected_count: 0,
        }
    }

    /// Verify a single entry
    pub fn verify(&mut self, entry: &VerifiedEntry) -> VerificationResult {
        let result = verify_proof(entry, &self.expected_root);

        match &result {
            VerificationResult::Valid => self.verified_count += 1,
            _ => self.rejected_count += 1,
        }

        result
    }

    /// Get stats
    pub fn stats(&self) -> (usize, usize) {
        (self.verified_count, self.rejected_count)
    }

    /// Check if any entries were rejected
    pub fn has_rejections(&self) -> bool {
        self.rejected_count > 0
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_entry() {
        let hash1 = hash_entry("challenges", b"key1", b"value1");
        let hash2 = hash_entry("challenges", b"key1", b"value1");
        let hash3 = hash_entry("challenges", b"key1", b"value2");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_nodes() {
        let left = [1u8; 32];
        let right = [2u8; 32];

        let parent1 = hash_nodes(&left, &right);
        let parent2 = hash_nodes(&left, &right);
        let parent3 = hash_nodes(&right, &left); // Different order

        assert_eq!(parent1, parent2);
        assert_ne!(parent1, parent3);
    }

    #[test]
    fn test_merkle_tree_single_entry() {
        let mut builder = MerkleTreeBuilder::new();
        builder.add_entry("challenges", b"test", b"data");

        let (root, entries) = builder.build();

        assert_eq!(entries.len(), 1);
        assert_ne!(root, [0u8; 32]);

        // Verify the entry
        let result = verify_proof(&entries[0], &root);
        assert!(result.is_valid());
    }

    #[test]
    fn test_merkle_tree_multiple_entries() {
        let mut builder = MerkleTreeBuilder::new();
        builder.add_entry("challenges", b"key1", b"value1");
        builder.add_entry("challenges", b"key2", b"value2");
        builder.add_entry("agents", b"agent1", b"data1");
        builder.add_entry("weights", b"w1", b"100");

        let (root, entries) = builder.build();

        assert_eq!(entries.len(), 4);

        // All entries should verify
        for entry in &entries {
            let result = verify_proof(entry, &root);
            assert!(
                result.is_valid(),
                "Entry {:?} failed verification: {:?}",
                entry.key,
                result
            );
        }
    }

    #[test]
    fn test_tampered_entry_rejected() {
        let mut builder = MerkleTreeBuilder::new();
        builder.add_entry("challenges", b"key1", b"value1");
        builder.add_entry("challenges", b"key2", b"value2");

        let (root, mut entries) = builder.build();

        // Tamper with an entry
        entries[0].value = b"TAMPERED".to_vec();

        // Should fail verification
        let result = verify_proof(&entries[0], &root);
        assert!(!result.is_valid());
        assert!(matches!(result, VerificationResult::LeafMismatch { .. }));
    }

    #[test]
    fn test_wrong_root_rejected() {
        let mut builder = MerkleTreeBuilder::new();
        builder.add_entry("challenges", b"key1", b"value1");

        let (_, entries) = builder.build();

        // Use wrong root
        let wrong_root = [99u8; 32];

        let result = verify_proof(&entries[0], &wrong_root);
        assert!(!result.is_valid());
        assert!(matches!(result, VerificationResult::RootMismatch { .. }));
    }

    #[test]
    fn test_state_sync_verifier() {
        let mut builder = MerkleTreeBuilder::new();
        builder.add_entry("challenges", b"k1", b"v1");
        builder.add_entry("challenges", b"k2", b"v2");

        let (root, entries) = builder.build();

        let mut verifier = StateSyncVerifier::new(root);

        // Verify valid entries
        for entry in &entries {
            let result = verifier.verify(entry);
            assert!(result.is_valid());
        }

        assert_eq!(verifier.stats(), (2, 0));
        assert!(!verifier.has_rejections());

        // Try tampered entry
        let mut tampered = entries[0].clone();
        tampered.value = b"bad".to_vec();
        let result = verifier.verify(&tampered);
        assert!(!result.is_valid());

        assert_eq!(verifier.stats(), (2, 1));
        assert!(verifier.has_rejections());
    }

    #[test]
    fn test_empty_tree() {
        let builder = MerkleTreeBuilder::new();
        let (root, entries) = builder.build();

        assert_eq!(root, [0u8; 32]);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_verification_result_is_valid() {
        assert!(VerificationResult::Valid.is_valid());
        assert!(!VerificationResult::Invalid {
            reason: "test".to_string()
        }
        .is_valid());
        assert!(!VerificationResult::LeafMismatch {
            expected: [1u8; 32],
            got: [2u8; 32]
        }
        .is_valid());
        assert!(!VerificationResult::RootMismatch {
            expected: [1u8; 32],
            computed: [2u8; 32]
        }
        .is_valid());
    }
}
