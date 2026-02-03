//! Distributed Storage Layer for Platform Network
//!
//! This crate provides a decentralized storage layer using DHT (Distributed Hash Table)
//! combined with local sled database for persistence. It replaces centralized PostgreSQL
//! with a distributed, eventually-consistent storage system.
//!
//! # Features
//!
//! - **Local Storage**: Persistent key-value storage using sled
//! - **DHT Integration**: Kademlia-style distributed hash table for network-wide storage
//! - **Replication**: Configurable replication policies with quorum reads/writes
//! - **Conflict Resolution**: Last-write-wins or version-based conflict resolution
//! - **Typed Storage**: Specialized types for submissions, evaluations, and weights
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Application Layer                        │
//! │         (submissions, evaluations, weights, etc.)           │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                  DistributedStore Trait                     │
//! │              (get, put, delete, list_prefix)                │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!               ┌──────────────┴──────────────┐
//!               ▼                             ▼
//! ┌─────────────────────────┐   ┌─────────────────────────────┐
//! │      LocalStorage       │   │        DhtStorage           │
//! │    (sled backend)       │   │  (local + DHT network)      │
//! └─────────────────────────┘   └─────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ## Local-only mode
//!
//! ```ignore
//! use platform_distributed_storage::{LocalStorage, LocalStorageBuilder, DistributedStore, StorageKey, PutOptions, GetOptions};
//!
//! // Create local storage
//! let storage = LocalStorageBuilder::new("node-1")
//!     .path("/var/lib/platform/data")
//!     .build()?;
//!
//! // Store a value
//! let key = StorageKey::submission("challenge-1", "abc123");
//! storage.put(key.clone(), b"submission data".to_vec(), PutOptions::default()).await?;
//!
//! // Retrieve a value
//! let value = storage.get(&key, GetOptions::default()).await?;
//! ```
//!
//! ## DHT-backed mode
//!
//! ```ignore
//! use platform_distributed_storage::{DhtStorage, DhtStorageBuilder, LocalStorageBuilder, ReplicationConfig};
//!
//! // Create local storage first
//! let local = LocalStorageBuilder::new("node-1")
//!     .path("/var/lib/platform/data")
//!     .build()?;
//!
//! // Create DHT storage with custom network handler
//! let dht = DhtStorage::with_network(
//!     local,
//!     my_network_handler,
//!     ReplicationConfig::default(),
//! );
//!
//! // Add known peers
//! dht.add_node(DhtNode::new("peer-1", "192.168.1.10:8080"));
//! ```
//!
//! # Storage Keys
//!
//! Keys are organized by namespace for efficient querying:
//!
//! - `submissions:{challenge_id}:{hash}` - Miner submissions
//! - `evaluations:{challenge_id}:{submission_hash}:{validator}` - Evaluation results
//! - `weights:{challenge_id}:{epoch}` - Weight aggregations
//! - `challenges:{challenge_id}` - Challenge metadata

pub mod challenge_store;
pub mod dht;
pub mod error;
pub mod local;
pub mod query;
pub mod replication;
pub mod state_consensus;
pub mod store;
pub mod submission;
pub mod weights;

// Re-export main types for convenience
pub use dht::{
    DhtNetworkHandler, DhtNode, DhtStorage, DhtStorageBuilder, LocalOnlyHandler, RoutingTable,
};
pub use error::{StorageError, StorageResult};
pub use local::{LocalStorage, LocalStorageBuilder, ReplicationInfo};
pub use query::{
    block_index_key, block_range_end, block_range_start, parse_block_index_key, QueryBuilder,
    QueryCursor, QueryFilter, QueryResult,
};
pub use replication::{
    ConflictResolution, ConflictResolver, QuorumCalculator, ReplicationConfig, ReplicationManager,
    ReplicationPolicy, ReplicationState,
};
pub use store::{
    DistributedStore, DistributedStoreExt, GetOptions, ListResult, PutOptions, StorageKey,
    StorageStats, StoredValue, ValueMetadata,
};
pub use submission::{
    AggregatedEvaluations, EvaluationStatus, StoredEvaluation, StoredSubmission, SubmissionStatus,
};
pub use weights::{StoredWeights, ValidatorWeightVote, WeightAggregator, WeightHistory};

// Challenge-specific storage
pub use challenge_store::{
    ChallengeStorage, ChallengeStore, ChallengeStoreRegistry, MerkleNode, MerkleProof,
};

// State consensus protocol
pub use state_consensus::{
    ConsensusResult as StateConsensusResult, FraudProof, GlobalStateLinker, InclusionProof,
    StateRootConsensus, StateRootConsensusError, StateRootProposal, StateRootVote,
};

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_full_submission_workflow() {
        // Create local storage
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        // Create a submission
        let submission = StoredSubmission::new(
            "challenge-1",
            "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
            Some("def solve(task): return task.upper()".to_string()),
            serde_json::json!({"language": "python", "version": "3.10"}),
        );

        // Store the submission
        let key = StorageKey::submission(&submission.challenge_id, &submission.submission_hash);
        let bytes = submission.to_bytes().expect("serialization failed");

        storage
            .put(key.clone(), bytes, PutOptions::default())
            .await
            .expect("put failed");

        // Retrieve and verify
        let result = storage
            .get(&key, GetOptions::default())
            .await
            .expect("get failed");

        assert!(result.is_some());
        let stored = result.unwrap();
        let decoded = StoredSubmission::from_bytes(&stored.data).expect("deserialization failed");

        assert_eq!(decoded.challenge_id, "challenge-1");
        assert_eq!(
            decoded.miner_hotkey,
            "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
        );
    }

    #[tokio::test]
    async fn test_evaluation_storage() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        // Create an evaluation
        let eval = StoredEvaluation::new(
            "challenge-1",
            "submission-hash",
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            0.85,
            1500,
            serde_json::json!({"tasks_completed": 17, "total_tasks": 20}),
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        );

        let key = StorageKey::evaluation(
            &eval.challenge_id,
            &eval.submission_hash,
            &eval.validator_hotkey,
        );
        let bytes = eval.to_bytes().expect("serialization failed");

        storage
            .put(key.clone(), bytes, PutOptions::default())
            .await
            .expect("put failed");

        let result = storage
            .get(&key, GetOptions::default())
            .await
            .expect("get failed");

        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_weights_workflow() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        // Simulate weight aggregation
        let mut aggregator = WeightAggregator::new("challenge-1", 42);

        // Add validator votes
        aggregator.add_vote(ValidatorWeightVote::new(
            "validator-1",
            "challenge-1",
            42,
            vec![("miner-1".to_string(), 0.6), ("miner-2".to_string(), 0.4)],
            vec![],
            1_000_000_000,
        ));

        aggregator.add_vote(ValidatorWeightVote::new(
            "validator-2",
            "challenge-1",
            42,
            vec![("miner-1".to_string(), 0.8), ("miner-2".to_string(), 0.2)],
            vec![],
            2_000_000_000,
        ));

        // Aggregate
        let weights = aggregator.aggregate_stake_weighted();

        // Store
        let key = StorageKey::weights(&weights.challenge_id, weights.epoch);
        let bytes = weights.to_bytes().expect("serialization failed");

        storage
            .put(key.clone(), bytes, PutOptions::default())
            .await
            .expect("put failed");

        // Verify
        let result = storage
            .get(&key, GetOptions::default())
            .await
            .expect("get failed");

        assert!(result.is_some());
        let stored = result.unwrap();
        let decoded = StoredWeights::from_bytes(&stored.data).expect("deserialization failed");

        assert_eq!(decoded.epoch, 42);
        assert!(decoded.verify_hash());
    }

    #[tokio::test]
    async fn test_dht_local_only() {
        let local = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        let dht = DhtStorage::local_only(local);

        let key = StorageKey::new("test", "key1");
        let value = b"hello world".to_vec();

        dht.put(key.clone(), value.clone(), PutOptions::default())
            .await
            .expect("put failed");

        let result = dht
            .get(&key, GetOptions::default())
            .await
            .expect("get failed");

        assert!(result.is_some());
        assert_eq!(result.unwrap().data, value);
    }

    #[tokio::test]
    async fn test_list_by_namespace() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        // Add submissions for different challenges
        for i in 0..5 {
            let key = StorageKey::submission("challenge-1", &format!("hash-{}", i));
            storage
                .put(
                    key,
                    format!("data-{}", i).into_bytes(),
                    PutOptions::default(),
                )
                .await
                .expect("put failed");
        }

        for i in 0..3 {
            let key = StorageKey::submission("challenge-2", &format!("hash-{}", i));
            storage
                .put(
                    key,
                    format!("data-{}", i).into_bytes(),
                    PutOptions::default(),
                )
                .await
                .expect("put failed");
        }

        // List all submissions
        let result = storage
            .list_prefix("submissions", None, 100, None)
            .await
            .expect("list failed");

        assert_eq!(result.items.len(), 8);
    }

    #[tokio::test]
    async fn test_extension_methods() {
        let storage = LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage");

        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct TestData {
            name: String,
            value: i32,
        }

        let key = StorageKey::new("test", "json-key");
        let data = TestData {
            name: "test".to_string(),
            value: 42,
        };

        // Use extension methods
        storage
            .put_json(key.clone(), &data)
            .await
            .expect("put_json failed");

        let result: Option<TestData> = storage.get_json(&key).await.expect("get_json failed");
        assert_eq!(result, Some(data));
    }
}
