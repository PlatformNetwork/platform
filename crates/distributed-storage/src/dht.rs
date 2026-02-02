//! DHT integration for distributed queries
//!
//! This module provides a DHT-backed storage implementation that uses
//! a Kademlia-style distributed hash table for finding and storing data
//! across the network.
//!
//! **Note:** This is a stub implementation that will be connected to
//! the p2p-consensus crate for actual network operations.

use async_trait::async_trait;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, trace, warn};

use crate::error::{StorageError, StorageResult};
use crate::local::LocalStorage;
use crate::replication::ReplicationConfig;
use crate::store::{
    DistributedStore, GetOptions, ListResult, PutOptions, StorageKey, StorageStats, StoredValue,
    ValueMetadata,
};

/// DHT node information
#[derive(Clone, Debug)]
pub struct DhtNode {
    /// Node ID (typically derived from the hotkey)
    pub id: String,
    /// Network address
    pub address: String,
    /// Node's distance from a given key (for routing)
    pub distance: Option<[u8; 32]>,
    /// Last seen timestamp
    pub last_seen: i64,
    /// Whether the node is currently reachable
    pub is_online: bool,
}

impl DhtNode {
    /// Create a new DHT node
    pub fn new(id: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            address: address.into(),
            distance: None,
            last_seen: chrono::Utc::now().timestamp_millis(),
            is_online: true,
        }
    }
}

/// Calculate XOR distance between two 32-byte arrays
///
/// In Kademlia, the distance between two identifiers is the XOR of those identifiers,
/// interpreted as an unsigned integer. This is a valid metric:
/// - d(x, x) = 0
/// - d(x, y) = d(y, x)
/// - d(x, z) <= d(x, y) + d(y, z)
fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Compare two XOR distances using lexicographic ordering
///
/// Since XOR distances are represented as 256-bit numbers (32 bytes),
/// lexicographic comparison provides correct numerical ordering.
fn distance_cmp(d1: &[u8; 32], d2: &[u8; 32]) -> std::cmp::Ordering {
    d1.cmp(d2)
}

/// Hash a node ID to a 32-byte array using SHA256
///
/// This converts the string node ID to a fixed-size identifier
/// suitable for XOR distance calculations.
fn hash_node_id(node_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(node_id.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// DHT routing table
#[derive(Debug, Default)]
pub struct RoutingTable {
    /// Known nodes indexed by ID
    nodes: HashMap<String, DhtNode>,
    /// Nodes organized by k-bucket (distance prefix)
    buckets: Vec<HashSet<String>>,
}

impl RoutingTable {
    /// Create a new routing table
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            // 256 k-buckets for 256-bit key space
            buckets: vec![HashSet::new(); 256],
        }
    }

    /// Add or update a node
    pub fn add_node(&mut self, node: DhtNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    /// Remove a node
    pub fn remove_node(&mut self, node_id: &str) {
        self.nodes.remove(node_id);
        for bucket in &mut self.buckets {
            bucket.remove(node_id);
        }
    }

    /// Get a node by ID
    pub fn get_node(&self, node_id: &str) -> Option<&DhtNode> {
        self.nodes.get(node_id)
    }

    /// Get all known nodes
    pub fn all_nodes(&self) -> impl Iterator<Item = &DhtNode> {
        self.nodes.values()
    }

    /// Get the number of known nodes
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Find the k closest nodes to a key using XOR distance metric
    ///
    /// This implements the core Kademlia algorithm for finding nodes closest
    /// to a given key. Nodes are sorted by their XOR distance to the key hash,
    /// and the k closest are returned.
    pub fn find_closest(&self, key_hash: &[u8; 32], k: usize) -> Vec<&DhtNode> {
        if self.nodes.is_empty() {
            return Vec::new();
        }

        // Calculate distances for all nodes and sort
        let mut nodes_with_distance: Vec<(&DhtNode, [u8; 32])> = self
            .nodes
            .values()
            .map(|node| {
                let node_hash = hash_node_id(&node.id);
                let distance = xor_distance(&node_hash, key_hash);
                (node, distance)
            })
            .collect();

        // Sort by XOR distance (ascending - closest first)
        nodes_with_distance.sort_by(|(_, d1), (_, d2)| distance_cmp(d1, d2));

        // Return the k closest nodes
        nodes_with_distance
            .into_iter()
            .take(k)
            .map(|(node, _)| node)
            .collect()
    }

    /// Mark a node as offline
    pub fn mark_offline(&mut self, node_id: &str) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.is_online = false;
        }
    }

    /// Mark a node as online
    pub fn mark_online(&mut self, node_id: &str) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.is_online = true;
            node.last_seen = chrono::Utc::now().timestamp_millis();
        }
    }

    /// Get online nodes
    pub fn online_nodes(&self) -> impl Iterator<Item = &DhtNode> {
        self.nodes.values().filter(|n| n.is_online)
    }
}

/// Handler for DHT network operations
///
/// This trait will be implemented by the p2p-consensus layer to provide
/// actual network communication.
#[async_trait]
pub trait DhtNetworkHandler: Send + Sync {
    /// Find nodes close to a key
    async fn find_nodes(&self, key_hash: &[u8; 32]) -> StorageResult<Vec<DhtNode>>;

    /// Get a value from a remote node
    async fn get_value(
        &self,
        node: &DhtNode,
        key: &StorageKey,
    ) -> StorageResult<Option<StoredValue>>;

    /// Put a value to a remote node
    async fn put_value(
        &self,
        node: &DhtNode,
        key: &StorageKey,
        value: &StoredValue,
    ) -> StorageResult<()>;

    /// Delete a value from a remote node
    async fn delete_value(&self, node: &DhtNode, key: &StorageKey) -> StorageResult<bool>;

    /// Ping a node to check if it's alive
    async fn ping(&self, node: &DhtNode) -> StorageResult<bool>;
}

/// No-op network handler for local-only mode
pub struct LocalOnlyHandler;

#[async_trait]
impl DhtNetworkHandler for LocalOnlyHandler {
    async fn find_nodes(&self, _key_hash: &[u8; 32]) -> StorageResult<Vec<DhtNode>> {
        Ok(Vec::new())
    }

    async fn get_value(
        &self,
        _node: &DhtNode,
        _key: &StorageKey,
    ) -> StorageResult<Option<StoredValue>> {
        Ok(None)
    }

    async fn put_value(
        &self,
        _node: &DhtNode,
        _key: &StorageKey,
        _value: &StoredValue,
    ) -> StorageResult<()> {
        Ok(())
    }

    async fn delete_value(&self, _node: &DhtNode, _key: &StorageKey) -> StorageResult<bool> {
        Ok(false)
    }

    async fn ping(&self, _node: &DhtNode) -> StorageResult<bool> {
        Ok(false)
    }
}

/// DHT-backed distributed storage
///
/// This combines local storage with DHT operations for distributed
/// key-value storage across the network.
pub struct DhtStorage<H: DhtNetworkHandler = LocalOnlyHandler> {
    /// Local storage backend
    local: Arc<LocalStorage>,
    /// DHT routing table
    routing_table: RwLock<RoutingTable>,
    /// Network handler for DHT operations
    network: Arc<H>,
    /// Replication configuration
    replication_config: ReplicationConfig,
    /// Whether DHT is enabled (false = local-only mode)
    dht_enabled: bool,
}

impl DhtStorage<LocalOnlyHandler> {
    /// Create a new DHT storage in local-only mode
    pub fn local_only(local: LocalStorage) -> Self {
        Self {
            local: Arc::new(local),
            routing_table: RwLock::new(RoutingTable::new()),
            network: Arc::new(LocalOnlyHandler),
            replication_config: ReplicationConfig::default(),
            dht_enabled: false,
        }
    }
}

impl<H: DhtNetworkHandler> DhtStorage<H> {
    /// Create a new DHT storage with a custom network handler
    pub fn with_network(
        local: LocalStorage,
        network: H,
        replication_config: ReplicationConfig,
    ) -> Self {
        Self {
            local: Arc::new(local),
            routing_table: RwLock::new(RoutingTable::new()),
            network: Arc::new(network),
            replication_config,
            dht_enabled: true,
        }
    }

    /// Get the local storage
    pub fn local(&self) -> &LocalStorage {
        &self.local
    }

    /// Check if DHT mode is enabled
    pub fn is_dht_enabled(&self) -> bool {
        self.dht_enabled
    }

    /// Add a node to the routing table
    pub fn add_node(&self, node: DhtNode) {
        self.routing_table.write().add_node(node);
    }

    /// Remove a node from the routing table
    pub fn remove_node(&self, node_id: &str) {
        self.routing_table.write().remove_node(node_id);
    }

    /// Get the number of known nodes
    pub fn node_count(&self) -> usize {
        self.routing_table.read().node_count()
    }

    /// Get nodes closest to a key
    fn find_closest_nodes(&self, key: &StorageKey, count: usize) -> Vec<DhtNode> {
        let key_hash = key.hash();
        self.routing_table
            .read()
            .find_closest(&key_hash, count)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Perform a quorum read across multiple nodes
    async fn quorum_read(
        &self,
        key: &StorageKey,
        quorum_size: usize,
    ) -> StorageResult<Option<StoredValue>> {
        // First check local
        let local_result = self
            .local
            .get(
                key,
                GetOptions {
                    local_only: true,
                    ..Default::default()
                },
            )
            .await?;

        if !self.dht_enabled {
            return Ok(local_result);
        }

        // Find closest nodes
        let nodes = self.find_closest_nodes(key, self.replication_config.replication_factor);

        if nodes.is_empty() {
            return Ok(local_result);
        }

        // Query remote nodes
        let mut values: Vec<StoredValue> = Vec::new();
        if let Some(v) = local_result {
            values.push(v);
        }

        for node in &nodes {
            match self.network.get_value(node, key).await {
                Ok(Some(v)) => values.push(v),
                Ok(None) => {}
                Err(e) => {
                    warn!("Failed to get value from node {}: {}", node.id, e);
                    self.routing_table.write().mark_offline(&node.id);
                }
            }

            if values.len() >= quorum_size {
                break;
            }
        }

        if values.is_empty() {
            return Ok(None);
        }

        // Return the newest value
        let newest = values.into_iter().max_by(|a, b| {
            if a.is_newer_than(b) {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Less
            }
        });

        Ok(newest)
    }

    /// Perform a quorum write across multiple nodes
    async fn quorum_write(
        &self,
        key: &StorageKey,
        value: &StoredValue,
        quorum_size: usize,
    ) -> StorageResult<usize> {
        if !self.dht_enabled {
            return Ok(1); // Just local
        }

        // Find closest nodes
        let nodes = self.find_closest_nodes(key, self.replication_config.replication_factor);

        let mut success_count = 1; // Local write already done

        for node in &nodes {
            match self.network.put_value(node, key, value).await {
                Ok(()) => {
                    success_count += 1;
                    self.local.mark_replicated(key, &node.id).await?;
                }
                Err(e) => {
                    warn!("Failed to put value to node {}: {}", node.id, e);
                    self.routing_table.write().mark_offline(&node.id);
                }
            }
        }

        if success_count >= quorum_size {
            Ok(success_count)
        } else {
            Err(StorageError::QuorumNotReached {
                required: quorum_size,
                received: success_count,
            })
        }
    }
}

#[async_trait]
impl<H: DhtNetworkHandler + 'static> DistributedStore for DhtStorage<H> {
    async fn get(
        &self,
        key: &StorageKey,
        options: GetOptions,
    ) -> StorageResult<Option<StoredValue>> {
        trace!(
            "DhtStorage::get key={} local_only={}",
            key,
            options.local_only
        );

        if options.local_only || !self.dht_enabled {
            return self.local.get(key, options).await;
        }

        if options.quorum_read {
            let quorum_size = options
                .quorum_size
                .unwrap_or(self.replication_config.read_quorum);
            self.quorum_read(key, quorum_size).await
        } else {
            // Try local first, then DHT if not found
            let local_result = self.local.get(key, GetOptions::default()).await?;
            if local_result.is_some() {
                return Ok(local_result);
            }

            // Not found locally, try DHT
            self.quorum_read(key, 1).await
        }
    }

    async fn put(
        &self,
        key: StorageKey,
        value: Vec<u8>,
        options: PutOptions,
    ) -> StorageResult<ValueMetadata> {
        trace!(
            "DhtStorage::put key={} local_only={} quorum={}",
            key,
            options.local_only,
            options.quorum_write
        );

        // Always write locally first
        let local_options = PutOptions {
            local_only: true,
            ..options.clone()
        };
        let metadata = self
            .local
            .put(key.clone(), value.clone(), local_options)
            .await?;

        if options.local_only || !self.dht_enabled {
            return Ok(metadata);
        }

        // Create stored value for replication
        let stored_value = StoredValue {
            data: value,
            metadata: metadata.clone(),
        };

        if options.quorum_write {
            let quorum_size = options
                .quorum_size
                .unwrap_or(self.replication_config.write_quorum);

            let replicated = self.quorum_write(&key, &stored_value, quorum_size).await?;
            debug!(
                "DhtStorage::put key={} replicated to {} nodes",
                key, replicated
            );
        } else {
            // Background replication (fire and forget)
            let _replicated = self.quorum_write(&key, &stored_value, 1).await;
        }

        Ok(metadata)
    }

    async fn delete(&self, key: &StorageKey) -> StorageResult<bool> {
        trace!("DhtStorage::delete key={}", key);

        // Delete locally
        let deleted = self.local.delete(key).await?;

        if !self.dht_enabled {
            return Ok(deleted);
        }

        // Delete from remote nodes
        let nodes = self.find_closest_nodes(key, self.replication_config.replication_factor);

        for node in &nodes {
            match self.network.delete_value(node, key).await {
                Ok(_) => {}
                Err(e) => {
                    warn!("Failed to delete value from node {}: {}", node.id, e);
                }
            }
        }

        Ok(deleted)
    }

    async fn exists(&self, key: &StorageKey) -> StorageResult<bool> {
        self.local.exists(key).await
    }

    async fn list_prefix(
        &self,
        namespace: &str,
        prefix: Option<&[u8]>,
        limit: usize,
        continuation_token: Option<&[u8]>,
    ) -> StorageResult<ListResult> {
        // List operations are always local
        // DHT doesn't support efficient range queries
        self.local
            .list_prefix(namespace, prefix, limit, continuation_token)
            .await
    }

    async fn stats(&self) -> StorageResult<StorageStats> {
        let mut stats = self.local.stats().await?;
        stats.remote_peers = self.routing_table.read().node_count() as u64;
        Ok(stats)
    }
}

/// Builder for DhtStorage
pub struct DhtStorageBuilder<H: DhtNetworkHandler = LocalOnlyHandler> {
    local: Option<LocalStorage>,
    network: Option<H>,
    replication_config: ReplicationConfig,
}

impl DhtStorageBuilder<LocalOnlyHandler> {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            local: None,
            network: None,
            replication_config: ReplicationConfig::default(),
        }
    }
}

impl Default for DhtStorageBuilder<LocalOnlyHandler> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: DhtNetworkHandler> DhtStorageBuilder<H> {
    /// Set the local storage
    pub fn local_storage(mut self, local: LocalStorage) -> Self {
        self.local = Some(local);
        self
    }

    /// Set the replication configuration
    pub fn replication_config(mut self, config: ReplicationConfig) -> Self {
        self.replication_config = config;
        self
    }

    /// Build a local-only storage
    pub fn build_local_only(self) -> StorageResult<DhtStorage<LocalOnlyHandler>> {
        let local = self
            .local
            .ok_or_else(|| StorageError::InvalidData("Local storage is required".to_string()))?;

        Ok(DhtStorage::local_only(local))
    }
}

impl<H: DhtNetworkHandler + 'static> DhtStorageBuilder<H> {
    /// Set the network handler
    pub fn network_handler(self, network: H) -> DhtStorageBuilder<H> {
        DhtStorageBuilder {
            local: self.local,
            network: Some(network),
            replication_config: self.replication_config,
        }
    }

    /// Build the DHT storage
    pub fn build(self) -> StorageResult<DhtStorage<H>> {
        let local = self
            .local
            .ok_or_else(|| StorageError::InvalidData("Local storage is required".to_string()))?;

        let network = self.network.ok_or_else(|| {
            StorageError::InvalidData("Network handler is required for DHT mode".to_string())
        })?;

        Ok(DhtStorage::with_network(
            local,
            network,
            self.replication_config,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalStorageBuilder;

    fn create_local_storage() -> LocalStorage {
        LocalStorageBuilder::new("test-node")
            .in_memory()
            .build()
            .expect("Failed to create storage")
    }

    #[tokio::test]
    async fn test_local_only_mode() {
        let local = create_local_storage();
        let dht = DhtStorage::local_only(local);

        assert!(!dht.is_dht_enabled());

        let key = StorageKey::new("test", "key1");
        let value = b"hello".to_vec();

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

    #[test]
    fn test_routing_table() {
        let mut rt = RoutingTable::new();

        let node1 = DhtNode::new("node1", "127.0.0.1:8000");
        let node2 = DhtNode::new("node2", "127.0.0.1:8001");

        rt.add_node(node1);
        rt.add_node(node2);

        assert_eq!(rt.node_count(), 2);
        assert!(rt.get_node("node1").is_some());
        assert!(rt.get_node("node3").is_none());

        rt.remove_node("node1");
        assert_eq!(rt.node_count(), 1);
    }

    #[test]
    fn test_routing_table_online_status() {
        let mut rt = RoutingTable::new();
        rt.add_node(DhtNode::new("node1", "127.0.0.1:8000"));

        assert!(rt.get_node("node1").unwrap().is_online);

        rt.mark_offline("node1");
        assert!(!rt.get_node("node1").unwrap().is_online);

        rt.mark_online("node1");
        assert!(rt.get_node("node1").unwrap().is_online);
    }

    #[tokio::test]
    async fn test_builder() {
        let local = create_local_storage();

        let dht = DhtStorageBuilder::new()
            .local_storage(local)
            .build_local_only()
            .expect("build failed");

        assert!(!dht.is_dht_enabled());
    }

    #[tokio::test]
    async fn test_add_remove_nodes() {
        let local = create_local_storage();
        let dht = DhtStorage::local_only(local);

        assert_eq!(dht.node_count(), 0);

        dht.add_node(DhtNode::new("node1", "127.0.0.1:8000"));
        assert_eq!(dht.node_count(), 1);

        dht.remove_node("node1");
        assert_eq!(dht.node_count(), 0);
    }

    #[tokio::test]
    async fn test_stats_includes_remote_peers() {
        let local = create_local_storage();
        let dht = DhtStorage::local_only(local);

        dht.add_node(DhtNode::new("node1", "127.0.0.1:8000"));
        dht.add_node(DhtNode::new("node2", "127.0.0.1:8001"));

        let stats = dht.stats().await.expect("stats failed");
        assert_eq!(stats.remote_peers, 2);
    }

    #[test]
    fn test_xor_distance() {
        // Test basic XOR properties
        let a = [0u8; 32];
        let b = [0xffu8; 32];

        // Distance to self is zero
        let d_aa = xor_distance(&a, &a);
        assert_eq!(d_aa, [0u8; 32]);

        // Distance is symmetric
        let d_ab = xor_distance(&a, &b);
        let d_ba = xor_distance(&b, &a);
        assert_eq!(d_ab, d_ba);

        // XOR of zeros and all-ones gives all-ones
        assert_eq!(d_ab, [0xffu8; 32]);

        // Test with specific values
        let mut c = [0u8; 32];
        c[0] = 0x10;
        let d_ac = xor_distance(&a, &c);
        let mut expected = [0u8; 32];
        expected[0] = 0x10;
        assert_eq!(d_ac, expected);
    }

    #[test]
    fn test_distance_cmp() {
        let zero = [0u8; 32];
        let mut small = [0u8; 32];
        small[31] = 1; // Small distance (only LSB set)
        let mut large = [0u8; 32];
        large[0] = 1; // Large distance (MSB set)

        // Zero is smallest
        assert_eq!(distance_cmp(&zero, &small), std::cmp::Ordering::Less);
        assert_eq!(distance_cmp(&zero, &large), std::cmp::Ordering::Less);

        // Small < Large (since MSB comparison dominates)
        assert_eq!(distance_cmp(&small, &large), std::cmp::Ordering::Less);

        // Equal distances
        assert_eq!(distance_cmp(&small, &small), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_hash_node_id() {
        // Hash should be deterministic
        let h1 = hash_node_id("test-node");
        let h2 = hash_node_id("test-node");
        assert_eq!(h1, h2);

        // Different IDs should produce different hashes
        let h3 = hash_node_id("other-node");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_find_closest_with_xor_distance() {
        let mut rt = RoutingTable::new();

        // Add multiple nodes
        rt.add_node(DhtNode::new("node-a", "127.0.0.1:8000"));
        rt.add_node(DhtNode::new("node-b", "127.0.0.1:8001"));
        rt.add_node(DhtNode::new("node-c", "127.0.0.1:8002"));
        rt.add_node(DhtNode::new("node-d", "127.0.0.1:8003"));
        rt.add_node(DhtNode::new("node-e", "127.0.0.1:8004"));

        // Create a key hash (using hash of "test-key")
        let key_hash = hash_node_id("test-key");

        // Find closest 3 nodes
        let closest = rt.find_closest(&key_hash, 3);
        assert_eq!(closest.len(), 3);

        // Verify that returned nodes are actually the closest
        // by checking that all non-returned nodes are at least as far
        let closest_ids: HashSet<String> = closest.iter().map(|n| n.id.clone()).collect();

        // Calculate distances for all returned nodes
        let returned_distances: Vec<[u8; 32]> = closest
            .iter()
            .map(|n| xor_distance(&hash_node_id(&n.id), &key_hash))
            .collect();

        // Get max distance among returned nodes
        let max_returned = returned_distances.iter().max().expect("should have max");

        // Check that non-returned nodes are not closer than any returned node
        for node in rt.all_nodes() {
            if !closest_ids.contains(&node.id) {
                let dist = xor_distance(&hash_node_id(&node.id), &key_hash);
                assert!(
                    distance_cmp(&dist, max_returned) != std::cmp::Ordering::Less,
                    "Node {} should not be closer than returned nodes",
                    node.id
                );
            }
        }
    }

    #[test]
    fn test_find_closest_fewer_than_k_nodes() {
        let mut rt = RoutingTable::new();
        rt.add_node(DhtNode::new("node1", "127.0.0.1:8000"));
        rt.add_node(DhtNode::new("node2", "127.0.0.1:8001"));

        let key_hash = [0u8; 32];
        let closest = rt.find_closest(&key_hash, 5);

        // Should return all available nodes when k > node count
        assert_eq!(closest.len(), 2);
    }

    #[test]
    fn test_find_closest_empty_table() {
        let rt = RoutingTable::new();
        let key_hash = [0u8; 32];
        let closest = rt.find_closest(&key_hash, 5);

        assert!(closest.is_empty());
    }
}
