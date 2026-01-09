//! Secondary indexes for fast queries
//!
//! Provides indexed access to data by:
//! - Collection
//! - Field values (JSON)
//! - Range queries
//! - Full-text search (basic)

use crate::storage::{RocksStorage, CF_INDEXES};
use std::sync::Arc;
use tracing::debug;

/// Index definition
#[derive(Debug, Clone)]
pub struct IndexDef {
    pub name: String,
    pub collection: String,
    pub field: String,
    pub index_type: IndexType,
}

/// Type of index
#[derive(Debug, Clone, Copy)]
pub enum IndexType {
    /// Hash index for equality lookups
    Hash,
    /// B-tree index for range queries
    BTree,
    /// Full-text index for text search
    FullText,
}

/// Index manager
pub struct IndexManager {
    storage: Arc<RocksStorage>,
    indexes: Vec<IndexDef>,
}

impl IndexManager {
    /// Create a new index manager
    pub fn new(storage: Arc<RocksStorage>) -> anyhow::Result<Self> {
        let mut manager = Self {
            storage,
            indexes: Vec::new(),
        };

        // Define default indexes
        manager.add_index(IndexDef {
            name: "challenges_by_name".to_string(),
            collection: "challenges".to_string(),
            field: "name".to_string(),
            index_type: IndexType::Hash,
        });

        manager.add_index(IndexDef {
            name: "agents_by_challenge".to_string(),
            collection: "agents".to_string(),
            field: "challenge_id".to_string(),
            index_type: IndexType::Hash,
        });

        manager.add_index(IndexDef {
            name: "evaluations_by_agent".to_string(),
            collection: "evaluations".to_string(),
            field: "agent_hash".to_string(),
            index_type: IndexType::Hash,
        });

        manager.add_index(IndexDef {
            name: "evaluations_by_score".to_string(),
            collection: "evaluations".to_string(),
            field: "score".to_string(),
            index_type: IndexType::BTree,
        });

        manager.add_index(IndexDef {
            name: "weights_by_block".to_string(),
            collection: "weights".to_string(),
            field: "block".to_string(),
            index_type: IndexType::BTree,
        });

        Ok(manager)
    }

    /// Add an index definition
    pub fn add_index(&mut self, index: IndexDef) {
        self.indexes.push(index);
    }

    /// Index an entry
    pub fn index_entry(&self, collection: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        // Try to parse value as JSON
        let json: serde_json::Value = match serde_json::from_slice(value) {
            Ok(v) => v,
            Err(_) => return Ok(()), // Not JSON, skip indexing
        };

        for index in &self.indexes {
            if index.collection != collection {
                continue;
            }

            // Extract field value
            if let Some(field_value) = json.get(&index.field) {
                let index_key = self.build_index_key(&index.name, field_value, key);
                self.storage.put(CF_INDEXES, &index_key, key)?;
                debug!(
                    "Indexed {}.{} for key {:?}",
                    collection,
                    index.field,
                    hex::encode(&key[..key.len().min(8)])
                );
            }
        }

        Ok(())
    }

    /// Remove index entries for a key
    pub fn remove_entry(&self, collection: &str, key: &[u8]) -> anyhow::Result<()> {
        // Get existing value to extract indexed fields
        if let Some(value) = self.storage.get(collection, key)? {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&value) {
                for index in &self.indexes {
                    if index.collection != collection {
                        continue;
                    }

                    if let Some(field_value) = json.get(&index.field) {
                        let index_key = self.build_index_key(&index.name, field_value, key);
                        self.storage.delete(CF_INDEXES, &index_key)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Build index key
    fn build_index_key(
        &self,
        index_name: &str,
        field_value: &serde_json::Value,
        primary_key: &[u8],
    ) -> Vec<u8> {
        let value_str = match field_value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => format!("{:020}", n.as_f64().unwrap_or(0.0) as i64),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => field_value.to_string(),
        };

        format!("{}:{}:{}", index_name, value_str, hex::encode(primary_key)).into_bytes()
    }

    /// Execute a query
    pub fn execute_query(&self, query: Query) -> anyhow::Result<QueryResult> {
        let start = std::time::Instant::now();

        let results = match &query.filter {
            Some(filter) => self.query_with_filter(&query.collection, filter, query.limit)?,
            None => self.query_all(&query.collection, query.limit)?,
        };

        let total_count = results.len();
        Ok(QueryResult {
            entries: results,
            execution_time_us: start.elapsed().as_micros() as u64,
            total_count,
        })
    }

    /// Query all entries in a collection
    fn query_all(&self, collection: &str, limit: Option<usize>) -> anyhow::Result<Vec<QueryEntry>> {
        let entries = self.storage.iter_collection(collection)?;
        let limit = limit.unwrap_or(1000);

        Ok(entries
            .into_iter()
            .take(limit)
            .map(|(key, value)| QueryEntry { key, value })
            .collect())
    }

    /// Query with a filter
    fn query_with_filter(
        &self,
        collection: &str,
        filter: &Filter,
        limit: Option<usize>,
    ) -> anyhow::Result<Vec<QueryEntry>> {
        // Find matching index
        let index = self
            .indexes
            .iter()
            .find(|i| i.collection == collection && i.field == filter.field);

        match index {
            Some(idx) => self.query_indexed(idx, filter, limit),
            None => self.query_scan(collection, filter, limit),
        }
    }

    /// Query using an index
    fn query_indexed(
        &self,
        index: &IndexDef,
        filter: &Filter,
        limit: Option<usize>,
    ) -> anyhow::Result<Vec<QueryEntry>> {
        let limit = limit.unwrap_or(1000);

        match &filter.op {
            FilterOp::Eq(value) => {
                let prefix = format!("{}:{}:", index.name, value);
                let index_entries = self.storage.iter_prefix(CF_INDEXES, prefix.as_bytes())?;

                let mut results = Vec::new();
                for (_, primary_key) in index_entries.into_iter().take(limit) {
                    if let Some(value) = self.storage.get(&index.collection, &primary_key)? {
                        results.push(QueryEntry {
                            key: primary_key,
                            value,
                        });
                    }
                }

                Ok(results)
            }
            FilterOp::Gt(value)
            | FilterOp::Gte(value)
            | FilterOp::Lt(value)
            | FilterOp::Lte(value) => {
                // Range query - iterate index entries
                let prefix = format!("{}:", index.name);
                let index_entries = self.storage.iter_prefix(CF_INDEXES, prefix.as_bytes())?;

                let mut results = Vec::new();
                for (index_key, primary_key) in index_entries {
                    // Parse index key to extract value
                    let key_str = String::from_utf8_lossy(&index_key);
                    let parts: Vec<&str> = key_str.split(':').collect();
                    if parts.len() < 2 {
                        continue;
                    }

                    let indexed_value = parts[1];
                    let matches = match &filter.op {
                        FilterOp::Gt(v) => indexed_value > v.as_str(),
                        FilterOp::Gte(v) => indexed_value >= v.as_str(),
                        FilterOp::Lt(v) => indexed_value < v.as_str(),
                        FilterOp::Lte(v) => indexed_value <= v.as_str(),
                        _ => false,
                    };

                    if matches {
                        if let Some(value) = self.storage.get(&index.collection, &primary_key)? {
                            results.push(QueryEntry {
                                key: primary_key,
                                value,
                            });
                            if results.len() >= limit {
                                break;
                            }
                        }
                    }
                }

                Ok(results)
            }
            FilterOp::In(values) => {
                let mut results = Vec::new();
                for value in values {
                    let prefix = format!("{}:{}:", index.name, value);
                    let index_entries = self.storage.iter_prefix(CF_INDEXES, prefix.as_bytes())?;

                    for (_, primary_key) in index_entries {
                        if let Some(value) = self.storage.get(&index.collection, &primary_key)? {
                            results.push(QueryEntry {
                                key: primary_key,
                                value,
                            });
                            if results.len() >= limit {
                                return Ok(results);
                            }
                        }
                    }
                }

                Ok(results)
            }
            FilterOp::Contains(_) => {
                // Full scan for contains
                self.query_scan(&index.collection, filter, Some(limit))
            }
        }
    }

    /// Query with full scan (no index)
    fn query_scan(
        &self,
        collection: &str,
        filter: &Filter,
        limit: Option<usize>,
    ) -> anyhow::Result<Vec<QueryEntry>> {
        let limit = limit.unwrap_or(1000);
        let entries = self.storage.iter_collection(collection)?;

        let mut results = Vec::new();
        for (key, value) in entries {
            // Try to parse as JSON and filter
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&value) {
                if self.matches_filter(&json, filter) {
                    results.push(QueryEntry { key, value });
                    if results.len() >= limit {
                        break;
                    }
                }
            }
        }

        Ok(results)
    }

    /// Check if a JSON value matches a filter
    fn matches_filter(&self, json: &serde_json::Value, filter: &Filter) -> bool {
        let field_value = match json.get(&filter.field) {
            Some(v) => v,
            None => return false,
        };

        let field_str = match field_value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => field_value.to_string(),
        };

        match &filter.op {
            FilterOp::Eq(v) => &field_str == v,
            FilterOp::Gt(v) => &field_str > v,
            FilterOp::Gte(v) => &field_str >= v,
            FilterOp::Lt(v) => &field_str < v,
            FilterOp::Lte(v) => &field_str <= v,
            FilterOp::In(values) => values.contains(&field_str),
            FilterOp::Contains(v) => field_str.contains(v.as_str()),
        }
    }
}

/// Query definition
#[derive(Debug, Clone)]
pub struct Query {
    pub collection: String,
    pub filter: Option<Filter>,
    pub order_by: Option<OrderBy>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

impl Query {
    pub fn new(collection: impl Into<String>) -> Self {
        Self {
            collection: collection.into(),
            filter: None,
            order_by: None,
            limit: None,
            offset: None,
        }
    }

    pub fn filter(mut self, filter: Filter) -> Self {
        self.filter = Some(filter);
        self
    }

    pub fn order_by(mut self, field: impl Into<String>, desc: bool) -> Self {
        self.order_by = Some(OrderBy {
            field: field.into(),
            descending: desc,
        });
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }
}

/// Query filter
#[derive(Debug, Clone)]
pub struct Filter {
    pub field: String,
    pub op: FilterOp,
}

impl Filter {
    pub fn eq(field: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            op: FilterOp::Eq(value.into()),
        }
    }

    pub fn gt(field: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            op: FilterOp::Gt(value.into()),
        }
    }

    pub fn contains(field: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            op: FilterOp::Contains(value.into()),
        }
    }
}

/// Filter operation
#[derive(Debug, Clone)]
pub enum FilterOp {
    Eq(String),
    Gt(String),
    Gte(String),
    Lt(String),
    Lte(String),
    In(Vec<String>),
    Contains(String),
}

/// Order by clause
#[derive(Debug, Clone)]
pub struct OrderBy {
    pub field: String,
    pub descending: bool,
}

/// Query result
#[derive(Debug, Clone)]
pub struct QueryResult {
    pub entries: Vec<QueryEntry>,
    pub execution_time_us: u64,
    pub total_count: usize,
}

/// Query result entry
#[derive(Debug, Clone)]
pub struct QueryEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

impl QueryEntry {
    /// Parse value as JSON
    pub fn as_json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.value).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::RocksStorage;
    use crate::test_utils::*;
    use tempfile::tempdir;

    #[test]
    fn test_indexing() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(RocksStorage::open(dir.path()).unwrap());
        let indexes = IndexManager::new(storage.clone()).unwrap();

        // Store a challenge
        let challenge = serde_json::json!({
            "id": "test-challenge",
            "name": "Terminal Benchmark",
            "mechanism_id": 0
        });

        let key = b"test-challenge";
        let value = serde_json::to_vec(&challenge).unwrap();

        storage.put("challenges", key, &value).unwrap();
        indexes.index_entry("challenges", key, &value).unwrap();

        // Query by name
        let query = Query::new("challenges").filter(Filter::eq("name", "Terminal Benchmark"));
        let result = indexes.execute_query(query).unwrap();
        assert_eq!(result.entries.len(), 1);
    }

    #[test]
    fn test_index_manager_new() {
        let (indexes, _, _dir) = create_test_index_manager();
        assert_eq!(indexes.indexes.len(), 5);
    }

    #[test]
    fn test_add_index() {
        let (mut indexes, _, _dir) = create_test_index_manager();
        let count_before = indexes.indexes.len();

        indexes.add_index(IndexDef {
            name: "test_index".to_string(),
            collection: "test".to_string(),
            field: "field".to_string(),
            index_type: IndexType::Hash,
        });

        assert_eq!(indexes.indexes.len(), count_before + 1);
    }

    #[test]
    fn test_query_eq_filter() {
        let (indexes, storage, _dir) = create_test_index_manager();

        let challenge1 = serde_json::json!({"name": "Challenge1", "mechanism_id": 1});
        let challenge2 = serde_json::json!({"name": "Challenge2", "mechanism_id": 2});

        storage
            .put(
                "challenges",
                b"c1",
                &serde_json::to_vec(&challenge1).unwrap(),
            )
            .unwrap();
        storage
            .put(
                "challenges",
                b"c2",
                &serde_json::to_vec(&challenge2).unwrap(),
            )
            .unwrap();

        indexes
            .index_entry(
                "challenges",
                b"c1",
                &serde_json::to_vec(&challenge1).unwrap(),
            )
            .unwrap();
        indexes
            .index_entry(
                "challenges",
                b"c2",
                &serde_json::to_vec(&challenge2).unwrap(),
            )
            .unwrap();

        let query = Query::new("challenges").filter(Filter::eq("name", "Challenge1"));
        let result = indexes.execute_query(query).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.total_count, 1);
    }

    #[test]
    fn test_query_gt_filter() {
        let (indexes, storage, _dir) = create_test_index_manager();

        for i in 1..=5 {
            let eval = serde_json::json!({"agent_hash": format!("agent{}", i), "score": i * 10});
            storage
                .put(
                    "evaluations",
                    format!("eval{}", i).as_bytes(),
                    &serde_json::to_vec(&eval).unwrap(),
                )
                .unwrap();
            indexes
                .index_entry(
                    "evaluations",
                    format!("eval{}", i).as_bytes(),
                    &serde_json::to_vec(&eval).unwrap(),
                )
                .unwrap();
        }

        let query = Query::new("evaluations").filter(Filter::gt("score", "00000000000000000030"));
        let result = indexes.execute_query(query).unwrap();
        assert!(result.entries.len() >= 2); // scores 40, 50
    }

    #[test]
    fn test_query_contains_filter() {
        let (indexes, storage, _dir) = create_test_index_manager();

        let challenge1 = serde_json::json!({"name": "Terminal Benchmark", "mechanism_id": 1});
        let challenge2 = serde_json::json!({"name": "Simple Task", "mechanism_id": 2});

        storage
            .put(
                "challenges",
                b"c1",
                &serde_json::to_vec(&challenge1).unwrap(),
            )
            .unwrap();
        storage
            .put(
                "challenges",
                b"c2",
                &serde_json::to_vec(&challenge2).unwrap(),
            )
            .unwrap();

        indexes
            .index_entry(
                "challenges",
                b"c1",
                &serde_json::to_vec(&challenge1).unwrap(),
            )
            .unwrap();
        indexes
            .index_entry(
                "challenges",
                b"c2",
                &serde_json::to_vec(&challenge2).unwrap(),
            )
            .unwrap();

        let query = Query::new("challenges").filter(Filter::contains("name", "Terminal"));
        let result = indexes.execute_query(query).unwrap();
        assert_eq!(result.entries.len(), 1);
    }

    #[test]
    fn test_query_in_filter() {
        let (indexes, storage, _dir) = create_test_index_manager();

        for i in 1..=5 {
            let agent = serde_json::json!({"challenge_id": format!("ch{}", i), "status": "active"});
            storage
                .put(
                    "agents",
                    format!("agent{}", i).as_bytes(),
                    &serde_json::to_vec(&agent).unwrap(),
                )
                .unwrap();
            indexes
                .index_entry(
                    "agents",
                    format!("agent{}", i).as_bytes(),
                    &serde_json::to_vec(&agent).unwrap(),
                )
                .unwrap();
        }

        let query = Query::new("agents").filter(Filter {
            field: "challenge_id".to_string(),
            op: FilterOp::In(vec!["ch1".to_string(), "ch3".to_string()]),
        });
        let result = indexes.execute_query(query).unwrap();
        assert_eq!(result.entries.len(), 2);
    }

    #[test]
    fn test_query_without_filter() {
        let (indexes, storage, _dir) = create_test_index_manager();

        for i in 1..=3 {
            let challenge = serde_json::json!({"name": format!("C{}", i), "mechanism_id": i});
            storage
                .put(
                    "challenges",
                    format!("c{}", i).as_bytes(),
                    &serde_json::to_vec(&challenge).unwrap(),
                )
                .unwrap();
        }

        let query = Query::new("challenges");
        let result = indexes.execute_query(query).unwrap();
        assert_eq!(result.entries.len(), 3);
        assert_eq!(result.total_count, 3);
    }

    #[test]
    fn test_query_with_limit() {
        let (indexes, storage, _dir) = create_test_index_manager();

        for i in 1..=10 {
            let challenge = serde_json::json!({"name": format!("C{}", i), "mechanism_id": i});
            storage
                .put(
                    "challenges",
                    format!("c{}", i).as_bytes(),
                    &serde_json::to_vec(&challenge).unwrap(),
                )
                .unwrap();
        }

        let query = Query::new("challenges").limit(5);
        let result = indexes.execute_query(query).unwrap();
        assert!(result.entries.len() <= 5);
    }

    #[test]
    fn test_remove_entry() {
        let (indexes, storage, _dir) = create_test_index_manager();

        let challenge = serde_json::json!({"name": "Test", "mechanism_id": 1});
        let key = b"test-key";
        let value = serde_json::to_vec(&challenge).unwrap();

        storage.put("challenges", key, &value).unwrap();
        indexes.index_entry("challenges", key, &value).unwrap();

        // Verify indexed
        let query = Query::new("challenges").filter(Filter::eq("name", "Test"));
        let result = indexes.execute_query(query).unwrap();
        assert_eq!(result.entries.len(), 1);

        // Remove entry
        indexes.remove_entry("challenges", key).unwrap();

        // Verify not indexed anymore (note: storage still has the entry)
        let result2 = indexes
            .execute_query(Query::new("challenges").filter(Filter::eq("name", "Test")))
            .unwrap();
        assert_eq!(result2.entries.len(), 0);
    }

    #[test]
    fn test_index_non_json_value() {
        let (indexes, storage, _dir) = create_test_index_manager();

        let non_json = b"not json data";
        storage.put("challenges", b"key", non_json).unwrap();

        // Should not error, just skip indexing
        let result = indexes.index_entry("challenges", b"key", non_json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_query_scan_without_index() {
        let (indexes, storage, _dir) = create_test_index_manager();

        // Use challenges collection but query a field that doesn't have an index
        let item = serde_json::json!({"custom_field": "value", "name": "test"});
        storage
            .put("challenges", b"key1", &serde_json::to_vec(&item).unwrap())
            .unwrap();

        // Query a field that doesn't have an index - will do full scan
        let query = Query::new("challenges").filter(Filter::eq("custom_field", "value"));
        let result = indexes.execute_query(query).unwrap();
        assert_eq!(result.entries.len(), 1);
    }

    #[test]
    fn test_query_entry_as_json() {
        let entry = QueryEntry {
            key: b"key".to_vec(),
            value: serde_json::to_vec(&serde_json::json!({"field": "value"})).unwrap(),
        };

        let json = entry.as_json().unwrap();
        assert_eq!(json["field"], "value");
    }

    #[test]
    fn test_query_entry_as_json_invalid() {
        let entry = QueryEntry {
            key: b"key".to_vec(),
            value: b"not json".to_vec(),
        };

        assert!(entry.as_json().is_none());
    }

    #[test]
    fn test_query_builder_methods() {
        let query = Query::new("test")
            .filter(Filter::eq("field", "value"))
            .order_by("field", true)
            .limit(10)
            .offset(5);

        assert_eq!(query.collection, "test");
        assert!(query.filter.is_some());
        assert!(query.order_by.is_some());
        assert_eq!(query.limit, Some(10));
        assert_eq!(query.offset, Some(5));
    }

    #[test]
    fn test_filter_constructors() {
        let eq_filter = Filter::eq("field", "value");
        assert_eq!(eq_filter.field, "field");
        match eq_filter.op {
            FilterOp::Eq(v) => assert_eq!(v, "value"),
            _ => panic!("Expected Eq"),
        }

        let gt_filter = Filter::gt("field", "100");
        match gt_filter.op {
            FilterOp::Gt(_) => {}
            _ => panic!("Expected Gt"),
        }

        let contains_filter = Filter::contains("field", "substring");
        match contains_filter.op {
            FilterOp::Contains(_) => {}
            _ => panic!("Expected Contains"),
        }
    }

    #[test]
    fn test_index_type_variants() {
        let _ = IndexType::Hash;
        let _ = IndexType::BTree;
        let _ = IndexType::FullText;
    }

    #[test]
    fn test_filter_op_variants() {
        let _eq = FilterOp::Eq("test".to_string());
        let _gt = FilterOp::Gt("test".to_string());
        let _gte = FilterOp::Gte("test".to_string());
        let _lt = FilterOp::Lt("test".to_string());
        let _lte = FilterOp::Lte("test".to_string());
        let _in = FilterOp::In(vec!["a".to_string(), "b".to_string()]);
        let _contains = FilterOp::Contains("test".to_string());
    }

    #[test]
    fn test_query_gte_filter() {
        let (indexes, storage, _dir) = create_test_index_manager();

        for i in 1..=3 {
            let weight = serde_json::json!({"block": i * 100, "value": i});
            storage
                .put(
                    "weights",
                    format!("w{}", i).as_bytes(),
                    &serde_json::to_vec(&weight).unwrap(),
                )
                .unwrap();
            indexes
                .index_entry(
                    "weights",
                    format!("w{}", i).as_bytes(),
                    &serde_json::to_vec(&weight).unwrap(),
                )
                .unwrap();
        }

        let query = Query::new("weights").filter(Filter {
            field: "block".to_string(),
            op: FilterOp::Gte("00000000000000000200".to_string()),
        });
        let result = indexes.execute_query(query).unwrap();
        assert!(result.entries.len() >= 2); // blocks 200, 300
    }

    #[test]
    fn test_query_lt_filter() {
        let (indexes, storage, _dir) = create_test_index_manager();

        for i in 1..=3 {
            let weight = serde_json::json!({"block": i * 100, "value": i});
            storage
                .put(
                    "weights",
                    format!("w{}", i).as_bytes(),
                    &serde_json::to_vec(&weight).unwrap(),
                )
                .unwrap();
            indexes
                .index_entry(
                    "weights",
                    format!("w{}", i).as_bytes(),
                    &serde_json::to_vec(&weight).unwrap(),
                )
                .unwrap();
        }

        let query = Query::new("weights").filter(Filter {
            field: "block".to_string(),
            op: FilterOp::Lt("00000000000000000200".to_string()),
        });
        let result = indexes.execute_query(query).unwrap();
        assert!(result.entries.len() >= 1); // block 100
    }

    #[test]
    fn test_query_lte_filter() {
        let (indexes, storage, _dir) = create_test_index_manager();

        for i in 1..=3 {
            let weight = serde_json::json!({"block": i * 100, "value": i});
            storage
                .put(
                    "weights",
                    format!("w{}", i).as_bytes(),
                    &serde_json::to_vec(&weight).unwrap(),
                )
                .unwrap();
            indexes
                .index_entry(
                    "weights",
                    format!("w{}", i).as_bytes(),
                    &serde_json::to_vec(&weight).unwrap(),
                )
                .unwrap();
        }

        let query = Query::new("weights").filter(Filter {
            field: "block".to_string(),
            op: FilterOp::Lte("00000000000000000200".to_string()),
        });
        let result = indexes.execute_query(query).unwrap();
        assert!(result.entries.len() >= 2); // blocks 100, 200
    }

    #[test]
    fn test_matches_filter_with_number() {
        let (indexes, _, _dir) = create_test_index_manager();

        let json = serde_json::json!({"score": 100});
        let filter = Filter::eq("score", "100");

        assert!(indexes.matches_filter(&json, &filter));
    }

    #[test]
    fn test_matches_filter_with_bool() {
        let (indexes, _, _dir) = create_test_index_manager();

        let json = serde_json::json!({"active": true});
        let filter = Filter::eq("active", "true");

        assert!(indexes.matches_filter(&json, &filter));
    }

    #[test]
    fn test_matches_filter_missing_field() {
        let (indexes, _, _dir) = create_test_index_manager();

        let json = serde_json::json!({"other": "value"});
        let filter = Filter::eq("missing_field", "value");

        assert!(!indexes.matches_filter(&json, &filter));
    }
}
