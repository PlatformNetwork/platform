//! Storage types for dynamic storage system
//!
//! Provides typed storage keys and values for the blockchain.

use platform_core::{ChallengeId, Hotkey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Storage key with namespace
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StorageKey {
    /// Namespace (usually challenge_id or "system")
    pub namespace: String,
    /// Optional validator scope
    pub validator: Option<Hotkey>,
    /// Key name
    pub key: String,
}

impl StorageKey {
    /// Create a system-level key
    pub fn system(key: impl Into<String>) -> Self {
        Self {
            namespace: "system".to_string(),
            validator: None,
            key: key.into(),
        }
    }

    /// Create a challenge-level key
    pub fn challenge(challenge_id: &ChallengeId, key: impl Into<String>) -> Self {
        Self {
            namespace: challenge_id.0.to_string(),
            validator: None,
            key: key.into(),
        }
    }

    /// Create a validator-scoped key within a challenge
    pub fn validator(
        challenge_id: &ChallengeId,
        validator: &Hotkey,
        key: impl Into<String>,
    ) -> Self {
        Self {
            namespace: challenge_id.0.to_string(),
            validator: Some(validator.clone()),
            key: key.into(),
        }
    }

    /// Create a global validator key (not challenge-specific)
    pub fn global_validator(validator: &Hotkey, key: impl Into<String>) -> Self {
        Self {
            namespace: "validators".to_string(),
            validator: Some(validator.clone()),
            key: key.into(),
        }
    }

    /// Convert to bytes for storage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.namespace.as_bytes());
        bytes.push(0x00); // Separator
        if let Some(ref v) = self.validator {
            bytes.extend(v.as_bytes());
        }
        bytes.push(0x00); // Separator
        bytes.extend(self.key.as_bytes());
        bytes
    }

    /// Get the prefix for scanning keys in a namespace
    pub fn namespace_prefix(namespace: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(namespace.as_bytes());
        bytes.push(0x00);
        bytes
    }
}

/// Typed storage value
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StorageValue {
    /// Boolean value
    Bool(bool),
    /// Unsigned 64-bit integer
    U64(u64),
    /// Signed 64-bit integer
    I64(i64),
    /// Unsigned 128-bit integer (for large numbers like TAO amounts)
    U128(u128),
    /// Floating point
    F64(f64),
    /// UTF-8 string
    String(String),
    /// Raw bytes
    Bytes(Vec<u8>),
    /// JSON value (for complex structures)
    Json(serde_json::Value),
    /// List of values
    List(Vec<StorageValue>),
    /// Map of string keys to values
    Map(HashMap<String, StorageValue>),
    /// Null/None
    Null,
}

impl StorageValue {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            StorageValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            StorageValue::U64(v) => Some(*v),
            StorageValue::I64(v) if *v >= 0 => Some(*v as u64),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            StorageValue::I64(v) => Some(*v),
            StorageValue::U64(v) if *v <= i64::MAX as u64 => Some(*v as i64),
            _ => None,
        }
    }

    pub fn as_u128(&self) -> Option<u128> {
        match self {
            StorageValue::U128(v) => Some(*v),
            StorageValue::U64(v) => Some(*v as u128),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            StorageValue::F64(v) => Some(*v),
            StorageValue::U64(v) => Some(*v as f64),
            StorageValue::I64(v) => Some(*v as f64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            StorageValue::String(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            StorageValue::Bytes(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_json(&self) -> Option<&serde_json::Value> {
        match self {
            StorageValue::Json(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&Vec<StorageValue>> {
        match self {
            StorageValue::List(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&HashMap<String, StorageValue>> {
        match self {
            StorageValue::Map(v) => Some(v),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, StorageValue::Null)
    }
}

impl From<bool> for StorageValue {
    fn from(v: bool) -> Self {
        StorageValue::Bool(v)
    }
}

impl From<u64> for StorageValue {
    fn from(v: u64) -> Self {
        StorageValue::U64(v)
    }
}

impl From<i64> for StorageValue {
    fn from(v: i64) -> Self {
        StorageValue::I64(v)
    }
}

impl From<u128> for StorageValue {
    fn from(v: u128) -> Self {
        StorageValue::U128(v)
    }
}

impl From<f64> for StorageValue {
    fn from(v: f64) -> Self {
        StorageValue::F64(v)
    }
}

impl From<String> for StorageValue {
    fn from(v: String) -> Self {
        StorageValue::String(v)
    }
}

impl From<&str> for StorageValue {
    fn from(v: &str) -> Self {
        StorageValue::String(v.to_string())
    }
}

impl From<Vec<u8>> for StorageValue {
    fn from(v: Vec<u8>) -> Self {
        StorageValue::Bytes(v)
    }
}

impl From<serde_json::Value> for StorageValue {
    fn from(v: serde_json::Value) -> Self {
        StorageValue::Json(v)
    }
}

/// Storage entry with metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageEntry {
    /// The value
    pub value: StorageValue,
    /// When this entry was created
    pub created_at: SystemTime,
    /// When this entry was last modified
    pub modified_at: SystemTime,
    /// Time-to-live (None = persistent)
    pub ttl: Option<Duration>,
    /// Version for optimistic locking
    pub version: u64,
    /// Who wrote this entry (validator hotkey)
    pub writer: Option<Hotkey>,
}

impl StorageEntry {
    pub fn new(value: StorageValue, writer: Option<Hotkey>) -> Self {
        let now = SystemTime::now();
        Self {
            value,
            created_at: now,
            modified_at: now,
            ttl: None,
            version: 1,
            writer,
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Check if this entry has expired
    pub fn is_expired(&self) -> bool {
        if let Some(ttl) = self.ttl {
            if let Ok(elapsed) = self.created_at.elapsed() {
                return elapsed > ttl;
            }
        }
        false
    }

    /// Update the value, incrementing version
    pub fn update(&mut self, value: StorageValue, writer: Option<Hotkey>) {
        self.value = value;
        self.modified_at = SystemTime::now();
        self.version += 1;
        self.writer = writer;
    }
}

/// Storage change event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageChange {
    pub key: StorageKey,
    pub old_value: Option<StorageValue>,
    pub new_value: Option<StorageValue>,
    pub block_height: u64,
    pub timestamp: SystemTime,
}

/// Storage statistics
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StorageStats {
    pub total_keys: u64,
    pub total_size_bytes: u64,
    pub namespaces: HashMap<String, NamespaceStats>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NamespaceStats {
    pub key_count: u64,
    pub size_bytes: u64,
    pub validator_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_key_system() {
        let key = StorageKey::system("version");
        assert_eq!(key.namespace, "system");
        assert!(key.validator.is_none());
        assert_eq!(key.key, "version");
    }

    #[test]
    fn test_storage_key_challenge() {
        let cid = ChallengeId(uuid::Uuid::new_v4());
        let key = StorageKey::challenge(&cid, "leaderboard");
        assert_eq!(key.namespace, cid.0.to_string());
        assert!(key.validator.is_none());
    }

    #[test]
    fn test_storage_key_validator() {
        let cid = ChallengeId(uuid::Uuid::new_v4());
        let hotkey = Hotkey([1u8; 32]);
        let key = StorageKey::validator(&cid, &hotkey, "score");
        assert!(key.validator.is_some());
    }

    #[test]
    fn test_storage_value_conversions() {
        let v = StorageValue::from(42u64);
        assert_eq!(v.as_u64(), Some(42));

        let v = StorageValue::from("hello");
        assert_eq!(v.as_str(), Some("hello"));

        let v = StorageValue::from(true);
        assert_eq!(v.as_bool(), Some(true));
    }

    #[test]
    fn test_storage_entry_expiry() {
        let entry =
            StorageEntry::new(StorageValue::Bool(true), None).with_ttl(Duration::from_millis(1));

        std::thread::sleep(Duration::from_millis(10));
        assert!(entry.is_expired());
    }

    #[test]
    fn test_storage_key_to_bytes() {
        let key = StorageKey::system("version");
        let bytes = key.to_bytes();
        assert!(!bytes.is_empty());
        assert!(bytes.contains(&0x00)); // Separator
    }

    #[test]
    fn test_storage_key_namespace_prefix() {
        let prefix = StorageKey::namespace_prefix("system");
        assert!(prefix.ends_with(&[0x00]));
    }

    #[test]
    fn test_storage_key_global_validator() {
        let hotkey = Hotkey([2u8; 32]);
        let key = StorageKey::global_validator(&hotkey, "reputation");
        assert_eq!(key.namespace, "validators");
        assert!(key.validator.is_some());
        assert_eq!(key.key, "reputation");
    }

    #[test]
    fn test_storage_value_as_u128() {
        let v = StorageValue::U128(1000u128);
        assert_eq!(v.as_u128(), Some(1000u128));

        let v = StorageValue::U64(100);
        assert_eq!(v.as_u128(), Some(100u128));

        let v = StorageValue::String("not a number".into());
        assert_eq!(v.as_u128(), None);
    }

    #[test]
    fn test_storage_value_as_f64() {
        let v = StorageValue::F64(3.125);
        assert_eq!(v.as_f64(), Some(3.125));

        let v = StorageValue::U64(42);
        assert_eq!(v.as_f64(), Some(42.0));

        let v = StorageValue::I64(-10);
        assert_eq!(v.as_f64(), Some(-10.0));

        let v = StorageValue::String("not a number".into());
        assert_eq!(v.as_f64(), None);
    }

    #[test]
    fn test_storage_value_as_bytes() {
        let bytes = vec![1u8, 2, 3];
        let v = StorageValue::Bytes(bytes.clone());
        assert_eq!(v.as_bytes(), Some(bytes.as_slice()));

        let v = StorageValue::String("test".into());
        assert_eq!(v.as_bytes(), None);
    }

    #[test]
    fn test_storage_value_as_json() {
        let json = serde_json::json!({"key": "value"});
        let v = StorageValue::Json(json.clone());
        assert_eq!(v.as_json(), Some(&json));

        let v = StorageValue::String("test".into());
        assert_eq!(v.as_json(), None);
    }

    #[test]
    fn test_storage_value_as_list() {
        let list = vec![StorageValue::U64(1), StorageValue::U64(2)];
        let v = StorageValue::List(list.clone());
        assert!(v.as_list().is_some());
        assert_eq!(v.as_list().unwrap().len(), 2);

        let v = StorageValue::String("test".into());
        assert!(v.as_list().is_none());
    }

    #[test]
    fn test_storage_value_as_map() {
        let mut map = HashMap::new();
        map.insert("key".to_string(), StorageValue::U64(42));
        let v = StorageValue::Map(map.clone());
        assert!(v.as_map().is_some());
        assert_eq!(v.as_map().unwrap().len(), 1);

        let v = StorageValue::String("test".into());
        assert!(v.as_map().is_none());
    }
    #[test]
    fn test_storage_value_is_null() {
        let v = StorageValue::Null;
        assert!(v.is_null());

        let v = StorageValue::U64(0);
        assert!(!v.is_null());
    }

    #[test]
    fn test_storage_value_from_conversions() {
        let v: StorageValue = 123i64.into();
        assert_eq!(v.as_i64(), Some(123));

        let v: StorageValue = 456u128.into();
        assert_eq!(v.as_u128(), Some(456));

        let v: StorageValue = 3.125f64.into();
        assert_eq!(v.as_f64(), Some(3.125));

        let v: StorageValue = vec![1u8, 2, 3].into();
        assert!(v.as_bytes().is_some());

        let v: StorageValue = serde_json::json!({"test": "value"}).into();
        assert!(v.as_json().is_some());
    }

    #[test]
    fn test_storage_entry_new() {
        let hotkey = Hotkey([3u8; 32]);
        let entry = StorageEntry::new(StorageValue::U64(100), Some(hotkey.clone()));

        assert_eq!(entry.value.as_u64(), Some(100));
        assert_eq!(entry.version, 1);
        assert_eq!(entry.writer, Some(hotkey));
        assert!(entry.ttl.is_none());
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_storage_entry_update() {
        let hotkey1 = Hotkey([4u8; 32]);
        let hotkey2 = Hotkey([5u8; 32]);
        let mut entry = StorageEntry::new(StorageValue::U64(100), Some(hotkey1));

        assert_eq!(entry.version, 1);

        entry.update(StorageValue::U64(200), Some(hotkey2.clone()));

        assert_eq!(entry.value.as_u64(), Some(200));
        assert_eq!(entry.version, 2);
        assert_eq!(entry.writer, Some(hotkey2));
    }

    #[test]
    fn test_storage_entry_not_expired() {
        let entry =
            StorageEntry::new(StorageValue::Bool(true), None).with_ttl(Duration::from_secs(3600));

        assert!(!entry.is_expired());
    }

    #[test]
    fn test_storage_entry_no_ttl_never_expires() {
        let entry = StorageEntry::new(StorageValue::Bool(true), None);
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_storage_change_creation() {
        let key = StorageKey::system("test");
        let change = StorageChange {
            key: key.clone(),
            old_value: Some(StorageValue::U64(1)),
            new_value: Some(StorageValue::U64(2)),
            block_height: 100,
            timestamp: SystemTime::now(),
        };

        assert_eq!(change.key.key, "test");
        assert_eq!(change.old_value.as_ref().unwrap().as_u64(), Some(1));
        assert_eq!(change.new_value.as_ref().unwrap().as_u64(), Some(2));
        assert_eq!(change.block_height, 100);
    }

    #[test]
    fn test_storage_stats_default() {
        let stats = StorageStats::default();
        assert_eq!(stats.total_keys, 0);
        assert_eq!(stats.total_size_bytes, 0);
        assert!(stats.namespaces.is_empty());
    }

    #[test]
    fn test_namespace_stats_default() {
        let stats = NamespaceStats::default();
        assert_eq!(stats.key_count, 0);
        assert_eq!(stats.size_bytes, 0);
        assert_eq!(stats.validator_count, 0);
    }

    #[test]
    fn test_storage_value_as_i64_conversion() {
        let v = StorageValue::U64(100);
        assert_eq!(v.as_i64(), Some(100));

        let v = StorageValue::U64(u64::MAX);
        assert_eq!(v.as_i64(), None); // Too large for i64
    }

    #[test]
    fn test_storage_value_as_u64_conversion() {
        let v = StorageValue::I64(50);
        assert_eq!(v.as_u64(), Some(50));

        let v = StorageValue::I64(-1);
        assert_eq!(v.as_u64(), None); // Negative
    }

    #[test]
    fn test_storage_value_as_u128_from_u64() {
        // Line 115: Covers StorageValue::U64(v) => Some(*v as u128) path
        let v = StorageValue::U64(12345);
        assert_eq!(v.as_u128(), Some(12345u128));
    }

    #[test]
    fn test_storage_value_as_f64_from_i64() {
        // Line 155: Covers StorageValue::I64(v) => Some(*v as f64) path
        let v = StorageValue::I64(-42);
        assert_eq!(v.as_f64(), Some(-42.0));
    }

    #[test]
    fn test_storage_value_from_string() {
        // Test impl From<String> for StorageValue
        let s = String::from("test value");
        let v: StorageValue = s.into();
        assert_eq!(v.as_str(), Some("test value"));
    }

    #[test]
    fn test_storage_value_as_bool_none_path() {
        // Test as_bool returns None for non-Bool variants
        let v = StorageValue::U64(1);
        assert_eq!(v.as_bool(), None);

        let v = StorageValue::String("true".to_string());
        assert_eq!(v.as_bool(), None);

        let v = StorageValue::Null;
        assert_eq!(v.as_bool(), None);
    }

    #[test]
    fn test_storage_value_as_str_none_path() {
        // Test as_str returns None for non-String variants
        let v = StorageValue::U64(42);
        assert_eq!(v.as_str(), None);

        let v = StorageValue::Bool(true);
        assert_eq!(v.as_str(), None);

        let v = StorageValue::Null;
        assert_eq!(v.as_str(), None);
    }
}