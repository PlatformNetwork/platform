//! WASM runtime host interface definitions for network access.
//!
//! This crate defines the host function surface exposed to challenge WASM
//! modules for controlled internet access. The interface is declarative so
//! runtimes can enforce deterministic, auditable behavior across validators.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Host functions that may be exposed to WASM challenges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostFunction {
    HttpRequest,
    HttpGet,
    HttpPost,
    DnsResolve,
}

/// Network policy aligned with secure-container-runtime patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Whether any outbound network access is allowed.
    pub enabled: bool,
    /// Allowed outbound hostnames or suffixes.
    pub allowed_hosts: Vec<String>,
    /// Allowed outbound IP CIDR ranges.
    pub allowed_ip_ranges: Vec<String>,
    /// Allowed URL schemes (https only in production).
    pub allowed_schemes: Vec<HttpScheme>,
    /// Allowed outbound TCP ports.
    pub allowed_ports: Vec<u16>,
    /// DNS resolution policy.
    pub dns_policy: DnsPolicy,
    /// Request/response limits.
    pub limits: RequestLimits,
    /// Audit logging policy for network calls.
    pub audit: AuditPolicy,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_hosts: Vec::new(),
            allowed_ip_ranges: Vec::new(),
            allowed_schemes: vec![HttpScheme::Https],
            allowed_ports: vec![443],
            dns_policy: DnsPolicy::default(),
            limits: RequestLimits::default(),
            audit: AuditPolicy::default(),
        }
    }
}

impl NetworkPolicy {
    /// Strict policy with explicit allow-list and HTTPS only.
    pub fn strict(allowed_hosts: Vec<String>) -> Self {
        Self {
            enabled: true,
            allowed_hosts,
            ..Default::default()
        }
    }

    /// Development policy with relaxed defaults.
    pub fn development() -> Self {
        Self {
            enabled: true,
            allowed_schemes: vec![HttpScheme::Https, HttpScheme::Http],
            allowed_ports: vec![80, 443],
            dns_policy: DnsPolicy::development(),
            limits: RequestLimits::development(),
            audit: AuditPolicy::development(),
            ..Default::default()
        }
    }
}

/// Supported HTTP schemes for outbound requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpScheme {
    Http,
    Https,
}

/// DNS resolution policy for WASM network calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsPolicy {
    /// Whether DNS resolution is allowed.
    pub enabled: bool,
    /// Allowed DNS query types (A/AAAA/CNAME, etc.).
    pub allowed_record_types: Vec<DnsRecordType>,
    /// Maximum DNS lookups per execution.
    pub max_lookups: u32,
    /// Cache TTL in seconds for deterministic resolution.
    pub cache_ttl_secs: u64,
    /// Whether to block private or loopback ranges.
    pub block_private_ranges: bool,
}

impl Default for DnsPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_record_types: vec![DnsRecordType::A, DnsRecordType::Aaaa],
            max_lookups: 8,
            cache_ttl_secs: 60,
            block_private_ranges: true,
        }
    }
}

impl DnsPolicy {
    /// Development DNS policy.
    pub fn development() -> Self {
        Self {
            enabled: true,
            max_lookups: 32,
            cache_ttl_secs: 10,
            block_private_ranges: false,
            ..Default::default()
        }
    }
}

/// DNS record types permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Txt,
}

/// Request/response limits enforced by the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLimits {
    /// Maximum request body size in bytes.
    pub max_request_bytes: u64,
    /// Maximum response body size in bytes.
    pub max_response_bytes: u64,
    /// Maximum total headers size in bytes.
    pub max_header_bytes: u64,
    /// Per-request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum number of HTTP requests per execution.
    pub max_requests: u32,
    /// Maximum redirects permitted per request.
    pub max_redirects: u8,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_request_bytes: 256 * 1024,
            max_response_bytes: 512 * 1024,
            max_header_bytes: 32 * 1024,
            timeout_ms: 5_000,
            max_requests: 8,
            max_redirects: 2,
        }
    }
}

impl RequestLimits {
    /// Development-friendly limits.
    pub fn development() -> Self {
        Self {
            max_request_bytes: 1024 * 1024,
            max_response_bytes: 2 * 1024 * 1024,
            max_header_bytes: 64 * 1024,
            timeout_ms: 15_000,
            max_requests: 32,
            max_redirects: 4,
        }
    }
}

/// Audit logging configuration for network access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPolicy {
    /// Whether to emit audit events.
    pub enabled: bool,
    /// Whether to include request headers in logs.
    pub log_headers: bool,
    /// Whether to include request/response bodies in logs.
    pub log_bodies: bool,
    /// Additional tags to attach to audit events.
    pub tags: HashMap<String, String>,
}

impl Default for AuditPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            log_headers: false,
            log_bodies: false,
            tags: HashMap::new(),
        }
    }
}

impl AuditPolicy {
    /// Development audit policy.
    pub fn development() -> Self {
        Self {
            enabled: true,
            log_headers: true,
            log_bodies: false,
            tags: HashMap::new(),
        }
    }
}

/// HTTP request description for WASM host calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// HTTP response returned to WASM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Supported HTTP methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

/// DNS resolution request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRequest {
    pub hostname: String,
    pub record_type: DnsRecordType,
}

/// DNS resolution response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResponse {
    pub records: Vec<String>,
}

/// Audit log entry for network operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAuditEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub challenge_id: String,
    pub validator_id: String,
    pub action: NetworkAuditAction,
    pub metadata: HashMap<String, String>,
}

/// Specific network audit action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAuditAction {
    HttpRequest { url: String, method: HttpMethod },
    HttpResponse { status: u16, bytes: u64 },
    DnsLookup { hostname: String },
    PolicyDenied { reason: String },
}

/// Errors emitted by host networking operations.
#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum NetworkError {
    #[error("network access disabled")]
    NetworkDisabled,
    #[error("policy violation: {0}")]
    PolicyViolation(String),
    #[error("request limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("dns resolution failed: {0}")]
    DnsFailure(String),
    #[error("http request failed: {0}")]
    HttpFailure(String),
    #[error("request timeout")]
    Timeout,
}

/// Hook for emitting audit events from the runtime.
pub trait NetworkAuditLogger: Send + Sync {
    fn record(&self, entry: NetworkAuditEntry);
}
