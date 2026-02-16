//! WASM runtime host interface definitions for network access.
//!
//! This crate defines the host function surface exposed to challenge WASM
//! modules for controlled internet access. The interface is declarative so
//! runtimes can enforce deterministic, auditable behavior across validators.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

pub mod network;
pub mod runtime;
pub mod storage;
pub use network::{NetworkHostFunctions, NetworkState, NetworkStateError};
pub use storage::{
    InMemoryStorageBackend, NoopStorageBackend, StorageAuditEntry, StorageAuditLogger,
    StorageBackend, StorageDeleteRequest, StorageGetRequest, StorageGetResponse, StorageHostConfig,
    StorageHostError, StorageHostState, StorageHostStatus, StorageOperation,
    StorageProposeWriteRequest, StorageProposeWriteResponse,
};

pub const HOST_FUNCTION_NAMESPACE: &str = "platform_network";
pub const HOST_HTTP_REQUEST: &str = "http_request";
pub const HOST_HTTP_GET: &str = "http_get";
pub const HOST_HTTP_POST: &str = "http_post";
pub const HOST_DNS_RESOLVE: &str = "dns_resolve";

pub use runtime::{
    ChallengeInstance, HostFunctionRegistrar, InstanceConfig, RuntimeConfig, RuntimeState,
    WasmModule, WasmRuntime, WasmRuntimeError,
};
pub use storage::{
    HOST_STORAGE_ALLOC, HOST_STORAGE_DELETE, HOST_STORAGE_GET, HOST_STORAGE_GET_RESULT,
    HOST_STORAGE_NAMESPACE, HOST_STORAGE_PROPOSE_WRITE,
};

/// Host functions that may be exposed to WASM challenges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostFunction {
    HttpRequest,
    HttpGet,
    HttpPost,
    DnsResolve,
}

/// Network policy aligned with secure-container-runtime patterns.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Whether outbound internet access is allowed.
    pub allow_internet: bool,
    /// HTTP access rules.
    pub http: HttpPolicy,
    /// Allowed outbound IP CIDR ranges.
    pub allowed_ip_ranges: Vec<String>,
    /// DNS resolution policy.
    pub dns_policy: DnsPolicy,
    /// Request/response limits.
    pub limits: RequestLimits,
    /// Audit logging policy for network calls.
    pub audit: AuditPolicy,
}

impl NetworkPolicy {
    /// Strict policy with explicit allow-list and HTTPS only.
    pub fn strict(allowed_hosts: Vec<String>) -> Self {
        Self {
            allow_internet: true,
            http: HttpPolicy {
                allowed_hosts,
                ..HttpPolicy::default()
            },
            ..Default::default()
        }
    }

    /// Development policy with relaxed defaults.
    pub fn development() -> Self {
        Self {
            allow_internet: true,
            http: HttpPolicy::development(),
            dns_policy: DnsPolicy::development(),
            limits: RequestLimits::development(),
            audit: AuditPolicy::development(),
            ..Default::default()
        }
    }

    /// Validate and normalize network policy for runtime enforcement.
    pub fn validate(&self) -> Result<ValidatedNetworkPolicy, NetworkPolicyError> {
        let http = self.http.validate()?;
        let dns = self.dns_policy.validate()?;
        let allowed_ip_ranges = parse_ip_ranges(&self.allowed_ip_ranges)?;

        Ok(ValidatedNetworkPolicy {
            allow_internet: self.allow_internet,
            http,
            allowed_ip_ranges,
            dns_policy: dns,
            limits: self.limits.clone(),
            audit: self.audit.clone(),
        })
    }
}

/// HTTP-specific access policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpPolicy {
    /// Allowed outbound hostnames or suffixes.
    pub allowed_hosts: Vec<String>,
    /// Allowed URL schemes (https only in production).
    pub allowed_schemes: Vec<HttpScheme>,
    /// Allowed outbound TCP ports.
    pub allowed_ports: Vec<u16>,
}

impl Default for HttpPolicy {
    fn default() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            allowed_schemes: vec![HttpScheme::Https],
            allowed_ports: vec![443],
        }
    }
}

impl HttpPolicy {
    /// Development HTTP policy with relaxed defaults.
    pub fn development() -> Self {
        Self {
            allowed_schemes: vec![HttpScheme::Https, HttpScheme::Http],
            allowed_ports: vec![80, 443],
            ..Default::default()
        }
    }

    fn validate(&self) -> Result<ValidatedHttpPolicy, NetworkPolicyError> {
        let allowed_hosts = normalize_hosts(&self.allowed_hosts)?;
        let allowed_ports = normalize_ports(&self.allowed_ports)?;

        Ok(ValidatedHttpPolicy {
            allowed_hosts,
            allowed_schemes: self.allowed_schemes.clone(),
            allowed_ports,
        })
    }
}

/// Supported HTTP schemes for outbound requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// Allowed DNS hostnames or suffixes.
    pub allowed_hosts: Vec<String>,
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
            allowed_hosts: Vec::new(),
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

    fn validate(&self) -> Result<ValidatedDnsPolicy, NetworkPolicyError> {
        let allowed_hosts = normalize_hosts(&self.allowed_hosts)?;

        Ok(ValidatedDnsPolicy {
            enabled: self.enabled,
            allowed_hosts,
            allowed_record_types: self.allowed_record_types.clone(),
            max_lookups: self.max_lookups,
            cache_ttl_secs: self.cache_ttl_secs,
            block_private_ranges: self.block_private_ranges,
        })
    }
}

/// DNS record types permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// Normalized policy for runtime enforcement.
#[derive(Debug, Clone)]
pub struct ValidatedNetworkPolicy {
    pub allow_internet: bool,
    pub http: ValidatedHttpPolicy,
    pub allowed_ip_ranges: Vec<ipnet::IpNet>,
    pub dns_policy: ValidatedDnsPolicy,
    pub limits: RequestLimits,
    pub audit: AuditPolicy,
}

impl ValidatedNetworkPolicy {
    /// Validate an outbound HTTP request against policy.
    pub fn is_http_request_allowed(&self, url: &str) -> Result<(), NetworkPolicyError> {
        if !self.allow_internet {
            return Err(NetworkPolicyError::NetworkDisabled);
        }

        let parsed =
            url::Url::parse(url).map_err(|err| NetworkPolicyError::InvalidUrl(err.to_string()))?;
        let scheme = match parsed.scheme() {
            "http" => HttpScheme::Http,
            "https" => HttpScheme::Https,
            other => return Err(NetworkPolicyError::SchemeNotAllowed(other.to_string())),
        };

        if !self.http.allowed_schemes.is_empty() && !self.http.allowed_schemes.contains(&scheme) {
            return Err(NetworkPolicyError::SchemeNotAllowed(
                parsed.scheme().to_string(),
            ));
        }

        let host = parsed.host().ok_or(NetworkPolicyError::MissingHost)?;
        let host_string = normalize_host_string(&host);
        let port = parsed
            .port_or_known_default()
            .ok_or(NetworkPolicyError::MissingPort)?;

        if !self.http.allowed_ports.is_empty() && !self.http.allowed_ports.contains(&port) {
            return Err(NetworkPolicyError::PortNotAllowed(port));
        }

        if !self.is_host_allowed(&host, &host_string) {
            return Err(NetworkPolicyError::HostNotAllowed(host_string));
        }

        Ok(())
    }

    /// Validate a DNS lookup against policy.
    pub fn is_dns_lookup_allowed(
        &self,
        hostname: &str,
        record_type: DnsRecordType,
    ) -> Result<(), NetworkPolicyError> {
        if !self.allow_internet {
            return Err(NetworkPolicyError::NetworkDisabled);
        }

        if !self.dns_policy.enabled {
            return Err(NetworkPolicyError::DnsDisabled);
        }

        if !self.dns_policy.allowed_record_types.is_empty()
            && !self.dns_policy.allowed_record_types.contains(&record_type)
        {
            return Err(NetworkPolicyError::DnsRecordTypeNotAllowed(record_type));
        }

        let host = url::Host::parse(hostname)
            .map_err(|_| NetworkPolicyError::InvalidHost(hostname.to_string()))?;
        let host_string = normalize_host_string(&host);

        if !self.dns_policy.allowed_hosts.is_empty()
            && !self
                .dns_policy
                .allowed_hosts
                .iter()
                .any(|pattern| pattern.matches(&host_string))
        {
            return Err(NetworkPolicyError::HostNotAllowed(host_string));
        }

        Ok(())
    }

    fn is_host_allowed<T: AsRef<str>>(&self, host: &url::Host<T>, host_string: &str) -> bool {
        let host_allowed = if self.http.allowed_hosts.is_empty() {
            true
        } else {
            self.http
                .allowed_hosts
                .iter()
                .any(|pattern| pattern.matches(host_string))
        };

        match host {
            url::Host::Ipv4(ip) => host_allowed || self.is_ip_allowed(IpAddr::V4(*ip)),
            url::Host::Ipv6(ip) => host_allowed || self.is_ip_allowed(IpAddr::V6(*ip)),
            url::Host::Domain(_) => host_allowed,
        }
    }

    fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        if self.allowed_ip_ranges.is_empty() {
            return false;
        }

        self.allowed_ip_ranges.iter().any(|net| net.contains(&ip))
    }
}

/// Normalized HTTP policy for runtime enforcement.
#[derive(Debug, Clone)]
pub struct ValidatedHttpPolicy {
    pub allowed_hosts: Vec<NormalizedHostPattern>,
    pub allowed_schemes: Vec<HttpScheme>,
    pub allowed_ports: Vec<u16>,
}

/// Normalized DNS policy for runtime enforcement.
#[derive(Debug, Clone)]
pub struct ValidatedDnsPolicy {
    pub enabled: bool,
    pub allowed_hosts: Vec<NormalizedHostPattern>,
    pub allowed_record_types: Vec<DnsRecordType>,
    pub max_lookups: u32,
    pub cache_ttl_secs: u64,
    pub block_private_ranges: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedHostPattern {
    pattern: String,
    match_subdomains: bool,
}

impl NormalizedHostPattern {
    fn matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_lowercase();
        if self.match_subdomains {
            host == self.pattern || host.ends_with(&format!(".{}", self.pattern))
        } else {
            host == self.pattern
        }
    }
}

/// Errors emitted when validating network policies.
#[derive(Debug, thiserror::Error)]
pub enum NetworkPolicyError {
    #[error("network access disabled")]
    NetworkDisabled,
    #[error("dns access disabled")]
    DnsDisabled,
    #[error("invalid host pattern: {0}")]
    InvalidHost(String),
    #[error("invalid ip range: {0}")]
    InvalidIpRange(String),
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("missing host in url")]
    MissingHost,
    #[error("missing port in url")]
    MissingPort,
    #[error("scheme not allowed: {0}")]
    SchemeNotAllowed(String),
    #[error("host not allowed: {0}")]
    HostNotAllowed(String),
    #[error("port not allowed: {0}")]
    PortNotAllowed(u16),
    #[error("dns record type not allowed: {0:?}")]
    DnsRecordTypeNotAllowed(DnsRecordType),
}

fn normalize_hosts(
    allowed_hosts: &[String],
) -> Result<Vec<NormalizedHostPattern>, NetworkPolicyError> {
    allowed_hosts
        .iter()
        .map(|host| normalize_host_pattern(host))
        .collect()
}

fn normalize_host_pattern(host: &str) -> Result<NormalizedHostPattern, NetworkPolicyError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(NetworkPolicyError::InvalidHost(host.to_string()));
    }

    let (pattern, match_subdomains) = if let Some(stripped) = trimmed.strip_prefix("*.") {
        (stripped, true)
    } else if let Some(stripped) = trimmed.strip_prefix('.') {
        (stripped, true)
    } else {
        (trimmed, false)
    };

    let normalized = pattern.trim_end_matches('.').to_lowercase();
    if normalized.is_empty() {
        return Err(NetworkPolicyError::InvalidHost(host.to_string()));
    }

    url::Host::parse(&normalized).map_err(|_| NetworkPolicyError::InvalidHost(host.to_string()))?;

    Ok(NormalizedHostPattern {
        pattern: normalized,
        match_subdomains,
    })
}

fn normalize_ports(allowed_ports: &[u16]) -> Result<Vec<u16>, NetworkPolicyError> {
    if allowed_ports.contains(&0) {
        return Err(NetworkPolicyError::PortNotAllowed(0));
    }

    Ok(allowed_ports.to_vec())
}

fn parse_ip_ranges(ranges: &[String]) -> Result<Vec<ipnet::IpNet>, NetworkPolicyError> {
    ranges
        .iter()
        .map(|range| {
            ipnet::IpNet::from_str(range)
                .map_err(|_| NetworkPolicyError::InvalidIpRange(range.to_string()))
        })
        .collect()
}

fn normalize_host_string<T: AsRef<str>>(host: &url::Host<T>) -> String {
    match host {
        url::Host::Domain(domain) => domain.as_ref().trim_end_matches('.').to_lowercase(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => ip.to_string(),
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

/// HTTP GET request payload for host calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpGetRequest {
    pub url: String,
    pub headers: HashMap<String, String>,
}

/// HTTP POST request payload for host calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpPostRequest {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_policy_allows_https() {
        let policy = NetworkPolicy::strict(vec!["example.com".to_string()]);
        let validated = policy.validate().expect("policy should validate");

        assert!(validated
            .is_http_request_allowed("https://example.com/path")
            .is_ok());
        assert!(validated
            .is_http_request_allowed("http://example.com")
            .is_err());
    }

    #[test]
    fn test_http_policy_wildcard_hosts() {
        let policy = NetworkPolicy::strict(vec!["*.example.com".to_string()]);
        let validated = policy.validate().expect("policy should validate");

        assert!(validated
            .is_http_request_allowed("https://api.example.com")
            .is_ok());
        assert!(validated
            .is_http_request_allowed("https://example.com")
            .is_ok());
        assert!(validated
            .is_http_request_allowed("https://evil.com")
            .is_err());
    }

    #[test]
    fn test_http_policy_ports() {
        let mut policy = NetworkPolicy::strict(vec!["example.com".to_string()]);
        policy.http.allowed_ports = vec![443];
        let validated = policy.validate().expect("policy should validate");

        assert!(validated
            .is_http_request_allowed("https://example.com:443")
            .is_ok());
        assert!(validated
            .is_http_request_allowed("https://example.com:8443")
            .is_err());
    }

    #[test]
    fn test_dns_policy_allows_record() {
        let mut policy = NetworkPolicy::strict(vec!["example.com".to_string()]);
        policy.dns_policy.enabled = true;
        policy.dns_policy.allowed_hosts = vec!["example.com".to_string()];
        let validated = policy.validate().expect("policy should validate");

        assert!(validated
            .is_dns_lookup_allowed("example.com", DnsRecordType::A)
            .is_ok());
        assert!(validated
            .is_dns_lookup_allowed("evil.com", DnsRecordType::A)
            .is_err());
    }

    #[test]
    fn test_invalid_host_rejected() {
        let policy = NetworkPolicy::strict(vec!["bad host".to_string()]);
        assert!(policy.validate().is_err());
    }
}
