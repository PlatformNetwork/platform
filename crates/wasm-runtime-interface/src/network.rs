use crate::{
    DnsRecordType, DnsRequest, DnsResponse, HostFunction, HttpGetRequest, HttpMethod,
    HttpPostRequest, HttpRequest, HttpResponse, NetworkAuditAction, NetworkAuditEntry,
    NetworkAuditLogger, NetworkError, NetworkPolicy, NetworkPolicyError, ValidatedNetworkPolicy,
    HOST_DNS_RESOLVE, HOST_FUNCTION_NAMESPACE, HOST_HTTP_GET, HOST_HTTP_POST, HOST_HTTP_REQUEST,
};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::Resolver;
use wasmtime::{Caller, Linker, Memory};

use crate::runtime::{HostFunctionRegistrar, RuntimeState, WasmRuntimeError};

pub const HOST_LOG_MESSAGE: &str = "log_message";
pub const HOST_GET_TIMESTAMP: &str = "get_timestamp";

const DEFAULT_DNS_BUF_SIZE: i32 = 4096;

#[derive(Debug, thiserror::Error)]
pub enum NetworkStateError {
    #[error("network policy invalid: {0}")]
    InvalidPolicy(#[from] NetworkPolicyError),
    #[error("failed to initialize http client: {0}")]
    HttpClient(String),
    #[error("failed to initialize dns resolver: {0}")]
    DnsResolver(String),
}

#[derive(Clone, Debug)]
pub struct NetworkHostFunctions {
    enabled: Vec<HostFunction>,
}

impl NetworkHostFunctions {
    pub fn new(enabled: Vec<HostFunction>) -> Self {
        Self { enabled }
    }

    pub fn all() -> Self {
        Self {
            enabled: vec![
                HostFunction::HttpRequest,
                HostFunction::HttpGet,
                HostFunction::HttpPost,
                HostFunction::DnsResolve,
            ],
        }
    }
}

impl Default for NetworkHostFunctions {
    fn default() -> Self {
        Self::all()
    }
}

impl HostFunctionRegistrar for NetworkHostFunctions {
    fn register(&self, linker: &mut Linker<RuntimeState>) -> Result<(), WasmRuntimeError> {
        if self.enabled.contains(&HostFunction::HttpRequest) {
            linker
                .func_wrap(
                    HOST_FUNCTION_NAMESPACE,
                    HOST_HTTP_REQUEST,
                    |mut caller: Caller<RuntimeState>,
                     req_ptr: i32,
                     req_len: i32,
                     resp_ptr: i32,
                     resp_len: i32|
                     -> i32 {
                        handle_http_request(&mut caller, req_ptr, req_len, resp_ptr, resp_len)
                    },
                )
                .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;
        }

        if self.enabled.contains(&HostFunction::HttpGet) {
            linker
                .func_wrap(
                    HOST_FUNCTION_NAMESPACE,
                    HOST_HTTP_GET,
                    |mut caller: Caller<RuntimeState>,
                     req_ptr: i32,
                     req_len: i32,
                     resp_ptr: i32,
                     resp_len: i32|
                     -> i32 {
                        handle_http_get(&mut caller, req_ptr, req_len, resp_ptr, resp_len)
                    },
                )
                .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;
        }

        if self.enabled.contains(&HostFunction::HttpPost) {
            linker
                .func_wrap(
                    HOST_FUNCTION_NAMESPACE,
                    HOST_HTTP_POST,
                    |mut caller: Caller<RuntimeState>,
                     req_ptr: i32,
                     req_len: i32,
                     resp_ptr: i32,
                     resp_len: i32,
                     _extra: i32|
                     -> i32 {
                        handle_http_post(&mut caller, req_ptr, req_len, resp_ptr, resp_len)
                    },
                )
                .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;
        }

        if self.enabled.contains(&HostFunction::DnsResolve) {
            linker
                .func_wrap(
                    HOST_FUNCTION_NAMESPACE,
                    HOST_DNS_RESOLVE,
                    |mut caller: Caller<RuntimeState>,
                     req_ptr: i32,
                     req_len: i32,
                     resp_ptr: i32|
                     -> i32 {
                        handle_dns_request(&mut caller, req_ptr, req_len, resp_ptr)
                    },
                )
                .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;
        }

        linker
            .func_wrap(
                HOST_FUNCTION_NAMESPACE,
                HOST_LOG_MESSAGE,
                |mut caller: Caller<RuntimeState>, level: i32, msg_ptr: i32, msg_len: i32| {
                    handle_log_message(&mut caller, level, msg_ptr, msg_len);
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_FUNCTION_NAMESPACE,
                HOST_GET_TIMESTAMP,
                |caller: Caller<RuntimeState>| -> i64 { handle_get_timestamp(&caller) },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        Ok(())
    }
}

pub struct NetworkState {
    policy: ValidatedNetworkPolicy,
    audit_logger: Option<Arc<dyn NetworkAuditLogger>>,
    http_client: Client,
    dns_resolver: Resolver,
    dns_cache: HashMap<DnsCacheKey, DnsCacheEntry>,
    requests_made: u32,
    dns_lookups: u32,
    request_timestamps: Vec<Instant>,
    challenge_id: String,
    validator_id: String,
}

impl NetworkState {
    pub fn new(
        policy: NetworkPolicy,
        audit_logger: Option<Arc<dyn NetworkAuditLogger>>,
        challenge_id: String,
        validator_id: String,
    ) -> Result<Self, NetworkStateError> {
        let validated = policy.validate()?;

        let redirect_policy = if validated.limits.max_redirects == 0 {
            Policy::none()
        } else {
            Policy::limited(validated.limits.max_redirects as usize)
        };

        let http_client = Client::builder()
            .timeout(Duration::from_millis(validated.limits.timeout_ms))
            .redirect(redirect_policy)
            .build()
            .map_err(|err| NetworkStateError::HttpClient(err.to_string()))?;

        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.timeout = Duration::from_millis(validated.limits.timeout_ms);
        resolver_opts.attempts = 1;
        resolver_opts.cache_size = 0;
        resolver_opts.use_hosts_file = false;
        resolver_opts.num_concurrent_reqs = 1;

        if validated.dns_policy.cache_ttl_secs > 0 {
            let ttl = Duration::from_secs(validated.dns_policy.cache_ttl_secs);
            resolver_opts.positive_min_ttl = Some(ttl);
            resolver_opts.positive_max_ttl = Some(ttl);
            resolver_opts.negative_min_ttl = Some(ttl);
            resolver_opts.negative_max_ttl = Some(ttl);
        }

        let dns_resolver = Resolver::new(ResolverConfig::default(), resolver_opts)
            .map_err(|err| NetworkStateError::DnsResolver(err.to_string()))?;

        Ok(Self {
            policy: validated,
            audit_logger,
            http_client,
            dns_resolver,
            dns_cache: HashMap::new(),
            requests_made: 0,
            dns_lookups: 0,
            request_timestamps: Vec::new(),
            challenge_id,
            validator_id,
        })
    }

    pub fn requests_made(&self) -> u32 {
        self.requests_made
    }

    pub fn dns_lookups(&self) -> u32 {
        self.dns_lookups
    }

    pub fn reset_counters(&mut self) {
        self.requests_made = 0;
        self.dns_lookups = 0;
        self.request_timestamps.clear();
        self.dns_cache.clear();
    }

    pub fn handle_http_request(
        &mut self,
        request: HttpRequest,
    ) -> Result<HttpResponse, NetworkError> {
        if !self.policy.allow_internet {
            self.audit_denial("http_request denied: network disabled");
            return Err(NetworkError::NetworkDisabled);
        }

        self.ensure_request_budget()?;

        if let Err(e) = self.validate_http_request(&request) {
            self.audit_denial(&format!(
                "http_request policy denied url={} reason={}",
                request.url, e
            ));
            return Err(e);
        }

        self.requests_made = self.requests_made.saturating_add(1);
        self.request_timestamps.push(Instant::now());

        self.audit(NetworkAuditAction::HttpRequest {
            url: request.url.clone(),
            method: request.method,
        });

        let _resolved_ip = self.resolve_and_validate_ip(&request.url)?;

        let method = to_reqwest_method(request.method);
        let mut builder = self.http_client.request(method, &request.url);
        let headers = to_header_map(&request.headers)?;
        builder = builder.headers(headers);

        if !request.body.is_empty() {
            builder = builder.body(request.body.clone());
        }

        let response = builder.send().map_err(map_reqwest_error)?;
        let status = response.status().as_u16();
        let headers = collect_headers(response.headers())?;

        let body = read_response_body(response, self.policy.limits.max_response_bytes)?;

        self.ensure_header_limits(&headers)?;

        self.audit(NetworkAuditAction::HttpResponse {
            status,
            bytes: body.len() as u64,
        });

        info!(
            challenge_id = %self.challenge_id,
            validator_id = %self.validator_id,
            url = %request.url,
            status = status,
            response_bytes = body.len(),
            "http request completed"
        );

        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }

    pub fn handle_dns_request(&mut self, request: DnsRequest) -> Result<DnsResponse, NetworkError> {
        if !self.policy.allow_internet {
            self.audit_denial("dns_lookup denied: network disabled");
            return Err(NetworkError::NetworkDisabled);
        }

        self.ensure_dns_budget()?;

        if let Err(e) = self
            .policy
            .is_dns_lookup_allowed(&request.hostname, request.record_type)
        {
            self.audit_denial(&format!(
                "dns_lookup policy denied hostname={} type={:?} reason={}",
                request.hostname, request.record_type, e
            ));
            return Err(map_policy_error(e));
        }

        self.dns_lookups = self.dns_lookups.saturating_add(1);

        let cache_key = DnsCacheKey::new(&request.hostname, request.record_type);
        if let Some(entry) = self.dns_cache.get(&cache_key) {
            if entry.expires_at > Instant::now() {
                return Ok(DnsResponse {
                    records: entry.records.clone(),
                });
            }
        }

        self.audit(NetworkAuditAction::DnsLookup {
            hostname: request.hostname.clone(),
        });

        let records = resolve_dns(&self.dns_resolver, &request, &self.policy)?;
        if records.is_empty() {
            return Err(NetworkError::DnsFailure("no records returned".to_string()));
        }

        if self.policy.dns_policy.cache_ttl_secs > 0 {
            let expires_at =
                Instant::now() + Duration::from_secs(self.policy.dns_policy.cache_ttl_secs);
            self.dns_cache.insert(
                cache_key,
                DnsCacheEntry {
                    records: records.clone(),
                    expires_at,
                },
            );
        }

        info!(
            challenge_id = %self.challenge_id,
            validator_id = %self.validator_id,
            hostname = %request.hostname,
            record_count = records.len(),
            "dns lookup completed"
        );

        Ok(DnsResponse { records })
    }

    fn ensure_request_budget(&self) -> Result<(), NetworkError> {
        if self.policy.limits.max_requests == 0 {
            return Err(NetworkError::LimitExceeded(
                "http requests disabled".to_string(),
            ));
        }

        if self.requests_made >= self.policy.limits.max_requests {
            self.audit_denial(&format!(
                "http request limit exceeded: {}/{}",
                self.requests_made, self.policy.limits.max_requests
            ));
            return Err(NetworkError::LimitExceeded(
                "http request limit exceeded".to_string(),
            ));
        }

        Ok(())
    }

    fn ensure_dns_budget(&self) -> Result<(), NetworkError> {
        if self.policy.dns_policy.max_lookups == 0 {
            return Err(NetworkError::LimitExceeded(
                "dns lookups disabled".to_string(),
            ));
        }

        if self.dns_lookups >= self.policy.dns_policy.max_lookups {
            self.audit_denial(&format!(
                "dns lookup limit exceeded: {}/{}",
                self.dns_lookups, self.policy.dns_policy.max_lookups
            ));
            return Err(NetworkError::LimitExceeded(
                "dns lookup limit exceeded".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_http_request(&self, request: &HttpRequest) -> Result<(), NetworkError> {
        if request.body.len() as u64 > self.policy.limits.max_request_bytes {
            return Err(NetworkError::LimitExceeded(format!(
                "request body too large: {} > {}",
                request.body.len(),
                self.policy.limits.max_request_bytes
            )));
        }

        self.ensure_header_limits(&request.headers)?;

        self.policy
            .is_http_request_allowed(&request.url)
            .map_err(map_policy_error)
    }

    fn resolve_and_validate_ip(&self, url: &str) -> Result<Option<IpAddr>, NetworkError> {
        let parsed = url::Url::parse(url)
            .map_err(|err| NetworkError::PolicyViolation(format!("invalid url: {err}")))?;

        let host_str = match parsed.host_str() {
            Some(h) => h,
            None => return Ok(None),
        };

        if let Ok(ip) = host_str.parse::<IpAddr>() {
            self.validate_ip_against_policy(ip)?;
            return Ok(Some(ip));
        }

        let lookup = self.dns_resolver.lookup_ip(host_str).map_err(|err| {
            NetworkError::DnsFailure(format!("pre-connect resolve failed: {err}"))
        })?;

        for ip in lookup.iter() {
            self.validate_ip_against_policy(ip)?;
        }

        Ok(lookup.iter().next())
    }

    fn validate_ip_against_policy(&self, ip: IpAddr) -> Result<(), NetworkError> {
        if self.policy.dns_policy.block_private_ranges && is_private_ip(ip) {
            self.audit_denial(&format!("blocked private/reserved IP: {ip}"));
            return Err(NetworkError::PolicyViolation(format!(
                "connection to private/reserved IP blocked: {ip}"
            )));
        }

        if !self.policy.allowed_ip_ranges.is_empty()
            && !self
                .policy
                .allowed_ip_ranges
                .iter()
                .any(|net| net.contains(&ip))
        {
            self.audit_denial(&format!("IP not in allowed ranges: {ip}"));
            return Err(NetworkError::PolicyViolation(format!(
                "IP not in allowed ranges: {ip}"
            )));
        }

        Ok(())
    }

    fn ensure_header_limits(&self, headers: &HashMap<String, String>) -> Result<(), NetworkError> {
        let header_bytes = header_size(headers);
        if header_bytes > self.policy.limits.max_header_bytes {
            return Err(NetworkError::LimitExceeded(format!(
                "header size exceeds limit: {} > {}",
                header_bytes, self.policy.limits.max_header_bytes
            )));
        }

        Ok(())
    }

    fn audit(&self, action: NetworkAuditAction) {
        if !self.policy.audit.enabled {
            return;
        }

        if let Some(logger) = &self.audit_logger {
            let entry = NetworkAuditEntry {
                timestamp: chrono::Utc::now(),
                challenge_id: self.challenge_id.clone(),
                validator_id: self.validator_id.clone(),
                action,
                metadata: self.policy.audit.tags.clone(),
            };
            logger.record(entry);
        }
    }

    fn audit_denial(&self, reason: &str) {
        self.audit(NetworkAuditAction::PolicyDenied {
            reason: reason.to_string(),
        });

        warn!(
            challenge_id = %self.challenge_id,
            validator_id = %self.validator_id,
            reason = %reason,
            "network policy denied"
        );
    }
}

#[derive(Clone, Debug)]
struct DnsCacheEntry {
    records: Vec<String>,
    expires_at: Instant,
}

#[derive(Clone, Debug, Eq)]
struct DnsCacheKey {
    hostname: String,
    record_type: DnsRecordType,
}

impl DnsCacheKey {
    fn new(hostname: &str, record_type: DnsRecordType) -> Self {
        Self {
            hostname: hostname.to_lowercase(),
            record_type,
        }
    }
}

impl PartialEq for DnsCacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.hostname == other.hostname && self.record_type == other.record_type
    }
}

impl Hash for DnsCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hostname.hash(state);
        self.record_type.hash(state);
    }
}

fn handle_http_request(
    caller: &mut Caller<RuntimeState>,
    req_ptr: i32,
    req_len: i32,
    resp_ptr: i32,
    resp_len: i32,
) -> i32 {
    let enforcement = "http_request";
    let request_bytes = match read_memory(caller, req_ptr, req_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(challenge_id = %caller.data().challenge_id, validator_id = %caller.data().validator_id, function = enforcement, error = %err, "host memory read failed");
            return write_result::<HttpResponse>(
                caller,
                resp_ptr,
                resp_len,
                Err(NetworkError::HttpFailure(err)),
            );
        }
    };

    let request = match bincode::deserialize::<HttpRequest>(&request_bytes) {
        Ok(req) => req,
        Err(err) => {
            warn!(challenge_id = %caller.data().challenge_id, validator_id = %caller.data().validator_id, function = enforcement, error = %err, "host request decode failed");
            return write_result::<HttpResponse>(
                caller,
                resp_ptr,
                resp_len,
                Err(NetworkError::HttpFailure(format!(
                    "invalid http request payload: {err}"
                ))),
            );
        }
    };

    let result = caller.data_mut().network_state.handle_http_request(request);
    if let Err(ref err) = result {
        warn!(challenge_id = %caller.data().challenge_id, validator_id = %caller.data().validator_id, function = enforcement, error = %err, "host request denied");
    }
    write_result(caller, resp_ptr, resp_len, result)
}

fn handle_http_get(
    caller: &mut Caller<RuntimeState>,
    req_ptr: i32,
    req_len: i32,
    resp_ptr: i32,
    resp_len: i32,
) -> i32 {
    let enforcement = "http_get";
    let request_bytes = match read_memory(caller, req_ptr, req_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(challenge_id = %caller.data().challenge_id, validator_id = %caller.data().validator_id, function = enforcement, error = %err, "host memory read failed");
            return write_result::<HttpResponse>(
                caller,
                resp_ptr,
                resp_len,
                Err(NetworkError::HttpFailure(err)),
            );
        }
    };

    let request = match bincode::deserialize::<HttpGetRequest>(&request_bytes) {
        Ok(req) => req,
        Err(err) => {
            warn!(challenge_id = %caller.data().challenge_id, validator_id = %caller.data().validator_id, function = enforcement, error = %err, "host request decode failed");
            return write_result::<HttpResponse>(
                caller,
                resp_ptr,
                resp_len,
                Err(NetworkError::HttpFailure(format!(
                    "invalid http get payload: {err}"
                ))),
            );
        }
    };

    let request = HttpRequest {
        method: HttpMethod::Get,
        url: request.url,
        headers: request.headers,
        body: Vec::new(),
    };

    let result = caller.data_mut().network_state.handle_http_request(request);
    if let Err(ref err) = result {
        warn!(challenge_id = %caller.data().challenge_id, validator_id = %caller.data().validator_id, function = enforcement, error = %err, "host request denied");
    }
    write_result(caller, resp_ptr, resp_len, result)
}

fn handle_http_post(
    caller: &mut Caller<RuntimeState>,
    req_ptr: i32,
    req_len: i32,
    resp_ptr: i32,
    resp_len: i32,
) -> i32 {
    let enforcement = "http_post";
    let request_bytes = match read_memory(caller, req_ptr, req_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(challenge_id = %caller.data().challenge_id, validator_id = %caller.data().validator_id, function = enforcement, error = %err, "host memory read failed");
            return write_result::<HttpResponse>(
                caller,
                resp_ptr,
                resp_len,
                Err(NetworkError::HttpFailure(err)),
            );
        }
    };

    let request = match bincode::deserialize::<HttpPostRequest>(&request_bytes) {
        Ok(req) => req,
        Err(err) => {
            warn!(challenge_id = %caller.data().challenge_id, validator_id = %caller.data().validator_id, function = enforcement, error = %err, "host request decode failed");
            return write_result::<HttpResponse>(
                caller,
                resp_ptr,
                resp_len,
                Err(NetworkError::HttpFailure(format!(
                    "invalid http post payload: {err}"
                ))),
            );
        }
    };

    let request = HttpRequest {
        method: HttpMethod::Post,
        url: request.url,
        headers: request.headers,
        body: request.body,
    };

    let result = caller.data_mut().network_state.handle_http_request(request);
    if let Err(ref err) = result {
        warn!(challenge_id = %caller.data().challenge_id, validator_id = %caller.data().validator_id, function = enforcement, error = %err, "host request denied");
    }
    write_result(caller, resp_ptr, resp_len, result)
}

fn handle_dns_request(
    caller: &mut Caller<RuntimeState>,
    req_ptr: i32,
    req_len: i32,
    resp_ptr: i32,
) -> i32 {
    let resp_len = DEFAULT_DNS_BUF_SIZE;
    let enforcement = "dns_resolve";
    let request_bytes = match read_memory(caller, req_ptr, req_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(challenge_id = %caller.data().challenge_id, validator_id = %caller.data().validator_id, function = enforcement, error = %err, "host memory read failed");
            return write_result::<DnsResponse>(
                caller,
                resp_ptr,
                resp_len,
                Err(NetworkError::DnsFailure(err)),
            );
        }
    };

    let request = match bincode::deserialize::<DnsRequest>(&request_bytes) {
        Ok(req) => req,
        Err(err) => {
            warn!(challenge_id = %caller.data().challenge_id, validator_id = %caller.data().validator_id, function = enforcement, error = %err, "host request decode failed");
            return write_result::<DnsResponse>(
                caller,
                resp_ptr,
                resp_len,
                Err(NetworkError::DnsFailure(format!(
                    "invalid dns request payload: {err}"
                ))),
            );
        }
    };

    let result = caller.data_mut().network_state.handle_dns_request(request);
    if let Err(ref err) = result {
        warn!(challenge_id = %caller.data().challenge_id, validator_id = %caller.data().validator_id, function = enforcement, error = %err, "host request denied");
    }
    write_result(caller, resp_ptr, resp_len, result)
}

fn handle_log_message(caller: &mut Caller<RuntimeState>, level: i32, msg_ptr: i32, msg_len: i32) {
    let msg = match read_memory(caller, msg_ptr, msg_len) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                error = %err,
                "log_message: failed to read message from wasm memory"
            );
            return;
        }
    };

    let challenge_id = caller.data().challenge_id.clone();
    match level {
        0 => info!(challenge_id = %challenge_id, "[wasm] {}", msg),
        1 => warn!(challenge_id = %challenge_id, "[wasm] {}", msg),
        _ => error!(challenge_id = %challenge_id, "[wasm] {}", msg),
    }
}

fn handle_get_timestamp(caller: &Caller<RuntimeState>) -> i64 {
    if let Some(ts) = caller.data().fixed_timestamp_ms {
        return ts;
    }
    chrono::Utc::now().timestamp_millis()
}

fn resolve_dns(
    resolver: &Resolver,
    request: &DnsRequest,
    policy: &ValidatedNetworkPolicy,
) -> Result<Vec<String>, NetworkError> {
    match request.record_type {
        DnsRecordType::A | DnsRecordType::Aaaa => {
            let lookup = resolver
                .lookup_ip(request.hostname.as_str())
                .map_err(|err| NetworkError::DnsFailure(err.to_string()))?;
            let records = lookup
                .iter()
                .filter(|ip| match request.record_type {
                    DnsRecordType::A => ip.is_ipv4(),
                    DnsRecordType::Aaaa => ip.is_ipv6(),
                    _ => false,
                })
                .filter(|ip| {
                    if policy.dns_policy.block_private_ranges {
                        !is_private_ip(*ip)
                    } else {
                        true
                    }
                })
                .filter(|ip| {
                    if policy.allowed_ip_ranges.is_empty() {
                        true
                    } else {
                        policy.allowed_ip_ranges.iter().any(|net| net.contains(ip))
                    }
                })
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>();
            Ok(records)
        }
        DnsRecordType::Cname => resolve_generic(resolver, request, RecordType::CNAME),
        DnsRecordType::Txt => resolve_generic(resolver, request, RecordType::TXT),
    }
}

fn resolve_generic(
    resolver: &Resolver,
    request: &DnsRequest,
    record_type: RecordType,
) -> Result<Vec<String>, NetworkError> {
    let lookup = resolver
        .lookup(request.hostname.as_str(), record_type)
        .map_err(|err| NetworkError::DnsFailure(err.to_string()))?;

    Ok(lookup.iter().map(|record| record.to_string()).collect())
}

fn read_response_body(
    mut response: reqwest::blocking::Response,
    max_response_bytes: u64,
) -> Result<Vec<u8>, NetworkError> {
    let mut body = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut total: u64 = 0;
    let max_allowed = max_response_bytes;

    loop {
        let bytes_read = response
            .read(&mut buffer)
            .map_err(|err| NetworkError::HttpFailure(err.to_string()))?;
        if bytes_read == 0 {
            break;
        }
        total = total.saturating_add(bytes_read as u64);
        if total > max_allowed {
            return Err(NetworkError::LimitExceeded(format!(
                "response body too large: exceeded {max_allowed} bytes"
            )));
        }
        body.extend_from_slice(&buffer[..bytes_read]);
    }

    Ok(body)
}

fn to_reqwest_method(method: HttpMethod) -> reqwest::Method {
    match method {
        HttpMethod::Get => reqwest::Method::GET,
        HttpMethod::Post => reqwest::Method::POST,
        HttpMethod::Put => reqwest::Method::PUT,
        HttpMethod::Patch => reqwest::Method::PATCH,
        HttpMethod::Delete => reqwest::Method::DELETE,
        HttpMethod::Head => reqwest::Method::HEAD,
        HttpMethod::Options => reqwest::Method::OPTIONS,
    }
}

fn to_header_map(headers: &HashMap<String, String>) -> Result<HeaderMap, NetworkError> {
    let mut header_map = HeaderMap::new();
    for (key, value) in headers {
        let name = HeaderName::from_bytes(key.as_bytes())
            .map_err(|err| NetworkError::HttpFailure(err.to_string()))?;
        let header_value = HeaderValue::from_str(value)
            .map_err(|err| NetworkError::HttpFailure(err.to_string()))?;
        header_map.insert(name, header_value);
    }
    Ok(header_map)
}

fn collect_headers(headers: &HeaderMap) -> Result<HashMap<String, String>, NetworkError> {
    let mut result: HashMap<String, String> = HashMap::new();
    for (name, value) in headers.iter() {
        let value = value
            .to_str()
            .map_err(|err| NetworkError::HttpFailure(err.to_string()))?;
        result
            .entry(name.as_str().to_string())
            .and_modify(|existing| {
                existing.push(',');
                existing.push_str(value);
            })
            .or_insert_with(|| value.to_string());
    }
    Ok(result)
}

fn header_size(headers: &HashMap<String, String>) -> u64 {
    headers
        .iter()
        .map(|(key, value)| (key.len() + value.len()) as u64)
        .sum()
}

fn map_policy_error(err: NetworkPolicyError) -> NetworkError {
    match err {
        NetworkPolicyError::NetworkDisabled => NetworkError::NetworkDisabled,
        other => NetworkError::PolicyViolation(other.to_string()),
    }
}

fn map_reqwest_error(err: reqwest::Error) -> NetworkError {
    if err.is_timeout() {
        NetworkError::Timeout
    } else {
        NetworkError::HttpFailure(err.to_string())
    }
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => {
            addr.is_private()
                || addr.is_loopback()
                || addr.is_link_local()
                || addr.is_broadcast()
                || addr.is_unspecified()
                || addr.is_multicast()
                || is_cgnat(addr)
                || is_documentation_v4(addr)
        }
        IpAddr::V6(addr) => {
            addr.is_loopback()
                || addr.is_unspecified()
                || addr.is_unique_local()
                || addr.is_unicast_link_local()
                || addr.is_multicast()
        }
    }
}

fn is_cgnat(addr: std::net::Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_documentation_v4(addr: std::net::Ipv4Addr) -> bool {
    let octets = addr.octets();
    (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
}

fn read_memory(caller: &mut Caller<RuntimeState>, ptr: i32, len: i32) -> Result<Vec<u8>, String> {
    if ptr < 0 || len < 0 {
        return Err("negative pointer/length".to_string());
    }
    let ptr = ptr as usize;
    let len = len as usize;
    let memory = get_memory(caller).ok_or_else(|| "memory export not found".to_string())?;
    let data = memory.data(caller);
    let end = ptr
        .checked_add(len)
        .ok_or_else(|| "pointer overflow".to_string())?;
    if end > data.len() {
        return Err("memory read out of bounds".to_string());
    }
    Ok(data[ptr..end].to_vec())
}

fn write_result<T: serde::Serialize>(
    caller: &mut Caller<RuntimeState>,
    resp_ptr: i32,
    resp_len: i32,
    result: Result<T, NetworkError>,
) -> i32 {
    let response_bytes = match bincode::serialize(&result) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "failed to serialize response");
            return -1;
        }
    };

    write_bytes(caller, resp_ptr, resp_len, &response_bytes)
}

fn write_bytes(
    caller: &mut Caller<RuntimeState>,
    resp_ptr: i32,
    resp_len: i32,
    bytes: &[u8],
) -> i32 {
    if resp_ptr < 0 || resp_len < 0 {
        return -1;
    }
    if bytes.len() > i32::MAX as usize {
        return -1;
    }
    let resp_len = resp_len as usize;
    if bytes.len() > resp_len {
        return -(bytes.len() as i32);
    }

    let memory = match get_memory(caller) {
        Some(memory) => memory,
        None => return -1,
    };

    let ptr = resp_ptr as usize;
    let end = match ptr.checked_add(bytes.len()) {
        Some(end) => end,
        None => return -1,
    };
    let data = memory.data_mut(caller);
    if end > data.len() {
        return -1;
    }
    data[ptr..end].copy_from_slice(bytes);
    bytes.len() as i32
}

fn get_memory(caller: &mut Caller<RuntimeState>) -> Option<Memory> {
    let memory_export = caller.data().memory_export.clone();
    caller
        .get_export(&memory_export)
        .and_then(|export| export.into_memory())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DnsPolicy;

    fn test_policy_strict(hosts: Vec<String>) -> NetworkPolicy {
        NetworkPolicy::strict(hosts)
    }

    fn test_policy_with_dns(hosts: Vec<String>, dns_hosts: Vec<String>) -> NetworkPolicy {
        let mut policy = NetworkPolicy::strict(hosts);
        policy.dns_policy = DnsPolicy {
            enabled: true,
            allowed_hosts: dns_hosts,
            allowed_record_types: vec![DnsRecordType::A, DnsRecordType::Aaaa],
            max_lookups: 8,
            cache_ttl_secs: 60,
            block_private_ranges: true,
        };
        policy
    }

    #[test]
    fn test_network_state_creation() {
        let policy = test_policy_strict(vec!["example.com".to_string()]);
        let state = NetworkState::new(
            policy,
            None,
            "test-challenge".into(),
            "test-validator".into(),
        );
        assert!(state.is_ok());
        let state = state.unwrap();
        assert_eq!(state.requests_made(), 0);
        assert_eq!(state.dns_lookups(), 0);
    }

    #[test]
    fn test_request_budget_enforcement() {
        let mut policy = test_policy_strict(vec!["example.com".to_string()]);
        policy.limits.max_requests = 2;
        let mut state = NetworkState::new(policy, None, "test".into(), "test".into()).unwrap();

        assert!(state.ensure_request_budget().is_ok());
        state.requests_made = 2;
        let err = state.ensure_request_budget().unwrap_err();
        assert!(matches!(err, NetworkError::LimitExceeded(_)));
    }

    #[test]
    fn test_dns_budget_enforcement() {
        let mut policy = test_policy_with_dns(
            vec!["example.com".to_string()],
            vec!["example.com".to_string()],
        );
        policy.dns_policy.max_lookups = 3;
        let mut state = NetworkState::new(policy, None, "test".into(), "test".into()).unwrap();

        assert!(state.ensure_dns_budget().is_ok());
        state.dns_lookups = 3;
        let err = state.ensure_dns_budget().unwrap_err();
        assert!(matches!(err, NetworkError::LimitExceeded(_)));
    }

    #[test]
    fn test_request_budget_zero_disabled() {
        let mut policy = test_policy_strict(vec!["example.com".to_string()]);
        policy.limits.max_requests = 0;
        let state = NetworkState::new(policy, None, "test".into(), "test".into()).unwrap();

        let err = state.ensure_request_budget().unwrap_err();
        assert!(matches!(err, NetworkError::LimitExceeded(_)));
    }

    #[test]
    fn test_dns_budget_zero_disabled() {
        let mut policy = test_policy_with_dns(
            vec!["example.com".to_string()],
            vec!["example.com".to_string()],
        );
        policy.dns_policy.max_lookups = 0;
        let state = NetworkState::new(policy, None, "test".into(), "test".into()).unwrap();

        let err = state.ensure_dns_budget().unwrap_err();
        assert!(matches!(err, NetworkError::LimitExceeded(_)));
    }

    #[test]
    fn test_validate_http_request_body_too_large() {
        let mut policy = test_policy_strict(vec!["example.com".to_string()]);
        policy.limits.max_request_bytes = 10;
        let state = NetworkState::new(policy, None, "test".into(), "test".into()).unwrap();

        let request = HttpRequest {
            method: HttpMethod::Get,
            url: "https://example.com".to_string(),
            headers: HashMap::new(),
            body: vec![0u8; 100],
        };

        let err = state.validate_http_request(&request).unwrap_err();
        assert!(matches!(err, NetworkError::LimitExceeded(_)));
    }

    #[test]
    fn test_validate_http_request_headers_too_large() {
        let mut policy = test_policy_strict(vec!["example.com".to_string()]);
        policy.limits.max_header_bytes = 10;
        let state = NetworkState::new(policy, None, "test".into(), "test".into()).unwrap();

        let mut headers = HashMap::new();
        headers.insert("x-large".to_string(), "a".repeat(100));

        let request = HttpRequest {
            method: HttpMethod::Get,
            url: "https://example.com".to_string(),
            headers,
            body: Vec::new(),
        };

        let err = state.validate_http_request(&request).unwrap_err();
        assert!(matches!(err, NetworkError::LimitExceeded(_)));
    }

    #[test]
    fn test_validate_http_request_url_policy() {
        let policy = test_policy_strict(vec!["example.com".to_string()]);
        let state = NetworkState::new(policy, None, "test".into(), "test".into()).unwrap();

        let request = HttpRequest {
            method: HttpMethod::Get,
            url: "https://evil.com".to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        };

        let err = state.validate_http_request(&request).unwrap_err();
        assert!(matches!(err, NetworkError::PolicyViolation(_)));
    }

    #[test]
    fn test_validate_http_request_allowed() {
        let policy = test_policy_strict(vec!["example.com".to_string()]);
        let state = NetworkState::new(policy, None, "test".into(), "test".into()).unwrap();

        let request = HttpRequest {
            method: HttpMethod::Get,
            url: "https://example.com/api".to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        };

        assert!(state.validate_http_request(&request).is_ok());
    }

    #[test]
    fn test_is_private_ip_v4() {
        assert!(is_private_ip(IpAddr::V4(std::net::Ipv4Addr::new(
            127, 0, 0, 1
        ))));
        assert!(is_private_ip(IpAddr::V4(std::net::Ipv4Addr::new(
            10, 0, 0, 1
        ))));
        assert!(is_private_ip(IpAddr::V4(std::net::Ipv4Addr::new(
            192, 168, 1, 1
        ))));
        assert!(is_private_ip(IpAddr::V4(std::net::Ipv4Addr::new(
            172, 16, 0, 1
        ))));
        assert!(is_private_ip(IpAddr::V4(std::net::Ipv4Addr::new(
            169, 254, 1, 1
        ))));
        assert!(is_private_ip(IpAddr::V4(std::net::Ipv4Addr::new(
            0, 0, 0, 0
        ))));
        assert!(!is_private_ip(IpAddr::V4(std::net::Ipv4Addr::new(
            8, 8, 8, 8
        ))));
        assert!(!is_private_ip(IpAddr::V4(std::net::Ipv4Addr::new(
            1, 1, 1, 1
        ))));
    }

    #[test]
    fn test_is_private_ip_v6() {
        assert!(is_private_ip(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
        assert!(is_private_ip(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)));
        assert!(!is_private_ip(IpAddr::V6(
            "2001:4860:4860::8888".parse().unwrap()
        )));
    }

    #[test]
    fn test_is_cgnat() {
        assert!(is_cgnat(std::net::Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_cgnat(std::net::Ipv4Addr::new(100, 127, 255, 254)));
        assert!(!is_cgnat(std::net::Ipv4Addr::new(100, 128, 0, 1)));
        assert!(!is_cgnat(std::net::Ipv4Addr::new(100, 63, 255, 255)));
    }

    #[test]
    fn test_is_documentation_v4() {
        assert!(is_documentation_v4(std::net::Ipv4Addr::new(192, 0, 2, 1)));
        assert!(is_documentation_v4(std::net::Ipv4Addr::new(
            198, 51, 100, 1
        )));
        assert!(is_documentation_v4(std::net::Ipv4Addr::new(203, 0, 113, 1)));
        assert!(!is_documentation_v4(std::net::Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_reset_counters() {
        let policy = test_policy_strict(vec!["example.com".to_string()]);
        let mut state = NetworkState::new(policy, None, "test".into(), "test".into()).unwrap();

        state.requests_made = 5;
        state.dns_lookups = 3;
        state.request_timestamps.push(Instant::now());

        state.reset_counters();

        assert_eq!(state.requests_made(), 0);
        assert_eq!(state.dns_lookups(), 0);
        assert!(state.request_timestamps.is_empty());
        assert!(state.dns_cache.is_empty());
    }

    #[test]
    fn test_validate_ip_against_policy_private_blocked() {
        let mut policy = test_policy_strict(vec!["example.com".to_string()]);
        policy.dns_policy.block_private_ranges = true;
        let state = NetworkState::new(policy, None, "test".into(), "test".into()).unwrap();

        let loopback = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
        let err = state.validate_ip_against_policy(loopback).unwrap_err();
        assert!(matches!(err, NetworkError::PolicyViolation(_)));
    }

    #[test]
    fn test_validate_ip_against_policy_public_allowed() {
        let mut policy = test_policy_strict(vec!["example.com".to_string()]);
        policy.dns_policy.block_private_ranges = true;
        let state = NetworkState::new(policy, None, "test".into(), "test".into()).unwrap();

        let public = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        assert!(state.validate_ip_against_policy(public).is_ok());
    }

    #[test]
    fn test_validate_ip_against_policy_ip_range_filter() {
        let mut policy = test_policy_strict(vec!["example.com".to_string()]);
        policy.dns_policy.block_private_ranges = false;
        policy.allowed_ip_ranges = vec!["8.8.0.0/16".to_string()];
        let state = NetworkState::new(policy, None, "test".into(), "test".into()).unwrap();

        let allowed = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        assert!(state.validate_ip_against_policy(allowed).is_ok());

        let denied = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
        let err = state.validate_ip_against_policy(denied).unwrap_err();
        assert!(matches!(err, NetworkError::PolicyViolation(_)));
    }

    #[test]
    fn test_validate_ip_against_policy_empty_ranges_no_block() {
        let mut policy = test_policy_strict(vec!["example.com".to_string()]);
        policy.dns_policy.block_private_ranges = false;
        policy.allowed_ip_ranges = vec![];
        let state = NetworkState::new(policy, None, "test".into(), "test".into()).unwrap();

        let any_ip = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        assert!(state.validate_ip_against_policy(any_ip).is_ok());
    }

    #[test]
    fn test_audit_denial_logged() {
        use std::sync::Mutex;

        struct TestLogger {
            entries: Mutex<Vec<NetworkAuditEntry>>,
        }

        impl NetworkAuditLogger for TestLogger {
            fn record(&self, entry: NetworkAuditEntry) {
                self.entries.lock().unwrap().push(entry);
            }
        }

        let logger = Arc::new(TestLogger {
            entries: Mutex::new(Vec::new()),
        });

        let mut policy = test_policy_strict(vec!["example.com".to_string()]);
        policy.audit.enabled = true;
        let state = NetworkState::new(
            policy,
            Some(logger.clone()),
            "chal-1".into(),
            "val-1".into(),
        )
        .unwrap();

        state.audit_denial("test denial reason");

        let entries = logger.entries.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].challenge_id, "chal-1");
        assert_eq!(entries[0].validator_id, "val-1");
        match &entries[0].action {
            NetworkAuditAction::PolicyDenied { reason } => {
                assert!(reason.contains("test denial reason"));
            }
            _ => panic!("expected PolicyDenied action"),
        }
    }

    #[test]
    fn test_header_size_calculation() {
        let mut headers = HashMap::new();
        headers.insert("key1".to_string(), "val1".to_string());
        headers.insert("key2".to_string(), "val2".to_string());
        assert_eq!(header_size(&headers), 16);
    }

    #[test]
    fn test_network_disabled_policy() {
        let policy = NetworkPolicy::default();
        let state = NetworkState::new(policy, None, "test".into(), "test".into()).unwrap();

        let request = HttpRequest {
            method: HttpMethod::Get,
            url: "https://example.com".to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        };

        let err = state.validate_http_request(&request).unwrap_err();
        assert!(matches!(err, NetworkError::NetworkDisabled));
    }

    #[test]
    fn test_map_policy_error_network_disabled() {
        let err = map_policy_error(NetworkPolicyError::NetworkDisabled);
        assert!(matches!(err, NetworkError::NetworkDisabled));
    }

    #[test]
    fn test_map_policy_error_other() {
        let err = map_policy_error(NetworkPolicyError::HostNotAllowed("evil.com".into()));
        assert!(matches!(err, NetworkError::PolicyViolation(_)));
    }
}
