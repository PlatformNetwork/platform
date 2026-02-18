//! Container Host Functions for WASM Challenges
//!
//! This module provides host functions that allow WASM code to delegate
//! container execution to the host. All operations are gated by `ContainerPolicy`.
//!
//! # Host Functions
//!
//! - `container_run(req_ptr, req_len, resp_ptr, resp_len) -> i32` - Run a container

use crate::runtime::{HostFunctionRegistrar, RuntimeState, WasmRuntimeError};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::{Duration, Instant};
use tracing::{info, warn};
use wasmtime::{Caller, Linker, Memory};

pub const HOST_CONTAINER_NAMESPACE: &str = "platform_container";
pub const HOST_CONTAINER_RUN: &str = "container_run";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ContainerHostStatus {
    Success = 0,
    Disabled = 1,
    ImageNotAllowed = -1,
    ExecutionTimeout = -2,
    ExecutionFailed = -3,
    ResourceLimitExceeded = -4,
    InternalError = -100,
}

impl ContainerHostStatus {
    pub fn to_i32(self) -> i32 {
        self as i32
    }

    pub fn from_i32(code: i32) -> Self {
        match code {
            0 => Self::Success,
            1 => Self::Disabled,
            -1 => Self::ImageNotAllowed,
            -2 => Self::ExecutionTimeout,
            -3 => Self::ExecutionFailed,
            -4 => Self::ResourceLimitExceeded,
            _ => Self::InternalError,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerPolicy {
    pub enabled: bool,
    pub allowed_images: Vec<String>,
    pub max_memory_mb: u64,
    pub max_cpu_count: u32,
    pub max_execution_time_secs: u64,
    pub allow_network: bool,
    pub max_containers_per_execution: u32,
}

impl Default for ContainerPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_images: Vec::new(),
            max_memory_mb: 512,
            max_cpu_count: 1,
            max_execution_time_secs: 60,
            allow_network: false,
            max_containers_per_execution: 4,
        }
    }
}

impl ContainerPolicy {
    pub fn development() -> Self {
        Self {
            enabled: true,
            allowed_images: vec!["*".to_string()],
            max_memory_mb: 2048,
            max_cpu_count: 4,
            max_execution_time_secs: 300,
            allow_network: true,
            max_containers_per_execution: 16,
        }
    }

    pub fn is_image_allowed(&self, image: &str) -> bool {
        if !self.enabled {
            return false;
        }
        self.allowed_images
            .iter()
            .any(|i| i == "*" || i == image || image.starts_with(&format!("{}:", i)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRunRequest {
    pub image: String,
    pub command: Vec<String>,
    pub env_vars: Vec<(String, String)>,
    pub working_dir: Option<String>,
    pub stdin: Option<Vec<u8>>,
    pub memory_limit_mb: Option<u64>,
    pub cpu_limit: Option<u32>,
    pub network_mode: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRunResponse {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ContainerExecError {
    Disabled,
    ImageNotAllowed(String),
    ExecutionTimeout(u64),
    ExecutionFailed(String),
    ResourceLimitExceeded(String),
    MemoryError(String),
}

pub struct ContainerState {
    pub policy: ContainerPolicy,
    pub challenge_id: String,
    pub validator_id: String,
    pub containers_run: u32,
}

impl ContainerState {
    pub fn new(policy: ContainerPolicy, challenge_id: String, validator_id: String) -> Self {
        Self {
            policy,
            challenge_id,
            validator_id,
            containers_run: 0,
        }
    }

    pub fn reset_counters(&mut self) {
        self.containers_run = 0;
    }
}

#[derive(Clone, Debug)]
pub struct ContainerHostFunctions;

impl ContainerHostFunctions {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ContainerHostFunctions {
    fn default() -> Self {
        Self::new()
    }
}

impl HostFunctionRegistrar for ContainerHostFunctions {
    fn register(&self, linker: &mut Linker<RuntimeState>) -> Result<(), WasmRuntimeError> {
        linker
            .func_wrap(
                HOST_CONTAINER_NAMESPACE,
                HOST_CONTAINER_RUN,
                |mut caller: Caller<RuntimeState>,
                 req_ptr: i32,
                 req_len: i32,
                 resp_ptr: i32,
                 resp_len: i32|
                 -> i32 {
                    handle_container_run(&mut caller, req_ptr, req_len, resp_ptr, resp_len)
                },
            )
            .map_err(|e| {
                WasmRuntimeError::HostFunction(format!(
                    "failed to register {}: {}",
                    HOST_CONTAINER_RUN, e
                ))
            })?;

        Ok(())
    }
}

fn handle_container_run(
    caller: &mut Caller<RuntimeState>,
    req_ptr: i32,
    req_len: i32,
    resp_ptr: i32,
    resp_len: i32,
) -> i32 {
    let request_bytes = match read_memory(caller, req_ptr, req_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                error = %err,
                "container_run: host memory read failed"
            );
            return write_result(
                caller,
                resp_ptr,
                resp_len,
                Err::<ContainerRunResponse, ContainerExecError>(ContainerExecError::MemoryError(
                    err,
                )),
            );
        }
    };

    let request = match bincode::deserialize::<ContainerRunRequest>(&request_bytes) {
        Ok(req) => req,
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                error = %err,
                "container_run: request decode failed"
            );
            return write_result(
                caller,
                resp_ptr,
                resp_len,
                Err::<ContainerRunResponse, ContainerExecError>(
                    ContainerExecError::ExecutionFailed(format!(
                        "invalid container run request: {err}"
                    )),
                ),
            );
        }
    };

    let policy = &caller.data().container_state.policy;

    if !policy.enabled {
        return write_result(
            caller,
            resp_ptr,
            resp_len,
            Err::<ContainerRunResponse, ContainerExecError>(ContainerExecError::Disabled),
        );
    }

    if !policy.is_image_allowed(&request.image) {
        warn!(
            challenge_id = %caller.data().challenge_id,
            image = %request.image,
            "container_run: image not allowed"
        );
        return write_result(
            caller,
            resp_ptr,
            resp_len,
            Err::<ContainerRunResponse, ContainerExecError>(ContainerExecError::ImageNotAllowed(
                request.image,
            )),
        );
    }

    if caller.data().container_state.containers_run
        >= caller
            .data()
            .container_state
            .policy
            .max_containers_per_execution
    {
        return write_result(
            caller,
            resp_ptr,
            resp_len,
            Err::<ContainerRunResponse, ContainerExecError>(
                ContainerExecError::ResourceLimitExceeded("container limit exceeded".to_string()),
            ),
        );
    }

    let timeout_secs = policy.max_execution_time_secs;
    let timeout_ms = if request.timeout_ms > 0 {
        request.timeout_ms.min(timeout_secs.saturating_mul(1000))
    } else {
        timeout_secs.saturating_mul(1000)
    };
    let timeout = Duration::from_millis(timeout_ms);

    let memory_limit = request
        .memory_limit_mb
        .unwrap_or(policy.max_memory_mb)
        .min(policy.max_memory_mb);

    let network_mode = if policy.allow_network {
        request.network_mode.as_deref().unwrap_or("bridge")
    } else {
        "none"
    };

    let result = execute_container(&request, timeout, memory_limit, network_mode);

    let challenge_id = caller.data().challenge_id.clone();
    let validator_id = caller.data().validator_id.clone();

    match &result {
        Ok(resp) => {
            caller.data_mut().container_state.containers_run += 1;
            info!(
                challenge_id = %challenge_id,
                validator_id = %validator_id,
                image = %request.image,
                exit_code = resp.exit_code,
                stdout_bytes = resp.stdout.len(),
                stderr_bytes = resp.stderr.len(),
                duration_ms = resp.duration_ms,
                "container_run completed"
            );
        }
        Err(err) => {
            warn!(
                challenge_id = %challenge_id,
                validator_id = %validator_id,
                image = %request.image,
                error = ?err,
                "container_run failed"
            );
        }
    }

    write_result(caller, resp_ptr, resp_len, result)
}

fn execute_container(
    request: &ContainerRunRequest,
    timeout: Duration,
    memory_limit_mb: u64,
    network_mode: &str,
) -> Result<ContainerRunResponse, ContainerExecError> {
    let start = Instant::now();

    let mut cmd = Command::new("docker");
    cmd.arg("run");
    cmd.arg("--rm");
    cmd.args(["--network", network_mode]);
    cmd.args(["--memory", &format!("{}m", memory_limit_mb)]);

    for (key, value) in &request.env_vars {
        cmd.args(["-e", &format!("{}={}", key, value)]);
    }

    if let Some(ref dir) = request.working_dir {
        cmd.args(["-w", dir]);
    }

    cmd.arg(&request.image);
    for arg in &request.command {
        cmd.arg(arg);
    }

    let has_stdin = request.stdin.as_ref().is_some_and(|s| !s.is_empty());

    if has_stdin {
        cmd.stdin(std::process::Stdio::piped());
    } else {
        cmd.stdin(std::process::Stdio::null());
    }
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| ContainerExecError::ExecutionFailed(e.to_string()))?;

    if has_stdin {
        if let Some(ref stdin_data) = request.stdin {
            if let Some(ref mut stdin) = child.stdin {
                use std::io::Write;
                let _ = stdin.write_all(stdin_data);
            }
        }
        child.stdin.take();
    }

    let output = loop {
        if start.elapsed() > timeout {
            let _ = child.kill();
            return Err(ContainerExecError::ExecutionTimeout(timeout.as_secs()));
        }
        match child.try_wait() {
            Ok(Some(_)) => {
                break child
                    .wait_with_output()
                    .map_err(|e| ContainerExecError::ExecutionFailed(e.to_string()))?
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(ContainerExecError::ExecutionFailed(e.to_string())),
        }
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(ContainerRunResponse {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: output.stdout,
        stderr: output.stderr,
        duration_ms,
    })
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

fn write_result<T: serde::Serialize, E: serde::Serialize>(
    caller: &mut Caller<RuntimeState>,
    resp_ptr: i32,
    resp_len: i32,
    result: Result<T, E>,
) -> i32 {
    let response_bytes = match bincode::serialize(&result) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "failed to serialize container response");
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

    #[test]
    fn test_container_host_status_conversion() {
        assert_eq!(ContainerHostStatus::Success.to_i32(), 0);
        assert_eq!(ContainerHostStatus::Disabled.to_i32(), 1);
        assert_eq!(ContainerHostStatus::ImageNotAllowed.to_i32(), -1);
        assert_eq!(ContainerHostStatus::InternalError.to_i32(), -100);

        assert_eq!(
            ContainerHostStatus::from_i32(0),
            ContainerHostStatus::Success
        );
        assert_eq!(
            ContainerHostStatus::from_i32(1),
            ContainerHostStatus::Disabled
        );
        assert_eq!(
            ContainerHostStatus::from_i32(-999),
            ContainerHostStatus::InternalError
        );
    }

    #[test]
    fn test_container_policy_default() {
        let policy = ContainerPolicy::default();
        assert!(!policy.enabled);
        assert!(policy.allowed_images.is_empty());
        assert!(!policy.is_image_allowed("ubuntu"));
    }

    #[test]
    fn test_container_policy_development() {
        let policy = ContainerPolicy::development();
        assert!(policy.enabled);
        assert!(policy.is_image_allowed("ubuntu"));
        assert!(policy.is_image_allowed("python:3.11"));
    }

    #[test]
    fn test_container_policy_image_check() {
        let policy = ContainerPolicy {
            enabled: true,
            allowed_images: vec!["ubuntu".to_string(), "python".to_string()],
            ..Default::default()
        };
        assert!(policy.is_image_allowed("ubuntu"));
        assert!(policy.is_image_allowed("python:3.11"));
        assert!(!policy.is_image_allowed("alpine"));
    }

    #[test]
    fn test_container_state_creation() {
        let state = ContainerState::new(
            ContainerPolicy::default(),
            "test".to_string(),
            "test".to_string(),
        );
        assert_eq!(state.containers_run, 0);
    }

    #[test]
    fn test_container_state_reset() {
        let mut state = ContainerState::new(
            ContainerPolicy::default(),
            "test".to_string(),
            "test".to_string(),
        );
        state.containers_run = 5;
        state.reset_counters();
        assert_eq!(state.containers_run, 0);
    }

    #[test]
    fn test_container_run_request_serialization() {
        let request = ContainerRunRequest {
            image: "ubuntu:22.04".to_string(),
            command: vec!["echo".to_string(), "hello".to_string()],
            env_vars: vec![("KEY".to_string(), "VALUE".to_string())],
            working_dir: None,
            stdin: None,
            memory_limit_mb: Some(256),
            cpu_limit: Some(1),
            network_mode: None,
            timeout_ms: 5000,
        };

        let bytes = bincode::serialize(&request).unwrap();
        let deserialized: ContainerRunRequest = bincode::deserialize(&bytes).unwrap();
        assert_eq!(deserialized.image, "ubuntu:22.04");
        assert_eq!(deserialized.command, vec!["echo", "hello"]);
    }
}
