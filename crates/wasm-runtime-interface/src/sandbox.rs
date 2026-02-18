//! Sandbox Host Functions for WASM Challenges
//!
//! This module provides host functions that allow WASM code to interact with
//! sandboxed command execution. All operations are gated by `SandboxPolicy`.
//!
//! # Host Functions
//!
//! - `sandbox_exec(cmd_ptr, cmd_len) -> i64` - Execute a sandboxed command
//! - `sandbox_get_tasks() -> i64` - Retrieve pending task list
//! - `sandbox_configure(cfg_ptr, cfg_len) -> i32` - Update sandbox configuration
//! - `sandbox_status() -> i32` - Query sandbox status
//! - `get_timestamp() -> i64` - Get current timestamp in milliseconds
//! - `log_message(level, msg_ptr, msg_len)` - Log a message from WASM

#![allow(dead_code, unused_variables, unused_imports)]

use crate::SandboxPolicy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, warn};
use wasmtime::{Caller, Linker, Memory};

use crate::runtime::{HostFunctionRegistrar, RuntimeState, WasmRuntimeError};

pub const HOST_SANDBOX_NAMESPACE: &str = "platform_sandbox";
pub const HOST_SANDBOX_EXEC: &str = "sandbox_exec";
pub const HOST_SANDBOX_GET_TASKS: &str = "sandbox_get_tasks";
pub const HOST_SANDBOX_CONFIGURE: &str = "sandbox_configure";
pub const HOST_SANDBOX_STATUS: &str = "sandbox_status";
pub const HOST_SANDBOX_GET_TIMESTAMP: &str = "get_timestamp";
pub const HOST_SANDBOX_LOG_MESSAGE: &str = "log_message";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SandboxHostStatus {
    Success = 0,
    Disabled = 1,
    CommandNotAllowed = -1,
    ExecutionTimeout = -2,
    ExecutionFailed = -3,
    InvalidConfig = -4,
    InternalError = -100,
}

impl SandboxHostStatus {
    pub fn to_i32(self) -> i32 {
        self as i32
    }

    pub fn from_i32(code: i32) -> Self {
        match code {
            0 => Self::Success,
            1 => Self::Disabled,
            -1 => Self::CommandNotAllowed,
            -2 => Self::ExecutionTimeout,
            -3 => Self::ExecutionFailed,
            -4 => Self::InvalidConfig,
            _ => Self::InternalError,
        }
    }
}

#[derive(Debug, Error)]
pub enum SandboxHostError {
    #[error("sandbox disabled")]
    Disabled,

    #[error("command not allowed: {0}")]
    CommandNotAllowed(String),

    #[error("execution timeout after {0}s")]
    ExecutionTimeout(u64),

    #[error("execution failed: {0}")]
    ExecutionFailed(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("memory error: {0}")]
    MemoryError(String),

    #[error("internal error: {0}")]
    InternalError(String),
}

impl From<SandboxHostError> for SandboxHostStatus {
    fn from(err: SandboxHostError) -> Self {
        match err {
            SandboxHostError::Disabled => Self::Disabled,
            SandboxHostError::CommandNotAllowed(_) => Self::CommandNotAllowed,
            SandboxHostError::ExecutionTimeout(_) => Self::ExecutionTimeout,
            SandboxHostError::ExecutionFailed(_) => Self::ExecutionFailed,
            SandboxHostError::InvalidConfig(_) => Self::InvalidConfig,
            SandboxHostError::MemoryError(_) => Self::InternalError,
            SandboxHostError::InternalError(_) => Self::InternalError,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxExecRequest {
    pub command: String,
    pub args: Vec<String>,
    pub env_vars: Vec<(String, String)>,
    pub working_dir: Option<String>,
    pub stdin: Option<Vec<u8>>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxExecResponse {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SandboxExecError {
    Disabled,
    CommandNotAllowed(String),
    ExecutionTimeout(u64),
    ExecutionFailed(String),
    MemoryError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxHostConfig {
    pub policy: SandboxPolicy,
    pub max_concurrent_tasks: usize,
    pub max_output_bytes: usize,
}

impl Default for SandboxHostConfig {
    fn default() -> Self {
        Self {
            policy: SandboxPolicy::default(),
            max_concurrent_tasks: 4,
            max_output_bytes: 1024 * 1024,
        }
    }
}

impl SandboxHostConfig {
    pub fn permissive() -> Self {
        Self {
            policy: SandboxPolicy::development(),
            max_concurrent_tasks: 16,
            max_output_bytes: 10 * 1024 * 1024,
        }
    }

    pub fn is_command_allowed(&self, command: &str) -> bool {
        if !self.policy.enable_sandbox {
            return false;
        }
        self.policy
            .allowed_commands
            .iter()
            .any(|c| c == "*" || c == command)
    }
}

pub struct SandboxHostState {
    pub config: SandboxHostConfig,
    pub challenge_id: String,
    pub pending_results: HashMap<u32, Vec<u8>>,
    pub next_result_id: u32,
    pub commands_executed: u32,
}

impl SandboxHostState {
    pub fn new(challenge_id: String, config: SandboxHostConfig) -> Self {
        Self {
            config,
            challenge_id,
            pending_results: HashMap::new(),
            next_result_id: 1,
            commands_executed: 0,
        }
    }

    pub fn store_result(&mut self, data: Vec<u8>) -> u32 {
        let id = self.next_result_id;
        self.next_result_id = self.next_result_id.wrapping_add(1);
        self.pending_results.insert(id, data);
        id
    }

    pub fn take_result(&mut self, id: u32) -> Option<Vec<u8>> {
        self.pending_results.remove(&id)
    }

    pub fn reset_counters(&mut self) {
        self.commands_executed = 0;
    }
}

pub struct SandboxHostFunctions;

impl SandboxHostFunctions {
    pub fn all() -> Self {
        Self
    }
}

impl HostFunctionRegistrar for SandboxHostFunctions {
    fn register(&self, linker: &mut Linker<RuntimeState>) -> Result<(), WasmRuntimeError> {
        linker
            .func_wrap(HOST_SANDBOX_NAMESPACE, HOST_SANDBOX_STATUS, || -> i32 {
                SandboxHostStatus::Success.to_i32()
            })
            .map_err(|e| {
                WasmRuntimeError::HostFunction(format!(
                    "failed to register {}: {}",
                    HOST_SANDBOX_STATUS, e
                ))
            })?;

        linker
            .func_wrap(
                HOST_SANDBOX_NAMESPACE,
                HOST_SANDBOX_EXEC,
                |mut caller: Caller<RuntimeState>,
                 req_ptr: i32,
                 req_len: i32,
                 resp_ptr: i32,
                 resp_len: i32|
                 -> i32 {
                    handle_sandbox_exec(&mut caller, req_ptr, req_len, resp_ptr, resp_len)
                },
            )
            .map_err(|e| {
                WasmRuntimeError::HostFunction(format!(
                    "failed to register {}: {}",
                    HOST_SANDBOX_EXEC, e
                ))
            })?;

        linker
            .func_wrap(
                HOST_SANDBOX_NAMESPACE,
                HOST_SANDBOX_GET_TIMESTAMP,
                |caller: Caller<RuntimeState>| -> i64 { handle_get_timestamp(&caller) },
            )
            .map_err(|e| {
                WasmRuntimeError::HostFunction(format!(
                    "failed to register {}: {}",
                    HOST_SANDBOX_GET_TIMESTAMP, e
                ))
            })?;

        linker
            .func_wrap(
                HOST_SANDBOX_NAMESPACE,
                HOST_SANDBOX_LOG_MESSAGE,
                |mut caller: Caller<RuntimeState>, level: i32, msg_ptr: i32, msg_len: i32| {
                    handle_log_message(&mut caller, level, msg_ptr, msg_len);
                },
            )
            .map_err(|e| {
                WasmRuntimeError::HostFunction(format!(
                    "failed to register {}: {}",
                    HOST_SANDBOX_LOG_MESSAGE, e
                ))
            })?;

        Ok(())
    }
}

fn handle_sandbox_exec(
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
                validator_id = %caller.data().validator_id,
                error = %err,
                "sandbox_exec host memory read failed"
            );
            return write_result(
                caller,
                resp_ptr,
                resp_len,
                Err::<SandboxExecResponse, SandboxExecError>(SandboxExecError::MemoryError(err)),
            );
        }
    };

    let request = match bincode::deserialize::<SandboxExecRequest>(&request_bytes) {
        Ok(req) => req,
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                validator_id = %caller.data().validator_id,
                error = %err,
                "sandbox_exec request decode failed"
            );
            return write_result(
                caller,
                resp_ptr,
                resp_len,
                Err::<SandboxExecResponse, SandboxExecError>(SandboxExecError::ExecutionFailed(
                    format!("invalid sandbox exec request: {err}"),
                )),
            );
        }
    };

    let policy = &caller.data().sandbox_policy;

    if !policy.enable_sandbox {
        warn!(
            challenge_id = %caller.data().challenge_id,
            validator_id = %caller.data().validator_id,
            command = %request.command,
            "sandbox_exec denied: sandbox disabled"
        );
        return write_result(
            caller,
            resp_ptr,
            resp_len,
            Err::<SandboxExecResponse, SandboxExecError>(SandboxExecError::Disabled),
        );
    }

    let command_allowed = policy
        .allowed_commands
        .iter()
        .any(|c| c == "*" || c == &request.command);

    if !command_allowed {
        warn!(
            challenge_id = %caller.data().challenge_id,
            validator_id = %caller.data().validator_id,
            command = %request.command,
            "sandbox_exec command not allowed"
        );
        return write_result(
            caller,
            resp_ptr,
            resp_len,
            Err::<SandboxExecResponse, SandboxExecError>(SandboxExecError::CommandNotAllowed(
                request.command,
            )),
        );
    }

    let timeout_secs = caller.data().sandbox_policy.max_execution_time_secs;
    let timeout_ms = if request.timeout_ms > 0 {
        request.timeout_ms.min(timeout_secs.saturating_mul(1000))
    } else {
        timeout_secs.saturating_mul(1000)
    };
    let timeout = Duration::from_millis(timeout_ms);

    let result = execute_command(&request, timeout);

    let challenge_id = caller.data().challenge_id.clone();
    let validator_id = caller.data().validator_id.clone();

    match &result {
        Ok(resp) => {
            info!(
                challenge_id = %challenge_id,
                validator_id = %validator_id,
                command = %request.command,
                exit_code = resp.exit_code,
                stdout_bytes = resp.stdout.len(),
                stderr_bytes = resp.stderr.len(),
                duration_ms = resp.duration_ms,
                "sandbox_exec command completed"
            );
        }
        Err(err) => {
            warn!(
                challenge_id = %challenge_id,
                validator_id = %validator_id,
                command = %request.command,
                error = ?err,
                "sandbox_exec command failed"
            );
        }
    }

    write_result(caller, resp_ptr, resp_len, result)
}

fn execute_command(
    request: &SandboxExecRequest,
    timeout: Duration,
) -> Result<SandboxExecResponse, SandboxExecError> {
    let start = Instant::now();

    let mut cmd = Command::new(&request.command);
    cmd.args(&request.args);
    cmd.env_clear();
    for (key, value) in &request.env_vars {
        cmd.env(key, value);
    }

    if let Some(ref dir) = request.working_dir {
        cmd.current_dir(dir);
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
        .map_err(|e| SandboxExecError::ExecutionFailed(e.to_string()))?;

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
            return Err(SandboxExecError::ExecutionTimeout(timeout.as_secs()));
        }
        match child.try_wait() {
            Ok(Some(_)) => {
                break child
                    .wait_with_output()
                    .map_err(|e| SandboxExecError::ExecutionFailed(e.to_string()))?
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => return Err(SandboxExecError::ExecutionFailed(e.to_string())),
        }
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(SandboxExecResponse {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: output.stdout,
        stderr: output.stderr,
        duration_ms,
    })
}

fn handle_get_timestamp(caller: &Caller<RuntimeState>) -> i64 {
    if let Some(ts) = caller.data().fixed_timestamp_ms {
        return ts;
    }
    chrono::Utc::now().timestamp_millis()
}

fn handle_log_message(caller: &mut Caller<RuntimeState>, level: i32, msg_ptr: i32, msg_len: i32) {
    let msg = match read_memory(caller, msg_ptr, msg_len) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                error = %err,
                "sandbox log_message: failed to read message from wasm memory"
            );
            return;
        }
    };

    let challenge_id = caller.data().challenge_id.clone();
    match level {
        0 => info!(challenge_id = %challenge_id, "[wasm-sandbox] {}", msg),
        1 => warn!(challenge_id = %challenge_id, "[wasm-sandbox] {}", msg),
        _ => error!(challenge_id = %challenge_id, "[wasm-sandbox] {}", msg),
    }
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
            warn!(error = %err, "failed to serialize sandbox exec response");
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
    fn test_sandbox_host_status_conversion() {
        assert_eq!(SandboxHostStatus::Success.to_i32(), 0);
        assert_eq!(SandboxHostStatus::Disabled.to_i32(), 1);
        assert_eq!(SandboxHostStatus::CommandNotAllowed.to_i32(), -1);
        assert_eq!(SandboxHostStatus::InternalError.to_i32(), -100);

        assert_eq!(SandboxHostStatus::from_i32(0), SandboxHostStatus::Success);
        assert_eq!(SandboxHostStatus::from_i32(1), SandboxHostStatus::Disabled);
        assert_eq!(
            SandboxHostStatus::from_i32(-1),
            SandboxHostStatus::CommandNotAllowed
        );
        assert_eq!(
            SandboxHostStatus::from_i32(-999),
            SandboxHostStatus::InternalError
        );
    }

    #[test]
    fn test_sandbox_host_error_to_status() {
        let err = SandboxHostError::Disabled;
        assert_eq!(SandboxHostStatus::from(err), SandboxHostStatus::Disabled);

        let err = SandboxHostError::CommandNotAllowed("bash".to_string());
        assert_eq!(
            SandboxHostStatus::from(err),
            SandboxHostStatus::CommandNotAllowed
        );

        let err = SandboxHostError::ExecutionTimeout(30);
        assert_eq!(
            SandboxHostStatus::from(err),
            SandboxHostStatus::ExecutionTimeout
        );
    }

    #[test]
    fn test_sandbox_host_config_command_check() {
        let config = SandboxHostConfig::default();
        assert!(!config.is_command_allowed("bash"));

        let config = SandboxHostConfig::permissive();
        assert!(config.is_command_allowed("bash"));
        assert!(config.is_command_allowed("anything"));

        let config = SandboxHostConfig {
            policy: SandboxPolicy {
                enable_sandbox: true,
                allowed_commands: vec!["bash".to_string(), "sh".to_string()],
                max_execution_time_secs: 30,
            },
            ..Default::default()
        };
        assert!(config.is_command_allowed("bash"));
        assert!(config.is_command_allowed("sh"));
        assert!(!config.is_command_allowed("python3"));
    }

    #[test]
    fn test_sandbox_host_state() {
        let mut state =
            SandboxHostState::new("challenge-1".to_string(), SandboxHostConfig::default());

        let id1 = state.store_result(b"result1".to_vec());
        let id2 = state.store_result(b"result2".to_vec());

        assert_ne!(id1, id2);

        let result1 = state.take_result(id1);
        assert_eq!(result1, Some(b"result1".to_vec()));

        let result1_again = state.take_result(id1);
        assert_eq!(result1_again, None);

        let result2 = state.take_result(id2);
        assert_eq!(result2, Some(b"result2".to_vec()));
    }

    #[test]
    fn test_sandbox_policy_defaults() {
        let policy = SandboxPolicy::default();
        assert!(!policy.enable_sandbox);
        assert!(policy.allowed_commands.is_empty());
        assert_eq!(policy.max_execution_time_secs, 30);
    }

    #[test]
    fn test_sandbox_policy_term_challenge() {
        let policy = SandboxPolicy::term_challenge();
        assert!(policy.enable_sandbox);
        assert!(policy.allowed_commands.contains(&"bash".to_string()));
        assert!(policy.allowed_commands.contains(&"python3".to_string()));
        assert_eq!(policy.max_execution_time_secs, 60);
    }

    #[test]
    fn test_execute_command_echo() {
        let request = SandboxExecRequest {
            command: "echo".to_string(),
            args: vec!["hello".to_string()],
            env_vars: Vec::new(),
            working_dir: None,
            stdin: None,
            timeout_ms: 5000,
        };

        let result = execute_command(&request, Duration::from_secs(5));
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.exit_code, 0);
        assert_eq!(String::from_utf8_lossy(&resp.stdout).trim(), "hello");
    }

    #[test]
    fn test_execute_command_not_found() {
        let request = SandboxExecRequest {
            command: "nonexistent_command_12345".to_string(),
            args: Vec::new(),
            env_vars: Vec::new(),
            working_dir: None,
            stdin: None,
            timeout_ms: 5000,
        };

        let result = execute_command(&request, Duration::from_secs(5));
        assert!(result.is_err());
        match result {
            Err(SandboxExecError::ExecutionFailed(_)) => {}
            other => panic!("expected ExecutionFailed, got {:?}", other),
        }
    }

    #[test]
    fn test_execute_command_with_stdin() {
        let request = SandboxExecRequest {
            command: "cat".to_string(),
            args: Vec::new(),
            env_vars: Vec::new(),
            working_dir: None,
            stdin: Some(b"stdin data".to_vec()),
            timeout_ms: 5000,
        };

        let result = execute_command(&request, Duration::from_secs(5));
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.exit_code, 0);
        assert_eq!(String::from_utf8_lossy(&resp.stdout), "stdin data");
    }

    #[test]
    fn test_sandbox_exec_request_serialization() {
        let request = SandboxExecRequest {
            command: "echo".to_string(),
            args: vec!["test".to_string()],
            env_vars: vec![("KEY".to_string(), "VALUE".to_string())],
            working_dir: None,
            stdin: None,
            timeout_ms: 5000,
        };

        let bytes = bincode::serialize(&request).unwrap();
        let deserialized: SandboxExecRequest = bincode::deserialize(&bytes).unwrap();
        assert_eq!(deserialized.command, "echo");
        assert_eq!(deserialized.args, vec!["test"]);
    }

    #[test]
    fn test_sandbox_exec_response_serialization() {
        let response = SandboxExecResponse {
            exit_code: 0,
            stdout: b"output".to_vec(),
            stderr: Vec::new(),
            duration_ms: 42,
        };

        let result: Result<SandboxExecResponse, SandboxExecError> = Ok(response);
        let bytes = bincode::serialize(&result).unwrap();
        let deserialized: Result<SandboxExecResponse, SandboxExecError> =
            bincode::deserialize(&bytes).unwrap();
        assert!(deserialized.is_ok());
        let resp = deserialized.unwrap();
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, b"output");
    }
}
