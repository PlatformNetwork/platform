//! Terminal Host Functions for WASM Challenges
//!
//! This module provides host functions that allow WASM code to interact with
//! the host terminal environment. All operations are gated by `TerminalPolicy`.
//!
//! # Host Functions
//!
//! - `terminal_exec(cmd_ptr, cmd_len, result_ptr, result_len) -> i32`
//! - `terminal_read_file(path_ptr, path_len, buf_ptr, buf_len) -> i32`
//! - `terminal_write_file(path_ptr, path_len, data_ptr, data_len) -> i32`
//! - `terminal_list_dir(path_ptr, path_len, buf_ptr, buf_len) -> i32`
//! - `terminal_get_time() -> i64`
//! - `terminal_random_seed(buf_ptr, buf_len) -> i32`

use crate::runtime::{HostFunctionRegistrar, RuntimeState, WasmRuntimeError};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::Duration;
use tracing::warn;
use wasmtime::{Caller, Linker, Memory};

pub const HOST_TERMINAL_NAMESPACE: &str = "platform_terminal";
pub const HOST_TERMINAL_EXEC: &str = "terminal_exec";
pub const HOST_TERMINAL_READ_FILE: &str = "terminal_read_file";
pub const HOST_TERMINAL_WRITE_FILE: &str = "terminal_write_file";
pub const HOST_TERMINAL_LIST_DIR: &str = "terminal_list_dir";
pub const HOST_TERMINAL_GET_TIME: &str = "terminal_get_time";
pub const HOST_TERMINAL_RANDOM_SEED: &str = "terminal_random_seed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum TerminalHostStatus {
    Success = 0,
    Disabled = 1,
    CommandNotAllowed = -1,
    PathNotAllowed = -2,
    FileTooLarge = -3,
    BufferTooSmall = -4,
    IoError = -5,
    LimitExceeded = -6,
    Timeout = -7,
    InternalError = -100,
}

impl TerminalHostStatus {
    pub fn to_i32(self) -> i32 {
        self as i32
    }

    pub fn from_i32(code: i32) -> Self {
        match code {
            0 => Self::Success,
            1 => Self::Disabled,
            -1 => Self::CommandNotAllowed,
            -2 => Self::PathNotAllowed,
            -3 => Self::FileTooLarge,
            -4 => Self::BufferTooSmall,
            -5 => Self::IoError,
            -6 => Self::LimitExceeded,
            -7 => Self::Timeout,
            _ => Self::InternalError,
        }
    }
}

/// Policy controlling WASM access to terminal operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalPolicy {
    pub enabled: bool,
    pub allowed_commands: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub max_file_size: usize,
    pub max_executions: u32,
    pub max_output_bytes: usize,
    pub timeout_ms: u64,
}

impl Default for TerminalPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_commands: Vec::new(),
            allowed_paths: Vec::new(),
            max_file_size: 1024 * 1024,
            max_executions: 0,
            max_output_bytes: 512 * 1024,
            timeout_ms: 5_000,
        }
    }
}

impl TerminalPolicy {
    pub fn development() -> Self {
        Self {
            enabled: true,
            allowed_commands: vec![
                "bash".to_string(),
                "sh".to_string(),
                "echo".to_string(),
                "cat".to_string(),
                "ls".to_string(),
                "python3".to_string(),
                "node".to_string(),
            ],
            allowed_paths: vec!["/tmp".to_string(), "/workspace".to_string()],
            max_file_size: 10 * 1024 * 1024,
            max_executions: 64,
            max_output_bytes: 2 * 1024 * 1024,
            timeout_ms: 30_000,
        }
    }

    pub fn term_challenge() -> Self {
        Self {
            enabled: true,
            allowed_commands: vec![
                "bash".to_string(),
                "sh".to_string(),
                "python3".to_string(),
                "node".to_string(),
            ],
            allowed_paths: vec!["/tmp".to_string()],
            max_file_size: 1024 * 1024,
            max_executions: 32,
            max_output_bytes: 1024 * 1024,
            timeout_ms: 60_000,
        }
    }

    pub fn is_command_allowed(&self, command: &str) -> bool {
        if !self.enabled {
            return false;
        }
        self.allowed_commands
            .iter()
            .any(|c| c == "*" || c == command)
    }

    pub fn is_path_allowed(&self, path: &str) -> bool {
        if !self.enabled {
            return false;
        }
        if self.allowed_paths.is_empty() {
            return true;
        }
        self.allowed_paths.iter().any(|p| path.starts_with(p))
    }
}

/// Mutable terminal state for tracking per-instance usage.
pub struct TerminalState {
    pub policy: TerminalPolicy,
    pub challenge_id: String,
    pub validator_id: String,
    pub executions: u32,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

impl TerminalState {
    pub fn new(policy: TerminalPolicy, challenge_id: String, validator_id: String) -> Self {
        Self {
            policy,
            challenge_id,
            validator_id,
            executions: 0,
            bytes_read: 0,
            bytes_written: 0,
        }
    }

    pub fn reset_counters(&mut self) {
        self.executions = 0;
        self.bytes_read = 0;
        self.bytes_written = 0;
    }
}

#[derive(Clone, Debug)]
pub struct TerminalHostFunctions;

impl TerminalHostFunctions {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TerminalHostFunctions {
    fn default() -> Self {
        Self::new()
    }
}

impl HostFunctionRegistrar for TerminalHostFunctions {
    fn register(&self, linker: &mut Linker<RuntimeState>) -> Result<(), WasmRuntimeError> {
        linker
            .func_wrap(
                HOST_TERMINAL_NAMESPACE,
                HOST_TERMINAL_EXEC,
                |mut caller: Caller<RuntimeState>,
                 cmd_ptr: i32,
                 cmd_len: i32,
                 result_ptr: i32,
                 result_len: i32|
                 -> i32 {
                    handle_terminal_exec(&mut caller, cmd_ptr, cmd_len, result_ptr, result_len)
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_TERMINAL_NAMESPACE,
                HOST_TERMINAL_READ_FILE,
                |mut caller: Caller<RuntimeState>,
                 path_ptr: i32,
                 path_len: i32,
                 buf_ptr: i32,
                 buf_len: i32|
                 -> i32 {
                    handle_terminal_read_file(&mut caller, path_ptr, path_len, buf_ptr, buf_len)
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_TERMINAL_NAMESPACE,
                HOST_TERMINAL_WRITE_FILE,
                |mut caller: Caller<RuntimeState>,
                 path_ptr: i32,
                 path_len: i32,
                 data_ptr: i32,
                 data_len: i32|
                 -> i32 {
                    handle_terminal_write_file(&mut caller, path_ptr, path_len, data_ptr, data_len)
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_TERMINAL_NAMESPACE,
                HOST_TERMINAL_LIST_DIR,
                |mut caller: Caller<RuntimeState>,
                 path_ptr: i32,
                 path_len: i32,
                 buf_ptr: i32,
                 buf_len: i32|
                 -> i32 {
                    handle_terminal_list_dir(&mut caller, path_ptr, path_len, buf_ptr, buf_len)
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_TERMINAL_NAMESPACE,
                HOST_TERMINAL_GET_TIME,
                |caller: Caller<RuntimeState>| -> i64 {
                    if let Some(ts) = caller.data().fixed_timestamp_ms {
                        return ts;
                    }
                    chrono::Utc::now().timestamp_millis()
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_TERMINAL_NAMESPACE,
                HOST_TERMINAL_RANDOM_SEED,
                |mut caller: Caller<RuntimeState>, buf_ptr: i32, buf_len: i32| -> i32 {
                    handle_terminal_random_seed(&mut caller, buf_ptr, buf_len)
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        Ok(())
    }
}

fn handle_terminal_exec(
    caller: &mut Caller<RuntimeState>,
    cmd_ptr: i32,
    cmd_len: i32,
    result_ptr: i32,
    result_len: i32,
) -> i32 {
    let enabled = caller.data().terminal_state.policy.enabled;
    if !enabled {
        return TerminalHostStatus::Disabled.to_i32();
    }

    let cmd_bytes = match read_wasm_memory(caller, cmd_ptr, cmd_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "terminal_exec: failed to read command from wasm memory");
            return TerminalHostStatus::InternalError.to_i32();
        }
    };

    let cmd_str = match std::str::from_utf8(&cmd_bytes) {
        Ok(s) => s.to_string(),
        Err(_) => return TerminalHostStatus::InternalError.to_i32(),
    };

    let command_name = cmd_str.split_whitespace().next().unwrap_or("").to_string();

    {
        let state = &caller.data().terminal_state;
        if !state.policy.is_command_allowed(&command_name) {
            warn!(
                challenge_id = %state.challenge_id,
                command = %command_name,
                "terminal_exec: command not allowed"
            );
            return TerminalHostStatus::CommandNotAllowed.to_i32();
        }
        if state.executions >= state.policy.max_executions {
            return TerminalHostStatus::LimitExceeded.to_i32();
        }
    }

    let timeout_ms = caller.data().terminal_state.policy.timeout_ms;
    let max_output = caller.data().terminal_state.policy.max_output_bytes;

    let output = match Command::new("sh")
        .arg("-c")
        .arg(&cmd_str)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => {
            let start = std::time::Instant::now();
            let timeout = Duration::from_millis(timeout_ms);
            match child.wait_with_output() {
                Ok(out) => {
                    if start.elapsed() > timeout {
                        return TerminalHostStatus::Timeout.to_i32();
                    }
                    out
                }
                Err(err) => {
                    warn!(error = %err, "terminal_exec: command wait failed");
                    return TerminalHostStatus::IoError.to_i32();
                }
            }
        }
        Err(err) => {
            warn!(error = %err, "terminal_exec: command spawn failed");
            return TerminalHostStatus::IoError.to_i32();
        }
    };

    caller.data_mut().terminal_state.executions += 1;

    let mut result_data = output.stdout;
    if result_data.len() > max_output {
        result_data.truncate(max_output);
    }

    if result_len < 0 || result_data.len() > result_len as usize {
        return TerminalHostStatus::BufferTooSmall.to_i32();
    }

    if let Err(err) = write_wasm_memory(caller, result_ptr, &result_data) {
        warn!(error = %err, "terminal_exec: failed to write result to wasm memory");
        return TerminalHostStatus::InternalError.to_i32();
    }

    result_data.len() as i32
}

fn handle_terminal_read_file(
    caller: &mut Caller<RuntimeState>,
    path_ptr: i32,
    path_len: i32,
    buf_ptr: i32,
    buf_len: i32,
) -> i32 {
    let enabled = caller.data().terminal_state.policy.enabled;
    if !enabled {
        return TerminalHostStatus::Disabled.to_i32();
    }

    let path_bytes = match read_wasm_memory(caller, path_ptr, path_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "terminal_read_file: failed to read path from wasm memory");
            return TerminalHostStatus::InternalError.to_i32();
        }
    };

    let path_str = match std::str::from_utf8(&path_bytes) {
        Ok(s) => s.to_string(),
        Err(_) => return TerminalHostStatus::InternalError.to_i32(),
    };

    if !caller
        .data()
        .terminal_state
        .policy
        .is_path_allowed(&path_str)
    {
        return TerminalHostStatus::PathNotAllowed.to_i32();
    }

    let max_file_size = caller.data().terminal_state.policy.max_file_size;

    let contents = match std::fs::read(&path_str) {
        Ok(data) => data,
        Err(err) => {
            warn!(error = %err, path = %path_str, "terminal_read_file: read failed");
            return TerminalHostStatus::IoError.to_i32();
        }
    };

    if contents.len() > max_file_size {
        return TerminalHostStatus::FileTooLarge.to_i32();
    }

    if buf_len < 0 || contents.len() > buf_len as usize {
        return TerminalHostStatus::BufferTooSmall.to_i32();
    }

    if let Err(err) = write_wasm_memory(caller, buf_ptr, &contents) {
        warn!(error = %err, "terminal_read_file: failed to write to wasm memory");
        return TerminalHostStatus::InternalError.to_i32();
    }

    caller.data_mut().terminal_state.bytes_read += contents.len() as u64;

    contents.len() as i32
}

fn handle_terminal_write_file(
    caller: &mut Caller<RuntimeState>,
    path_ptr: i32,
    path_len: i32,
    data_ptr: i32,
    data_len: i32,
) -> i32 {
    let enabled = caller.data().terminal_state.policy.enabled;
    if !enabled {
        return TerminalHostStatus::Disabled.to_i32();
    }

    let path_bytes = match read_wasm_memory(caller, path_ptr, path_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "terminal_write_file: failed to read path from wasm memory");
            return TerminalHostStatus::InternalError.to_i32();
        }
    };

    let path_str = match std::str::from_utf8(&path_bytes) {
        Ok(s) => s.to_string(),
        Err(_) => return TerminalHostStatus::InternalError.to_i32(),
    };

    if !caller
        .data()
        .terminal_state
        .policy
        .is_path_allowed(&path_str)
    {
        return TerminalHostStatus::PathNotAllowed.to_i32();
    }

    let data = match read_wasm_memory(caller, data_ptr, data_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "terminal_write_file: failed to read data from wasm memory");
            return TerminalHostStatus::InternalError.to_i32();
        }
    };

    let max_file_size = caller.data().terminal_state.policy.max_file_size;
    if data.len() > max_file_size {
        return TerminalHostStatus::FileTooLarge.to_i32();
    }

    if let Err(err) = std::fs::write(&path_str, &data) {
        warn!(error = %err, path = %path_str, "terminal_write_file: write failed");
        return TerminalHostStatus::IoError.to_i32();
    }

    caller.data_mut().terminal_state.bytes_written += data.len() as u64;

    TerminalHostStatus::Success.to_i32()
}

fn handle_terminal_list_dir(
    caller: &mut Caller<RuntimeState>,
    path_ptr: i32,
    path_len: i32,
    buf_ptr: i32,
    buf_len: i32,
) -> i32 {
    let enabled = caller.data().terminal_state.policy.enabled;
    if !enabled {
        return TerminalHostStatus::Disabled.to_i32();
    }

    let path_bytes = match read_wasm_memory(caller, path_ptr, path_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "terminal_list_dir: failed to read path from wasm memory");
            return TerminalHostStatus::InternalError.to_i32();
        }
    };

    let path_str = match std::str::from_utf8(&path_bytes) {
        Ok(s) => s.to_string(),
        Err(_) => return TerminalHostStatus::InternalError.to_i32(),
    };

    if !caller
        .data()
        .terminal_state
        .policy
        .is_path_allowed(&path_str)
    {
        return TerminalHostStatus::PathNotAllowed.to_i32();
    }

    let entries = match std::fs::read_dir(&path_str) {
        Ok(rd) => rd,
        Err(err) => {
            warn!(error = %err, path = %path_str, "terminal_list_dir: read_dir failed");
            return TerminalHostStatus::IoError.to_i32();
        }
    };

    let mut names = Vec::new();
    for entry in entries {
        match entry {
            Ok(e) => {
                if let Some(name) = e.file_name().to_str() {
                    names.push(name.to_string());
                }
            }
            Err(_) => continue,
        }
    }

    let result = names.join("\n");
    let result_bytes = result.as_bytes();

    if buf_len < 0 || result_bytes.len() > buf_len as usize {
        return TerminalHostStatus::BufferTooSmall.to_i32();
    }

    if let Err(err) = write_wasm_memory(caller, buf_ptr, result_bytes) {
        warn!(error = %err, "terminal_list_dir: failed to write to wasm memory");
        return TerminalHostStatus::InternalError.to_i32();
    }

    result_bytes.len() as i32
}

fn handle_terminal_random_seed(
    caller: &mut Caller<RuntimeState>,
    buf_ptr: i32,
    buf_len: i32,
) -> i32 {
    if buf_len <= 0 {
        return TerminalHostStatus::InternalError.to_i32();
    }

    let len = buf_len as usize;
    let mut seed = vec![0u8; len];

    // Use a deterministic seed based on challenge_id and timestamp for reproducibility
    let challenge_id = caller.data().challenge_id.clone();
    let ts = caller
        .data()
        .fixed_timestamp_ms
        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(challenge_id.as_bytes());
    hasher.update(ts.to_le_bytes());
    let hash = hasher.finalize();

    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = hash[i % 32];
    }

    if let Err(err) = write_wasm_memory(caller, buf_ptr, &seed) {
        warn!(error = %err, "terminal_random_seed: failed to write to wasm memory");
        return TerminalHostStatus::InternalError.to_i32();
    }

    TerminalHostStatus::Success.to_i32()
}

fn read_wasm_memory(
    caller: &mut Caller<RuntimeState>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, String> {
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

fn write_wasm_memory(
    caller: &mut Caller<RuntimeState>,
    ptr: i32,
    bytes: &[u8],
) -> Result<(), String> {
    if ptr < 0 {
        return Err("negative pointer".to_string());
    }
    let ptr = ptr as usize;
    let memory = get_memory(caller).ok_or_else(|| "memory export not found".to_string())?;
    let end = ptr
        .checked_add(bytes.len())
        .ok_or_else(|| "pointer overflow".to_string())?;
    let data = memory.data_mut(caller);
    if end > data.len() {
        return Err("memory write out of bounds".to_string());
    }
    data[ptr..end].copy_from_slice(bytes);
    Ok(())
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
    fn test_terminal_host_status_conversion() {
        assert_eq!(TerminalHostStatus::Success.to_i32(), 0);
        assert_eq!(TerminalHostStatus::Disabled.to_i32(), 1);
        assert_eq!(TerminalHostStatus::CommandNotAllowed.to_i32(), -1);
        assert_eq!(TerminalHostStatus::InternalError.to_i32(), -100);

        assert_eq!(TerminalHostStatus::from_i32(0), TerminalHostStatus::Success);
        assert_eq!(
            TerminalHostStatus::from_i32(1),
            TerminalHostStatus::Disabled
        );
        assert_eq!(
            TerminalHostStatus::from_i32(-999),
            TerminalHostStatus::InternalError
        );
    }

    #[test]
    fn test_terminal_policy_default() {
        let policy = TerminalPolicy::default();
        assert!(!policy.enabled);
        assert!(policy.allowed_commands.is_empty());
        assert_eq!(policy.max_executions, 0);
    }

    #[test]
    fn test_terminal_policy_development() {
        let policy = TerminalPolicy::development();
        assert!(policy.enabled);
        assert!(policy.is_command_allowed("bash"));
        assert!(policy.is_command_allowed("python3"));
        assert!(!policy.is_command_allowed("rm"));
    }

    #[test]
    fn test_terminal_policy_path_check() {
        let policy = TerminalPolicy::term_challenge();
        assert!(policy.is_path_allowed("/tmp/test.txt"));
        assert!(!policy.is_path_allowed("/etc/passwd"));
    }

    #[test]
    fn test_terminal_policy_disabled_blocks_all() {
        let policy = TerminalPolicy::default();
        assert!(!policy.is_command_allowed("bash"));
        assert!(!policy.is_path_allowed("/tmp"));
    }

    #[test]
    fn test_terminal_state_creation() {
        let state = TerminalState::new(
            TerminalPolicy::default(),
            "test".to_string(),
            "test".to_string(),
        );
        assert_eq!(state.executions, 0);
        assert_eq!(state.bytes_read, 0);
        assert_eq!(state.bytes_written, 0);
    }

    #[test]
    fn test_terminal_state_reset() {
        let mut state = TerminalState::new(
            TerminalPolicy::default(),
            "test".to_string(),
            "test".to_string(),
        );
        state.executions = 5;
        state.bytes_read = 1000;
        state.bytes_written = 500;

        state.reset_counters();

        assert_eq!(state.executions, 0);
        assert_eq!(state.bytes_read, 0);
        assert_eq!(state.bytes_written, 0);
    }
}
