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

#![allow(dead_code, unused_variables, unused_imports)]

use crate::SandboxPolicy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::{debug, info, warn};

pub const HOST_SANDBOX_NAMESPACE: &str = "platform_sandbox";
pub const HOST_SANDBOX_EXEC: &str = "sandbox_exec";
pub const HOST_SANDBOX_GET_TASKS: &str = "sandbox_get_tasks";
pub const HOST_SANDBOX_CONFIGURE: &str = "sandbox_configure";
pub const HOST_SANDBOX_STATUS: &str = "sandbox_status";

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

impl crate::runtime::HostFunctionRegistrar for SandboxHostFunctions {
    fn register(
        &self,
        linker: &mut wasmtime::Linker<crate::runtime::RuntimeState>,
    ) -> Result<(), crate::runtime::WasmRuntimeError> {
        linker
            .func_wrap(HOST_SANDBOX_NAMESPACE, HOST_SANDBOX_STATUS, || -> i32 {
                SandboxHostStatus::Success.to_i32()
            })
            .map_err(|e| {
                crate::runtime::WasmRuntimeError::HostFunction(format!(
                    "failed to register {}: {}",
                    HOST_SANDBOX_STATUS, e
                ))
            })?;
        Ok(())
    }
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
}
