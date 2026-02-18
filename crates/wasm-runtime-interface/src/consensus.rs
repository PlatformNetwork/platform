//! Consensus Host Functions for WASM Challenges
//!
//! This module provides host functions that allow WASM code to query
//! the P2P consensus state. All operations are gated by `ConsensusPolicy`.
//!
//! # Host Functions
//!
//! - `consensus_get_epoch() -> i64` — Get current epoch number
//! - `consensus_get_validators(buf_ptr, buf_len) -> i32` — Get active validator list
//! - `consensus_propose_weight(uid, weight) -> i32` — Propose a weight for a UID
//! - `consensus_get_votes(buf_ptr, buf_len) -> i32` — Get current weight votes
//! - `consensus_get_state_hash(buf_ptr) -> i32` — Get current state hash (32 bytes)
//! - `consensus_get_submission_count() -> i32` — Get pending submission count
//! - `consensus_get_block_height() -> i64` — Get current logical block height

use crate::runtime::{HostFunctionRegistrar, RuntimeState, WasmRuntimeError};
use serde::{Deserialize, Serialize};
use tracing::warn;
use wasmtime::{Caller, Linker, Memory};

pub const HOST_CONSENSUS_NAMESPACE: &str = "platform_consensus";
pub const HOST_CONSENSUS_GET_EPOCH: &str = "consensus_get_epoch";
pub const HOST_CONSENSUS_GET_VALIDATORS: &str = "consensus_get_validators";
pub const HOST_CONSENSUS_PROPOSE_WEIGHT: &str = "consensus_propose_weight";
pub const HOST_CONSENSUS_GET_VOTES: &str = "consensus_get_votes";
pub const HOST_CONSENSUS_GET_STATE_HASH: &str = "consensus_get_state_hash";
pub const HOST_CONSENSUS_GET_SUBMISSION_COUNT: &str = "consensus_get_submission_count";
pub const HOST_CONSENSUS_GET_BLOCK_HEIGHT: &str = "consensus_get_block_height";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ConsensusHostStatus {
    Success = 0,
    Disabled = 1,
    BufferTooSmall = -1,
    ProposalLimitExceeded = -2,
    InvalidArgument = -3,
    InternalError = -100,
}

impl ConsensusHostStatus {
    pub fn to_i32(self) -> i32 {
        self as i32
    }

    pub fn from_i32(code: i32) -> Self {
        match code {
            0 => Self::Success,
            1 => Self::Disabled,
            -1 => Self::BufferTooSmall,
            -2 => Self::ProposalLimitExceeded,
            -3 => Self::InvalidArgument,
            _ => Self::InternalError,
        }
    }
}

/// Policy controlling WASM access to consensus state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusPolicy {
    pub enabled: bool,
    pub allow_weight_proposals: bool,
    pub max_weight_proposals: u32,
}

impl Default for ConsensusPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_weight_proposals: false,
            max_weight_proposals: 0,
        }
    }
}

impl ConsensusPolicy {
    pub fn development() -> Self {
        Self {
            enabled: true,
            allow_weight_proposals: true,
            max_weight_proposals: 256,
        }
    }

    pub fn read_only() -> Self {
        Self {
            enabled: true,
            allow_weight_proposals: false,
            max_weight_proposals: 0,
        }
    }
}

/// Mutable consensus state accessible from WASM host functions.
///
/// Populated by the validator node before each WASM instantiation with
/// a snapshot of the current chain state.
pub struct ConsensusState {
    pub policy: ConsensusPolicy,
    pub epoch: u64,
    pub block_height: u64,
    pub state_hash: [u8; 32],
    pub validators_json: Vec<u8>,
    pub votes_json: Vec<u8>,
    pub submission_count: u32,
    pub weight_proposals_made: u32,
    pub proposed_weights: Vec<(u16, u16)>,
    pub challenge_id: String,
    pub validator_id: String,
}

impl ConsensusState {
    pub fn new(policy: ConsensusPolicy, challenge_id: String, validator_id: String) -> Self {
        Self {
            policy,
            epoch: 0,
            block_height: 0,
            state_hash: [0u8; 32],
            validators_json: Vec::new(),
            votes_json: Vec::new(),
            submission_count: 0,
            weight_proposals_made: 0,
            proposed_weights: Vec::new(),
            challenge_id,
            validator_id,
        }
    }

    pub fn reset_counters(&mut self) {
        self.weight_proposals_made = 0;
        self.proposed_weights.clear();
    }
}

#[derive(Clone, Debug)]
pub struct ConsensusHostFunctions;

impl ConsensusHostFunctions {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ConsensusHostFunctions {
    fn default() -> Self {
        Self::new()
    }
}

impl HostFunctionRegistrar for ConsensusHostFunctions {
    fn register(&self, linker: &mut Linker<RuntimeState>) -> Result<(), WasmRuntimeError> {
        linker
            .func_wrap(
                HOST_CONSENSUS_NAMESPACE,
                HOST_CONSENSUS_GET_EPOCH,
                |caller: Caller<RuntimeState>| -> i64 { handle_get_epoch(&caller) },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_CONSENSUS_NAMESPACE,
                HOST_CONSENSUS_GET_VALIDATORS,
                |mut caller: Caller<RuntimeState>, buf_ptr: i32, buf_len: i32| -> i32 {
                    handle_get_validators(&mut caller, buf_ptr, buf_len)
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_CONSENSUS_NAMESPACE,
                HOST_CONSENSUS_PROPOSE_WEIGHT,
                |mut caller: Caller<RuntimeState>, uid: i32, weight: i32| -> i32 {
                    handle_propose_weight(&mut caller, uid, weight)
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_CONSENSUS_NAMESPACE,
                HOST_CONSENSUS_GET_VOTES,
                |mut caller: Caller<RuntimeState>, buf_ptr: i32, buf_len: i32| -> i32 {
                    handle_get_votes(&mut caller, buf_ptr, buf_len)
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_CONSENSUS_NAMESPACE,
                HOST_CONSENSUS_GET_STATE_HASH,
                |mut caller: Caller<RuntimeState>, buf_ptr: i32| -> i32 {
                    handle_get_state_hash(&mut caller, buf_ptr)
                },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_CONSENSUS_NAMESPACE,
                HOST_CONSENSUS_GET_SUBMISSION_COUNT,
                |caller: Caller<RuntimeState>| -> i32 { handle_get_submission_count(&caller) },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        linker
            .func_wrap(
                HOST_CONSENSUS_NAMESPACE,
                HOST_CONSENSUS_GET_BLOCK_HEIGHT,
                |caller: Caller<RuntimeState>| -> i64 { handle_get_block_height(&caller) },
            )
            .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;

        Ok(())
    }
}

fn handle_get_epoch(caller: &Caller<RuntimeState>) -> i64 {
    let state = &caller.data().consensus_state;
    if !state.policy.enabled {
        return -1;
    }
    state.epoch as i64
}

fn handle_get_validators(caller: &mut Caller<RuntimeState>, buf_ptr: i32, buf_len: i32) -> i32 {
    let data = {
        let state = &caller.data().consensus_state;
        if !state.policy.enabled {
            return ConsensusHostStatus::Disabled.to_i32();
        }
        state.validators_json.clone()
    };

    if data.is_empty() {
        return 0;
    }

    if buf_len < 0 || (data.len() as i32) > buf_len {
        return ConsensusHostStatus::BufferTooSmall.to_i32();
    }

    if let Err(err) = write_wasm_memory(caller, buf_ptr, &data) {
        warn!(error = %err, "consensus_get_validators: failed to write to wasm memory");
        return ConsensusHostStatus::InternalError.to_i32();
    }

    data.len() as i32
}

fn handle_propose_weight(caller: &mut Caller<RuntimeState>, uid: i32, weight: i32) -> i32 {
    if uid < 0 || weight < 0 {
        return ConsensusHostStatus::InvalidArgument.to_i32();
    }

    let state = &caller.data().consensus_state;
    if !state.policy.enabled {
        return ConsensusHostStatus::Disabled.to_i32();
    }
    if !state.policy.allow_weight_proposals {
        return ConsensusHostStatus::Disabled.to_i32();
    }
    if state.weight_proposals_made >= state.policy.max_weight_proposals {
        return ConsensusHostStatus::ProposalLimitExceeded.to_i32();
    }

    let state = &mut caller.data_mut().consensus_state;
    state.weight_proposals_made += 1;
    state.proposed_weights.push((uid as u16, weight as u16));

    ConsensusHostStatus::Success.to_i32()
}

fn handle_get_votes(caller: &mut Caller<RuntimeState>, buf_ptr: i32, buf_len: i32) -> i32 {
    let data = {
        let state = &caller.data().consensus_state;
        if !state.policy.enabled {
            return ConsensusHostStatus::Disabled.to_i32();
        }
        state.votes_json.clone()
    };

    if data.is_empty() {
        return 0;
    }

    if buf_len < 0 || (data.len() as i32) > buf_len {
        return ConsensusHostStatus::BufferTooSmall.to_i32();
    }

    if let Err(err) = write_wasm_memory(caller, buf_ptr, &data) {
        warn!(error = %err, "consensus_get_votes: failed to write to wasm memory");
        return ConsensusHostStatus::InternalError.to_i32();
    }

    data.len() as i32
}

fn handle_get_state_hash(caller: &mut Caller<RuntimeState>, buf_ptr: i32) -> i32 {
    let hash = {
        let state = &caller.data().consensus_state;
        if !state.policy.enabled {
            return ConsensusHostStatus::Disabled.to_i32();
        }
        state.state_hash
    };

    if let Err(err) = write_wasm_memory(caller, buf_ptr, &hash) {
        warn!(error = %err, "consensus_get_state_hash: failed to write to wasm memory");
        return ConsensusHostStatus::InternalError.to_i32();
    }

    ConsensusHostStatus::Success.to_i32()
}

fn handle_get_submission_count(caller: &Caller<RuntimeState>) -> i32 {
    let state = &caller.data().consensus_state;
    if !state.policy.enabled {
        return ConsensusHostStatus::Disabled.to_i32();
    }
    state.submission_count as i32
}

fn handle_get_block_height(caller: &Caller<RuntimeState>) -> i64 {
    let state = &caller.data().consensus_state;
    if !state.policy.enabled {
        return -1;
    }
    state.block_height as i64
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
    fn test_consensus_host_status_conversion() {
        assert_eq!(ConsensusHostStatus::Success.to_i32(), 0);
        assert_eq!(ConsensusHostStatus::Disabled.to_i32(), 1);
        assert_eq!(ConsensusHostStatus::BufferTooSmall.to_i32(), -1);
        assert_eq!(ConsensusHostStatus::ProposalLimitExceeded.to_i32(), -2);
        assert_eq!(ConsensusHostStatus::InternalError.to_i32(), -100);

        assert_eq!(
            ConsensusHostStatus::from_i32(0),
            ConsensusHostStatus::Success
        );
        assert_eq!(
            ConsensusHostStatus::from_i32(1),
            ConsensusHostStatus::Disabled
        );
        assert_eq!(
            ConsensusHostStatus::from_i32(-1),
            ConsensusHostStatus::BufferTooSmall
        );
        assert_eq!(
            ConsensusHostStatus::from_i32(-999),
            ConsensusHostStatus::InternalError
        );
    }

    #[test]
    fn test_consensus_policy_default() {
        let policy = ConsensusPolicy::default();
        assert!(policy.enabled);
        assert!(!policy.allow_weight_proposals);
        assert_eq!(policy.max_weight_proposals, 0);
    }

    #[test]
    fn test_consensus_policy_development() {
        let policy = ConsensusPolicy::development();
        assert!(policy.enabled);
        assert!(policy.allow_weight_proposals);
        assert_eq!(policy.max_weight_proposals, 256);
    }

    #[test]
    fn test_consensus_state_creation() {
        let state = ConsensusState::new(
            ConsensusPolicy::default(),
            "test-challenge".to_string(),
            "test-validator".to_string(),
        );
        assert_eq!(state.epoch, 0);
        assert_eq!(state.block_height, 0);
        assert_eq!(state.submission_count, 0);
        assert_eq!(state.weight_proposals_made, 0);
        assert!(state.proposed_weights.is_empty());
    }

    #[test]
    fn test_consensus_state_reset() {
        let mut state = ConsensusState::new(
            ConsensusPolicy::development(),
            "test".to_string(),
            "test".to_string(),
        );
        state.weight_proposals_made = 5;
        state.proposed_weights.push((0, 100));
        state.proposed_weights.push((1, 200));

        state.reset_counters();

        assert_eq!(state.weight_proposals_made, 0);
        assert!(state.proposed_weights.is_empty());
    }
}
