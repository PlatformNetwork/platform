use crate::runtime::{HostFunctionRegistrar, RuntimeState, WasmRuntimeError};
use serde::{Deserialize, Serialize};
use tracing::warn;
use wasmtime::{Caller, Linker};

pub const HOST_TIME_NAMESPACE: &str = "platform_time";
pub const HOST_GET_TIMESTAMP: &str = "get_timestamp";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeHostFunction {
    GetTimestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeMode {
    Real,
    #[default]
    Deterministic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimePolicy {
    pub enabled: bool,
    pub mode: TimeMode,
    pub fixed_timestamp_ms: u64,
}

impl Default for TimePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: TimeMode::Deterministic,
            fixed_timestamp_ms: 1_700_000_000_000,
        }
    }
}

impl TimePolicy {
    pub fn real() -> Self {
        Self {
            enabled: true,
            mode: TimeMode::Real,
            fixed_timestamp_ms: 0,
        }
    }

    pub fn deterministic(timestamp_ms: u64) -> Self {
        Self {
            enabled: true,
            mode: TimeMode::Deterministic,
            fixed_timestamp_ms: timestamp_ms,
        }
    }

    pub fn development() -> Self {
        Self::real()
    }
}

#[allow(dead_code)]
pub struct TimeState {
    policy: TimePolicy,
    challenge_id: String,
    validator_id: String,
}

impl TimeState {
    pub fn new(policy: TimePolicy, challenge_id: String, validator_id: String) -> Self {
        Self {
            policy,
            challenge_id,
            validator_id,
        }
    }

    /// Update the fixed timestamp used in deterministic mode.
    /// Called by the persistent instance machinery to keep time current.
    pub fn set_fixed_timestamp(&mut self, ts_ms: u64) {
        self.policy.fixed_timestamp_ms = ts_ms;
    }

    pub fn get_timestamp(&self) -> Result<u64, TimeError> {
        if !self.policy.enabled {
            return Err(TimeError::Disabled);
        }

        match self.policy.mode {
            TimeMode::Real => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| TimeError::Failed(e.to_string()))?;
                Ok(now.as_millis() as u64)
            }
            TimeMode::Deterministic => Ok(self.policy.fixed_timestamp_ms),
        }
    }
}

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum TimeError {
    #[error("time access disabled")]
    Disabled,
    #[error("time failed: {0}")]
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct TimeHostFunctions {
    enabled: Vec<TimeHostFunction>,
}

impl TimeHostFunctions {
    pub fn new(enabled: Vec<TimeHostFunction>) -> Self {
        Self { enabled }
    }

    pub fn all() -> Self {
        Self {
            enabled: vec![TimeHostFunction::GetTimestamp],
        }
    }
}

impl Default for TimeHostFunctions {
    fn default() -> Self {
        Self::all()
    }
}

impl HostFunctionRegistrar for TimeHostFunctions {
    fn register(&self, linker: &mut Linker<RuntimeState>) -> Result<(), WasmRuntimeError> {
        if self.enabled.contains(&TimeHostFunction::GetTimestamp) {
            linker
                .func_wrap(
                    HOST_TIME_NAMESPACE,
                    HOST_GET_TIMESTAMP,
                    |mut caller: Caller<RuntimeState>| -> i64 { handle_get_timestamp(&mut caller) },
                )
                .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;
        }

        Ok(())
    }
}

fn handle_get_timestamp(caller: &mut Caller<RuntimeState>) -> i64 {
    match caller.data().time_state.get_timestamp() {
        Ok(ts) => ts as i64,
        Err(err) => {
            warn!(
                challenge_id = %caller.data().challenge_id,
                validator_id = %caller.data().validator_id,
                error = %err,
                "get_timestamp failed"
            );
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_policy_default() {
        let policy = TimePolicy::default();
        assert!(policy.enabled);
        assert_eq!(policy.mode, TimeMode::Deterministic);
        assert_eq!(policy.fixed_timestamp_ms, 1_700_000_000_000);
    }

    #[test]
    fn test_time_policy_real() {
        let policy = TimePolicy::real();
        assert!(policy.enabled);
        assert_eq!(policy.mode, TimeMode::Real);
    }

    #[test]
    fn test_time_policy_deterministic() {
        let ts = 1_234_567_890_000;
        let policy = TimePolicy::deterministic(ts);
        assert!(policy.enabled);
        assert_eq!(policy.mode, TimeMode::Deterministic);
        assert_eq!(policy.fixed_timestamp_ms, ts);
    }

    #[test]
    fn test_time_state_deterministic() {
        let state = TimeState::new(
            TimePolicy::deterministic(42_000),
            "test".into(),
            "test".into(),
        );
        assert_eq!(state.get_timestamp().unwrap(), 42_000);
    }

    #[test]
    fn test_time_state_real() {
        let state = TimeState::new(TimePolicy::real(), "test".into(), "test".into());
        let ts = state.get_timestamp().unwrap();
        assert!(ts > 1_700_000_000_000);
    }

    #[test]
    fn test_time_state_disabled() {
        let state = TimeState::new(
            TimePolicy {
                enabled: false,
                ..Default::default()
            },
            "test".into(),
            "test".into(),
        );
        let err = state.get_timestamp().unwrap_err();
        assert!(matches!(err, TimeError::Disabled));
    }

    #[test]
    fn test_time_host_functions_all() {
        let funcs = TimeHostFunctions::all();
        assert!(funcs.enabled.contains(&TimeHostFunction::GetTimestamp));
    }
}
