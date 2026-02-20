#![no_std]

extern crate alloc;

pub mod alloc_impl;
pub mod host_functions;
pub mod llm_types;
pub mod types;

pub use llm_types::{LlmMessage, LlmRequest, LlmResponse, LlmUsage};
pub use types::{
    score_f64_scaled, SandboxExecRequest, SandboxExecResponse, TaskDefinition, TaskResult,
};
pub use types::{ContainerRunRequest, ContainerRunResponse};
pub use types::{EvaluationInput, EvaluationOutput};
pub use types::{WasmRouteDefinition, WasmRouteRequest, WasmRouteResponse, WeightEntry};

pub trait Challenge {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn evaluate(&self, input: EvaluationInput) -> EvaluationOutput;
    fn validate(&self, input: EvaluationInput) -> bool;

    fn generate_task(&self, _params: &[u8]) -> alloc::vec::Vec<u8> {
        alloc::vec::Vec::new()
    }

    fn setup_environment(&self, _config: &[u8]) -> bool {
        true
    }

    fn tasks(&self) -> alloc::vec::Vec<u8> {
        alloc::vec::Vec::new()
    }

    fn configure(&self, _config: &[u8]) {}

    /// Return serialized [`WasmRouteDefinition`]s describing the HTTP routes
    /// this challenge exposes. The default implementation returns an empty
    /// vector (no custom routes).
    fn routes(&self) -> alloc::vec::Vec<u8> {
        alloc::vec::Vec::new()
    }

    /// Handle an incoming route request and return a serialized
    /// [`WasmRouteResponse`]. The `request` parameter is a bincode-encoded
    /// [`WasmRouteRequest`]. The default implementation returns an empty
    /// vector.
    fn handle_route(&self, _request: &[u8]) -> alloc::vec::Vec<u8> {
        alloc::vec::Vec::new()
    }

    /// Return serialized epoch weight entries (`Vec<WeightEntry>`) that the
    /// validator should set on-chain. The default implementation returns an
    /// empty vector (no weights).
    fn get_weights(&self) -> alloc::vec::Vec<u8> {
        alloc::vec::Vec::new()
    }

    /// Validate whether a storage write with the given `key` and `value` is
    /// permitted. The default implementation allows all writes.
    fn validate_storage_write(&self, _key: &[u8], _value: &[u8]) -> bool {
        true
    }
}

/// Pack a pointer and length into a single i64 value.
///
/// The high 32 bits hold the length and the low 32 bits hold the pointer.
/// The host runtime uses this convention to locate serialized data in WASM
/// linear memory.
pub fn pack_ptr_len(ptr: i32, len: i32) -> i64 {
    ((len as i64) << 32) | ((ptr as u32) as i64)
}

/// Register a [`Challenge`] implementation and export the required WASM ABI
/// functions (`evaluate`, `validate`, `get_name`, `get_version`,
/// `generate_task`, `setup_environment`, `get_tasks`, `configure`,
/// `get_routes`, `handle_route`, and `alloc`).
///
/// The type must provide a `const fn new() -> Self` constructor so that the
/// challenge instance can be placed in a `static`.
///
/// # Usage
///
/// ```ignore
/// struct MyChallenge;
///
/// impl MyChallenge {
///     pub const fn new() -> Self { Self }
/// }
///
/// impl platform_challenge_sdk_wasm::Challenge for MyChallenge {
///     fn name(&self) -> &'static str { "my-challenge" }
///     fn version(&self) -> &'static str { "0.1.0" }
///     fn evaluate(&self, input: EvaluationInput) -> EvaluationOutput {
///         EvaluationOutput::success(100, "ok")
///     }
///     fn validate(&self, input: EvaluationInput) -> bool { true }
/// }
///
/// platform_challenge_sdk_wasm::register_challenge!(MyChallenge);
/// ```
///
/// A custom const initializer can be supplied when `Default::default()` is not
/// const-evaluable:
///
/// ```ignore
/// platform_challenge_sdk_wasm::register_challenge!(MyChallenge, MyChallenge::new());
/// ```
#[macro_export]
macro_rules! register_challenge {
    ($ty:ty) => {
        $crate::register_challenge!($ty, <$ty as Default>::default());
    };
    ($ty:ty, $init:expr) => {
        static _CHALLENGE: $ty = $init;

        #[no_mangle]
        pub extern "C" fn evaluate(agent_ptr: i32, agent_len: i32) -> i64 {
            let slice =
                unsafe { core::slice::from_raw_parts(agent_ptr as *const u8, agent_len as usize) };
            let input: $crate::EvaluationInput = match bincode::deserialize(slice) {
                Ok(v) => v,
                Err(_) => {
                    return $crate::pack_ptr_len(0, 0);
                }
            };
            let output = <$ty as $crate::Challenge>::evaluate(&_CHALLENGE, input);
            let encoded = match bincode::serialize(&output) {
                Ok(v) => v,
                Err(_) => {
                    return $crate::pack_ptr_len(0, 0);
                }
            };
            let ptr = $crate::alloc_impl::sdk_alloc(encoded.len());
            if ptr.is_null() {
                return $crate::pack_ptr_len(0, 0);
            }
            unsafe {
                core::ptr::copy_nonoverlapping(encoded.as_ptr(), ptr, encoded.len());
            }
            $crate::pack_ptr_len(ptr as i32, encoded.len() as i32)
        }

        #[no_mangle]
        pub extern "C" fn validate(agent_ptr: i32, agent_len: i32) -> i32 {
            let slice =
                unsafe { core::slice::from_raw_parts(agent_ptr as *const u8, agent_len as usize) };
            let input: $crate::EvaluationInput = match bincode::deserialize(slice) {
                Ok(v) => v,
                Err(_) => return 0,
            };
            if <$ty as $crate::Challenge>::validate(&_CHALLENGE, input) {
                1
            } else {
                0
            }
        }

        #[no_mangle]
        pub extern "C" fn get_name() -> i32 {
            let name = <$ty as $crate::Challenge>::name(&_CHALLENGE);
            let ptr = $crate::alloc_impl::sdk_alloc(4 + name.len());
            if ptr.is_null() {
                return 0;
            }
            let len_bytes = (name.len() as u32).to_le_bytes();
            unsafe {
                core::ptr::copy_nonoverlapping(len_bytes.as_ptr(), ptr, 4);
                core::ptr::copy_nonoverlapping(name.as_ptr(), ptr.add(4), name.len());
            }
            ptr as i32
        }

        #[no_mangle]
        pub extern "C" fn get_version() -> i32 {
            let ver = <$ty as $crate::Challenge>::version(&_CHALLENGE);
            let ptr = $crate::alloc_impl::sdk_alloc(4 + ver.len());
            if ptr.is_null() {
                return 0;
            }
            let len_bytes = (ver.len() as u32).to_le_bytes();
            unsafe {
                core::ptr::copy_nonoverlapping(len_bytes.as_ptr(), ptr, 4);
                core::ptr::copy_nonoverlapping(ver.as_ptr(), ptr.add(4), ver.len());
            }
            ptr as i32
        }

        #[no_mangle]
        pub extern "C" fn generate_task(params_ptr: i32, params_len: i32) -> i64 {
            let slice = unsafe {
                core::slice::from_raw_parts(params_ptr as *const u8, params_len as usize)
            };
            let output = <$ty as $crate::Challenge>::generate_task(&_CHALLENGE, slice);
            if output.is_empty() {
                return $crate::pack_ptr_len(0, 0);
            }
            let ptr = $crate::alloc_impl::sdk_alloc(output.len());
            if ptr.is_null() {
                return $crate::pack_ptr_len(0, 0);
            }
            unsafe {
                core::ptr::copy_nonoverlapping(output.as_ptr(), ptr, output.len());
            }
            $crate::pack_ptr_len(ptr as i32, output.len() as i32)
        }

        #[no_mangle]
        pub extern "C" fn setup_environment(config_ptr: i32, config_len: i32) -> i32 {
            let slice = unsafe {
                core::slice::from_raw_parts(config_ptr as *const u8, config_len as usize)
            };
            if <$ty as $crate::Challenge>::setup_environment(&_CHALLENGE, slice) {
                1
            } else {
                0
            }
        }

        #[no_mangle]
        pub extern "C" fn get_tasks() -> i64 {
            let output = <$ty as $crate::Challenge>::tasks(&_CHALLENGE);
            if output.is_empty() {
                return $crate::pack_ptr_len(0, 0);
            }
            let ptr = $crate::alloc_impl::sdk_alloc(output.len());
            if ptr.is_null() {
                return $crate::pack_ptr_len(0, 0);
            }
            unsafe {
                core::ptr::copy_nonoverlapping(output.as_ptr(), ptr, output.len());
            }
            $crate::pack_ptr_len(ptr as i32, output.len() as i32)
        }

        #[no_mangle]
        pub extern "C" fn configure(config_ptr: i32, config_len: i32) -> i32 {
            let slice = unsafe {
                core::slice::from_raw_parts(config_ptr as *const u8, config_len as usize)
            };
            <$ty as $crate::Challenge>::configure(&_CHALLENGE, slice);
            1
        }

        #[no_mangle]
        pub extern "C" fn get_routes() -> i64 {
            let output = <$ty as $crate::Challenge>::routes(&_CHALLENGE);
            if output.is_empty() {
                return $crate::pack_ptr_len(0, 0);
            }
            let ptr = $crate::alloc_impl::sdk_alloc(output.len());
            if ptr.is_null() {
                return $crate::pack_ptr_len(0, 0);
            }
            unsafe {
                core::ptr::copy_nonoverlapping(output.as_ptr(), ptr, output.len());
            }
            $crate::pack_ptr_len(ptr as i32, output.len() as i32)
        }

        #[no_mangle]
        pub extern "C" fn handle_route(req_ptr: i32, req_len: i32) -> i64 {
            let slice =
                unsafe { core::slice::from_raw_parts(req_ptr as *const u8, req_len as usize) };
            let output = <$ty as $crate::Challenge>::handle_route(&_CHALLENGE, slice);
            if output.is_empty() {
                return $crate::pack_ptr_len(0, 0);
            }
            let ptr = $crate::alloc_impl::sdk_alloc(output.len());
            if ptr.is_null() {
                return $crate::pack_ptr_len(0, 0);
            }
            unsafe {
                core::ptr::copy_nonoverlapping(output.as_ptr(), ptr, output.len());
            }
            $crate::pack_ptr_len(ptr as i32, output.len() as i32)
        }

        #[no_mangle]
        pub extern "C" fn get_weights() -> i64 {
            let output = <$ty as $crate::Challenge>::get_weights(&_CHALLENGE);
            if output.is_empty() {
                return $crate::pack_ptr_len(0, 0);
            }
            let ptr = $crate::alloc_impl::sdk_alloc(output.len());
            if ptr.is_null() {
                return $crate::pack_ptr_len(0, 0);
            }
            unsafe {
                core::ptr::copy_nonoverlapping(output.as_ptr(), ptr, output.len());
            }
            $crate::pack_ptr_len(ptr as i32, output.len() as i32)
        }

        #[no_mangle]
        pub extern "C" fn validate_storage_write(
            key_ptr: i32,
            key_len: i32,
            val_ptr: i32,
            val_len: i32,
        ) -> i32 {
            let key =
                unsafe { core::slice::from_raw_parts(key_ptr as *const u8, key_len as usize) };
            let value =
                unsafe { core::slice::from_raw_parts(val_ptr as *const u8, val_len as usize) };
            if <$ty as $crate::Challenge>::validate_storage_write(&_CHALLENGE, key, value) {
                1
            } else {
                0
            }
        }
    };
}
