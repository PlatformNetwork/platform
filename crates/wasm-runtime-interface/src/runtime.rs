use crate::{NetworkPolicy, NetworkState};
use std::sync::Arc;
use thiserror::Error;
use tracing::info;
use wasmtime::{
    Config, Engine, Error as WasmtimeError, Func, Instance, Linker, Memory, Module,
    ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder, Val,
};

pub const DEFAULT_WASM_MEMORY_NAME: &str = "memory";

#[derive(Debug, Error)]
pub enum WasmRuntimeError {
    #[error("module compile failed: {0}")]
    Compile(String),
    #[error("module instantiation failed: {0}")]
    Instantiate(String),
    #[error("host function registration failed: {0}")]
    HostFunction(String),
    #[error("missing export: {0}")]
    MissingExport(String),
    #[error("memory error: {0}")]
    Memory(String),
    #[error("execution error: {0}")]
    Execution(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("fuel exhausted")]
    FuelExhausted,
    #[error("policy violation: {0}")]
    PolicyViolation(String),
}

impl From<WasmtimeError> for WasmRuntimeError {
    fn from(err: WasmtimeError) -> Self {
        let msg = err.to_string();
        if msg.contains("fuel") {
            Self::FuelExhausted
        } else {
            Self::Execution(msg)
        }
    }
}

impl From<std::io::Error> for WasmRuntimeError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

pub trait HostFunctionRegistrar: Send + Sync {
    fn register(&self, linker: &mut Linker<RuntimeState>) -> Result<(), WasmRuntimeError>;
}

#[derive(Clone)]
pub struct RuntimeConfig {
    pub max_memory_bytes: u64,
    pub max_instances: u32,
    pub allow_fuel: bool,
    pub fuel_limit: Option<u64>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 512 * 1024 * 1024,
            max_instances: 32,
            allow_fuel: false,
            fuel_limit: None,
        }
    }
}

#[derive(Clone)]
pub struct InstanceConfig {
    pub network_policy: NetworkPolicy,
    pub memory_export: String,
    pub challenge_id: String,
    pub validator_id: String,
}

impl Default for InstanceConfig {
    fn default() -> Self {
        Self {
            network_policy: NetworkPolicy::default(),
            memory_export: DEFAULT_WASM_MEMORY_NAME.to_string(),
            challenge_id: "unknown".to_string(),
            validator_id: "unknown".to_string(),
        }
    }
}

pub struct RuntimeState {
    pub network_policy: NetworkPolicy,
    pub network_state: NetworkState,
    pub memory_export: String,
    pub challenge_id: String,
    pub validator_id: String,
    limits: StoreLimits,
}

impl RuntimeState {
    pub fn new(
        network_policy: NetworkPolicy,
        network_state: NetworkState,
        memory_export: String,
        challenge_id: String,
        validator_id: String,
        limits: StoreLimits,
    ) -> Self {
        Self {
            network_policy,
            network_state,
            memory_export,
            challenge_id,
            validator_id,
            limits,
        }
    }

    pub fn reset_network_counters(&mut self) {
        self.network_state.reset_counters();
    }
}

impl ResourceLimiter for RuntimeState {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, WasmtimeError> {
        self.limits.memory_growing(current, desired, maximum)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, WasmtimeError> {
        self.limits.table_growing(current, desired, maximum)
    }
}

pub struct WasmRuntime {
    engine: Engine,
    config: RuntimeConfig,
}

impl WasmRuntime {
    pub fn new(config: RuntimeConfig) -> Result<Self, WasmRuntimeError> {
        let mut engine_config = Config::new();
        if config.allow_fuel {
            engine_config.consume_fuel(true);
        }
        let engine = Engine::new(&engine_config)
            .map_err(|err: WasmtimeError| WasmRuntimeError::Execution(err.to_string()))?;
        Ok(Self { engine, config })
    }

    pub fn from_engine(engine: Engine, config: RuntimeConfig) -> Self {
        Self { engine, config }
    }

    pub fn compile_module(&self, wasm: &[u8]) -> Result<WasmModule, WasmRuntimeError> {
        let module = Module::from_binary(&self.engine, wasm)
            .map_err(|err: WasmtimeError| WasmRuntimeError::Compile(err.to_string()))?;
        Ok(WasmModule { module })
    }

    pub fn instantiate(
        &self,
        module: &WasmModule,
        instance_config: InstanceConfig,
        registrar: Option<Arc<dyn HostFunctionRegistrar>>,
    ) -> Result<ChallengeInstance, WasmRuntimeError> {
        let mut limits = StoreLimitsBuilder::new();
        limits = limits.memory_size(self.config.max_memory_bytes as usize);
        limits = limits.instances(self.config.max_instances as usize);
        let network_state = NetworkState::new(
            instance_config.network_policy.clone(),
            None,
            instance_config.challenge_id.clone(),
            instance_config.validator_id.clone(),
        )
        .map_err(|err| WasmRuntimeError::HostFunction(err.to_string()))?;
        let runtime_state = RuntimeState::new(
            instance_config.network_policy.clone(),
            network_state,
            instance_config.memory_export.clone(),
            instance_config.challenge_id.clone(),
            instance_config.validator_id.clone(),
            limits.build(),
        );
        let mut store = Store::new(&self.engine, runtime_state);

        if self.config.allow_fuel {
            if let Some(limit) = self.config.fuel_limit {
                store
                    .set_fuel(limit)
                    .map_err(|err: WasmtimeError| WasmRuntimeError::Execution(err.to_string()))?;
            }
        }

        store.limiter(|state| &mut state.limits);

        let mut linker = Linker::new(&self.engine);
        if let Some(registrar) = registrar {
            registrar.register(&mut linker)?;
        }

        let instance = linker
            .instantiate(&mut store, &module.module)
            .map_err(|err: WasmtimeError| WasmRuntimeError::Instantiate(err.to_string()))?;

        let memory = instance
            .get_memory(&mut store, &instance_config.memory_export)
            .ok_or_else(|| {
                WasmRuntimeError::MissingExport(instance_config.memory_export.clone())
            })?;

        info!(
            challenge_id = %instance_config.challenge_id,
            validator_id = %instance_config.validator_id,
            max_memory = self.config.max_memory_bytes,
            fuel_enabled = self.config.allow_fuel,
            fuel_limit = ?self.config.fuel_limit,
            "wasm challenge instance created"
        );

        Ok(ChallengeInstance {
            store,
            instance,
            memory,
        })
    }
}

pub struct WasmModule {
    module: Module,
}

impl WasmModule {
    pub fn module(&self) -> &Module {
        &self.module
    }
}

pub struct ChallengeInstance {
    store: Store<RuntimeState>,
    instance: Instance,
    memory: Memory,
}

impl ChallengeInstance {
    pub fn store(&self) -> &Store<RuntimeState> {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut Store<RuntimeState> {
        &mut self.store
    }

    pub fn memory(&self) -> &Memory {
        &self.memory
    }

    pub fn get_func(&mut self, name: &str) -> Result<Func, WasmRuntimeError> {
        self.instance
            .get_func(&mut self.store, name)
            .ok_or_else(|| WasmRuntimeError::MissingExport(name.to_string()))
    }

    pub fn call(&mut self, name: &str, params: &[Val]) -> Result<Vec<Val>, WasmRuntimeError> {
        let func = self.get_func(name)?;
        let ty = func.ty(&self.store);
        let mut results = vec![Val::I32(0); ty.results().len()];
        func.call(&mut self.store, params, &mut results)?;
        Ok(results)
    }

    pub fn read_memory(
        &mut self,
        offset: usize,
        length: usize,
    ) -> Result<Vec<u8>, WasmRuntimeError> {
        let data = self.memory.data(&self.store);
        let end = offset.saturating_add(length);
        if end > data.len() {
            return Err(WasmRuntimeError::Memory("read out of bounds".to_string()));
        }
        Ok(data[offset..end].to_vec())
    }

    pub fn write_memory(&mut self, offset: usize, bytes: &[u8]) -> Result<(), WasmRuntimeError> {
        let data = self.memory.data_mut(&mut self.store);
        let end = offset.saturating_add(bytes.len());
        if end > data.len() {
            return Err(WasmRuntimeError::Memory("write out of bounds".to_string()));
        }
        data[offset..end].copy_from_slice(bytes);
        Ok(())
    }

    pub fn call_i32_i32_return_i64(
        &mut self,
        name: &str,
        arg0: i32,
        arg1: i32,
    ) -> Result<i64, WasmRuntimeError> {
        let func = self
            .instance
            .get_typed_func::<(i32, i32), i64>(&mut self.store, name)
            .map_err(|_| WasmRuntimeError::MissingExport(name.to_string()))?;
        func.call(&mut self.store, (arg0, arg1))
            .map_err(|err: WasmtimeError| WasmRuntimeError::Execution(err.to_string()))
    }

    pub fn call_i32_i32_return_i32(
        &mut self,
        name: &str,
        arg0: i32,
        arg1: i32,
    ) -> Result<i32, WasmRuntimeError> {
        let func = self
            .instance
            .get_typed_func::<(i32, i32), i32>(&mut self.store, name)
            .map_err(|_| WasmRuntimeError::MissingExport(name.to_string()))?;
        func.call(&mut self.store, (arg0, arg1))
            .map_err(|err: WasmtimeError| WasmRuntimeError::Execution(err.to_string()))
    }

    pub fn call_return_i32(&mut self, name: &str) -> Result<i32, WasmRuntimeError> {
        let func = self
            .instance
            .get_typed_func::<(), i32>(&mut self.store, name)
            .map_err(|_| WasmRuntimeError::MissingExport(name.to_string()))?;
        func.call(&mut self.store, ())
            .map_err(|err: WasmtimeError| WasmRuntimeError::Execution(err.to_string()))
    }

    pub fn call_return_i64(&mut self, name: &str) -> Result<i64, WasmRuntimeError> {
        let func = self
            .instance
            .get_typed_func::<(), i64>(&mut self.store, name)
            .map_err(|_| WasmRuntimeError::MissingExport(name.to_string()))?;
        func.call(&mut self.store, ())
            .map_err(|err: WasmtimeError| WasmRuntimeError::Execution(err.to_string()))
    }

    pub fn fuel_remaining(&self) -> Option<u64> {
        self.store.get_fuel().ok()
    }

    pub fn network_requests_made(&self) -> u32 {
        self.store.data().network_state.requests_made()
    }

    pub fn network_dns_lookups(&self) -> u32 {
        self.store.data().network_state.dns_lookups()
    }

    pub fn reset_network_state(&mut self) {
        self.store.data_mut().reset_network_counters();
    }

    pub fn challenge_id(&self) -> &str {
        &self.store.data().challenge_id
    }

    pub fn validator_id(&self) -> &str {
        &self.store.data().validator_id
    }

    pub fn with_state<F, T>(&mut self, func: F) -> Result<T, WasmRuntimeError>
    where
        F: FnOnce(&mut RuntimeState) -> Result<T, WasmRuntimeError>,
    {
        func(self.store.data_mut())
    }
}
