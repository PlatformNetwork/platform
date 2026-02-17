use anyhow::{Context, Result};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};
use wasm_runtime_interface::{
    ExecPolicy, InstanceConfig, NetworkHostFunctions, NetworkPolicy, RuntimeConfig, TimePolicy,
    WasmModule, WasmRuntime, WasmRuntimeError,
};

pub struct WasmExecutorConfig {
    pub module_dir: PathBuf,
    pub max_memory_bytes: u64,
    pub enable_fuel: bool,
    pub fuel_limit: Option<u64>,
}

impl Default for WasmExecutorConfig {
    fn default() -> Self {
        Self {
            module_dir: PathBuf::from("./wasm_modules"),
            max_memory_bytes: 512 * 1024 * 1024,
            enable_fuel: false,
            fuel_limit: None,
        }
    }
}

pub struct ExecutionMetrics {
    pub execution_time_ms: u128,
    pub memory_used_bytes: u64,
    pub network_requests_made: u32,
    pub fuel_consumed: Option<u64>,
}

pub struct WasmChallengeExecutor {
    runtime: WasmRuntime,
    config: WasmExecutorConfig,
    module_cache: RwLock<HashMap<String, Arc<WasmModule>>>,
}

impl WasmChallengeExecutor {
    pub fn new(config: WasmExecutorConfig) -> Result<Self> {
        let runtime_config = RuntimeConfig {
            max_memory_bytes: config.max_memory_bytes,
            max_instances: 32,
            allow_fuel: config.enable_fuel,
            fuel_limit: config.fuel_limit,
        };

        let runtime = WasmRuntime::new(runtime_config)
            .map_err(|e| anyhow::anyhow!("Failed to create WASM runtime: {}", e))?;

        info!(
            module_dir = %config.module_dir.display(),
            max_memory_bytes = config.max_memory_bytes,
            fuel_enabled = config.enable_fuel,
            "WASM challenge executor initialized"
        );

        Ok(Self {
            runtime,
            config,
            module_cache: RwLock::new(HashMap::new()),
        })
    }

    pub fn execute_evaluation(
        &self,
        module_path: &str,
        network_policy: &NetworkPolicy,
        input_data: &[u8],
    ) -> Result<(i64, ExecutionMetrics)> {
        let start = Instant::now();

        let module = self
            .load_module(module_path)
            .context("Failed to load WASM module")?;

        let network_host_fns = Arc::new(NetworkHostFunctions::all());

        let instance_config = InstanceConfig {
            network_policy: network_policy.clone(),
            exec_policy: ExecPolicy::default(),
            time_policy: TimePolicy::default(),
            audit_logger: None,
            memory_export: "memory".to_string(),
            challenge_id: module_path.to_string(),
            validator_id: "validator".to_string(),
            restart_id: String::new(),
            config_version: 0,
            ..Default::default()
        };

        let mut instance = self
            .runtime
            .instantiate(&module, instance_config, Some(network_host_fns))
            .map_err(|e| anyhow::anyhow!("WASM instantiation failed: {}", e))?;

        let initial_fuel = instance.fuel_remaining();

        let alloc_result = instance.call_i32_i32_return_i32("allocate", input_data.len() as i32, 0);
        let ptr = match alloc_result {
            Ok(p) => p,
            Err(_) => {
                let mem_size = instance.memory().data_size(instance.store());
                let offset = mem_size.saturating_sub(input_data.len() + 1024);
                if offset == 0 {
                    return Err(anyhow::anyhow!(
                        "WASM module has insufficient memory for input data"
                    ));
                }
                offset as i32
            }
        };

        instance
            .write_memory(ptr as usize, input_data)
            .map_err(|e| anyhow::anyhow!("Failed to write input data to WASM memory: {}", e))?;

        let score = instance
            .call_i32_i32_return_i64("evaluate", ptr, input_data.len() as i32)
            .map_err(|e| match &e {
                WasmRuntimeError::FuelExhausted => {
                    anyhow::anyhow!("WASM execution exceeded fuel limit")
                }
                WasmRuntimeError::Execution(msg) if msg.contains("timeout") => {
                    anyhow::anyhow!("WASM execution timed out")
                }
                _ => anyhow::anyhow!("WASM evaluate call failed: {}", e),
            })?;

        let fuel_consumed = match (initial_fuel, instance.fuel_remaining()) {
            (Some(initial), Some(remaining)) => Some(initial.saturating_sub(remaining)),
            _ => None,
        };

        let metrics = ExecutionMetrics {
            execution_time_ms: start.elapsed().as_millis(),
            memory_used_bytes: instance.memory().data_size(instance.store()) as u64,
            network_requests_made: instance.network_requests_made(),
            fuel_consumed,
        };

        info!(
            module = module_path,
            score,
            execution_time_ms = metrics.execution_time_ms,
            memory_bytes = metrics.memory_used_bytes,
            network_requests = metrics.network_requests_made,
            fuel_consumed = ?metrics.fuel_consumed,
            "WASM evaluation completed"
        );

        Ok((score, metrics))
    }

    #[allow(dead_code)]
    pub fn execute_validation(
        &self,
        module_path: &str,
        network_policy: &NetworkPolicy,
        input_data: &[u8],
    ) -> Result<(bool, ExecutionMetrics)> {
        let start = Instant::now();

        let module = self
            .load_module(module_path)
            .context("Failed to load WASM module")?;

        let network_host_fns = Arc::new(NetworkHostFunctions::all());

        let instance_config = InstanceConfig {
            network_policy: network_policy.clone(),
            exec_policy: ExecPolicy::default(),
            time_policy: TimePolicy::default(),
            audit_logger: None,
            memory_export: "memory".to_string(),
            challenge_id: module_path.to_string(),
            validator_id: "validator".to_string(),
            restart_id: String::new(),
            config_version: 0,
            ..Default::default()
        };

        let mut instance = self
            .runtime
            .instantiate(&module, instance_config, Some(network_host_fns))
            .map_err(|e| anyhow::anyhow!("WASM instantiation failed: {}", e))?;

        let initial_fuel = instance.fuel_remaining();

        let alloc_result = instance.call_i32_i32_return_i32("allocate", input_data.len() as i32, 0);
        let ptr = match alloc_result {
            Ok(p) => p,
            Err(_) => {
                let mem_size = instance.memory().data_size(instance.store());
                let offset = mem_size.saturating_sub(input_data.len() + 1024);
                if offset == 0 {
                    return Err(anyhow::anyhow!(
                        "WASM module has insufficient memory for input data"
                    ));
                }
                offset as i32
            }
        };

        instance
            .write_memory(ptr as usize, input_data)
            .map_err(|e| anyhow::anyhow!("Failed to write input data to WASM memory: {}", e))?;

        let result = instance
            .call_i32_i32_return_i32("validate", ptr, input_data.len() as i32)
            .map_err(|e| match &e {
                WasmRuntimeError::FuelExhausted => {
                    anyhow::anyhow!("WASM execution exceeded fuel limit")
                }
                WasmRuntimeError::Execution(msg) if msg.contains("timeout") => {
                    anyhow::anyhow!("WASM execution timed out")
                }
                _ => anyhow::anyhow!("WASM validate call failed: {}", e),
            })?;

        let valid = result != 0;

        let fuel_consumed = match (initial_fuel, instance.fuel_remaining()) {
            (Some(initial), Some(remaining)) => Some(initial.saturating_sub(remaining)),
            _ => None,
        };

        let metrics = ExecutionMetrics {
            execution_time_ms: start.elapsed().as_millis(),
            memory_used_bytes: instance.memory().data_size(instance.store()) as u64,
            network_requests_made: instance.network_requests_made(),
            fuel_consumed,
        };

        info!(
            module = module_path,
            valid,
            execution_time_ms = metrics.execution_time_ms,
            memory_bytes = metrics.memory_used_bytes,
            network_requests = metrics.network_requests_made,
            fuel_consumed = ?metrics.fuel_consumed,
            "WASM validation completed"
        );

        Ok((valid, metrics))
    }

    fn load_module(&self, module_path: &str) -> Result<Arc<WasmModule>> {
        {
            let cache = self.module_cache.read();
            if let Some(module) = cache.get(module_path) {
                debug!(module = module_path, "WASM module loaded from cache");
                return Ok(Arc::clone(module));
            }
        }

        let full_path = self.config.module_dir.join(module_path);
        let wasm_bytes = std::fs::read(&full_path)
            .with_context(|| format!("Failed to read WASM module from {}", full_path.display()))?;

        info!(
            module = module_path,
            size_bytes = wasm_bytes.len(),
            "Compiling WASM module"
        );

        let module = self
            .runtime
            .compile_module(&wasm_bytes)
            .map_err(|e| anyhow::anyhow!("WASM compilation failed: {}", e))?;

        let module = Arc::new(module);

        {
            let mut cache = self.module_cache.write();
            cache.insert(module_path.to_string(), Arc::clone(&module));
        }

        info!(module = module_path, "WASM module compiled and cached");
        Ok(module)
    }

    #[allow(dead_code)]
    pub fn invalidate_cache(&self, module_path: &str) {
        let mut cache = self.module_cache.write();
        if cache.remove(module_path).is_some() {
            info!(module = module_path, "WASM module cache entry invalidated");
        }
    }

    #[allow(dead_code)]
    pub fn clear_cache(&self) {
        let mut cache = self.module_cache.write();
        let count = cache.len();
        cache.clear();
        info!(cleared = count, "WASM module cache cleared");
    }

    #[allow(dead_code)]
    pub fn cached_module_count(&self) -> usize {
        self.module_cache.read().len()
    }

    pub fn resolve_module_path(&self, module_path: &str) -> PathBuf {
        self.config.module_dir.join(module_path)
    }

    pub fn module_exists(&self, module_path: &str) -> bool {
        self.resolve_module_path(module_path).exists()
    }
}
