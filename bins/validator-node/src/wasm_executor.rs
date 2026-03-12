use anyhow::{Context, Result};
use parking_lot::{Mutex, RwLock};
use platform_challenge_sdk_wasm::{DedupFlags, EvaluationInput, EvaluationOutput, WeightEntry};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};
use wasm_runtime_interface::{
    ChallengeInstance, ConsensusPolicy, ExecPolicy, InMemoryStorageBackend, InstanceConfig,
    LlmPolicy, NetworkPolicy, RuntimeConfig, SandboxPolicy, StorageBackend, StorageHostConfig,
    TerminalPolicy, TimePolicy, WasmModule, WasmRuntime, WasmRuntimeError,
};

const MAX_EVALUATION_OUTPUT_SIZE: usize = 64 * 1024 * 1024;
const MAX_ROUTE_OUTPUT_SIZE: u64 = 16 * 1024 * 1024;
const MAX_TASK_OUTPUT_SIZE: u64 = 16 * 1024 * 1024;

#[allow(dead_code)]
pub struct WasmExecutorConfig {
    pub module_dir: PathBuf,
    pub max_memory_bytes: u64,
    pub enable_fuel: bool,
    pub fuel_limit: Option<u64>,
    pub storage_host_config: StorageHostConfig,
    pub storage_backend: Arc<dyn StorageBackend>,
    pub chutes_api_key: Option<String>,
    /// Optional distributed storage for loading WASM modules
    pub distributed_storage: Option<Arc<dyn platform_distributed_storage::DistributedStore>>,
    /// Shared chain state: LLM-capable validators (JSON bytes)
    pub llm_validators_json: Arc<parking_lot::RwLock<Vec<u8>>>,
    /// Shared chain state: registered hotkeys (JSON bytes)
    pub registered_hotkeys_json: Arc<parking_lot::RwLock<Vec<u8>>>,
}

impl std::fmt::Debug for WasmExecutorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmExecutorConfig")
            .field("module_dir", &self.module_dir)
            .field("max_memory_bytes", &self.max_memory_bytes)
            .field("enable_fuel", &self.enable_fuel)
            .field("fuel_limit", &self.fuel_limit)
            .field(
                "chutes_api_key",
                &self.chutes_api_key.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl Default for WasmExecutorConfig {
    fn default() -> Self {
        Self {
            module_dir: PathBuf::from("./wasm_modules"),
            max_memory_bytes: 512 * 1024 * 1024,
            enable_fuel: false,
            fuel_limit: None,
            storage_host_config: StorageHostConfig::default(),
            storage_backend: Arc::new(InMemoryStorageBackend::new()),
            chutes_api_key: None,
            distributed_storage: None,
            llm_validators_json: Arc::new(parking_lot::RwLock::new(Vec::new())),
            registered_hotkeys_json: Arc::new(parking_lot::RwLock::new(Vec::new())),
        }
    }
}

pub struct ExecutionMetrics {
    pub execution_time_ms: u128,
    pub memory_used_bytes: u64,
    pub network_requests_made: u32,
    pub fuel_consumed: Option<u64>,
}

/// Per-challenge deduplication state. Each function that the WASM module
/// requested deduplication for gets an [`AtomicBool`] guard.
struct DedupState {
    flags: i32,
    sync_running: AtomicBool,
    get_weights_running: AtomicBool,
    evaluate_running: AtomicBool,
}

impl DedupState {
    fn new(flags: i32) -> Self {
        Self {
            flags,
            sync_running: AtomicBool::new(false),
            get_weights_running: AtomicBool::new(false),
            evaluate_running: AtomicBool::new(false),
        }
    }

    fn try_acquire(&self, flag: i32) -> Option<DedupGuard<'_>> {
        if self.flags & flag == 0 {
            return Some(DedupGuard { atom: None });
        }
        let atom = match flag {
            DedupFlags::SYNC => &self.sync_running,
            DedupFlags::GET_WEIGHTS => &self.get_weights_running,
            DedupFlags::EVALUATE => &self.evaluate_running,
            _ => return Some(DedupGuard { atom: None }),
        };
        if atom
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(DedupGuard { atom: Some(atom) })
        } else {
            None
        }
    }
}

struct DedupGuard<'a> {
    atom: Option<&'a AtomicBool>,
}

impl Drop for DedupGuard<'_> {
    fn drop(&mut self) {
        if let Some(atom) = self.atom {
            atom.store(false, Ordering::Release);
        }
    }
}

/// A persistent WASM instance that stays alive between calls.
/// The module_version tracks which compiled module this instance was created
/// from; when the module is re-uploaded the instance is recreated.
struct PersistentInstance {
    instance: ChallengeInstance,
    module_version: u64,
    created_at: Instant,
}

// ChallengeInstance contains wasmtime Store which is Send but not Sync.
// We protect access with a Mutex so only one call at a time.
unsafe impl Send for PersistentInstance {}

pub struct WasmChallengeExecutor {
    runtime: WasmRuntime,
    config: WasmExecutorConfig,
    module_cache: RwLock<HashMap<String, Arc<WasmModule>>>,
    module_versions: RwLock<HashMap<String, u64>>,
    persistent_instances: RwLock<HashMap<String, Arc<Mutex<PersistentInstance>>>>,
    dedup_state: RwLock<HashMap<String, Arc<DedupState>>>,
    /// Cache of last successful get_weights results per challenge.
    /// Used to return stale-but-valid data when the dedup guard blocks a concurrent call,
    /// instead of returning an empty Vec that the caller treats as "0 entries → 100% burn".
    last_good_weights: RwLock<HashMap<String, Vec<platform_challenge_sdk::WeightAssignment>>>,
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
            module_versions: RwLock::new(HashMap::new()),
            persistent_instances: RwLock::new(HashMap::new()),
            dedup_state: RwLock::new(HashMap::new()),
            last_good_weights: RwLock::new(HashMap::new()),
        })
    }

    fn get_or_init_dedup(&self, challenge_id: &str, module: &WasmModule) -> Arc<DedupState> {
        {
            let cache = self.dedup_state.read();
            if let Some(state) = cache.get(challenge_id) {
                return Arc::clone(state);
            }
        }
        let flags = self.query_dedup_flags(module);
        let state = Arc::new(DedupState::new(flags));
        let mut cache = self.dedup_state.write();
        cache
            .entry(challenge_id.to_string())
            .or_insert_with(|| Arc::clone(&state));
        Arc::clone(cache.get(challenge_id).unwrap())
    }

    fn query_dedup_flags(&self, module: &WasmModule) -> i32 {
        let instance_config = InstanceConfig {
            challenge_id: "dedup-probe".to_string(),
            validator_id: "validator".to_string(),
            storage_host_config: self.config.storage_host_config.clone(),
            storage_backend: Arc::clone(&self.config.storage_backend),
            ..Default::default()
        };
        let mut instance = match self.runtime.instantiate(module, instance_config, None) {
            Ok(i) => i,
            Err(_) => return DedupFlags::NONE,
        };
        match instance.call_return_i32("get_dedup_flags") {
            Ok(flags) => {
                if flags != 0 {
                    info!(flags, "WASM module declares dedup flags");
                }
                flags
            }
            Err(_) => DedupFlags::NONE,
        }
    }

    pub fn execute_evaluation(
        &self,
        module_path: &str,
        network_policy: &NetworkPolicy,
        agent_data: &[u8],
        challenge_id: &str,
        params: &[u8],
    ) -> Result<(EvaluationOutput, ExecutionMetrics)> {
        self.execute_evaluation_with_sandbox(
            module_path,
            network_policy,
            &SandboxPolicy::default(),
            agent_data,
            challenge_id,
            params,
        )
    }

    pub fn execute_evaluation_with_sandbox(
        &self,
        module_path: &str,
        network_policy: &NetworkPolicy,
        sandbox_policy: &SandboxPolicy,
        agent_data: &[u8],
        challenge_id: &str,
        params: &[u8],
    ) -> Result<(EvaluationOutput, ExecutionMetrics)> {
        let start = Instant::now();

        let module = self
            .load_module(module_path)
            .context("Failed to load WASM module")?;

        let dedup = self.get_or_init_dedup(module_path, &module);
        let _guard = match dedup.try_acquire(DedupFlags::EVALUATE) {
            Some(g) => g,
            None => {
                debug!(module = module_path, "evaluate skipped: already running");
                let metrics = ExecutionMetrics {
                    execution_time_ms: 0,
                    memory_used_bytes: 0,
                    network_requests_made: 0,
                    fuel_consumed: None,
                };
                return Ok((
                    EvaluationOutput::failure("skipped: already running"),
                    metrics,
                ));
            }
        };

        let input = EvaluationInput {
            agent_data: agent_data.to_vec(),
            challenge_id: challenge_id.to_string(),
            params: params.to_vec(),
            task_definition: None,
            environment_config: None,
        };

        let serialized =
            bincode::serialize(&input).context("Failed to serialize EvaluationInput")?;

        let instance_config = InstanceConfig {
            network_policy: network_policy.clone(),
            sandbox_policy: sandbox_policy.clone(),
            exec_policy: ExecPolicy::default(),
            time_policy: TimePolicy::default(),
            audit_logger: None,
            memory_export: "memory".to_string(),
            challenge_id: challenge_id.to_string(),
            validator_id: "validator".to_string(),
            restart_id: String::new(),
            config_version: 0,
            storage_host_config: StorageHostConfig {
                allow_direct_writes: true,
                require_consensus: true,
                ..self.config.storage_host_config.clone()
            },
            storage_backend: Arc::clone(&self.config.storage_backend),
            fixed_timestamp_ms: None,
            consensus_policy: ConsensusPolicy::default(),
            terminal_policy: TerminalPolicy::default(),
            llm_policy: match &self.config.chutes_api_key {
                Some(key) => LlmPolicy::with_api_key(key.clone()),
                None => LlmPolicy::default(),
            },
            ..Default::default()
        };

        let mut instance = self
            .runtime
            .instantiate(&module, instance_config, None)
            .map_err(|e| anyhow::anyhow!("WASM instantiation failed: {}", e))?;

        let initial_fuel = instance.fuel_remaining();

        let ptr = self.allocate_input(&mut instance, &serialized)?;

        instance
            .write_memory(ptr as usize, &serialized)
            .map_err(|e| anyhow::anyhow!("Failed to write input data to WASM memory: {}", e))?;

        let result = instance
            .call_i32_i32_return_i64("evaluate", ptr, serialized.len() as i32)
            .map_err(|e| match &e {
                WasmRuntimeError::FuelExhausted => {
                    anyhow::anyhow!("WASM execution exceeded fuel limit")
                }
                WasmRuntimeError::Execution(msg) if msg.contains("timeout") => {
                    anyhow::anyhow!("WASM execution timed out")
                }
                _ => anyhow::anyhow!("WASM evaluate call failed: {}", e),
            })?;

        let out_len = ((result >> 32) & 0xFFFF_FFFF) as u32;
        let out_ptr = (result & 0xFFFF_FFFF) as u32;

        if out_ptr == 0 && out_len == 0 {
            return Err(anyhow::anyhow!(
                "WASM evaluate returned null pointer, deserialization failed inside module"
            ));
        }

        if out_len as usize > MAX_EVALUATION_OUTPUT_SIZE {
            return Err(anyhow::anyhow!(
                "EvaluationOutput size {} exceeds maximum allowed {}",
                out_len,
                MAX_EVALUATION_OUTPUT_SIZE
            ));
        }

        let output_bytes = instance
            .read_memory(out_ptr as usize, out_len as usize)
            .map_err(|e| {
                anyhow::anyhow!("Failed to read evaluation output from WASM memory: {}", e)
            })?;

        let output: EvaluationOutput = bincode::deserialize(&output_bytes)
            .context("Failed to deserialize EvaluationOutput from WASM module")?;

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
            challenge_id,
            score = output.score,
            valid = output.valid,
            message = %output.message,
            execution_time_ms = metrics.execution_time_ms,
            memory_bytes = metrics.memory_used_bytes,
            network_requests = metrics.network_requests_made,
            fuel_consumed = ?metrics.fuel_consumed,
            "WASM evaluation completed"
        );

        Ok((output, metrics))
    }

    #[allow(dead_code)]
    pub fn execute_validation(
        &self,
        module_path: &str,
        network_policy: &NetworkPolicy,
        agent_data: &[u8],
        challenge_id: &str,
        params: &[u8],
    ) -> Result<(bool, ExecutionMetrics)> {
        let start = Instant::now();

        let module = self
            .load_module(module_path)
            .context("Failed to load WASM module")?;

        let input = EvaluationInput {
            agent_data: agent_data.to_vec(),
            challenge_id: challenge_id.to_string(),
            params: params.to_vec(),
            task_definition: None,
            environment_config: None,
        };

        let serialized =
            bincode::serialize(&input).context("Failed to serialize EvaluationInput")?;

        let instance_config = InstanceConfig {
            network_policy: network_policy.clone(),
            sandbox_policy: SandboxPolicy::default(),
            exec_policy: ExecPolicy::default(),
            time_policy: TimePolicy::default(),
            audit_logger: None,
            memory_export: "memory".to_string(),
            challenge_id: challenge_id.to_string(),
            validator_id: "validator".to_string(),
            restart_id: String::new(),
            config_version: 0,
            storage_host_config: StorageHostConfig {
                allow_direct_writes: true,
                require_consensus: true,
                ..self.config.storage_host_config.clone()
            },
            storage_backend: Arc::clone(&self.config.storage_backend),
            fixed_timestamp_ms: None,
            consensus_policy: ConsensusPolicy::default(),
            terminal_policy: TerminalPolicy::default(),
            llm_policy: match &self.config.chutes_api_key {
                Some(key) => LlmPolicy::with_api_key(key.clone()),
                None => LlmPolicy::default(),
            },
            ..Default::default()
        };

        let mut instance = self
            .runtime
            .instantiate(&module, instance_config, None)
            .map_err(|e| anyhow::anyhow!("WASM instantiation failed: {}", e))?;

        let initial_fuel = instance.fuel_remaining();

        let ptr = self.allocate_input(&mut instance, &serialized)?;

        instance
            .write_memory(ptr as usize, &serialized)
            .map_err(|e| anyhow::anyhow!("Failed to write input data to WASM memory: {}", e))?;

        let result = instance
            .call_i32_i32_return_i32("validate", ptr, serialized.len() as i32)
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
            challenge_id,
            valid,
            execution_time_ms = metrics.execution_time_ms,
            memory_bytes = metrics.memory_used_bytes,
            network_requests = metrics.network_requests_made,
            fuel_consumed = ?metrics.fuel_consumed,
            "WASM validation completed"
        );

        Ok((valid, metrics))
    }

    fn allocate_input(
        &self,
        instance: &mut wasm_runtime_interface::ChallengeInstance,
        input_data: &[u8],
    ) -> Result<i32> {
        if let Ok(p) = instance.call_i32_return_i32("alloc", input_data.len() as i32) {
            return Ok(p);
        }

        if let Ok(p) = instance.call_i32_i32_return_i32("allocate", input_data.len() as i32, 0) {
            return Ok(p);
        }

        let mem_size = instance.memory().data_size(instance.store());
        let required = input_data.len() + 1024;
        if mem_size < required + 4096 {
            return Err(anyhow::anyhow!(
                "WASM module has insufficient memory for input data ({} < {})",
                mem_size,
                required + 4096
            ));
        }
        let offset = mem_size - required;
        Ok(offset as i32)
    }

    #[allow(dead_code)]
    pub fn execute_get_tasks(
        &self,
        module_path: &str,
        network_policy: &NetworkPolicy,
        sandbox_policy: &SandboxPolicy,
    ) -> Result<(Vec<u8>, ExecutionMetrics)> {
        let start = Instant::now();

        let module = self
            .load_module(module_path)
            .context("Failed to load WASM module")?;

        let instance_config = InstanceConfig {
            network_policy: network_policy.clone(),
            sandbox_policy: sandbox_policy.clone(),
            exec_policy: ExecPolicy::default(),
            time_policy: TimePolicy::default(),
            audit_logger: None,
            memory_export: "memory".to_string(),
            challenge_id: module_path.to_string(),
            validator_id: "validator".to_string(),
            restart_id: String::new(),
            config_version: 0,
            storage_host_config: self.config.storage_host_config.clone(),
            storage_backend: Arc::clone(&self.config.storage_backend),
            fixed_timestamp_ms: None,
            consensus_policy: ConsensusPolicy::default(),
            terminal_policy: TerminalPolicy::default(),
            llm_policy: match &self.config.chutes_api_key {
                Some(key) => LlmPolicy::with_api_key(key.clone()),
                None => LlmPolicy::default(),
            },
            ..Default::default()
        };

        let mut instance = self
            .runtime
            .instantiate(&module, instance_config, None)
            .map_err(|e| anyhow::anyhow!("WASM instantiation failed: {}", e))?;

        let initial_fuel = instance.fuel_remaining();

        let result = instance
            .call_return_i64("get_tasks")
            .map_err(|e| anyhow::anyhow!("WASM get_tasks call failed: {}", e))?;

        let out_len = (result >> 32) as i32;
        let out_ptr = (result & 0xFFFF_FFFF) as i32;

        if out_len > 0 && out_len as u64 > MAX_TASK_OUTPUT_SIZE {
            return Err(anyhow::anyhow!(
                "WASM get_tasks output size {} exceeds maximum allowed {}",
                out_len,
                MAX_TASK_OUTPUT_SIZE
            ));
        }

        let result_data = if out_ptr > 0 && out_len > 0 {
            instance
                .read_memory(out_ptr as usize, out_len as usize)
                .map_err(|e| {
                    anyhow::anyhow!("failed to read WASM memory for get_tasks output: {}", e)
                })?
        } else {
            Vec::new()
        };

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
            result_bytes = result_data.len(),
            execution_time_ms = metrics.execution_time_ms,
            "WASM get_tasks completed"
        );

        Ok((result_data, metrics))
    }

    #[allow(dead_code)]
    pub fn execute_configure(
        &self,
        module_path: &str,
        network_policy: &NetworkPolicy,
        sandbox_policy: &SandboxPolicy,
        config_data: &[u8],
    ) -> Result<(i32, ExecutionMetrics)> {
        let start = Instant::now();

        let module = self
            .load_module(module_path)
            .context("Failed to load WASM module")?;

        let instance_config = InstanceConfig {
            network_policy: network_policy.clone(),
            sandbox_policy: sandbox_policy.clone(),
            exec_policy: ExecPolicy::default(),
            time_policy: TimePolicy::default(),
            audit_logger: None,
            memory_export: "memory".to_string(),
            challenge_id: module_path.to_string(),
            validator_id: "validator".to_string(),
            restart_id: String::new(),
            config_version: 0,
            storage_host_config: self.config.storage_host_config.clone(),
            storage_backend: Arc::clone(&self.config.storage_backend),
            fixed_timestamp_ms: None,
            consensus_policy: ConsensusPolicy::default(),
            terminal_policy: TerminalPolicy::default(),
            llm_policy: match &self.config.chutes_api_key {
                Some(key) => LlmPolicy::with_api_key(key.clone()),
                None => LlmPolicy::default(),
            },
            ..Default::default()
        };

        let mut instance = self
            .runtime
            .instantiate(&module, instance_config, None)
            .map_err(|e| anyhow::anyhow!("WASM instantiation failed: {}", e))?;

        let initial_fuel = instance.fuel_remaining();

        let ptr = self.allocate_input(&mut instance, config_data)?;

        instance
            .write_memory(ptr as usize, config_data)
            .map_err(|e| anyhow::anyhow!("Failed to write config data to WASM memory: {}", e))?;

        let result = instance
            .call_i32_i32_return_i32("configure", ptr, config_data.len() as i32)
            .map_err(|e| anyhow::anyhow!("WASM configure call failed: {}", e))?;

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
            result,
            execution_time_ms = metrics.execution_time_ms,
            "WASM configure completed"
        );

        Ok((result, metrics))
    }

    #[allow(dead_code)]
    pub fn execute_get_routes(
        &self,
        module_path: &str,
        network_policy: &NetworkPolicy,
        sandbox_policy: &SandboxPolicy,
    ) -> Result<(Vec<u8>, ExecutionMetrics)> {
        let start = Instant::now();

        let module = self
            .load_module(module_path)
            .context("Failed to load WASM module")?;

        let instance_config = InstanceConfig {
            network_policy: network_policy.clone(),
            sandbox_policy: sandbox_policy.clone(),
            exec_policy: ExecPolicy::default(),
            time_policy: TimePolicy::default(),
            audit_logger: None,
            memory_export: "memory".to_string(),
            challenge_id: module_path.to_string(),
            validator_id: "validator".to_string(),
            restart_id: String::new(),
            config_version: 0,
            storage_host_config: self.config.storage_host_config.clone(),
            storage_backend: Arc::clone(&self.config.storage_backend),
            fixed_timestamp_ms: None,
            consensus_policy: ConsensusPolicy::default(),
            terminal_policy: TerminalPolicy::default(),
            llm_policy: match &self.config.chutes_api_key {
                Some(key) => LlmPolicy::with_api_key(key.clone()),
                None => LlmPolicy::default(),
            },
            ..Default::default()
        };

        let mut instance = self
            .runtime
            .instantiate(&module, instance_config, None)
            .map_err(|e| anyhow::anyhow!("WASM instantiation failed: {}", e))?;

        let initial_fuel = instance.fuel_remaining();

        let result = instance
            .call_return_i64("get_routes")
            .map_err(|e| anyhow::anyhow!("WASM get_routes call failed: {}", e))?;

        let out_len = (result >> 32) as i32;
        let out_ptr = (result & 0xFFFF_FFFF) as i32;

        if out_len > 0 && out_len as u64 > MAX_ROUTE_OUTPUT_SIZE {
            return Err(anyhow::anyhow!(
                "WASM get_routes output size {} exceeds maximum allowed {}",
                out_len,
                MAX_ROUTE_OUTPUT_SIZE
            ));
        }

        let result_data = if out_ptr > 0 && out_len > 0 {
            instance
                .read_memory(out_ptr as usize, out_len as usize)
                .map_err(|e| {
                    anyhow::anyhow!("failed to read WASM memory for get_routes output: {}", e)
                })?
        } else {
            Vec::new()
        };

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
            result_bytes = result_data.len(),
            execution_time_ms = metrics.execution_time_ms,
            "WASM get_routes completed"
        );

        Ok((result_data, metrics))
    }

    /// Execute get_routes using provided WASM bytes directly (avoids reload)
    pub fn execute_get_routes_from_bytes(
        &self,
        module_id: &str,
        wasm_bytes: &[u8],
        network_policy: &NetworkPolicy,
        sandbox_policy: &SandboxPolicy,
    ) -> Result<(Vec<u8>, ExecutionMetrics)> {
        let start = Instant::now();

        info!(
            module = module_id,
            size_bytes = wasm_bytes.len(),
            "Compiling WASM module from bytes"
        );

        let module = self
            .runtime
            .compile_module(wasm_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to compile WASM module: {}", e))?;

        // Cache the compiled module for later use by call_route
        let module = Arc::new(module);
        {
            let mut cache = self.module_cache.write();
            cache.insert(module_id.to_string(), Arc::clone(&module));
        }

        // Note: Don't pass extra host functions - instantiate() already registers all of them
        let instance_config = InstanceConfig {
            network_policy: network_policy.clone(),
            sandbox_policy: sandbox_policy.clone(),
            exec_policy: ExecPolicy::default(),
            time_policy: TimePolicy::default(),
            audit_logger: None,
            memory_export: "memory".to_string(),
            challenge_id: module_id.to_string(),
            validator_id: "validator".to_string(),
            restart_id: String::new(),
            config_version: 0,
            storage_host_config: self.config.storage_host_config.clone(),
            storage_backend: Arc::clone(&self.config.storage_backend),
            fixed_timestamp_ms: None,
            consensus_policy: ConsensusPolicy::default(),
            terminal_policy: TerminalPolicy::default(),
            llm_policy: match &self.config.chutes_api_key {
                Some(key) => LlmPolicy::with_api_key(key.clone()),
                None => LlmPolicy::default(),
            },
            ..Default::default()
        };

        let mut instance = self
            .runtime
            .instantiate(&module, instance_config, None) // None - host functions already registered
            .map_err(|e| anyhow::anyhow!("WASM instantiation failed: {}", e))?;

        let initial_fuel = instance.fuel_remaining();

        let result = instance
            .call_return_i64("get_routes")
            .map_err(|e| anyhow::anyhow!("WASM get_routes call failed: {}", e))?;

        let out_len = (result >> 32) as i32;
        let out_ptr = (result & 0xFFFF_FFFF) as i32;

        if out_len > 0 && out_len as u64 > MAX_ROUTE_OUTPUT_SIZE {
            return Err(anyhow::anyhow!(
                "WASM get_routes output size {} exceeds maximum allowed {}",
                out_len,
                MAX_ROUTE_OUTPUT_SIZE
            ));
        }

        let result_data = if out_ptr > 0 && out_len > 0 {
            instance
                .read_memory(out_ptr as usize, out_len as usize)
                .map_err(|e| {
                    anyhow::anyhow!("failed to read WASM memory for get_routes output: {}", e)
                })?
        } else {
            Vec::new()
        };

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
            module = module_id,
            result_bytes = result_data.len(),
            execution_time_ms = metrics.execution_time_ms,
            "WASM get_routes from bytes completed"
        );

        Ok((result_data, metrics))
    }

    #[allow(dead_code)]
    pub fn execute_handle_route(
        &self,
        module_path: &str,
        network_policy: &NetworkPolicy,
        sandbox_policy: &SandboxPolicy,
        request_data: &[u8],
    ) -> Result<(Vec<u8>, ExecutionMetrics)> {
        let start = Instant::now();

        let module = self
            .load_module(module_path)
            .context("Failed to load WASM module")?;

        // Pass real wall-clock time so WASM routes (e.g. /sudo/sync_github)
        // can compute correct 24 h window for GitHub API queries.
        let real_now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let instance_config = InstanceConfig {
            network_policy: network_policy.clone(),
            sandbox_policy: sandbox_policy.clone(),
            exec_policy: ExecPolicy::default(),
            time_policy: TimePolicy::deterministic(real_now_ms),
            audit_logger: None,
            memory_export: "memory".to_string(),
            challenge_id: module_path.to_string(),
            validator_id: "validator".to_string(),
            restart_id: String::new(),
            config_version: 0,
            storage_host_config: StorageHostConfig {
                allow_direct_writes: true,
                require_consensus: true,
                ..self.config.storage_host_config.clone()
            },
            storage_backend: Arc::clone(&self.config.storage_backend),
            fixed_timestamp_ms: None,
            consensus_policy: ConsensusPolicy::default(),
            terminal_policy: TerminalPolicy::default(),
            llm_policy: match &self.config.chutes_api_key {
                Some(key) => LlmPolicy::with_api_key(key.clone()),
                None => LlmPolicy::default(),
            },
            llm_validators_json: self.config.llm_validators_json.read().clone(),
            registered_hotkeys_json: self.config.registered_hotkeys_json.read().clone(),
            ..Default::default()
        };

        let mut instance = self
            .runtime
            .instantiate(&module, instance_config, None)
            .map_err(|e| anyhow::anyhow!("WASM instantiation failed: {}", e))?;

        let initial_fuel = instance.fuel_remaining();

        let ptr = self.allocate_input(&mut instance, request_data)?;

        instance
            .write_memory(ptr as usize, request_data)
            .map_err(|e| anyhow::anyhow!("Failed to write request data to WASM memory: {}", e))?;

        let result = instance
            .call_i32_i32_return_i64("handle_route", ptr, request_data.len() as i32)
            .map_err(|e| match &e {
                WasmRuntimeError::FuelExhausted => {
                    anyhow::anyhow!("WASM execution exceeded fuel limit")
                }
                WasmRuntimeError::Execution(msg) if msg.contains("timeout") => {
                    anyhow::anyhow!("WASM execution timed out")
                }
                _ => anyhow::anyhow!("WASM handle_route call failed: {}", e),
            })?;

        let out_len = (result >> 32) as i32;
        let out_ptr = (result & 0xFFFF_FFFF) as i32;

        if out_len > 0 && out_len as u64 > MAX_ROUTE_OUTPUT_SIZE {
            return Err(anyhow::anyhow!(
                "WASM handle_route output size {} exceeds maximum allowed {}",
                out_len,
                MAX_ROUTE_OUTPUT_SIZE
            ));
        }

        let result_data = if out_ptr > 0 && out_len > 0 {
            instance
                .read_memory(out_ptr as usize, out_len as usize)
                .map_err(|e| {
                    anyhow::anyhow!("failed to read WASM memory for handle_route output: {}", e)
                })?
        } else {
            Vec::new()
        };

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
            result_bytes = result_data.len(),
            execution_time_ms = metrics.execution_time_ms,
            "WASM handle_route completed"
        );

        Ok((result_data, metrics))
    }

    /// Execute handle_route with RouteRequest, returning RouteResponse
    pub fn call_route(
        &self,
        module_path: &str,
        request: platform_challenge_sdk::RouteRequest,
    ) -> Result<platform_challenge_sdk::RouteResponse> {
        use platform_challenge_sdk::RouteResponse;

        // Convert RouteRequest to WasmRouteRequest and serialize with bincode
        let wasm_request = platform_challenge_sdk_wasm::WasmRouteRequest {
            method: request.method.clone(),
            path: request.path.clone(),
            params: request
                .params
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            query: request
                .query
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            body: serde_json::to_vec(&request.body).unwrap_or_default(),
            auth_hotkey: request.auth_hotkey.clone(),
        };

        let request_data =
            bincode::serialize(&wasm_request).context("Failed to serialize WasmRouteRequest")?;

        let network_policy = NetworkPolicy::development();
        let sandbox_policy = SandboxPolicy::default();

        let (response_data, _metrics) = self.execute_handle_route(
            module_path,
            &network_policy,
            &sandbox_policy,
            &request_data,
        )?;

        // Deserialize WasmRouteResponse from bincode
        let wasm_response: platform_challenge_sdk_wasm::WasmRouteResponse =
            bincode::deserialize(&response_data)
                .context("Failed to deserialize WasmRouteResponse")?;

        // Convert to RouteResponse
        let body: serde_json::Value = if wasm_response.body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&wasm_response.body).unwrap_or(serde_json::Value::Null)
        };

        Ok(RouteResponse {
            status: wasm_response.status,
            headers: std::collections::HashMap::new(),
            body,
        })
    }

    /// Execute get_weights on a WASM challenge module.
    /// Returns Vec<WeightAssignment> with hotkey (SS58/hex) + f64 weight.
    /// The caller is responsible for converting hotkeys to UIDs via metagraph.
    #[allow(dead_code)]
    pub fn execute_get_weights(
        &self,
        module_path: &str,
    ) -> Result<Vec<platform_challenge_sdk::WeightAssignment>> {
        self.execute_get_weights_with_block(module_path, 0, 0)
    }

    /// Execute get_weights on a WASM challenge module with block context.
    pub fn execute_get_weights_with_block(
        &self,
        module_path: &str,
        block_height: u64,
        epoch: u64,
    ) -> Result<Vec<platform_challenge_sdk::WeightAssignment>> {
        // Ensure get_weights reads only consensus-confirmed data, not pending sync writes.
        // Scope to this challenge only to avoid clearing other challenges' in-flight writes.
        self.config
            .storage_backend
            .clear_pending_writes_for_challenge(module_path);
        let start = Instant::now();

        let module = self
            .load_module(module_path)
            .context("Failed to load WASM module")?;

        let dedup = self.get_or_init_dedup(module_path, &module);
        let _guard = match dedup.try_acquire(DedupFlags::GET_WEIGHTS) {
            Some(g) => g,
            None => {
                let cache = self.last_good_weights.read();
                if let Some(cached) = cache.get(module_path) {
                    info!(
                        module = module_path,
                        weight_count = cached.len(),
                        "get_weights dedup collision: returning cached last-good weights"
                    );
                    return Ok(cached.clone());
                }
                debug!(module = module_path, "get_weights skipped: already running, no cache available");
                return Ok(Vec::new());
            }
        };

        let instance_config = InstanceConfig {
            challenge_id: module_path.to_string(),
            validator_id: "validator".to_string(),
            storage_host_config: StorageHostConfig {
                allow_direct_writes: true,
                require_consensus: true,
                ..self.config.storage_host_config.clone()
            },
            storage_backend: Arc::clone(&self.config.storage_backend),
            consensus_policy: ConsensusPolicy::read_only(),
            block_height,
            epoch,
            ..Default::default()
        };

        let mut instance = self
            .runtime
            .instantiate(&module, instance_config, None)
            .map_err(|e| anyhow::anyhow!("WASM instantiation failed: {}", e))?;

        let result = instance
            .call_return_i64("get_weights")
            .map_err(|e| anyhow::anyhow!("WASM get_weights call failed: {}", e))?;

        let out_len = (result >> 32) as i32;
        let out_ptr = (result & 0xFFFF_FFFF) as i32;

        let result_data = if out_ptr > 0 && out_len > 0 {
            instance
                .read_memory(out_ptr as usize, out_len as usize)
                .map_err(|e| {
                    anyhow::anyhow!("failed to read WASM memory for get_weights output: {}", e)
                })?
        } else {
            return Ok(Vec::new());
        };

        // Try hotkey-based WeightAssignment first (bounty-challenge, modern challenges),
        // then fall back to UID-based WeightEntry (legacy challenges).
        let weights: Vec<platform_challenge_sdk::WeightAssignment> = if let Ok(assignments) =
            bincode::deserialize::<Vec<platform_challenge_sdk::WeightAssignment>>(&result_data)
        {
            assignments
        } else {
            let weight_entries: Vec<WeightEntry> = bincode::deserialize(&result_data)
                    .context("Failed to deserialize get_weights output as Vec<WeightEntry> or Vec<WeightAssignment>")?;
            weight_entries
                .into_iter()
                .map(|entry| platform_challenge_sdk::WeightAssignment {
                    hotkey: format!("uid:{}", entry.uid),
                    weight: entry.weight as f64 / 65535.0,
                })
                .collect()
        };

        info!(
            module = module_path,
            weight_count = weights.len(),
            execution_time_ms = start.elapsed().as_millis() as u64,
            "WASM get_weights completed"
        );

        if !weights.is_empty() {
            let mut cache = self.last_good_weights.write();
            cache.insert(module_path.to_string(), weights.clone());
        }

        Ok(weights)
    }

    /// Execute sync on a WASM challenge module.
    /// Returns WasmSyncResult with leaderboard hash and stats for consensus.
    #[allow(dead_code)]
    pub fn execute_sync(
        &self,
        module_path: &str,
    ) -> Result<platform_challenge_sdk_wasm::WasmSyncResult> {
        self.execute_sync_with_block(module_path, 0, 0)
    }

    /// Execute sync on a WASM challenge module with block context.
    /// Reuses the persistent WASM instance across calls for in-memory state.
    pub fn execute_sync_with_block(
        &self,
        module_path: &str,
        block_height: u64,
        epoch: u64,
    ) -> Result<platform_challenge_sdk_wasm::WasmSyncResult> {
        let start = Instant::now();

        let module = self
            .load_module(module_path)
            .context("Failed to load WASM module")?;

        let dedup = self.get_or_init_dedup(module_path, &module);
        let _guard = match dedup.try_acquire(DedupFlags::SYNC) {
            Some(g) => g,
            None => {
                debug!(module = module_path, "sync skipped: already running");
                return Ok(platform_challenge_sdk_wasm::WasmSyncResult {
                    leaderboard_hash: [0u8; 32],
                    total_users: 0,
                    total_valid_issues: 0,
                    total_invalid_issues: 0,
                    total_pending_issues: 0,
                    sync_timestamp: 0,
                });
            }
        };

        let pi = self.get_or_create_persistent(module_path, block_height, epoch)?;
        let mut pi_guard = pi.lock();

        let real_now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Update block/epoch/timestamp on the persistent instance
        {
            let state = pi_guard.instance.store_mut().data_mut();
            state.consensus_state.block_height = block_height;
            state.consensus_state.epoch = epoch;
            state.fixed_timestamp_ms = Some(real_now_ms as i64);
            state.time_state.set_fixed_timestamp(real_now_ms);
        }

        // Reset fuel before each sync call
        if self.config.enable_fuel {
            if let Some(limit) = self.config.fuel_limit {
                let _ = pi_guard.instance.store_mut().set_fuel(limit);
            }
        }

        let result = pi_guard
            .instance
            .call_return_i64("sync")
            .map_err(|e| anyhow::anyhow!("WASM sync call failed: {}", e))?;

        let out_len = (result >> 32) as i32;
        let out_ptr = (result & 0xFFFF_FFFF) as i32;

        if out_ptr <= 0 || out_len <= 0 {
            return Ok(platform_challenge_sdk_wasm::WasmSyncResult {
                leaderboard_hash: [0u8; 32],
                total_users: 0,
                total_valid_issues: 0,
                total_invalid_issues: 0,
                total_pending_issues: 0,
                sync_timestamp: 0,
            });
        }

        let result_data = pi_guard
            .instance
            .read_memory(out_ptr as usize, out_len as usize)
            .map_err(|e| anyhow::anyhow!("failed to read WASM memory for sync output: {}", e))?;

        let sync_result: platform_challenge_sdk_wasm::WasmSyncResult =
            bincode::deserialize(&result_data)
                .context("Failed to deserialize sync output as WasmSyncResult")?;

        info!(
            module = module_path,
            total_users = sync_result.total_users,
            execution_time_ms = start.elapsed().as_millis() as u64,
            "WASM sync completed (persistent instance)"
        );

        // Clear the pending writes cache for this challenge so subsequent reads
        // (e.g., get_weights) only see consensus-confirmed data.
        self.config
            .storage_backend
            .clear_pending_writes_for_challenge(module_path);

        Ok(sync_result)
    }

    /// Execute the aggregate function on a WASM challenge module.
    /// Takes evaluations from all validators and returns a final
    /// leaderboard + weights that all validators will use.
    pub fn execute_aggregate(
        &self,
        module_path: &str,
        input: &platform_challenge_sdk_wasm::AggregationInput,
    ) -> Result<platform_challenge_sdk_wasm::AggregationOutput> {
        let start = Instant::now();

        let module = self
            .load_module(module_path)
            .context("Failed to load WASM module")?;

        let serialized =
            bincode::serialize(input).context("Failed to serialize AggregationInput")?;

        let instance_config = InstanceConfig {
            challenge_id: module_path.to_string(),
            validator_id: "validator".to_string(),
            storage_host_config: StorageHostConfig {
                allow_direct_writes: true,
                require_consensus: true,
                ..self.config.storage_host_config.clone()
            },
            storage_backend: Arc::clone(&self.config.storage_backend),
            consensus_policy: ConsensusPolicy::read_only(),
            block_height: input.block_height,
            epoch: input.epoch,
            ..Default::default()
        };

        let mut instance = self
            .runtime
            .instantiate(&module, instance_config, None)
            .map_err(|e| anyhow::anyhow!("WASM instantiation failed: {}", e))?;

        let ptr = self.allocate_input(&mut instance, &serialized)?;
        instance
            .write_memory(ptr as usize, &serialized)
            .map_err(|e| {
                anyhow::anyhow!("Failed to write aggregate input to WASM memory: {}", e)
            })?;

        let result = instance
            .call_i32_i32_return_i64("aggregate", ptr, serialized.len() as i32)
            .map_err(|e| anyhow::anyhow!("WASM aggregate call failed: {}", e))?;

        let out_len = (result >> 32) as i32;
        let out_ptr = (result & 0xFFFF_FFFF) as i32;

        if out_ptr <= 0 || out_len <= 0 {
            return Ok(platform_challenge_sdk_wasm::AggregationOutput {
                leaderboard: Vec::new(),
                weights: Vec::new(),
                leaderboard_hash: [0u8; 32],
            });
        }

        let result_data = instance
            .read_memory(out_ptr as usize, out_len as usize)
            .map_err(|e| {
                anyhow::anyhow!("Failed to read WASM memory for aggregate output: {}", e)
            })?;

        let output: platform_challenge_sdk_wasm::AggregationOutput =
            bincode::deserialize(&result_data)
                .context("Failed to deserialize AggregationOutput")?;

        info!(
            module = module_path,
            leaderboard_size = output.leaderboard.len(),
            weight_count = output.weights.len(),
            execution_time_ms = start.elapsed().as_millis() as u64,
            "WASM aggregate completed"
        );

        Ok(output)
    }

    #[allow(dead_code)]
    pub fn execute_validate_storage_write(
        &self,
        module_path: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<bool> {
        let module = self
            .load_module(module_path)
            .context("Failed to load WASM module")?;

        let instance_config = InstanceConfig {
            challenge_id: module_path.to_string(),
            validator_id: "validator".to_string(),
            storage_host_config: StorageHostConfig::default(),
            storage_backend: Arc::clone(&self.config.storage_backend),
            ..Default::default()
        };

        let mut instance = self
            .runtime
            .instantiate(&module, instance_config, None)
            .map_err(|e| anyhow::anyhow!("WASM instantiation failed: {}", e))?;

        let key_ptr = self.allocate_input(&mut instance, key)?;
        instance
            .write_memory(key_ptr as usize, key)
            .map_err(|e| anyhow::anyhow!("Failed to write key to WASM memory: {}", e))?;

        let val_ptr = self.allocate_input(&mut instance, value)?;
        instance
            .write_memory(val_ptr as usize, value)
            .map_err(|e| anyhow::anyhow!("Failed to write value to WASM memory: {}", e))?;

        let result = instance
            .call_i32_i32_i32_i32_return_i32(
                "validate_storage_write",
                key_ptr,
                key.len() as i32,
                val_ptr,
                value.len() as i32,
            )
            .map_err(|e| anyhow::anyhow!("WASM validate_storage_write call failed: {}", e))?;

        Ok(result == 1)
    }

    fn load_module(&self, module_path: &str) -> Result<Arc<WasmModule>> {
        {
            let cache = self.module_cache.read();
            if let Some(module) = cache.get(module_path) {
                debug!(module = module_path, "WASM module loaded from cache");
                return Ok(Arc::clone(module));
            }
        }

        // Note: We don't try distributed storage here because this is a sync function
        // that may be called from async context. The WASM should already be cached
        // locally after upload. Use load_module_async for distributed storage access.
        let wasm_bytes: Option<Vec<u8>> = None;

        // Fallback to filesystem if not in distributed storage
        let wasm_bytes = match wasm_bytes {
            Some(bytes) => bytes,
            None => {
                let full_path = self.config.module_dir.join(module_path);
                std::fs::read(&full_path).with_context(|| {
                    format!("Failed to read WASM module from {}", full_path.display())
                })?
            }
        };

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

    /// Get or create a persistent WASM instance for a challenge.
    /// The instance is reused across sync/background_tick calls.
    /// It is recreated when the module is re-uploaded (version bump).
    fn get_or_create_persistent(
        &self,
        module_path: &str,
        block_height: u64,
        epoch: u64,
    ) -> Result<Arc<Mutex<PersistentInstance>>> {
        let current_version = self
            .module_versions
            .read()
            .get(module_path)
            .copied()
            .unwrap_or(0);

        // Check if we already have a valid persistent instance
        {
            let cache = self.persistent_instances.read();
            if let Some(pi) = cache.get(module_path) {
                let guard = pi.lock();
                if guard.module_version == current_version {
                    drop(guard);
                    return Ok(Arc::clone(pi));
                }
                // Version mismatch, will recreate below
            }
        }

        // Create a new persistent instance
        let module = self
            .load_module(module_path)
            .context("Failed to load WASM module for persistent instance")?;

        let real_now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let instance_config = InstanceConfig {
            challenge_id: module_path.to_string(),
            validator_id: "validator".to_string(),
            storage_host_config: StorageHostConfig {
                allow_direct_writes: true,
                require_consensus: true,
                ..self.config.storage_host_config.clone()
            },
            storage_backend: Arc::clone(&self.config.storage_backend),
            consensus_policy: ConsensusPolicy::default(),
            network_policy: NetworkPolicy::development(),
            time_policy: TimePolicy::deterministic(real_now_ms),
            llm_policy: match &self.config.chutes_api_key {
                Some(key) => LlmPolicy::with_api_key(key.clone()),
                None => LlmPolicy::default(),
            },
            block_height,
            epoch,
            ..Default::default()
        };

        let instance = self
            .runtime
            .instantiate(&module, instance_config, None)
            .map_err(|e| anyhow::anyhow!("Failed to create persistent WASM instance: {}", e))?;

        let pi = Arc::new(Mutex::new(PersistentInstance {
            instance,
            module_version: current_version,
            created_at: Instant::now(),
        }));

        self.persistent_instances
            .write()
            .insert(module_path.to_string(), Arc::clone(&pi));
        info!(
            module = module_path,
            version = current_version,
            "persistent WASM instance created"
        );
        Ok(pi)
    }

    /// Execute background_tick() on the persistent WASM instance.
    /// Called every block for lightweight background work.
    /// Uses try_lock to avoid blocking sync() which has higher priority.
    pub fn execute_background_tick(
        &self,
        module_path: &str,
        block_height: u64,
        epoch: u64,
    ) -> Result<()> {
        let pi = self.get_or_create_persistent(module_path, block_height, epoch)?;
        let mut guard = match pi.try_lock() {
            Some(g) => g,
            None => {
                debug!(
                    module = module_path,
                    "background_tick skipped: instance busy (sync in progress)"
                );
                return Ok(());
            }
        };

        let real_now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Update block/epoch/timestamp context on the persistent instance
        {
            let state = guard.instance.store_mut().data_mut();
            state.consensus_state.block_height = block_height;
            state.consensus_state.epoch = epoch;
            state.fixed_timestamp_ms = Some(real_now_ms as i64);
            state.time_state.set_fixed_timestamp(real_now_ms);
        }

        // Reset fuel if enabled
        if self.config.enable_fuel {
            if let Some(limit) = self.config.fuel_limit {
                let _ = guard.instance.store_mut().set_fuel(limit);
            }
        }

        // Call background_tick - void function, no return value
        match guard.instance.call("background_tick", &[]) {
            Ok(_) => {}
            Err(WasmRuntimeError::MissingExport(_)) => {
                // WASM doesn't export background_tick, that's fine
            }
            Err(e) => {
                warn!(module = module_path, error = %e, "background_tick failed");
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn invalidate_cache(&self, module_path: &str) {
        let mut cache = self.module_cache.write();
        if cache.remove(module_path).is_some() {
            info!(module = module_path, "WASM module cache entry invalidated");
        }
        self.dedup_state.write().remove(module_path);
        // Bump module version so persistent instance gets recreated
        let mut versions = self.module_versions.write();
        let v = versions.entry(module_path.to_string()).or_insert(0);
        *v += 1;
        info!(module = module_path, version = *v, "module version bumped");
        // Drop old persistent instance
        if self
            .persistent_instances
            .write()
            .remove(module_path)
            .is_some()
        {
            info!(module = module_path, "persistent instance dropped");
        }
    }

    #[allow(dead_code)]
    pub fn clear_cache(&self) {
        let mut cache = self.module_cache.write();
        let count = cache.len();
        cache.clear();
        self.persistent_instances.write().clear();
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
        // Check module cache first
        if self.module_cache.read().contains_key(module_path) {
            return true;
        }
        // Check filesystem
        self.resolve_module_path(module_path).exists()
    }

    /// Async version that also checks distributed storage
    #[allow(dead_code)]
    pub async fn module_exists_async(&self, module_path: &str) -> bool {
        // Check module cache first
        if self.module_cache.read().contains_key(module_path) {
            return true;
        }
        // Check filesystem
        if self.resolve_module_path(module_path).exists() {
            return true;
        }
        // Check distributed storage
        if let Some(ref storage) = self.config.distributed_storage {
            let key = platform_distributed_storage::StorageKey::new("wasm", module_path);
            if let Ok(exists) = storage.exists(&key).await {
                return exists;
            }
        }
        false
    }

    /// Validate that WASM bytes are a valid module
    pub fn validate_wasm_module(&self, wasm_bytes: &[u8]) -> Result<()> {
        self.runtime
            .compile_module(wasm_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid WASM module: {}", e))?;
        Ok(())
    }
}
