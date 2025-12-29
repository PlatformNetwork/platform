//! Main challenge runtime
//!
//! Coordinates challenge execution across the validator.
//!
//! Weight flow at epoch end:
//! 1. Evaluation phase ends -> collect weights from all challenges
//! 2. Group weights by mechanism_id (each challenge has one mechanism)
//! 3. Commit phase: commit hash for each mechanism
//! 4. Reveal phase: reveal weights for each mechanism
//! 5. Submit to Bittensor using batch_set_mechanism_weights

use crate::{ChallengeManager, JobScheduler};
use parking_lot::RwLock;
use platform_challenge_sdk::{Challenge, ChallengeId, EvaluationJob, EvaluationResult};
use platform_core::Hotkey;
use platform_epoch::{
    EpochConfig, EpochManager, EpochPhase, EpochTransition, MechanismCommitRevealManager,
    MechanismCommitment, MechanismWeightManager,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Runtime configuration
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    /// Base path for challenge databases
    pub data_dir: PathBuf,
    /// Epoch configuration
    pub epoch_config: EpochConfig,
    /// Maximum concurrent evaluations
    pub max_concurrent_evaluations: usize,
    /// Evaluation timeout in seconds
    pub evaluation_timeout_secs: u64,
    /// Secret for weight commitments
    pub commitment_secret: Vec<u8>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data/challenges"),
            epoch_config: EpochConfig::default(),
            max_concurrent_evaluations: 4,
            evaluation_timeout_secs: 300,
            commitment_secret: rand_secret(),
        }
    }
}

fn rand_secret() -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("secret_{}", seed).into_bytes()
}

/// Events emitted by the runtime
#[derive(Clone, Debug)]
pub enum RuntimeEvent {
    /// Challenge loaded
    ChallengeLoaded {
        id: ChallengeId,
        name: String,
        mechanism_id: u8,
    },
    /// Challenge unloaded
    ChallengeUnloaded { id: ChallengeId },
    /// Evaluation completed
    EvaluationCompleted {
        challenge_id: ChallengeId,
        job_id: uuid::Uuid,
        result: EvaluationResult,
    },
    /// Evaluation failed
    EvaluationFailed {
        challenge_id: ChallengeId,
        job_id: uuid::Uuid,
        error: String,
    },
    /// Weights collected from all challenges (per mechanism)
    WeightsCollected { epoch: u64, mechanisms: Vec<u8> },
    /// Weights committed for a mechanism
    MechanismWeightsCommitted {
        mechanism_id: u8,
        epoch: u64,
        commit_hash: String,
    },
    /// Weights revealed for a mechanism
    MechanismWeightsRevealed {
        mechanism_id: u8,
        epoch: u64,
        num_weights: usize,
    },
    /// All mechanism weights ready for Bittensor submission
    WeightsReadyForSubmission {
        epoch: u64,
        /// (mechanism_id, uids, weights) tuples ready for batch_set_mechanism_weights
        mechanism_weights: Vec<(u8, Vec<u16>, Vec<u16>)>,
    },
    /// Epoch transition
    EpochTransition(EpochTransition),
}

/// The main challenge runtime
pub struct ChallengeRuntime {
    config: RuntimeConfig,
    validator: Hotkey,

    /// Challenge manager
    manager: Arc<ChallengeManager>,

    /// Job scheduler
    scheduler: Arc<JobScheduler>,

    /// Epoch manager
    epoch_manager: Arc<EpochManager>,

    /// Mechanism weight manager (groups weights by mechanism_id)
    mechanism_weights: Arc<RwLock<MechanismWeightManager>>,

    /// Mechanism commit-reveal manager (commit/reveal per mechanism)
    mechanism_commit_reveal: Arc<MechanismCommitRevealManager>,

    /// Challenge to mechanism mapping
    challenge_mechanisms: Arc<RwLock<HashMap<ChallengeId, u8>>>,

    /// Event sender
    event_tx: mpsc::Sender<RuntimeEvent>,

    /// Event receiver (to be taken by consumer)
    event_rx: Option<mpsc::Receiver<RuntimeEvent>>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,
}

impl ChallengeRuntime {
    /// Create a new runtime
    pub fn new(config: RuntimeConfig, validator: Hotkey, current_block: u64) -> Self {
        let (event_tx, event_rx) = mpsc::channel(1000);

        // Create data directory if it doesn't exist
        std::fs::create_dir_all(&config.data_dir).ok();

        let current_epoch = current_block / config.epoch_config.blocks_per_epoch;

        let epoch_manager = Arc::new(EpochManager::new(
            config.epoch_config.clone(),
            current_block,
        ));

        // Create manager and set validator
        let manager = Arc::new(ChallengeManager::new(config.data_dir.clone()));
        manager.set_validator(validator.clone());

        Self {
            manager,
            scheduler: Arc::new(JobScheduler::new(config.max_concurrent_evaluations)),
            epoch_manager,
            mechanism_weights: Arc::new(RwLock::new(MechanismWeightManager::new(current_epoch))),
            mechanism_commit_reveal: Arc::new(MechanismCommitRevealManager::new()),
            challenge_mechanisms: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            event_rx: Some(event_rx),
            shutdown: Arc::new(RwLock::new(false)),
            config,
            validator,
        }
    }

    /// Take the event receiver (can only be called once)
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<RuntimeEvent>> {
        self.event_rx.take()
    }

    /// Get current epoch
    pub fn current_epoch(&self) -> u64 {
        self.epoch_manager.current_epoch()
    }

    /// Get current phase
    pub fn current_phase(&self) -> EpochPhase {
        self.epoch_manager.current_phase()
    }

    /// Update epoch configuration (e.g., when syncing with Bittensor tempo)
    pub fn update_epoch_config(&self, new_config: EpochConfig) {
        self.epoch_manager.update_config(new_config);
    }

    /// Register a challenge with its mechanism_id
    pub async fn register_challenge<C: Challenge + 'static>(
        &self,
        challenge: C,
        mechanism_id: u8,
    ) -> Result<(), RuntimeError> {
        let id = challenge.id();
        let name = challenge.name().to_string();

        // Register with manager
        self.manager.register(challenge).await?;

        // Register challenge-mechanism mapping
        self.challenge_mechanisms.write().insert(id, mechanism_id);
        self.mechanism_weights
            .write()
            .register_challenge(id, mechanism_id);

        // Emit event
        let _ = self
            .event_tx
            .send(RuntimeEvent::ChallengeLoaded {
                id,
                name: name.clone(),
                mechanism_id,
            })
            .await;

        info!(
            "Challenge registered: {} ({}) -> mechanism {}",
            name, id, mechanism_id
        );
        Ok(())
    }

    /// Get mechanism_id for a challenge
    pub fn get_mechanism_for_challenge(&self, challenge_id: &ChallengeId) -> Option<u8> {
        self.challenge_mechanisms.read().get(challenge_id).copied()
    }

    /// Unregister a challenge
    pub async fn unregister_challenge(&self, id: &ChallengeId) -> Result<(), RuntimeError> {
        self.manager.unregister(id).await?;

        let _ = self
            .event_tx
            .send(RuntimeEvent::ChallengeUnloaded { id: *id })
            .await;

        info!("Challenge unregistered: {}", id);
        Ok(())
    }

    /// Submit an evaluation job
    pub async fn submit_job(&self, job: EvaluationJob) -> Result<uuid::Uuid, RuntimeError> {
        let job_id = job.id;
        self.scheduler.submit(job).await?;
        debug!("Job submitted: {}", job_id);
        Ok(job_id)
    }

    /// Process a new block
    pub async fn on_new_block(&self, block_number: u64) -> Result<(), RuntimeError> {
        // Update epoch manager
        if let Some(transition) = self.epoch_manager.on_new_block(block_number) {
            let _ = self
                .event_tx
                .send(RuntimeEvent::EpochTransition(transition.clone()))
                .await;

            match transition {
                EpochTransition::NewEpoch { new_epoch, .. } => {
                    self.on_new_epoch(new_epoch).await?;
                }
                EpochTransition::PhaseChange {
                    epoch, new_phase, ..
                } => {
                    self.on_phase_change(epoch, new_phase).await?;
                }
            }
        }

        Ok(())
    }

    /// Handle new epoch
    async fn on_new_epoch(&self, epoch: u64) -> Result<(), RuntimeError> {
        info!("New epoch started: {}", epoch);

        // Reset mechanism weight manager for new epoch
        *self.mechanism_weights.write() = MechanismWeightManager::new(epoch);

        // Re-register all challenge-mechanism mappings
        for (challenge_id, mechanism_id) in self.challenge_mechanisms.read().iter() {
            self.mechanism_weights
                .write()
                .register_challenge(*challenge_id, *mechanism_id);
        }

        // Reset commit-reveal manager
        self.mechanism_commit_reveal.new_epoch(epoch);

        // Notify all challenges
        for id in self.manager.list_challenges() {
            if let Some(ctx) = self.manager.get_context(&id) {
                if let Some(challenge) = self.manager.get_challenge(&id) {
                    if let Err(e) = challenge.on_epoch_start(&ctx, epoch).await {
                        warn!("Challenge {} on_epoch_start error: {}", id, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle phase change - just logs, does not trigger commit/reveal
    ///
    /// Commit/reveal are triggered by Bittensor events (CommitWindowOpen, RevealWindowOpen)
    /// not by internal phase tracking. This ensures timing matches Bittensor exactly.
    async fn on_phase_change(&self, epoch: u64, phase: EpochPhase) -> Result<(), RuntimeError> {
        info!(
            "Epoch {} phase: {} (info only - actions triggered by Bittensor events)",
            epoch, phase
        );
        Ok(())
    }

    /// Collect weights from all challenges and group by mechanism
    async fn collect_weights_by_mechanism(&self, epoch: u64) -> Result<(), RuntimeError> {
        info!("Collecting weights from all challenges for epoch {}", epoch);

        let mut collected_mechanisms = Vec::new();

        for challenge_id in self.manager.list_challenges() {
            let mechanism_id = match self.challenge_mechanisms.read().get(&challenge_id) {
                Some(id) => *id,
                None => {
                    warn!("Challenge {} has no mechanism_id, skipping", challenge_id);
                    continue;
                }
            };

            let ctx = match self.manager.get_context(&challenge_id) {
                Some(ctx) => ctx,
                None => continue,
            };

            let challenge = match self.manager.get_challenge(&challenge_id) {
                Some(c) => c,
                None => continue,
            };

            // Calculate weights from this challenge
            match challenge.calculate_weights(&ctx).await {
                Ok(weights) => {
                    // Get emission weight from challenge (fraction of total emissions)
                    let emission_weight = challenge.emission_weight();

                    info!(
                        "Challenge {} -> mechanism {}: {} weights, {}% emission",
                        challenge_id,
                        mechanism_id,
                        weights.len(),
                        (emission_weight * 100.0).round()
                    );

                    // Submit to mechanism weight manager with emission scaling
                    // Remaining weight (1.0 - emission_weight) goes to UID 0 (burn)
                    self.mechanism_weights.write().submit_weights(
                        challenge_id,
                        mechanism_id,
                        weights,
                        emission_weight,
                    );

                    if !collected_mechanisms.contains(&mechanism_id) {
                        collected_mechanisms.push(mechanism_id);
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to calculate weights for challenge {}: {}",
                        challenge_id, e
                    );
                }
            }
        }

        // Emit event
        let _ = self
            .event_tx
            .send(RuntimeEvent::WeightsCollected {
                epoch,
                mechanisms: collected_mechanisms,
            })
            .await;

        Ok(())
    }

    /// Commit weights for all mechanisms
    ///
    /// Called when Bittensor CommitWindowOpen event fires.
    pub async fn commit_weights(&self, epoch: u64) -> Result<(), RuntimeError> {
        info!("Committing weights for epoch {} (per mechanism)", epoch);

        // First collect weights from all challenges
        self.collect_weights_by_mechanism(epoch).await?;

        // Now commit each mechanism's weights
        let all_mechanisms = self.mechanism_weights.read().list_mechanisms();

        for mechanism_id in all_mechanisms {
            // Get mechanism weights, releasing lock before await
            let mech_weights = self
                .mechanism_weights
                .read()
                .get_mechanism_weights(mechanism_id);
            if let Some(mech_weights) = mech_weights {
                // Create commitment for this mechanism
                let commitment = MechanismCommitment::new(
                    mechanism_id,
                    epoch,
                    &mech_weights,
                    &self.config.commitment_secret,
                );

                let hash_hex = commitment.hash_hex();

                // Submit to mechanism commit-reveal manager
                self.mechanism_commit_reveal.commit(commitment);

                // Emit event
                let _ = self
                    .event_tx
                    .send(RuntimeEvent::MechanismWeightsCommitted {
                        mechanism_id,
                        epoch,
                        commit_hash: hash_hex.clone(),
                    })
                    .await;

                debug!(
                    "Committed weights for mechanism {} epoch {}: hash={}",
                    mechanism_id, epoch, hash_hex
                );
            }
        }

        Ok(())
    }

    /// Reveal weights for all mechanisms
    ///
    /// Called when Bittensor RevealWindowOpen event fires.
    pub async fn reveal_weights(&self, epoch: u64) -> Result<(), RuntimeError> {
        info!("Revealing weights for epoch {} (per mechanism)", epoch);

        let all_mechanisms = self.mechanism_weights.read().list_mechanisms();

        for mechanism_id in all_mechanisms {
            // Get mechanism weights, releasing lock before await
            let mech_weights = self
                .mechanism_weights
                .read()
                .get_mechanism_weights(mechanism_id);
            if let Some(mech_weights) = mech_weights {
                match self
                    .mechanism_commit_reveal
                    .reveal(mechanism_id, mech_weights.clone())
                {
                    Ok(()) => {
                        let _ = self
                            .event_tx
                            .send(RuntimeEvent::MechanismWeightsRevealed {
                                mechanism_id,
                                epoch,
                                num_weights: mech_weights.weights.len(),
                            })
                            .await;

                        debug!(
                            "Revealed weights for mechanism {} epoch {}",
                            mechanism_id, epoch
                        );
                    }
                    Err(e) => {
                        error!(
                            "Failed to reveal weights for mechanism {}: {}",
                            mechanism_id, e
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Finalize weights and prepare for Bittensor submission
    async fn finalize_weights(&self, epoch: u64) -> Result<(), RuntimeError> {
        info!("Finalizing weights for epoch {}", epoch);

        // Check all reveals are done
        if !self.mechanism_commit_reveal.all_revealed() {
            warn!("Not all mechanisms revealed weights");
        }

        // Get all revealed weights ready for Bittensor batch submission
        let mechanism_weights = self.mechanism_commit_reveal.get_revealed_weights();

        info!(
            "Epoch {} finalized: {} mechanisms ready for Bittensor submission",
            epoch,
            mechanism_weights.len()
        );

        // Emit event with weights ready for batch_set_mechanism_weights
        let _ = self
            .event_tx
            .send(RuntimeEvent::WeightsReadyForSubmission {
                epoch,
                mechanism_weights,
            })
            .await;

        Ok(())
    }

    /// Get all mechanism weights for batch submission to Bittensor
    /// Returns Vec<(mechanism_id, uids, weights)> for use with batch_set_mechanism_weights
    ///
    /// Note: This returns revealed weights from internal commit-reveal.
    /// For direct weights, use collect_and_get_weights() instead.
    pub fn get_mechanism_weights_for_submission(&self) -> Vec<(u8, Vec<u16>, Vec<u16>)> {
        self.mechanism_commit_reveal.get_revealed_weights()
    }

    /// Collect weights from all challenges and return them for Bittensor submission
    ///
    /// This is the primary method for event-driven weight submission.
    /// Called when Bittensor CommitWindowOpen event fires.
    ///
    /// # Arguments
    /// * `hotkey_to_uid` - Optional mapping from SS58 hotkey to Bittensor UID.
    ///   If None, weights are returned with sequential UIDs (for testing only).
    ///   In production, pass the metagraph mapping from SubtensorClient::get_uids_for_hotkeys().
    pub async fn collect_and_get_weights(&self) -> Vec<(u8, Vec<u16>, Vec<u16>)> {
        self.collect_and_get_weights_with_mapping(None).await
    }

    /// Collect weights with explicit hotkey->UID mapping from metagraph
    ///
    /// # Arguments
    /// * `hotkey_to_uid` - Mapping from SS58 hotkey to Bittensor UID from metagraph
    pub async fn collect_and_get_weights_with_mapping(
        &self,
        hotkey_to_uid: Option<&HashMap<String, u16>>,
    ) -> Vec<(u8, Vec<u16>, Vec<u16>)> {
        let epoch = self.epoch_manager.current_epoch();
        info!("Collecting weights for epoch {} (event-driven)", epoch);

        let mut result = Vec::new();

        for challenge_id in self.manager.list_challenges() {
            let mechanism_id = match self.challenge_mechanisms.read().get(&challenge_id) {
                Some(id) => *id,
                None => {
                    warn!("Challenge {} has no mechanism_id, skipping", challenge_id);
                    continue;
                }
            };

            let ctx = match self.manager.get_context(&challenge_id) {
                Some(ctx) => ctx,
                None => continue,
            };

            let challenge = match self.manager.get_challenge(&challenge_id) {
                Some(c) => c,
                None => continue,
            };

            // Calculate weights from this challenge
            match challenge.calculate_weights(&ctx).await {
                Ok(weights) => {
                    if weights.is_empty() {
                        debug!("Challenge {} has no weights", challenge_id);
                        continue;
                    }

                    info!(
                        "Challenge {} -> mechanism {}: {} weights",
                        challenge_id,
                        mechanism_id,
                        weights.len()
                    );

                    // Convert to Bittensor format (uid, weight as u16)
                    let (uids, weight_values): (Vec<u16>, Vec<u16>) = if let Some(mapping) =
                        hotkey_to_uid
                    {
                        // Use metagraph mapping to convert hotkeys to UIDs
                        weights
                            .iter()
                            .filter_map(|w| {
                                mapping.get(&w.hotkey).map(|uid| {
                                    let weight_u16 = (w.weight.clamp(0.0, 1.0) * 65535.0) as u16;
                                    (*uid, weight_u16)
                                })
                            })
                            .unzip()
                    } else {
                        // Fallback: use sequential UIDs (for testing only)
                        warn!(
                            "No hotkey->UID mapping provided, using sequential UIDs (testing mode)"
                        );
                        let uids: Vec<u16> = (0..weights.len() as u16).collect();
                        let weight_values: Vec<u16> = weights
                            .iter()
                            .map(|w| (w.weight.clamp(0.0, 1.0) * 65535.0) as u16)
                            .collect();
                        (uids, weight_values)
                    };

                    if !uids.is_empty() {
                        result.push((mechanism_id, uids, weight_values));
                    } else {
                        warn!(
                            "Challenge {} has {} weights but no valid UIDs found in mapping",
                            challenge_id,
                            weights.len()
                        );
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to calculate weights for challenge {}: {}",
                        challenge_id, e
                    );
                }
            }
        }

        info!("Collected weights for {} mechanisms", result.len());
        result
    }

    /// Get all registered mechanism IDs (for initial weight submission)
    pub fn get_registered_mechanism_ids(&self) -> Vec<u8> {
        self.challenge_mechanisms
            .read()
            .values()
            .copied()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }

    /// Get commitment hashes for all mechanisms (for commit phase on Bittensor)
    pub fn get_mechanism_commitments(&self) -> Vec<(u8, [u8; 32])> {
        self.mechanism_commit_reveal
            .get_all_commitments()
            .into_iter()
            .map(|c| (c.mechanism_id, c.commit_hash))
            .collect()
    }

    /// Run the evaluation loop
    pub async fn run_evaluation_loop(&self) {
        info!("Starting evaluation loop");

        loop {
            if *self.shutdown.read() {
                break;
            }

            // Get next job from scheduler
            if let Some(job) = self.scheduler.next_job().await {
                let manager = self.manager.clone();
                let event_tx = self.event_tx.clone();
                let validator = self.validator.clone();
                let epoch = self.epoch_manager.current_epoch();

                // Execute in background
                tokio::spawn(async move {
                    let result = Self::execute_job(&manager, &job, &validator, epoch).await;

                    match result {
                        Ok(eval_result) => {
                            let _ = event_tx
                                .send(RuntimeEvent::EvaluationCompleted {
                                    challenge_id: job.challenge_id,
                                    job_id: job.id,
                                    result: eval_result,
                                })
                                .await;
                        }
                        Err(e) => {
                            let _ = event_tx
                                .send(RuntimeEvent::EvaluationFailed {
                                    challenge_id: job.challenge_id,
                                    job_id: job.id,
                                    error: e.to_string(),
                                })
                                .await;
                        }
                    }
                });
            }

            // Small delay to prevent busy loop
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        info!("Evaluation loop stopped");
    }

    /// Execute a single job
    async fn execute_job(
        manager: &ChallengeManager,
        job: &EvaluationJob,
        validator: &Hotkey,
        epoch: u64,
    ) -> Result<EvaluationResult, RuntimeError> {
        let ctx = manager
            .get_context(&job.challenge_id)
            .ok_or(RuntimeError::ChallengeNotFound(job.challenge_id))?
            .with_job_id(job.id);

        let challenge = manager
            .get_challenge(&job.challenge_id)
            .ok_or(RuntimeError::ChallengeNotFound(job.challenge_id))?;

        let start = std::time::Instant::now();

        let result = challenge
            .handle_job(&ctx, job)
            .await
            .map_err(|e| RuntimeError::Evaluation(e.to_string()))?;

        let execution_time = start.elapsed().as_millis() as u64;

        // Save result to challenge DB
        let result_with_time = EvaluationResult {
            execution_time_ms: execution_time,
            ..result
        };

        ctx.db()
            .save_result(&result_with_time)
            .map_err(|e| RuntimeError::Database(e.to_string()))?;

        debug!(
            "Job {} completed in {}ms: score={}",
            job.id, execution_time, result_with_time.score
        );

        Ok(result_with_time)
    }

    /// Shutdown the runtime
    pub fn shutdown(&self) {
        *self.shutdown.write() = true;
        info!("Runtime shutdown requested");
    }

    /// Get runtime status
    pub fn status(&self) -> RuntimeStatus {
        RuntimeStatus {
            challenges_loaded: self.manager.list_challenges().len(),
            mechanisms_registered: self.challenge_mechanisms.read().len(),
            current_epoch: self.epoch_manager.current_epoch(),
            current_phase: self.epoch_manager.current_phase(),
            pending_jobs: self.scheduler.pending_count(),
            running_jobs: self.scheduler.running_count(),
        }
    }
}

/// Runtime status
#[derive(Clone, Debug)]
pub struct RuntimeStatus {
    pub challenges_loaded: usize,
    pub mechanisms_registered: usize,
    pub current_epoch: u64,
    pub current_phase: EpochPhase,
    pub pending_jobs: usize,
    pub running_jobs: usize,
}

/// Runtime errors
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("Challenge not found: {0:?}")]
    ChallengeNotFound(ChallengeId),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Evaluation error: {0}")]
    Evaluation(String),

    #[error("Scheduler error: {0}")]
    Scheduler(String),

    #[error("Commit-reveal error: {0}")]
    CommitReveal(String),

    #[error("Manager error: {0}")]
    Manager(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<crate::ManagerError> for RuntimeError {
    fn from(err: crate::ManagerError) -> Self {
        RuntimeError::Manager(err.to_string())
    }
}

impl From<crate::SchedulerError> for RuntimeError {
    fn from(err: crate::SchedulerError) -> Self {
        RuntimeError::Scheduler(err.to_string())
    }
}
