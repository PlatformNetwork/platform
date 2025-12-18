//! Weight submission to Bittensor
//!
//! This module handles submitting weights to the Bittensor network using the
//! commit-reveal pattern that matches subtensor's exact format.
//!
//! ## CRv4 Support
//! When commit_reveal_version == 4, uses timelock encryption (TLE) for automatic
//! on-chain reveal. The chain decrypts weights when DRAND pulse becomes available.
//!
//! ## Persistence
//! Commits are persisted to disk to survive restarts. This ensures that if
//! the validator restarts between commit and reveal, it can still reveal
//! the previously committed weights.

use crate::SubtensorClient;
use anyhow::Result;
use bittensor_rs::chain::ExtrinsicWait;
use bittensor_rs::validator_weights::{
    commit_weights, prepare_commit_reveal, prepare_mechanism_commit_reveal, reveal_weights,
    set_weights,
};
use bittensor_rs::{
    commit_mechanism_weights, get_next_epoch_start_block, reveal_mechanism_weights,
    set_mechanism_weights,
};
// CRv4 imports (no persistence needed - chain auto-reveals)
use bittensor_rs::crv4::{
    calculate_reveal_round, commit_timelocked_mechanism_weights, get_commit_reveal_version,
    get_last_drand_round, get_mechid_storage_index, get_reveal_period, get_tempo,
    prepare_crv4_commit, DEFAULT_COMMIT_REVEAL_VERSION,
};
use platform_challenge_sdk::WeightAssignment;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};

/// Default path for commit persistence
const DEFAULT_COMMITS_FILE: &str = "pending_commits.json";

/// Persisted state for weight commits
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PersistedCommitState {
    /// Epoch when commits were made
    pub committed_epoch: Option<u64>,
    /// Pending mechanism commits (mechanism_id -> commit data)
    pub pending_mechanism_commits: HashMap<u8, PendingMechanismCommit>,
    /// Standard pending commit (non-mechanism)
    pub pending_commit: Option<PendingCommitV2>,
    /// Last revealed epoch per mechanism
    pub last_revealed_epoch: HashMap<u8, u64>,
}

impl PersistedCommitState {
    /// Load from file, returning default if file doesn't exist
    pub fn load(path: &PathBuf) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(state) => {
                    info!("Loaded persisted commit state from {:?}", path);
                    state
                }
                Err(e) => {
                    warn!("Failed to parse commit state file: {}", e);
                    Self::default()
                }
            },
            Err(_) => {
                debug!("No existing commit state file at {:?}", path);
                Self::default()
            }
        }
    }

    /// Save to file
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        debug!("Saved commit state to {:?}", path);
        Ok(())
    }

    /// Check if we have commits for a specific epoch
    pub fn has_commits_for_epoch(&self, epoch: u64) -> bool {
        self.committed_epoch == Some(epoch) && !self.pending_mechanism_commits.is_empty()
    }

    /// Check if we already revealed for this epoch
    pub fn has_revealed_for_epoch(&self, mechanism_id: u8, epoch: u64) -> bool {
        self.last_revealed_epoch
            .get(&mechanism_id)
            .map(|e| *e >= epoch)
            .unwrap_or(false)
    }

    /// Clear old state for new epoch
    pub fn new_epoch(&mut self, epoch: u64) {
        // Keep pending commits if they haven't been revealed yet
        // Clear the committed_epoch to allow new commits
        if self.committed_epoch != Some(epoch) {
            // New epoch - clear old unrevealed commits (they're now invalid)
            if !self.pending_mechanism_commits.is_empty() {
                warn!(
                    "Clearing {} unrevealed commits from previous epoch",
                    self.pending_mechanism_commits.len()
                );
                self.pending_mechanism_commits.clear();
            }
            self.pending_commit = None;
        }
    }
}

/// Weight submission manager with persistence
pub struct WeightSubmitter {
    client: SubtensorClient,
    /// Persisted commit state (for hash-based commit-reveal v2/v3)
    state: PersistedCommitState,
    /// Path to persistence file
    persist_path: PathBuf,
    /// Current epoch (updated externally)
    current_epoch: u64,
    /// Cached commit-reveal version from chain
    cached_crv_version: Option<u16>,
}

/// Pending mechanism commit data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingMechanismCommit {
    pub mechanism_id: u8,
    pub hash: String,
    pub uids: Vec<u16>,
    pub weights: Vec<u16>,
    /// Salt stored as hex string to avoid JSON serialization issues with u16
    pub salt_hex: String,
    pub version_key: u64,
    pub epoch: u64,
}

impl PendingMechanismCommit {
    /// Get salt as Vec<u16> from hex storage
    pub fn get_salt(&self) -> Vec<u16> {
        // Decode hex to bytes, then convert pairs of bytes to u16 (little-endian)
        let bytes = hex::decode(&self.salt_hex).unwrap_or_default();
        bytes
            .chunks(2)
            .map(|chunk| {
                if chunk.len() == 2 {
                    u16::from_le_bytes([chunk[0], chunk[1]])
                } else {
                    chunk[0] as u16
                }
            })
            .collect()
    }

    /// Create salt_hex from Vec<u16>
    pub fn salt_to_hex(salt: &[u16]) -> String {
        // Convert each u16 to 2 bytes (little-endian) and hex encode
        let bytes: Vec<u8> = salt.iter().flat_map(|s| s.to_le_bytes()).collect();
        hex::encode(bytes)
    }
}

/// Pending commit data using subtensor-compatible format (v2)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingCommitV2 {
    pub hash: String,
    pub uids: Vec<u16>,
    pub weights: Vec<u16>,
    /// Salt stored as hex string to avoid JSON serialization issues
    pub salt_hex: String,
    pub version_key: u64,
    pub epoch: u64,
}

impl PendingCommitV2 {
    /// Get salt as Vec<u16> from hex storage
    pub fn get_salt(&self) -> Vec<u16> {
        let bytes = hex::decode(&self.salt_hex).unwrap_or_default();
        bytes
            .chunks(2)
            .map(|chunk| {
                if chunk.len() == 2 {
                    u16::from_le_bytes([chunk[0], chunk[1]])
                } else {
                    chunk[0] as u16
                }
            })
            .collect()
    }

    /// Create salt_hex from Vec<u16>
    pub fn salt_to_hex(salt: &[u16]) -> String {
        let bytes: Vec<u8> = salt.iter().flat_map(|s| s.to_le_bytes()).collect();
        hex::encode(bytes)
    }
}

impl WeightSubmitter {
    /// Create a new weight submitter with persistence
    pub fn new(client: SubtensorClient, data_dir: Option<PathBuf>) -> Self {
        let persist_path = data_dir
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_COMMITS_FILE);

        let state = PersistedCommitState::load(&persist_path);

        if !state.pending_mechanism_commits.is_empty() {
            info!(
                "Loaded {} pending commits from previous session (epoch {:?})",
                state.pending_mechanism_commits.len(),
                state.committed_epoch
            );
        }

        Self {
            client,
            state,
            persist_path,
            current_epoch: 0,
            cached_crv_version: None,
        }
    }

    /// Get commit-reveal version from chain (cached)
    pub async fn get_crv_version(&mut self) -> Result<u16> {
        if let Some(v) = self.cached_crv_version {
            return Ok(v);
        }

        let client = self.client.client()?;
        let version = get_commit_reveal_version(client)
            .await
            .unwrap_or(DEFAULT_COMMIT_REVEAL_VERSION);
        self.cached_crv_version = Some(version);
        info!("Commit-reveal version from chain: {}", version);
        Ok(version)
    }

    /// Check if CRv4 (timelock encryption) is enabled
    pub async fn is_crv4_enabled(&mut self) -> bool {
        self.get_crv_version().await.unwrap_or(0) >= 4
    }

    /// Get mutable access to the client
    pub fn client_mut(&mut self) -> &mut SubtensorClient {
        &mut self.client
    }

    /// Update current epoch and handle epoch transition
    pub fn set_epoch(&mut self, epoch: u64) {
        if epoch != self.current_epoch {
            info!(
                "Weight submitter epoch update: {} -> {}",
                self.current_epoch, epoch
            );
            self.current_epoch = epoch;
            self.state.new_epoch(epoch);
            if let Err(e) = self.state.save(&self.persist_path) {
                error!("Failed to save commit state: {}", e);
            }
        }
    }

    /// Check if we already committed for current epoch
    pub fn has_committed_for_epoch(&self, epoch: u64) -> bool {
        self.state.has_commits_for_epoch(epoch)
    }

    /// Save state to disk
    fn persist(&self) {
        if let Err(e) = self.state.save(&self.persist_path) {
            error!("Failed to persist commit state: {}", e);
        }
    }

    /// Submit weights to Bittensor
    ///
    /// If commit-reveal is enabled:
    ///   1. First call commits the hash
    ///   2. Second call reveals the weights (after tempo blocks)
    ///
    /// If not:
    ///   - Directly calls set_weights
    pub async fn submit_weights(&mut self, weights: &[WeightAssignment]) -> Result<String> {
        if self.client.use_commit_reveal() {
            self.submit_with_commit_reveal(weights).await
        } else {
            self.submit_direct(weights).await
        }
    }

    /// Direct weight submission (no commit-reveal)
    async fn submit_direct(&self, weights: &[WeightAssignment]) -> Result<String> {
        let (uids, weight_values) = self.prepare_weights(weights)?;

        if uids.is_empty() {
            return Err(anyhow::anyhow!("No valid UIDs found for weights"));
        }

        // Convert u16 weights to f32 for set_weights
        let weight_f32: Vec<f32> = weight_values.iter().map(|w| *w as f32 / 65535.0).collect();

        info!("Submitting {} weights directly", uids.len());

        let tx_hash = set_weights(
            self.client.client()?,
            self.client.signer()?,
            self.client.netuid(),
            &uids,
            &weight_f32,
            Some(self.client.version_key()),
            ExtrinsicWait::Finalized,
        )
        .await?;

        info!("Weights submitted: {}", tx_hash);
        Ok(tx_hash)
    }

    /// Submit with commit-reveal pattern (v2 - subtensor compatible)
    async fn submit_with_commit_reveal(&mut self, weights: &[WeightAssignment]) -> Result<String> {
        // If we have a pending commit, reveal it
        if let Some(pending) = self.state.pending_commit.take() {
            self.persist();
            return self.reveal_pending_v2(pending).await;
        }

        // Otherwise, create new commit using v2 format
        let (uids, weight_values) = self.prepare_weights(weights)?;

        if uids.is_empty() {
            return Err(anyhow::anyhow!("No valid UIDs found for weights"));
        }

        // Convert to u16 for subtensor
        let uids_u16: Vec<u16> = uids.iter().map(|u| *u as u16).collect();

        // Get account public key for hash
        let account = self.client.signer()?.account_id().0;
        let version_key = self.client.version_key();

        // Generate commit using v2 format (subtensor compatible)
        let commit_data = prepare_commit_reveal(
            &account,
            self.client.netuid(),
            &uids_u16,
            &weight_values,
            version_key,
            8, // salt length
        );

        info!("Committing weights hash (v2): {}", commit_data.commit_hash);

        let tx_hash = commit_weights(
            self.client.client()?,
            self.client.signer()?,
            self.client.netuid(),
            &commit_data.commit_hash,
            ExtrinsicWait::Finalized,
        )
        .await?;

        // Store pending commit for reveal (salt as hex to avoid serialization issues)
        self.state.pending_commit = Some(PendingCommitV2 {
            hash: commit_data.commit_hash,
            uids: commit_data.uids,
            weights: commit_data.weights,
            salt_hex: PendingCommitV2::salt_to_hex(&commit_data.salt),
            version_key: commit_data.version_key,
            epoch: self.current_epoch,
        });
        self.persist();

        info!("Weights committed: {}", tx_hash);
        Ok(tx_hash)
    }

    /// Reveal pending commit (v2 format)
    async fn reveal_pending_v2(&mut self, pending: PendingCommitV2) -> Result<String> {
        info!("Revealing weights for commit: {}", pending.hash);

        // Convert uids to u64 for reveal_weights API
        let uids_u64: Vec<u64> = pending.uids.iter().map(|u| *u as u64).collect();
        let salt = pending.get_salt();

        debug!(
            "Revealing: uids={:?}, weights={:?}, salt_hex={}, salt={:?}",
            pending.uids, pending.weights, pending.salt_hex, salt
        );

        let tx_hash = reveal_weights(
            self.client.client()?,
            self.client.signer()?,
            self.client.netuid(),
            &uids_u64,
            &pending.weights,
            &salt, // Now correctly passing &[u16]
            pending.version_key,
            ExtrinsicWait::Finalized,
        )
        .await?;

        info!("Weights revealed: {}", tx_hash);
        Ok(tx_hash)
    }

    /// Check if we have a pending commit to reveal
    pub fn has_pending_commit(&self) -> bool {
        self.state.pending_commit.is_some()
    }

    /// Prepare weights for submission
    /// Converts WeightAssignment to (UIDs, normalized u16 weights)
    fn prepare_weights(&self, weights: &[WeightAssignment]) -> Result<(Vec<u64>, Vec<u16>)> {
        // Get hotkeys from weights
        let hotkeys: Vec<String> = weights.iter().map(|w| w.agent_hash.clone()).collect();

        // Lookup UIDs for hotkeys from cached metagraph
        let uid_map = self.client.get_uids_for_hotkeys(&hotkeys);

        let mut uids = Vec::new();
        let mut weight_values = Vec::new();

        for weight in weights {
            if let Some((_, uid)) = uid_map.iter().find(|(h, _)| h == &weight.agent_hash) {
                uids.push(*uid as u64);
                // Convert 0-1 weight to u16 (0-65535)
                let w_u16 = (weight.weight.clamp(0.0, 1.0) * 65535.0) as u16;
                weight_values.push(w_u16);
            } else {
                warn!("No UID found for hotkey: {}", weight.agent_hash);
            }
        }

        debug!(
            "Prepared {} weights from {} assignments",
            uids.len(),
            weights.len()
        );
        Ok((uids, weight_values))
    }

    /// Force reveal without new commit (if we have pending)
    pub async fn force_reveal(&mut self) -> Result<Option<String>> {
        if let Some(pending) = self.state.pending_commit.take() {
            self.persist();
            let tx = self.reveal_pending_v2(pending).await?;
            Ok(Some(tx))
        } else {
            Ok(None)
        }
    }

    /// Submit weights for multiple mechanisms in a single batch transaction
    /// This is used at epoch end to submit all mechanism weights at once.
    ///
    /// mechanism_weights: Vec<(mechanism_id, uids, weights)>
    ///
    /// Automatically selects the appropriate method:
    /// - CRv4: Uses timelock encryption (chain auto-reveals)
    /// - CRv2/v3: Uses hash-based commit-reveal (needs manual reveal)
    /// - Direct: No commit-reveal
    pub async fn submit_mechanism_weights_batch(
        &mut self,
        mechanism_weights: &[(u8, Vec<u16>, Vec<u16>)],
    ) -> Result<String> {
        if mechanism_weights.is_empty() {
            return Err(anyhow::anyhow!("No mechanism weights to submit"));
        }

        // Check commit-reveal mode
        if !self.client.use_commit_reveal() {
            return self
                .submit_mechanism_weights_batch_direct(mechanism_weights)
                .await;
        }

        // Check CRv4 (timelock encryption)
        let crv_version = self.get_crv_version().await.unwrap_or(0);
        if crv_version >= 4 {
            info!("Using CRv4 (timelock encryption) for weight submission");
            return self
                .submit_mechanism_weights_batch_crv4(mechanism_weights)
                .await;
        }

        // Fall back to hash-based commit-reveal
        self.submit_mechanism_weights_batch_commit_reveal(mechanism_weights)
            .await
    }

    /// Submit mechanism weights using CRv4 (timelock encryption)
    /// No manual reveal needed - chain decrypts automatically when DRAND pulse arrives
    async fn submit_mechanism_weights_batch_crv4(
        &mut self,
        mechanism_weights: &[(u8, Vec<u16>, Vec<u16>)],
    ) -> Result<String> {
        let client = self.client.client()?;
        let signer = self.client.signer()?;
        let netuid = self.client.netuid();
        let version_key = self.client.version_key();
        let hotkey_bytes = signer.account_id().0.to_vec();

        // Get chain parameters for reveal round calculation
        let current_block = client.block_number().await?;
        let tempo = get_tempo(client, netuid).await.unwrap_or(360);
        let reveal_period = get_reveal_period(client, netuid).await.unwrap_or(1);
        let block_time = 12.0; // Standard Bittensor block time
        let crv_version = self
            .cached_crv_version
            .unwrap_or(DEFAULT_COMMIT_REVEAL_VERSION);

        // Get chain's last DRAND round (CRITICAL: must use chain state, not system time)
        let chain_last_drand_round = get_last_drand_round(client).await?;

        let mut last_tx = String::new();
        let mut committed_count = 0;

        for (mechanism_id, uids, weights) in mechanism_weights {
            // Calculate reveal round for this mechanism (relative to chain's DRAND state)
            let storage_index = get_mechid_storage_index(netuid, *mechanism_id);
            let reveal_round = calculate_reveal_round(
                tempo,
                current_block,
                storage_index,
                reveal_period,
                block_time,
                chain_last_drand_round,
            );

            // Encrypt payload using TLE
            let encrypted =
                prepare_crv4_commit(&hotkey_bytes, uids, weights, version_key, reveal_round)?;

            info!(
                "CRv4 committing mechanism {}: {} uids, chain_last_drand={}, reveal_round={}",
                mechanism_id,
                uids.len(),
                chain_last_drand_round,
                reveal_round
            );

            // Submit timelocked commit - no persistence needed, chain auto-reveals
            let tx_hash = commit_timelocked_mechanism_weights(
                client,
                signer,
                netuid,
                *mechanism_id,
                &encrypted,
                reveal_round,
                crv_version,
                ExtrinsicWait::Finalized,
            )
            .await?;

            info!(
                "CRv4 mechanism {} committed: {} (auto-reveal at round {})",
                mechanism_id, tx_hash, reveal_round
            );

            last_tx = tx_hash;
            committed_count += 1;
        }

        info!(
            "CRv4 batch complete: {} mechanisms committed (no reveal needed)",
            committed_count
        );
        Ok(last_tx)
    }

    /// Submit mechanism weights directly (without commit-reveal)
    async fn submit_mechanism_weights_batch_direct(
        &mut self,
        mechanism_weights: &[(u8, Vec<u16>, Vec<u16>)],
    ) -> Result<String> {
        use bittensor_rs::validator::utility::batch_set_mechanism_weights;

        let weights_for_batch: Vec<(u8, Vec<u16>, Vec<u16>)> = mechanism_weights.to_vec();

        info!(
            "Batch submitting weights directly for {} mechanisms",
            weights_for_batch.len()
        );

        let tx_hash = batch_set_mechanism_weights(
            self.client.client()?,
            self.client.signer()?,
            self.client.netuid(),
            weights_for_batch,
            self.client.version_key(),
            ExtrinsicWait::Finalized,
        )
        .await?;

        info!("Batch mechanism weights submitted: {}", tx_hash);
        Ok(tx_hash)
    }

    /// Submit mechanism weights using commit-reveal pattern
    async fn submit_mechanism_weights_batch_commit_reveal(
        &mut self,
        mechanism_weights: &[(u8, Vec<u16>, Vec<u16>)],
    ) -> Result<String> {
        use bittensor_rs::commit_hash_to_hex;
        use bittensor_rs::generate_mechanism_commit_hash;
        use bittensor_rs::generate_salt;
        use bittensor_rs::validator::utility::{batch_all, BatchCall};

        let account = self.client.signer()?.account_id().0;
        let netuid = self.client.netuid();
        let version_key = self.client.version_key();

        // Generate commits for all mechanisms
        let mut batch_calls = Vec::new();
        let mut pending_commits = Vec::new();

        for (mechanism_id, uids, weights) in mechanism_weights {
            // Generate salt (8 u16 values)
            let salt = generate_salt(8);
            let salt_hex = PendingMechanismCommit::salt_to_hex(&salt);

            debug!(
                "Commit mechanism {}: uids={:?}, weights={:?}, salt={:?}, salt_hex={}, version_key={}",
                mechanism_id, uids, weights, salt, salt_hex, version_key
            );

            // Generate commit hash
            let commit_hash = generate_mechanism_commit_hash(
                &account,
                netuid,
                *mechanism_id,
                uids,
                weights,
                &salt,
                version_key,
            );

            let commit_hash_hex = commit_hash_to_hex(&commit_hash);
            info!(
                "Generated commit for mechanism {}: {} (salt_hex={})",
                mechanism_id,
                &commit_hash_hex[..16],
                &salt_hex[..16]
            );

            // Add to batch
            batch_calls.push(BatchCall::commit_mechanism_weights(
                netuid,
                *mechanism_id,
                &commit_hash,
            ));

            // Store pending commit for later reveal (salt as hex to avoid serialization issues)
            pending_commits.push(PendingMechanismCommit {
                mechanism_id: *mechanism_id,
                hash: commit_hash_hex,
                uids: uids.clone(),
                weights: weights.clone(),
                salt_hex, // Already computed above
                version_key,
                epoch: self.current_epoch,
            });
        }

        info!(
            "Batch committing weights for {} mechanisms",
            batch_calls.len()
        );

        // Submit all commits in one batch transaction
        let tx_hash = batch_all(
            self.client.client()?,
            self.client.signer()?,
            batch_calls,
            ExtrinsicWait::Finalized,
        )
        .await?;

        // Store pending commits for reveal and persist
        for pending in pending_commits {
            self.state
                .pending_mechanism_commits
                .insert(pending.mechanism_id, pending);
        }
        self.state.committed_epoch = Some(self.current_epoch);
        self.persist();

        info!(
            "Batch mechanism commits submitted: {} (reveals pending, epoch {})",
            tx_hash, self.current_epoch
        );
        Ok(tx_hash)
    }

    /// Reveal all pending mechanism commits
    pub async fn reveal_pending_mechanism_commits(&mut self) -> Result<Option<String>> {
        use bittensor_rs::reveal_mechanism_weights;

        if self.state.pending_mechanism_commits.is_empty() {
            return Ok(None);
        }

        let pending: Vec<_> = self.state.pending_mechanism_commits.drain().collect();
        self.persist();

        info!("Revealing {} pending mechanism commits", pending.len());

        // Reveal each mechanism's weights
        // Batch reveal via mechanism weights API
        let mut last_tx = String::new();
        let mut revealed_mechanisms = Vec::new();

        for (_, commit) in pending {
            let mechanism_id = commit.mechanism_id;
            let epoch = commit.epoch;
            let salt = commit.get_salt();

            debug!(
                "Revealing mechanism {}: uids={:?}, weights={:?}, salt_hex={}, salt={:?}, version_key={}",
                mechanism_id, commit.uids, commit.weights, commit.salt_hex, salt, commit.version_key
            );

            let tx_hash = reveal_mechanism_weights(
                self.client.client()?,
                self.client.signer()?,
                self.client.netuid(),
                mechanism_id,
                &commit.uids,
                &commit.weights,
                &salt,
                commit.version_key,
                ExtrinsicWait::Finalized,
            )
            .await?;

            info!(
                "Revealed mechanism {} weights: {} (epoch {})",
                mechanism_id, tx_hash, epoch
            );
            revealed_mechanisms.push((mechanism_id, epoch));
            last_tx = tx_hash;
        }

        // Track revealed epochs
        for (mechanism_id, epoch) in revealed_mechanisms {
            self.state.last_revealed_epoch.insert(mechanism_id, epoch);
        }
        self.persist();

        Ok(Some(last_tx))
    }

    /// Check if there are pending mechanism commits to reveal
    pub fn has_pending_mechanism_commits(&self) -> bool {
        !self.state.pending_mechanism_commits.is_empty()
    }

    /// Get pending commit info for logging
    pub fn pending_commits_info(&self) -> String {
        if self.state.pending_mechanism_commits.is_empty() {
            "none".to_string()
        } else {
            let ids: Vec<_> = self.state.pending_mechanism_commits.keys().collect();
            format!(
                "{} mechanisms {:?} (epoch {:?})",
                ids.len(),
                ids,
                self.state.committed_epoch
            )
        }
    }
}

/// Utility to convert f64 weights to normalized u16
pub fn normalize_to_u16(weights: &[f64]) -> Vec<u16> {
    let sum: f64 = weights.iter().sum();
    if sum == 0.0 {
        return vec![0; weights.len()];
    }

    weights
        .iter()
        .map(|w| ((w / sum) * 65535.0) as u16)
        .collect()
}

/// Mechanism weight manager for handling per-challenge weights
pub struct MechanismWeightManager {
    client: SubtensorClient,
    /// Track last epoch we set weights for each mechanism
    last_weight_epoch: HashMap<u8, u64>,
    /// Pending mechanism commits (mechanism_id -> PendingMechanismCommitV2)
    pending_mechanism_commits: HashMap<u8, PendingMechanismCommitV2>,
}

/// Pending mechanism commit data using subtensor-compatible format (v2)
#[derive(Clone, Debug)]
struct PendingMechanismCommitV2 {
    mechanism_id: u8,
    hash: String,
    uids: Vec<u16>, // u16 to match subtensor
    weights: Vec<u16>,
    salt: Vec<u16>, // u16 salt as required by subtensor
    version_key: u64,
    epoch: u64,
}

impl MechanismWeightManager {
    /// Create a new mechanism weight manager
    pub fn new(client: SubtensorClient) -> Self {
        Self {
            client,
            last_weight_epoch: HashMap::new(),
            pending_mechanism_commits: HashMap::new(),
        }
    }

    /// Get mutable access to the client
    pub fn client_mut(&mut self) -> &mut SubtensorClient {
        &mut self.client
    }

    /// Get the next epoch start block
    pub async fn get_next_epoch(&self) -> Result<u64> {
        let client = self.client.client()?;
        let next_epoch = get_next_epoch_start_block(client, self.client.netuid(), None)
            .await?
            .unwrap_or(0);
        Ok(next_epoch)
    }

    /// Check if weights have already been set for this mechanism in current epoch
    pub fn has_set_weights_for_epoch(&self, mechanism_id: u8, epoch: u64) -> bool {
        self.last_weight_epoch
            .get(&mechanism_id)
            .map(|e| *e >= epoch)
            .unwrap_or(false)
    }

    /// Submit mechanism weights for a specific challenge
    /// Returns Ok(None) if weights already set for this epoch
    pub async fn submit_mechanism_weights(
        &mut self,
        mechanism_id: u8,
        weights: &[WeightAssignment],
        epoch: u64,
    ) -> Result<Option<String>> {
        // Check if already set for this epoch
        if self.has_set_weights_for_epoch(mechanism_id, epoch) {
            info!(
                "Weights already set for mechanism {} in epoch {}, skipping",
                mechanism_id, epoch
            );
            return Ok(None);
        }

        // Prepare weights with fallback to UID 0
        let (uids, weight_values) = self.prepare_weights_with_fallback(weights)?;

        if self.client.use_commit_reveal() {
            self.submit_mechanism_with_commit_reveal(mechanism_id, uids, weight_values, epoch)
                .await
        } else {
            self.submit_mechanism_direct(mechanism_id, uids, weight_values, epoch)
                .await
        }
    }

    /// Submit mechanism weights directly (no commit-reveal)
    async fn submit_mechanism_direct(
        &mut self,
        mechanism_id: u8,
        uids: Vec<u64>,
        weights: Vec<u16>,
        epoch: u64,
    ) -> Result<Option<String>> {
        // Convert u16 weights to f32 for set_mechanism_weights
        let weight_f32: Vec<f32> = weights.iter().map(|w| *w as f32 / 65535.0).collect();

        info!(
            "Submitting {} mechanism {} weights directly",
            uids.len(),
            mechanism_id
        );

        let tx_hash = set_mechanism_weights(
            self.client.client()?,
            self.client.signer()?,
            self.client.netuid(),
            mechanism_id,
            &uids,
            &weight_f32,
            Some(self.client.version_key()),
            ExtrinsicWait::Finalized,
        )
        .await?;

        // Mark as set for this epoch
        self.last_weight_epoch.insert(mechanism_id, epoch);

        info!("Mechanism {} weights submitted: {}", mechanism_id, tx_hash);
        Ok(Some(tx_hash))
    }

    /// Submit mechanism weights with commit-reveal pattern (v2 - subtensor compatible)
    async fn submit_mechanism_with_commit_reveal(
        &mut self,
        mechanism_id: u8,
        uids: Vec<u64>,
        weights: Vec<u16>,
        epoch: u64,
    ) -> Result<Option<String>> {
        // Check if we have a pending commit to reveal
        if let Some(pending) = self.pending_mechanism_commits.remove(&mechanism_id) {
            return self.reveal_mechanism_pending_v2(pending).await;
        }

        // Convert to u16 for subtensor
        let uids_u16: Vec<u16> = uids.iter().map(|u| *u as u16).collect();

        // Get account public key for hash
        let account = self.client.signer()?.account_id().0;
        let version_key = self.client.version_key();

        // Generate commit using v2 format (subtensor compatible)
        let commit_data = prepare_mechanism_commit_reveal(
            &account,
            self.client.netuid(),
            mechanism_id,
            &uids_u16,
            &weights,
            version_key,
            8, // salt length
        );

        info!(
            "Committing mechanism {} weights hash (v2): {}",
            mechanism_id, commit_data.commit_hash
        );

        let tx_hash = commit_mechanism_weights(
            self.client.client()?,
            self.client.signer()?,
            self.client.netuid(),
            mechanism_id,
            &commit_data.commit_hash,
            ExtrinsicWait::Finalized,
        )
        .await?;

        // Store pending commit for reveal
        self.pending_mechanism_commits.insert(
            mechanism_id,
            PendingMechanismCommitV2 {
                mechanism_id,
                hash: commit_data.commit_hash,
                uids: commit_data.uids,
                weights: commit_data.weights,
                salt: commit_data.salt,
                version_key: commit_data.version_key,
                epoch,
            },
        );

        info!("Mechanism {} weights committed: {}", mechanism_id, tx_hash);
        Ok(Some(tx_hash))
    }

    /// Reveal pending mechanism commit (v2 format)
    async fn reveal_mechanism_pending_v2(
        &mut self,
        pending: PendingMechanismCommitV2,
    ) -> Result<Option<String>> {
        info!(
            "Revealing mechanism {} weights for commit: {}",
            pending.mechanism_id, pending.hash
        );

        let tx_hash = reveal_mechanism_weights(
            self.client.client()?,
            self.client.signer()?,
            self.client.netuid(),
            pending.mechanism_id,
            &pending.uids,
            &pending.weights,
            &pending.salt,
            pending.version_key,
            ExtrinsicWait::Finalized,
        )
        .await?;

        // Mark as set for this epoch
        self.last_weight_epoch
            .insert(pending.mechanism_id, pending.epoch);

        info!(
            "Mechanism {} weights revealed: {}",
            pending.mechanism_id, tx_hash
        );
        Ok(Some(tx_hash))
    }

    /// Prepare weights with fallback to UID 0 if empty or sum < 1
    fn prepare_weights_with_fallback(
        &self,
        weights: &[WeightAssignment],
    ) -> Result<(Vec<u64>, Vec<u16>)> {
        let (mut uids, mut weight_values) = self.prepare_weights(weights)?;

        // If no weights, put everything on UID 0
        if uids.is_empty() {
            info!("No valid weights, defaulting to UID 0");
            return Ok((vec![0], vec![65535])); // 100% to UID 0
        }

        // Calculate sum and check if we need to fill
        let sum: u32 = weight_values.iter().map(|w| *w as u32).sum();
        let target_sum: u32 = 65535;

        if sum < target_sum {
            let remaining = (target_sum - sum) as u16;

            // Check if UID 0 is already in the list
            if let Some(pos) = uids.iter().position(|u| *u == 0) {
                // Add remaining to existing UID 0
                weight_values[pos] = weight_values[pos].saturating_add(remaining);
            } else {
                // Add UID 0 with remaining weight
                uids.push(0);
                weight_values.push(remaining);
                info!(
                    "Adding {} weight to UID 0 to fill to sum=1",
                    remaining as f64 / 65535.0
                );
            }
        }

        Ok((uids, weight_values))
    }

    /// Prepare weights for submission (convert hotkeys to UIDs)
    fn prepare_weights(&self, weights: &[WeightAssignment]) -> Result<(Vec<u64>, Vec<u16>)> {
        let hotkeys: Vec<String> = weights.iter().map(|w| w.agent_hash.clone()).collect();

        let uid_map = self.client.get_uids_for_hotkeys(&hotkeys);

        let mut uids = Vec::new();
        let mut weight_values = Vec::new();

        for weight in weights {
            if let Some((_, uid)) = uid_map.iter().find(|(h, _)| h == &weight.agent_hash) {
                uids.push(*uid as u64);
                let w_u16 = (weight.weight.clamp(0.0, 1.0) * 65535.0) as u16;
                weight_values.push(w_u16);
            } else {
                warn!("No UID found for hotkey: {}", weight.agent_hash);
            }
        }

        debug!(
            "Prepared {} weights from {} assignments",
            uids.len(),
            weights.len()
        );
        Ok((uids, weight_values))
    }

    /// Check if we have pending commits to reveal for any mechanism
    pub fn has_pending_commits(&self) -> bool {
        !self.pending_mechanism_commits.is_empty()
    }

    /// Get list of mechanisms with pending commits
    pub fn pending_mechanism_ids(&self) -> Vec<u8> {
        self.pending_mechanism_commits.keys().cloned().collect()
    }

    /// Force reveal all pending mechanism commits
    pub async fn reveal_all_pending(&mut self) -> Result<Vec<(u8, String)>> {
        let mut results = Vec::new();
        let pending_ids: Vec<u8> = self.pending_mechanism_commits.keys().cloned().collect();

        for mec_id in pending_ids {
            if let Some(pending) = self.pending_mechanism_commits.remove(&mec_id) {
                if let Some(tx) = self.reveal_mechanism_pending_v2(pending).await? {
                    results.push((mec_id, tx));
                }
            }
        }

        Ok(results)
    }

    /// Reset epoch tracking (call at epoch boundary)
    pub fn reset_epoch_tracking(&mut self) {
        self.last_weight_epoch.clear();
    }
}
