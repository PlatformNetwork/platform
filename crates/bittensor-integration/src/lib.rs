#![allow(dead_code, unused_variables, unused_imports)]
//! Bittensor Integration for Mini-Chain
//!
//! Connects the Mini-Chain P2P layer to Bittensor blockchain
//! for submitting weights and reading metagraph state.
//!
//! Features:
//! - Validators synced from Bittensor metagraph
//! - Block subscription for epoch synchronization
//! - Weight submission via mechanism-based batching
//! - Concurrent weight collection from challenge endpoints
//!
//! The `BlockSync` module subscribes to finalized Bittensor blocks
//! to synchronize platform epochs with on-chain state.

mod block_sync;
mod challenge_weight_collector;
mod client;
mod config;
mod validator_sync;
mod weights;

#[cfg(test)]
mod tests;

pub use block_sync::*;
pub use challenge_weight_collector::*;
pub use client::*;
pub use config::*;
pub use validator_sync::*;
pub use weights::*;

// Re-export bittensor-rs types for convenience
pub use bittensor_rs::BittensorClient;

// Re-export high-level Subtensor API (use this directly instead of custom wrappers)
pub use bittensor_rs::{
    PendingCommit, Salt, Subtensor, SubtensorBuilder, SubtensorState, WeightResponse,
    WeightResponseData,
};

// Re-export chain types needed for weight submission
pub use bittensor_rs::chain::{signer_from_seed, BittensorSigner, ExtrinsicWait};

// Re-export metagraph sync for validator discovery
pub use bittensor_rs::metagraph::sync_metagraph;
