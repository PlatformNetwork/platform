#![allow(dead_code, unused_variables, unused_imports)]
//! Platform Challenge SDK
//!
//! SDK for developing challenges on Platform Network.
//! Fully decentralized P2P architecture - validators communicate directly.
//!
//! # Quick Start - Server Mode
//!
//! Challenge runs as HTTP server, validators call `/evaluate`:
//!
//! ```rust,ignore
//! use platform_challenge_sdk::prelude::*;
//!
//! struct MyChallenge;
//!
//! #[async_trait]
//! impl ServerChallenge for MyChallenge {
//!     fn challenge_id(&self) -> &str { "my-challenge" }
//!     fn name(&self) -> &str { "My Challenge" }
//!     fn version(&self) -> &str { "0.1.0" }
//!
//!     async fn evaluate(&self, req: EvaluationRequest) -> Result<EvaluationResponse, ChallengeError> {
//!         // Your evaluation logic here
//!         let score = evaluate_submission(&req.data)?;
//!         Ok(EvaluationResponse::success(&req.request_id, score, json!({})))
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), ChallengeError> {
//!     ChallengeServer::builder(MyChallenge)
//!         .port(8080)
//!         .build()
//!         .run()
//!         .await
//! }
//! ```
//!
//! # Quick Start - P2P Mode
//!
//! ```rust,ignore
//! use platform_challenge_sdk::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), ChallengeError> {
//!     run_decentralized(MyChallenge).await
//! }
//! ```
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Your Challenge                          │
//! │  impl ServerChallenge { evaluate(), validate(), ... }       │
//! ├─────────────────────────────────────────────────────────────┤
//! │                  Platform Challenge SDK                     │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
//! │  │   Server    │  │  P2P Client │  │   Types     │        │
//! │  │ (HTTP mode) │  │ (libp2p)    │  │ (generic)   │        │
//! │  └─────────────┘  └─────────────┘  └─────────────┘        │
//! ├─────────────────────────────────────────────────────────────┤
//! │                  Validator Network (P2P)                    │
//! │         (gossipsub, DHT, consensus)                         │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Note on Terminology
//!
//! This SDK is **generic** - it doesn't use challenge-specific terms like
//! "agent", "miner", etc. Each challenge defines its own terminology:
//! - `EvaluationRequest.data` contains challenge-specific submission data
//! - `EvaluationResponse.results` contains challenge-specific result data
//! - `participant_id` is generic (could be miner hotkey, user id, etc.)

// ============================================================================
// MODULES
// ============================================================================

/// Data types and utilities
pub mod data;
/// Database utilities
pub mod database;
/// Decentralized challenge runner for P2P mode
pub mod decentralized;
/// Error types
pub mod error;
/// P2P client for decentralized communication
pub mod p2p_client;
/// HTTP routes
pub mod routes;
/// Server mode - expose challenge as HTTP server
pub mod server;
/// Submission types
pub mod submission_types;
/// Test challenge implementation
pub mod test_challenge;
/// Core types
pub mod types;
/// Weight calculation types
pub mod weight_types;
/// Weight calculation utilities
pub mod weights;

// ============================================================================
// EXPORTS
// ============================================================================

pub use decentralized::run_decentralized;
pub use p2p_client::{
    P2PChallengeClient, P2PChallengeConfig, P2PChallengeMessage, PendingSubmission,
    ValidatorEvaluationResult,
};
pub use server::{
    ChallengeServer, ChallengeServerBuilder, ConfigLimits, ConfigResponse, EvaluationRequest,
    EvaluationResponse, HealthResponse, ServerChallenge, ServerConfig, ValidationRequest,
    ValidationResponse,
};

pub use data::*;
pub use database::*;
pub use error::*;
pub use routes::*;
pub use submission_types::*;
pub use test_challenge::SimpleTestChallenge;
pub use types::*;
pub use weight_types::*;
pub use weights::*;

/// Prelude for P2P challenge development
pub mod prelude {
    pub use super::error::ChallengeError;
    pub use super::server::{
        ChallengeServer, EvaluationRequest, EvaluationResponse, ServerChallenge, ServerConfig,
        ValidationRequest, ValidationResponse,
    };

    // P2P mode
    pub use super::decentralized::run_decentralized;
    pub use super::p2p_client::{
        P2PChallengeClient, P2PChallengeConfig, P2PChallengeMessage, PendingSubmission,
        ValidatorEvaluationResult,
    };

    // Common utilities
    pub use async_trait::async_trait;
    pub use serde::{Deserialize, Serialize};
    pub use serde_json::{json, Value};
    pub use tracing::{debug, error, info, warn};
}
