#![allow(dead_code, unused_variables, unused_imports)]
//! Mini-Chain RPC Server
//!
//! Substrate-style JSON-RPC 2.0 server for chain queries.
//!
//! Single endpoint: POST / with JSON-RPC request
//!
//! Methods:
//! - system_health        - Health check
//! - system_version       - Get version info
//! - system_peers         - Get connected peers
//! - chain_getHead        - Get latest block
//! - chain_getBlock       - Get block by number
//! - chain_getState       - Get full chain state
//! - state_getStorage     - Get storage value by key
//! - state_getValidators  - Get validators list
//! - state_getValidator   - Get single validator
//! - state_getChallenges  - Get challenges list
//! - state_getChallenge   - Get single challenge
//! - state_getJobs        - Get pending jobs
//! - state_getEpoch       - Get epoch info

mod auth;
mod handlers;
pub mod health;
mod jsonrpc;
mod server;
mod types;

pub use auth::*;
pub use handlers::*;
pub use health::{create_health_check, HealthCheck, HealthResponse, HealthStatus, ReadinessStatus};
pub use jsonrpc::*;
pub use server::*;
pub use types::*;
