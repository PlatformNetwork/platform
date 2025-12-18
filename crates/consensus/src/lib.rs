#![allow(dead_code, unused_variables, unused_imports)]
//! PBFT-style Consensus for Mini-Chain
//!
//! Simplified Practical Byzantine Fault Tolerance for ~8 validators.
//! Requires 2f+1 votes where f is the max faulty nodes (f=2 for 8 validators).
//!
//! Also includes Stake-Based Governance Consensus:
//! - 50%+ stake threshold for chain modifications
//! - Bootstrap period (block < 7175360) with subnet owner authority
//! - Proposal system with timeouts and double-voting prevention
//!
//! # Security Model
//!
//! The governance system implements a dual-authority model:
//!
//! 1. **Bootstrap Period** (block < 7,175,360):
//!    - Subnet owner (hotkey: 5GziQCcRpN8NCJktX343brnfuVe3w6gUYieeStXPD1Dag2At)
//!      can execute actions without stake verification
//!    - This allows network setup while validators join
//!    - Data can be downloaded from owner's validator without verification
//!
//! 2. **Stake Consensus** (block >= 7,175,360):
//!    - All chain modifications require 50%+ of total stake approval
//!    - Proposals have minimum voting period (1 hour) and timeout (24 hours)
//!    - Double-voting is prevented
//!    - Rate limiting prevents spam proposals

pub mod governance_integration;
pub mod pbft;
pub mod stake_governance;
pub mod state;
pub mod types;

pub use governance_integration::*;
pub use pbft::*;
pub use stake_governance::*;
pub use state::*;
pub use types::*;
