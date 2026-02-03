//! Challenge Registry for Platform Network
//!
//! Manages the lifecycle of challenge crates including:
//! - Challenge discovery and registration
//! - Version management and migrations
//! - Hot-reload support with state preservation
//! - Health monitoring
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                   Challenge Registry                        │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
//! │  │  Discovery  │  │  Lifecycle  │  │   Health    │         │
//! │  │   Manager   │  │   Manager   │  │   Monitor   │         │
//! │  └─────────────┘  └─────────────┘  └─────────────┘         │
//! ├─────────────────────────────────────────────────────────────┤
//! │                 Challenge State Store                       │
//! │         (evaluations, checkpoints, migrations)              │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod discovery;
pub mod error;
pub mod health;
pub mod lifecycle;
pub mod migration;
pub mod registry;
pub mod state;
pub mod version;

pub use discovery::{ChallengeDiscovery, DiscoveredChallenge};
pub use error::{RegistryError, RegistryResult};
pub use health::{ChallengeHealth, HealthMonitor, HealthStatus};
pub use lifecycle::{ChallengeLifecycle, LifecycleEvent, LifecycleState};
pub use migration::{ChallengeMigration, MigrationPlan, MigrationStatus};
pub use registry::{ChallengeEntry, ChallengeRegistry, RegisteredChallenge};
pub use state::{ChallengeState, StateSnapshot, StateStore};
pub use version::{ChallengeVersion, VersionConstraint, VersionedChallenge};
