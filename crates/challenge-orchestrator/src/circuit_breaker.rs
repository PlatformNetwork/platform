//! Circuit Breaker for Challenge Container Connections
//!
//! Implements the circuit breaker pattern to prevent repeated requests to
//! unhealthy challenge containers. This avoids wasting resources waiting
//! for timeouts on known-bad endpoints.
//!
//! ## States
//! - **Closed**: Normal operation, requests pass through
//! - **Open**: Fast-fail all requests (container known to be unhealthy)
//! - **HalfOpen**: Allow limited test requests to check recovery
//!
//! ## Transitions
//! - Closed → Open: After `failure_threshold` consecutive failures
//! - Open → HalfOpen: After `reset_timeout` duration
//! - HalfOpen → Closed: After `success_threshold` consecutive successes
//! - HalfOpen → Open: On any failure

use parking_lot::RwLock;
use platform_core::ChallengeId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Circuit breaker configuration
#[derive(Clone, Debug)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit
    pub failure_threshold: u32,
    /// Duration to wait before transitioning from Open to HalfOpen
    pub reset_timeout: Duration,
    /// Number of consecutive successes in HalfOpen to close the circuit
    pub success_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            reset_timeout: Duration::from_secs(30),
            success_threshold: 2,
        }
    }
}

/// Circuit breaker state
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation - requests pass through
    Closed,
    /// Fast-fail mode - reject all requests
    Open,
    /// Testing recovery - allow limited requests
    HalfOpen,
}

/// Internal state tracking for a single circuit
#[derive(Debug)]
struct CircuitData {
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
    last_state_change: Instant,
}

impl CircuitData {
    fn new() -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure_time: None,
            last_state_change: Instant::now(),
        }
    }
}

/// Circuit breaker manager for multiple challenges
pub struct CircuitBreakerManager {
    circuits: Arc<RwLock<HashMap<ChallengeId, CircuitData>>>,
    config: CircuitBreakerConfig,
}

impl CircuitBreakerManager {
    /// Create a new circuit breaker manager with default configuration
    pub fn new() -> Self {
        Self::with_config(CircuitBreakerConfig::default())
    }

    /// Create a new circuit breaker manager with custom configuration
    pub fn with_config(config: CircuitBreakerConfig) -> Self {
        Self {
            circuits: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Check if a request should be allowed for the given challenge
    ///
    /// Returns `Ok(())` if the request can proceed, or `Err(CircuitOpenError)`
    /// if the circuit is open and the request should be rejected.
    pub fn check(&self, challenge_id: ChallengeId) -> Result<(), CircuitOpenError> {
        let mut circuits = self.circuits.write();
        let circuit = circuits
            .entry(challenge_id)
            .or_insert_with(CircuitData::new);

        match circuit.state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open => {
                // Check if we should transition to HalfOpen
                if let Some(last_failure) = circuit.last_failure_time {
                    if last_failure.elapsed() >= self.config.reset_timeout {
                        info!(
                            challenge_id = %challenge_id,
                            "Circuit transitioning from Open to HalfOpen"
                        );
                        circuit.state = CircuitState::HalfOpen;
                        circuit.success_count = 0;
                        circuit.last_state_change = Instant::now();
                        return Ok(());
                    }
                }
                Err(CircuitOpenError {
                    challenge_id,
                    time_until_retry: circuit
                        .last_failure_time
                        .map(|t| self.config.reset_timeout.saturating_sub(t.elapsed())),
                })
            }
            CircuitState::HalfOpen => {
                // Allow the request through for testing
                Ok(())
            }
        }
    }

    /// Record a successful request
    pub fn record_success(&self, challenge_id: ChallengeId) {
        let mut circuits = self.circuits.write();
        let circuit = circuits
            .entry(challenge_id)
            .or_insert_with(CircuitData::new);

        match circuit.state {
            CircuitState::Closed => {
                // Reset failure count on success
                circuit.failure_count = 0;
            }
            CircuitState::HalfOpen => {
                circuit.success_count += 1;
                if circuit.success_count >= self.config.success_threshold {
                    info!(
                        challenge_id = %challenge_id,
                        successes = circuit.success_count,
                        "Circuit transitioning from HalfOpen to Closed"
                    );
                    circuit.state = CircuitState::Closed;
                    circuit.failure_count = 0;
                    circuit.success_count = 0;
                    circuit.last_state_change = Instant::now();
                } else {
                    debug!(
                        challenge_id = %challenge_id,
                        successes = circuit.success_count,
                        threshold = self.config.success_threshold,
                        "HalfOpen circuit: success recorded"
                    );
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but reset if it does
                circuit.failure_count = 0;
            }
        }
    }

    /// Record a failed request
    pub fn record_failure(&self, challenge_id: ChallengeId) {
        let mut circuits = self.circuits.write();
        let circuit = circuits
            .entry(challenge_id)
            .or_insert_with(CircuitData::new);

        circuit.last_failure_time = Some(Instant::now());

        match circuit.state {
            CircuitState::Closed => {
                circuit.failure_count += 1;
                if circuit.failure_count >= self.config.failure_threshold {
                    warn!(
                        challenge_id = %challenge_id,
                        failures = circuit.failure_count,
                        "Circuit transitioning from Closed to Open"
                    );
                    circuit.state = CircuitState::Open;
                    circuit.last_state_change = Instant::now();
                } else {
                    debug!(
                        challenge_id = %challenge_id,
                        failures = circuit.failure_count,
                        threshold = self.config.failure_threshold,
                        "Closed circuit: failure recorded"
                    );
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in HalfOpen immediately opens the circuit
                warn!(
                    challenge_id = %challenge_id,
                    "Circuit transitioning from HalfOpen to Open (failure during test)"
                );
                circuit.state = CircuitState::Open;
                circuit.success_count = 0;
                circuit.last_state_change = Instant::now();
            }
            CircuitState::Open => {
                // Already open, just update failure time
            }
        }
    }

    /// Get the current state of a circuit
    pub fn get_state(&self, challenge_id: ChallengeId) -> CircuitState {
        self.circuits
            .read()
            .get(&challenge_id)
            .map(|c| c.state.clone())
            .unwrap_or(CircuitState::Closed)
    }

    /// Reset a circuit to closed state (e.g., after manual intervention)
    pub fn reset(&self, challenge_id: ChallengeId) {
        let mut circuits = self.circuits.write();
        if let Some(circuit) = circuits.get_mut(&challenge_id) {
            info!(
                challenge_id = %challenge_id,
                previous_state = ?circuit.state,
                "Circuit manually reset to Closed"
            );
            circuit.state = CircuitState::Closed;
            circuit.failure_count = 0;
            circuit.success_count = 0;
            circuit.last_failure_time = None;
            circuit.last_state_change = Instant::now();
        }
    }

    /// Remove a circuit (e.g., when challenge is removed)
    pub fn remove(&self, challenge_id: ChallengeId) {
        self.circuits.write().remove(&challenge_id);
    }

    /// Get statistics for all circuits
    pub fn get_stats(&self) -> Vec<CircuitStats> {
        self.circuits
            .read()
            .iter()
            .map(|(id, data)| CircuitStats {
                challenge_id: *id,
                state: data.state.clone(),
                failure_count: data.failure_count,
                success_count: data.success_count,
                time_in_state: data.last_state_change.elapsed(),
            })
            .collect()
    }
}

impl Default for CircuitBreakerManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Error returned when circuit is open
#[derive(Debug, Clone)]
pub struct CircuitOpenError {
    pub challenge_id: ChallengeId,
    pub time_until_retry: Option<Duration>,
}

impl std::fmt::Display for CircuitOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Circuit open for challenge {}: ",
            self.challenge_id
        )?;
        if let Some(duration) = self.time_until_retry {
            write!(f, "retry in {:.1}s", duration.as_secs_f64())
        } else {
            write!(f, "retry time unknown")
        }
    }
}

impl std::error::Error for CircuitOpenError {}

/// Statistics for a single circuit
#[derive(Debug, Clone)]
pub struct CircuitStats {
    pub challenge_id: ChallengeId,
    pub state: CircuitState,
    pub failure_count: u32,
    pub success_count: u32,
    pub time_in_state: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    fn test_challenge_id() -> ChallengeId {
        ChallengeId::new()
    }

    #[test]
    fn test_new_circuit_is_closed() {
        let manager = CircuitBreakerManager::new();
        let id = test_challenge_id();
        assert_eq!(manager.get_state(id), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_opens_after_threshold_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            reset_timeout: Duration::from_secs(30),
            success_threshold: 2,
        };
        let manager = CircuitBreakerManager::with_config(config);
        let id = test_challenge_id();

        // First two failures - still closed
        manager.record_failure(id);
        manager.record_failure(id);
        assert_eq!(manager.get_state(id), CircuitState::Closed);
        assert!(manager.check(id).is_ok());

        // Third failure - opens circuit
        manager.record_failure(id);
        assert_eq!(manager.get_state(id), CircuitState::Open);
        assert!(manager.check(id).is_err());
    }

    #[test]
    fn test_success_resets_failure_count() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            reset_timeout: Duration::from_secs(30),
            success_threshold: 2,
        };
        let manager = CircuitBreakerManager::with_config(config);
        let id = test_challenge_id();

        manager.record_failure(id);
        manager.record_failure(id);
        manager.record_success(id); // Reset failure count
        manager.record_failure(id);
        manager.record_failure(id);

        // Should still be closed (only 2 consecutive failures)
        assert_eq!(manager.get_state(id), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_transitions_to_half_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            reset_timeout: Duration::from_millis(50),
            success_threshold: 1,
        };
        let manager = CircuitBreakerManager::with_config(config);
        let id = test_challenge_id();

        manager.record_failure(id);
        assert_eq!(manager.get_state(id), CircuitState::Open);

        // Wait for reset timeout
        sleep(Duration::from_millis(60));

        // Check should transition to HalfOpen
        assert!(manager.check(id).is_ok());
        assert_eq!(manager.get_state(id), CircuitState::HalfOpen);
    }

    #[test]
    fn test_half_open_closes_on_success() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            reset_timeout: Duration::from_millis(10),
            success_threshold: 2,
        };
        let manager = CircuitBreakerManager::with_config(config);
        let id = test_challenge_id();

        // Open the circuit
        manager.record_failure(id);
        sleep(Duration::from_millis(20));
        manager.check(id).unwrap(); // Transition to HalfOpen

        // First success
        manager.record_success(id);
        assert_eq!(manager.get_state(id), CircuitState::HalfOpen);

        // Second success - closes circuit
        manager.record_success(id);
        assert_eq!(manager.get_state(id), CircuitState::Closed);
    }

    #[test]
    fn test_half_open_opens_on_failure() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            reset_timeout: Duration::from_millis(10),
            success_threshold: 2,
        };
        let manager = CircuitBreakerManager::with_config(config);
        let id = test_challenge_id();

        // Open the circuit
        manager.record_failure(id);
        sleep(Duration::from_millis(20));
        manager.check(id).unwrap(); // Transition to HalfOpen

        // Failure in HalfOpen immediately opens
        manager.record_failure(id);
        assert_eq!(manager.get_state(id), CircuitState::Open);
    }

    #[test]
    fn test_manual_reset() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            reset_timeout: Duration::from_secs(300),
            success_threshold: 1,
        };
        let manager = CircuitBreakerManager::with_config(config);
        let id = test_challenge_id();

        manager.record_failure(id);
        assert_eq!(manager.get_state(id), CircuitState::Open);

        manager.reset(id);
        assert_eq!(manager.get_state(id), CircuitState::Closed);
        assert!(manager.check(id).is_ok());
    }

    #[test]
    fn test_remove_circuit() {
        let manager = CircuitBreakerManager::new();
        let id = test_challenge_id();

        manager.record_failure(id);
        manager.remove(id);

        // Should be back to default (Closed)
        assert_eq!(manager.get_state(id), CircuitState::Closed);
    }

    #[test]
    fn test_get_stats() {
        let manager = CircuitBreakerManager::new();
        let id1 = test_challenge_id();
        let id2 = test_challenge_id();

        manager.record_failure(id1);
        manager.record_success(id2);

        let stats = manager.get_stats();
        assert_eq!(stats.len(), 2);
    }

    #[test]
    fn test_circuit_open_error_display() {
        let err = CircuitOpenError {
            challenge_id: test_challenge_id(),
            time_until_retry: Some(Duration::from_secs(15)),
        };
        let msg = err.to_string();
        assert!(msg.contains("Circuit open"));
        assert!(msg.contains("retry in"));
    }
}
