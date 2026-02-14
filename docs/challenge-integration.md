# Challenge Integration Guide

This guide explains how to integrate challenge crates with the Platform validator network.

## Overview

Platform uses a modular challenge architecture where each challenge:
- Runs as a separate Docker container
- Communicates via HTTP/WebSocket with validators
- Has its own state persistence
- Supports hot-reload without losing evaluation progress

Challenge outputs feed directly into validator consensus. The validator network is fully peer-to-peer: challenge scores and derived weights are exchanged only via libp2p, with no centralized relays.

---

## P2P-Only Consensus Inputs

Validators evaluate challenges locally and publish weight commitments over the P2P mesh. Each validator’s voting power is proportional to its Bittensor stake, so higher-stake validators have higher influence in the aggregated weights.

1. **Stake-weighted validator set**: Active validators are derived from the metagraph, with voting power proportional to stake.
2. **Commit phase**: Validators broadcast commitments to their challenge weight vectors over libp2p.
3. **Reveal phase**: Validators reveal the weight vectors that match their commitments.
4. **Epoch boundary aggregation**: At each epoch boundary, weights are aggregated with stake weighting to produce the canonical weight matrix.
5. **Consensus finalization**: Validators finalize the epoch by agreeing on the aggregated weights and resulting state hash via P2P.

These aggregated weights are submitted to Bittensor as the subnet’s consensus output.

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                    Platform Validator                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Challenge  │  │  Challenge  │  │    State    │         │
│  │  Registry   │  │ Orchestrator│  │   Manager   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
├─────────────────────────────────────────────────────────────┤
│                   Checkpoint System                          │
│     (periodic saves, graceful shutdown, crash recovery)     │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
    ┌─────────────┐   ┌─────────────┐  ┌─────────────┐
    │ Challenge A │   │ Challenge B │  │ Challenge N │
    │  (Docker)   │   │  (Docker)   │  │  (Docker)   │
    └─────────────┘   └─────────────┘  └─────────────┘
```

## Testing With Docker

Challenge containers are exercised by the validator test harness. Use `./scripts/test-comprehensive.sh` to run Docker-backed integration tests; it will call `scripts/install-docker.sh` if Docker or Compose are missing (unless `PLATFORM_TEST_DOCKER_MODE=skip`).

---

## Creating a Challenge Crate

### 1. Project Structure

Your challenge crate should follow this structure:

```
my-challenge/
├── Cargo.toml
├── src/
│   ├── lib.rs           # Challenge implementation
│   ├── evaluation.rs    # Evaluation logic
│   └── scoring.rs       # Scoring algorithm
├── Dockerfile           # Container build
└── README.md           # Documentation
```

### 2. Dependencies

Add Platform SDK to your `Cargo.toml`:

```toml
[dependencies]
platform-challenge-sdk = { git = "https://github.com/PlatformNetwork/platform" }
```

### 3. Implement the Challenge Trait

```rust
use platform_challenge_sdk::prelude::*;

pub struct MyChallenge {
    // Your challenge state
}

#[async_trait]
impl ServerChallenge for MyChallenge {
    fn challenge_id(&self) -> &str {
        "my-challenge"
    }

    fn name(&self) -> &str {
        "My Challenge"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    async fn evaluate(
        &self,
        req: EvaluationRequest,
    ) -> Result<EvaluationResponse, ChallengeError> {
        // Your evaluation logic
        let score = self.evaluate_submission(&req.data)?;
        
        Ok(EvaluationResponse::success(
            &req.request_id,
            score,
            json!({"details": "evaluation complete"}),
        ))
    }
}
```

### 4. Docker Container

Create a `Dockerfile`:

```dockerfile
FROM rust:1.90 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/my-challenge /usr/local/bin/
EXPOSE 8080
CMD ["my-challenge"]
```

## State Persistence

### Checkpoint Integration

Challenges automatically benefit from Platform's checkpoint system:

1. **Periodic Checkpoints**: Every 5 minutes
2. **Shutdown Checkpoints**: On graceful shutdown
3. **Crash Recovery**: On restart, state is restored

### Custom State

To persist challenge-specific state:

```rust
use platform_challenge_sdk::database::Database;

impl MyChallenge {
    pub fn save_state(&self, db: &Database) -> Result<()> {
        db.set("my_state_key", &self.state)?;
        Ok(())
    }

    pub fn load_state(&mut self, db: &Database) -> Result<()> {
        if let Some(state) = db.get("my_state_key")? {
            self.state = state;
        }
        Ok(())
    }
}
```

## Hot-Reload Support

Platform supports updating challenges without losing evaluation progress:

### 1. Graceful Shutdown Signal

When receiving SIGTERM, your challenge should:
1. Stop accepting new evaluations
2. Complete in-progress evaluations
3. Persist any local state
4. Exit cleanly

```rust
tokio::select! {
    _ = tokio::signal::ctrl_c() => {
        info!("Shutting down gracefully...");
        self.save_state(&db)?;
    }
}
```

### 2. Version Compatibility

Ensure backward compatibility between versions:

```rust
#[derive(Serialize, Deserialize)]
struct MyState {
    #[serde(default)]
    version: u32,
    // ... fields
}

impl MyState {
    fn migrate(&mut self) {
        if self.version < 2 {
            // Migration logic
            self.version = 2;
        }
    }
}
```

## Health Checks

Implement health check endpoints:

```rust
// GET /health - Returns 200 if healthy
// GET /ready - Returns 200 if ready for traffic
// GET /live - Returns 200 if process is alive
```

## Registration

### Local Development

Add to workspace `Cargo.toml`:

```toml
[workspace]
members = [
    # ... existing members
    "challenges/my-challenge",
]
```

### Production Deployment

1. Build and push Docker image
2. Register via sudo action (network operator only)
3. Validators automatically pull the image

## Best Practices

1. **Deterministic Evaluation**: Same input should produce same output
2. **Timeout Handling**: Set reasonable timeouts
3. **Resource Limits**: Respect CPU/memory constraints
4. **Logging**: Use structured logging with tracing
5. **Error Handling**: Return meaningful error messages
6. **Testing**: Include comprehensive unit tests

## Example Challenges

- [term-challenge](https://github.com/PlatformNetwork/term-challenge) - Terminal benchmark

## Troubleshooting

### Common Issues

1. **Challenge not starting**: Check Docker logs
2. **Evaluation timeout**: Increase timeout or optimize
3. **State loss after update**: Verify checkpoint creation
4. **Version mismatch**: Check compatibility constraints

### Debugging

Enable debug logging:
```bash
RUST_LOG=debug my-challenge
```

## API Reference

See [platform-challenge-sdk documentation](../crates/challenge-sdk/README.md).