# Validator/Core/P2P/WASM Audit Notes

## Scope

Reviewed: `bins/validator-node`, `crates/core`, `crates/p2p-consensus`, `crates/challenge-registry`, `crates/wasm-runtime-interface`.

## Key Findings

### Validator Node
- `bins/validator-node` wires consensus + storage. Challenge execution uses the WASM runtime path.

### Challenge Registry
- Registry entries store WASM module metadata as primary execution configuration.
- `discovery` supports local path and WASM directory scanning; P2P discovery is toggled but no concrete implementation yet.

### Core State
- `core::ChainState` includes WASM `wasm_challenge_configs`.

### P2P Consensus
- Consensus engine is PBFT-style and uses validator stake data from `ValidatorSet`. Stake is taken from heartbeats unless verified stake is set (metagraph refresh uses `set_verified_stake`).

### WASM Runtime Interface
- Runtime is strict and well-structured: `NetworkPolicy` with validation, explicit host functions, request limits, and audit log hooks.
- No apparent recursion; resource caps are enforced via wasmtime `StoreLimits` and request limits.

## Completed Cleanup

The following legacy Docker/container code has been removed:

1. **`crates/secure-container-runtime`** — Deleted. Docker container management crate.
2. **`crates/challenge-orchestrator`** — Deleted. Docker-based challenge container orchestration crate.
3. **`docker_image` field** — Removed from `ChallengeEntry` and `DiscoveredChallenge`.
4. **`DockerRegistry` discovery source** — Removed from `DiscoverySource`.
5. **Docker registry scanning** — Removed from `DiscoveryConfig`.
6. **Validator node dependency** — Removed `secure-container-runtime` dependency from `validator-node`.

## Remaining Follow-up

1. **Unify challenge configs**
   - Collapse any remaining legacy Docker configs in `core::ChainState` and `p2p-consensus::ChainState` to WASM-only representations.
2. **Consensus state challenge metadata**
   - Replace `p2p-consensus::ChallengeConfig` docker image with WASM module metadata (hash/path/entrypoint/policy) to support WASM-only evaluation.

## Suggested Next Steps

- Integrate WASM runtime execution into validator flow and consensus state.
- Align core state to store WASM metadata only, with migration of existing state.
