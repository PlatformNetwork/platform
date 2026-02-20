# Challenges

Challenges define the evaluation logic for miners. Platform treats challenges as **WASM modules** with deterministic execution, explicit resource limits, and signed metadata distributed over the validator network.

## Challenge Lifecycle

```mermaid
sequenceDiagram
    participant Owner as Sudo Owner
    participant Registry as Challenge Registry
    participant Validators as Validator Set
    participant Runtime as WASM Runtime

    Owner->>Registry: Add/Update/Remove (signed)
    Registry->>Validators: Broadcast metadata
    Validators->>Runtime: Load WASM module
    Runtime-->>Validators: Ready + policy enforcement
    Validators-->>Owner: Consensus-approved state
```

## Challenge Execution Flow

```mermaid
flowchart TD
    Miner[Miners] -->|Submit payload| P2P[(libp2p gossipsub)]
    P2P --> Validators[Validators]
    Validators --> Runtime[WASM Sandbox]
    Runtime --> Validators
    Validators -->|Scores + votes| P2P
```

## Runtime Constraints

- CPU, memory, and I/O quotas enforced per evaluation.
- Network access allowed only via explicit policy.
- Deterministic execution required for consensus reproducibility.

## Challenge Metadata

Each metadata bundle includes:

- Challenge identifier + version.
- WASM module hash and entrypoint.
- Resource policy (CPU/memory/time limits).
- Network policy (allowed domains/IPs).
- Scoring configuration and mechanism mapping.

## Challenge States

```mermaid
stateDiagram-v2
    [*] --> Draft
    Draft --> Active: Signed registration
    Active --> Deprecated: New version released
    Deprecated --> Retired: Removed via consensus
    Active --> Retired: Emergency removal
```

## References

- [Challenge Integration Guide](challenge-integration.md)
- [Security Model](security.md)
- [Architecture](architecture.md)
