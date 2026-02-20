# Architecture

Platform is a **WASM-only, P2P validator network** for deterministic challenge evaluation on Bittensor. Validators exchange submissions, evaluations, and consensus votes directly over libp2p, then submit finalized weight matrices to the chain.

## Core Components

- **Validator Node (`validator-node`)**: P2P networking, consensus, evaluation, and weight submission.
- **Challenge Registry**: signed metadata for active challenges (WASM modules + runtime policies).
- **WASM Runtime Interface**: sandboxed execution with resource caps and audited host functions.
- **P2P Consensus Engine**: PBFT-style voting with stake-weighted validator set.
- **Distributed Storage (DHT)**: shared submissions, checkpoints, and consensus state.

## System Context

```mermaid
flowchart LR
    Owner[Sudo Owner] -->|Signed challenge updates| Mesh[(libp2p Mesh)]
    Mesh --> DHT[(DHT: submissions + checkpoints)]
    Mesh --> V1[Validator 1]
    Mesh --> V2[Validator 2]
    Mesh --> VN[Validator N]
    V1 -->|Evaluations + votes| Mesh
    V2 -->|Evaluations + votes| Mesh
    VN -->|Evaluations + votes| Mesh
    V1 -->|Final weights| BT[Bittensor Chain]
    V2 -->|Final weights| BT
    VN -->|Final weights| BT
```

## Consensus Flow (PBFT-style)

```mermaid
sequenceDiagram
    participant L as Leader
    participant V1 as Validator 1
    participant V2 as Validator 2
    participant Vn as Validator N

    L->>V1: Proposal(action, height)
    L->>V2: Proposal(action, height)
    L->>Vn: Proposal(action, height)
    V1-->>L: Vote(approve/reject)
    V2-->>L: Vote(approve/reject)
    Vn-->>L: Vote(approve/reject)
    L-->>V1: Commit(>=2f+1 approvals)
    L-->>V2: Commit(>=2f+1 approvals)
    L-->>Vn: Commit(>=2f+1 approvals)
```

## Data Flow

```mermaid
flowchart TD
    Miner[Miners] -->|Submit payload| P2P[(libp2p gossipsub)]
    P2P --> Validators[Validator Nodes]
    Validators --> Runtime[WASM Sandbox]
    Runtime --> Validators
    Validators -->|Aggregate scores + consensus| DHT[(DHT + consensus state)]
    Validators -->|Stake-weighted weights| Bittensor[Bittensor Chain]
```

## Runtime Policy Boundary

```mermaid
flowchart LR
    Validator[Validator Node] --> Runtime[WASM Runtime]
    Runtime --> Policy[Runtime Policy]
    Runtime --> HostFns[Whitelisted Host Functions]
    Runtime --> Audit[Audit Logs]
    Policy --> Runtime
    HostFns --> Runtime
    Runtime -->|Deterministic outputs| Validator
```

## Operational Boundaries

- **WASM-only**: challenge execution runs in WASM.
- **Consensus-driven changes**: challenge lifecycle events require PBFT approvals.

## Storage Model

- **DHT entries**: submissions, evaluation results, consensus checkpoints.
- **Local persistence**: validator state and audit logs under `data/`.

## Related Documentation

- [Security Model](security.md)
- [Challenges](challenges.md)
- [Challenge Integration Guide](challenge-integration.md)
- [Validator Operations](operations/validator.md)
