<div align="center">

# ρlατfοrm

**Distributed validator network for decentralized AI evaluation on Bittensor**

[![CI](https://github.com/PlatformNetwork/platform/actions/workflows/ci.yml/badge.svg)](https://github.com/PlatformNetwork/platform/actions/workflows/ci.yml)
[![Coverage](https://platformnetwork.github.io/platform/badges/coverage.svg)](https://github.com/PlatformNetwork/platform/actions)
[![License](https://img.shields.io/github/license/PlatformNetwork/platform)](https://github.com/PlatformNetwork/platform/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/PlatformNetwork/platform)](https://github.com/PlatformNetwork/platform/stargazers)
[![Rust](https://img.shields.io/badge/rust-1.90+-orange.svg)](https://www.rust-lang.org/)

![Platform Banner](assets/banner.jpg)

![Alt](https://repobeats.axiom.co/api/embed/4b44b7f7c97e0591af537309baea88689aefe810.svg "Repobeats analytics image")

</div>

---

## Overview

Platform is a **WASM-first, peer-to-peer validator network** for deterministic evaluation of miner submissions on Bittensor. Validators execute challenge logic in a hardened WASM runtime, reach stake-weighted consensus over libp2p, and submit finalized weights to the chain. **Docker is reserved for local and CI test harnesses only.**

**Core principles**
- Decentralized libp2p mesh (gossipsub + DHT) with no centralized relays.
- Stake-weighted PBFT-style consensus for challenge state and weight aggregation.
- Deterministic WASM execution with strict runtime policy and auditability.
- Explicit separation of production runtime (WASM) and test-only containers (Docker).

---

## Documentation Index

- [Architecture](docs/architecture.md)
- [Security Model](docs/security.md)
- [Challenges](docs/challenges.md)
- [Challenge Integration Guide](docs/challenge-integration.md)
- [Validator Guide](docs/validator.md)
- [Validator Operations](docs/operations/validator.md)

---

## Network Architecture

```mermaid
flowchart LR
    Owner[Sudo Owner] -->|Signed challenge actions| Mesh[(libp2p Mesh)]
    Mesh --> DHT[(DHT: submissions + consensus state)]
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

---

## Consensus & Weight Submission

```mermaid
sequenceDiagram
    participant L as Leader
    participant V1 as Validator 1
    participant V2 as Validator 2
    participant Vn as Validator N
    participant BT as Bittensor

    L->>V1: Proposal(action, height)
    L->>V2: Proposal(action, height)
    L->>Vn: Proposal(action, height)
    V1-->>L: Vote(approve/reject)
    V2-->>L: Vote(approve/reject)
    Vn-->>L: Vote(approve/reject)
    L-->>V1: Commit(>=2f+1 approvals)
    L-->>V2: Commit(>=2f+1 approvals)
    L-->>Vn: Commit(>=2f+1 approvals)
    V1->>BT: Submit weights
    V2->>BT: Submit weights
    Vn->>BT: Submit weights
```

---

## Runtime Policy (WASM-First)

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

---

## Quick Start (Validator)

```bash
git clone https://github.com/PlatformNetwork/platform.git
cd platform
cp .env.example .env
# Edit .env: add your VALIDATOR_SECRET_KEY (BIP39 mnemonic)
mkdir -p data
cargo build --release --bin validator-node
./target/release/validator-node --data-dir ./data --secret-key "${VALIDATOR_SECRET_KEY}"
```

See [Validator Operations](docs/operations/validator.md) for hardware, configuration, and monitoring.

---

## Docker Policy

- **Production**: WASM runtime only.
- **Testing**: Docker-backed harnesses only (e.g., `./scripts/test-comprehensive.sh`).

---

## License

MIT
