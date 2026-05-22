<div align="center">

# ρlατfοrm

**Multi-challenge Bittensor subnet platform with master/validator orchestration**

**[Miner Guide](docs/miner/README.md) • [Validator Guide](docs/validator/README.md) • [Architecture](docs/architecture.md) • [Challenges](docs/challenges.md) • [Security](docs/security.md) • [Website](https://platform.network)**

[![CI](https://github.com/PlatformNetwork/platform/actions/workflows/ci.yml/badge.svg)](https://github.com/PlatformNetwork/platform/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/PlatformNetwork/platform)](https://github.com/PlatformNetwork/platform/blob/main/LICENSE)
[![Bittensor](https://img.shields.io/badge/Bittensor-subnet-black.svg)](https://bittensor.com/)

![Platform Banner](assets/banner.jpg)

![Live challenge board](assets/challenges.svg)

</div>

---

## Overview

Platform is a **multi-challenge Bittensor subnet platform**. It lets independent challenge
subnets run under one validator network, routes miner traffic to the right challenge, collects raw
challenge weights, normalizes emissions, maps miner hotkeys to Bittensor UIDs, and submits final
weights on-chain.

Each challenge lives in its own repository and owns its submissions, scoring logic, state, and
public miner experience. Platform provides the orchestration layer that makes those challenges run
together as one subnet.

## Core Principles

- One **Platform master validator** controls the central registry and orchestration.
- One repository and image per **challenge**, isolated from other challenges.
- Challenges expose a standard internal weight contract to Platform.
- Public challenge APIs are proxied through Platform without exposing internal control routes.
- Master PostgreSQL is private to the master process.
- Challenge state remains owned by each challenge.
- Validators can run all active challenge containers from the master registry.

---

## Documentation Index

- [Architecture](docs/architecture.md)
- [Miner guide](docs/miner/README.md)
- [Validator guide](docs/validator/README.md)
- [Challenges](docs/challenges.md)
- [Challenge Integration Guide](docs/challenge-integration.md)
- [Security Model](docs/security.md)
- [Validator Operations](docs/operations/validator.md)

---

## Network Architecture

```mermaid
flowchart LR
    BT[Bittensor] --> M[Master]
    M --> PG[(Postgres)]
    M --> DO[Docker]
    DO --> C1[Challenge A]
    DO --> C2[Challenge B]
    C1 --> S1[(SQLite)]
    C2 --> S2[(SQLite)]
    V[Validator] --> R[Registry]
    R --> M
    U[Miners] --> P[Proxy]
    P --> C1
    P --> C2
    M --> W[set_weights]
    W --> BT
```

---

## Weight Flow

```mermaid
sequenceDiagram
    participant E as Epoch
    participant M as Master
    participant A as Challenge A
    participant B as Challenge B
    participant G as Aggregator
    participant BT as Bittensor

    E->>M: trigger
    M->>A: collect challenge weights
    M->>B: collect challenge weights
    A-->>M: hotkey -> weight
    B-->>M: hotkey -> weight
    M->>G: normalize + emissions
    G-->>M: uid weights
    M->>BT: set_weights
```

---

## What Platform Does

Platform coordinates the full lifecycle of a multi-challenge subnet:

1. The master tracks active challenges and their emission shares.
2. Validators synchronize the challenge registry.
3. Challenge containers run isolated from the master and from each other.
4. Miners interact with the relevant challenge through Platform's public proxy.
5. Each challenge calculates raw hotkey weights from its own scoring rules.
6. Platform normalizes challenge outputs, applies configured emissions, and maps hotkeys to UIDs.
7. Final weights are submitted to Bittensor at epoch boundaries.

If a challenge fails, Platform can isolate that challenge's contribution without taking down the
entire subnet.

## Roles

### Miners

Miners choose a challenge, follow that challenge's submission rules, and monitor challenge-specific
leaderboards through Platform.

### Challenge Owners

Challenge owners maintain independent repositories, images, scoring logic, public documentation, and
weight contracts.

### Validators

Validators run Platform, synchronize the registry, launch challenge containers, collect raw weights,
and submit final normalized weights to Bittensor.

---

## Repository Layout

```text
platform/
  src/platform_network/      # CLI, APIs, orchestration, Bittensor wrappers
  alembic/                   # PostgreSQL migrations
  config/                    # YAML example configs
  docker/                    # Dockerfiles and dev compose
  docs/                      # Project, miner, validator, and challenge docs
  plan/                      # Detailed design plan
  tests/                     # Unit/runtime validation tests
```


## Deployment Policy

Platform separates local development defaults from production and Kubernetes deployment policy:

- Dev, test, and local Compose workflows may use SQLite for the master database and local or mutable challenge images while iterating.
- Production and Kubernetes deployments require an external PostgreSQL database provided through an explicit secret or URL. SQLite is rejected for production and Kubernetes control-plane state.
- Production challenge and control-plane images must use a semver tag plus a `sha256` digest, for example `ghcr.io/platformnetwork/demo:1.2.3@sha256:<64-hex-digest>`. Production rejects `latest`, untagged images, and missing digests. Platform release versioning starts at `3.0.0`; see `docs/versioning.md` for the SemVer, Git tag, and GHCR tag policy.
- Production remote GPU servers and Kubernetes targets must keep `verify_tls=true`; `verify_tls=false` is only acceptable for clearly local or test-only endpoints.
- Multi-server and Kubernetes target routing trusts only enabled, healthy, non-draining targets with remaining GPU capacity. Production agent targets must use HTTPS and `verify_tls=true`; persisted insecure targets are rejected when production policy is active.
- Kubernetes broker jobs and challenge workloads map CPU and memory to PodSpec requests and limits. Docker-only `pids_limit`, `memory_swap`, and custom Docker network modes are rejected for Kubernetes because PID and swap enforcement belongs at the cluster or admission-policy boundary.
- Docker Compose services that mount `/var/run/docker.sock` are local control-plane paths with host Docker daemon access. Treat that socket as root-equivalent host access, not as production isolation.
- Watchtower is only for the explicit local and staging Compose overlay and uses `nickfedor/watchtower:1.17.1` for Docker 29 API compatibility. Do not add Watchtower labels to challenge containers, broker-created jobs, databases, or Kubernetes manifests.

Use `deploy/helm/platform/values.production.example.yaml` as the production policy fixture and keep local examples explicitly labeled as local or development-only.

## Validation Quick Reference

Run these commands from the repository root when validating the platform locally. Some commands require Docker, Helm, kubeconform, kind, and kubectl. If a tool is missing, record the bounded blocker rather than claiming that surface was tested.

```bash
uv sync --extra dev --extra master
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
uv run pytest --cov=platform_network --cov-report=term-missing --cov-fail-under=80

docker compose -f docker/compose.yml config --quiet
docker compose -f docker/compose.dev.yml config --quiet
docker compose -f docker/compose.yml -f docker/compose.watchtower.yml config --quiet

helm lint deploy/helm/platform
helm template platform deploy/helm/platform > /tmp/platform-default.yaml
kubeconform -strict -summary /tmp/platform-default.yaml
helm template platform deploy/helm/platform -f deploy/helm/platform/values.production.example.yaml > /tmp/platform-production.yaml
kubeconform -strict -summary /tmp/platform-production.yaml

kind delete cluster --name platform-validation
kind create cluster --name platform-validation
kind get kubeconfig --name platform-validation > /tmp/platform-validation-kubeconfig
KUBECONFIG=/tmp/platform-validation-kubeconfig kubectl apply --dry-run=server -f /tmp/platform-default.yaml
KUBECONFIG=/tmp/platform-validation-kubeconfig kubectl apply --dry-run=server -f /tmp/platform-production.yaml
kind delete cluster --name platform-validation
docker compose -f docker/compose.yml -f docker/compose.watchtower.yml down --remove-orphans
```

Evidence for local validation should live in a local, gitignored evidence directory and must not contain kubeconfigs, tokens, credentialed database URLs, private registry credentials, bearer secrets, private keys, or Docker registry auth.

Current Task 12 evidence records the Python quality gates as passing without lowering the documented gates: `uv run ruff format --check .`, `uv run mypy src tests`, `uv run ruff check .`, and the full coverage command all pass. Historical Task 11 evidence recorded Ruff format and mypy blockers, but those blockers are resolved in the current validation state.

---

## License

Apache-2.0
