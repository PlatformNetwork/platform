# Validator Guide

## Purpose

Platform validators operate the multi-challenge subnet. They synchronize the active challenge
registry, run challenge containers, collect raw challenge weights, normalize emissions, map hotkeys
to Bittensor UIDs, and submit final weights at epoch boundaries.

## Validator Roles

### Master Validator

The master owns:

- challenge registry and emission configuration;
- challenge lifecycle orchestration;
- private database state;
- public challenge proxy;
- raw weight collection;
- final Bittensor weight submission.

### Normal Validator

Normal validators synchronize with the registry and run active challenge containers locally. They
keep challenge services available and follow registry updates from the master.

## Master Operations

Run the private master process:

```bash
uv run platform master run --config config/master.example.yaml
```

Run the public proxy process:

```bash
uv run platform master proxy --config config/master.example.yaml
```

The master process handles registry state, challenge orchestration, and final weight logic. The
proxy process exposes public challenge traffic while blocking internal challenge routes.

## Normal Validator Operations

Run a normal validator:

```bash
uv run platform validator run --config config/validator.example.yaml
```

Normal validators fetch the active registry with `GET https://chain.platform.network/v1/registry`,
pull configured challenge images, run containers, and retry if registry access is temporarily
unavailable.

## Challenge Management

Create a new challenge repository from the template:

```bash
uv run platform challenge create demo --out ../demo
```

Register and operate a challenge locally while iterating:

```bash
uv run platform challenge register demo ghcr.io/org/demo:latest 10
uv run platform challenge activate demo
uv run platform challenge pull demo
uv run platform challenge restart demo
```

Run database migrations:

```bash
uv run platform db migrate
```

## Challenge Contract

Every challenge must provide health, version, and protected weight endpoints:

```http
GET /health
GET /version
GET /internal/v1/get_weights
```

Platform calls the protected weight endpoint with the shared challenge token and challenge slug
header. Public miner routes are proxied under the challenge slug, while internal and health routes
are blocked from public proxy access.

Example weight response:

```json
{
  "challenge_slug": "demo",
  "epoch": 1760000000,
  "weights": {
    "5Abc...": 1.0
  }
}
```

## Weight Lifecycle

1. Each active challenge computes raw hotkey weights.
2. Platform requests weights from each challenge.
3. Platform ignores failed challenge responses for that epoch.
4. Platform applies each challenge's configured emission share.
5. Platform normalizes hotkey scores.
6. Platform maps hotkeys to Bittensor UIDs.
7. Platform submits final weights on-chain.

## Configuration Areas

Validators should review:

- Bittensor endpoint and subnet UID;
- validator hotkey or secret key;
- master database URL;
- public proxy URL;
- Docker and broker settings;
- challenge image registry access;
- per-challenge shared tokens;
- emission allocations;
- logging and telemetry settings.


## Database, Image, and TLS Policy

Platform intentionally keeps local workflows usable while enforcing stricter production rules:

- Dev, test, and local validator workflows may use SQLite for master state and may register local, mutable, or `latest` challenge images during iteration.
- Production and Kubernetes deployments must use an external PostgreSQL database secret or URL. SQLite is not a production or Kubernetes database.
- Production challenge and control-plane images must include a semver tag plus a `sha256` digest, such as `ghcr.io/platformnetwork/demo:1.2.3@sha256:<64-hex-digest>`. Production rejects `latest`, untagged images, and missing digests.
- Production Docker image allowlists must be registry and namespace scoped. Broad prefixes are development-only.
- Production remote GPU servers and Kubernetes targets must use `verify_tls=true`; `verify_tls=false` is only for local or test-only targets.
- Production Kubernetes agent targets must use HTTPS plus `verify_tls=true`. Target routing should reuse persisted assignments only for enabled, healthy, non-draining targets with remaining GPU capacity.

## Validation Commands

Run project validators before releases from the repository root:

```bash
uv sync --extra dev --extra master
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
uv run pytest --cov=platform_network --cov-report=term-missing --cov-fail-under=80
```

Current Task 12 evidence records the commands above as passing without changing the gates: Ruff check, Ruff format check, mypy, and full coverage. Historical Task 11 evidence recorded Ruff format and mypy blockers, but those blockers are resolved in the current validation state. Keep the commands above unchanged so CI and local evidence use the same gates.

If Docker configuration changes, also validate Compose output:

```bash
docker compose -f docker/compose.yml config --quiet
docker compose -f docker/compose.dev.yml config --quiet
docker compose -f docker/compose.yml -f docker/compose.watchtower.yml config --quiet
```

If Kubernetes or production policy changes, validate Helm and Kubernetes manifests:

```bash
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
```

Clean up local Compose validation resources with:

```bash
docker compose -f docker/compose.yml -f docker/compose.watchtower.yml down --remove-orphans
```

## Local and Staging Watchtower Policy

The Watchtower Compose overlay is for local and staging Docker Compose deployments only. It is not part of the production Kubernetes deployment path, and production Kubernetes must use Kubernetes image rollout and rollback controls instead.

Watchtower uses the maintained `nickfedor/watchtower:1.17.1` image for Docker 29 API compatibility and is configured with `--label-enable`. Only these Platform control-plane services are opted in with `com.centurylinklabs.watchtower.enable=true`:

- `master-admin`
- `master-proxy`
- `platform-docker-broker`
- `validator`
- `gpu-agent`

Do not add Watchtower labels to challenge containers, broker-created job containers, database services, or Kubernetes manifests. Challenge and job images remain controlled by the registry, broker, and validator lifecycle rather than background image replacement.

When enabling the overlay, operators should monitor the `master-admin`, `master-proxy`, and `platform-docker-broker` health endpoints and confirm validators reconnect after an update. Keep an explicit rollback image tag available. Watchtower can replace containers, but it doesn't prove application health or perform production rollback orchestration.

Run the local or staging overlay with:

```bash
docker compose -f docker/compose.yml -f docker/compose.watchtower.yml up -d
```

## Docker and Kubernetes Runtime Boundaries

Local Compose services that mount `/var/run/docker.sock` can control the host Docker daemon. Treat that as root-equivalent host access. These socket mounts support local Docker orchestration and Watchtower checks; they are not a production isolation boundary, and broker-created jobs must not receive the socket.

Kubernetes challenge workloads reject Docker-only `pids_limit`, `memory_swap`, and custom Docker network modes. Kubernetes PID and swap ceilings must come from cluster configuration or admission policy, not from this PodSpec path.


## Broker Archive and Cleanup Security

Broker uploads are untrusted. Docker and Kubernetes broker paths reject archive traversal, absolute paths, links, device members, malformed images, and unsafe mounts before runtime resources are created. Kubernetes broker runs should attempt cleanup of the Job, NetworkPolicy, and mount Secret across success and failure paths. Evidence should show those checks without storing archive payloads or credentials.

## Operational Checklist

Before running a validator:

1. Configure secrets and never commit them.
2. Verify database connectivity.
3. Verify Docker access.
4. Pull or build challenge images.
5. Confirm challenge health and version responses.
6. Confirm protected weight calls work with the shared token.
7. Confirm hotkeys map to Bittensor UIDs.
8. Monitor epoch timing and weight submission logs.

During operation:

- keep challenge images updated with registry changes;
- watch for failing challenge containers;
- rotate tokens if exposed;
- back up master database state;
- monitor Bittensor submission failures;
- keep challenge emission shares aligned with owner intent.

## Security Checklist

- Keep master database private.
- Keep challenge shared tokens private.
- Block public access to internal challenge routes.
- Run challenge containers with isolated state and resource limits.
- Avoid logging bearer tokens, hotkey secrets, or broker tokens.
- Treat challenge code as untrusted unless it is reviewed and pinned.
