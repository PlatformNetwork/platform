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

Normal validators fetch the active registry, pull configured challenge images, run containers, and
retry if registry access is temporarily unavailable.

## Challenge Management

Create a new challenge repository from the template:

```bash
uv run platform challenge create demo --out ../demo
```

Register and operate a challenge:

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

## Validation Commands

Run project validators before releases:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
```

If Docker configuration changes, also validate compose output:

```bash
docker compose config
```

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
