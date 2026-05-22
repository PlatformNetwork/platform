# Validator Guide

![Platform Banner](../assets/banner.jpg)

## Master Mode

```bash
uv run platform master run --config config/master.example.yaml
uv run platform master proxy --config config/master.example.yaml
```

The master exposes:

- private admin and registry API
- public challenge proxy API
- Docker orchestration for active local challenges
- weight aggregation and Bittensor wrappers

## Normal Validator Mode

```bash
uv run platform validator run --config config/validator.example.yaml
```

A normal validator fetches active challenges with `GET https://chain.platform.network/v1/registry` and launches them locally.

## CLI

Local development may register mutable images while iterating. Production must use semver-tagged images pinned with `sha256` digests and must not use `latest`.

```bash
uv run platform challenge create demo --out ../demo
uv run platform challenge register demo ghcr.io/org/demo:latest 10
uv run platform challenge activate demo
uv run platform challenge pull demo
uv run platform challenge restart demo
uv run platform db migrate
```

## Production Policy

Dev, test, and local runs may use SQLite and local mutable images. Production and Kubernetes deployments require an external PostgreSQL secret or URL, reject SQLite, reject production `latest` or untagged images, require semver plus `sha256` digest image references, and require `verify_tls=true` for production remote GPU or Kubernetes targets.

Production Kubernetes agent targets must use HTTPS plus `verify_tls=true`. Multi-server target routing should trust only enabled, healthy, non-draining targets with available GPU capacity. Kubernetes rejects Docker-only PID and swap settings because enforceable PID or swap ceilings belong to cluster or admission policy.

Watchtower is a local and staging Compose overlay only and uses `nickfedor/watchtower:1.17.1` for Docker 29 API compatibility. Do not add Watchtower labels to challenges, broker-created jobs, databases, or Kubernetes manifests. Local Compose services that mount `/var/run/docker.sock` have root-equivalent host Docker daemon access and should not be treated as production isolation.

Broker archives are untrusted input. Docker and Kubernetes broker paths reject traversal, absolute paths, links, device members, malformed images, and unsafe mounts before runtime resources are created. Kubernetes broker cleanup should attempt to delete the Job, NetworkPolicy, and mount Secret across success and failure paths.

## Validation

The full operations runbook is in [Validator Operations](operations/validator.md). It includes the exact `uv`, Docker Compose, Helm, kubeconform, kind, kubectl server dry-run, and cleanup commands used for local validation. Current Task 12 evidence records Ruff check, Ruff format check, mypy, and full coverage passing; the earlier Task 11 Ruff format and mypy blockers are historical and resolved.
