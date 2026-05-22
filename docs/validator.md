# Validator Quick Start

This page is only for normal validator Kubernetes installation. The validator
fetches the public registry from `https://chain.platform.network/v1/registry`,
runs active challenge workloads through Kubernetes, and keeps them synchronized.

## Automatic Install

Run from the repository root:

```bash
./scripts/install-validator.sh
```

The installer asks only for the validator hotkey mnemonic. Do not enter coldkey
material. The mnemonic is read silently, converted to hotkey files in a temporary
local directory, and stored as a Kubernetes Secret.

The installer always performs a real Kubernetes installation and prompts for the
validator hotkey mnemonic. It also installs a validator image-updater CronJob
that periodically restarts the Deployment so updated mutable GHCR tags are
repulled. Use a disposable namespace and test mnemonic when validating the full
install flow.

Follow the validator:

```bash
kubectl -n platform-validator logs -f deployment/platform-validator
```

Stop only installer-managed validator objects:

```bash
./scripts/install-validator.sh --cleanup
```

## Manual Install

Create equivalent Kubernetes resources manually: namespace, service account,
namespaced runtime RBAC, state PVC, validator ConfigMap, hotkey Secret, and a
Deployment that runs:

```text
platform validator run --config config/validator.kubernetes.yaml
```

The ConfigMap must set `runtime.backend: kubernetes`,
`validator.registry_url: https://chain.platform.network`, `database.url` to an external PostgreSQL URL such as `postgresql+asyncpg://platform:<password>@postgres.platform.svc.cluster.local/platform`, `docker.broker_allowed_images` to registry-scoped prefixes such as `ghcr.io/platformnetwork/`, and `kubernetes.in_cluster: true`. SQLite URLs, wildcard prefixes, and broad prefixes such as `platformnetwork/` are rejected in Kubernetes mode.

## Safety

- The installer never needs coldkey material.
- Cleanup is scoped to this validator Deployment and its installer-managed objects.
- The default registry URL is `https://chain.platform.network`.
- The validator runs in Kubernetes mode; do not install it with local Compose.
- The hotkey Secret is readable by cluster admins and any subject with Secret read RBAC; use a dedicated namespace and enable Kubernetes Secret encryption at rest.
