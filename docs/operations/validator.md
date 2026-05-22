# Validator Operations

Run these commands from the repository root. This runbook is only for normal
validator Kubernetes installation and operation.

## Install Or Update

Automatic Kubernetes install:

```bash
./scripts/install-validator.sh
```

The installer performs real Kubernetes changes and prompts for the validator
hotkey mnemonic. It creates a validator image-updater CronJob that periodically
runs `kubectl rollout restart deployment/platform-validator`; with
`imagePullPolicy: Always`, this repulls updated mutable GHCR tags when the Pod
restarts. Validate the full install flow only against a disposable cluster or
namespace with disposable test hotkey material.

Stop only installer-managed validator objects:

```bash
./scripts/install-validator.sh --cleanup
```

## Runtime Commands

```bash
kubectl -n platform-validator get deployment platform-validator
kubectl -n platform-validator get pods
kubectl -n platform-validator logs -f deployment/platform-validator
kubectl -n platform-validator describe deployment platform-validator
```

## Secret Handling

The only secret requested during install is the validator hotkey mnemonic. Never
enter coldkey material. Do not store mnemonics in `.env`, shell history, support
threads, screenshots, or evidence logs.

The installer creates a Kubernetes Secret named `platform-validator-wallet` from
generated hotkey files and deletes the temporary local wallet directory when it
exits. Kubernetes Secrets are readable to cluster admins and any subject with
Secret read RBAC; use a dedicated namespace and enable encryption at rest for
production clusters.

## Registry And Wallet Defaults

```text
PLATFORM_VALIDATOR_REGISTRY_URL=https://chain.platform.network
PLATFORM_NAMESPACE=platform-validator
PLATFORM_WALLET_NAME=platform-validator
PLATFORM_WALLET_HOTKEY=validator
PLATFORM_DATABASE_URL=postgresql+asyncpg://platform:<password>@postgres.platform.svc.cluster.local/platform
PLATFORM_BROKER_ALLOWED_IMAGES=ghcr.io/platformnetwork/,registry.example.com/platform/
PLATFORM_VALIDATOR_AUTO_UPDATE_SCHEDULE=*/5 * * * *
PLATFORM_VALIDATOR_AUTO_UPDATE_IMAGE=registry.k8s.io/kubectl@sha256:99b37df34bc4f99ee322521d4c85cb98c1ceb8f70ff0618bef84eec9fe1ebc20
```

The validator pod sees the hotkey at:

```text
/var/lib/platform/wallets/platform-validator/hotkeys/validator
```

## Kubernetes Scope

The installer applies only namespaced resources needed by the validator:
Namespace, validator ServiceAccount/RBAC, updater ServiceAccount/RBAC, PVC,
ConfigMap, Secret, Deployment, and updater CronJob. Cleanup removes only the
installer-managed updater CronJob/RBAC/ServiceAccount plus the validator
Deployment, ConfigMap, Secret, Role, RoleBinding, and ServiceAccount. The PVC is
preserved intentionally so validator state is not destroyed by an update; delete
it manually only when you intentionally want to erase local validator state.

Kubernetes mode requires an external PostgreSQL `PLATFORM_DATABASE_URL` and
registry-scoped `PLATFORM_BROKER_ALLOWED_IMAGES`. SQLite URLs, wildcards, and
broad prefixes such as `platformnetwork/` fail settings validation.

## Validation

```bash
bash -n scripts/install-validator.sh
uv run pytest tests/unit/test_validator_install_docs.py
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
uv run pytest --cov=platform_network --cov-report=term-missing --cov-fail-under=80
```

The full installer is an interactive real install. Run it only when the current
Kubernetes context, namespace, and hotkey material are safe to mutate. CI
publishes Docker images to GHCR only from trusted events: PRs build with
`push: false`, while `main`, `v*.*.*` tags, and confirmed manual runs publish.
Kubernetes does not notice GHCR tag changes by itself; the installed CronJob
creates the rollout needed for the validator Pod to repull a mutable tag.

If Kubernetes or a Python tool is unavailable, record the missing tool as a
blocker instead of marking that surface as tested.
