# Validator Operations

Run these commands from the repository root. This runbook is only for normal
validator Kubernetes installation and operation.

## Install Or Update

Automatic Kubernetes install:

```bash
./scripts/install-validator.sh
```

The installer performs real Kubernetes changes and prompts for the validator
hotkey mnemonic. It creates `platform-validator-helm-upgrader`, a CronJob that periodically downloads the configured GitHub chart source and runs a full `helm upgrade --install platform-validator` with `--atomic`, `--wait`, and `--cleanup-on-fail`. It uses `HELM_DRIVER=configmap`, `concurrencyPolicy: Forbid`, and references the validator wallet Secret by name without printing its contents. Validate the full install flow only against a disposable cluster or
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
PLATFORM_AUTO_UPGRADE_SCHEDULE=*/5 * * * *
PLATFORM_AUTO_UPGRADE_HELM_IMAGE=alpine/helm:3.15.4
PLATFORM_AUTO_UPGRADE_REPO=PlatformNetwork/platform
PLATFORM_AUTO_UPGRADE_REF=main
```

The auto-upgrade image must contain the `helm` CLI and basic archive download tools. The default is `alpine/helm:3.15.4`.

The validator pod sees the hotkey at:

```text
/var/lib/platform/wallets/platform-validator/hotkeys/validator
```

## Kubernetes Scope

The installer applies only namespaced resources needed by the validator:
Namespace, validator ServiceAccount/RBAC, Helm-upgrader ServiceAccount/RBAC, PVC,
ConfigMap, Secret, Deployment, and Helm-upgrader CronJob. Cleanup removes only the
installer-managed Helm-upgrader CronJob/RBAC/ServiceAccount plus the validator
Deployment, ConfigMap, Role, RoleBinding, and ServiceAccount. The PVC and wallet Secret are
preserved intentionally so validator state and key material are not destroyed by an update; delete
them manually only when you intentionally want to erase local validator state and credentials.

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
Kubernetes does not notice GitHub or chart changes by itself; the installed CronJob
runs a full Helm upgrade from the configured repo/ref and lets Helm reconcile the namespace.

If Kubernetes or a Python tool is unavailable, record the missing tool as a
blocker instead of marking that surface as tested.
