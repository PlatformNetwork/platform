# Validator Kubernetes Installation Guide

This guide is only for normal validators. It installs a validator as Kubernetes
resources that synchronize challenge metadata from the public Platform registry
and start challenge workloads through the Kubernetes API.

The default registry endpoint is:

```text
https://chain.platform.network/v1/registry
```

## Secret Rule

The installer asks for one secret only: the validator hotkey mnemonic. Never enter
coldkey material into the installer, shell history, logs, screenshots, support
channels, or evidence files. The mnemonic is read with silent input, converted into
hotkey files in a temporary local directory, stored as a Kubernetes Secret, and the
temporary directory is deleted automatically.

## Automatic Kubernetes Install

Run from the repository root:

```bash
./scripts/install-validator.sh
```

The script performs these actions:

1. Deletes only prior installer-managed validator objects in the selected namespace.
2. Applies Namespace, validator ServiceAccount/RBAC, Helm-upgrader ServiceAccount/RBAC, PVC, ConfigMap, Deployment, and Helm auto-upgrade CronJob.
3. Prompts silently for the validator hotkey mnemonic.
4. Creates the `platform-validator-wallet` Kubernetes Secret from generated hotkey files.
5. Starts the validator Deployment in Kubernetes mode and schedules full Helm upgrade checks.

Useful options:

```bash
./scripts/install-validator.sh --namespace platform-validator
./scripts/install-validator.sh --image ghcr.io/platformnetwork/platform:v1.2.3@sha256:<digest>
./scripts/install-validator.sh --auto-upgrade-schedule '*/5 * * * *'
./scripts/install-validator.sh --auto-upgrade-helm-image alpine/helm:3.15.4
./scripts/install-validator.sh --database-url postgresql+asyncpg://platform:<password>@postgres.platform.svc.cluster.local/platform
./scripts/install-validator.sh --broker-allowed-images ghcr.io/platformnetwork/,registry.example.com/platform/
./scripts/install-validator.sh --registry-url https://chain.platform.network
./scripts/install-validator.sh --netuid 0
./scripts/install-validator.sh --wallet-name platform-validator --wallet-hotkey validator
./scripts/install-validator.sh --cleanup
```

The installer always performs a real cluster installation and always imports a
hotkey Secret. It also installs `cronjob/platform-validator-helm-upgrader`, a scoped CronJob that periodically downloads the configured GitHub chart source and runs `helm upgrade --install platform-validator ... --atomic --wait --cleanup-on-fail`. The job sets `HELM_DRIVER=configmap`, uses `concurrencyPolicy: Forbid`, and references `platform-validator-wallet` by name instead of reading or printing wallet data. Automated validation must use a disposable cluster, disposable namespace, and disposable test mnemonic supplied through a secure channel.

`--cleanup` is scoped to objects created by this installer:

```text
cronjob/platform-validator-helm-upgrader
role/platform-validator-helm-upgrader
rolebinding/platform-validator-helm-upgrader
serviceaccount/platform-validator-helm-upgrader
deployment/platform-validator
configmap/platform-validator-config
role/platform-validator-runtime
rolebinding/platform-validator-runtime
serviceaccount/platform-validator
```

It does not run broad cluster cleanup commands, does not delete unrelated
workloads, and intentionally preserves `secret/platform-validator-wallet`.

## Manual Kubernetes Installation

If you do not use the script, reproduce the same flow manually:

1. Create a namespace for the validator.
2. Create a ServiceAccount plus a namespaced Role/RoleBinding that can manage
   Secrets, Services, Pods/logs, PVCs, Deployments, StatefulSets, Jobs, HPAs, and
   NetworkPolicies in that namespace.
3. Create a ConfigMap containing `validator.yaml`. Kubernetes mode enables the production policy gate, so `database.url` or `PLATFORM_DATABASE_URL` must be an external PostgreSQL URL and `docker.broker_allowed_images` or `PLATFORM_BROKER_ALLOWED_IMAGES` must use registry-scoped prefixes, not broad Docker Hub or wildcard prefixes.

```yaml
runtime:
  backend: kubernetes
database:
  url: postgresql+asyncpg://platform:<password>@postgres.platform.svc.cluster.local/platform
validator:
  registry_url: https://chain.platform.network
docker:
  broker_allowed_images:
    - ghcr.io/platformnetwork/
    - registry.example.com/platform/
kubernetes:
  in_cluster: true
  broker_backend: kubernetes
  namespace: platform-validator
  service_account: platform-validator
network:
  wallet_name: platform-validator
  wallet_hotkey: validator
  wallet_path: /var/lib/platform/wallets
```

`PLATFORM_DATABASE_URL` is for Platform control-plane state. It is not `CHALLENGE_DATABASE_URL`, and it must not be copied into challenge manifests. In Kubernetes managed challenge mode, Platform creates a separate managed Postgres server and Secret per challenge slug, then injects that challenge's `CHALLENGE_DATABASE_URL` automatically from its own Secret.

4. Regenerate only the validator hotkey from its mnemonic on a local trusted
   machine and create a Kubernetes Secret containing the generated hotkey files.
   The Secret is readable by cluster admins and any subject with Secret read RBAC
   unless the cluster is locked down with dedicated namespaces, minimal RBAC, and
   Secret encryption at rest.
5. Create a Deployment that runs:

```text
platform validator run --config config/validator.kubernetes.yaml
```

Mount the ConfigMap at `/app/config/validator.kubernetes.yaml`, mount validator
state at `/var/lib/platform`, and mount the hotkey Secret at:

```text
/var/lib/platform/wallets/platform-validator/hotkeys
```

## Challenge database lifecycle

For each active challenge slug, Kubernetes managed mode creates isolated managed Postgres resources. Platform injects `CHALLENGE_DATABASE_URL` from the per-challenge Secret. The challenge `/data` PVC stays separate and remains available for artifacts, analyzer output, local files, and the generated SQLite fallback.

When a challenge is removed, Platform keeps the managed Postgres Secret and data claim by default. Deleting those retained resources is a manual destructive purge because it can remove database contents or the credential needed to reconnect to retained data.

## Runtime Checks

```bash
kubectl -n platform-validator get pods
kubectl -n platform-validator logs -f deployment/platform-validator
kubectl -n platform-validator describe deployment platform-validator
```

## Validation Commands

Before changing the installer or docs, run:

```bash
bash -n scripts/install-validator.sh
uv run pytest tests/unit/test_validator_install_docs.py
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
```

Run the full installer only when you intend to mutate a real Kubernetes context
and can provide the validator hotkey mnemonic interactively. GHCR image
publication is handled by CI: pull requests build images without pushing, while
trusted `main`, `v*.*.*` tag, or confirmed manual runs publish `platform` and
`platform-master` images to GHCR.
