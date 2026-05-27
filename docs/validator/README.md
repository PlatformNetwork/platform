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
./scripts/install-validator.sh --database-url postgresql+asyncpg://platform:<password>@postgres.platform.svc.cluster.local/platform
```

The script performs these actions:

1. Applies Namespace, validator ServiceAccount/RBAC, image-updater ServiceAccount/RBAC, Helm-upgrader ServiceAccount/RBAC, PVC, ConfigMap, Deployment, image auto-update CronJob, and Helm auto-upgrade CronJob without deleting healthy existing workloads.
2. Stores the required database URL in the configured database Secret and references it from the Deployment.
3. Prompts silently for the validator hotkey mnemonic.
4. Creates the `platform-validator-wallet` Kubernetes Secret from generated hotkey files.
5. Starts the validator Deployment in Kubernetes mode, schedules active image digest refreshes, and schedules suspended full Helm upgrade checks.

Useful options:

```bash
export PLATFORM_DATABASE_URL='postgresql+asyncpg://platform:<password>@postgres.platform.svc.cluster.local/platform'
./scripts/install-validator.sh --namespace platform-validator
./scripts/install-validator.sh --image ghcr.io/platformnetwork/platform:v1.2.3@sha256:<digest>
./scripts/install-validator.sh --image-update-schedule '*/1 * * * *'
./scripts/install-validator.sh --image-updater-image ghcr.io/platformnetwork/platform:latest
./scripts/install-validator.sh --auto-upgrade-schedule '*/5 * * * *'
./scripts/install-validator.sh --auto-upgrade-helm-image alpine/helm:3.15.4
./scripts/install-validator.sh --broker-allowed-images ghcr.io/platformnetwork/,registry.example.com/platform/
./scripts/install-validator.sh --registry-url https://chain.platform.network
./scripts/install-validator.sh --netuid 100
./scripts/install-validator.sh --wallet-name platform-validator --wallet-hotkey validator
./scripts/install-validator.sh --cleanup
```

Normal install performs a real cluster installation and imports a hotkey Secret. It installs `cronjob/platform-validator-image-updater`, a scoped CronJob that refreshes the validator Deployment to the latest digest for the configured image tag without downloading or applying mutable Helm chart source. It also installs `cronjob/platform-validator-helm-upgrader`, a scoped CronJob for full chart changes that is suspended by default; unsuspend it only when you intentionally trust the configured repo/ref to run `helm upgrade --install platform-validator ... --atomic --wait --cleanup-on-fail`. The Helm job sets `HELM_DRIVER=configmap`, uses `concurrencyPolicy: Forbid`, and pins live-safe non-secret references for future self-upgrades: the database URL Secret name/key, namespace, wallet Secret name, wallet name/hotkey labels, `validator.deploymentNameOverride=platform-validator`, and `persistence.existingClaim=platform-validator-state`. It references `platform-validator-wallet` and `platform-validator-state` by name instead of reading or printing wallet data, database URLs, or PVC contents. Set `PLATFORM_DATABASE_URL_SECRET_NAME` and `PLATFORM_DATABASE_URL_SECRET_KEY` before running the installer if your live database URL Secret is not `platform-validator-database-url` key `url`. Automated validation must use a disposable cluster, disposable namespace, and disposable test mnemonic supplied through a secure channel.

Before relying on self-upgrades, verify the referenced objects and keys exist without printing their values:

```bash
kubectl -n platform-validator get secret platform-validator-database-url -o jsonpath='{.data.url}' >/dev/null
kubectl -n platform-validator get secret platform-validator-wallet -o jsonpath='{.data.hotkey}' >/dev/null
kubectl -n platform-validator get secret platform-validator-wallet -o jsonpath='{.data.hotkeypub\.txt}' >/dev/null
kubectl -n platform-validator get pvc platform-validator-state
kubectl -n platform-validator get cronjob platform-validator-image-updater
kubectl -n platform-validator get cronjob platform-validator-helm-upgrader
```

If any prerequisite is missing, keep the Helm-upgrader CronJob suspended with `autoUpgrade.suspend=true` until the referenced Secret/PVC exists with the intended key or name. If the validator is already healthy, use these checks to confirm the CronJob bootstrap references instead of replacing the deployment just to recreate the CronJob.

`--cleanup` is scoped to objects created by this installer:

```text
cronjob/platform-validator-helm-upgrader
role/platform-validator-helm-upgrader
rolebinding/platform-validator-helm-upgrader
serviceaccount/platform-validator-helm-upgrader
cronjob/platform-validator-image-updater
role/platform-validator-image-updater
rolebinding/platform-validator-image-updater
serviceaccount/platform-validator-image-updater
deployment/platform-validator
configmap/platform-validator-config
role/platform-validator-runtime
rolebinding/platform-validator-runtime
serviceaccount/platform-validator
secret/platform-validator-database-url
```

It does not run broad cluster cleanup commands, does not delete unrelated
workloads, and intentionally preserves `secret/platform-validator-wallet` and
the validator state PVC. It removes the configured database URL Secret because
the installer manages that credential reference.

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
