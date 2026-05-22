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
2. Applies Namespace, validator ServiceAccount/RBAC, updater ServiceAccount/RBAC, PVC, ConfigMap, Deployment, and updater CronJob.
3. Prompts silently for the validator hotkey mnemonic.
4. Creates the `platform-validator-wallet` Kubernetes Secret from generated hotkey files.
5. Starts the validator Deployment in Kubernetes mode and schedules updater rollouts.

Useful options:

```bash
./scripts/install-validator.sh --namespace platform-validator
./scripts/install-validator.sh --image ghcr.io/platformnetwork/platform:v1.2.3@sha256:<digest>
./scripts/install-validator.sh --auto-update-schedule '*/5 * * * *'
./scripts/install-validator.sh --database-url postgresql+asyncpg://platform:<password>@postgres.platform.svc.cluster.local/platform
./scripts/install-validator.sh --broker-allowed-images ghcr.io/platformnetwork/,registry.example.com/platform/
./scripts/install-validator.sh --registry-url https://chain.platform.network
./scripts/install-validator.sh --netuid 0
./scripts/install-validator.sh --wallet-name platform-validator --wallet-hotkey validator
./scripts/install-validator.sh --cleanup
```

The installer always performs a real cluster installation and always imports a
hotkey Secret. It also installs a scoped CronJob that periodically restarts the
validator Deployment so mutable GHCR tags such as `latest` are repulled by
Kubernetes. Automated validation must use a disposable cluster, disposable
namespace, and disposable test mnemonic supplied through a secure channel.

`--cleanup` is scoped to objects created by this installer:

```text
cronjob/platform-validator-image-updater
role/platform-validator-image-updater
rolebinding/platform-validator-image-updater
serviceaccount/platform-validator-image-updater
deployment/platform-validator
configmap/platform-validator-config
secret/platform-validator-wallet
role/platform-validator-runtime
rolebinding/platform-validator-runtime
serviceaccount/platform-validator
```

It does not run broad cluster cleanup commands and it does not delete unrelated
workloads.

## Manual Kubernetes Installation

If you do not use the script, reproduce the same flow manually:

1. Create a namespace for the validator.
2. Create a ServiceAccount plus a namespaced Role/RoleBinding that can manage
   Secrets, Services, Pods/logs, PVCs, Deployments, StatefulSets, Jobs, HPAs, and
   NetworkPolicies in that namespace.
3. Create a ConfigMap containing `validator.yaml`. Kubernetes mode enables the production policy gate, so `database.url` must be an external PostgreSQL URL and `docker.broker_allowed_images` must use registry-scoped prefixes, not broad Docker Hub or wildcard prefixes.

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
