# Cortex Foundation Master Installation Guide

Foundation-only installer for Cortex Foundation master infrastructure. Do not run this for validators or third-party operators.

This guide covers the committed Kubernetes installer for the master control plane. It installs the Platform master admin API, proxy, broker, shared master ConfigMap, and config sync CronJob in the master namespace. It does not install validator workloads, chain submission jobs, or any key material.

## Default Namespace

```text
PLATFORM_NAMESPACE=platform-master
```

Use a different namespace only for Cortex Foundation managed test clusters. Do not reuse the namespace reserved for normal operator installs.

## Automatic Install

Run from the repository root:

```bash
./scripts/install-master.sh
```

The script performs these actions:

1. Prints the foundation-only warning before it changes the cluster.
2. Deletes only prior installer-managed master objects in the selected namespace.
3. Applies Namespace, ServiceAccount/RBAC, ConfigMap, admin Deployment and Service, proxy Deployment and Service, broker Deployment and Service, and `platform-master-config-sync`.
4. Runs the master admin API with `platform master run --config config/master.kubernetes.yaml`.
5. Runs the proxy and broker with the same master config.

Useful options:

```bash
./scripts/install-master.sh --namespace platform-master
./scripts/install-master.sh --image ghcr.io/platformnetwork/platform-master:v1.2.3@sha256:<digest>
./scripts/install-master.sh --config-sync-schedule '*/1 * * * *'
./scripts/install-master.sh --config-sync-image ghcr.io/platformnetwork/platform-master:v1.2.3@sha256:<digest>
./scripts/install-master.sh --config-sync-repo PlatformNetwork/platform --config-sync-ref main
./scripts/install-master.sh --database-url postgresql+asyncpg://platform:<password>@postgres.platform.svc.cluster.local/platform
./scripts/install-master.sh --netuid 0
./scripts/install-master.sh --cleanup
```

## Config Sync

The installer creates `cronjob/platform-master-config-sync`. The job uses a namespace-local ServiceAccount and runs:

```text
platform kubernetes sync-config
```

The sync hook is limited to the master ConfigMap and master Deployments created by this installer. It is a hook for the config sync engine. It is not an installer rerun path.

## Explicit Non Goals

- It does not create validator resources.
- It does not run the master weights CLI command.
- It does not create a master on-chain submission CronJob.
- It does not ask for, print, or store key material.
- It does not use external paste services as the canonical source.

## Runtime Checks

```bash
kubectl -n platform-master get deployment platform-master-admin platform-master-proxy platform-master-broker
kubectl -n platform-master get cronjob platform-master-config-sync
kubectl -n platform-master logs -f deployment/platform-master-admin
```

## Validation Commands

Before changing the installer or docs, run:

```bash
bash -n scripts/install-master.sh
uv run pytest tests/unit/test_master_install_docs.py tests/unit/test_validator_install_docs.py -q
```

Run the full installer only when the current Kubernetes context and namespace are owned by Cortex Foundation master infrastructure.
