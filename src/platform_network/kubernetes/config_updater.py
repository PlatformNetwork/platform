from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import httpx
import yaml

from platform_network.validator.image_updater import (
    _InClusterAppsApi,
    _InClusterBatchApi,
    _InClusterClient,
)

CONFIG_DIGEST_ANNOTATION = "platform.network/config-digest"
CONFIG_MAP_KEY = "master.yaml"


@dataclass(frozen=True)
class ConfigSyncSource:
    repository: str
    branch: str
    paths: tuple[str, ...]
    sync_secrets: bool = False
    allowed_kinds: tuple[str, ...] = ("ConfigMap",)
    fetcher: Callable[[ConfigSyncSource], str] | None = field(
        default=None, compare=False, repr=False
    )

    @classmethod
    def default(
        cls, fetcher: Callable[[ConfigSyncSource], str] | None = None
    ) -> ConfigSyncSource:
        return cls(
            repository="PlatformNetwork/platform",
            branch="main",
            paths=("deploy/helm/platform/values.yaml",),
            sync_secrets=False,
            allowed_kinds=("ConfigMap",),
            fetcher=fetcher,
        )


@dataclass(frozen=True)
class RolloutTarget:
    kind: str
    name: str


@dataclass(frozen=True)
class ConfigSyncResult:
    changed: bool
    reason: str
    current_digest: str | None = None
    new_digest: str | None = None


class ConfigSyncUpdater:
    def __init__(
        self,
        core_api: Any,
        apps_api: Any,
        source: ConfigSyncSource,
        batch_api: Any | None = None,
    ) -> None:
        self.core_api = core_api
        self.apps_api = apps_api
        self.source = source
        self.batch_api = batch_api

    def sync_once(
        self,
        *,
        namespace: str,
        config_map: str,
        rollout_targets: Sequence[RolloutTarget],
    ) -> ConfigSyncResult:
        self._validate_rollout_targets(rollout_targets)
        current = self.core_api.read_namespaced_config_map(config_map, namespace)
        current_digest = _annotation(getattr(current, "metadata", None))
        try:
            config_text = self._fetch_config()
            self._validate_config(config_text)
        except SecretSyncRejected:
            return ConfigSyncResult(
                changed=False,
                reason="secret_sync_rejected",
                current_digest=current_digest,
            )
        except Exception:
            return ConfigSyncResult(
                changed=False,
                reason="invalid_config",
                current_digest=current_digest,
            )
        config_payload = _runtime_config_payload(
            config_text, config_map=config_map, namespace=namespace
        )
        new_digest = _digest(config_payload)
        rollouts_current = self._rollouts_current(
            namespace, rollout_targets, new_digest
        )
        if current_digest == new_digest and rollouts_current:
            return ConfigSyncResult(
                changed=False,
                reason="already_current",
                current_digest=current_digest,
                new_digest=new_digest,
            )
        if current_digest != new_digest:
            self.core_api.patch_namespaced_config_map(
                config_map,
                namespace,
                {
                    "metadata": {"annotations": {CONFIG_DIGEST_ANNOTATION: new_digest}},
                    "data": {CONFIG_MAP_KEY: config_payload},
                },
            )
        for target in rollout_targets:
            self._patch_rollout(namespace, target, new_digest)
        return ConfigSyncResult(
            changed=True,
            reason="updated" if current_digest != new_digest else "rollout_retried",
            current_digest=current_digest,
            new_digest=new_digest,
        )

    def _fetch_config(self) -> str:
        if self.source.fetcher is not None:
            return self.source.fetcher(self.source)
        return fetch_github_config(self.source)

    def _validate_config(self, config_text: str) -> None:
        validate_config_text(config_text, allowed_kinds=self.source.allowed_kinds)

    def _validate_rollout_targets(
        self, rollout_targets: Sequence[RolloutTarget]
    ) -> None:
        for target in rollout_targets:
            kind = _rollout_kind(target.kind)
            if kind not in {"deployment", "cronjob"}:
                raise ValueError(f"unsupported rollout kind: {target.kind}")
            if kind == "cronjob" and self.batch_api is None:
                raise ValueError("batch API is required for cronjob rollout patches")

    def _patch_rollout(
        self, namespace: str, target: RolloutTarget, digest: str
    ) -> None:
        kind = _rollout_kind(target.kind)
        if kind == "deployment":
            self.apps_api.patch_namespaced_deployment(
                target.name,
                namespace,
                {
                    "spec": {
                        "template": {
                            "metadata": {
                                "annotations": {CONFIG_DIGEST_ANNOTATION: digest}
                            }
                        }
                    }
                },
            )
            return
        if self.batch_api is None:
            raise ValueError("batch API is required for cronjob rollout patches")
        self.batch_api.patch_namespaced_cron_job(
            target.name,
            namespace,
            {
                "spec": {
                    "jobTemplate": {
                        "spec": {
                            "template": {
                                "metadata": {
                                    "annotations": {CONFIG_DIGEST_ANNOTATION: digest}
                                }
                            }
                        }
                    }
                }
            },
        )

    def _rollouts_current(
        self, namespace: str, rollout_targets: Sequence[RolloutTarget], digest: str
    ) -> bool:
        for target in rollout_targets:
            if self._read_rollout_digest(namespace, target) != digest:
                return False
        return True

    def _read_rollout_digest(self, namespace: str, target: RolloutTarget) -> str | None:
        kind = _rollout_kind(target.kind)
        if kind == "deployment":
            reader = getattr(self.apps_api, "read_namespaced_deployment", None)
            if reader is None:
                return None
            workload = reader(target.name, namespace)
            template = getattr(getattr(workload, "spec", None), "template", None)
            return _annotation(getattr(template, "metadata", None))
        if self.batch_api is None:
            raise ValueError("batch API is required for cronjob rollout patches")
        reader = getattr(self.batch_api, "read_namespaced_cron_job", None)
        if reader is None:
            return None
        workload = reader(target.name, namespace)
        job_template = getattr(getattr(workload, "spec", None), "job_template", None)
        pod_template = getattr(getattr(job_template, "spec", None), "template", None)
        return _annotation(getattr(pod_template, "metadata", None))


class SecretSyncRejected(ValueError):
    pass


def validate_config_text(config_text: str, *, allowed_kinds: Sequence[str]) -> None:
    """Validate fetched config text (pure; shared with the Swarm supervisor port).

    Raises :class:`SecretSyncRejected` for any Secret manifest and
    :class:`ValueError` for kinds outside ``allowed_kinds`` or unparseable
    YAML — byte-identical behavior to the original inline validation.
    """
    documents = list(yaml.safe_load_all(config_text))
    for document in documents:
        if not isinstance(document, dict):
            continue
        kind = document.get("kind")
        if not kind:
            continue
        if str(kind).lower() == "secret":
            raise SecretSyncRejected("refusing to sync plaintext Secret manifest")
        if kind not in allowed_kinds:
            raise ValueError(f"unsupported config kind: {kind}")


def fetch_github_config(source: ConfigSyncSource) -> str:
    texts: list[str] = []
    with httpx.Client(timeout=30.0) as client:
        for path in source.paths:
            url = _github_raw_url(source.repository, source.branch, path)
            response = client.get(url)
            response.raise_for_status()
            texts.append(response.text)
    return "\n---\n".join(texts)


def create_incluster_config_sync_updater(source: ConfigSyncSource) -> ConfigSyncUpdater:
    return ConfigSyncUpdater(
        _InClusterCoreApi(),
        _InClusterAppsApi(),
        source,
        _InClusterBatchApi(),
    )


class _InClusterCoreApi:
    def __init__(self) -> None:
        self.client = _InClusterClient()

    def read_namespaced_config_map(self, name: str, namespace: str) -> Any:
        return self.client.get(f"/api/v1/namespaces/{namespace}/configmaps/{name}")

    def patch_namespaced_config_map(
        self, name: str, namespace: str, body: dict[str, Any]
    ) -> None:
        self.client.patch(f"/api/v1/namespaces/{namespace}/configmaps/{name}", body)


def _github_raw_url(repository: str, branch: str, path: str) -> str:
    repo = repository.strip("/")
    encoded_branch = quote(branch, safe="")
    encoded_path = "/".join(quote(part, safe="") for part in path.strip("/").split("/"))
    return f"https://raw.githubusercontent.com/{repo}/{encoded_branch}/{encoded_path}"


def _digest(config_text: str) -> str:
    return f"sha256:{hashlib.sha256(config_text.encode('utf-8')).hexdigest()}"


def _annotation(metadata: Any) -> str | None:
    annotations = getattr(metadata, "annotations", None) or {}
    value = annotations.get(CONFIG_DIGEST_ANNOTATION)
    return value if isinstance(value, str) else None


def _rollout_kind(kind: str) -> str:
    return kind.replace("_", "").replace("-", "").lower()


def _runtime_config_payload(
    config_text: str, *, config_map: str, namespace: str
) -> str:
    documents = [document for document in yaml.safe_load_all(config_text)]
    for document in documents:
        if not isinstance(document, dict):
            continue
        if document.get("kind") != "ConfigMap":
            continue
        data = document.get("data")
        if isinstance(data, dict) and isinstance(data.get(CONFIG_MAP_KEY), str):
            return data[CONFIG_MAP_KEY]
    if (
        len(documents) == 1
        and isinstance(documents[0], dict)
        and _looks_like_helm_values(documents[0])
    ):
        return _helm_values_to_runtime_config(
            documents[0], config_map=config_map, namespace=namespace
        )
    return config_text


def _looks_like_helm_values(values: dict[str, Any]) -> bool:
    return any(
        key in values
        for key in (
            "image",
            "images",
            "masterAdmin",
            "masterProxy",
            "kubernetesTargets",
            "configSync",
        )
    )


def _helm_values_to_runtime_config(
    values: dict[str, Any], *, config_map: str, namespace: str
) -> str:
    release_name = config_map.removesuffix("-config")
    environment = _string_value(values, "environment", "development")
    runtime = _mapping_value(values, "runtime")
    network = _mapping_value(values, "network")
    validator = _mapping_value(values, "validator")
    master = _mapping_value(values, "masterAdmin")
    proxy = _mapping_value(values, "masterProxy")
    broker = _mapping_value(values, "broker")
    docker = _mapping_value(values, "docker")
    kubernetes = _mapping_value(values, "kubernetes")
    kubernetes_targets = _mapping_value(values, "kubernetesTargets")
    remote_targets = kubernetes_targets.get("targets", [])
    weights_url = validator.get("weightsUrl")

    runtime_config = {
        "environment": environment,
        "runtime": {"backend": _string_value(runtime, "backend", "kubernetes")},
        "database": {"url": "${PLATFORM_DATABASE__URL}"},
        "network": {
            "netuid": network.get("netuid", 100),
            "chain_endpoint": network.get("chainEndpoint", ""),
            "wallet_name": network.get("walletName", "default"),
            "wallet_hotkey": network.get("walletHotkey", "default"),
            "wallet_path": network.get("walletPath", "/var/lib/platform/wallets"),
        },
        "validator": {
            "registry_url": validator.get(
                "registryUrl", "https://chain.platform.network"
            ),
            "registry_retry_seconds": validator.get("registryRetrySeconds", 15),
            "weights_url": weights_url,
            "weights_interval_seconds": validator.get("weightsIntervalSeconds", 360),
            "weights_timeout_seconds": validator.get("weightsTimeoutSeconds", 15.0),
            "weights_retries": validator.get("weightsRetries", 3),
            "weights_freshness_seconds": validator.get("weightsFreshnessSeconds", 720),
        },
        "master": {
            "registry_url": f"http://{release_name}-admin:{master.get('port', 8000)}",
            "admin_host": "0.0.0.0",
            "admin_port": master.get("port", 8000),
            "proxy_host": "0.0.0.0",
            "proxy_port": proxy.get("port", 8080),
        },
        "docker": {
            "broker_host": "0.0.0.0",
            "broker_port": broker.get("port", 8082),
            "broker_url": broker.get("publicUrl")
            or f"http://{release_name}-broker:{broker.get('port', 8082)}",
            "broker_allowed_images": docker.get(
                "brokerAllowedImages", ["ghcr.io/platformnetwork/"]
            ),
        },
        "kubernetes": {
            "namespace": namespace,
            "in_cluster": True,
            "target_state_file": "/var/lib/platform/kubernetes_targets.json",
            "service_account": _helm_service_account(
                values, kubernetes, release_name=release_name, namespace=namespace
            ),
            "challenge_mode": kubernetes.get("challengeMode", "statefulset"),
            "broker_backend": kubernetes.get("brokerBackend", "kubernetes"),
            "storage_class": kubernetes.get("storageClass", ""),
            "storage_size": kubernetes.get("storageSize", "10Gi"),
            "gpu_resource_name": kubernetes.get("gpuResourceName", "nvidia.com/gpu"),
            "runtime_class_name": kubernetes.get("runtimeClassName", ""),
            "image_pull_secrets": _mapping_value(values, "image").get(
                "pullSecrets", []
            ),
            "node_selector": kubernetes.get("nodeSelector", {}),
            "tolerations": kubernetes.get("tolerations", []),
        },
        "kubernetes_targets": remote_targets
        if kubernetes_targets.get("enabled")
        else [],
    }
    return yaml.safe_dump(runtime_config, sort_keys=False)


def _mapping_value(values: dict[str, Any], key: str) -> dict[str, Any]:
    value = values.get(key)
    return value if isinstance(value, dict) else {}


def _helm_service_account(
    values: dict[str, Any],
    kubernetes: dict[str, Any],
    *,
    release_name: str,
    namespace: str,
) -> Any:
    validator = _mapping_value(values, "validator")
    if namespace == validator.get("namespace") or release_name.endswith("-validator"):
        return release_name
    master = _mapping_value(values, "master")
    if master.get("enabled") is False:
        return release_name
    return kubernetes.get("serviceAccount", "platform-master")


def _string_value(values: dict[str, Any], key: str, default: str) -> str:
    value = values.get(key)
    return value if isinstance(value, str) else default
