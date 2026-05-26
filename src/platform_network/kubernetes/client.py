from __future__ import annotations

import ast
import json
import time
from pathlib import Path
from typing import Any


class KubernetesDependencyError(RuntimeError):
    pass


class KubernetesClient:
    """Small dynamic Kubernetes client wrapper used by runtime backends."""

    def __init__(
        self,
        *,
        namespace: str,
        kubeconfig: str | None = None,
        in_cluster: bool = True,
        field_manager: str = "platform-network",
    ) -> None:
        self.namespace = namespace
        self.field_manager = field_manager
        try:
            from kubernetes import client, config, dynamic
        except ImportError as exc:  # pragma: no cover - environment-specific
            raise KubernetesDependencyError(
                "Install the Kubernetes extra to use runtime.backend=kubernetes."
            ) from exc
        if in_cluster:
            config.load_incluster_config()
            configuration = client.Configuration.get_default_copy()
            token = Path(
                "/var/run/secrets/kubernetes.io/serviceaccount/token"
            ).read_text(encoding="utf-8")
            configuration.api_key["BearerToken"] = token.strip()
            configuration.api_key_prefix["BearerToken"] = "Bearer"
            api_client = client.ApiClient(configuration)
        else:
            config.load_kube_config(config_file=kubeconfig)
            api_client = client.ApiClient()
        self._dynamic = dynamic.DynamicClient(api_client)
        self._core = client.CoreV1Api(api_client)
        self._batch = client.BatchV1Api(api_client)

    def apply(self, resource: dict[str, Any]) -> dict[str, Any]:
        api = self._api_for(resource)
        metadata = resource.get("metadata", {})
        name = metadata["name"]
        namespace = metadata.get("namespace", self.namespace)
        result = api.patch(
            body=resource,
            namespace=namespace,
            name=name,
            content_type="application/apply-patch+yaml",
            field_manager=self.field_manager,
            force=True,
        )
        return result.to_dict() if hasattr(result, "to_dict") else dict(result)

    def delete(self, resource: dict[str, Any] | str, name: str | None = None) -> None:
        try:
            if isinstance(resource, dict):
                api = self._api_for(resource)
                metadata = resource.get("metadata", {})
                name = metadata["name"]
                namespace = metadata.get("namespace", self.namespace)
            else:
                kind, name = resource, name
                api = self._api_by_kind(kind)
                namespace = self.namespace
            api.delete(name=name, namespace=namespace)
        except Exception:
            return

    def get(self, kind: str, name: str) -> dict[str, Any] | None:
        try:
            result = self._api_by_kind(kind).get(name=name, namespace=self.namespace)
        except Exception:
            return None
        return result.to_dict() if hasattr(result, "to_dict") else dict(result)

    def patch_workload_image(
        self, *, kind: str, name: str, container: str, image: str
    ) -> None:
        body = {
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {"name": container, "image": image},
                        ]
                    }
                }
            }
        }
        self._api_by_kind(kind).patch(
            body=body,
            namespace=self.namespace,
            name=name,
            content_type="application/strategic-merge-patch+json",
        )
        if kind == "StatefulSet":
            self._delete_statefulset_pods_with_stale_image(
                name=name,
                container=container,
                image=image,
            )

    def _delete_statefulset_pods_with_stale_image(
        self, *, name: str, container: str, image: str
    ) -> None:
        statefulset = self.get("StatefulSet", name)
        selector = _statefulset_label_selector(statefulset)
        if not selector:
            return
        pods = self._core.list_namespaced_pod(
            namespace=self.namespace,
            label_selector=selector,
        )
        for pod in getattr(pods, "items", []):
            pod_name = _pod_name(pod)
            if not pod_name or _pod_container_image(pod, container) == image:
                continue
            self._core.delete_namespaced_pod(
                name=pod_name,
                namespace=self.namespace,
                propagation_policy="Background",
            )

    def wait_workload_ready(
        self, *, kind: str, name: str, replicas: int = 1, timeout_seconds: int = 120
    ) -> None:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            workload = self.get(kind, name)
            status = (workload or {}).get("status", {})
            ready = status.get("ready_replicas") or status.get("readyReplicas") or 0
            if int(ready) >= replicas:
                return
            time.sleep(2)
        raise TimeoutError(f"{kind}/{name} did not become ready")

    def wait_job_complete(self, name: str, *, timeout_seconds: int) -> int:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            job = self.get("Job", name)
            status = (job or {}).get("status", {})
            if status.get("succeeded", 0) >= 1:
                return 0
            if status.get("failed", 0) >= 1:
                return 1
            time.sleep(2)
        return 124

    def pod_logs_for_job(self, job_name: str, *, tail_lines: int = 1000) -> str:
        pods = self._core.list_namespaced_pod(
            namespace=self.namespace,
            label_selector=f"job-name={job_name}",
        )
        if not pods.items:
            return ""
        pod = pods.items[0]
        return self._core.read_namespaced_pod_log(
            name=pod.metadata.name,
            namespace=self.namespace,
            tail_lines=tail_lines,
        )

    def service_json(
        self, service_name: str, path: str, *, port: int | str | None = None
    ) -> dict[str, Any]:
        name = f"{service_name}:{port}" if port is not None else service_name
        response = self._core.connect_get_namespaced_service_proxy_with_path(
            name=name,
            namespace=self.namespace,
            path=path.strip("/"),
        )
        if isinstance(response, str):
            try:
                payload = json.loads(response)
            except json.JSONDecodeError:
                payload = ast.literal_eval(response)
        else:
            payload = response
        if not isinstance(payload, dict):
            raise ValueError(f"Service proxy {service_name}/{path} returned non-object")
        return payload

    def delete_jobs_by_label(self, label_selector: str) -> None:
        try:
            self._batch.delete_collection_namespaced_job(
                namespace=self.namespace,
                label_selector=label_selector,
                propagation_policy="Background",
            )
        except Exception:
            return

    def delete_by_label(self, kind: str, label_selector: str) -> None:
        try:
            self._api_by_kind(kind).delete(
                namespace=self.namespace,
                label_selector=label_selector,
                propagation_policy="Background",
            )
        except Exception:
            return

    def list_jobs_by_label(self, label_selector: str) -> list[dict[str, Any]]:
        result = self._batch.list_namespaced_job(
            namespace=self.namespace,
            label_selector=label_selector,
        )
        return [
            item.to_dict() if hasattr(item, "to_dict") else dict(item)
            for item in result.items
        ]

    def _api_for(self, resource: dict[str, Any]) -> Any:
        return self._dynamic.resources.get(
            api_version=resource["apiVersion"], kind=resource["kind"]
        )

    def _api_by_kind(self, kind: str) -> Any:
        versions = {
            "Secret": "v1",
            "Service": "v1",
            "Deployment": "apps/v1",
            "StatefulSet": "apps/v1",
            "Job": "batch/v1",
            "HorizontalPodAutoscaler": "autoscaling/v2",
            "NetworkPolicy": "networking.k8s.io/v1",
            "ScaledObject": "keda.sh/v1alpha1",
        }
        return self._dynamic.resources.get(api_version=versions[kind], kind=kind)


def _statefulset_label_selector(statefulset: dict[str, Any] | None) -> str | None:
    selector = ((statefulset or {}).get("spec") or {}).get("selector") or {}
    match_labels = selector.get("match_labels") or selector.get("matchLabels") or {}
    if not match_labels:
        return None
    return ",".join(f"{key}={value}" for key, value in sorted(match_labels.items()))


def _pod_name(pod: Any) -> str | None:
    metadata = getattr(pod, "metadata", None)
    return getattr(metadata, "name", None)


def _pod_container_image(pod: Any, container_name: str) -> str | None:
    spec = getattr(pod, "spec", None)
    for container in getattr(spec, "containers", []) or []:
        if getattr(container, "name", None) == container_name:
            return getattr(container, "image", None)
    return None
