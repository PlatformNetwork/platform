from __future__ import annotations

import json
import time
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
        if isinstance(resource, dict):
            api = self._api_for(resource)
            metadata = resource.get("metadata", {})
            name = metadata["name"]
            namespace = metadata.get("namespace", self.namespace)
        else:
            kind, name = resource, name
            api = self._api_by_kind(kind)
            namespace = self.namespace
        try:
            api.delete(name=name, namespace=namespace)
        except Exception:
            return

    def get(self, kind: str, name: str) -> dict[str, Any] | None:
        try:
            result = self._api_by_kind(kind).get(name=name, namespace=self.namespace)
        except Exception:
            return None
        return result.to_dict() if hasattr(result, "to_dict") else dict(result)

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
        payload = json.loads(response) if isinstance(response, str) else response
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
