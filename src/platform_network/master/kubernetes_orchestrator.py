from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import httpx

from platform_network.kubernetes.client import KubernetesClient
from platform_network.kubernetes.names import challenge_name, challenge_secret_name
from platform_network.kubernetes.resources import (
    build_challenge_hpa,
    build_challenge_scaled_object,
    build_challenge_secret,
    build_challenge_service,
    build_challenge_workload,
)
from platform_network.master.docker_orchestrator import (
    ChallengeRuntime,
    ChallengeSpec,
    DockerOrchestrationError,
)


class KubernetesOrchestrator:
    """Orchestrate challenges as Kubernetes workloads."""

    def __init__(
        self,
        *,
        client: Any | None = None,
        namespace: str = "platform",
        mode: str = "statefulset",
        storage_class_name: str | None = None,
        storage_size: str = "10Gi",
        pull_ghcr_only: bool = True,
        request_timeout_seconds: float = 5.0,
        health_retries: int = 12,
        health_retry_delay_seconds: float = 2.0,
        gpu_resource_name: str = "nvidia.com/gpu",
        node_selector: dict[str, str] | None = None,
        tolerations: list[dict[str, Any]] | None = None,
        runtime_class_name: str | None = None,
        image_pull_secrets: list[str] | None = None,
        autoscaling_enabled: bool = True,
        autoscaling_keda_enabled: bool = False,
        autoscaling_min_replicas: int = 1,
        autoscaling_max_replicas: int = 3,
        autoscaling_target_cpu_utilization: int = 70,
        docker_broker_url: str = "http://platform-broker:8082",
        health_check_mode: str = "direct",
        kubeconfig: str | None = None,
        in_cluster: bool = True,
    ) -> None:
        self.client = client or KubernetesClient(
            namespace=namespace, kubeconfig=kubeconfig, in_cluster=in_cluster
        )
        self.namespace = namespace
        self.mode = mode
        self.storage_class_name = storage_class_name
        self.storage_size = storage_size
        self.pull_ghcr_only = pull_ghcr_only
        self.request_timeout_seconds = request_timeout_seconds
        self.health_retries = health_retries
        self.health_retry_delay_seconds = health_retry_delay_seconds
        self.gpu_resource_name = gpu_resource_name
        self.node_selector = node_selector or {}
        self.tolerations = tolerations or []
        self.runtime_class_name = runtime_class_name
        self.image_pull_secrets = image_pull_secrets or []
        self.autoscaling_enabled = autoscaling_enabled
        self.autoscaling_keda_enabled = autoscaling_keda_enabled
        self.autoscaling_min_replicas = autoscaling_min_replicas
        self.autoscaling_max_replicas = autoscaling_max_replicas
        self.autoscaling_target_cpu_utilization = autoscaling_target_cpu_utilization
        self.docker_broker_url = docker_broker_url
        self.health_check_mode = health_check_mode
        self._runtime: dict[str, ChallengeRuntime] = {}

    @property
    def runtime(self) -> dict[str, ChallengeRuntime]:
        return dict(self._runtime)

    def pull_image(self, image: str) -> object:
        if self.pull_ghcr_only and not image.startswith("ghcr.io/"):
            raise DockerOrchestrationError("Challenge images must be pulled from GHCR")
        return {"image": image, "status": "scheduled-by-kubernetes"}

    def start_challenge(
        self, spec: ChallengeSpec, *, recreate: bool = False
    ) -> ChallengeRuntime:
        self.pull_image(spec.image)
        if recreate:
            self.stop_challenge(spec.slug, remove=True)
        secret = build_challenge_secret(spec, namespace=self.namespace)
        if secret is not None:
            self.client.apply(secret)
        workload = build_challenge_workload(
            spec,
            namespace=self.namespace,
            mode=self.mode,
            storage_class_name=self.storage_class_name,
            storage_size=self.storage_size,
            replicas=self._initial_replicas(),
            gpu_resource_name=self.gpu_resource_name,
            node_selector=self.node_selector,
            tolerations=self.tolerations,
            runtime_class_name=self.runtime_class_name,
            image_pull_secrets=self.image_pull_secrets,
            docker_broker_url=self.docker_broker_url,
        )
        service = build_challenge_service(spec, namespace=self.namespace)
        self.client.apply(service)
        self.client.apply(workload)
        if self._should_apply_autoscaler(spec):
            if self.autoscaling_keda_enabled:
                autoscaler = build_challenge_scaled_object(
                    spec,
                    namespace=self.namespace,
                    min_replicas=self.autoscaling_min_replicas,
                    max_replicas=self.autoscaling_max_replicas,
                    target_cpu_utilization=self.autoscaling_target_cpu_utilization,
                )
            else:
                autoscaler = build_challenge_hpa(
                    spec,
                    namespace=self.namespace,
                    min_replicas=self.autoscaling_min_replicas,
                    max_replicas=self.autoscaling_max_replicas,
                    target_cpu_utilization=self.autoscaling_target_cpu_utilization,
                )
            self.client.apply(autoscaler)
        self.client.wait_workload_ready(
            kind=workload["kind"],
            name=workload["metadata"]["name"],
            replicas=workload["spec"]["replicas"],
            timeout_seconds=int(
                self.health_retries * self.health_retry_delay_seconds
                + self.request_timeout_seconds
            ),
        )
        health, version = self.wait_until_ready(spec)
        runtime = ChallengeRuntime(
            slug=spec.slug,
            image=spec.image,
            container_id=challenge_name(spec.slug),
            container_name=challenge_name(spec.slug),
            internal_base_url=spec.internal_base_url,
            sqlite_volume_name=spec.sqlite_volume_name,
            health=health,
            version=version,
        )
        self._runtime[spec.slug] = runtime
        return runtime

    def restart_challenge(self, spec: ChallengeSpec) -> ChallengeRuntime:
        return self.start_challenge(spec, recreate=True)

    def stop_challenge(self, slug: str, *, remove: bool = False) -> None:
        name = challenge_name(slug)
        self.client.delete("Deployment", name)
        self.client.delete("StatefulSet", name)
        self.client.delete("HorizontalPodAutoscaler", name)
        self.client.delete("ScaledObject", name)
        if remove:
            self.client.delete("Service", name)
            self.client.delete("Secret", challenge_secret_name(slug))
        self._runtime.pop(slug, None)

    def pull_challenge(self, spec: ChallengeSpec) -> object:
        return self.start_challenge(spec, recreate=False)

    def wait_until_ready(
        self, spec: ChallengeSpec
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        last_error: Exception | None = None
        for _attempt in range(self.health_retries):
            try:
                health = self._challenge_json(spec, "health")
                self._validate_health(spec, health)
                version = self._challenge_json(spec, "version")
                self._validate_version(spec, version)
                return health, version
            except Exception as exc:
                last_error = exc
                time.sleep(self.health_retry_delay_seconds)
        raise DockerOrchestrationError(
            f"Challenge {spec.slug!r} failed Kubernetes health/version checks"
        ) from last_error

    def _get_json(self, url: str) -> dict[str, Any]:
        response = httpx.get(url, timeout=self.request_timeout_seconds)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise DockerOrchestrationError(
                f"Challenge endpoint {url} returned non-object JSON"
            )
        return payload

    def _challenge_json(self, spec: ChallengeSpec, path: str) -> dict[str, Any]:
        if self.health_check_mode == "service_proxy":
            return self.client.service_json(
                challenge_name(spec.slug), path, port=spec.port
            )
        return self._get_json(f"{spec.internal_base_url}/{path}")

    def _should_apply_autoscaler(self, spec: ChallengeSpec) -> bool:
        return (
            self.mode == "deployment"
            and self.autoscaling_enabled
            and self.autoscaling_max_replicas > 1
            and spec.resources.cpu is not None
        )

    def _initial_replicas(self) -> int:
        if self.mode == "deployment" and self.autoscaling_enabled:
            return self.autoscaling_min_replicas
        return 1

    def _validate_health(self, spec: ChallengeSpec, payload: dict[str, Any]) -> None:
        status = payload.get("status")
        if status not in {None, "ok", "healthy"}:
            raise DockerOrchestrationError(
                f"Challenge {spec.slug!r} reported unhealthy status: {status!r}"
            )

    def _validate_version(self, spec: ChallengeSpec, payload: dict[str, Any]) -> None:
        api_version = payload.get("api_version") or payload.get("apiVersion")
        if api_version is not None and str(api_version) != spec.expected_api_version:
            raise DockerOrchestrationError(
                f"Challenge {spec.slug!r} API version mismatch: {api_version!r}"
            )
        capabilities = payload.get("capabilities")
        if capabilities is None:
            return
        if not isinstance(capabilities, list):
            raise DockerOrchestrationError(
                f"Challenge {spec.slug!r} returned invalid capabilities"
            )
        missing = set(spec.required_capabilities).difference(
            str(item) for item in capabilities
        )
        if missing:
            raise DockerOrchestrationError(
                f"Challenge {spec.slug!r} missing capabilities: {sorted(missing)}"
            )

    @classmethod
    def from_settings(cls, settings: Any) -> KubernetesOrchestrator:
        return cls(
            namespace=settings.kubernetes.namespace,
            mode=settings.kubernetes.challenge_mode,
            storage_class_name=settings.kubernetes.storage_class,
            storage_size=settings.kubernetes.storage_size,
            gpu_resource_name=settings.kubernetes.gpu_resource_name,
            node_selector=settings.kubernetes.node_selector,
            tolerations=settings.kubernetes.tolerations,
            runtime_class_name=settings.kubernetes.runtime_class_name,
            image_pull_secrets=settings.kubernetes.image_pull_secrets,
            autoscaling_enabled=settings.kubernetes.autoscaling.enabled,
            autoscaling_keda_enabled=settings.kubernetes.autoscaling.keda_enabled,
            autoscaling_min_replicas=settings.kubernetes.autoscaling.min_replicas,
            autoscaling_max_replicas=settings.kubernetes.autoscaling.max_replicas,
            autoscaling_target_cpu_utilization=(
                settings.kubernetes.autoscaling.target_cpu_utilization
            ),
            docker_broker_url=settings.docker.broker_url,
            health_check_mode=(
                "direct" if settings.kubernetes.in_cluster else "service_proxy"
            ),
            kubeconfig=settings.kubernetes.kubeconfig,
            in_cluster=settings.kubernetes.in_cluster,
        )


class KubernetesTargetRouter:
    def __init__(
        self,
        *,
        default_orchestrator: KubernetesOrchestrator,
        target_orchestrators: dict[str, Any],
        target_capacities: dict[str, int],
    ) -> None:
        self.default_orchestrator = default_orchestrator
        self.target_orchestrators = target_orchestrators
        self.target_capacities = target_capacities
        self._slug_to_target: dict[str, str] = {}

    @property
    def runtime(self) -> dict[str, ChallengeRuntime]:
        runtime = self.default_orchestrator.runtime
        for orchestrator in self.target_orchestrators.values():
            runtime.update(orchestrator.runtime)
        return runtime

    def start_challenge(
        self, spec: ChallengeSpec, *, recreate: bool = False
    ) -> ChallengeRuntime:
        target_id, orchestrator = self._select(spec)
        runtime = orchestrator.start_challenge(spec, recreate=recreate)
        if target_id:
            self._slug_to_target[spec.slug] = target_id
        return runtime

    def restart_challenge(self, spec: ChallengeSpec) -> ChallengeRuntime:
        return self.start_challenge(spec, recreate=True)

    def stop_challenge(self, slug: str, *, remove: bool = False) -> None:
        target_id = self._slug_to_target.pop(slug, None)
        if target_id:
            self.target_orchestrators[target_id].stop_challenge(slug, remove=remove)
            return
        self.default_orchestrator.stop_challenge(slug, remove=remove)

    def pull_image(self, image: str) -> object:
        return self.default_orchestrator.pull_image(image)

    def pull_challenge(self, spec: ChallengeSpec) -> object:
        return self.start_challenge(spec, recreate=False)

    def _select(self, spec: ChallengeSpec) -> tuple[str | None, Any]:
        requested = spec.resources.gpu_server
        if requested:
            orchestrator = self.target_orchestrators.get(requested)
            if orchestrator is None:
                raise DockerOrchestrationError(
                    f"Unknown Kubernetes target: {requested}"
                )
            return requested, orchestrator
        if spec.resources.gpu_count:
            for target_id, orchestrator in self.target_orchestrators.items():
                if self.target_capacities.get(target_id, 0) >= spec.resources.gpu_count:
                    return target_id, orchestrator
        return None, self.default_orchestrator

    @classmethod
    def from_settings(
        cls, settings: Any, target_registry: Any
    ) -> KubernetesTargetRouter:
        default = KubernetesOrchestrator.from_settings(settings)
        target_orchestrators: dict[str, Any] = {}
        target_capacities: dict[str, int] = {}
        for target in target_registry.list():
            if not target.enabled:
                continue
            if target.mode == "agent":
                from platform_network.kubernetes.agent import KubernetesAgentClient

                token = target_registry.get_agent_token(target.id)
                if not target.agent_url or not token:
                    continue
                target_orchestrators[target.id] = KubernetesAgentClient(
                    target_id=target.id,
                    base_url=target.agent_url,
                    token=token,
                    timeout_seconds=target.timeout_seconds,
                    verify_tls=target.verify_tls,
                )
                target_capacities[target.id] = target.gpu_count
                continue
            defaults = settings.kubernetes.target_defaults
            target_orchestrators[target.id] = KubernetesOrchestrator(
                namespace=target.namespace,
                mode=settings.kubernetes.challenge_mode,
                storage_class_name=target.storage_class
                or settings.kubernetes.storage_class,
                storage_size=settings.kubernetes.storage_size,
                gpu_resource_name=defaults.gpu_resource_name
                or settings.kubernetes.gpu_resource_name,
                node_selector={
                    **settings.kubernetes.node_selector,
                    **defaults.node_selector,
                    **target.node_selector,
                },
                tolerations=target.tolerations
                or defaults.tolerations
                or settings.kubernetes.tolerations,
                runtime_class_name=target.runtime_class_name
                or defaults.runtime_class_name
                or settings.kubernetes.runtime_class_name,
                image_pull_secrets=defaults.image_pull_secrets
                or settings.kubernetes.image_pull_secrets,
                autoscaling_enabled=settings.kubernetes.autoscaling.enabled,
                autoscaling_keda_enabled=settings.kubernetes.autoscaling.keda_enabled,
                autoscaling_min_replicas=settings.kubernetes.autoscaling.min_replicas,
                autoscaling_max_replicas=settings.kubernetes.autoscaling.max_replicas,
                autoscaling_target_cpu_utilization=(
                    settings.kubernetes.autoscaling.target_cpu_utilization
                ),
                docker_broker_url=settings.docker.broker_url,
                health_check_mode="service_proxy",
                kubeconfig=target.kubeconfig_file,
                in_cluster=False,
            )
            target_capacities[target.id] = target.gpu_count
        return cls(
            default_orchestrator=default,
            target_orchestrators=target_orchestrators,
            target_capacities=target_capacities,
        )


def kubeconfig_from_file(path: str | Path | None) -> str | None:
    return None if path is None else str(path)
