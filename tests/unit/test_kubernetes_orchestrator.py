from __future__ import annotations

from typing import Any

import pytest

from platform_network.master.docker_orchestrator import (
    ChallengeResources,
    ChallengeSpec,
    DockerOrchestrationError,
)
from platform_network.master.kubernetes_orchestrator import (
    KubernetesOrchestrator,
    KubernetesTargetRouter,
)


class FakeKubernetesClient:
    def __init__(self) -> None:
        self.applied: list[dict[str, Any]] = []
        self.deleted: list[tuple[str, str | None]] = []
        self.waits: list[dict[str, Any]] = []

    def apply(self, resource: dict[str, Any]) -> dict[str, Any]:
        self.applied.append(resource)
        return resource

    def delete(self, resource: dict[str, Any] | str, name: str | None = None) -> None:
        if isinstance(resource, dict):
            self.deleted.append((resource["kind"], resource["metadata"]["name"]))
        else:
            self.deleted.append((resource, name))

    def wait_workload_ready(
        self, *, kind: str, name: str, replicas: int, timeout_seconds: int
    ) -> None:
        self.waits.append(
            {
                "kind": kind,
                "name": name,
                "replicas": replicas,
                "timeout_seconds": timeout_seconds,
            }
        )

    def service_json(
        self, service_name: str, path: str, *, port: int | str | None = None
    ) -> dict[str, Any]:
        if path == "health":
            return {"status": "ok", "service": service_name, "port": port}
        return {"api_version": "1.0", "capabilities": ["get_weights", "proxy_routes"]}


def test_deployment_start_applies_service_workload_hpa_and_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeKubernetesClient()
    orchestrator = KubernetesOrchestrator(
        client=client,
        mode="deployment",
        autoscaling_min_replicas=2,
        autoscaling_max_replicas=4,
        health_retries=1,
        health_retry_delay_seconds=0,
    )
    spec = ChallengeSpec(
        slug="demo",
        image="ghcr.io/org/demo:1",
        challenge_token="token",
        resources=ChallengeResources(cpu=1),
    )
    monkeypatch.setattr(
        orchestrator,
        "_get_json",
        lambda url: (
            {"status": "ok", "slug": "demo"}
            if url.endswith("/health")
            else {"api_version": "1.0", "capabilities": ["get_weights", "proxy_routes"]}
        ),
    )

    runtime = orchestrator.start_challenge(spec)
    kinds = [resource["kind"] for resource in client.applied]

    assert kinds == ["Secret", "Service", "Deployment", "HorizontalPodAutoscaler"]
    assert client.applied[2]["spec"]["replicas"] == 2
    assert client.applied[3]["spec"]["maxReplicas"] == 4
    assert client.waits[0]["replicas"] == 2
    assert runtime.container_name == "challenge-demo"
    assert orchestrator.runtime["demo"] == runtime


def test_statefulset_start_does_not_apply_hpa(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeKubernetesClient()
    orchestrator = KubernetesOrchestrator(
        client=client,
        mode="statefulset",
        autoscaling_max_replicas=4,
        health_retries=1,
        health_retry_delay_seconds=0,
    )
    spec = ChallengeSpec(slug="demo", image="ghcr.io/org/demo:1")
    monkeypatch.setattr(
        orchestrator,
        "_get_json",
        lambda url: (
            {"status": "ok"}
            if url.endswith("/health")
            else {"api_version": "1.0", "capabilities": ["get_weights", "proxy_routes"]}
        ),
    )

    orchestrator.start_challenge(spec)

    assert [resource["kind"] for resource in client.applied] == [
        "Service",
        "StatefulSet",
    ]
    assert client.waits[0]["replicas"] == 1


def test_deployment_start_can_apply_keda_scaled_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeKubernetesClient()
    orchestrator = KubernetesOrchestrator(
        client=client,
        mode="deployment",
        autoscaling_keda_enabled=True,
        autoscaling_min_replicas=1,
        autoscaling_max_replicas=3,
        health_retries=1,
        health_retry_delay_seconds=0,
    )
    spec = ChallengeSpec(
        slug="demo",
        image="ghcr.io/org/demo:1",
        resources=ChallengeResources(cpu=1),
    )
    monkeypatch.setattr(
        orchestrator,
        "_get_json",
        lambda url: (
            {"status": "ok"}
            if url.endswith("/health")
            else {"api_version": "1.0", "capabilities": ["get_weights", "proxy_routes"]}
        ),
    )

    orchestrator.start_challenge(spec)

    assert [resource["kind"] for resource in client.applied] == [
        "Service",
        "Deployment",
        "ScaledObject",
    ]


def test_stop_deletes_workloads_hpa_and_optional_service_secret() -> None:
    client = FakeKubernetesClient()
    orchestrator = KubernetesOrchestrator(client=client)

    orchestrator.stop_challenge("demo", remove=True)

    assert client.deleted == [
        ("Deployment", "challenge-demo"),
        ("StatefulSet", "challenge-demo"),
        ("HorizontalPodAutoscaler", "challenge-demo"),
        ("ScaledObject", "challenge-demo"),
        ("Service", "challenge-demo"),
        ("Secret", "challenge-demo-secrets"),
    ]


def test_pull_rejects_non_ghcr_images() -> None:
    orchestrator = KubernetesOrchestrator(client=FakeKubernetesClient())
    with pytest.raises(DockerOrchestrationError, match="GHCR"):
        orchestrator.pull_image("docker.io/org/demo:1")


def test_ready_validation_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    orchestrator = KubernetesOrchestrator(
        client=FakeKubernetesClient(),
        health_retries=1,
        health_retry_delay_seconds=0,
    )
    spec = ChallengeSpec(slug="demo", image="ghcr.io/org/demo:1")
    monkeypatch.setattr(orchestrator, "_get_json", lambda url: {"status": "bad"})

    with pytest.raises(DockerOrchestrationError, match="failed Kubernetes"):
        orchestrator.wait_until_ready(spec)


def test_service_proxy_readiness_uses_kubernetes_api() -> None:
    client = FakeKubernetesClient()
    orchestrator = KubernetesOrchestrator(
        client=client,
        health_check_mode="service_proxy",
        health_retries=1,
        health_retry_delay_seconds=0,
    )

    health, version = orchestrator.wait_until_ready(
        ChallengeSpec(slug="demo", image="ghcr.io/org/demo:1")
    )

    assert health["service"] == "challenge-demo"
    assert version["api_version"] == "1.0"


def test_kubernetes_target_router_routes_explicit_and_gpu_targets() -> None:
    default = StubOrchestrator("default")
    gpu = StubOrchestrator("gpu-a")
    router = KubernetesTargetRouter(
        default_orchestrator=default,  # type: ignore[arg-type]
        target_orchestrators={"gpu-a": gpu},  # type: ignore[arg-type]
        target_capacities={"gpu-a": 2},
    )

    explicit = ChallengeSpec(
        slug="explicit",
        image="ghcr.io/org/demo:1",
        resources=ChallengeResources(gpu_server="gpu-a", gpu_count=1),
    )
    automatic = ChallengeSpec(
        slug="automatic",
        image="ghcr.io/org/demo:1",
        resources=ChallengeResources(gpu_count=1),
    )
    local = ChallengeSpec(slug="local", image="ghcr.io/org/demo:1")

    assert router.start_challenge(explicit).container_name == "gpu-a-explicit"
    assert router.start_challenge(automatic).container_name == "gpu-a-automatic"
    assert router.start_challenge(local).container_name == "default-local"
    with pytest.raises(DockerOrchestrationError, match="Unknown Kubernetes target"):
        router.start_challenge(
            ChallengeSpec(
                slug="missing",
                image="ghcr.io/org/demo:1",
                resources=ChallengeResources(gpu_server="missing"),
            )
        )


class StubOrchestrator:
    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self._runtime = {}

    @property
    def runtime(self):
        return dict(self._runtime)

    def start_challenge(self, spec: ChallengeSpec, *, recreate: bool = False):
        runtime = type(
            "Runtime",
            (),
            {
                "container_name": f"{self.prefix}-{spec.slug}",
                "slug": spec.slug,
                "image": spec.image,
            },
        )()
        self._runtime[spec.slug] = runtime
        return runtime

    def restart_challenge(self, spec: ChallengeSpec):
        return self.start_challenge(spec, recreate=True)

    def stop_challenge(self, slug: str, *, remove: bool = False) -> None:
        self._runtime.pop(slug, None)

    def pull_image(self, image: str):
        return image

    def pull_challenge(self, spec: ChallengeSpec):
        return self.start_challenge(spec)
