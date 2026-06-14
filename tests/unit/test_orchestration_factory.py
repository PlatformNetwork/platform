"""Factory dispatch tests for the orchestration backend seam (Task 4).

Settings are stubbed with SimpleNamespace on purpose: the factory must stay
decoupled from full Settings validation (Task 3 evolves the validator in
parallel), so we exercise dispatch with plain backend strings.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

import platform_network.master.kubernetes_orchestrator as kubernetes_orchestrator
from platform_network.gpu.router import ChallengeOrchestratorRouter
from platform_network.master.docker_orchestrator import ChallengeSpec
from platform_network.master.kubernetes_orchestrator import KubernetesTargetRouter
from platform_network.master.swarm_backend import SwarmChallengeOrchestrator
from platform_network.orchestration.factory import (
    DockerOrchestrationBackend,
    KubernetesOrchestrationBackend,
    OrchestrationBackend,
    create_backend,
)


class _FakeKubernetesClient:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


def _docker_settings_stub(backend: str = "docker") -> SimpleNamespace:
    return SimpleNamespace(
        runtime=SimpleNamespace(backend=backend),
        docker=SimpleNamespace(
            network_name="platform-net",
            secret_dir="/tmp/platform-secrets",
            internal_network=True,
            broker_url="http://platform-broker:8082",
        ),
    )


def _kubernetes_settings_stub() -> SimpleNamespace:
    return SimpleNamespace(
        environment="development",
        runtime=SimpleNamespace(backend="kubernetes"),
        docker=SimpleNamespace(broker_url="http://platform-broker:8082"),
        kubernetes=SimpleNamespace(
            namespace="platform",
            challenge_mode="statefulset",
            storage_class=None,
            storage_size="10Gi",
            gpu_resource_name="nvidia.com/gpu",
            node_selector={},
            tolerations=[],
            runtime_class_name=None,
            image_pull_secrets=[],
            in_cluster=False,
            kubeconfig=None,
            autoscaling=SimpleNamespace(
                enabled=True,
                keda_enabled=False,
                min_replicas=1,
                max_replicas=3,
                target_cpu_utilization=70,
            ),
            managed_postgres=SimpleNamespace(
                enabled=True,
                image="postgres:16-alpine",
                storage_class=None,
                storage_size="10Gi",
                retain_pvc=True,
                retain_secret=True,
                resources=SimpleNamespace(requests={}, limits={}),
            ),
        ),
    )


def _registry_stub() -> SimpleNamespace:
    return SimpleNamespace(list=lambda: [])


def test_create_backend_kubernetes_returns_kubernetes_impl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        kubernetes_orchestrator, "KubernetesClient", _FakeKubernetesClient
    )
    backend = create_backend(
        _kubernetes_settings_stub(),
        kubernetes_target_registry_factory=_registry_stub,
        gpu_clients_factory=dict,
    )
    assert isinstance(backend, KubernetesOrchestrationBackend)
    assert isinstance(backend, OrchestrationBackend)
    assert isinstance(backend.router, ChallengeOrchestratorRouter)
    assert isinstance(backend.router.local_orchestrator, KubernetesTargetRouter)
    assert backend.router.gpu_clients == {}


def test_create_backend_docker_returns_docker_impl() -> None:
    backend = create_backend(
        _docker_settings_stub(),
        kubernetes_target_registry_factory=_registry_stub,
        gpu_clients_factory=dict,
    )
    assert isinstance(backend, DockerOrchestrationBackend)
    assert isinstance(backend, OrchestrationBackend)
    assert isinstance(backend.router, ChallengeOrchestratorRouter)
    local = backend.router.local_orchestrator
    # Task 9 deliberately swapped DockerOrchestrator for the Swarm-backed
    # implementation behind the stable DockerOrchestrationBackend seam.
    assert isinstance(local, SwarmChallengeOrchestrator)
    assert local.network_name == "platform-net"
    assert local.docker_broker_url == "http://platform-broker:8082"
    assert local.placement_constraint == "node.role==worker"


def test_create_backend_invalid_backend_raises() -> None:
    with pytest.raises(ValueError, match="swarm"):
        create_backend(
            _docker_settings_stub(backend="swarm"),
            kubernetes_target_registry_factory=_registry_stub,
            gpu_clients_factory=dict,
        )


def test_kubernetes_backend_does_not_build_gpu_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        kubernetes_orchestrator, "KubernetesClient", _FakeKubernetesClient
    )

    def _explode() -> dict[str, Any]:
        raise AssertionError("gpu clients must not be built for kubernetes backend")

    backend = create_backend(
        _kubernetes_settings_stub(),
        kubernetes_target_registry_factory=_registry_stub,
        gpu_clients_factory=_explode,
    )
    assert isinstance(backend, KubernetesOrchestrationBackend)


def test_backend_delegates_to_router() -> None:
    calls: list[tuple[str, Any]] = []

    class _Recorder:
        runtime = {"slug": "rt"}
        gpu_clients: dict[str, Any] = {}

        def start_challenge(self, spec: Any, *, recreate: bool = False) -> str:
            calls.append(("start", (spec, recreate)))
            return "started"

        def restart_challenge(self, spec: Any) -> str:
            calls.append(("restart", spec))
            return "restarted"

        def pull_image(self, image: str) -> str:
            calls.append(("pull_image", image))
            return "pulled"

        def pull_challenge(self, spec: Any) -> str:
            calls.append(("pull_challenge", spec))
            return "pulled-challenge"

    backend = DockerOrchestrationBackend(_Recorder())  # type: ignore[arg-type]
    spec = cast(ChallengeSpec, "spec")
    assert backend.runtime == {"slug": "rt"}
    assert backend.start_challenge(spec, recreate=True) == "started"
    assert backend.restart_challenge(spec) == "restarted"
    assert backend.pull_image("ghcr.io/x:y") == "pulled"
    assert backend.pull_challenge(spec) == "pulled-challenge"
    assert calls == [
        ("start", ("spec", True)),
        ("restart", "spec"),
        ("pull_image", "ghcr.io/x:y"),
        ("pull_challenge", "spec"),
    ]
