"""Factory returning the orchestration backend for the configured runtime.

The interface is intentionally minimal: it is the exact union of what
control-plane call sites in ``cli_app/main.py`` use today —
``DockerRuntimeController`` (``runtime``, ``restart_challenge``,
``pull_challenge``/``pull_image``) and ``NormalValidatorRunner``
(``start_challenge``). Do not add speculative methods here; extend it
only when a real call site needs more.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

from platform_network.gpu.client import GpuAgentClient
from platform_network.gpu.router import ChallengeOrchestratorRouter
from platform_network.master.docker_orchestrator import (
    ChallengeRuntime,
    ChallengeSpec,
)
from platform_network.master.kubernetes_orchestrator import KubernetesTargetRouter
from platform_network.master.swarm_backend import SwarmChallengeOrchestrator

KNOWN_BACKENDS = ("kubernetes", "docker")


@runtime_checkable
class OrchestrationBackend(Protocol):
    """What control-plane call sites actually need from an orchestrator."""

    @property
    def runtime(self) -> dict[str, ChallengeRuntime]: ...

    def start_challenge(
        self, spec: ChallengeSpec, *, recreate: bool = False
    ) -> ChallengeRuntime: ...

    def restart_challenge(self, spec: ChallengeSpec) -> ChallengeRuntime: ...

    def pull_image(self, image: str) -> object: ...

    def pull_challenge(self, spec: ChallengeSpec) -> object: ...


class _RouterBackedBackend:
    """Thin adapter delegating to the pre-existing router composition."""

    def __init__(self, router: ChallengeOrchestratorRouter) -> None:
        self.router = router

    @property
    def runtime(self) -> dict[str, ChallengeRuntime]:
        return self.router.runtime

    def start_challenge(
        self, spec: ChallengeSpec, *, recreate: bool = False
    ) -> ChallengeRuntime:
        return self.router.start_challenge(spec, recreate=recreate)

    def restart_challenge(self, spec: ChallengeSpec) -> ChallengeRuntime:
        return self.router.restart_challenge(spec)

    def pull_image(self, image: str) -> object:
        return self.router.pull_image(image)

    def pull_challenge(self, spec: ChallengeSpec) -> object:
        return self.router.pull_challenge(spec)


class KubernetesOrchestrationBackend(_RouterBackedBackend):
    """Wraps the existing KubernetesTargetRouter call flow unchanged."""


class DockerOrchestrationBackend(_RouterBackedBackend):
    """Thin shell over the Swarm-backed docker orchestration composition.

    Task 9 swapped the local orchestrator behind this type to
    ``SwarmChallengeOrchestrator`` (replicated services/jobs on an encrypted
    overlay); the factory dispatch and this public type remain the stable
    seam.
    """


def create_backend(
    settings: Any,
    *,
    kubernetes_target_registry_factory: Callable[[], Any],
    gpu_clients_factory: Callable[[], dict[str, GpuAgentClient]],
) -> OrchestrationBackend:
    """Return the orchestration backend for ``settings.runtime.backend``.

    Dependency factories are invoked lazily and only on the branch that
    needs them, mirroring the pre-factory behavior (the kubernetes path
    never built GPU clients, the docker path never built the Kubernetes
    target registry).
    """

    backend = settings.runtime.backend
    if backend == "kubernetes":
        return KubernetesOrchestrationBackend(
            ChallengeOrchestratorRouter(
                local_orchestrator=KubernetesTargetRouter.from_settings(
                    settings, kubernetes_target_registry_factory()
                ),
                gpu_clients={},
            )
        )
    if backend == "docker":
        swarm_kwargs: dict[str, Any] = {
            "network_name": settings.docker.network_name,
            "internal_network": settings.docker.internal_network,
            "docker_broker_url": settings.docker.broker_url,
        }
        if settings.docker.challenge_placement_constraint:
            swarm_kwargs["placement_constraint"] = (
                settings.docker.challenge_placement_constraint
            )
        return DockerOrchestrationBackend(
            ChallengeOrchestratorRouter(
                local_orchestrator=SwarmChallengeOrchestrator(**swarm_kwargs),
                gpu_clients=gpu_clients_factory(),
            )
        )
    raise ValueError(
        f"Unsupported orchestration backend: {backend!r} "
        f"(expected one of {KNOWN_BACKENDS})"
    )
