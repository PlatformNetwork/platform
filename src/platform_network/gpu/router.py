from __future__ import annotations

from typing import Protocol

from platform_network.gpu.client import GpuAgentClient
from platform_network.master.docker_orchestrator import (
    ChallengeRuntime,
    ChallengeSpec,
    DockerOrchestrationError,
)


class LocalOrchestrator(Protocol):
    @property
    def runtime(self) -> dict[str, ChallengeRuntime]: ...
    def start_challenge(
        self, spec: ChallengeSpec, *, recreate: bool = False
    ) -> ChallengeRuntime: ...
    def restart_challenge(self, spec: ChallengeSpec) -> ChallengeRuntime: ...
    def stop_challenge(self, slug: str, *, remove: bool = False) -> None: ...
    def pull_image(self, image: str) -> object: ...


class ChallengeOrchestratorRouter:
    def __init__(
        self,
        *,
        local_orchestrator: LocalOrchestrator,
        gpu_clients: dict[str, GpuAgentClient] | None = None,
    ) -> None:
        self.local_orchestrator = local_orchestrator
        self.gpu_clients = gpu_clients or {}
        self._remote_runtime: dict[str, ChallengeRuntime] = {}
        self._remote_slug_to_server: dict[str, str] = {}

    @property
    def runtime(self) -> dict[str, ChallengeRuntime]:
        return {**self.local_orchestrator.runtime, **self._remote_runtime}

    def start_challenge(
        self, spec: ChallengeSpec, *, recreate: bool = False
    ) -> ChallengeRuntime:
        client = self._gpu_client(spec)
        if client is None:
            return self.local_orchestrator.start_challenge(spec, recreate=recreate)
        runtime = client.start_challenge(spec, recreate=recreate)
        self._remember_remote(spec, runtime)
        return runtime

    def restart_challenge(self, spec: ChallengeSpec) -> ChallengeRuntime:
        client = self._gpu_client(spec)
        if client is None:
            return self.local_orchestrator.restart_challenge(spec)
        runtime = client.restart_challenge(spec)
        self._remember_remote(spec, runtime)
        return runtime

    def stop_challenge(self, slug: str, *, remove: bool = False) -> None:
        server_id = self._remote_slug_to_server.get(slug)
        if server_id:
            self.gpu_clients[server_id].stop_challenge(slug, remove=remove)
            self._remote_slug_to_server.pop(slug, None)
            self._remote_runtime.pop(slug, None)
            return
        self.local_orchestrator.stop_challenge(slug, remove=remove)

    def pull_image(self, image: str) -> object:
        return self.local_orchestrator.pull_image(image)

    def pull_challenge(self, spec: ChallengeSpec) -> object:
        if self._gpu_client(spec) is not None:
            return self.start_challenge(spec, recreate=False)
        return self.local_orchestrator.pull_image(spec.image)

    def _gpu_client(self, spec: ChallengeSpec) -> GpuAgentClient | None:
        server_id = spec.resources.gpu_server
        if not server_id:
            return None
        client = self.gpu_clients.get(server_id)
        if client is None:
            raise DockerOrchestrationError(f"Unknown GPU server: {server_id}")
        return client

    def _remember_remote(self, spec: ChallengeSpec, runtime: ChallengeRuntime) -> None:
        server_id = spec.resources.gpu_server
        if server_id is None:
            return
        self._remote_runtime[spec.slug] = runtime
        self._remote_slug_to_server[spec.slug] = server_id
