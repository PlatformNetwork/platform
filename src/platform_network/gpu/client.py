from __future__ import annotations

from dataclasses import dataclass

import httpx

from platform_network.master.docker_orchestrator import (
    ChallengeRuntime,
    ChallengeSpec,
    DockerOrchestrationError,
)
from platform_network.schemas.gpu import (
    GpuChallengeResources,
    GpuChallengeRuntimeResponse,
    GpuChallengeSlugRequest,
    GpuChallengeSpecRequest,
)


@dataclass(frozen=True)
class GpuAgentClient:
    server_id: str
    base_url: str
    token: str
    timeout_seconds: float = 30.0
    verify_tls: bool = True

    def start_challenge(
        self, spec: ChallengeSpec, *, recreate: bool = False
    ) -> ChallengeRuntime:
        request = _from_challenge_spec(spec, recreate=recreate)
        return self._post_runtime("/v1/challenges/start", request.model_dump())

    def restart_challenge(self, spec: ChallengeSpec) -> ChallengeRuntime:
        request = _from_challenge_spec(spec, recreate=True)
        return self._post_runtime("/v1/challenges/restart", request.model_dump())

    def stop_challenge(self, slug: str, *, remove: bool = False) -> None:
        request = GpuChallengeSlugRequest(slug=slug, remove=remove)
        self._post("/v1/challenges/stop", request.model_dump())

    def get_status(self, slug: str) -> ChallengeRuntime:
        with httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            verify=self.verify_tls,
        ) as client:
            response = client.get(
                f"/v1/challenges/{slug}/status", headers=self._headers()
            )
        return _runtime_from_response(self._validated(response))

    def health(self) -> dict[str, object]:
        with httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            verify=self.verify_tls,
        ) as client:
            response = client.get("/health")
        return self._validated(response)

    def _post_runtime(self, path: str, payload: dict[str, object]) -> ChallengeRuntime:
        return _runtime_from_response(self._post(path, payload))

    def _post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        with httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            verify=self.verify_tls,
        ) as client:
            response = client.post(path, json=payload, headers=self._headers())
        return self._validated(response)

    def _validated(self, response: httpx.Response) -> dict[str, object]:
        try:
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise DockerOrchestrationError(
                f"GPU server {self.server_id!r} request failed: {response.text}"
            ) from exc
        payload = response.json()
        if not isinstance(payload, dict):
            raise DockerOrchestrationError(
                f"GPU server {self.server_id!r} returned invalid JSON"
            )
        return payload

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


def _from_challenge_spec(
    spec: ChallengeSpec, *, recreate: bool
) -> GpuChallengeSpecRequest:
    return GpuChallengeSpecRequest(
        slug=spec.slug,
        image=spec.image,
        version=spec.version,
        challenge_token=spec.challenge_token,
        docker_broker_token=spec.docker_broker_token,
        env=spec.env,
        secrets=spec.secrets,
        resources=GpuChallengeResources(
            cpu=spec.resources.cpu,
            memory=spec.resources.memory,
            gpu_count=spec.resources.gpu_count,
            gpu_device_ids=list(spec.resources.gpu_device_ids),
            gpu_capabilities=list(spec.resources.gpu_capabilities),
        ),
        required_capabilities=list(spec.required_capabilities),
        expected_api_version=spec.expected_api_version,
        port=spec.port,
        recreate=recreate,
    )


def _runtime_from_response(payload: dict[str, object]) -> ChallengeRuntime:
    response = GpuChallengeRuntimeResponse.model_validate(payload)
    return ChallengeRuntime(
        slug=response.slug,
        image=response.image,
        container_id=response.container_id,
        container_name=response.container_name,
        internal_base_url=response.internal_base_url,
        sqlite_volume_name=response.sqlite_volume_name,
        health=response.health,
        version=response.version,
    )
