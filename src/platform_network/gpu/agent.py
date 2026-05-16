from __future__ import annotations

import secrets
from collections.abc import Callable

from fastapi import FastAPI, Header, HTTPException, status

from platform_network.master.docker_orchestrator import (
    ChallengeResources,
    ChallengeSpec,
    DockerOrchestrationError,
    DockerOrchestrator,
)
from platform_network.schemas.gpu import (
    GpuChallengeRuntimeResponse,
    GpuChallengeSlugRequest,
    GpuChallengeSpecRequest,
    GpuChallengeStopResponse,
)


class GpuAgentService:
    def __init__(self, orchestrator: DockerOrchestrator) -> None:
        self.orchestrator = orchestrator

    def start(self, request: GpuChallengeSpecRequest) -> GpuChallengeRuntimeResponse:
        runtime = self.orchestrator.start_challenge(
            _to_challenge_spec(request), recreate=request.recreate
        )
        return GpuChallengeRuntimeResponse.from_runtime(runtime)

    def restart(self, request: GpuChallengeSpecRequest) -> GpuChallengeRuntimeResponse:
        runtime = self.orchestrator.restart_challenge(_to_challenge_spec(request))
        return GpuChallengeRuntimeResponse.from_runtime(runtime)

    def stop(self, request: GpuChallengeSlugRequest) -> GpuChallengeStopResponse:
        self.orchestrator.stop_challenge(request.slug, remove=request.remove)
        return GpuChallengeStopResponse()

    def status(self, slug: str) -> GpuChallengeRuntimeResponse:
        runtime = self.orchestrator.runtime.get(slug)
        if runtime is None:
            raise KeyError(slug)
        return GpuChallengeRuntimeResponse.from_runtime(runtime)


def create_gpu_agent_app(
    *,
    token_provider: Callable[[], str],
    service: GpuAgentService,
) -> FastAPI:
    app = FastAPI(title="Platform GPU Agent", version="1.0")

    @app.get("/health", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/challenges/start", response_model=GpuChallengeRuntimeResponse)
    def start(
        request: GpuChallengeSpecRequest,
        authorization: str | None = Header(default=None),
    ) -> GpuChallengeRuntimeResponse:
        _authenticate(token_provider, authorization)
        try:
            return service.start(request)
        except DockerOrchestrationError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    @app.post("/v1/challenges/restart", response_model=GpuChallengeRuntimeResponse)
    def restart(
        request: GpuChallengeSpecRequest,
        authorization: str | None = Header(default=None),
    ) -> GpuChallengeRuntimeResponse:
        _authenticate(token_provider, authorization)
        try:
            return service.restart(request)
        except DockerOrchestrationError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    @app.post("/v1/challenges/stop", response_model=GpuChallengeStopResponse)
    def stop(
        request: GpuChallengeSlugRequest,
        authorization: str | None = Header(default=None),
    ) -> GpuChallengeStopResponse:
        _authenticate(token_provider, authorization)
        return service.stop(request)

    @app.get("/v1/challenges/{slug}/status", response_model=GpuChallengeRuntimeResponse)
    def challenge_status(
        slug: str,
        authorization: str | None = Header(default=None),
    ) -> GpuChallengeRuntimeResponse:
        _authenticate(token_provider, authorization)
        try:
            return service.status(slug)
        except KeyError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown challenge") from exc

    return app


def _authenticate(token_provider: Callable[[], str], authorization: str | None) -> None:
    expected = token_provider()
    if not expected:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing GPU agent token")
    expected_header = f"Bearer {expected}"
    if authorization is None or not secrets.compare_digest(
        authorization, expected_header
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid GPU agent token")


def _to_challenge_spec(request: GpuChallengeSpecRequest) -> ChallengeSpec:
    return ChallengeSpec(
        slug=request.slug,
        image=request.image,
        version=request.version,
        challenge_token=request.challenge_token,
        docker_broker_token=request.docker_broker_token,
        env=request.env,
        secrets=request.secrets,
        resources=ChallengeResources(
            cpu=request.resources.cpu,
            memory=request.resources.memory,
            gpu_count=request.resources.gpu_count,
            gpu_device_ids=tuple(request.resources.gpu_device_ids),
            gpu_capabilities=tuple(request.resources.gpu_capabilities),
        ),
        required_capabilities=tuple(request.required_capabilities),
        expected_api_version=request.expected_api_version,
        port=request.port,
    )
