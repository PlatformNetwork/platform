from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, Response, status

from platform_network.kubernetes.names import challenge_name
from platform_network.master.docker_orchestrator import (
    ChallengeResources,
    ChallengeRuntime,
    ChallengeSpec,
    DockerOrchestrationError,
)
from platform_network.master.kubernetes_broker import KubernetesBrokerService
from platform_network.master.kubernetes_orchestrator import KubernetesOrchestrator
from platform_network.schemas.docker_broker import (
    BrokerCleanupRequest,
    BrokerCleanupResponse,
    BrokerListRequest,
    BrokerListResponse,
    BrokerRunRequest,
    BrokerRunResponse,
)
from platform_network.schemas.gpu import (
    GpuChallengeResources,
    GpuChallengeRuntimeResponse,
    GpuChallengeSlugRequest,
    GpuChallengeSpecRequest,
    GpuChallengeStopResponse,
)


@dataclass
class KubernetesAgentClient:
    target_id: str
    base_url: str
    token: str
    timeout_seconds: float = 30.0
    verify_tls: bool = True
    docker_broker_url: str | None = None
    _runtime: dict[str, ChallengeRuntime] = field(default_factory=dict, init=False)

    def start_challenge(
        self, spec: ChallengeSpec, *, recreate: bool = False
    ) -> ChallengeRuntime:
        request = _from_challenge_spec(
            spec, recreate=recreate, docker_broker_url=self.docker_broker_url
        )
        runtime = _runtime_from_response(
            self._post("/v1/challenges/start", request.model_dump())
        )
        self._runtime[spec.slug] = runtime
        return runtime

    def restart_challenge(self, spec: ChallengeSpec) -> ChallengeRuntime:
        request = _from_challenge_spec(
            spec, recreate=True, docker_broker_url=self.docker_broker_url
        )
        runtime = _runtime_from_response(
            self._post("/v1/challenges/restart", request.model_dump())
        )
        self._runtime[spec.slug] = runtime
        return runtime

    def stop_challenge(self, slug: str, *, remove: bool = False) -> None:
        self._post(
            "/v1/challenges/stop",
            GpuChallengeSlugRequest(slug=slug, remove=remove).model_dump(),
        )
        self._runtime.pop(slug, None)

    def get_status(self, slug: str) -> ChallengeRuntime:
        with httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            verify=self.verify_tls,
        ) as client:
            response = client.get(
                f"/v1/challenges/{slug}/status", headers=self._headers()
            )
        runtime = _runtime_from_response(self._validated(response))
        self._runtime[slug] = runtime
        return runtime

    def pull_image(self, image: str) -> object:
        return self._post("/v1/images/pull", {"image": image})

    def pull_challenge(self, spec: ChallengeSpec) -> object:
        return self.start_challenge(spec, recreate=False)

    @property
    def runtime(self) -> dict[str, ChallengeRuntime]:
        return dict(self._runtime)

    def run_broker(
        self, challenge_slug: str, request: BrokerRunRequest
    ) -> BrokerRunResponse:
        payload = self._post(
            f"/v1/broker/{challenge_slug}/run",
            request.model_dump(mode="json"),
            timeout_seconds=max(self.timeout_seconds, request.timeout_seconds + 15),
        )
        return BrokerRunResponse.model_validate(payload)

    def cleanup_broker(
        self, challenge_slug: str, request: BrokerCleanupRequest
    ) -> BrokerCleanupResponse:
        payload = self._post(
            f"/v1/broker/{challenge_slug}/cleanup", request.model_dump(mode="json")
        )
        return BrokerCleanupResponse.model_validate(payload)

    def list_broker(
        self, challenge_slug: str, request: BrokerListRequest
    ) -> BrokerListResponse:
        payload = self._post(
            f"/v1/broker/{challenge_slug}/list", request.model_dump(mode="json")
        )
        return BrokerListResponse.model_validate(payload)

    def health(self) -> dict[str, object]:
        with httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            verify=self.verify_tls,
        ) as client:
            response = client.get("/health", headers=self._headers())
        return self._validated(response)

    async def forward_challenge_request(
        self,
        *,
        slug: str,
        method: str,
        path: str,
        query: str = "",
        content: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        safe_path = quote(path.lstrip("/"), safe="/")
        url = f"/v1/challenges/{quote(slug, safe='')}/proxy/{safe_path}"
        if query:
            url = f"{url}?{query}"
        forwarded_headers = dict(headers or {})
        challenge_authorization = forwarded_headers.pop("Authorization", None)
        if challenge_authorization is None:
            challenge_authorization = forwarded_headers.pop("authorization", None)
        if challenge_authorization is not None:
            forwarded_headers["X-Platform-Forward-Authorization"] = (
                challenge_authorization
            )
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            verify=self.verify_tls,
            follow_redirects=False,
        ) as client:
            response = await client.request(
                method,
                url,
                content=content,
                headers={**forwarded_headers, **self._headers()},
            )
        return response

    def _post(
        self,
        path: str,
        payload: dict[str, object],
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, object]:
        with httpx.Client(
            base_url=self.base_url,
            timeout=(
                timeout_seconds if timeout_seconds is not None else self.timeout_seconds
            ),
            verify=self.verify_tls,
        ) as client:
            response = client.post(path, json=payload, headers=self._headers())
        return self._validated(response)

    def _validated(self, response: httpx.Response) -> dict[str, object]:
        try:
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise DockerOrchestrationError(
                f"Kubernetes target {self.target_id!r} request failed: {response.text}"
            ) from exc
        payload = response.json()
        if not isinstance(payload, dict):
            raise DockerOrchestrationError(
                f"Kubernetes target {self.target_id!r} returned invalid JSON"
            )
        return payload

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


class KubernetesAgentBrokerService:
    def __init__(self, client: KubernetesAgentClient) -> None:
        self.client = client

    def run(self, challenge_slug: str, request: BrokerRunRequest) -> BrokerRunResponse:
        return self.client.run_broker(challenge_slug, request)

    def cleanup(
        self, challenge_slug: str, request: BrokerCleanupRequest
    ) -> BrokerCleanupResponse:
        return self.client.cleanup_broker(challenge_slug, request)

    def list_containers(
        self, challenge_slug: str, request: BrokerListRequest
    ) -> BrokerListResponse:
        return self.client.list_broker(challenge_slug, request)


def create_kubernetes_agent_app(
    *,
    token_provider: Callable[[], str],
    orchestrator: KubernetesOrchestrator,
    broker_service: KubernetesBrokerService,
) -> FastAPI:
    app = FastAPI(title="Platform Kubernetes Agent", version="1.0")

    @app.get("/health", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.api_route(
        "/v1/challenges/{slug}/proxy/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    )
    async def challenge_proxy(
        slug: str,
        path: str,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> Response:
        _authenticate(token_provider, authorization)
        upstream_url = _challenge_url(slug, path, request.url.query)
        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower()
            not in {
                "authorization",
                "host",
                "connection",
                "content-length",
                "transfer-encoding",
                "x-platform-forward-authorization",
            }
        }
        forwarded_authorization = request.headers.get(
            "x-platform-forward-authorization"
        )
        if forwarded_authorization:
            headers["Authorization"] = forwarded_authorization
        try:
            async with httpx.AsyncClient(
                timeout=orchestrator.request_timeout_seconds,
                follow_redirects=False,
            ) as client:
                upstream = await client.request(
                    request.method,
                    upstream_url,
                    content=await request.body(),
                    headers=headers,
                )
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="challenge unavailable",
            ) from exc
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers={
                key: value
                for key, value in upstream.headers.items()
                if key.lower()
                not in {
                    "connection",
                    "keep-alive",
                    "proxy-authenticate",
                    "proxy-authorization",
                    "te",
                    "trailer",
                    "transfer-encoding",
                    "upgrade",
                }
            },
            media_type=upstream.headers.get("content-type"),
        )

    @app.post("/v1/images/pull")
    def pull_image(
        request: dict[str, str],
        authorization: str | None = Header(default=None),
    ) -> object:
        _authenticate(token_provider, authorization)
        return orchestrator.pull_image(request["image"])

    @app.post("/v1/challenges/start", response_model=GpuChallengeRuntimeResponse)
    def start(
        request: GpuChallengeSpecRequest,
        authorization: str | None = Header(default=None),
    ) -> GpuChallengeRuntimeResponse:
        _authenticate(token_provider, authorization)
        runtime = orchestrator.start_challenge(
            _to_challenge_spec(request), recreate=request.recreate
        )
        return GpuChallengeRuntimeResponse.from_runtime(runtime)

    @app.post("/v1/challenges/restart", response_model=GpuChallengeRuntimeResponse)
    def restart(
        request: GpuChallengeSpecRequest,
        authorization: str | None = Header(default=None),
    ) -> GpuChallengeRuntimeResponse:
        _authenticate(token_provider, authorization)
        runtime = orchestrator.restart_challenge(_to_challenge_spec(request))
        return GpuChallengeRuntimeResponse.from_runtime(runtime)

    @app.post("/v1/challenges/stop", response_model=GpuChallengeStopResponse)
    def stop(
        request: GpuChallengeSlugRequest,
        authorization: str | None = Header(default=None),
    ) -> GpuChallengeStopResponse:
        _authenticate(token_provider, authorization)
        orchestrator.stop_challenge(request.slug, remove=request.remove)
        return GpuChallengeStopResponse()

    @app.get("/v1/challenges/{slug}/status", response_model=GpuChallengeRuntimeResponse)
    def challenge_status(
        slug: str,
        authorization: str | None = Header(default=None),
    ) -> GpuChallengeRuntimeResponse:
        _authenticate(token_provider, authorization)
        runtime = orchestrator.runtime.get(slug)
        if runtime is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown challenge")
        return GpuChallengeRuntimeResponse.from_runtime(runtime)

    @app.post("/v1/broker/{challenge_slug}/run", response_model=BrokerRunResponse)
    def broker_run(
        challenge_slug: str,
        request: BrokerRunRequest,
        authorization: str | None = Header(default=None),
    ) -> BrokerRunResponse:
        _authenticate(token_provider, authorization)
        return broker_service.run(challenge_slug, request)

    @app.post(
        "/v1/broker/{challenge_slug}/cleanup", response_model=BrokerCleanupResponse
    )
    def broker_cleanup(
        challenge_slug: str,
        request: BrokerCleanupRequest,
        authorization: str | None = Header(default=None),
    ) -> BrokerCleanupResponse:
        _authenticate(token_provider, authorization)
        return broker_service.cleanup(challenge_slug, request)

    @app.post("/v1/broker/{challenge_slug}/list", response_model=BrokerListResponse)
    def broker_list(
        challenge_slug: str,
        request: BrokerListRequest,
        authorization: str | None = Header(default=None),
    ) -> BrokerListResponse:
        _authenticate(token_provider, authorization)
        return broker_service.list_containers(challenge_slug, request)

    return app


def _authenticate(token_provider: Callable[[], str], authorization: str | None) -> None:
    expected = token_provider()
    if not expected:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "missing Kubernetes agent token"
        )
    expected_header = f"Bearer {expected}"
    if authorization is None or not secrets.compare_digest(
        authorization, expected_header
    ):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "invalid Kubernetes agent token"
        )


def _from_challenge_spec(
    spec: ChallengeSpec, *, recreate: bool, docker_broker_url: str | None = None
) -> GpuChallengeSpecRequest:
    env = dict(spec.env)
    if docker_broker_url and "docker_executor" in spec.required_capabilities:
        env["CHALLENGE_DOCKER_BROKER_URL"] = docker_broker_url
    return GpuChallengeSpecRequest(
        slug=spec.slug,
        image=spec.image,
        version=spec.version,
        challenge_token=spec.challenge_token,
        docker_broker_token=spec.docker_broker_token,
        env=env,
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
        workload_class="service",
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


def _challenge_url(slug: str, path: str, query: str) -> str:
    safe_path = quote(path.lstrip("/"), safe="/")
    url = f"http://{challenge_name(slug)}:8000/{safe_path}"
    if query:
        url = f"{url}?{query}"
    return url
