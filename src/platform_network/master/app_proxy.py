"""Public FastAPI proxy app for challenge routes."""

from __future__ import annotations

import inspect
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, AsyncExitStack, asynccontextmanager
from posixpath import normpath
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import FastAPI, HTTPException, Request, Response, status
from starlette.background import BackgroundTask
from starlette.responses import StreamingResponse

from platform_network.bittensor.metagraph_cache import MetagraphCache
from platform_network.kubernetes.agent import KubernetesAgentClient
from platform_network.master.docker_orchestrator import DockerOrchestrationError
from platform_network.master.registry import ChallengeNotFoundError
from platform_network.schemas.challenge import ChallengeRecord, ChallengeStatus
from platform_network.security.miner_auth import (
    MinerAuthError,
    MinerNonceStore,
    MinerUploadVerifier,
    NonceReplayError,
)

SENSITIVE_REQUEST_HEADERS = {
    "authorization",
    "proxy-authorization",
    "x-admin-token",
    "x-platform-admin-token",
    "x-platform-challenge-token",
    "x-platform-internal-token",
    "x-platform-shared-token",
    "x-hotkey",
    "x-signature",
    "x-nonce",
    "x-timestamp",
    "x-platform-verified-hotkey",
    "x-platform-verified-uid",
    "x-platform-verified-nonce",
    "x-platform-request-hash",
}

MINER_SIGNATURE_HEADERS = {
    "x-hotkey",
    "x-signature",
    "x-nonce",
    "x-timestamp",
}

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

BLOCKED_EXACT_PATHS = {"/health", "/version"}
BENCHMARK_EXECUTION_ACTIONS = {"run", "execute", "launch"}
PRISM_EXACT_PUBLIC_PATHS = {
    "/leaderboard",
    "/architectures",
    "/training-variants",
    "/epochs/current",
}


ClientFactory = Callable[[], AbstractAsyncContextManager[httpx.AsyncClient]]
ChallengeTokenProvider = Callable[[str], str]


def is_blocked_proxy_path(path: str) -> bool:
    """Return whether a public proxy path targets a private challenge route."""

    normalized = normpath(f"/{path.lstrip('/')}")
    return (
        normalized in BLOCKED_EXACT_PATHS
        or normalized == "/internal"
        or normalized.startswith("/internal/")
        or _is_benchmark_execution_path(normalized)
    )


def _is_benchmark_execution_path(normalized: str) -> bool:
    if normalized == "/benchmark-executions":
        return True
    if normalized.startswith("/benchmark-executions/"):
        return True
    parts = [part for part in normalized.split("/") if part]
    if not parts or parts[-1] not in BENCHMARK_EXECUTION_ACTIONS:
        return False
    return parts[0] in {"benchmark", "benchmarks"}


def prism_upstream_proxy_path(slug: str, path: str) -> str:
    normalized = normpath(f"/{path.lstrip('/')}")
    if slug != "prism" or normalized == "/.":
        return path
    if normalized.startswith("/v1/"):
        return normalized
    if normalized in PRISM_EXACT_PUBLIC_PATHS:
        return f"/v1{normalized}"
    parts = [part for part in normalized.split("/") if part]
    if len(parts) == 2 and parts[0] == "submissions":
        return f"/v1{normalized}"
    return path


def _is_agent_challenge_env_route(slug: str, method: str, path: str) -> bool:
    if slug != "agent-challenge":
        return False

    normalized = normpath(f"/{path.lstrip('/')}")
    parts = [part for part in normalized.split("/") if part]
    if len(parts) == 3 and parts[0] == "submissions" and parts[2] == "env":
        return method.upper() in {"GET", "PUT"}
    if (
        len(parts) == 4
        and parts[0] == "submissions"
        and parts[2] == "env"
        and parts[3] == "confirm-empty"
    ):
        return method.upper() == "POST"
    if len(parts) == 3 and parts[0] == "submissions" and parts[2] == "launch":
        return method.upper() == "POST"
    return False


def _forward_headers(
    request: Request, *, preserve_miner_signature_headers: bool = False
) -> dict[str, str]:
    """Copy safe request headers for forwarding to a public challenge route."""

    headers: dict[str, str] = {}
    for key, value in request.headers.items():
        lowered = key.lower()
        preserve_header = (
            preserve_miner_signature_headers and lowered in MINER_SIGNATURE_HEADERS
        )
        if (
            lowered in HOP_BY_HOP_HEADERS
            or (lowered in SENSITIVE_REQUEST_HEADERS and not preserve_header)
            or lowered == "host"
        ):
            continue
        headers[key] = value

    headers["X-Platform-Proxy"] = "true"
    return headers


def _response_headers(response: httpx.Response) -> dict[str, str]:
    """Copy safe upstream response headers back to the caller."""

    return {
        key: value
        for key, value in response.headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
    }


def _is_event_stream(response: httpx.Response) -> bool:
    return (
        response.headers.get("content-type", "").lower().startswith("text/event-stream")
    )


def _target_url(base_url: str, path: str, query: str) -> str:
    safe_path = quote(path.lstrip("/"), safe="/")
    url = f"{base_url.rstrip('/')}/{safe_path}"
    if query:
        url = f"{url}?{query}"
    return url


def _agent_client_for_challenge(
    target_registry: Any | None, challenge_slug: str
) -> KubernetesAgentClient | None:
    if target_registry is None or not hasattr(target_registry, "get_assignment"):
        return None
    target_id = target_registry.get_assignment(challenge_slug)
    if not target_id:
        return None
    target = target_registry.get(target_id)
    if target.mode != "agent" or not target.agent_url:
        return None
    token = target_registry.get_agent_token(target.id)
    if not token:
        return None
    return KubernetesAgentClient(
        target_id=target.id,
        base_url=target.agent_url,
        token=token,
        timeout_seconds=target.timeout_seconds,
        verify_tls=target.verify_tls,
    )


def _challenge_token_provider(registry: Any) -> ChallengeTokenProvider:
    def provider(slug: str) -> str:
        get_token = getattr(registry, "get_token", None)
        if callable(get_token):
            return str(get_token(slug))
        return ""

    return provider


async def _resolve_value(value):  # type: ignore[no-untyped-def]
    if inspect.isawaitable(value):
        return await value
    return value


async def _resolve_challenge(registry: Any, value: str) -> ChallengeRecord:
    try:
        return await _resolve_value(registry.get(value))
    except ChallengeNotFoundError:
        matches = [
            item
            for item in await _resolve_value(registry.list())
            if item.name.lower() == value.lower()
        ]
        if len(matches) == 1:
            return matches[0]
        raise


async def _active_challenge(registry: Any, value: str) -> ChallengeRecord:
    try:
        challenge = await _resolve_challenge(registry, value)
    except ChallengeNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Challenge not found"
        ) from exc
    if challenge.status != ChallengeStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Challenge not found"
        )
    return challenge


@asynccontextmanager
async def _default_client_factory() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
        yield client


def create_proxy_app(
    *,
    registry: Any,
    client_factory: ClientFactory = _default_client_factory,
    miner_verifier: MinerUploadVerifier | None = None,
    nonce_store: MinerNonceStore | None = None,
    metagraph_cache: MetagraphCache | None = None,
    challenge_token_provider: ChallengeTokenProvider | None = None,
    kubernetes_target_registry: Any | None = None,
    netuid: int = 100,
    upload_signature_ttl_seconds: int = 300,
    upload_nonce_ttl_seconds: int = 86_400,
    upload_max_body_bytes: int = 2_000_000,
    upload_require_registered_hotkey: bool = True,
) -> FastAPI:
    """Create the public proxy FastAPI app.

    Admin/registry concerns are intentionally not mounted in this app.
    """

    app = FastAPI(title="Platform Network Challenge Proxy", version="1.0")
    challenge_registry = registry
    token_provider = challenge_token_provider or _challenge_token_provider(
        challenge_registry
    )
    if miner_verifier is None and nonce_store is None:
        raise ValueError("nonce_store or miner_verifier is required")
    if miner_verifier is None and metagraph_cache is None:
        raise ValueError("metagraph_cache or miner_verifier is required")
    if miner_verifier is None:
        assert nonce_store is not None
        assert metagraph_cache is not None
        verifier = MinerUploadVerifier(
            netuid=netuid,
            nonce_store=nonce_store,
            metagraph_cache=metagraph_cache,
            ttl_seconds=upload_signature_ttl_seconds,
            require_registered_hotkey=upload_require_registered_hotkey,
        )
    else:
        verifier = miner_verifier

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    async def forward_upstream(
        challenge: ChallengeRecord,
        *,
        method: str,
        path: str,
        query: str,
        body: bytes,
        headers: dict[str, str],
    ) -> httpx.Response:
        agent = _agent_client_for_challenge(kubernetes_target_registry, challenge.slug)
        if agent is not None:
            return await agent.forward_challenge_request(
                slug=challenge.slug,
                method=method,
                path=path,
                query=query,
                content=body,
                headers=headers,
            )
        url = _target_url(challenge.internal_base_url, path, query)
        async with client_factory() as client:
            return await client.request(
                method,
                url,
                content=body,
                headers=headers,
            )

    async def forward_proxy_response(
        challenge: ChallengeRecord,
        *,
        method: str,
        path: str,
        query: str,
        body: bytes,
        headers: dict[str, str],
    ) -> Response:
        agent = _agent_client_for_challenge(kubernetes_target_registry, challenge.slug)
        if agent is not None:
            upstream = await agent.forward_challenge_request(
                slug=challenge.slug,
                method=method,
                path=path,
                query=query,
                content=body,
                headers=headers,
            )
            return Response(
                content=upstream.content,
                status_code=upstream.status_code,
                headers=_response_headers(upstream),
                media_type=upstream.headers.get("content-type"),
            )

        url = _target_url(challenge.internal_base_url, path, query)
        stack = AsyncExitStack()
        try:
            client = await stack.enter_async_context(client_factory())
            upstream = await stack.enter_async_context(
                client.stream(
                    method,
                    url,
                    content=body,
                    headers=headers,
                )
            )
            if _is_event_stream(upstream):
                return StreamingResponse(
                    upstream.aiter_raw(),
                    status_code=upstream.status_code,
                    headers=_response_headers(upstream),
                    media_type=upstream.headers.get("content-type"),
                    background=BackgroundTask(stack.aclose),
                )

            content = await upstream.aread()
        except Exception:
            await stack.aclose()
            raise

        await stack.aclose()
        return Response(
            content=content,
            status_code=upstream.status_code,
            headers=_response_headers(upstream),
            media_type=upstream.headers.get("content-type"),
        )

    async def proxy_request(slug: str, path: str, request: Request) -> Response:
        if is_blocked_proxy_path(path):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Proxy path is not allowed",
            )

        challenge = await _active_challenge(challenge_registry, slug)

        body = await request.body()
        is_agent_challenge_env_route = _is_agent_challenge_env_route(
            slug, request.method, path
        )
        headers = _forward_headers(
            request,
            preserve_miner_signature_headers=is_agent_challenge_env_route,
        )
        headers["X-Platform-Challenge-Slug"] = slug
        try:
            return await forward_proxy_response(
                challenge,
                method=request.method,
                path=prism_upstream_proxy_path(slug, path),
                query=request.url.query,
                body=body,
                headers=headers,
            )
        except (httpx.HTTPError, DockerOrchestrationError) as exc:
            unavailable_status = (
                status.HTTP_503_SERVICE_UNAVAILABLE
                if is_agent_challenge_env_route
                else status.HTTP_502_BAD_GATEWAY
            )
            raise HTTPException(
                status_code=unavailable_status, detail="Challenge unavailable"
            ) from exc

    async def bridge_upload(challenge_name: str, request: Request) -> Response:
        challenge = await _active_challenge(challenge_registry, challenge_name)
        body = await request.body()
        if len(body) > upload_max_body_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Submission too large",
            )
        try:
            identity = await verifier.verify(
                method=request.method,
                path=request.url.path,
                headers=request.headers,
                body=body,
                challenge_slug=challenge.slug,
            )
        except NonceReplayError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        except MinerAuthError as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

        token = token_provider(challenge.slug)
        if not token:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY, "Challenge token is unavailable"
            )
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Platform-Challenge-Slug": challenge.slug,
            "X-Platform-Verified-Hotkey": identity.hotkey,
            "X-Platform-Verified-Nonce": identity.nonce,
            "X-Platform-Request-Hash": identity.body_hash,
            "Content-Type": request.headers.get(
                "content-type", "application/octet-stream"
            ),
            "Accept": "application/json",
        }
        if identity.uid is not None:
            headers["X-Platform-Verified-Uid"] = str(identity.uid)
        filename = request.headers.get("x-submission-filename")
        if filename:
            headers["X-Submission-Filename"] = filename
        try:
            upstream = await forward_upstream(
                challenge,
                method="POST",
                path="/internal/v1/bridge/submissions",
                query=request.url.query,
                body=body,
                headers=headers,
            )
        except (httpx.HTTPError, DockerOrchestrationError) as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY, detail="Challenge unavailable"
            ) from exc
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=_response_headers(upstream),
            media_type=upstream.headers.get("content-type"),
        )

    async def bridge_status(
        challenge_name: str, submission_id: str, request: Request
    ) -> Response:
        challenge = await _active_challenge(challenge_registry, challenge_name)
        try:
            upstream = await forward_upstream(
                challenge,
                method="GET",
                path=f"/v1/submissions/{submission_id}",
                query=request.url.query,
                body=b"",
                headers=_forward_headers(request),
            )
        except (httpx.HTTPError, DockerOrchestrationError) as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY, detail="Challenge unavailable"
            ) from exc
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=_response_headers(upstream),
            media_type=upstream.headers.get("content-type"),
        )

    @app.post("/v1/challenges/{challenge_name}/submissions")
    async def upload_submission(challenge_name: str, request: Request) -> Response:
        return await bridge_upload(challenge_name, request)

    @app.get("/v1/challenges/{challenge_name}/submissions/{submission_id}")
    async def bridge_submission_status(
        challenge_name: str, submission_id: str, request: Request
    ) -> Response:
        return await bridge_status(challenge_name, submission_id, request)

    @app.api_route(
        "/challenges/{slug}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    )
    async def proxy_root(slug: str, request: Request) -> Response:
        return await proxy_request(slug, "", request)

    @app.api_route(
        "/challenges/{slug}/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    )
    async def proxy_path(slug: str, path: str, request: Request) -> Response:
        return await proxy_request(slug, path, request)

    app.state.challenge_registry = challenge_registry
    app.state.miner_upload_verifier = verifier
    return app
