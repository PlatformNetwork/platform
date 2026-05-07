"""Private FastAPI app for challenge administration and registry access."""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from typing import Protocol

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from platform_network.master.challenge_dashboard import (
    ChallengeMetricsProvider,
    render_challenges_dashboard_svg,
)
from platform_network.master.registry import (
    ChallengeAlreadyExistsError,
    ChallengeNotFoundError,
    ChallengeRegistry,
    record_to_admin_view,
)
from platform_network.schemas.challenge import (
    ChallengeAdminView,
    ChallengeCreate,
    ChallengeCreateResponse,
    ChallengeStatus,
    ChallengeUpdate,
    RegistryResponse,
    RuntimeOperationResponse,
)


class RuntimeController(Protocol):
    """Runtime controller protocol used by admin lifecycle endpoints."""

    async def pull(self, slug: str) -> RuntimeOperationResponse:
        """Pull the configured challenge image."""

    async def restart(self, slug: str) -> RuntimeOperationResponse:
        """Restart a challenge runtime."""

    async def status(self, slug: str) -> RuntimeOperationResponse:
        """Return runtime status for a challenge."""


class NoopRuntimeController:
    """Safe default runtime controller for API-only deployments/tests."""

    async def pull(self, slug: str) -> RuntimeOperationResponse:
        """Report that Docker orchestration has not been wired yet."""

        return RuntimeOperationResponse(
            slug=slug,
            operation="pull",
            status="not_configured",
            detail="Runtime controller is not configured.",
        )

    async def restart(self, slug: str) -> RuntimeOperationResponse:
        """Report that Docker orchestration has not been wired yet."""

        return RuntimeOperationResponse(
            slug=slug,
            operation="restart",
            status="not_configured",
            detail="Runtime controller is not configured.",
        )

    async def status(self, slug: str) -> RuntimeOperationResponse:
        """Report that Docker orchestration has not been wired yet."""

        return RuntimeOperationResponse(
            slug=slug,
            operation="status",
            status="not_configured",
            detail="Runtime controller is not configured.",
        )


TokenProvider = Callable[[], str | Awaitable[str]]

_bearer_scheme = HTTPBearer(auto_error=False)


def load_admin_token_from_environment() -> str:
    """Load the admin token from `ADMIN_TOKEN` or `ADMIN_TOKEN_FILE`."""

    token = os.getenv("ADMIN_TOKEN")
    if token:
        return token

    token_file = os.getenv("ADMIN_TOKEN_FILE")
    if token_file:
        with open(token_file, encoding="utf-8") as file:
            return file.read().strip()

    return ""


async def _resolve_token(provider: TokenProvider) -> str:
    token = provider()
    if hasattr(token, "__await__"):
        return await token  # type: ignore[misc]
    return token


def _constant_time_match(left: str, right: str) -> bool:
    import hmac

    return bool(left and right and hmac.compare_digest(left, right))


def _not_found(slug: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail=f"Challenge '{slug}' not found"
    )


def create_admin_app(
    *,
    registry: ChallengeRegistry | None = None,
    runtime_controller: RuntimeController | None = None,
    metrics_provider: ChallengeMetricsProvider | None = None,
    admin_token_provider: TokenProvider = load_admin_token_from_environment,
) -> FastAPI:
    """Create the private admin/registry FastAPI app."""

    app = FastAPI(title="Platform Network Admin API", version="1.0")
    challenge_registry = registry or ChallengeRegistry()
    controller = runtime_controller or NoopRuntimeController()

    async def require_admin(
        x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    ) -> None:
        expected = await _resolve_token(admin_token_provider)
        provided = x_admin_token or (credentials.credentials if credentials else "")
        if not _constant_time_match(provided, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
            )

    @app.get("/v1/registry", response_model=RegistryResponse)
    async def get_registry() -> RegistryResponse:
        return challenge_registry.registry_response()

    @app.get("/v1/challenges/dashboard.svg")
    async def get_challenges_dashboard_svg() -> Response:
        svg = render_challenges_dashboard_svg(
            challenge_registry.list(), metrics_provider=metrics_provider
        )
        return Response(
            content=svg,
            media_type="image/svg+xml",
            headers={"Cache-Control": "no-store"},
        )

    @app.post(
        "/v1/admin/challenges",
        response_model=ChallengeCreateResponse,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_admin)],
    )
    async def create_challenge(payload: ChallengeCreate) -> ChallengeCreateResponse:
        try:
            record, token = challenge_registry.create(payload)
        except ChallengeAlreadyExistsError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Challenge '{payload.slug}' already exists",
            ) from exc
        return ChallengeCreateResponse(
            challenge=record_to_admin_view(record), challenge_token=token
        )

    @app.get(
        "/v1/admin/challenges/{slug}",
        response_model=ChallengeAdminView,
        dependencies=[Depends(require_admin)],
    )
    async def get_challenge(slug: str) -> ChallengeAdminView:
        try:
            return record_to_admin_view(challenge_registry.get(slug))
        except ChallengeNotFoundError as exc:
            raise _not_found(slug) from exc

    @app.patch(
        "/v1/admin/challenges/{slug}",
        response_model=ChallengeAdminView,
        dependencies=[Depends(require_admin)],
    )
    async def patch_challenge(
        slug: str, payload: ChallengeUpdate
    ) -> ChallengeAdminView:
        try:
            return record_to_admin_view(challenge_registry.update(slug, payload))
        except ChallengeNotFoundError as exc:
            raise _not_found(slug) from exc

    @app.post(
        "/v1/admin/challenges/{slug}/activate",
        response_model=ChallengeAdminView,
        dependencies=[Depends(require_admin)],
    )
    async def activate_challenge(slug: str) -> ChallengeAdminView:
        try:
            return record_to_admin_view(
                challenge_registry.set_status(slug, ChallengeStatus.ACTIVE)
            )
        except ChallengeNotFoundError as exc:
            raise _not_found(slug) from exc

    @app.post(
        "/v1/admin/challenges/{slug}/deactivate",
        response_model=ChallengeAdminView,
        dependencies=[Depends(require_admin)],
    )
    async def deactivate_challenge(slug: str) -> ChallengeAdminView:
        try:
            return record_to_admin_view(
                challenge_registry.set_status(slug, ChallengeStatus.INACTIVE)
            )
        except ChallengeNotFoundError as exc:
            raise _not_found(slug) from exc

    async def _runtime_operation(slug: str, operation: str) -> RuntimeOperationResponse:
        try:
            challenge_registry.get(slug)
        except ChallengeNotFoundError as exc:
            raise _not_found(slug) from exc

        if operation == "pull":
            return await controller.pull(slug)
        if operation == "restart":
            return await controller.restart(slug)
        return await controller.status(slug)

    @app.post(
        "/v1/admin/challenges/{slug}/pull",
        response_model=RuntimeOperationResponse,
        dependencies=[Depends(require_admin)],
    )
    async def pull_challenge(slug: str) -> RuntimeOperationResponse:
        return await _runtime_operation(slug, "pull")

    @app.post(
        "/v1/admin/challenges/{slug}/restart",
        response_model=RuntimeOperationResponse,
        dependencies=[Depends(require_admin)],
    )
    async def restart_challenge(slug: str) -> RuntimeOperationResponse:
        return await _runtime_operation(slug, "restart")

    @app.get(
        "/v1/admin/challenges/{slug}/status",
        response_model=RuntimeOperationResponse,
        dependencies=[Depends(require_admin)],
    )
    async def challenge_status(slug: str) -> RuntimeOperationResponse:
        return await _runtime_operation(slug, "status")

    @app.middleware("http")
    async def no_secret_request_state(request: Request, call_next):  # type: ignore[no-untyped-def]
        # This middleware intentionally does not log request headers or tokens.
        return await call_next(request)

    app.state.challenge_registry = challenge_registry
    app.state.runtime_controller = controller
    return app


app = create_admin_app()
