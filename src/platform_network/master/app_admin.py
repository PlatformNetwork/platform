"""Private FastAPI app for challenge administration and registry access."""

from __future__ import annotations

import html
import inspect
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, NoReturn

from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from platform_network.config.policy import (
    ProductionPolicyError,
    validate_image_reference,
)
from platform_network.master.admin.auth import (
    TokenProvider,
    constant_time_match,
    load_admin_token_from_environment,
    resolve_token,
)
from platform_network.master.admin.runtime import (
    RuntimeController,
)
from platform_network.master.challenge_dashboard import (
    ChallengeMetricsProvider,
    render_challenges_dashboard_svg,
)
from platform_network.master.registry import (
    ChallengeAlreadyExistsError,
    ChallengeNotFoundError,
    record_to_admin_view,
)
from platform_network.master.service import MasterWeightService, active_challenge_inputs
from platform_network.schemas.challenge import (
    ChallengeAdminView,
    ChallengeCreate,
    ChallengeCreateResponse,
    ChallengeStatus,
    ChallengeUpdate,
    RegistryResponse,
    RuntimeOperationResponse,
)
from platform_network.schemas.weights import MasterWeightsResponse

_bearer_scheme = HTTPBearer(auto_error=False)


def _not_found(slug: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail=f"Challenge '{slug}' not found"
    )


def build_admin_router(
    *,
    registry: Any,
    runtime_controller: RuntimeController,
    metrics_provider: ChallengeMetricsProvider | None = None,
    weight_service: MasterWeightService | None = None,
    netuid: int = 100,
    chain_endpoint: str = "",
    now_fn: Callable[[], datetime] = lambda: datetime.now(UTC),
    admin_token_provider: TokenProvider = load_admin_token_from_environment,
    enforce_production_policy: bool = False,
    include_health: bool = True,
) -> APIRouter:
    """Build the admin/registry routes as a reusable ``APIRouter``.

    The public reads (``/v1/registry``, ``/v1/weights/latest``,
    ``/v1/challenges/dashboard.svg`` and, when ``include_health`` is set,
    ``GET /health``) stay open; every management/write/runtime-control route is
    gated by ``require_admin``. Pass ``include_health=False`` when including this
    router into an app that already serves ``GET /health`` (the proxy) so the
    duplicate registration is deduped.
    """

    router = APIRouter()
    challenge_registry = registry
    controller = runtime_controller

    async def resolve(value):  # type: ignore[no-untyped-def]
        if inspect.isawaitable(value):
            return await value
        return value

    async def registry_get(slug: str):
        return await resolve(challenge_registry.get(slug))

    async def registry_list():
        return await resolve(challenge_registry.list())

    async def registry_create(payload: ChallengeCreate):
        return await resolve(challenge_registry.create(payload))

    async def registry_update(slug: str, payload: ChallengeUpdate):
        return await resolve(challenge_registry.update(slug, payload))

    async def registry_set_status(slug: str, status_value: ChallengeStatus):
        return await resolve(challenge_registry.set_status(slug, status_value))

    async def registry_response():
        return await resolve(challenge_registry.registry_response())

    def _raise_policy_error(exc: ProductionPolicyError) -> NoReturn:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    async def require_admin(
        x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    ) -> None:
        expected = await resolve_token(admin_token_provider)
        provided = x_admin_token or (credentials.credentials if credentials else "")
        if not constant_time_match(provided, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
            )

    @router.get("/v1/registry", response_model=RegistryResponse)
    async def get_registry() -> RegistryResponse:
        return await registry_response()

    @router.get("/v1/weights/latest", response_model=MasterWeightsResponse)
    async def get_latest_weights() -> MasterWeightsResponse:
        if weight_service is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Master weight service unavailable",
            )
        try:
            challenges, tokens = await active_challenge_inputs(challenge_registry)
            return await weight_service.compute_latest_response(
                challenges,
                tokens,
                netuid=netuid,
                chain_endpoint=chain_endpoint,
                now_fn=now_fn,
            )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)
            ) from exc

    if include_health:

        @router.get("/health", include_in_schema=False)
        async def health() -> dict[str, str]:
            return {"status": "ok"}

    @router.get("/v1/challenges/dashboard.svg")
    async def get_challenges_dashboard_svg() -> Response:
        svg = render_challenges_dashboard_svg(
            await registry_list(), metrics_provider=metrics_provider
        )
        return Response(
            content=svg,
            media_type="image/svg+xml",
            headers={"Cache-Control": "no-store"},
        )

    @router.get("/admin", dependencies=[Depends(require_admin)])
    async def admin_home() -> Response:
        content = (
            "<h1>Platform Admin</h1>"
            "<ul>"
            "<li><a href='/admin/challenges'>Challenges</a></li>"
            "</ul>"
        )
        return Response(content=content, media_type="text/html")

    @router.get("/admin/challenges", dependencies=[Depends(require_admin)])
    async def admin_challenges() -> Response:
        rows = "".join(
            "<tr>"
            f"<td>{html.escape(record.slug)}</td>"
            f"<td>{html.escape(str(record.status))}</td>"
            f"<td>{html.escape(record.image)}</td>"
            f"<td>{html.escape(str(record.resources))}</td>"
            "</tr>"
            for record in await registry_list()
        )
        return Response(
            content=f"<h1>Challenges</h1><table>{rows}</table>",
            media_type="text/html",
        )

    @router.post(
        "/v1/admin/challenges",
        response_model=ChallengeCreateResponse,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_admin)],
    )
    async def create_challenge(payload: ChallengeCreate) -> ChallengeCreateResponse:
        try:
            validate_image_reference(
                payload.image, production=enforce_production_policy
            )
            record, token = await registry_create(payload)
        except ChallengeAlreadyExistsError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Challenge '{payload.slug}' already exists",
            ) from exc
        except ProductionPolicyError as exc:
            _raise_policy_error(exc)
        broker_token = ""
        get_broker_token = getattr(challenge_registry, "get_broker_token", None)
        if callable(get_broker_token):
            broker_token = await resolve(get_broker_token(record.slug))
        if not broker_token:
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "Docker broker token is unavailable",
            )
        return ChallengeCreateResponse(
            challenge=record_to_admin_view(record),
            challenge_token=token,
            docker_broker_token=broker_token,
        )

    @router.get(
        "/v1/admin/challenges/{slug}",
        response_model=ChallengeAdminView,
        dependencies=[Depends(require_admin)],
    )
    async def get_challenge(slug: str) -> ChallengeAdminView:
        try:
            return record_to_admin_view(await registry_get(slug))
        except ChallengeNotFoundError as exc:
            raise _not_found(slug) from exc

    @router.patch(
        "/v1/admin/challenges/{slug}",
        response_model=ChallengeAdminView,
        dependencies=[Depends(require_admin)],
    )
    async def patch_challenge(
        slug: str, payload: ChallengeUpdate
    ) -> ChallengeAdminView:
        try:
            if payload.image is not None:
                validate_image_reference(
                    payload.image, production=enforce_production_policy
                )
            return record_to_admin_view(await registry_update(slug, payload))
        except ChallengeNotFoundError as exc:
            raise _not_found(slug) from exc
        except ProductionPolicyError as exc:
            _raise_policy_error(exc)

    @router.post(
        "/v1/admin/challenges/{slug}/activate",
        response_model=ChallengeAdminView,
        dependencies=[Depends(require_admin)],
    )
    async def activate_challenge(slug: str) -> ChallengeAdminView:
        try:
            return record_to_admin_view(
                await registry_set_status(slug, ChallengeStatus.ACTIVE)
            )
        except ChallengeNotFoundError as exc:
            raise _not_found(slug) from exc

    @router.post(
        "/v1/admin/challenges/{slug}/deactivate",
        response_model=ChallengeAdminView,
        dependencies=[Depends(require_admin)],
    )
    async def deactivate_challenge(slug: str) -> ChallengeAdminView:
        try:
            return record_to_admin_view(
                await registry_set_status(slug, ChallengeStatus.INACTIVE)
            )
        except ChallengeNotFoundError as exc:
            raise _not_found(slug) from exc

    async def _runtime_operation(slug: str, operation: str) -> RuntimeOperationResponse:
        try:
            await registry_get(slug)
        except ChallengeNotFoundError as exc:
            raise _not_found(slug) from exc

        if operation == "pull":
            return await controller.pull(slug)
        if operation == "restart":
            return await controller.restart(slug)
        return await controller.status(slug)

    @router.post(
        "/v1/admin/challenges/{slug}/pull",
        response_model=RuntimeOperationResponse,
        dependencies=[Depends(require_admin)],
    )
    async def pull_challenge(slug: str) -> RuntimeOperationResponse:
        return await _runtime_operation(slug, "pull")

    @router.post(
        "/v1/admin/challenges/{slug}/restart",
        response_model=RuntimeOperationResponse,
        dependencies=[Depends(require_admin)],
    )
    async def restart_challenge(slug: str) -> RuntimeOperationResponse:
        return await _runtime_operation(slug, "restart")

    @router.get(
        "/v1/admin/challenges/{slug}/status",
        response_model=RuntimeOperationResponse,
        dependencies=[Depends(require_admin)],
    )
    async def challenge_status(slug: str) -> RuntimeOperationResponse:
        return await _runtime_operation(slug, "status")

    return router


def create_admin_app(
    *,
    registry: Any,
    runtime_controller: RuntimeController,
    metrics_provider: ChallengeMetricsProvider | None = None,
    weight_service: MasterWeightService | None = None,
    netuid: int = 100,
    chain_endpoint: str = "",
    now_fn: Callable[[], datetime] = lambda: datetime.now(UTC),
    admin_token_provider: TokenProvider = load_admin_token_from_environment,
    enforce_production_policy: bool = False,
) -> FastAPI:
    """Create the private admin/registry FastAPI app.

    Thin wrapper around :func:`build_admin_router`; the single-port proxy app
    includes the same router so the admin/registry surface is served on one port.
    """

    app = FastAPI(title="Platform Network Admin API", version="1.0")
    app.include_router(
        build_admin_router(
            registry=registry,
            runtime_controller=runtime_controller,
            metrics_provider=metrics_provider,
            weight_service=weight_service,
            netuid=netuid,
            chain_endpoint=chain_endpoint,
            now_fn=now_fn,
            admin_token_provider=admin_token_provider,
            enforce_production_policy=enforce_production_policy,
            include_health=True,
        )
    )

    @app.middleware("http")
    async def no_secret_request_state(request: Request, call_next):  # type: ignore[no-untyped-def]
        # This middleware intentionally does not log request headers or tokens.
        return await call_next(request)

    app.state.challenge_registry = registry
    app.state.runtime_controller = runtime_controller
    return app
