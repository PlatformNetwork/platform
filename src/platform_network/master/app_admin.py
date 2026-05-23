"""Private FastAPI app for challenge administration and registry access."""

from __future__ import annotations

import html
import inspect
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, NoReturn

from fastapi import (
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
    validate_tls_enabled,
)
from platform_network.gpu.client import GpuAgentClient
from platform_network.gpu.registry import (
    GpuServerAlreadyExistsError,
    GpuServerNotFoundError,
)
from platform_network.kubernetes.registry import (
    KubernetesTargetAlreadyExistsError,
    KubernetesTargetNotFoundError,
    KubernetesTargetSecretError,
)
from platform_network.master.admin.auth import (
    TokenProvider,
    constant_time_match,
    load_admin_token_from_environment,
    resolve_token,
)
from platform_network.master.admin.gpu_registry import (
    GpuServerRegistry,
)
from platform_network.master.admin.kubernetes_targets import (
    KubernetesTargetRegistry,
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
from platform_network.schemas.gpu_server import (
    GpuServerCreate,
    GpuServerHealth,
    GpuServerRecord,
    GpuServerUpdate,
    GpuServerView,
)
from platform_network.schemas.kubernetes_target import (
    KubernetesTargetCreate,
    KubernetesTargetHealth,
    KubernetesTargetRecord,
    KubernetesTargetUpdate,
    KubernetesTargetView,
)
from platform_network.schemas.weights import MasterWeightsResponse

_bearer_scheme = HTTPBearer(auto_error=False)


def _not_found(slug: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail=f"Challenge '{slug}' not found"
    )


def create_admin_app(
    *,
    registry: Any,
    runtime_controller: RuntimeController,
    gpu_registry: GpuServerRegistry,
    kubernetes_target_registry: KubernetesTargetRegistry | None = None,
    metrics_provider: ChallengeMetricsProvider | None = None,
    weight_service: MasterWeightService | None = None,
    netuid: int = 0,
    chain_endpoint: str = "",
    now_fn: Callable[[], datetime] = lambda: datetime.now(UTC),
    admin_token_provider: TokenProvider = load_admin_token_from_environment,
    enforce_production_policy: bool = False,
) -> FastAPI:
    """Create the private admin/registry FastAPI app."""

    app = FastAPI(title="Platform Network Admin API", version="1.0")
    challenge_registry = registry
    controller = runtime_controller
    gpu_servers = gpu_registry
    kubernetes_targets = kubernetes_target_registry

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

    @app.get("/v1/registry", response_model=RegistryResponse)
    async def get_registry() -> RegistryResponse:
        return await registry_response()

    @app.get("/v1/weights/latest", response_model=MasterWeightsResponse)
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

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/challenges/dashboard.svg")
    async def get_challenges_dashboard_svg() -> Response:
        svg = render_challenges_dashboard_svg(
            await registry_list(), metrics_provider=metrics_provider
        )
        return Response(
            content=svg,
            media_type="image/svg+xml",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/admin", dependencies=[Depends(require_admin)])
    async def admin_home() -> Response:
        content = (
            "<h1>Platform Admin</h1>"
            "<ul>"
            "<li><a href='/admin/challenges'>Challenges</a></li>"
            "<li><a href='/admin/gpu-servers'>GPU servers</a></li>"
            "<li><a href='/admin/kubernetes-targets'>Kubernetes targets</a></li>"
            "</ul>"
        )
        return Response(content=content, media_type="text/html")

    @app.get("/admin/challenges", dependencies=[Depends(require_admin)])
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

    @app.get("/admin/gpu-servers", dependencies=[Depends(require_admin)])
    async def admin_gpu_servers() -> Response:
        rows = "".join(
            "<tr>"
            f"<td>{html.escape(record.id)}</td>"
            f"<td>{html.escape(record.base_url)}</td>"
            f"<td>{record.enabled}</td>"
            f"<td>{record.min_gpu_count}</td>"
            "</tr>"
            for record in gpu_servers.list()
        )
        form = (
            "<form method='post' action='/v1/admin/gpu-servers'>"
            "<input name='id' placeholder='id'/>"
            "<input name='base_url' placeholder='base_url'/>"
            "</form>"
        )
        return Response(
            content=f"<h1>GPU servers</h1>{form}<table>{rows}</table>",
            media_type="text/html",
        )

    def _kubernetes_target_registry() -> KubernetesTargetRegistry:
        if kubernetes_targets is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Kubernetes target registry unavailable",
            )
        return kubernetes_targets

    @app.get("/admin/kubernetes-targets", dependencies=[Depends(require_admin)])
    async def admin_kubernetes_targets() -> Response:
        target_registry = _kubernetes_target_registry()
        rows = "".join(
            "<tr>"
            f"<td>{html.escape(record.id)}</td>"
            f"<td>{html.escape(record.mode)}</td>"
            f"<td>{html.escape(record.namespace)}</td>"
            f"<td>{record.enabled}</td>"
            f"<td>{record.gpu_count}</td>"
            "</tr>"
            for record in target_registry.list()
        )
        form = (
            "<form method='post' action='/v1/admin/kubernetes-targets'>"
            "<input name='id' placeholder='id'/>"
            "<input name='namespace' placeholder='namespace'/>"
            "</form>"
        )
        return Response(
            content=f"<h1>Kubernetes targets</h1>{form}<table>{rows}</table>",
            media_type="text/html",
        )

    @app.post(
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

    @app.get(
        "/v1/admin/challenges/{slug}",
        response_model=ChallengeAdminView,
        dependencies=[Depends(require_admin)],
    )
    async def get_challenge(slug: str) -> ChallengeAdminView:
        try:
            return record_to_admin_view(await registry_get(slug))
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
            if payload.image is not None:
                validate_image_reference(
                    payload.image, production=enforce_production_policy
                )
            return record_to_admin_view(await registry_update(slug, payload))
        except ChallengeNotFoundError as exc:
            raise _not_found(slug) from exc
        except ProductionPolicyError as exc:
            _raise_policy_error(exc)

    @app.post(
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

    @app.post(
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

    def _gpu_not_found(server_id: str) -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"GPU server '{server_id}' not found",
        )

    def _gpu_view(record: GpuServerRecord) -> GpuServerView:
        return GpuServerView(**record.model_dump())

    @app.get(
        "/v1/admin/gpu-servers",
        response_model=list[GpuServerView],
        dependencies=[Depends(require_admin)],
    )
    async def list_gpu_servers() -> list[GpuServerView]:
        return [_gpu_view(record) for record in gpu_servers.list()]

    @app.post(
        "/v1/admin/gpu-servers",
        response_model=GpuServerView,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_admin)],
    )
    async def create_gpu_server(payload: GpuServerCreate) -> GpuServerView:
        try:
            validate_tls_enabled(
                verify_tls=payload.verify_tls,
                production=enforce_production_policy,
                subject=f"GPU server {payload.id!r}",
            )
            return _gpu_view(gpu_servers.create(payload))
        except GpuServerAlreadyExistsError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"GPU server '{payload.id}' already exists",
            ) from exc
        except ProductionPolicyError as exc:
            _raise_policy_error(exc)

    @app.get(
        "/v1/admin/gpu-servers/{server_id}",
        response_model=GpuServerView,
        dependencies=[Depends(require_admin)],
    )
    async def get_gpu_server(server_id: str) -> GpuServerView:
        try:
            return _gpu_view(gpu_servers.get(server_id))
        except GpuServerNotFoundError as exc:
            raise _gpu_not_found(server_id) from exc

    @app.patch(
        "/v1/admin/gpu-servers/{server_id}",
        response_model=GpuServerView,
        dependencies=[Depends(require_admin)],
    )
    async def update_gpu_server(
        server_id: str, payload: GpuServerUpdate
    ) -> GpuServerView:
        try:
            if payload.verify_tls is not None:
                validate_tls_enabled(
                    verify_tls=payload.verify_tls,
                    production=enforce_production_policy,
                    subject=f"GPU server {server_id!r}",
                )
            return _gpu_view(gpu_servers.update(server_id, payload))
        except GpuServerNotFoundError as exc:
            raise _gpu_not_found(server_id) from exc
        except ProductionPolicyError as exc:
            _raise_policy_error(exc)

    @app.delete(
        "/v1/admin/gpu-servers/{server_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        dependencies=[Depends(require_admin)],
    )
    async def delete_gpu_server(server_id: str) -> Response:
        try:
            gpu_servers.delete(server_id)
        except GpuServerNotFoundError as exc:
            raise _gpu_not_found(server_id) from exc
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.post(
        "/v1/admin/gpu-servers/{server_id}/enable",
        response_model=GpuServerView,
        dependencies=[Depends(require_admin)],
    )
    async def enable_gpu_server(server_id: str) -> GpuServerView:
        try:
            return _gpu_view(gpu_servers.set_enabled(server_id, True))
        except GpuServerNotFoundError as exc:
            raise _gpu_not_found(server_id) from exc

    @app.post(
        "/v1/admin/gpu-servers/{server_id}/disable",
        response_model=GpuServerView,
        dependencies=[Depends(require_admin)],
    )
    async def disable_gpu_server(server_id: str) -> GpuServerView:
        try:
            return _gpu_view(gpu_servers.set_enabled(server_id, False))
        except GpuServerNotFoundError as exc:
            raise _gpu_not_found(server_id) from exc

    @app.post(
        "/v1/admin/gpu-servers/{server_id}/health",
        response_model=GpuServerHealth,
        dependencies=[Depends(require_admin)],
    )
    async def gpu_server_health(server_id: str) -> GpuServerHealth:
        try:
            record = gpu_servers.get(server_id)
        except GpuServerNotFoundError as exc:
            raise _gpu_not_found(server_id) from exc
        token = gpu_servers.get_token(server_id)
        if not token:
            return GpuServerHealth(id=server_id, status="error", detail="missing token")
        try:
            client = GpuAgentClient(
                server_id=record.id,
                base_url=record.base_url,
                token=token,
                timeout_seconds=record.timeout_seconds,
                verify_tls=record.verify_tls,
            )
            client.health()
        except Exception as exc:
            return GpuServerHealth(id=server_id, status="error", detail=str(exc))
        return GpuServerHealth(id=server_id, status="ok")

    def _kubernetes_target_not_found(target_id: str) -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Kubernetes target '{target_id}' not found",
        )

    def _kubernetes_target_view(
        record: KubernetesTargetRecord,
    ) -> KubernetesTargetView:
        return KubernetesTargetView(**record.model_dump())

    @app.get(
        "/v1/admin/kubernetes-targets",
        response_model=list[KubernetesTargetView],
        dependencies=[Depends(require_admin)],
    )
    async def list_kubernetes_targets() -> list[KubernetesTargetView]:
        return [
            _kubernetes_target_view(record)
            for record in _kubernetes_target_registry().list()
        ]

    @app.post(
        "/v1/admin/kubernetes-targets",
        response_model=KubernetesTargetView,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_admin)],
    )
    async def create_kubernetes_target(
        payload: KubernetesTargetCreate,
    ) -> KubernetesTargetView:
        target_registry = _kubernetes_target_registry()
        try:
            validate_tls_enabled(
                verify_tls=payload.verify_tls,
                production=enforce_production_policy,
                subject=f"Kubernetes target {payload.id!r}",
            )
            return _kubernetes_target_view(target_registry.create(payload))
        except KubernetesTargetAlreadyExistsError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Kubernetes target '{payload.id}' already exists",
            ) from exc
        except KubernetesTargetSecretError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        except ProductionPolicyError as exc:
            _raise_policy_error(exc)

    @app.get(
        "/v1/admin/kubernetes-targets/{target_id}",
        response_model=KubernetesTargetView,
        dependencies=[Depends(require_admin)],
    )
    async def get_kubernetes_target(target_id: str) -> KubernetesTargetView:
        try:
            return _kubernetes_target_view(_kubernetes_target_registry().get(target_id))
        except KubernetesTargetNotFoundError as exc:
            raise _kubernetes_target_not_found(target_id) from exc

    @app.patch(
        "/v1/admin/kubernetes-targets/{target_id}",
        response_model=KubernetesTargetView,
        dependencies=[Depends(require_admin)],
    )
    async def update_kubernetes_target(
        target_id: str, payload: KubernetesTargetUpdate
    ) -> KubernetesTargetView:
        target_registry = _kubernetes_target_registry()
        try:
            if payload.verify_tls is not None:
                validate_tls_enabled(
                    verify_tls=payload.verify_tls,
                    production=enforce_production_policy,
                    subject=f"Kubernetes target {target_id!r}",
                )
            return _kubernetes_target_view(target_registry.update(target_id, payload))
        except KubernetesTargetNotFoundError as exc:
            raise _kubernetes_target_not_found(target_id) from exc
        except KubernetesTargetSecretError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        except ProductionPolicyError as exc:
            _raise_policy_error(exc)

    @app.delete(
        "/v1/admin/kubernetes-targets/{target_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        dependencies=[Depends(require_admin)],
    )
    async def delete_kubernetes_target(target_id: str) -> Response:
        try:
            _kubernetes_target_registry().delete(target_id)
        except KubernetesTargetNotFoundError as exc:
            raise _kubernetes_target_not_found(target_id) from exc
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.post(
        "/v1/admin/kubernetes-targets/{target_id}/enable",
        response_model=KubernetesTargetView,
        dependencies=[Depends(require_admin)],
    )
    async def enable_kubernetes_target(target_id: str) -> KubernetesTargetView:
        try:
            return _kubernetes_target_view(
                _kubernetes_target_registry().set_enabled(target_id, True)
            )
        except KubernetesTargetNotFoundError as exc:
            raise _kubernetes_target_not_found(target_id) from exc

    @app.post(
        "/v1/admin/kubernetes-targets/{target_id}/disable",
        response_model=KubernetesTargetView,
        dependencies=[Depends(require_admin)],
    )
    async def disable_kubernetes_target(target_id: str) -> KubernetesTargetView:
        try:
            return _kubernetes_target_view(
                _kubernetes_target_registry().set_enabled(target_id, False)
            )
        except KubernetesTargetNotFoundError as exc:
            raise _kubernetes_target_not_found(target_id) from exc

    @app.post(
        "/v1/admin/kubernetes-targets/{target_id}/health",
        response_model=KubernetesTargetHealth,
        dependencies=[Depends(require_admin)],
    )
    async def kubernetes_target_health(target_id: str) -> KubernetesTargetHealth:
        try:
            return _kubernetes_target_registry().health(target_id)
        except KubernetesTargetNotFoundError as exc:
            raise _kubernetes_target_not_found(target_id) from exc

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
    app.state.gpu_registry = gpu_servers
    app.state.kubernetes_target_registry = kubernetes_targets
    return app
