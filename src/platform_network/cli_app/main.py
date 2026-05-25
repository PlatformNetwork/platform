from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import typer

from platform_network.bittensor.factory import (
    create_bittensor_runtime,
    create_bittensor_submit_runtime,
)
from platform_network.bittensor.metagraph_cache import MetagraphCache
from platform_network.bittensor.validator_loop import run_epoch_loop
from platform_network.config import load_settings
from platform_network.config.policy import production_policy_enabled_for_settings
from platform_network.db.session import create_engine, create_session_factory
from platform_network.gpu.agent import GpuAgentService, create_gpu_agent_app
from platform_network.gpu.capabilities import ResourceCapabilityChecker
from platform_network.gpu.client import GpuAgentClient
from platform_network.gpu.registry import FileGpuServerRegistry
from platform_network.gpu.router import ChallengeOrchestratorRouter
from platform_network.kubernetes.agent import create_kubernetes_agent_app
from platform_network.kubernetes.config_updater import (
    ConfigSyncSource,
    RolloutTarget,
    create_incluster_config_sync_updater,
)
from platform_network.kubernetes.registry import FileKubernetesTargetRegistry
from platform_network.master.app_admin import create_admin_app
from platform_network.master.app_proxy import create_proxy_app
from platform_network.master.challenge_client import ChallengeClient
from platform_network.master.docker_broker import (
    DockerBrokerConfig,
    DockerBrokerService,
    create_docker_broker_app,
)
from platform_network.master.docker_orchestrator import (
    ChallengeResources,
    ChallengeSpec,
    DockerOrchestrator,
)
from platform_network.master.kubernetes_broker import (
    KubernetesBrokerRouterService,
    KubernetesBrokerService,
    create_kubernetes_broker_app,
)
from platform_network.master.kubernetes_orchestrator import KubernetesTargetRouter
from platform_network.master.registry import DatabaseChallengeRegistry
from platform_network.master.service import (
    MasterWeightService,
    active_challenge_inputs,
)
from platform_network.observability.logging import configure_logging
from platform_network.schemas.weights import FinalWeights, MasterWeightsResponse
from platform_network.security.admin_auth import read_secret
from platform_network.security.miner_auth import SqlAlchemyMinerNonceStore
from platform_network.template_engine import (
    ChallengeTemplateContext,
    render_challenge_template,
)
from platform_network.validator.image_updater import create_incluster_updater
from platform_network.validator.normal_runner import NormalValidatorRunner
from platform_network.validator.registry_client import RegistryClient
from platform_network.validator.weights_client import WeightsClient

app = typer.Typer(help="Platform Network multi-challenge subnet CLI")
master_app = typer.Typer(help="Run master components")
validator_app = typer.Typer(help="Run normal validator components")
challenge_app = typer.Typer(help="Manage and scaffold challenges")
db_app = typer.Typer(help="Database helpers")
registry_app = typer.Typer(help="Registry helpers")
gpu_app = typer.Typer(help="Run GPU server agents")
gpu_server_app = typer.Typer(help="Manage validator GPU servers")
kubernetes_app = typer.Typer(help="Run Kubernetes maintenance tasks")
k8s_server_app = typer.Typer(help="Manage Kubernetes targets")
k8s_agent_app = typer.Typer(help="Run Kubernetes target agents")
app.add_typer(master_app, name="master")
app.add_typer(validator_app, name="validator")
app.add_typer(challenge_app, name="challenge")
app.add_typer(db_app, name="db")
app.add_typer(registry_app, name="registry")
app.add_typer(gpu_app, name="gpu-agent")
app.add_typer(gpu_server_app, name="gpu-server")
app.add_typer(kubernetes_app, name="kubernetes")
app.add_typer(k8s_server_app, name="k8s-server")
app.add_typer(k8s_agent_app, name="k8s-agent")
PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _admin_token(config: Path) -> str:
    settings = load_settings(config)
    return read_secret(
        settings.security.admin_token,
        settings.security.admin_token_file,
    )


def _admin_post(
    config: Path,
    path: str,
    payload: dict[str, object] | None = None,
) -> None:
    _admin_request(config, "POST", path, payload)


def _admin_request(
    config: Path,
    method: str,
    path: str,
    payload: dict[str, object] | None = None,
) -> None:
    settings = load_settings(config)
    token = _admin_token(config)
    url = f"{settings.master.registry_url.rstrip('/')}{path}"
    headers = {"X-Admin-Token": token} if token else {}
    with httpx.Client(timeout=30.0) as client:
        response = client.request(method, url, json=payload, headers=headers)
        response.raise_for_status()
        if response.text:
            typer.echo(response.text)


def _parse_labels(labels: list[str] | None) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in labels or []:
        key, separator, value = item.partition("=")
        if not separator or not key:
            raise typer.BadParameter("labels must use key=value format")
        parsed[key] = value
    return parsed


def _parse_rollout_targets(targets: list[str] | None) -> tuple[RolloutTarget, ...]:
    raw_targets = targets or [
        "Deployment/platform-admin",
        "Deployment/platform-proxy",
        "Deployment/platform-broker",
        "Deployment/platform-validator",
    ]
    parsed: list[RolloutTarget] = []
    for item in raw_targets:
        kind, separator, name = item.partition("/")
        if not separator or not kind or not name:
            raise typer.BadParameter("rollout targets must use Kind/name format")
        parsed.append(RolloutTarget(kind=kind, name=name))
    return tuple(parsed)


class DockerRuntimeController:
    def __init__(
        self,
        registry: Any,
        orchestrator: Any,
    ) -> None:
        self.registry = registry
        self.orchestrator = orchestrator

    async def _spec(self, slug: str) -> ChallengeSpec:
        record = await _resolve(self.registry.get(slug))
        get_broker_token = getattr(self.registry, "get_broker_token", None)
        broker_token = get_broker_token(slug) if callable(get_broker_token) else None
        return ChallengeSpec(
            slug=record.slug,
            image=record.image,
            version=record.version,
            challenge_token=self.registry.get_token(slug),
            docker_broker_token=broker_token,
            env=record.env,
            resources=ChallengeResources.from_mapping(record.resources),
            required_capabilities=tuple(record.required_capabilities),
        )

    async def pull(self, slug: str):
        spec = await self._spec(slug)
        if hasattr(self.orchestrator, "pull_challenge"):
            self.orchestrator.pull_challenge(spec)
        else:
            self.orchestrator.pull_image(spec.image)
        return {
            "slug": slug,
            "operation": "pull",
            "status": "ok",
            "detail": spec.image,
        }

    async def restart(self, slug: str):
        runtime = self.orchestrator.restart_challenge(await self._spec(slug))
        return {
            "slug": slug,
            "operation": "restart",
            "status": "ok",
            "detail": runtime.container_name,
        }

    async def status(self, slug: str):
        runtime = self.orchestrator.runtime.get(slug)
        return {
            "slug": slug,
            "operation": "status",
            "status": "running" if runtime else "unknown",
            "detail": runtime.container_name if runtime else None,
        }


async def _resolve(value):
    import inspect

    if inspect.isawaitable(value):
        return await value
    return value


def _run_startup_migrations(settings) -> None:
    from platform_network.db.migrations import upgrade

    upgrade(PROJECT_ROOT / "alembic.ini", database_url=settings.database.url)


def _master_session_factory(settings):
    engine = create_engine(settings.database.url)
    return create_session_factory(engine)


def _master_registry(settings, session_factory=None) -> DatabaseChallengeRegistry:
    return DatabaseChallengeRegistry(
        session_factory or _master_session_factory(settings),
        secret_dir=settings.docker.secret_dir,
        network=settings.network.name,
        master_uid=settings.network.master_uid,
        production_policy=production_policy_enabled_for_settings(settings),
    )


def _gpu_registry(settings) -> FileGpuServerRegistry:
    return FileGpuServerRegistry(
        settings.docker.gpu_server_state_file,
        secret_dir=settings.docker.secret_dir,
        configured_servers=settings.gpu_servers,
        production_policy=production_policy_enabled_for_settings(settings),
    )


def _kubernetes_target_registry(settings) -> FileKubernetesTargetRegistry:
    return FileKubernetesTargetRegistry(
        settings.kubernetes.target_state_file,
        secret_dir=settings.docker.secret_dir,
        configured_targets=settings.kubernetes_targets,
        production_policy=production_policy_enabled_for_settings(settings),
    )


def _gpu_clients(settings) -> dict[str, GpuAgentClient]:
    clients: dict[str, GpuAgentClient] = {}
    registry = _gpu_registry(settings)
    for server in registry.list():
        if not server.enabled:
            continue
        token = registry.get_token(server.id)
        if not token:
            raise typer.BadParameter(f"GPU server {server.id!r} is missing a token")
        clients[server.id] = GpuAgentClient(
            server_id=server.id,
            base_url=server.base_url,
            token=token,
            timeout_seconds=server.timeout_seconds,
            verify_tls=server.verify_tls,
        )
    return clients


def _master_compute_metagraph_cache(settings) -> MetagraphCache:
    return create_bittensor_runtime(settings).metagraph_cache


def _master_weight_service(
    settings,
    kubernetes_targets=None,
    metagraph_cache: MetagraphCache | None = None,
) -> MasterWeightService:
    if kubernetes_targets is None:
        kubernetes_targets = _kubernetes_target_registry(settings)
    capability_records: dict[str, Any] = (
        {target.id: target for target in kubernetes_targets.list()}
        if settings.runtime.backend == "kubernetes"
        else {server.id: server for server in _gpu_registry(settings).list()}
    )
    return MasterWeightService(
        metagraph_cache=metagraph_cache or _master_compute_metagraph_cache(settings),
        challenge_client=ChallengeClient(
            timeout_seconds=settings.master.challenge_timeout_seconds,
            retries=settings.master.challenge_retries,
            kubernetes_target_registry=(
                kubernetes_targets if settings.runtime.backend == "kubernetes" else None
            ),
        ),
        capability_checker=ResourceCapabilityChecker(capability_records),
    )


def _ensure_kubernetes_broker_backend(settings) -> None:
    if (
        settings.runtime.backend == "kubernetes"
        and settings.kubernetes.broker_backend != "kubernetes"
    ):
        raise typer.BadParameter(
            "runtime.backend=kubernetes requires kubernetes.broker_backend=kubernetes"
        )


def _challenge_orchestrator(settings) -> ChallengeOrchestratorRouter:
    if settings.runtime.backend == "kubernetes":
        _ensure_kubernetes_broker_backend(settings)
        return ChallengeOrchestratorRouter(
            local_orchestrator=KubernetesTargetRouter.from_settings(
                settings, _kubernetes_target_registry(settings)
            ),
            gpu_clients={},
        )
    return ChallengeOrchestratorRouter(
        local_orchestrator=DockerOrchestrator(
            network_name=settings.docker.network_name,
            secret_dir=settings.docker.secret_dir,
            internal_network=settings.docker.internal_network,
            docker_broker_url=settings.docker.broker_url,
        ),
        gpu_clients=_gpu_clients(settings),
    )


async def _run_master_weight_epoch(
    service: MasterWeightService,
    registry: Any,
    *,
    submit: bool = False,
) -> FinalWeights:
    challenges, tokens = await active_challenge_inputs(registry)
    return await service.run_epoch(challenges, tokens, submit=submit)


async def _run_master_weight_epoch_response(
    service: MasterWeightService,
    registry: Any,
    *,
    netuid: int,
    chain_endpoint: str,
    now_fn: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> MasterWeightsResponse:
    challenges, tokens = await active_challenge_inputs(registry)
    return await service.compute_latest_response(
        challenges,
        tokens,
        netuid=netuid,
        chain_endpoint=chain_endpoint,
        now_fn=now_fn,
    )


@master_app.command("run")
def master_run(config: Path = typer.Option(Path("config/master.example.yaml"))):
    settings = load_settings(config)
    configure_logging(settings.observability.log_json)
    import uvicorn

    _run_startup_migrations(settings)
    session_factory = _master_session_factory(settings)
    registry = _master_registry(settings, session_factory)
    orchestrator = _challenge_orchestrator(settings)
    kubernetes_targets = _kubernetes_target_registry(settings)
    admin = create_admin_app(
        registry=registry,
        runtime_controller=DockerRuntimeController(registry, orchestrator),
        gpu_registry=_gpu_registry(settings),
        kubernetes_target_registry=kubernetes_targets,
        weight_service=_master_weight_service(settings, kubernetes_targets),
        netuid=settings.network.netuid,
        chain_endpoint=settings.network.chain_endpoint or "",
        admin_token_provider=lambda: read_secret(
            settings.security.admin_token,
            settings.security.admin_token_file,
        ),
        enforce_production_policy=production_policy_enabled_for_settings(settings),
    )
    endpoint = f"{settings.master.admin_host}:{settings.master.admin_port}"
    typer.echo(f"Starting master admin API on {endpoint}")
    uvicorn.run(admin, host=settings.master.admin_host, port=settings.master.admin_port)


@master_app.command("proxy")
def master_proxy(config: Path = typer.Option(Path("config/master.example.yaml"))):
    settings = load_settings(config)
    configure_logging(settings.observability.log_json)
    import uvicorn

    _run_startup_migrations(settings)
    engine = create_engine(settings.database.url)
    session_factory = create_session_factory(engine)
    registry = _master_registry(settings, session_factory)
    kubernetes_targets = _kubernetes_target_registry(settings)
    runtime = create_bittensor_runtime(settings)
    nonce_store = SqlAlchemyMinerNonceStore(
        session_factory,
        ttl_seconds=settings.master.upload_nonce_ttl_seconds,
    )
    proxy = create_proxy_app(
        registry=registry,
        metagraph_cache=runtime.metagraph_cache,
        nonce_store=nonce_store,
        netuid=settings.network.netuid,
        upload_signature_ttl_seconds=settings.master.upload_signature_ttl_seconds,
        upload_nonce_ttl_seconds=settings.master.upload_nonce_ttl_seconds,
        upload_max_body_bytes=settings.master.upload_max_body_bytes,
        upload_require_registered_hotkey=settings.master.upload_require_registered_hotkey,
        kubernetes_target_registry=(
            kubernetes_targets if settings.runtime.backend == "kubernetes" else None
        ),
    )
    endpoint = f"{settings.master.proxy_host}:{settings.master.proxy_port}"
    typer.echo(f"Starting proxy API on {endpoint}")
    uvicorn.run(proxy, host=settings.master.proxy_host, port=settings.master.proxy_port)


@master_app.command("broker")
def master_broker(config: Path = typer.Option(Path("config/master.example.yaml"))):
    settings = load_settings(config)
    configure_logging(settings.observability.log_json)
    import uvicorn

    _run_startup_migrations(settings)
    registry = _master_registry(settings)
    _ensure_kubernetes_broker_backend(settings)
    if settings.kubernetes.broker_backend == "kubernetes":
        broker = create_kubernetes_broker_app(
            registry=registry,
            service=KubernetesBrokerRouterService.from_settings(
                settings=settings,
                challenge_registry=registry,
                target_registry=_kubernetes_target_registry(settings),
            ),
        )
    else:
        broker = create_docker_broker_app(
            registry=registry,
            service=DockerBrokerService(
                DockerBrokerConfig(
                    workspace_dir=Path(settings.docker.broker_workspace_dir),
                    allowed_images=tuple(settings.docker.broker_allowed_images),
                )
            ),
        )
    endpoint = f"{settings.docker.broker_host}:{settings.docker.broker_port}"
    typer.echo(f"Starting Docker broker API on {endpoint}")
    uvicorn.run(
        broker, host=settings.docker.broker_host, port=settings.docker.broker_port
    )


@k8s_agent_app.command("run")
def k8s_agent_run(
    config: Path = typer.Option(Path("config/master.example.yaml")),
    token: str | None = typer.Option(None, help="Kubernetes agent bearer token."),
    token_file: Path | None = typer.Option(None, help="Path containing bearer token."),
    host: str = typer.Option("0.0.0.0"),
    port: int = typer.Option(8091),
):
    settings = load_settings(config)
    configure_logging(settings.observability.log_json)
    agent_token = read_secret(token, str(token_file) if token_file else None)
    if not agent_token:
        raise typer.BadParameter("Kubernetes agent token or token file is required")
    import uvicorn

    app_instance = create_kubernetes_agent_app(
        token_provider=lambda: agent_token,
        orchestrator=KubernetesTargetRouter.from_settings(
            settings, _kubernetes_target_registry(settings)
        ).default_orchestrator,
        broker_service=KubernetesBrokerService.from_settings(settings),
    )
    typer.echo(f"Starting Kubernetes agent API on {host}:{port}")
    uvicorn.run(app_instance, host=host, port=port)


@kubernetes_app.command("sync-config")
def kubernetes_sync_config(
    namespace: str = typer.Option(..., "--namespace"),
    config_map: str = typer.Option("platform-config", "--config-map"),
    github_repository: str = typer.Option(
        "PlatformNetwork/platform",
        "--github-repository",
        "--repo",
        help="GitHub owner/repository to fetch config from.",
    ),
    github_branch: str = typer.Option(
        "main",
        "--github-branch",
        "--ref",
        help="GitHub branch or ref to fetch config from.",
    ),
    values_path: list[str] | None = typer.Option(
        None,
        "--values-path",
        help="Repository path to a YAML values/manifests file. May be repeated.",
    ),
    rollout_target: list[str] | None = typer.Option(
        None,
        "--rollout-target",
        help=(
            "Workload to annotate after config changes, as Kind/name. May be repeated."
        ),
    ),
) -> None:
    paths = tuple(values_path or ["deploy/helm/platform/values.yaml"])
    source = ConfigSyncSource(
        repository=github_repository,
        branch=github_branch,
        paths=paths,
        sync_secrets=False,
        allowed_kinds=("ConfigMap",),
    )
    rollout_targets = _parse_rollout_targets(rollout_target)
    result = create_incluster_config_sync_updater(source).sync_once(
        namespace=namespace,
        config_map=config_map,
        rollout_targets=rollout_targets,
    )
    typer.echo(result.reason)


@gpu_app.command("run")
def gpu_agent_run(
    config: Path = typer.Option(Path("config/validator.example.yaml")),
    token: str | None = typer.Option(None, help="GPU agent bearer token."),
    token_file: Path | None = typer.Option(None, help="Path containing bearer token."),
    host: str = typer.Option("0.0.0.0"),
    port: int = typer.Option(8090),
):
    settings = load_settings(config)
    configure_logging(settings.observability.log_json)
    agent_token = read_secret(token, str(token_file) if token_file else None)
    if not agent_token:
        raise typer.BadParameter("GPU agent token or token file is required")
    import uvicorn

    app_instance = create_gpu_agent_app(
        token_provider=lambda: agent_token,
        service=GpuAgentService(
            DockerOrchestrator(
                network_name=settings.docker.network_name,
                secret_dir=settings.docker.secret_dir,
                internal_network=settings.docker.internal_network,
                docker_broker_url=settings.docker.broker_url,
            )
        ),
    )
    typer.echo(f"Starting GPU agent API on {host}:{port}")
    uvicorn.run(app_instance, host=host, port=port)


@gpu_server_app.command("add")
def gpu_server_add(
    server_id: str,
    url: str = typer.Option(..., "--url"),
    token: str | None = typer.Option(None, "--token"),
    token_file: Path | None = typer.Option(None, "--token-file"),
    enabled: bool = typer.Option(True, "--enabled/--disabled"),
    verify_tls: bool = typer.Option(True, "--verify-tls/--no-verify-tls"),
    timeout_seconds: float = typer.Option(30.0),
    min_gpu_count: int = typer.Option(1),
    config: Path = typer.Option(Path("config/validator.example.yaml")),
):
    _admin_post(
        config,
        "/v1/admin/gpu-servers",
        {
            "id": server_id,
            "base_url": url,
            "token": token,
            "token_file": str(token_file) if token_file else None,
            "enabled": enabled,
            "verify_tls": verify_tls,
            "timeout_seconds": timeout_seconds,
            "min_gpu_count": min_gpu_count,
        },
    )


@gpu_server_app.command("list")
def gpu_server_list(config: Path = typer.Option(Path("config/validator.example.yaml"))):
    _admin_request(config, "GET", "/v1/admin/gpu-servers")


@gpu_server_app.command("show")
def gpu_server_show(
    server_id: str, config: Path = typer.Option(Path("config/validator.example.yaml"))
):
    _admin_request(config, "GET", f"/v1/admin/gpu-servers/{server_id}")


@gpu_server_app.command("enable")
def gpu_server_enable(
    server_id: str, config: Path = typer.Option(Path("config/validator.example.yaml"))
):
    _admin_post(config, f"/v1/admin/gpu-servers/{server_id}/enable")


@gpu_server_app.command("disable")
def gpu_server_disable(
    server_id: str, config: Path = typer.Option(Path("config/validator.example.yaml"))
):
    _admin_post(config, f"/v1/admin/gpu-servers/{server_id}/disable")


@gpu_server_app.command("remove")
def gpu_server_remove(
    server_id: str, config: Path = typer.Option(Path("config/validator.example.yaml"))
):
    _admin_request(config, "DELETE", f"/v1/admin/gpu-servers/{server_id}")


@gpu_server_app.command("health")
def gpu_server_health(
    server_id: str, config: Path = typer.Option(Path("config/validator.example.yaml"))
):
    _admin_post(config, f"/v1/admin/gpu-servers/{server_id}/health")


@k8s_server_app.command("add-kubeconfig")
def k8s_server_add_kubeconfig(
    target_id: str,
    kubeconfig_file: Path = typer.Option(..., "--kubeconfig-file"),
    api_url: str | None = typer.Option(None, "--api-url"),
    namespace: str = typer.Option("platform", "--namespace"),
    service_account: str | None = typer.Option("platform-master", "--service-account"),
    gpu_count: int = typer.Option(0, "--gpu-count"),
    storage_class: str | None = typer.Option(None, "--storage-class"),
    runtime_class_name: str | None = typer.Option(None, "--runtime-class-name"),
    enabled: bool = typer.Option(True, "--enabled/--disabled"),
    verify_tls: bool = typer.Option(True, "--verify-tls/--no-verify-tls"),
    label: list[str] | None = typer.Option(None, "--label"),
    config: Path = typer.Option(Path("config/validator.example.yaml")),
):
    _admin_post(
        config,
        "/v1/admin/kubernetes-targets",
        {
            "id": target_id,
            "mode": "direct",
            "api_url": api_url,
            "namespace": namespace,
            "service_account": service_account,
            "kubeconfig_file": str(kubeconfig_file),
            "enabled": enabled,
            "verify_tls": verify_tls,
            "gpu_count": gpu_count,
            "storage_class": storage_class,
            "runtime_class_name": runtime_class_name,
            "labels": _parse_labels(label),
        },
    )


@k8s_server_app.command("add")
def k8s_server_add_agent(
    target_id: str,
    url: str = typer.Option(..., "--url", help="Kubernetes agent URL."),
    token: str | None = typer.Option(None, "--token"),
    token_file: Path | None = typer.Option(None, "--token-file"),
    gpu_count: int = typer.Option(1, "--gpu-count"),
    enabled: bool = typer.Option(True, "--enabled/--disabled"),
    verify_tls: bool = typer.Option(True, "--verify-tls/--no-verify-tls"),
    timeout_seconds: float = typer.Option(30.0),
    label: list[str] | None = typer.Option(None, "--label"),
    config: Path = typer.Option(Path("config/validator.example.yaml")),
):
    agent_token = read_secret(token, str(token_file) if token_file else None)
    if not agent_token:
        raise typer.BadParameter("Kubernetes agent token or token file is required")
    _admin_post(
        config,
        "/v1/admin/kubernetes-targets",
        {
            "id": target_id,
            "mode": "agent",
            "agent_url": url,
            "agent_token": agent_token,
            "enabled": enabled,
            "verify_tls": verify_tls,
            "timeout_seconds": timeout_seconds,
            "gpu_count": gpu_count,
            "labels": _parse_labels(label),
        },
    )


@k8s_server_app.command("list")
def k8s_server_list(config: Path = typer.Option(Path("config/validator.example.yaml"))):
    _admin_request(config, "GET", "/v1/admin/kubernetes-targets")


@k8s_server_app.command("show")
def k8s_server_show(
    target_id: str, config: Path = typer.Option(Path("config/validator.example.yaml"))
):
    _admin_request(config, "GET", f"/v1/admin/kubernetes-targets/{target_id}")


@k8s_server_app.command("health")
def k8s_server_health(
    target_id: str, config: Path = typer.Option(Path("config/validator.example.yaml"))
):
    _admin_post(config, f"/v1/admin/kubernetes-targets/{target_id}/health")


@k8s_server_app.command("enable")
def k8s_server_enable(
    target_id: str, config: Path = typer.Option(Path("config/validator.example.yaml"))
):
    _admin_post(config, f"/v1/admin/kubernetes-targets/{target_id}/enable")


@k8s_server_app.command("disable")
def k8s_server_disable(
    target_id: str, config: Path = typer.Option(Path("config/validator.example.yaml"))
):
    _admin_post(config, f"/v1/admin/kubernetes-targets/{target_id}/disable")


@k8s_server_app.command("remove")
def k8s_server_remove(
    target_id: str, config: Path = typer.Option(Path("config/validator.example.yaml"))
):
    _admin_request(config, "DELETE", f"/v1/admin/kubernetes-targets/{target_id}")


@master_app.command("refresh-challenge-images")
def master_refresh_challenge_images(
    config: Path = typer.Option(Path("config/master.example.yaml")),
    tag: str = typer.Option("latest", "--tag"),
):
    settings = load_settings(config)
    registry = _master_registry(settings)
    controller = DockerRuntimeController(registry, _challenge_orchestrator(settings))

    def mutable_base(image: str) -> str | None:
        from platform_network.validator.image_updater import parse_image_reference

        parsed = parse_image_reference(image)
        if parsed.registry != "ghcr.io":
            return None
        if parsed.tag.startswith("sha-"):
            return None
        return f"{parsed.registry}/{parsed.repository}:{tag}"

    async def refresh() -> None:
        from platform_network.kubernetes.client import KubernetesClient
        from platform_network.kubernetes.names import challenge_name
        from platform_network.schemas.challenge import ChallengeStatus, ChallengeUpdate
        from platform_network.validator.image_updater import (
            parse_image_reference,
            resolve_remote_digest,
        )

        kube_client = (
            KubernetesClient(
                namespace=settings.kubernetes.namespace,
                in_cluster=settings.kubernetes.in_cluster,
                kubeconfig=settings.kubernetes.kubeconfig,
            )
            if settings.runtime.backend == "kubernetes"
            else None
        )

        for record in await registry.list():
            if record.status in {ChallengeStatus.DRAFT, ChallengeStatus.DISABLED}:
                continue
            base = mutable_base(record.image)
            if base is None:
                typer.echo(f"{record.slug}: skipped {record.image}")
                continue
            digest = resolve_remote_digest(parse_image_reference(base))
            desired = f"{base}@{digest}"
            changed = desired != record.image
            if changed:
                await registry.update(record.slug, ChallengeUpdate(image=desired))
                typer.echo(f"{record.slug}: updated {desired}")
            else:
                typer.echo(f"{record.slug}: already-current {desired}")
            if record.status == ChallengeStatus.ACTIVE:
                if kube_client is not None:
                    workload_name = challenge_name(record.slug)
                    workload_kind = (
                        "StatefulSet"
                        if settings.kubernetes.challenge_mode == "statefulset"
                        else "Deployment"
                    )
                    kube_client.patch_workload_image(
                        kind=workload_kind,
                        name=workload_name,
                        container="challenge",
                        image=desired,
                    )
                    typer.echo(
                        f"{record.slug}: patched {workload_kind}/{workload_name}"
                    )
                elif changed:
                    result = await controller.restart(record.slug)
                    typer.echo(f"{record.slug}: restarted {result['status']}")

    asyncio.run(refresh())


@master_app.command("weights")
def master_weights(
    config: Path = typer.Option(Path("config/master.example.yaml")),
    once: bool = typer.Option(False, "--once/--loop"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    submit_on_chain: bool = typer.Option(
        False,
        "--submit-on-chain",
        help="Unsafe compatibility path: submit computed master weights on-chain.",
    ),
):
    settings = load_settings(config)
    configure_logging(settings.observability.log_json)
    _run_startup_migrations(settings)
    registry = _master_registry(settings)
    runtime = create_bittensor_runtime(settings)
    kubernetes_targets = _kubernetes_target_registry(settings)
    service = _master_weight_service(
        settings,
        kubernetes_targets,
        metagraph_cache=runtime.metagraph_cache,
    )
    if submit_on_chain and not dry_run:
        if runtime.weight_setter is None:
            runtime = create_bittensor_submit_runtime(settings)
        service.weight_setter = runtime.weight_setter

    async def epoch() -> None:
        submit = submit_on_chain and not dry_run
        final = await _run_master_weight_epoch(service, registry, submit=submit)
        action = "submit-on-chain" if submit else "compute-only"
        typer.echo(f"{action}: computed {len(final.uids)} weights")

    if once:
        asyncio.run(epoch())
        return
    asyncio.run(run_epoch_loop(settings.master.epoch_interval_seconds, epoch))


async def _run_validator_runtime(
    runner: NormalValidatorRunner,
    weights_interval_seconds: int,
) -> None:
    async def submit_weights() -> None:
        await runner.submit_latest_weights()

    await asyncio.gather(
        runner.run_forever(),
        run_epoch_loop(weights_interval_seconds, submit_weights),
    )


@validator_app.command("run")
def validator_run(config: Path = typer.Option(Path("config/validator.example.yaml"))):
    settings = load_settings(config)
    configure_logging(settings.observability.log_json)
    runtime = create_bittensor_submit_runtime(settings)
    runner = NormalValidatorRunner(
        registry_client=RegistryClient(settings.validator.registry_url),
        orchestrator=_challenge_orchestrator(settings),
        retry_seconds=settings.validator.registry_retry_seconds,
        weights_client=WeightsClient(
            settings.validator.resolved_weights_url,
            timeout_seconds=settings.validator.weights_timeout_seconds,
            retries=settings.validator.weights_retries,
        ),
        weight_setter=runtime.weight_setter,
        netuid=settings.network.netuid,
        weights_freshness_seconds=settings.validator.weights_freshness_seconds,
    )
    asyncio.run(
        _run_validator_runtime(runner, settings.validator.weights_interval_seconds)
    )


@validator_app.command("refresh-image")
def validator_refresh_image(
    namespace: str = typer.Option(..., "--namespace"),
    deployment: str | None = typer.Option(None, "--deployment"),
    name: str | None = typer.Option(None, "--name"),
    resource_kind: str = typer.Option("deployment", "--resource-kind"),
    container: str = typer.Option("validator", "--container"),
    image: str = typer.Option(..., "--image"),
    registry_endpoint: str = typer.Option("", "--registry-endpoint"),
):
    updated = create_incluster_updater().refresh(
        namespace=namespace,
        deployment=deployment,
        name=name,
        resource_kind=resource_kind,
        container=container,
        image=image,
        registry_endpoint=registry_endpoint or None,
    )
    typer.echo("updated" if updated else "already-current")


@challenge_app.command("create")
def challenge_create(
    slug: str,
    out: Path = typer.Option(..., "--out", help="Destination challenge repo path."),
    name: str | None = None,
    image: str | None = None,
    version: str = "0.1.0",
    overwrite: bool = False,
):
    context = ChallengeTemplateContext.from_slug(
        slug, name=name, ghcr_image=image, challenge_version=version
    )
    written = render_challenge_template(out, context, overwrite=overwrite)
    typer.echo(f"Created challenge template at {out} ({len(written)} files)")


@challenge_app.command("register")
def challenge_register(
    slug: str,
    image: str,
    emission: float,
    name: str | None = None,
    config: Path = typer.Option(Path("config/master.example.yaml")),
):
    _admin_post(
        config,
        "/v1/admin/challenges",
        {
            "slug": slug,
            "name": name or slug,
            "image": image,
            "version": image.rsplit(":", 1)[-1] if ":" in image else "latest",
            "emission_percent": emission,
        },
    )


@challenge_app.command("activate")
def challenge_activate(
    slug: str, config: Path = typer.Option(Path("config/master.example.yaml"))
):
    _admin_post(config, f"/v1/admin/challenges/{slug}/activate")


@challenge_app.command("deactivate")
def challenge_deactivate(
    slug: str, config: Path = typer.Option(Path("config/master.example.yaml"))
):
    _admin_post(config, f"/v1/admin/challenges/{slug}/deactivate")


@challenge_app.command("pull")
def challenge_pull(
    slug: str, config: Path = typer.Option(Path("config/master.example.yaml"))
):
    _admin_post(config, f"/v1/admin/challenges/{slug}/pull")


@challenge_app.command("restart")
def challenge_restart(
    slug: str, config: Path = typer.Option(Path("config/master.example.yaml"))
):
    _admin_post(config, f"/v1/admin/challenges/{slug}/restart")


@db_app.command("migrate")
def db_migrate(config: Path = typer.Option(Path("config/master.example.yaml"))):
    from platform_network.db.migrations import upgrade

    settings = load_settings(config)
    upgrade(PROJECT_ROOT / "alembic.ini", database_url=settings.database.url)


@db_app.command("revision")
def db_revision(message: str):
    from alembic.config import Config

    from alembic import command

    command.revision(
        Config(str(PROJECT_ROOT / "alembic.ini")),
        message=message,
        autogenerate=True,
    )


@registry_app.command("print")
def registry_print(config: Path = typer.Option(Path("config/validator.example.yaml"))):
    settings = load_settings(config)
    client = RegistryClient(settings.validator.registry_url)
    registry = asyncio.run(client.fetch_registry())
    typer.echo(registry.model_dump_json(indent=2))


if __name__ == "__main__":
    app()
