from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import httpx
import typer

from platform_network.bittensor.factory import create_bittensor_runtime
from platform_network.bittensor.validator_loop import run_epoch_loop
from platform_network.config import load_settings
from platform_network.db.session import create_engine, create_session_factory
from platform_network.gpu.agent import GpuAgentService, create_gpu_agent_app
from platform_network.gpu.capabilities import ResourceCapabilityChecker
from platform_network.gpu.client import GpuAgentClient
from platform_network.gpu.registry import FileGpuServerRegistry
from platform_network.gpu.router import ChallengeOrchestratorRouter
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
from platform_network.master.registry import (
    DatabaseChallengeRegistry,
    record_to_registry_view,
)
from platform_network.master.service import MasterWeightService
from platform_network.observability.logging import configure_logging
from platform_network.schemas.weights import FinalWeights
from platform_network.security.admin_auth import read_secret
from platform_network.security.miner_auth import SqlAlchemyMinerNonceStore
from platform_network.template_engine import (
    ChallengeTemplateContext,
    render_challenge_template,
)
from platform_network.validator.normal_runner import NormalValidatorRunner
from platform_network.validator.registry_client import RegistryClient

app = typer.Typer(help="Platform Network multi-challenge subnet CLI")
master_app = typer.Typer(help="Run master components")
validator_app = typer.Typer(help="Run normal validator components")
challenge_app = typer.Typer(help="Manage and scaffold challenges")
db_app = typer.Typer(help="Database helpers")
registry_app = typer.Typer(help="Registry helpers")
gpu_app = typer.Typer(help="Run GPU server agents")
gpu_server_app = typer.Typer(help="Manage validator GPU servers")
app.add_typer(master_app, name="master")
app.add_typer(validator_app, name="validator")
app.add_typer(challenge_app, name="challenge")
app.add_typer(db_app, name="db")
app.add_typer(registry_app, name="registry")
app.add_typer(gpu_app, name="gpu-agent")
app.add_typer(gpu_server_app, name="gpu-server")
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
    )


def _gpu_registry(settings) -> FileGpuServerRegistry:
    return FileGpuServerRegistry(
        settings.docker.gpu_server_state_file,
        secret_dir=settings.docker.secret_dir,
        configured_servers=settings.gpu_servers,
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


def _challenge_orchestrator(settings) -> ChallengeOrchestratorRouter:
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
) -> FinalWeights:
    records = await _resolve(registry.list(active_only=True))
    challenges = [record_to_registry_view(record) for record in records]
    tokens = {record.slug: registry.get_token(record.slug) for record in records}
    return await service.run_epoch(challenges, tokens)


@master_app.command("run")
def master_run(config: Path = typer.Option(Path("config/master.example.yaml"))):
    settings = load_settings(config)
    configure_logging(settings.observability.log_json)
    import uvicorn

    _run_startup_migrations(settings)
    session_factory = _master_session_factory(settings)
    registry = _master_registry(settings, session_factory)
    orchestrator = _challenge_orchestrator(settings)
    admin = create_admin_app(
        registry=registry,
        runtime_controller=DockerRuntimeController(registry, orchestrator),
        gpu_registry=_gpu_registry(settings),
        admin_token_provider=lambda: read_secret(
            settings.security.admin_token,
            settings.security.admin_token_file,
        ),
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


@master_app.command("weights")
def master_weights(
    config: Path = typer.Option(Path("config/master.example.yaml")),
    once: bool = typer.Option(False, "--once/--loop"),
):
    settings = load_settings(config)
    configure_logging(settings.observability.log_json)
    _run_startup_migrations(settings)
    registry = _master_registry(settings)
    runtime = create_bittensor_runtime(settings)
    gpu_registry = _gpu_registry(settings)
    service = MasterWeightService(
        metagraph_cache=runtime.metagraph_cache,
        weight_setter=runtime.weight_setter,
        challenge_client=ChallengeClient(
            timeout_seconds=settings.master.challenge_timeout_seconds,
            retries=settings.master.challenge_retries,
        ),
        capability_checker=ResourceCapabilityChecker(
            {server.id: server for server in gpu_registry.list()}
        ),
    )

    async def epoch() -> None:
        final = await _run_master_weight_epoch(service, registry)
        typer.echo(f"submit: computed {len(final.uids)} weights")

    if once:
        asyncio.run(epoch())
        return
    asyncio.run(run_epoch_loop(settings.master.epoch_interval_seconds, epoch))


@validator_app.command("run")
def validator_run(config: Path = typer.Option(Path("config/validator.example.yaml"))):
    settings = load_settings(config)
    configure_logging(settings.observability.log_json)
    runner = NormalValidatorRunner(
        registry_client=RegistryClient(settings.validator.registry_url),
        orchestrator=_challenge_orchestrator(settings),
        retry_seconds=settings.validator.registry_retry_seconds,
    )
    asyncio.run(runner.run_forever())


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
