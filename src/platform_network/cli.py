from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import typer

from platform_network.config import load_settings
from platform_network.master.app_admin import create_admin_app
from platform_network.master.app_proxy import create_proxy_app
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
from platform_network.master.registry import FileChallengeRegistry
from platform_network.observability.logging import configure_logging
from platform_network.security.admin_auth import read_secret
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
app.add_typer(master_app, name="master")
app.add_typer(validator_app, name="validator")
app.add_typer(challenge_app, name="challenge")
app.add_typer(db_app, name="db")
app.add_typer(registry_app, name="registry")
PROJECT_ROOT = Path(__file__).resolve().parents[2]


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
    settings = load_settings(config)
    token = _admin_token(config)
    url = f"{settings.master.registry_url.rstrip('/')}{path}"
    headers = {"X-Admin-Token": token} if token else {}
    with httpx.Client(timeout=30.0) as client:
        response = client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        typer.echo(response.text)


class DockerRuntimeController:
    def __init__(
        self,
        registry: FileChallengeRegistry,
        orchestrator: DockerOrchestrator,
    ) -> None:
        self.registry = registry
        self.orchestrator = orchestrator

    def _spec(self, slug: str) -> ChallengeSpec:
        record = self.registry.get(slug)
        return ChallengeSpec(
            slug=record.slug,
            image=record.image,
            version=record.version,
            challenge_token=self.registry.get_token(slug),
            env=record.env,
            resources=ChallengeResources.from_mapping(record.resources),
            required_capabilities=tuple(record.required_capabilities),
        )

    async def pull(self, slug: str):
        spec = self._spec(slug)
        self.orchestrator.pull_image(spec.image)
        return {
            "slug": slug,
            "operation": "pull",
            "status": "ok",
            "detail": spec.image,
        }

    async def restart(self, slug: str):
        runtime = self.orchestrator.restart_challenge(self._spec(slug))
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


@master_app.command("run")
def master_run(config: Path = typer.Option(Path("config/master.example.yaml"))):
    settings = load_settings(config)
    configure_logging(settings.observability.log_json)
    import uvicorn

    registry = FileChallengeRegistry(
        settings.master.registry_state_file,
        secret_dir=settings.docker.secret_dir,
        master_uid=settings.network.master_uid,
    )
    orchestrator = DockerOrchestrator(
        network_name=settings.docker.network_name,
        secret_dir=settings.docker.secret_dir,
        internal_network=settings.docker.internal_network,
        docker_broker_url=settings.docker.broker_url,
    )
    admin = create_admin_app(
        registry=registry,
        runtime_controller=DockerRuntimeController(registry, orchestrator),
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

    registry = FileChallengeRegistry(
        settings.master.registry_state_file,
        secret_dir=settings.docker.secret_dir,
        master_uid=settings.network.master_uid,
    )
    proxy = create_proxy_app(
        registry=registry,
    )
    endpoint = f"{settings.master.proxy_host}:{settings.master.proxy_port}"
    typer.echo(f"Starting proxy API on {endpoint}")
    uvicorn.run(proxy, host=settings.master.proxy_host, port=settings.master.proxy_port)


@master_app.command("broker")
def master_broker(config: Path = typer.Option(Path("config/master.example.yaml"))):
    settings = load_settings(config)
    configure_logging(settings.observability.log_json)
    import uvicorn

    registry = FileChallengeRegistry(
        settings.master.registry_state_file,
        secret_dir=settings.docker.secret_dir,
        master_uid=settings.network.master_uid,
    )
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


@validator_app.command("run")
def validator_run(config: Path = typer.Option(Path("config/validator.example.yaml"))):
    settings = load_settings(config)
    configure_logging(settings.observability.log_json)
    runner = NormalValidatorRunner(
        registry_client=RegistryClient(settings.validator.registry_url),
        orchestrator=DockerOrchestrator(
            network_name=settings.docker.network_name,
            secret_dir=settings.docker.secret_dir,
            internal_network=settings.docker.internal_network,
            docker_broker_url=settings.docker.broker_url,
        ),
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
