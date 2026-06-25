from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import typer

from base.bittensor.factory import (
    create_bittensor_runtime,
    create_bittensor_submit_runtime,
)
from base.bittensor.metagraph_cache import MetagraphCache
from base.bittensor.validator_loop import run_epoch_loop
from base.config import load_settings
from base.config.policy import production_policy_enabled_for_settings
from base.db.session import create_engine, create_session_factory
from base.master.app_proxy import create_proxy_app
from base.master.challenge_client import ChallengeClient
from base.master.docker_broker import create_docker_broker_app
from base.master.docker_orchestrator import (
    DEFAULT_SECRET_MOUNT_DIR,
    ChallengeResources,
    ChallengeSpec,
    port_from_internal_base_url,
    worker_command_from_metadata,
)
from base.master.registry import (
    ChallengeNotFoundError,
    DatabaseChallengeRegistry,
)
from base.master.service import (
    MasterWeightService,
    active_challenge_inputs,
)
from base.observability.logging import configure_logging
from base.schemas.challenge import (
    ChallengeCreate,
    ChallengeStatus,
    ChallengeUpdate,
)
from base.schemas.weights import FinalWeights, MasterWeightsResponse
from base.security.admin_auth import read_secret
from base.security.miner_auth import SqlAlchemyMinerNonceStore
from base.template_engine import (
    ChallengeTemplateContext,
    render_challenge_template,
)
from base.validator.normal_runner import NormalValidatorRunner
from base.validator.registry_client import RegistryClient
from base.validator.weights_client import WeightsClient

app = typer.Typer(help="BASE multi-challenge subnet CLI")
master_app = typer.Typer(help="Run master components")
master_challenges_app = typer.Typer(help="Manage master challenge records")
validator_app = typer.Typer(help="Run normal validator components")
challenge_app = typer.Typer(help="Manage and scaffold challenges")
db_app = typer.Typer(help="Database helpers")
registry_app = typer.Typer(help="Registry helpers")
worker_app = typer.Typer(help="Manage Swarm workers (CPU/GPU job nodes)")
master_app.add_typer(master_challenges_app, name="challenges")
master_app.add_typer(worker_app, name="worker")
app.add_typer(master_app, name="master")
app.add_typer(validator_app, name="validator")
app.add_typer(challenge_app, name="challenge")
app.add_typer(db_app, name="db")
app.add_typer(registry_app, name="registry")
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
        # Record-declared secret names beyond the per-slug registry tokens
        # (e.g. agent-challenge's submission_env_encryption_key) have no value
        # source on the master; they are provisioned out-of-band and carried
        # as external references so the Swarm backend mounts the pre-created
        # docker secrets without ever handling the values.
        external_secrets = tuple(
            name
            for name in (getattr(record, "secrets", []) or [])
            if name not in ("challenge_token", "docker_broker_token")
        )
        return ChallengeSpec(
            slug=record.slug,
            image=record.image,
            version=record.version,
            challenge_token=self.registry.get_token(slug),
            docker_broker_token=broker_token,
            env=record.env,
            external_secrets=external_secrets,
            resources=ChallengeResources.from_mapping(record.resources),
            required_capabilities=tuple(record.required_capabilities),
            port=port_from_internal_base_url(
                getattr(record, "internal_base_url", None)
            ),
            worker_command=worker_command_from_metadata(
                getattr(record, "metadata", {}) or {}
            ),
            workload_class="service",
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
    from base.db.migrations import upgrade

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


def _master_compute_metagraph_cache(settings) -> MetagraphCache:
    return create_bittensor_runtime(settings).metagraph_cache


def _master_weight_service(
    settings,
    metagraph_cache: MetagraphCache | None = None,
) -> MasterWeightService:
    return MasterWeightService(
        metagraph_cache=metagraph_cache or _master_compute_metagraph_cache(settings),
        challenge_client=ChallengeClient(
            timeout_seconds=settings.master.challenge_timeout_seconds,
            retries=settings.master.challenge_retries,
        ),
    )


def _challenge_orchestrator(settings):
    from base.master.swarm_backend import SwarmChallengeOrchestrator

    return SwarmChallengeOrchestrator(
        network_name=settings.docker.network_name,
        internal_network=settings.docker.internal_network,
        docker_broker_url=settings.docker.broker_url,
        challenge_placement_constraint=settings.docker.challenge_placement_constraint,
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


PRISM_SLUG = "prism"
AGENT_CHALLENGE_SLUG = "agent-challenge"
AGENT_CHALLENGE_TERMINAL_BENCH_RUNNER_IMAGE = (
    "ghcr.io/baseintelligence/agent-challenge-terminal-bench-runner:latest"
)
AGENT_CHALLENGE_SUBMISSION_ENV_SECRET = "submission_env_encryption_key"
AGENT_CHALLENGE_SUBMISSION_ENV_KEY_FILE = (
    f"{DEFAULT_SECRET_MOUNT_DIR}/{AGENT_CHALLENGE_SUBMISSION_ENV_SECRET}"
)
#: own_runner reads the task cache + frozen digest manifest from these in-job
#: paths; the broker bind-mounts them read-only (``broker_eval_readonly_mounts``)
#: from a host path or named volume provisioned out-of-band by
#: ``deploy/swarm/acquire-agent-challenge-cache.sh``.
AGENT_CHALLENGE_TASK_CACHE_DIR = "/opt/agent-challenge/task-cache"
AGENT_CHALLENGE_GOLDEN_DIR = "/opt/agent-challenge/golden"
#: Challenge API service DNS on the challenges overlay (matches
#: ``default_internal_base_url("agent-challenge")``); own_runner jobs POST
#: real-time trial logs here.
AGENT_CHALLENGE_INTERNAL_BASE_URL = "http://challenge-agent-challenge:8000"
#: Overlay the DooD eval job attaches to so it can reach the challenge API for
#: log streaming (matches the install-swarm.sh challenges network).
AGENT_CHALLENGE_JOB_NETWORK = "base_challenges"
PRISM_IMAGE = "ghcr.io/baseintelligence/prism:latest"
PRISM_EVALUATOR_IMAGE = "ghcr.io/baseintelligence/prism-evaluator:latest"
PRISM_VERSION = "0.1.0"
PRISM_EMISSION_PERCENT = Decimal("30")
AGENT_CHALLENGE_EMISSION_PERCENT = Decimal("15")
DEFAULT_BASE_BROKER_URL = "http://base-docker-broker:8082"


def _settings_docker_broker_url(settings: Any | None) -> str:
    docker_settings = getattr(settings, "docker", None)
    broker_url = getattr(docker_settings, "broker_url", None)
    return str(broker_url or DEFAULT_BASE_BROKER_URL)


def _parse_eval_readonly_mounts(values: list[str]) -> tuple[tuple[str, str], ...]:
    """Parse ``source:target`` mount specs into ``(source, target)`` tuples.

    ``source`` is an absolute host path or a Docker named volume; ``target`` is
    the absolute container mount path (split on the final ``:`` so neither side
    may itself contain a colon). Malformed entries are skipped.
    """
    parsed: list[tuple[str, str]] = []
    for raw in values:
        source, sep, target = raw.rpartition(":")
        if not sep or not source or not target.startswith("/"):
            continue
        parsed.append((source, target))
    return tuple(parsed)


#: Miner-visible mount target for the locked FineWeb-Edu TRAIN split; the
#: secret val/test splits are NEVER mounted into the eval container. The prism
#: evaluator's ``ctx.data_dir`` resolves to this read-only path.
PRISM_FINEWEB_EDU_TRAIN_DIR = "/data/fineweb-edu/train"
#: Mount target for the offline reference tokenizers (gpt2 tiktoken cache +
#: non-gated llama sentencepiece ``.model``).
PRISM_REFERENCE_TOKENIZER_DIR = "/opt/prism/reference-tokenizers"
#: Docker named volumes staged READ-ONLY on the GPU node (out-of-band, NOT
#: in-band tar) by the data-staging deploy feature. Only the train volume is
#: bound into the miner container; the held-out splits live in separate volumes
#: the eval container never mounts.
PRISM_FINEWEB_EDU_TRAIN_VOLUME = "prism_fineweb_edu_train"
PRISM_REFERENCE_TOKENIZER_VOLUME = "prism_reference_tokenizers"
#: Built-in prism locked-data read-only mounts: train split + reference
#: tokenizers, applied unless ``broker_eval_readonly_mounts_by_slug`` overrides
#: the prism slug. Keeps the broker wiring live before deploy config exists.
DEFAULT_PRISM_EVAL_READONLY_MOUNTS: tuple[tuple[str, str], ...] = (
    (PRISM_FINEWEB_EDU_TRAIN_VOLUME, PRISM_FINEWEB_EDU_TRAIN_DIR),
    (PRISM_REFERENCE_TOKENIZER_VOLUME, PRISM_REFERENCE_TOKENIZER_DIR),
)


def _eval_readonly_mounts_by_slug(
    configured: Mapping[str, list[str]] | None,
) -> dict[str, tuple[tuple[str, str], ...]]:
    """Resolve the per-slug read-only eval mounts for the broker.

    The prism slug receives :data:`DEFAULT_PRISM_EVAL_READONLY_MOUNTS` so the
    locked train split + reference tokenizers bind-mount READ-ONLY into the
    eval container out of the box. Any slug present in ``configured`` (from
    ``docker.broker_eval_readonly_mounts_by_slug``) overrides that default with
    its parsed ``source:target`` specs.
    """
    resolved: dict[str, tuple[tuple[str, str], ...]] = {
        PRISM_SLUG: DEFAULT_PRISM_EVAL_READONLY_MOUNTS,
    }
    for slug, specs in (configured or {}).items():
        resolved[slug] = _parse_eval_readonly_mounts(specs)
    return resolved


def _egress_locked_slugs(configured: list[str] | None) -> frozenset[str]:
    """Resolve the egress-locked eval slugs for the broker.

    The prism slug is locked by default so its untrusted eval job is pinned to
    the internal (no external route) overlay out of the box; any slug present
    in ``docker.broker_egress_locked_slugs`` is added to that allowlist.
    """
    return frozenset({PRISM_SLUG, *(configured or ())})


def _prism_image_for_settings(image: str, settings: Any | None) -> str:
    if settings is None or not production_policy_enabled_for_settings(settings):
        return image
    from base.supervisor.image_ref import (
        parse_image_reference,
        resolve_remote_digest,
    )

    reference = parse_image_reference(image)
    if reference.immutable:
        return image
    return reference.pinned(resolve_remote_digest(reference))


def _agent_challenge_own_runner_env(settings: Any | None) -> dict[str, str]:
    """Env for the agent-challenge own_runner Swarm DooD execution plane.

    The challenge's config validator accepts only
    ``terminal_bench_execution_backend == "own_runner"``; this wires the
    own_runner knobs: the runner job image (``CHALLENGE_HARBOR_RUNNER_IMAGE``,
    the legacy knob name own_runner reads), the read-only task-cache + frozen
    digest manifest mount targets (broker-injected via
    ``broker_eval_readonly_mounts``), the per-attempt log-stream URL, and the
    overlay the job attaches to so it can reach the challenge API.
    """
    broker_url = _settings_docker_broker_url(settings)
    docker_broker_token_file = f"{DEFAULT_SECRET_MOUNT_DIR}/docker_broker_token"
    return {
        "CHALLENGE_BENCHMARK_BACKEND": "terminal_bench",
        "CHALLENGE_DOCKER_ENABLED": "true",
        "CHALLENGE_DOCKER_BACKEND": "broker",
        "CHALLENGE_DOCKER_BROKER_URL": broker_url,
        "CHALLENGE_DOCKER_BROKER_TOKEN_FILE": docker_broker_token_file,
        "CHALLENGE_DOCKER_BROKER_NETWORK": AGENT_CHALLENGE_JOB_NETWORK,
        "CHALLENGE_TERMINAL_BENCH_EXECUTION_BACKEND": "own_runner",
        "CHALLENGE_HARBOR_RUNNER_IMAGE": AGENT_CHALLENGE_TERMINAL_BENCH_RUNNER_IMAGE,
        "CHALLENGE_OWN_RUNNER_CACHE_ROOT": AGENT_CHALLENGE_TASK_CACHE_DIR,
        "CHALLENGE_OWN_RUNNER_DIGEST_MANIFEST": (
            f"{AGENT_CHALLENGE_GOLDEN_DIR}/dataset-digest.json"
        ),
        "CHALLENGE_TERMINAL_BENCH_LOG_STREAM_URL": AGENT_CHALLENGE_INTERNAL_BASE_URL,
        "CHALLENGE_SUBMISSION_ENV_ENCRYPTION_KEY_FILE": (
            AGENT_CHALLENGE_SUBMISSION_ENV_KEY_FILE
        ),
    }


def _agent_challenge_secret_names(existing: list[str] | None = None) -> list[str]:
    names = [
        "challenge_token",
        "docker_broker_token",
        AGENT_CHALLENGE_SUBMISSION_ENV_SECRET,
    ]
    for name in existing or []:
        if name not in names:
            names.append(name)
    return names


def prism_challenge_create(settings: Any | None = None) -> ChallengeCreate:
    challenge_token_file = f"{DEFAULT_SECRET_MOUNT_DIR}/challenge_token"
    docker_broker_token_file = f"{DEFAULT_SECRET_MOUNT_DIR}/docker_broker_token"
    broker_url = _settings_docker_broker_url(settings)
    prism_image = _prism_image_for_settings(PRISM_IMAGE, settings)
    evaluator_image = _prism_image_for_settings(PRISM_EVALUATOR_IMAGE, settings)
    return ChallengeCreate(
        slug=PRISM_SLUG,
        name="PRISM",
        image=prism_image,
        version=PRISM_VERSION,
        emission_percent=PRISM_EMISSION_PERCENT,
        status=ChallengeStatus.ACTIVE,
        description="PRISM architecture and training reward challenge.",
        internal_base_url="http://challenge-prism:8080",
        required_capabilities=["get_weights", "proxy_routes"],
        resources={
            "cpu": "2",
            "memory": "8g",
        },
        volumes={"data": "/data"},
        env={
            "PRISM_SHARED_TOKEN_FILE": challenge_token_file,
            "CHALLENGE_SHARED_TOKEN_FILE": challenge_token_file,
            "PRISM_DOCKER_ENABLED": "true",
            "PRISM_DOCKER_BACKEND": "broker",
            "CHALLENGE_DOCKER_BACKEND": "broker",
            "PRISM_DOCKER_BROKER_URL": broker_url,
            "CHALLENGE_DOCKER_BROKER_URL": broker_url,
            "PRISM_DOCKER_BROKER_TOKEN_FILE": docker_broker_token_file,
            "CHALLENGE_DOCKER_BROKER_TOKEN_FILE": docker_broker_token_file,
            "PRISM_BASE_EVAL_IMAGE": evaluator_image,
        },
        secrets=["challenge_token", "docker_broker_token"],
        metadata={
            "repository_url": "https://github.com/BaseIntelligence/prism",
            "category": "Agentic (Multi-step)",
            "benchmark_label": "PRISM architecture and training reward boards",
            "evaluation_timeout_seconds": 900,
            "submission_format": "zip",
            # Task 24: PRISM metadata DB is SQLite on the challenge's named
            # LOCAL docker volume (base_prism_sqlite -> /data), WAL mode,
            # single writer (replicas=1). The retired managed Postgres is
            # archived to disk by scripts/archive_prism_postgres.sh (never
            # imported). workload_class is declarative here; the scheduling
            # authority remains ChallengeSpec.workload_class / Swarm Spec.Mode.
            "runtime_database": "challenge-local-sqlite",
            "runtime_database_url": "sqlite+aiosqlite:////data/challenge.sqlite3",
            "runtime_database_journal_mode": "wal",
            "workload_class": "service",
            "base_eval_image": evaluator_image,
            "base_eval_gpu_count": "1",
            "base_eval_max_gpu_count": "8",
        },
    )


def _prism_challenge_update(settings: Any | None = None) -> ChallengeUpdate:
    payload = prism_challenge_create(settings)
    data = payload.model_dump(exclude={"slug"})
    return ChallengeUpdate(**data)


async def seed_prism_challenges(
    registry: Any, settings: Any | None = None
) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        await _resolve(registry.get(PRISM_SLUG))
    except (ChallengeNotFoundError, KeyError):
        await _resolve(registry.create(prism_challenge_create(settings)))
        result[PRISM_SLUG] = "created"
    else:
        await _resolve(registry.update(PRISM_SLUG, _prism_challenge_update(settings)))
        result[PRISM_SLUG] = "updated"

    try:
        await _resolve(registry.get(AGENT_CHALLENGE_SLUG))
    except (ChallengeNotFoundError, KeyError):
        result[AGENT_CHALLENGE_SLUG] = "missing"
    else:
        record = await _resolve(registry.get(AGENT_CHALLENGE_SLUG))
        metadata = dict(getattr(record, "metadata", {}) or {})
        metadata["worker_command"] = ["agent-challenge-worker"]
        env = dict(getattr(record, "env", {}) or {})
        env.update(_agent_challenge_own_runner_env(settings))
        required_capabilities = set(getattr(record, "required_capabilities", []) or [])
        required_capabilities.update({"docker_executor", "get_weights", "proxy_routes"})
        await _resolve(
            registry.update(
                AGENT_CHALLENGE_SLUG,
                ChallengeUpdate(
                    emission_percent=AGENT_CHALLENGE_EMISSION_PERCENT,
                    env=env,
                    metadata=metadata,
                    required_capabilities=sorted(required_capabilities),
                    secrets=_agent_challenge_secret_names(
                        list(getattr(record, "secrets", []) or [])
                    ),
                ),
            )
        )
        result[AGENT_CHALLENGE_SLUG] = "updated"
    return result


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
    # Single public API: the proxy app also serves the admin/registry router, so
    # build the orchestrator + runtime controller + weight service (reusing the
    # already-built metagraph cache) and the admin token provider here. The
    # separate ``master run`` admin server is retired.
    orchestrator = _challenge_orchestrator(settings)
    runtime_controller = DockerRuntimeController(registry, orchestrator)
    weight_service = _master_weight_service(
        settings,
        metagraph_cache=runtime.metagraph_cache,
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
        extra_registered_hotkeys=settings.master.upload_extra_registered_hotkeys,
        runtime_controller=runtime_controller,
        weight_service=weight_service,
        chain_endpoint=settings.network.chain_endpoint or "",
        admin_token_provider=lambda: read_secret(
            settings.security.admin_token,
            settings.security.admin_token_file,
        ),
        enforce_production_policy=production_policy_enabled_for_settings(settings),
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
    from base.master.swarm_backend import (
        SwarmBrokerConfig,
        SwarmBrokerService,
    )

    docker_service = SwarmBrokerService(
        SwarmBrokerConfig(
            workspace_dir=Path(settings.docker.broker_workspace_dir),
            allowed_images=tuple(settings.docker.broker_allowed_images),
            node_role=settings.docker.broker_node_role,
            privileged_escape_slugs=(
                frozenset(settings.docker.broker_privileged_slugs)
                if settings.docker.allow_privileged
                else frozenset()
            ),
            allow_privileged_escape=(
                settings.docker.allow_privileged
                and settings.docker.broker_allow_privileged_escape
            ),
            cpu_job_constraint=settings.docker.cpu_job_constraint,
            gpu_job_constraint=settings.docker.gpu_job_constraint,
            docker_socket_slugs=frozenset(settings.docker.broker_docker_socket_slugs),
            docker_socket_path=settings.docker.broker_docker_socket_path,
            eval_readonly_mounts=_parse_eval_readonly_mounts(
                settings.docker.broker_eval_readonly_mounts
            ),
            eval_readonly_mounts_by_slug=_eval_readonly_mounts_by_slug(
                settings.docker.broker_eval_readonly_mounts_by_slug
            ),
            egress_locked_slugs=_egress_locked_slugs(
                settings.docker.broker_egress_locked_slugs
            ),
        )
    )
    broker = create_docker_broker_app(registry=registry, service=docker_service)
    endpoint = f"{settings.docker.broker_host}:{settings.docker.broker_port}"
    typer.echo(f"Starting Docker broker API on {endpoint}")
    uvicorn.run(
        broker, host=settings.docker.broker_host, port=settings.docker.broker_port
    )


@master_app.command("supervisor")
def master_supervisor(config: Path = typer.Option(Path("config/master.example.yaml"))):
    """Run the Swarm control-plane supervisor (systemd Type=notify)."""
    settings = load_settings(config)
    configure_logging(settings.observability.log_json)
    from base.supervisor import build_supervisor

    supervisor = build_supervisor(settings)
    typer.echo(
        f"Starting platform supervisor with {len(supervisor.tasks)} scheduled task(s)"
    )
    raise typer.Exit(code=supervisor.run())


def _docker_cli(args: list[str]) -> None:
    import subprocess

    completed = subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.stdout:
        typer.echo(completed.stdout.rstrip())
    if completed.returncode != 0:
        if completed.stderr:
            typer.echo(completed.stderr.rstrip(), err=True)
        raise typer.Exit(code=completed.returncode)


@worker_app.command("token")
def worker_token(
    role: str = typer.Option("worker", "--role", help="worker or manager"),
    rotate: bool = typer.Option(False, "--rotate", help="Rotate the join token first."),
):
    """Print the ``docker swarm join`` command for a new worker/manager node."""
    if role not in {"worker", "manager"}:
        raise typer.BadParameter("role must be 'worker' or 'manager'")
    args = ["swarm", "join-token"]
    if rotate:
        args.append("--rotate")
    args.append(role)
    _docker_cli(args)


@worker_app.command("list")
def worker_list():
    """List Swarm nodes (``docker node ls``)."""
    _docker_cli(["node", "ls"])


@worker_app.command("label")
def worker_label(
    node: str,
    workload: str = typer.Option(..., "--workload", help="cpu or gpu"),
):
    """Label a node so the broker schedules cpu/gpu jobs onto it."""
    if workload not in {"cpu", "gpu"}:
        raise typer.BadParameter("workload must be 'cpu' or 'gpu'")
    _docker_cli(["node", "update", "--label-add", f"base.workload={workload}", node])


@worker_app.command("drain")
def worker_drain(
    node: str,
    active: bool = typer.Option(
        False, "--active", help="Restore availability=active instead of draining."
    ),
):
    """Drain (or reactivate) a node's Swarm availability."""
    availability = "active" if active else "drain"
    _docker_cli(["node", "update", "--availability", availability, node])


@worker_app.command("rm")
def worker_rm(
    node: str,
    force: bool = typer.Option(False, "--force"),
):
    """Remove a node from the Swarm (``docker node rm``)."""
    args = ["node", "rm"]
    if force:
        args.append("--force")
    args.append(node)
    _docker_cli(args)


@worker_app.command("inspect")
def worker_inspect(node: str):
    """Inspect a Swarm node (``docker node inspect``)."""
    _docker_cli(["node", "inspect", node])


@master_app.command("refresh-challenge-images")
def master_refresh_challenge_images(
    config: Path = typer.Option(Path("config/master.example.yaml")),
    tag: str = typer.Option("latest", "--tag"),
):
    settings = load_settings(config)
    registry = _master_registry(settings)
    controller = DockerRuntimeController(registry, _challenge_orchestrator(settings))

    def mutable_base(image: str) -> str | None:
        from base.supervisor.image_ref import parse_image_reference

        parsed = parse_image_reference(image)
        if parsed.registry != "ghcr.io":
            return None
        if parsed.tag.startswith("sha-"):
            return None
        return f"{parsed.registry}/{parsed.repository}:{tag}"

    async def refresh() -> None:
        from base.schemas.challenge import ChallengeStatus, ChallengeUpdate
        from base.supervisor.image_ref import (
            parse_image_reference,
            resolve_remote_digest,
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
            if record.status == ChallengeStatus.ACTIVE and changed:
                result = await controller.restart(record.slug)
                typer.echo(f"{record.slug}: restarted {result['status']}")

    asyncio.run(refresh())


@master_challenges_app.command("seed-prism")
def master_challenges_seed_prism(
    config: Path = typer.Option(Path("config/master.example.yaml")),
):
    settings = load_settings(config)
    registry = _master_registry(settings)

    async def seed() -> None:
        result = await seed_prism_challenges(registry, settings)
        typer.echo(f"prism: {result[PRISM_SLUG]} emission={PRISM_EMISSION_PERCENT}")
        typer.echo(
            "agent-challenge: "
            f"{result[AGENT_CHALLENGE_SLUG]} "
            f"emission={AGENT_CHALLENGE_EMISSION_PERCENT}"
        )

    asyncio.run(seed())


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
    service = _master_weight_service(
        settings,
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
    from base.db.migrations import upgrade

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
