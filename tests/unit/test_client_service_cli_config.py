from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from typer.testing import CliRunner

import base.cli_app.main as cli_module
from base.bittensor.metagraph_cache import MetagraphCache
from base.bittensor.validator_loop import run_epoch_loop
from base.bittensor.weight_setter import WeightSetter
from base.cli_app.main import DockerRuntimeController, app
from base.config.loader import load_settings
from base.config.settings import ValidatorSettings
from base.master.assignment_coordination import (
    AssignmentCoordinationService,
    WorkAssignmentLifecycleResolver,
)
from base.master.challenge_client import ChallengeClient
from base.master.docker_orchestrator import ChallengeSpec
from base.master.llm_gateway import LLMGatewayService, SqlAlchemyUsageRecorder
from base.master.registry import ChallengeRegistry, FileChallengeRegistry
from base.master.service import MasterWeightService
from base.master.validator_coordination import ValidatorCoordinationService
from base.observability.logging import JsonFormatter, configure_logging
from base.observability.otel import init_otel
from base.observability.sentry import init_sentry
from base.schemas.challenge import (
    ChallengeCreate,
    ChallengeStatus,
    RegistryChallenge,
)
from base.schemas.weights import (
    ChallengeWeightsResult,
    MasterWeightsResponse,
)
from base.security.admin_auth import constant_time_match, read_secret
from base.security.challenge_auth import (
    bearer_token,
    require_challenge_token,
)
from base.security.tokens import (
    generate_token,
    hash_token,
    token_hint,
    verify_token,
)
from base.security.validator_auth import ValidatorSignedRequestVerifier
from base.validator.normal_runner import NormalValidatorRunner
from base.validator.registry_client import RegistryClient
from base.validator.weights_client import WeightsClient


@pytest.mark.asyncio
async def test_challenge_client_success_and_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    class Response:
        def __init__(self, status: int = 200) -> None:
            self.status = status

        def raise_for_status(self) -> None:
            if self.status >= 400:
                raise httpx.HTTPStatusError(
                    "bad",
                    request=httpx.Request("GET", "http://x"),
                    response=httpx.Response(self.status),
                )

        def json(self) -> dict[str, object]:
            return {"challenge_slug": "demo", "weights": {"hk": 1.0}}

    class AsyncClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def get(self, url: str, headers: dict[str, str]) -> Response:
            nonlocal calls
            calls += 1
            assert headers["Authorization"] == "Bearer tok"
            return Response()

    monkeypatch.setattr(httpx, "AsyncClient", AsyncClient)
    result = await ChallengeClient(retries=1).get_weights(
        slug="demo", base_url="http://challenge", token="tok", emission_percent=5
    )
    assert result.ok and result.weights == {"hk": 1.0}
    assert calls == 1

    class FailingClient(AsyncClient):
        async def get(self, url: str, headers: dict[str, str]) -> Response:
            return Response(500)

    monkeypatch.setattr(httpx, "AsyncClient", FailingClient)
    monkeypatch.setattr(asyncio, "sleep", async_noop)
    result = await ChallengeClient(retries=2).get_weights(
        slug="demo", base_url="http://challenge/", token="tok", emission_percent=5
    )
    assert not result.ok
    assert result.weights == {}
    assert result.error


async def async_noop(*args: object, **kwargs: object) -> None:
    return None


def test_master_weights_response_public_payload_contract() -> None:
    computed_at = datetime(2030, 1, 1, 12, 0, tzinfo=UTC)
    expires_at = computed_at + timedelta(seconds=720)
    metagraph_updated_at = computed_at - timedelta(seconds=30)

    response = MasterWeightsResponse(
        netuid=42,
        chain_endpoint="wss://chain.example:9944",
        uids=[3, 7],
        weights=[0.25, 0.75],
        hotkey_weights={"hk-a": 0.25, "hk-b": 0.75},
        computed_at=computed_at,
        expires_at=expires_at,
        source_challenges=[
            ChallengeWeightsResult(
                slug="demo", emission_percent=100, weights={"hk-b": 1.0}
            )
        ],
        metagraph_updated_at=metagraph_updated_at,
    )

    payload = response.model_dump(mode="json")

    assert payload == {
        "netuid": 42,
        "chain_endpoint": "wss://chain.example:9944",
        "uids": [3, 7],
        "weights": [0.25, 0.75],
        "hotkey_weights": {"hk-a": 0.25, "hk-b": 0.75},
        "computed_at": "2030-01-01T12:00:00Z",
        "expires_at": "2030-01-01T12:12:00Z",
        "source_challenges": [
            {
                "slug": "demo",
                "emission_percent": 100.0,
                "weights": {"hk-b": 1.0},
                "ok": True,
                "error": None,
            }
        ],
        "metagraph_updated_at": "2030-01-01T11:59:30Z",
    }
    assert "auth" not in payload
    assert "signature" not in payload


def test_master_weights_response_rejects_expired_payload() -> None:
    now = datetime.now(UTC)

    with pytest.raises(ValueError, match="expires_at must be in the future"):
        MasterWeightsResponse(
            netuid=42,
            chain_endpoint="wss://chain.example:9944",
            uids=[3],
            weights=[1.0],
            hotkey_weights={"hk-a": 1.0},
            computed_at=now - timedelta(seconds=721),
            expires_at=now - timedelta(seconds=1),
            source_challenges=[],
            metagraph_updated_at=now - timedelta(seconds=721),
        )


@pytest.mark.asyncio
async def test_master_weight_service_and_validator_runner() -> None:
    class Cache:
        def get(self) -> dict[str, int]:
            return {"hk": 3}

    class Setter:
        def __init__(self) -> None:
            self.calls: list[tuple[list[int], list[float]]] = []

        def set_weights(self, uids: list[int], weights: list[float]) -> None:
            self.calls.append((uids, weights))

    class Client:
        async def get_weights(self, **kwargs: object) -> ChallengeWeightsResult:
            return ChallengeWeightsResult(
                slug=str(kwargs["slug"]), emission_percent=10, weights={"hk": 2}
            )

    challenge = RegistryChallenge(
        slug="demo",
        name="Demo",
        image="ghcr.io/o/demo:1",
        version="1",
        emission_percent=Decimal("10"),
        status=ChallengeStatus.ACTIVE,
        internal_base_url="http://challenge-demo:8000",
        public_proxy_base_path="/challenges/demo",
        required_capabilities=["get_weights", "proxy_routes"],
        resources={"cpu": "2", "memory": "1g"},
        volumes={},
        env={},
        secrets=[],
        metadata={"worker_command": ["agent-challenge-worker"]},
    )
    setter = Setter()
    service = MasterWeightService(
        metagraph_cache=cast(MetagraphCache, Cache()),
        weight_setter=cast(WeightSetter, setter),
        challenge_client=cast(ChallengeClient, Client()),
    )
    final = await service.run_epoch([challenge], {"demo": "tok"})
    assert final.uids == [3]
    assert setter.calls == [([3], [1.0])]

    class Registry:
        async def fetch_registry(self):
            return SimpleNamespace(challenges=[challenge])

    class Orchestrator:
        def __init__(self) -> None:
            self.specs: list[ChallengeSpec] = []

        def start_challenge(self, spec):
            self.specs.append(spec)

    orchestrator = Orchestrator()
    runner = NormalValidatorRunner(
        registry_client=cast(RegistryClient, Registry()), orchestrator=orchestrator
    )
    await runner.run_once()
    assert orchestrator.specs[0].slug == "demo"
    assert orchestrator.specs[0].resources.cpu == 2.0
    assert orchestrator.specs[0].resources.memory == "1g"
    assert orchestrator.specs[0].worker_command == ("agent-challenge-worker",)


@pytest.mark.asyncio
async def test_master_weight_service_dry_run_skips_weight_setter() -> None:
    class Cache:
        def get(self) -> dict[str, int]:
            return {"hk": 3}

    class Setter:
        def set_weights(self, uids: list[int], weights: list[float]) -> None:
            raise AssertionError("dry-run must not submit weights")

    class Client:
        async def get_weights(self, **kwargs: object) -> ChallengeWeightsResult:
            return ChallengeWeightsResult(
                slug=str(kwargs["slug"]), emission_percent=10, weights={"hk": 2}
            )

    challenge = RegistryChallenge(
        slug="demo",
        name="Demo",
        image="ghcr.io/o/demo:1",
        version="1",
        emission_percent=Decimal("10"),
        status=ChallengeStatus.ACTIVE,
        internal_base_url="http://challenge-demo:8000",
        public_proxy_base_path="/challenges/demo",
        required_capabilities=["get_weights", "proxy_routes"],
        resources={"cpu": "2", "memory": "1g"},
        volumes={},
        env={},
        secrets=[],
    )
    service = MasterWeightService(
        metagraph_cache=cast(MetagraphCache, Cache()),
        weight_setter=cast(WeightSetter, Setter()),
        challenge_client=cast(ChallengeClient, Client()),
    )

    final = await service.run_epoch([challenge], {"demo": "tok"}, submit=False)

    assert final.uids == [3]
    assert final.weights == [1.0]


@pytest.mark.asyncio
async def test_master_weight_service_uid_zero_fallback_without_challenges() -> None:
    class Subtensor:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def metagraph(self, netuid: int) -> SimpleNamespace:
            return SimpleNamespace(hotkeys=["validator"] if netuid == 42 else [])

        def set_weights(self, **kwargs: object) -> dict[str, object]:
            self.calls.append(kwargs)
            return {"ok": True, **kwargs}

    class Client:
        async def get_weights(self, **kwargs: object) -> ChallengeWeightsResult:
            raise AssertionError("get_weights should not be called without challenges")

    subtensor = Subtensor()
    wallet = object()
    service = MasterWeightService(
        metagraph_cache=MetagraphCache(netuid=42, ttl_seconds=0, subtensor=subtensor),
        weight_setter=WeightSetter(subtensor=subtensor, wallet=wallet, netuid=42),
        challenge_client=cast(ChallengeClient, Client()),
    )

    final = await service.run_epoch([], {})

    assert final.uids == [0]
    assert final.weights == [1.0]
    assert subtensor.calls == [
        {
            "wallet": wallet,
            "netuid": 42,
            "uids": [0],
            "weights": [1.0],
            "version_key": 0,
            "wait_for_inclusion": False,
            "wait_for_finalization": False,
        }
    ]


@pytest.mark.asyncio
async def test_run_epoch_loop_logs_and_sleeps(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    async def callback() -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("boom")

    async def stop_after_sleep(seconds: int) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(asyncio, "sleep", stop_after_sleep)
    with pytest.raises(KeyboardInterrupt):
        await run_epoch_loop(1, callback)
    assert calls == 1


def test_config_env_security_and_observability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("network:\n  netuid: 1\n", encoding="utf-8")
    monkeypatch.setenv("BASE_NETWORK__NETUID", "9")
    monkeypatch.setenv("BASE_MASTER__ADMIN_PORT", "9999")
    monkeypatch.setenv("BASE_DOCKER__BROKER_URL", "http://broker:9999")
    settings = load_settings(config)
    assert settings.network.netuid == 9
    assert settings.master.admin_port == 9999
    assert settings.docker.broker_url == "http://broker:9999"
    with pytest.raises(FileNotFoundError):
        load_settings(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("- no\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_settings(bad)

    secret_file = tmp_path / "secret"
    secret_file.write_text("s", encoding="utf-8")
    assert read_secret(file_path=str(secret_file)) == "s"
    assert constant_time_match("a", "a")
    assert not constant_time_match("a", "b")
    token = generate_token()
    assert token_hint(token)
    assert verify_token(token, hash_token(token))
    assert bearer_token("Bearer abc") == "abc"
    assert bearer_token("bad") == ""
    dep = require_challenge_token(hash_token("abc"))
    asyncio.run(dep(authorization="Bearer abc"))

    configure_logging(json_logs=True)
    record = SimpleNamespace(
        levelname="INFO", name="x", getMessage=lambda: "msg", exc_info=None
    )
    assert '"message": "msg"' in JsonFormatter().format(record)  # type: ignore[arg-type]
    init_sentry(None)
    init_otel("svc")


def test_bittensor_cache_and_setter() -> None:
    class Subtensor:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def metagraph(self, netuid: int) -> object:
            self.calls.append(("metagraph", netuid))
            return SimpleNamespace(hotkeys=["a", "b"])

        def set_weights(self, **kwargs: object) -> dict[str, object]:
            self.calls.append(("set", kwargs["netuid"]))
            return {"ok": True, **kwargs}

    subtensor = Subtensor()
    cache = MetagraphCache(netuid=12, ttl_seconds=0, subtensor=subtensor)
    assert cache.get() == {"a": 0, "b": 1}
    assert cache.get(force=True) == {"a": 0, "b": 1}
    result = WeightSetter(subtensor=subtensor, wallet="wallet", netuid=12).set_weights(
        [1], [1.0]
    )
    assert result["ok"] is True
    with pytest.raises(ValueError, match="empty weights"):
        WeightSetter(subtensor=subtensor, wallet="wallet", netuid=12).set_weights(
            [], []
        )


def test_cli_create_and_runtime_controller(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "challenge"
    result = runner.invoke(app, ["challenge", "create", "demo", "--out", str(out)])
    assert result.exit_code == 0
    assert (out / "pyproject.toml").exists()

    registry = FileChallengeRegistry(
        tmp_path / "registry.json", secret_dir=tmp_path / "secrets"
    )
    registry.create(
        ChallengeCreate(
            slug="demo",
            name="Demo",
            image="ghcr.io/o/demo:1",
            version="1",
            resources={"cpus": "1.5", "memory": "2g"},
            metadata={"worker_command": ["agent-challenge-worker"]},
        )
    )

    class Orchestrator:
        def __init__(self) -> None:
            self.runtime: dict[str, object] = {}
            self.pulled: list[str] = []
            self.specs: list[ChallengeSpec] = []

        def pull_image(self, image: str) -> None:
            self.pulled.append(image)

        def restart_challenge(self, spec):
            self.specs.append(spec)
            return SimpleNamespace(container_name=spec.container_name)

    orchestrator = Orchestrator()
    controller = DockerRuntimeController(registry, orchestrator)  # type: ignore[arg-type]
    assert asyncio.run(controller.pull("demo"))["status"] == "ok"
    assert asyncio.run(controller.restart("demo"))["detail"] == "challenge-demo"
    assert orchestrator.specs[0].resources.cpu == 1.5
    assert orchestrator.specs[0].resources.memory == "2g"
    assert orchestrator.specs[0].worker_command == ("agent-challenge-worker",)
    assert asyncio.run(controller.status("demo"))["status"] == "unknown"


def test_cli_master_proxy_builds_single_port_app_with_admin_deps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "master.yaml"
    config.write_text(
        "\n".join(
            [
                "network:",
                "  netuid: 21",
                "  chain_endpoint: ws://chain",
                "master:",
                "  proxy_host: 127.0.0.1",
                "  proxy_port: 0",
                "docker:",
                f"  secret_dir: {tmp_path / 'secrets'}",
                "security:",
                "  admin_token: top-secret",
                "gateway:",
                "  token_secret: gw-secret",
            ]
        ),
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    class Cache:
        def get(self) -> dict[str, int]:
            return {}

    runtime = SimpleNamespace(metagraph_cache=Cache())
    orchestrator = object()
    weight_service = object()
    registry = object()
    nonce_store = object()

    def fake_weight_service(settings: object, metagraph_cache: object = None) -> object:
        captured["weight_service_cache"] = metagraph_cache
        return weight_service

    def fake_create_proxy_app(**kwargs: object) -> object:
        captured["proxy_kwargs"] = kwargs
        return SimpleNamespace()

    import uvicorn

    monkeypatch.setattr(
        cli_module, "create_bittensor_runtime", lambda settings: runtime
    )
    monkeypatch.setattr(
        cli_module, "_challenge_orchestrator", lambda settings: orchestrator
    )
    monkeypatch.setattr(cli_module, "_master_weight_service", fake_weight_service)
    monkeypatch.setattr(cli_module, "create_proxy_app", fake_create_proxy_app)
    monkeypatch.setattr(cli_module, "_run_startup_migrations", lambda settings: None)
    monkeypatch.setattr(
        cli_module,
        "_master_registry",
        lambda settings, session_factory=None: registry,
    )
    monkeypatch.setattr(cli_module, "create_engine", lambda url: object())
    monkeypatch.setattr(cli_module, "create_session_factory", lambda engine: object())
    monkeypatch.setattr(
        cli_module, "SqlAlchemyMinerNonceStore", lambda *a, **k: nonce_store
    )
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)

    result = CliRunner().invoke(app, ["master", "proxy", "--config", str(config)])

    assert result.exit_code == 0, result.output
    proxy_kwargs = cast(dict[str, object], captured["proxy_kwargs"])
    assert proxy_kwargs["weight_service"] is weight_service
    assert proxy_kwargs["chain_endpoint"] == "ws://chain"
    controller = proxy_kwargs["runtime_controller"]
    assert isinstance(controller, DockerRuntimeController)
    assert controller.orchestrator is orchestrator
    assert controller.registry is registry
    token_provider = proxy_kwargs["admin_token_provider"]
    assert callable(token_provider)
    assert token_provider() == "top-secret"
    assert captured["weight_service_cache"] is runtime.metagraph_cache
    assert proxy_kwargs["enforce_production_policy"] is False


def test_cli_master_proxy_wires_coordination_plane_and_gateway(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "master.yaml"
    config.write_text(
        "\n".join(
            [
                "network:",
                "  netuid: 21",
                "master:",
                "  proxy_host: 127.0.0.1",
                "  proxy_port: 0",
                "  validator_heartbeat_interval_seconds: 30",
                "  validator_heartbeat_timeout_seconds: 90",
                "  validator_health_interval_seconds: 7.5",
                "  assignment_lease_seconds: 1200",
                "docker:",
                f"  secret_dir: {tmp_path / 'secrets'}",
                "security:",
                "  admin_token: top-secret",
                "gateway:",
                "  token_secret: gw-secret",
            ]
        ),
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    class Cache:
        def get(self) -> dict[str, int]:
            return {}

    runtime = SimpleNamespace(metagraph_cache=Cache())
    session_factory = object()

    def fake_create_proxy_app(**kwargs: object) -> object:
        captured["proxy_kwargs"] = kwargs
        return SimpleNamespace()

    import uvicorn

    monkeypatch.setattr(
        cli_module, "create_bittensor_runtime", lambda settings: runtime
    )
    monkeypatch.setattr(
        cli_module, "_challenge_orchestrator", lambda settings: object()
    )
    monkeypatch.setattr(
        cli_module,
        "_master_weight_service",
        lambda settings, metagraph_cache=None: object(),
    )
    monkeypatch.setattr(cli_module, "create_proxy_app", fake_create_proxy_app)
    monkeypatch.setattr(cli_module, "_run_startup_migrations", lambda settings: None)
    monkeypatch.setattr(
        cli_module,
        "_master_registry",
        lambda settings, session_factory=None: object(),
    )
    monkeypatch.setattr(cli_module, "create_engine", lambda url: object())
    monkeypatch.setattr(
        cli_module, "create_session_factory", lambda engine: session_factory
    )
    monkeypatch.setattr(
        cli_module, "SqlAlchemyMinerNonceStore", lambda *a, **k: object()
    )
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)

    result = CliRunner().invoke(app, ["master", "proxy", "--config", str(config)])

    assert result.exit_code == 0, result.output
    proxy_kwargs = cast(dict[str, object], captured["proxy_kwargs"])

    validator_service = proxy_kwargs["validator_service"]
    assert isinstance(validator_service, ValidatorCoordinationService)
    assert validator_service.heartbeat_interval_seconds == 30
    assert validator_service.heartbeat_timeout_seconds == 90

    assert isinstance(
        proxy_kwargs["validator_verifier"], ValidatorSignedRequestVerifier
    )
    assert isinstance(
        proxy_kwargs["assignment_coordination_service"],
        AssignmentCoordinationService,
    )
    assert proxy_kwargs["validator_health_interval_seconds"] == 7.5

    gateway = proxy_kwargs["llm_gateway_service"]
    assert isinstance(gateway, LLMGatewayService)
    # Real resolver + recorder bound to the master DB session factory.
    assert isinstance(gateway._assignment_resolver, WorkAssignmentLifecycleResolver)
    assert isinstance(gateway._usage_recorder, SqlAlchemyUsageRecorder)


def test_cli_built_proxy_app_serves_coordination_and_runs_health_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "master.yaml"
    config.write_text(
        "\n".join(
            [
                "network:",
                "  netuid: 21",
                "master:",
                "  proxy_host: 127.0.0.1",
                "  proxy_port: 0",
                "  validator_health_interval_seconds: 0.05",
                "docker:",
                f"  secret_dir: {tmp_path / 'secrets'}",
                "security:",
                "  admin_token: top-secret",
                "gateway:",
                "  token_secret: gw-secret",
            ]
        ),
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    cache = MetagraphCache(netuid=21, ttl_seconds=300)
    cache.update_from_metagraph([], validator_permits=[], stakes=[])
    runtime = SimpleNamespace(metagraph_cache=cache)

    import uvicorn

    monkeypatch.setattr(
        cli_module, "create_bittensor_runtime", lambda settings: runtime
    )
    monkeypatch.setattr(
        cli_module, "_challenge_orchestrator", lambda settings: object()
    )
    monkeypatch.setattr(
        cli_module,
        "_master_weight_service",
        lambda settings, metagraph_cache=None: None,
    )
    monkeypatch.setattr(cli_module, "_run_startup_migrations", lambda settings: None)
    monkeypatch.setattr(
        cli_module,
        "_master_registry",
        lambda settings, session_factory=None: object(),
    )
    monkeypatch.setattr(cli_module, "create_engine", lambda url: object())
    monkeypatch.setattr(cli_module, "create_session_factory", lambda engine: object())
    monkeypatch.setattr(
        cli_module, "SqlAlchemyMinerNonceStore", lambda *a, **k: object()
    )
    monkeypatch.setattr(uvicorn, "run", lambda app, **k: captured.update(app=app))

    result = CliRunner().invoke(app, ["master", "proxy", "--config", str(config)])
    assert result.exit_code == 0, result.output

    built = cast(FastAPI, captured["app"])
    paths = {getattr(route, "path", None) for route in built.routes}
    assert "/v1/validators/register" in paths
    assert "/v1/validators/heartbeat" in paths
    assert "/v1/validators" in paths
    assert "/v1/assignments/pull" in paths
    assert "/v1/assignments/{assignment_id}/progress" in paths
    assert "/v1/assignments/{assignment_id}/result" in paths
    assert "/llm/deepseek/{path:path}" in paths
    assert "/llm/openrouter/{path:path}" in paths

    service = built.state.validator_coordination_service
    assert isinstance(service, ValidatorCoordinationService)
    assert built.state.assignment_coordination_service is not None
    assert isinstance(built.state.llm_gateway_service, LLMGatewayService)

    # The background crash-detection loop runs live when the app starts.
    calls: list[int] = []

    async def spy() -> list[str]:
        calls.append(1)
        return []

    monkeypatch.setattr(service, "detect_offline_validators", spy)
    with TestClient(built):
        deadline = time.time() + 2.0
        while not calls and time.time() < deadline:
            time.sleep(0.05)
    assert calls, "health loop did not run a crash-detection pass"


def test_cli_master_run_admin_server_is_retired() -> None:
    result = CliRunner().invoke(app, ["master", "run", "--help"], env={"TERM": "dumb"})

    assert result.exit_code != 0


def test_cli_master_weights_once_defaults_to_compute_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry_path = tmp_path / "registry.json"
    secret_dir = tmp_path / "secrets"
    config = tmp_path / "master.yaml"
    config.write_text(
        "\n".join(
            [
                "network:",
                "  netuid: 12",
                "  chain_endpoint: ws://chain",
                "  wallet_name: wallet",
                "  wallet_hotkey: hotkey",
                "master:",
                f"  registry_state_file: {registry_path}",
                "  metagraph_cache_ttl_seconds: 3",
                "  challenge_timeout_seconds: 1.5",
                "  challenge_retries: 2",
                "docker:",
                f"  secret_dir: {secret_dir}",
            ]
        ),
        encoding="utf-8",
    )
    registry = FileChallengeRegistry(registry_path, secret_dir=secret_dir)
    registry.create(
        ChallengeCreate(
            slug="demo",
            name="Demo",
            image="ghcr.io/o/demo:1",
            version="1",
            emission_percent=Decimal("10"),
            status=ChallengeStatus.ACTIVE,
        )
    )
    created_runtime: dict[str, object] = {}
    setter_calls: list[tuple[list[int], list[float]]] = []

    class Cache:
        def get(self) -> dict[str, int]:
            return {"hk": 7}

    class Setter:
        def set_weights(self, uids: list[int], weights: list[float]) -> None:
            setter_calls.append((uids, weights))

    class Client:
        def __init__(self, **kwargs: object) -> None:
            created_runtime["client_kwargs"] = kwargs

        async def get_weights(self, **kwargs: object) -> ChallengeWeightsResult:
            assert kwargs["token"]
            return ChallengeWeightsResult(
                slug=str(kwargs["slug"]),
                emission_percent=float(cast(float, kwargs["emission_percent"])),
                weights={"hk": 2.0},
            )

    def create_runtime(settings):
        created_runtime["netuid"] = settings.network.netuid
        created_runtime["chain_endpoint"] = settings.network.chain_endpoint
        created_runtime["wallet_name"] = settings.network.wallet_name
        created_runtime["wallet_hotkey"] = settings.network.wallet_hotkey
        return SimpleNamespace(metagraph_cache=Cache(), weight_setter=Setter())

    monkeypatch.setattr(cli_module, "create_bittensor_runtime", create_runtime)
    monkeypatch.setattr(
        cli_module,
        "_master_compute_metagraph_cache",
        lambda _settings: (_ for _ in ()).throw(
            AssertionError("master weights must reuse create_bittensor_runtime cache")
        ),
    )
    monkeypatch.setattr(cli_module, "ChallengeClient", Client)
    monkeypatch.setattr(cli_module, "_run_startup_migrations", lambda _settings: None)
    monkeypatch.setattr(cli_module, "_master_registry", lambda _settings: registry)

    result = CliRunner().invoke(
        app, ["master", "weights", "--config", str(config), "--once"]
    )

    assert result.exit_code == 0
    assert "compute-only: computed 1 weights" in result.output
    assert created_runtime["netuid"] == 12
    assert created_runtime["chain_endpoint"] == "ws://chain"
    assert created_runtime["wallet_name"] == "wallet"
    assert created_runtime["wallet_hotkey"] == "hotkey"
    client_kwargs = cast(dict[str, object], created_runtime["client_kwargs"])
    assert client_kwargs["timeout_seconds"] == 1.5
    assert client_kwargs["retries"] == 2
    assert setter_calls == []


def test_cli_master_weights_submit_on_chain_requires_explicit_unsafe_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry_path = tmp_path / "registry.json"
    secret_dir = tmp_path / "secrets"
    config = tmp_path / "master.yaml"
    config.write_text(
        "\n".join(
            [
                "network:",
                "  netuid: 12",
                "master:",
                f"  registry_state_file: {registry_path}",
                "docker:",
                f"  secret_dir: {secret_dir}",
            ]
        ),
        encoding="utf-8",
    )
    registry = FileChallengeRegistry(registry_path, secret_dir=secret_dir)
    registry.create(
        ChallengeCreate(
            slug="demo",
            name="Demo",
            image="ghcr.io/o/demo:1",
            version="1",
            emission_percent=Decimal("10"),
            status=ChallengeStatus.ACTIVE,
        )
    )
    setter_calls: list[tuple[list[int], list[float]]] = []

    class Cache:
        def get(self) -> dict[str, int]:
            return {"hk": 7}

    class Setter:
        def set_weights(self, uids: list[int], weights: list[float]) -> None:
            setter_calls.append((uids, weights))

    class Client:
        def __init__(self, **kwargs: object) -> None:
            pass

        async def get_weights(self, **kwargs: object) -> ChallengeWeightsResult:
            return ChallengeWeightsResult(
                slug=str(kwargs["slug"]),
                emission_percent=float(cast(float, kwargs["emission_percent"])),
                weights={"hk": 2.0},
            )

    def create_runtime(settings):
        return SimpleNamespace(metagraph_cache=Cache(), weight_setter=Setter())

    monkeypatch.setattr(cli_module, "create_bittensor_runtime", create_runtime)
    monkeypatch.setattr(cli_module, "ChallengeClient", Client)
    monkeypatch.setattr(cli_module, "_run_startup_migrations", lambda _settings: None)
    monkeypatch.setattr(cli_module, "_master_registry", lambda _settings: registry)

    result = CliRunner().invoke(
        app,
        [
            "master",
            "weights",
            "--config",
            str(config),
            "--once",
            "--submit-on-chain",
        ],
    )

    assert result.exit_code == 0
    assert "submit-on-chain: computed 1 weights" in result.output
    assert setter_calls == [([7], [1.0])]


def test_cli_master_weights_dry_run_does_not_submit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry_path = tmp_path / "registry.json"
    secret_dir = tmp_path / "secrets"
    config = tmp_path / "master.yaml"
    config.write_text(
        "\n".join(
            [
                "network:",
                "  netuid: 12",
                "master:",
                f"  registry_state_file: {registry_path}",
                "docker:",
                f"  secret_dir: {secret_dir}",
            ]
        ),
        encoding="utf-8",
    )
    registry = FileChallengeRegistry(registry_path, secret_dir=secret_dir)
    registry.create(
        ChallengeCreate(
            slug="demo",
            name="Demo",
            image="ghcr.io/o/demo:1",
            version="1",
            emission_percent=Decimal("10"),
            status=ChallengeStatus.ACTIVE,
        )
    )

    class Cache:
        def get(self) -> dict[str, int]:
            return {"hk": 7}

    class Setter:
        def set_weights(self, uids: list[int], weights: list[float]) -> None:
            raise AssertionError("dry-run must not submit weights")

    class Client:
        def __init__(self, **kwargs: object) -> None:
            pass

        async def get_weights(self, **kwargs: object) -> ChallengeWeightsResult:
            return ChallengeWeightsResult(
                slug=str(kwargs["slug"]),
                emission_percent=float(cast(float, kwargs["emission_percent"])),
                weights={"hk": 2.0},
            )

    def create_runtime(settings):
        return SimpleNamespace(metagraph_cache=Cache(), weight_setter=Setter())

    monkeypatch.setattr(cli_module, "create_bittensor_runtime", create_runtime)
    monkeypatch.setattr(cli_module, "ChallengeClient", Client)
    monkeypatch.setattr(cli_module, "_run_startup_migrations", lambda _settings: None)
    monkeypatch.setattr(cli_module, "_master_registry", lambda _settings: registry)

    result = CliRunner().invoke(
        app,
        ["master", "weights", "--config", str(config), "--once", "--dry-run"],
    )

    assert result.exit_code == 0
    assert "compute-only: computed 1 weights" in result.output


def test_cli_master_weights_help_documents_explicit_submit_opt_in() -> None:
    result = CliRunner().invoke(
        app, ["master", "weights", "--help"], env={"TERM": "dumb"}
    )

    assert result.exit_code == 0
    assert "--submit-on-chain" in result.output
    assert "--dry-run/--submit" not in result.output


def test_cli_master_weights_loop_uses_epoch_interval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry_path = tmp_path / "registry.json"
    config = tmp_path / "master.yaml"
    config.write_text(
        "\n".join(
            [
                "master:",
                f"  registry_state_file: {registry_path}",
                "  epoch_interval_seconds: 11",
                "docker:",
                f"  secret_dir: {tmp_path / 'secrets'}",
            ]
        ),
        encoding="utf-8",
    )
    intervals: list[int] = []

    class Cache:
        def get(self) -> dict[str, int]:
            return {}

    class Setter:
        def set_weights(self, uids: list[int], weights: list[float]) -> None:
            return None

    class Client:
        def __init__(self, **kwargs: object) -> None:
            pass

    def create_runtime(settings):
        return SimpleNamespace(metagraph_cache=Cache(), weight_setter=Setter())

    async def run_loop(interval_seconds: int, callback):
        intervals.append(interval_seconds)
        await callback()

    monkeypatch.setattr(cli_module, "create_bittensor_runtime", create_runtime)
    monkeypatch.setattr(cli_module, "ChallengeClient", Client)
    monkeypatch.setattr(cli_module, "run_epoch_loop", run_loop)
    monkeypatch.setattr(cli_module, "_run_startup_migrations", lambda _settings: None)
    monkeypatch.setattr(
        cli_module,
        "_master_registry",
        lambda settings: FileChallengeRegistry(
            settings.master.registry_state_file,
            secret_dir=settings.docker.secret_dir,
        ),
    )

    result = CliRunner().invoke(app, ["master", "weights", "--config", str(config)])

    assert result.exit_code == 0
    assert intervals == [11]


def _master_weights_payload(
    *,
    netuid: int = 42,
    uids: list[int] | None = None,
    weights: list[float] | None = None,
    expires_at: datetime | None = None,
) -> MasterWeightsResponse:
    now = datetime.now(UTC)
    return MasterWeightsResponse(
        netuid=netuid,
        chain_endpoint="wss://chain.example:9944",
        uids=[1, 2] if uids is None else uids,
        weights=[0.4, 0.6] if weights is None else weights,
        hotkey_weights={"hk-a": 0.4, "hk-b": 0.6},
        computed_at=now,
        expires_at=expires_at or now + timedelta(minutes=5),
        source_challenges=[],
        metagraph_updated_at=now,
    )


def test_weights_client_fetches_latest_master_weights(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_urls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(
            200,
            json=_master_weights_payload().model_dump(mode="json"),
        )

    transport = httpx.MockTransport(handler)

    class Client(httpx.AsyncClient):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(transport=transport)

    async def run() -> None:
        import base.validator.weights_client as module

        monkeypatch.setattr(module.httpx, "AsyncClient", Client)
        response = await WeightsClient("https://master.example/").fetch_latest()
        assert response.uids == [1, 2]
        assert response.weights == [0.4, 0.6]

    asyncio.run(run())

    assert requested_urls == ["https://master.example/v1/weights/latest"]


@pytest.mark.asyncio
async def test_validator_weights_submit_valid_payload_once() -> None:
    payload = _master_weights_payload()

    class Weights:
        async def fetch_latest(self) -> MasterWeightsResponse:
            return payload

    class Setter:
        def __init__(self) -> None:
            self.calls: list[tuple[list[int], list[float]]] = []

        def set_weights(self, uids: list[int], weights: list[float]) -> None:
            self.calls.append((uids, weights))

    setter = Setter()
    runner = NormalValidatorRunner(
        registry_client=cast(RegistryClient, SimpleNamespace()),
        orchestrator=SimpleNamespace(),
        weights_client=cast(WeightsClient, Weights()),
        weight_setter=cast(WeightSetter, setter),
        netuid=42,
    )

    assert await runner.submit_latest_weights() is True
    assert setter.calls == [([1, 2], [0.4, 0.6])]


@pytest.mark.asyncio
async def test_validator_weights_submit_returns_false_when_setter_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    payload = _master_weights_payload()

    class Weights:
        async def fetch_latest(self) -> MasterWeightsResponse:
            return payload

    class Setter:
        def set_weights(self, uids: list[int], weights: list[float]) -> None:
            raise RuntimeError("subtensor rejected weight submission")

    runner = NormalValidatorRunner(
        registry_client=cast(RegistryClient, SimpleNamespace()),
        orchestrator=SimpleNamespace(),
        weights_client=cast(WeightsClient, Weights()),
        weight_setter=cast(WeightSetter, Setter()),
        netuid=42,
    )

    caplog.set_level(logging.ERROR, logger="base.validator.normal_runner")
    assert await runner.submit_latest_weights() is False
    assert "validator weights submission failed" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rejected_result", [False, (False, "chain rejected"), [False, "chain rejected"]]
)
async def test_validator_weights_submit_returns_false_when_setter_rejects(
    rejected_result: object,
    caplog: pytest.LogCaptureFixture,
) -> None:
    payload = _master_weights_payload()

    class Weights:
        async def fetch_latest(self) -> MasterWeightsResponse:
            return payload

    class Setter:
        def set_weights(self, uids: list[int], weights: list[float]) -> object:
            return rejected_result

    runner = NormalValidatorRunner(
        registry_client=cast(RegistryClient, SimpleNamespace()),
        orchestrator=SimpleNamespace(),
        weights_client=cast(WeightsClient, Weights()),
        weight_setter=cast(WeightSetter, Setter()),
        netuid=42,
    )

    caplog.set_level(logging.WARNING, logger="base.validator.normal_runner")
    assert await runner.submit_latest_weights() is False
    assert "validator weights submission rejected" in caplog.text


@pytest.mark.asyncio
async def test_validator_weights_skip_invalid_payloads() -> None:
    valid = _master_weights_payload()
    expired_payload = valid.model_dump()
    expired_payload["expires_at"] = datetime.now(UTC) - timedelta(seconds=1)
    expired = MasterWeightsResponse.model_construct(**expired_payload)
    cases = [
        _master_weights_payload(netuid=7),
        expired,
        _master_weights_payload(uids=[]),
        _master_weights_payload(weights=[]),
        _master_weights_payload(uids=[1, 2], weights=[1.0]),
    ]

    class Setter:
        def set_weights(self, uids: list[int], weights: list[float]) -> None:
            raise AssertionError("invalid payload must not submit")

    def weights_client_for(payload: MasterWeightsResponse):
        class Weights:
            async def fetch_latest(self) -> MasterWeightsResponse:
                return payload

        return Weights()

    for payload in cases:
        runner = NormalValidatorRunner(
            registry_client=cast(RegistryClient, SimpleNamespace()),
            orchestrator=SimpleNamespace(),
            weights_client=cast(WeightsClient, weights_client_for(payload)),
            weight_setter=cast(WeightSetter, Setter()),
            netuid=42,
        )

        assert await runner.submit_latest_weights() is False


def test_validator_run_starts_registry_and_weight_submission_loops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "validator.yaml"
    config.write_text(
        "\n".join(
            [
                "network:",
                "  netuid: 12",
                "  chain_endpoint: ws://chain",
                "  wallet_name: validator-wallet",
                "  wallet_hotkey: validator-hotkey",
                "validator:",
                "  registry_url: https://registry.example",
                "  registry_retry_seconds: 9",
                "  weights_url: https://weights.example",
                "  weights_interval_seconds: 17",
                "  weights_timeout_seconds: 4.5",
                "  weights_retries: 2",
                "  weights_freshness_seconds: 111",
            ]
        ),
        encoding="utf-8",
    )
    events: list[tuple[str, object]] = []

    class Runtime:
        weight_setter = object()

    def create_submit_runtime(settings):
        events.append(("runtime_netuid", settings.network.netuid))
        events.append(("runtime_hotkey", settings.network.wallet_hotkey))
        return Runtime()

    class FakeRegistryClient:
        def __init__(self, base_url: str) -> None:
            events.append(("registry_url", base_url))

    class FakeWeightsClient:
        def __init__(
            self, base_url: str, *, timeout_seconds: float, retries: int
        ) -> None:
            events.append(("weights_client", (base_url, timeout_seconds, retries)))

    class FakeRunner:
        def __init__(self, **kwargs: object) -> None:
            events.append(("runner", kwargs))

        async def run_forever(self) -> None:
            events.append(("registry_loop", True))

        async def submit_latest_weights(self) -> bool:
            events.append(("submit_weights", True))
            return True

    async def fake_run_epoch_loop(interval_seconds: int, callback):
        events.append(("weights_interval", interval_seconds))
        await callback()

    monkeypatch.setattr(
        cli_module, "create_bittensor_submit_runtime", create_submit_runtime
    )
    monkeypatch.setattr(cli_module, "RegistryClient", FakeRegistryClient)
    monkeypatch.setattr(cli_module, "WeightsClient", FakeWeightsClient)
    monkeypatch.setattr(cli_module, "NormalValidatorRunner", FakeRunner)
    monkeypatch.setattr(cli_module, "run_epoch_loop", fake_run_epoch_loop)
    monkeypatch.setattr(
        cli_module, "_challenge_orchestrator", lambda settings: object()
    )

    result = CliRunner().invoke(app, ["validator", "run", "--config", str(config)])

    assert result.exit_code == 0
    assert ("registry_url", "https://registry.example") in events
    assert ("weights_client", ("https://weights.example", 4.5, 2)) in events
    assert ("weights_interval", 17) in events
    assert ("registry_loop", True) in events
    assert ("submit_weights", True) in events
    runner_kwargs = next(value for name, value in events if name == "runner")
    assert isinstance(runner_kwargs, dict)
    assert runner_kwargs["retry_seconds"] == 9
    assert runner_kwargs["weight_setter"] is Runtime.weight_setter
    assert runner_kwargs["netuid"] == 12
    assert runner_kwargs["weights_freshness_seconds"] == 111


def test_validator_run_defaults_weights_url_to_registry_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "validator.yaml"
    config.write_text(
        "\n".join(
            [
                "validator:",
                "  registry_url: https://registry.example",
            ]
        ),
        encoding="utf-8",
    )
    events: list[tuple[str, object]] = []

    class Runtime:
        weight_setter = object()

    class FakeRunner:
        def __init__(self, **kwargs: object) -> None:
            pass

        async def run_forever(self) -> None:
            return None

        async def submit_latest_weights(self) -> bool:
            return True

    class FakeWeightsClient:
        def __init__(
            self, base_url: str, *, timeout_seconds: float, retries: int
        ) -> None:
            events.append(("weights_url", base_url))

    async def fake_run_epoch_loop(interval_seconds: int, callback):
        await callback()

    monkeypatch.setattr(
        cli_module, "create_bittensor_submit_runtime", lambda settings: Runtime()
    )
    monkeypatch.setattr(cli_module, "RegistryClient", lambda base_url: object())
    monkeypatch.setattr(cli_module, "WeightsClient", FakeWeightsClient)
    monkeypatch.setattr(cli_module, "NormalValidatorRunner", FakeRunner)
    monkeypatch.setattr(cli_module, "run_epoch_loop", fake_run_epoch_loop)
    monkeypatch.setattr(
        cli_module, "_challenge_orchestrator", lambda settings: object()
    )

    result = CliRunner().invoke(app, ["validator", "run", "--config", str(config)])

    assert result.exit_code == 0
    assert events == [("weights_url", "https://registry.example")]


def test_seed_prism_challenges_is_idempotent_and_preserves_tokens() -> None:
    registry = ChallengeRegistry()
    _, agent_token = registry.create(
        ChallengeCreate(
            slug="agent-challenge",
            name="Agent Challenge",
            image="ghcr.io/baseintelligence/agent-challenge:latest",
            version="0.1.0",
            status=ChallengeStatus.ACTIVE,
            emission_percent=Decimal("40"),
        )
    )
    settings = SimpleNamespace(
        docker=SimpleNamespace(broker_url="http://base-broker:8082")
    )

    first = asyncio.run(cli_module.seed_prism_challenges(registry, settings))
    prism_token = registry.get_token("prism")
    second = asyncio.run(cli_module.seed_prism_challenges(registry, settings))

    assert first == {"prism": "created", "agent-challenge": "updated"}
    assert second == {"prism": "updated", "agent-challenge": "updated"}
    assert registry.get_token("agent-challenge") == agent_token
    assert registry.get_token("prism") == prism_token

    records = registry.list()
    assert [record.slug for record in records].count("prism") == 1
    prism = registry.get("prism")
    agent = registry.get("agent-challenge")
    assert prism.name == "PRISM"
    assert prism.image == "ghcr.io/baseintelligence/prism:latest"
    assert prism.version == "0.1.0"
    assert prism.status == ChallengeStatus.ACTIVE
    assert prism.emission_percent == Decimal("30")
    assert prism.internal_base_url == "http://challenge-prism:8080"
    assert prism.public_proxy_base_path == "/challenges/prism"
    assert prism.required_capabilities == ["get_weights", "proxy_routes"]
    challenge_token_file = "/run/secrets/base/challenge_token"
    assert prism.env["PRISM_SHARED_TOKEN_FILE"] == challenge_token_file
    assert prism.env["CHALLENGE_SHARED_TOKEN_FILE"] == challenge_token_file
    assert prism.env["PRISM_DOCKER_BACKEND"] == "broker"
    assert prism.env["PRISM_DOCKER_BROKER_URL"] == "http://base-broker:8082"
    assert prism.env["PRISM_DOCKER_BROKER_TOKEN_FILE"] == (
        "/run/secrets/base/docker_broker_token"
    )
    assert prism.env["PRISM_BASE_EVAL_IMAGE"] == (
        "ghcr.io/baseintelligence/prism-evaluator:latest"
    )
    assert prism.secrets == ["challenge_token", "docker_broker_token"]
    assert "gpu_count" not in prism.resources
    assert "gpu_capabilities" not in prism.resources
    assert prism.metadata["base_eval_gpu_count"] == "1"
    assert prism.metadata["runtime_database"] == "challenge-local-sqlite"
    assert prism.metadata["runtime_database_url"] == (
        "sqlite+aiosqlite:////data/challenge.sqlite3"
    )
    assert prism.metadata["runtime_database_journal_mode"] == "wal"
    assert prism.metadata["workload_class"] == "service"
    assert "postgres" not in str(prism.metadata)
    assert "token" not in prism.metadata
    assert "database_url" not in prism.metadata
    assert agent.emission_percent == Decimal("15")
    assert agent.metadata["worker_command"] == ["agent-challenge-worker"]
    assert agent.required_capabilities == [
        "docker_executor",
        "get_weights",
        "proxy_routes",
    ]
    assert agent.secrets == [
        "challenge_token",
        "docker_broker_token",
        "submission_env_encryption_key",
    ]
    assert agent.env["CHALLENGE_BENCHMARK_BACKEND"] == "terminal_bench"
    assert agent.env["CHALLENGE_DOCKER_ENABLED"] == "true"
    assert agent.env["CHALLENGE_DOCKER_BACKEND"] == "broker"
    assert agent.env["CHALLENGE_DOCKER_BROKER_URL"] == "http://base-broker:8082"
    assert agent.env["CHALLENGE_DOCKER_BROKER_TOKEN_FILE"] == (
        "/run/secrets/base/docker_broker_token"
    )
    assert agent.env["CHALLENGE_DOCKER_BROKER_NETWORK"] == "base_challenges"
    assert agent.env["CHALLENGE_TERMINAL_BENCH_EXECUTION_BACKEND"] == "own_runner"
    assert agent.env["CHALLENGE_HARBOR_RUNNER_IMAGE"] == (
        "ghcr.io/baseintelligence/agent-challenge-terminal-bench-runner:latest"
    )
    assert agent.env["CHALLENGE_OWN_RUNNER_CACHE_ROOT"] == (
        "/opt/agent-challenge/task-cache"
    )
    assert agent.env["CHALLENGE_OWN_RUNNER_DIGEST_MANIFEST"] == (
        "/opt/agent-challenge/golden/dataset-digest.json"
    )
    assert agent.env["CHALLENGE_TERMINAL_BENCH_LOG_STREAM_URL"] == (
        "http://challenge-agent-challenge:8000"
    )
    assert agent.env["CHALLENGE_SUBMISSION_ENV_ENCRYPTION_KEY_FILE"] == (
        "/run/secrets/base/submission_env_encryption_key"
    )
    # base_sdk knobs are retired by the own_runner cutover.
    assert "CHALLENGE_BASE_SDK_RUNNER_IMAGE" not in agent.env
    assert "CHALLENGE_BASE_SDK_ENVIRONMENT_IMPORT_PATH" not in agent.env


def test_seed_prism_challenges_pins_images_for_production_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import base.supervisor.image_ref as image_ref_module
    from base.config.policy import validate_image_reference

    prism_digest = "sha256:" + "a" * 64
    evaluator_digest = "sha256:" + "b" * 64
    resolved_images: list[str] = []

    def resolve_digest(image_reference, **kwargs: object) -> str:
        resolved_images.append(image_reference.tagged)
        if image_reference.repository == "baseintelligence/prism":
            return prism_digest
        if image_reference.repository == "baseintelligence/prism-evaluator":
            return evaluator_digest
        raise AssertionError(f"unexpected image {image_reference.tagged}")

    monkeypatch.setattr(image_ref_module, "resolve_remote_digest", resolve_digest)
    registry = ChallengeRegistry(production_policy=True)
    settings = SimpleNamespace(
        environment="production",
        docker=SimpleNamespace(broker_url="http://base-broker:8082"),
    )

    first = asyncio.run(cli_module.seed_prism_challenges(registry, settings))
    prism_token = registry.get_token("prism")
    second = asyncio.run(cli_module.seed_prism_challenges(registry, settings))

    prism = registry.get("prism")
    expected_prism_image = f"ghcr.io/baseintelligence/prism:latest@{prism_digest}"
    expected_evaluator_image = (
        f"ghcr.io/baseintelligence/prism-evaluator:latest@{evaluator_digest}"
    )
    assert first == {"prism": "created", "agent-challenge": "missing"}
    assert second == {"prism": "updated", "agent-challenge": "missing"}
    assert registry.get_token("prism") == prism_token
    assert prism.image == expected_prism_image
    assert prism.env["PRISM_BASE_EVAL_IMAGE"] == expected_evaluator_image
    assert prism.metadata["base_eval_image"] == expected_evaluator_image
    validate_image_reference(prism.image, production=True)
    assert resolved_images == [
        "ghcr.io/baseintelligence/prism:latest",
        "ghcr.io/baseintelligence/prism-evaluator:latest",
        "ghcr.io/baseintelligence/prism:latest",
        "ghcr.io/baseintelligence/prism-evaluator:latest",
    ]


def test_master_challenges_seed_prism_cli_path(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = SimpleNamespace()
    registry = object()
    calls: list[tuple[object, object]] = []

    async def seed(registry_arg: object, settings_arg: object) -> dict[str, str]:
        calls.append((registry_arg, settings_arg))
        return {"prism": "created", "agent-challenge": "updated"}

    monkeypatch.setattr(cli_module, "load_settings", lambda config: settings)
    monkeypatch.setattr(cli_module, "_master_registry", lambda settings_arg: registry)
    monkeypatch.setattr(cli_module, "seed_prism_challenges", seed)

    result = CliRunner().invoke(
        app, ["master", "challenges", "seed-prism", "--config", "unused.yaml"]
    )

    assert result.exit_code == 0, result.output
    assert calls == [(registry, settings)]
    assert "prism: created emission=30" in result.output
    assert "agent-challenge: updated emission=15" in result.output


def test_registry_client_with_asgi_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "network": "platform",
                "api_version": "1",
                "master_uid": 0,
                "challenges": [],
            },
        )

    transport = httpx.MockTransport(handler)

    class Client(httpx.AsyncClient):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(transport=transport)

    async def run() -> None:
        import base.validator.registry_client as module

        monkeypatch.setattr(module.httpx, "AsyncClient", Client)
        response = await RegistryClient("http://registry").fetch_registry()
        assert response.challenges == []

    asyncio.run(run())


def test_registry_client_default_validator_url_requests_public_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_urls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "network": "platform",
                "api_version": "1",
                "master_uid": 0,
                "challenges": [],
            },
        )

    transport = httpx.MockTransport(handler)

    class Client(httpx.AsyncClient):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(transport=transport)

    async def run() -> None:
        import base.validator.registry_client as module

        monkeypatch.setattr(module.httpx, "AsyncClient", Client)
        response = await RegistryClient(
            ValidatorSettings().registry_url
        ).fetch_registry()
        assert response.challenges == []

    asyncio.run(run())

    assert requested_urls == ["https://chain.joinbase.ai/v1/registry"]


def test_registry_client_trailing_slash_requests_single_registry_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_urls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "network": "platform",
                "api_version": "1",
                "master_uid": 0,
                "challenges": [],
            },
        )

    transport = httpx.MockTransport(handler)

    class Client(httpx.AsyncClient):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(transport=transport)

    async def run() -> None:
        import base.validator.registry_client as module

        monkeypatch.setattr(module.httpx, "AsyncClient", Client)
        response = await RegistryClient("https://chain.joinbase.ai/").fetch_registry()
        assert response.challenges == []

    asyncio.run(run())

    assert requested_urls == ["https://chain.joinbase.ai/v1/registry"]
