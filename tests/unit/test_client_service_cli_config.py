from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from typer.testing import CliRunner

from platform_network.bittensor.metagraph_cache import MetagraphCache
from platform_network.bittensor.validator_loop import run_epoch_loop
from platform_network.bittensor.weight_setter import WeightSetter
from platform_network.cli import DockerRuntimeController, app
from platform_network.config.loader import load_settings
from platform_network.master.challenge_client import ChallengeClient
from platform_network.master.registry import FileChallengeRegistry
from platform_network.master.service import MasterWeightService
from platform_network.observability.logging import JsonFormatter, configure_logging
from platform_network.observability.otel import init_otel
from platform_network.observability.sentry import init_sentry
from platform_network.schemas.challenge import (
    ChallengeCreate,
    ChallengeStatus,
    RegistryChallenge,
)
from platform_network.schemas.weights import ChallengeWeightsResult
from platform_network.security.admin_auth import constant_time_match, read_secret
from platform_network.security.challenge_auth import (
    bearer_token,
    require_challenge_token,
)
from platform_network.security.tokens import (
    generate_token,
    hash_token,
    token_hint,
    verify_token,
)
from platform_network.validator.normal_runner import NormalValidatorRunner
from platform_network.validator.registry_client import RegistryClient


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
        emission_percent=10,
        status=ChallengeStatus.ACTIVE,
        internal_base_url="http://challenge-demo:8000",
        public_proxy_base_path="/challenges/demo",
        required_capabilities=["get_weights", "proxy_routes"],
        resources={"cpu": "2", "memory": "1g"},
        volumes={},
        env={},
        secrets=[],
    )
    setter = Setter()
    service = MasterWeightService(
        metagraph_cache=Cache(), weight_setter=setter, challenge_client=Client()
    )  # type: ignore[arg-type]
    final = await service.run_epoch([challenge], {"demo": "tok"})
    assert final.uids == [3]
    assert setter.calls == [([3], [1.0])]

    class Registry:
        async def fetch_registry(self):
            return SimpleNamespace(challenges=[challenge])

    class Orchestrator:
        def __init__(self) -> None:
            self.specs = []

        def start_challenge(self, spec):
            self.specs.append(spec)

    orchestrator = Orchestrator()
    runner = NormalValidatorRunner(
        registry_client=Registry(), orchestrator=orchestrator
    )  # type: ignore[arg-type]
    await runner.run_once()
    assert orchestrator.specs[0].slug == "demo"
    assert orchestrator.specs[0].resources.cpu == 2.0
    assert orchestrator.specs[0].resources.memory == "1g"


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
    monkeypatch.setenv("PLATFORM_NETWORK__NETUID", "9")
    monkeypatch.setenv("PLATFORM_MASTER__ADMIN_PORT", "9999")
    monkeypatch.setenv("PLATFORM_DOCKER__BROKER_URL", "http://broker:9999")
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
            self.calls = []

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
        [0], [1.0]
    )
    assert result["ok"] is True


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
        )
    )

    class Orchestrator:
        def __init__(self) -> None:
            self.runtime = {}
            self.pulled = []
            self.specs = []

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
    assert asyncio.run(controller.status("demo"))["status"] == "unknown"


def test_registry_client_with_mock_transport() -> None:
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
    original = httpx.AsyncClient

    class Client(original):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(transport=transport, base_url="http://x")

    async def run() -> None:
        import platform_network.validator.registry_client as module

        module.httpx.AsyncClient = Client  # type: ignore[assignment]
        try:
            response = await RegistryClient("http://registry").fetch_registry()
            assert response.challenges == []
        finally:
            module.httpx.AsyncClient = original  # type: ignore[assignment]

    asyncio.run(run())
