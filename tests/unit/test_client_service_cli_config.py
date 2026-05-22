from __future__ import annotations

import asyncio
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import httpx
import pytest
from typer.testing import CliRunner

import platform_network.cli_app.main as cli_module
from platform_network.bittensor.metagraph_cache import MetagraphCache
from platform_network.bittensor.validator_loop import run_epoch_loop
from platform_network.bittensor.weight_setter import WeightSetter
from platform_network.cli_app.main import DockerRuntimeController, app
from platform_network.config.loader import load_settings
from platform_network.config.settings import ValidatorSettings
from platform_network.gpu.capabilities import CapabilityDecision
from platform_network.master.challenge_client import ChallengeClient
from platform_network.master.docker_orchestrator import ChallengeSpec
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


@pytest.mark.asyncio
async def test_challenge_client_routes_weights_through_assigned_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []

    class AgentClient:
        def __init__(self, **kwargs: object) -> None:
            calls.append(kwargs)

        async def forward_challenge_request(self, **kwargs: object) -> httpx.Response:
            calls.append(kwargs)
            return httpx.Response(
                200,
                json={"challenge_slug": "demo", "weights": {"hk": 1.0}},
            )

    class TargetRegistry:
        def get_assignment(self, slug: str) -> str | None:
            return "agent-a"

        def get(self, target_id: str):
            return SimpleNamespace(
                id=target_id,
                mode="agent",
                agent_url="https://agent-a",
                timeout_seconds=12,
                verify_tls=False,
            )

        def get_agent_token(self, target_id: str) -> str:
            return "agent-token"

    import platform_network.master.challenge_client as challenge_client_module

    monkeypatch.setattr(challenge_client_module, "KubernetesAgentClient", AgentClient)
    result = await ChallengeClient(
        retries=1,
        kubernetes_target_registry=TargetRegistry(),
    ).get_weights(
        slug="demo",
        base_url="http://unreachable",
        token="challenge-token",
        emission_percent=5,
    )

    assert result.ok
    assert calls[0]["base_url"] == "https://agent-a"
    assert calls[1]["path"] == "/internal/v1/get_weights"
    forwarded_headers = cast(dict[str, str], calls[1]["headers"])
    assert forwarded_headers["Authorization"] == "Bearer challenge-token"


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
            "wait_for_inclusion": False,
            "wait_for_finalization": False,
        }
    ]


@pytest.mark.asyncio
async def test_master_weight_service_fails_when_capability_blocked() -> None:
    class Cache:
        def get(self) -> dict[str, int]:
            return {"hk": 5}

    class Setter:
        def __init__(self) -> None:
            self.calls: list[tuple[list[int], list[float]]] = []

        def set_weights(self, uids: list[int], weights: list[float]) -> None:
            self.calls.append((uids, weights))

    class Checker:
        def check(self, resources) -> CapabilityDecision:
            return CapabilityDecision(False, "gpu_server_unknown")

    challenge = RegistryChallenge(
        slug="gpu-demo",
        name="GPU Demo",
        image="ghcr.io/o/demo:1",
        version="1",
        emission_percent=Decimal("10"),
        status=ChallengeStatus.ACTIVE,
        internal_base_url="http://challenge-demo:8000",
        public_proxy_base_path="/challenges/demo",
        required_capabilities=["get_weights", "proxy_routes"],
        resources={"gpu_server": "missing", "gpu_count": "1"},
        volumes={},
        env={},
        secrets=[],
    )
    setter = Setter()
    service = MasterWeightService(
        metagraph_cache=cast(MetagraphCache, Cache()),
        weight_setter=cast(WeightSetter, setter),
        capability_checker=Checker(),  # type: ignore[arg-type]
    )

    with pytest.raises(RuntimeError, match="cannot run"):
        await service.run_epoch([challenge], {})
    assert setter.calls == []


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
    assert asyncio.run(controller.status("demo"))["status"] == "unknown"


def test_cli_master_weights_once_wires_bittensor_runtime(
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
    monkeypatch.setattr(cli_module, "ChallengeClient", Client)
    monkeypatch.setattr(cli_module, "_run_startup_migrations", lambda _settings: None)
    monkeypatch.setattr(cli_module, "_master_registry", lambda _settings: registry)

    result = CliRunner().invoke(
        app, ["master", "weights", "--config", str(config), "--once"]
    )

    assert result.exit_code == 0
    assert "submit: computed 1 weights" in result.output
    assert created_runtime["netuid"] == 12
    assert created_runtime["chain_endpoint"] == "ws://chain"
    assert created_runtime["wallet_name"] == "wallet"
    assert created_runtime["wallet_hotkey"] == "hotkey"
    client_kwargs = cast(dict[str, object], created_runtime["client_kwargs"])
    assert client_kwargs["timeout_seconds"] == 1.5
    assert client_kwargs["retries"] == 2
    assert client_kwargs["kubernetes_target_registry"] is not None
    assert setter_calls == [([7], [1.0])]


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


def test_cli_gpu_clients_loads_enabled_servers(tmp_path: Path) -> None:
    token_file = tmp_path / "gpu-token"
    token_file.write_text("file-token", encoding="utf-8")
    config = tmp_path / "validator.yaml"
    config.write_text(
        "\n".join(
            [
                "gpu_servers:",
                "  - id: gpu-a",
                "    base_url: https://gpu-a",
                f"    token_file: {token_file}",
                "    verify_tls: true",
                "    timeout_seconds: 9",
                "  - id: gpu-b",
                "    base_url: https://gpu-b",
                "    token: disabled",
                "    enabled: false",
            ]
        ),
        encoding="utf-8",
    )

    clients = cli_module._gpu_clients(load_settings(config))  # noqa: SLF001

    assert list(clients) == ["gpu-a"]
    assert clients["gpu-a"].token == "file-token"
    assert clients["gpu-a"].verify_tls is True
    assert clients["gpu-a"].timeout_seconds == 9


def test_cli_gpu_server_commands_call_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str, dict[str, object] | None]] = []

    def admin_request(
        config: Path,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> None:
        calls.append((method, path, payload))

    monkeypatch.setattr(cli_module, "_admin_request", admin_request)
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "gpu-server",
            "add",
            "gpu-a",
            "--url",
            "https://gpu-a",
            "--token",
            "tok",
            "--no-verify-tls",
        ],
    )
    assert result.exit_code == 0
    assert calls[0][0] == "POST"
    assert calls[0][1] == "/v1/admin/gpu-servers"
    assert calls[0][2]["id"] == "gpu-a"  # type: ignore[index]
    assert calls[0][2]["verify_tls"] is False  # type: ignore[index]

    result = runner.invoke(app, ["gpu-server", "list"])
    assert result.exit_code == 0
    assert calls[1] == ("GET", "/v1/admin/gpu-servers", None)


def test_cli_k8s_server_commands_call_admin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, str, dict[str, object] | None]] = []

    def admin_request(
        config: Path,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> None:
        calls.append((method, path, payload))

    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text("apiVersion: v1\n", encoding="utf-8")
    monkeypatch.setattr(cli_module, "_admin_request", admin_request)
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "k8s-server",
            "add-kubeconfig",
            "k8s-a",
            "--kubeconfig-file",
            str(kubeconfig),
            "--api-url",
            "https://k8s-a",
            "--namespace",
            "platform-gpu",
            "--gpu-count",
            "2",
            "--label",
            "region=eu",
            "--no-verify-tls",
        ],
    )
    assert result.exit_code == 0
    assert calls[0][0] == "POST"
    assert calls[0][1] == "/v1/admin/kubernetes-targets"
    assert calls[0][2]["id"] == "k8s-a"  # type: ignore[index]
    assert calls[0][2]["kubeconfig_file"] == str(kubeconfig)  # type: ignore[index]
    assert calls[0][2]["labels"] == {"region": "eu"}  # type: ignore[index]
    assert calls[0][2]["verify_tls"] is False  # type: ignore[index]

    token_file = tmp_path / "agent-token"
    token_file.write_text("agent-token\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "k8s-server",
            "add",
            "agent-a",
            "--url",
            "https://agent-a",
            "--token-file",
            str(token_file),
            "--gpu-count",
            "4",
        ],
    )
    assert result.exit_code == 0
    assert calls[1][0] == "POST"
    assert calls[1][1] == "/v1/admin/kubernetes-targets"
    assert calls[1][2]["id"] == "agent-a"  # type: ignore[index]
    assert calls[1][2]["mode"] == "agent"  # type: ignore[index]
    assert calls[1][2]["agent_url"] == "https://agent-a"  # type: ignore[index]
    assert calls[1][2]["agent_token"] == "agent-token"  # type: ignore[index]
    assert calls[1][2]["gpu_count"] == 4  # type: ignore[index]

    result = runner.invoke(app, ["k8s-server", "list"])
    assert result.exit_code == 0
    assert calls[2] == ("GET", "/v1/admin/kubernetes-targets", None)

    result = runner.invoke(app, ["k8s-server", "health", "k8s-a"])
    assert result.exit_code == 0
    assert calls[3] == ("POST", "/v1/admin/kubernetes-targets/k8s-a/health", None)

    result = runner.invoke(app, ["k8s-server", "disable", "k8s-a"])
    assert result.exit_code == 0
    assert calls[4] == ("POST", "/v1/admin/kubernetes-targets/k8s-a/disable", None)

    result = runner.invoke(app, ["k8s-server", "enable", "k8s-a"])
    assert result.exit_code == 0
    assert calls[5] == ("POST", "/v1/admin/kubernetes-targets/k8s-a/enable", None)

    result = runner.invoke(app, ["k8s-server", "remove", "k8s-a"])
    assert result.exit_code == 0
    assert calls[6] == ("DELETE", "/v1/admin/kubernetes-targets/k8s-a", None)


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
        import platform_network.validator.registry_client as module

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
        import platform_network.validator.registry_client as module

        monkeypatch.setattr(module.httpx, "AsyncClient", Client)
        response = await RegistryClient(
            ValidatorSettings().registry_url
        ).fetch_registry()
        assert response.challenges == []

    asyncio.run(run())

    assert requested_urls == ["https://chain.platform.network/v1/registry"]


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
        import platform_network.validator.registry_client as module

        monkeypatch.setattr(module.httpx, "AsyncClient", Client)
        response = await RegistryClient(
            "https://chain.platform.network/"
        ).fetch_registry()
        assert response.challenges == []

    asyncio.run(run())

    assert requested_urls == ["https://chain.platform.network/v1/registry"]
