from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest

from platform_network.bittensor.metagraph_cache import MetagraphCache
from platform_network.bittensor.weight_setter import WeightSetter
from platform_network.kubernetes.registry import FileKubernetesTargetRegistry
from platform_network.master.challenge_client import ChallengeClient
from platform_network.master.docker_orchestrator import (
    ChallengeResources,
    ChallengeSpec,
)
from platform_network.master.kubernetes_broker import KubernetesBrokerRouterService
from platform_network.master.kubernetes_orchestrator import (
    KubernetesOrchestrator,
    KubernetesTargetRouter,
)
from platform_network.master.service import MasterWeightService
from platform_network.schemas.challenge import ChallengeStatus, RegistryChallenge
from platform_network.schemas.docker_broker import BrokerRunRequest
from platform_network.schemas.kubernetes_target import KubernetesTargetCreate


@pytest.mark.asyncio
async def test_platform_agents_broker_and_bittensor_weight_epoch(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    servers = {
        "https://agent-a": InMemoryAgentServer(
            token="agent-token-a",
            weights_by_slug={
                "agent-challenge": {"miner-a": 0.25, "miner-b": 0.75},
            },
        ),
        "https://agent-b": InMemoryAgentServer(
            token="agent-token-b",
            weights_by_slug={
                "terminal-heavy": {"miner-b": 1.0, "miner-c": 1.0},
            },
        ),
    }
    _install_in_memory_httpx(monkeypatch, servers)

    target_registry = FileKubernetesTargetRegistry(
        tmp_path / "targets.json", secret_dir=tmp_path / "secrets"
    )
    target_registry.create(
        KubernetesTargetCreate(
            id="agent-a",
            mode="agent",
            agent_url="https://agent-a",
            agent_token="agent-token-a",
            verify_tls=False,
            timeout_seconds=3,
            gpu_count=2,
        )
    )
    target_registry.create(
        KubernetesTargetCreate(
            id="agent-b",
            mode="agent",
            agent_url="https://agent-b",
            agent_token="agent-token-b",
            verify_tls=False,
            timeout_seconds=3,
            gpu_count=4,
        )
    )
    settings = SimpleNamespace(
        docker=SimpleNamespace(
            broker_url="http://platform-broker:8082",
            broker_allowed_images=("ghcr.io/platformnetwork/",),
        )
    )
    router = KubernetesTargetRouter(
        default_orchestrator=cast(KubernetesOrchestrator, UnusedOrchestrator()),
        settings=settings,
        target_registry=target_registry,
    )

    agent_runtime = router.start_challenge(
        ChallengeSpec(
            slug="agent-challenge",
            image="ghcr.io/platformnetwork/agent-challenge:latest",
            challenge_token="challenge-token-a",
            docker_broker_token="broker-token-a",
            resources=ChallengeResources(gpu_count=1),
            required_capabilities=(
                "get_weights",
                "proxy_routes",
                "docker_executor",
            ),
        )
    )
    heavy_runtime = router.start_challenge(
        ChallengeSpec(
            slug="terminal-heavy",
            image="ghcr.io/platformnetwork/terminal-heavy:latest",
            challenge_token="challenge-token-b",
            docker_broker_token="broker-token-b",
            resources=ChallengeResources(gpu_server="agent-b", gpu_count=2),
            required_capabilities=(
                "get_weights",
                "proxy_routes",
                "docker_executor",
            ),
        )
    )

    assert agent_runtime.container_name == "challenge-agent-challenge"
    assert heavy_runtime.container_name == "challenge-terminal-heavy"
    assert target_registry.get_assignment("agent-challenge") == "agent-a"
    assert target_registry.get_assignment("terminal-heavy") == "agent-b"
    assert (
        servers["https://agent-a"].starts[0]["env"]["CHALLENGE_DOCKER_BROKER_URL"]
        == "http://platform-broker:8082"
    )

    challenges = [
        _registry_challenge(
            "agent-challenge",
            Decimal("60"),
            {"gpu_count": "1"},
            agent_runtime.internal_base_url,
        ),
        _registry_challenge(
            "terminal-heavy",
            Decimal("40"),
            {"gpu_server": "agent-b", "gpu_count": "2"},
            heavy_runtime.internal_base_url,
        ),
    ]
    broker_router = KubernetesBrokerRouterService(
        default_service=UnusedBrokerService(),
        challenge_registry=ChallengeRegistry(challenges),
        settings=settings,
        target_registry=target_registry,
    )
    broker_response = broker_router.run(
        "agent-challenge",
        BrokerRunRequest(
            job_id="terminal-bench-job",
            task_id="terminal-bench@2.1",
            image="ghcr.io/platformnetwork/terminal-bench-runner:2.1",
            command=[
                "bash",
                "-lc",
                "harbor run --dataset terminal-bench@2.1 --include-task-name hello",
            ],
            env={"PLATFORM_BENCHMARK_DATASET": "terminal-bench@2.1"},
            labels={"platform.benchmark": "terminal_bench"},
            timeout_seconds=120,
        ),
    )

    assert broker_response.returncode == 0
    assert "PLATFORM_BENCHMARK_RESULT=" in broker_response.stdout
    assert servers["https://agent-a"].broker_runs[0]["job_id"] == "terminal-bench-job"
    assert (
        servers["https://agent-a"].broker_runs[0]["env"]["PLATFORM_BENCHMARK_DATASET"]
        == "terminal-bench@2.1"
    )

    subtensor = FakeSubtensor(["validator", "miner-a", "miner-b", "miner-c"])
    service = MasterWeightService(
        metagraph_cache=MetagraphCache(netuid=42, ttl_seconds=0, subtensor=subtensor),
        weight_setter=WeightSetter(subtensor=subtensor, wallet=object(), netuid=42),
        challenge_client=ChallengeClient(
            retries=1, kubernetes_target_registry=target_registry
        ),
    )
    final = await service.run_epoch(
        challenges,
        {"agent-challenge": "challenge-token-a", "terminal-heavy": "challenge-token-b"},
    )

    assert final.uids == [1, 2, 3]
    assert final.weights == pytest.approx([0.15, 0.65, 0.20])
    assert subtensor.metagraph_calls == [42]
    assert subtensor.set_weight_calls == [
        {
            "wallet": service.weight_setter.wallet,
            "netuid": 42,
            "uids": [1, 2, 3],
            "weights": pytest.approx([0.15, 0.65, 0.20]),
            "wait_for_inclusion": False,
            "wait_for_finalization": False,
        }
    ]
    assert servers["https://agent-a"].forwarded_auth["agent-challenge"] == (
        "Bearer challenge-token-a"
    )
    assert servers["https://agent-b"].forwarded_auth["terminal-heavy"] == (
        "Bearer challenge-token-b"
    )


class InMemoryAgentServer:
    def __init__(
        self, *, token: str, weights_by_slug: dict[str, dict[str, float]]
    ) -> None:
        self.token = token
        self.weights_by_slug = weights_by_slug
        self.starts: list[dict[str, Any]] = []
        self.broker_runs: list[dict[str, Any]] = []
        self.forwarded_auth: dict[str, str] = {}
        self._runtime: dict[str, dict[str, Any]] = {}

    def handle(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json_payload: dict[str, Any] | None = None,
    ) -> httpx.Response:
        self._authenticate(headers or {})
        path_only = path.split("?", 1)[0]
        if method == "GET" and path_only == "/health":
            return _json_response(method, path, {"status": "ok"})
        if method == "POST" and path_only == "/v1/challenges/start":
            payload = dict(json_payload or {})
            self.starts.append(payload)
            runtime = _runtime_payload(str(payload["slug"]), str(payload["image"]))
            self._runtime[str(payload["slug"])] = runtime
            return _json_response(method, path, runtime)
        if method == "POST" and path_only.startswith("/v1/broker/"):
            slug = path_only.split("/")[3]
            payload = dict(json_payload or {})
            self.broker_runs.append(payload | {"challenge_slug": slug})
            return _json_response(
                method,
                path,
                {
                    "container_name": f"broker-{slug}",
                    "stdout": (
                        'PLATFORM_BENCHMARK_RESULT={"score": 1.0, '
                        '"status": "completed"}'
                    ),
                    "stderr": "",
                    "returncode": 0,
                    "timed_out": False,
                },
            )
        if method == "GET" and path_only.startswith("/v1/challenges/"):
            parts = path_only.split("/")
            slug = parts[3]
            if len(parts) == 5 and parts[4] == "status":
                return _json_response(method, path, self._runtime[slug])
            if len(parts) >= 6 and parts[4] == "proxy":
                self.forwarded_auth[slug] = _header(
                    headers or {}, "x-platform-forward-authorization"
                )
                return _json_response(
                    method,
                    path,
                    {
                        "challenge_slug": slug,
                        "weights": self.weights_by_slug[slug],
                    },
                )
        return _json_response(method, path, {"detail": "not found"}, status_code=404)

    def _authenticate(self, headers: dict[str, str]) -> None:
        assert _header(headers, "authorization") == f"Bearer {self.token}"


class ChallengeRegistry:
    def __init__(self, challenges: list[RegistryChallenge]) -> None:
        self._challenges = {challenge.slug: challenge for challenge in challenges}

    def get(self, slug: str) -> RegistryChallenge:
        return self._challenges[slug]


class FakeSubtensor:
    def __init__(self, hotkeys: list[str]) -> None:
        self.hotkeys = hotkeys
        self.metagraph_calls: list[int] = []
        self.set_weight_calls: list[dict[str, Any]] = []

    def metagraph(self, netuid: int) -> SimpleNamespace:
        self.metagraph_calls.append(netuid)
        return SimpleNamespace(hotkeys=self.hotkeys)

    def set_weights(self, **kwargs: Any) -> dict[str, bool]:
        self.set_weight_calls.append(kwargs)
        return {"success": True}


class UnusedOrchestrator:
    @property
    def runtime(self) -> dict[str, Any]:
        return {}

    def start_challenge(self, *_: Any, **__: Any) -> None:
        raise AssertionError("default orchestrator should not be used")

    def stop_challenge(self, *_: Any, **__: Any) -> None:
        raise AssertionError("default orchestrator should not be used")


class UnusedBrokerService:
    def run(self, *_: Any, **__: Any) -> None:
        raise AssertionError("default broker service should not be used")

    def cleanup(self, *_: Any, **__: Any) -> None:
        raise AssertionError("default broker service should not be used")

    def list_containers(self, *_: Any, **__: Any) -> None:
        raise AssertionError("default broker service should not be used")


def _install_in_memory_httpx(
    monkeypatch: pytest.MonkeyPatch, servers: dict[str, InMemoryAgentServer]
) -> None:
    class SyncClient:
        def __init__(self, *, base_url: str, **_: Any) -> None:
            self.server = servers[base_url.rstrip("/")]

        def __enter__(self) -> SyncClient:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def post(
            self, path: str, *, json: dict[str, Any], headers: dict[str, str]
        ) -> httpx.Response:
            return self.server.handle("POST", path, headers=headers, json_payload=json)

        def get(self, path: str, *, headers: dict[str, str]) -> httpx.Response:
            return self.server.handle("GET", path, headers=headers)

    class AsyncClient:
        def __init__(self, *, base_url: str, **_: Any) -> None:
            self.server = servers[base_url.rstrip("/")]

        async def __aenter__(self) -> AsyncClient:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def request(
            self,
            method: str,
            url: str,
            *,
            headers: dict[str, str],
            **_: Any,
        ) -> httpx.Response:
            return self.server.handle(method, url, headers=headers)

    import platform_network.kubernetes.agent as agent_module

    monkeypatch.setattr(agent_module.httpx, "Client", SyncClient)
    monkeypatch.setattr(agent_module.httpx, "AsyncClient", AsyncClient)


def _registry_challenge(
    slug: str,
    emission_percent: Decimal,
    resources: dict[str, str],
    internal_base_url: str,
) -> RegistryChallenge:
    return RegistryChallenge(
        slug=slug,
        name=slug,
        image=f"ghcr.io/platformnetwork/{slug}:latest",
        version="1",
        emission_percent=emission_percent,
        status=ChallengeStatus.ACTIVE,
        internal_base_url=internal_base_url,
        public_proxy_base_path=f"/challenges/{slug}",
        required_capabilities=["get_weights", "proxy_routes", "docker_executor"],
        resources=resources,
        volumes={},
        env={},
        secrets=[],
    )


def _runtime_payload(slug: str, image: str) -> dict[str, Any]:
    return {
        "slug": slug,
        "image": image,
        "container_id": f"cid-{slug}",
        "container_name": f"challenge-{slug}",
        "internal_base_url": f"http://challenge-{slug}:8000",
        "sqlite_volume_name": f"platform_{slug.replace('-', '_')}_sqlite",
        "health": {"status": "ok"},
        "version": {"api_version": "1.0"},
    }


def _json_response(
    method: str, url: str, payload: dict[str, Any], *, status_code: int = 200
) -> httpx.Response:
    return httpx.Response(
        status_code,
        json=payload,
        request=httpx.Request(method, f"https://in-memory{url}"),
    )


def _header(headers: dict[str, str], name: str) -> str:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return ""
