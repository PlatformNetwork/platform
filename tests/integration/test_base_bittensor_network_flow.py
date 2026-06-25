from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest

import base.master.challenge_client as challenge_client_module
from base.bittensor.metagraph_cache import MetagraphCache
from base.bittensor.weight_setter import WeightSetter
from base.master.challenge_client import ChallengeClient
from base.master.service import MasterWeightService
from base.schemas.challenge import ChallengeStatus, RegistryChallenge
from base.validator.normal_runner import NormalValidatorRunner
from base.validator.weights_client import WeightsClient


@pytest.mark.asyncio
async def test_base_challenge_weights_and_bittensor_weight_epoch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    servers = {
        "http://challenge-agent-challenge:8000": InMemoryChallengeServer(
            slug="agent-challenge",
            token="challenge-token-a",
            weights={"miner-a": 0.25, "miner-b": 0.75},
        ),
        "http://challenge-terminal-heavy:8000": InMemoryChallengeServer(
            slug="terminal-heavy",
            token="challenge-token-b",
            weights={"miner-b": 1.0, "miner-c": 1.0},
        ),
    }
    _install_in_memory_httpx(monkeypatch, servers)

    challenges = [
        _registry_challenge(
            "agent-challenge",
            Decimal("60"),
            "http://challenge-agent-challenge:8000",
        ),
        _registry_challenge(
            "terminal-heavy",
            Decimal("40"),
            "http://challenge-terminal-heavy:8000",
        ),
    ]
    tokens = {
        "agent-challenge": "challenge-token-a",
        "terminal-heavy": "challenge-token-b",
    }

    subtensor = FakeSubtensor(["validator", "miner-a", "miner-b", "miner-c"])
    service = MasterWeightService(
        metagraph_cache=MetagraphCache(netuid=42, ttl_seconds=0, subtensor=subtensor),
        weight_setter=WeightSetter(subtensor=subtensor, wallet=object(), netuid=42),
        challenge_client=ChallengeClient(retries=1),
    )
    latest = await service.compute_latest_response(
        challenges,
        tokens,
        netuid=42,
        chain_endpoint="wss://chain.example:9944",
    )

    assert latest.uids == [1, 2, 3]
    assert latest.weights == pytest.approx([0.15, 0.65, 0.20])
    assert latest.hotkey_weights == {
        "miner-a": pytest.approx(0.15),
        "miner-b": pytest.approx(0.65),
        "miner-c": pytest.approx(0.20),
    }
    assert [result.slug for result in latest.source_challenges] == [
        "agent-challenge",
        "terminal-heavy",
    ]
    assert subtensor.metagraph_calls == [42]
    assert subtensor.set_weight_calls == []

    # The per-challenge shared token is forwarded to each challenge's internal
    # weights endpoint, scoped by the challenge slug header.
    agent_server = servers["http://challenge-agent-challenge:8000"]
    heavy_server = servers["http://challenge-terminal-heavy:8000"]
    assert agent_server.authorization == "Bearer challenge-token-a"
    assert heavy_server.authorization == "Bearer challenge-token-b"
    assert agent_server.forwarded_slug == "agent-challenge"
    assert heavy_server.forwarded_slug == "terminal-heavy"
    assert agent_server.path == "/internal/v1/get_weights"

    weights_client = SharedWeightsClient(latest)
    validator_a = NormalValidatorRunner(
        registry_client=cast(Any, SimpleNamespace()),
        orchestrator=SimpleNamespace(),
        weights_client=cast(WeightsClient, weights_client),
        weight_setter=WeightSetter(
            subtensor=subtensor, wallet="validator-a-hotkey", netuid=42
        ),
        netuid=42,
    )
    validator_b = NormalValidatorRunner(
        registry_client=cast(Any, SimpleNamespace()),
        orchestrator=SimpleNamespace(),
        weights_client=cast(WeightsClient, weights_client),
        weight_setter=WeightSetter(
            subtensor=subtensor, wallet="validator-b-hotkey", netuid=42
        ),
        netuid=42,
    )

    assert await validator_a.submit_latest_weights() is True
    assert await validator_b.submit_latest_weights() is True
    assert weights_client.fetches == [latest, latest]
    assert subtensor.set_weight_calls == [
        {
            "wallet": "validator-a-hotkey",
            "netuid": 42,
            "uids": [1, 2, 3],
            "weights": pytest.approx([0.15, 0.65, 0.20]),
            "version_key": 0,
            "wait_for_inclusion": False,
            "wait_for_finalization": False,
        },
        {
            "wallet": "validator-b-hotkey",
            "netuid": 42,
            "uids": [1, 2, 3],
            "weights": pytest.approx([0.15, 0.65, 0.20]),
            "version_key": 0,
            "wait_for_inclusion": False,
            "wait_for_finalization": False,
        },
    ]


class InMemoryChallengeServer:
    """Captures the authenticated GET to a challenge's internal weights route."""

    def __init__(self, *, slug: str, token: str, weights: dict[str, float]) -> None:
        self.slug = slug
        self.token = token
        self.weights = weights
        self.authorization: str | None = None
        self.forwarded_slug: str | None = None
        self.path: str | None = None

    def handle(self, url: str, headers: dict[str, str]) -> httpx.Response:
        request = httpx.Request("GET", url)
        self.authorization = _header(headers, "authorization")
        self.forwarded_slug = _header(headers, "x-base-challenge-slug")
        self.path = request.url.path
        return httpx.Response(
            200,
            json={"challenge_slug": self.slug, "weights": self.weights},
            request=request,
        )


class SharedWeightsClient:
    def __init__(self, payload: Any) -> None:
        self.payload = payload
        self.fetches: list[Any] = []

    async def fetch_latest(self) -> Any:
        self.fetches.append(self.payload)
        return self.payload


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


def _install_in_memory_httpx(
    monkeypatch: pytest.MonkeyPatch, servers: dict[str, InMemoryChallengeServer]
) -> None:
    class AsyncClient:
        def __init__(self, *_: Any, **__: Any) -> None:
            return None

        async def __aenter__(self) -> AsyncClient:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def get(
            self, url: str, *, headers: dict[str, str] | None = None
        ) -> httpx.Response:
            base = url.split("/internal/v1/get_weights", 1)[0]
            return servers[base].handle(url, headers or {})

    monkeypatch.setattr(challenge_client_module.httpx, "AsyncClient", AsyncClient)


def _registry_challenge(
    slug: str, emission_percent: Decimal, internal_base_url: str
) -> RegistryChallenge:
    return RegistryChallenge(
        slug=slug,
        name=slug,
        image=f"ghcr.io/baseintelligence/{slug}:latest",
        version="1",
        emission_percent=emission_percent,
        status=ChallengeStatus.ACTIVE,
        internal_base_url=internal_base_url,
        public_proxy_base_path=f"/challenges/{slug}",
        required_capabilities=["get_weights", "proxy_routes"],
        resources={},
        volumes={},
        env={},
        secrets=[],
    )


def _header(headers: dict[str, str], name: str) -> str:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return ""
