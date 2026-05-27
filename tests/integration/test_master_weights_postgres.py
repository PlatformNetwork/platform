from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import cast

import pytest

import platform_network.cli_app.main as cli_module
from platform_network.bittensor.metagraph_cache import MetagraphCache
from platform_network.bittensor.weight_setter import WeightSetter
from platform_network.db.session import create_engine, create_session_factory
from platform_network.master.challenge_client import ChallengeClient
from platform_network.master.registry import DatabaseChallengeRegistry
from platform_network.master.service import MasterWeightService
from platform_network.schemas.challenge import ChallengeCreate, ChallengeStatus
from platform_network.schemas.weights import ChallengeWeightsResult


@pytest.mark.postgres
async def test_master_weights_dry_run_uses_postgres_active_challenges_without_submit(
    tmp_path: Path,
    migrated_postgres_database: str,
    cleanup_postgres_database: Callable[[], Awaitable[None]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_engine(migrated_postgres_database)
    registry = DatabaseChallengeRegistry(
        create_session_factory(engine),
        secret_dir=tmp_path / "secrets",
        master_uid=3,
    )

    set_weight_calls: list[tuple[list[int], list[float]]] = []

    def fail_set_weights(
        self: WeightSetter, uids: list[int], weights: list[float]
    ) -> None:
        set_weight_calls.append((uids, weights))
        raise AssertionError("dry-run must not call WeightSetter.set_weights")

    monkeypatch.setattr(WeightSetter, "set_weights", fail_set_weights)
    try:
        await registry.create(
            ChallengeCreate(
                slug="weights-smoke-active",
                name="Weights Smoke Active",
                image="ghcr.io/platformnetwork/weights-smoke:1.0.0",
                version="1.0.0",
                emission_percent=Decimal("100"),
                status=ChallengeStatus.ACTIVE,
                internal_base_url="http://challenge-weights-smoke:8000",
            )
        )
        await registry.create(
            ChallengeCreate(
                slug="weights-smoke-inactive",
                name="Weights Smoke Inactive",
                image="ghcr.io/platformnetwork/weights-smoke:1.0.0",
                version="1.0.0",
                emission_percent=Decimal("0"),
                status=ChallengeStatus.INACTIVE,
                internal_base_url="http://challenge-weights-smoke-inactive:8000",
            )
        )

        service = MasterWeightService(
            metagraph_cache=cast(MetagraphCache, Cache()),
            weight_setter=WeightSetter(subtensor=None, wallet=None, netuid=0),
            challenge_client=cast(ChallengeClient, Client()),
        )

        final = await cli_module._run_master_weight_epoch(  # noqa: SLF001
            service,
            registry,
            submit=False,
        )

        assert final.uids == [9]
        assert final.weights == [1.0]
        assert set_weight_calls == []
    finally:
        await engine.dispose()
        await cleanup_postgres_database()


@pytest.mark.postgres
async def test_master_weights_latest_response_uses_active_challenges_no_submit(
    tmp_path: Path,
    migrated_postgres_database: str,
    cleanup_postgres_database: Callable[[], Awaitable[None]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_engine(migrated_postgres_database)
    registry = DatabaseChallengeRegistry(
        create_session_factory(engine),
        secret_dir=tmp_path / "secrets",
        master_uid=3,
    )

    set_weight_calls: list[tuple[list[int], list[float]]] = []

    def fail_set_weights(
        self: WeightSetter, uids: list[int], weights: list[float]
    ) -> None:
        set_weight_calls.append((uids, weights))
        raise AssertionError("weights API must not call WeightSetter.set_weights")

    monkeypatch.setattr(WeightSetter, "set_weights", fail_set_weights)
    try:
        await registry.create(
            ChallengeCreate(
                slug="prism",
                name="PRISM",
                image="ghcr.io/platformnetwork/prism:latest",
                version="0.1.0",
                emission_percent=Decimal("30"),
                status=ChallengeStatus.ACTIVE,
                internal_base_url="http://challenge-prism:8000",
            )
        )
        await registry.create(
            ChallengeCreate(
                slug="agent-challenge",
                name="Agent Challenge",
                image="ghcr.io/platformnetwork/agent-challenge:1.0.0",
                version="1.0.0",
                emission_percent=Decimal("15"),
                status=ChallengeStatus.ACTIVE,
                internal_base_url="http://challenge-agent-challenge:8000",
            )
        )
        await registry.create(
            ChallengeCreate(
                slug="weights-api-active",
                name="Weights API Active",
                image="ghcr.io/platformnetwork/weights-smoke:1.0.0",
                version="1.0.0",
                emission_percent=Decimal("5"),
                status=ChallengeStatus.ACTIVE,
                internal_base_url="http://challenge-weights-api:8000",
            )
        )
        await registry.create(
            ChallengeCreate(
                slug="weights-api-inactive",
                name="Weights API Inactive",
                image="ghcr.io/platformnetwork/weights-smoke:1.0.0",
                version="1.0.0",
                emission_percent=Decimal("50"),
                status=ChallengeStatus.INACTIVE,
                internal_base_url="http://challenge-weights-api-inactive:8000",
            )
        )

        service = MasterWeightService(
            metagraph_cache=cast(MetagraphCache, Cache()),
            weight_setter=WeightSetter(subtensor=None, wallet=None, netuid=0),
            challenge_client=cast(ChallengeClient, Client()),
        )

        response = await cli_module._run_master_weight_epoch_response(  # noqa: SLF001
            service,
            registry,
            netuid=42,
            chain_endpoint="wss://chain.example:9944",
            now_fn=lambda: datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
        )

        assert response.uids == [5, 15, 30]
        assert [round(weight, 8) for weight in response.weights] == [
            round(5 / 50, 8),
            round(15 / 50, 8),
            round(30 / 50, 8),
        ]
        assert response.hotkey_weights == {
            "prism-hotkey": 30 / 50,
            "agent-hotkey": 15 / 50,
            "other-hotkey": 5 / 50,
        }
        source_emissions = {
            result.slug: result.emission_percent
            for result in response.source_challenges
        }
        assert source_emissions == {
            "prism": 30.0,
            "agent-challenge": 15.0,
            "weights-api-active": 5.0,
        }
        assert response.netuid == 42
        assert set_weight_calls == []
    finally:
        await engine.dispose()
        await cleanup_postgres_database()


class Cache:
    def get(self) -> dict[str, int]:
        return {
            "miner-hotkey": 9,
            "prism-hotkey": 30,
            "agent-hotkey": 15,
            "other-hotkey": 5,
        }


class Client:
    def __init__(self) -> None:
        self.slugs: list[str] = []

    async def get_weights(self, **kwargs: object) -> ChallengeWeightsResult:
        slug = str(kwargs["slug"])
        self.slugs.append(slug)
        assert slug in {
            "weights-smoke-active",
            "weights-api-active",
            "prism",
            "agent-challenge",
        }
        weights_by_slug = {
            "weights-smoke-active": {"miner-hotkey": 1.0},
            "weights-api-active": {"other-hotkey": 1.0},
            "prism": {"prism-hotkey": 1.0},
            "agent-challenge": {"agent-hotkey": 1.0},
        }
        return ChallengeWeightsResult(
            slug=slug,
            emission_percent=float(cast(float, kwargs["emission_percent"])),
            weights=weights_by_slug[slug],
        )
