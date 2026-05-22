from __future__ import annotations

from collections.abc import Awaitable, Callable
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

    def fail_set_weights(
        self: WeightSetter, uids: list[int], weights: list[float]
    ) -> None:
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
    finally:
        await engine.dispose()
        await cleanup_postgres_database()


class Cache:
    def get(self) -> dict[str, int]:
        return {"miner-hotkey": 9}


class Client:
    def __init__(self) -> None:
        self.slugs: list[str] = []

    async def get_weights(self, **kwargs: object) -> ChallengeWeightsResult:
        slug = str(kwargs["slug"])
        self.slugs.append(slug)
        assert slug == "weights-smoke-active"
        return ChallengeWeightsResult(
            slug=slug,
            emission_percent=float(cast(float, kwargs["emission_percent"])),
            weights={"miner-hotkey": 1.0},
        )
