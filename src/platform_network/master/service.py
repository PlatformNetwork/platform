from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from platform_network.bittensor.metagraph_cache import MetagraphCache
from platform_network.bittensor.weight_setter import WeightSetter
from platform_network.gpu.capabilities import ResourceCapabilityChecker
from platform_network.master.aggregator import aggregate_challenge_weights
from platform_network.master.challenge_client import ChallengeClient
from platform_network.master.docker_orchestrator import ChallengeResources
from platform_network.master.registry import record_to_registry_view
from platform_network.schemas.challenge import RegistryChallenge
from platform_network.schemas.weights import (
    MASTER_WEIGHTS_FRESHNESS_SECONDS,
    ChallengeWeightsResult,
    FinalWeights,
    MasterWeightsResponse,
)

logger = logging.getLogger(__name__)


async def _resolve(value):  # type: ignore[no-untyped-def]
    if inspect.isawaitable(value):
        return await value
    return value


async def active_challenge_inputs(
    registry,  # type: ignore[no-untyped-def]
) -> tuple[list[RegistryChallenge], dict[str, str]]:
    records = await _resolve(registry.list(active_only=True))
    challenges = [record_to_registry_view(record) for record in records]
    tokens = {
        record.slug: await _resolve(registry.get_token(record.slug))
        for record in records
    }
    return challenges, tokens


def _metagraph_updated_at(
    metagraph_cache: MetagraphCache, fallback: datetime
) -> datetime:
    updated_at = float(getattr(metagraph_cache, "_updated_at", 0.0) or 0.0)
    if updated_at <= 0:
        return fallback
    return datetime.fromtimestamp(updated_at, UTC)


class MasterWeightService:
    def __init__(
        self,
        *,
        metagraph_cache: MetagraphCache,
        weight_setter: WeightSetter | None = None,
        challenge_client: ChallengeClient | None = None,
        capability_checker: ResourceCapabilityChecker | None = None,
    ) -> None:
        self.metagraph_cache = metagraph_cache
        self.weight_setter = weight_setter
        self.challenge_client = challenge_client or ChallengeClient()
        self.capability_checker = capability_checker

    async def collect_weights(
        self, challenges: list[RegistryChallenge], tokens: dict[str, str]
    ) -> list[ChallengeWeightsResult]:
        results: list[ChallengeWeightsResult] = []
        for challenge in challenges:
            decision = (
                self.capability_checker.check(
                    ChallengeResources.from_mapping(challenge.resources)
                )
                if self.capability_checker is not None
                else None
            )
            if decision is not None and not decision.can_run:
                raise RuntimeError(
                    f"challenge {challenge.slug!r} cannot run: {decision.reason}"
                )
            token = tokens.get(challenge.slug)
            if not token:
                raise RuntimeError(f"challenge {challenge.slug!r} is missing a token")
            result = await self.challenge_client.get_weights(
                slug=challenge.slug,
                base_url=challenge.internal_base_url,
                token=token,
                emission_percent=float(challenge.emission_percent),
            )
            if not result.ok:
                raise RuntimeError(
                    f"challenge {challenge.slug!r} failed to provide weights: "
                    f"{result.error or 'unknown error'}"
                )
            results.append(result)
        return results

    async def compute_weights(
        self, challenges: list[RegistryChallenge], tokens: dict[str, str]
    ) -> tuple[FinalWeights, list[ChallengeWeightsResult]]:
        hotkey_to_uid = self.metagraph_cache.get()
        results = await self.collect_weights(challenges, tokens)
        return aggregate_challenge_weights(results, hotkey_to_uid), results

    async def compute_latest_response(
        self,
        challenges: list[RegistryChallenge],
        tokens: dict[str, str],
        *,
        netuid: int,
        chain_endpoint: str,
        now_fn: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> MasterWeightsResponse:
        computed_at = now_fn()
        final, results = await self.compute_weights(challenges, tokens)
        return MasterWeightsResponse(
            netuid=netuid,
            chain_endpoint=chain_endpoint,
            uids=final.uids,
            weights=final.weights,
            hotkey_weights=final.hotkey_weights,
            computed_at=computed_at,
            expires_at=computed_at
            + timedelta(seconds=MASTER_WEIGHTS_FRESHNESS_SECONDS),
            source_challenges=results,
            metagraph_updated_at=_metagraph_updated_at(
                self.metagraph_cache, computed_at
            ),
        )

    async def run_epoch(
        self,
        challenges: list[RegistryChallenge],
        tokens: dict[str, str],
        *,
        submit: bool = True,
    ) -> FinalWeights:
        final, _results = await self.compute_weights(challenges, tokens)
        if not submit:
            logger.info(
                "computed weights without submitting",
                extra={"uids": len(final.uids), "challenges": len(challenges)},
            )
            return final
        if self.weight_setter is None:
            raise RuntimeError("WeightSetter is required when submit=True")
        self.weight_setter.set_weights(final.uids, final.weights)
        logger.info(
            "set weights",
            extra={"uids": len(final.uids), "challenges": len(challenges)},
        )
        return final
