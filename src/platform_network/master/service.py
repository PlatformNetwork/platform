from __future__ import annotations

import logging

from platform_network.bittensor.metagraph_cache import MetagraphCache
from platform_network.bittensor.weight_setter import WeightSetter
from platform_network.gpu.capabilities import ResourceCapabilityChecker
from platform_network.master.aggregator import aggregate_challenge_weights
from platform_network.master.challenge_client import ChallengeClient
from platform_network.master.docker_orchestrator import ChallengeResources
from platform_network.schemas.challenge import RegistryChallenge
from platform_network.schemas.weights import ChallengeWeightsResult, FinalWeights

logger = logging.getLogger(__name__)


class MasterWeightService:
    def __init__(
        self,
        *,
        metagraph_cache: MetagraphCache,
        weight_setter: WeightSetter,
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

    async def run_epoch(
        self, challenges: list[RegistryChallenge], tokens: dict[str, str]
    ) -> FinalWeights:
        hotkey_to_uid = self.metagraph_cache.get()
        results = await self.collect_weights(challenges, tokens)
        final = aggregate_challenge_weights(results, hotkey_to_uid)
        self.weight_setter.set_weights(final.uids, final.weights)
        logger.info(
            "set weights",
            extra={"uids": len(final.uids), "challenges": len(challenges)},
        )
        return final
