from __future__ import annotations

import asyncio
import logging
from typing import Any

from base.bittensor.weight_setter import (
    WeightSetter,
    is_rejected_set_weights_result,
)
from base.master.docker_orchestrator import (
    challenge_spec_from_registry,
)
from base.schemas.challenge import ChallengeStatus
from base.schemas.weights import MasterWeightsResponse
from base.validator.registry_client import RegistryClient
from base.validator.weights_client import (
    WeightsClient,
    validate_master_weights_payload,
)

logger = logging.getLogger(__name__)


class NormalValidatorRunner:
    def __init__(
        self,
        *,
        registry_client: RegistryClient,
        orchestrator: Any,
        retry_seconds: int = 15,
        weights_client: WeightsClient | None = None,
        weight_setter: WeightSetter | None = None,
        netuid: int | None = None,
        weights_freshness_seconds: int = 720,
    ) -> None:
        self.registry_client = registry_client
        self.orchestrator = orchestrator
        self.retry_seconds = retry_seconds
        self.weights_client = weights_client
        self.weight_setter = weight_setter
        self.netuid = netuid
        self.weights_freshness_seconds = weights_freshness_seconds

    async def run_once(self) -> None:
        registry = await self.registry_client.fetch_registry()
        for challenge in registry.challenges:
            if challenge.status != ChallengeStatus.ACTIVE:
                continue
            self.orchestrator.start_challenge(challenge_spec_from_registry(challenge))

    async def submit_latest_weights(self) -> bool:
        if (
            self.weights_client is None
            or self.weight_setter is None
            or self.netuid is None
        ):
            logger.warning("validator weights submission is not configured")
            return False
        try:
            payload = await self.weights_client.fetch_latest()
        except Exception:
            logger.exception("validator weights fetch failed")
            return False

        failure = self._validate_weights_payload(payload)
        if failure is not None:
            logger.warning("validator weights submission skipped: %s", failure)
            return False

        try:
            result = self.weight_setter.set_weights(payload.uids, payload.weights)
        except Exception:
            logger.exception("validator weights submission failed")
            return False
        if is_rejected_set_weights_result(result):
            logger.warning("validator weights submission rejected")
            return False
        return True

    def _validate_weights_payload(self, payload: MasterWeightsResponse) -> str | None:
        return validate_master_weights_payload(
            payload,
            netuid=self.netuid,
            weights_freshness_seconds=self.weights_freshness_seconds,
        )

    async def run_forever(self) -> None:
        while True:
            try:
                await self.run_once()
            except Exception:
                logger.exception("registry sync failed; retrying")
            await asyncio.sleep(self.retry_seconds)
