from __future__ import annotations

import asyncio
import logging
from typing import Any

from platform_network.master.docker_orchestrator import (
    ChallengeResources,
    ChallengeSpec,
)
from platform_network.schemas.challenge import ChallengeStatus
from platform_network.validator.registry_client import RegistryClient

logger = logging.getLogger(__name__)


class NormalValidatorRunner:
    def __init__(
        self,
        *,
        registry_client: RegistryClient,
        orchestrator: Any,
        retry_seconds: int = 15,
    ) -> None:
        self.registry_client = registry_client
        self.orchestrator = orchestrator
        self.retry_seconds = retry_seconds

    async def run_once(self) -> None:
        registry = await self.registry_client.fetch_registry()
        for challenge in registry.challenges:
            if challenge.status != ChallengeStatus.ACTIVE:
                continue
            spec = ChallengeSpec(
                slug=challenge.slug,
                image=challenge.image,
                version=challenge.version,
                env=challenge.env,
                resources=ChallengeResources.from_mapping(challenge.resources),
                required_capabilities=tuple(challenge.required_capabilities),
            )
            self.orchestrator.start_challenge(spec)

    async def run_forever(self) -> None:
        while True:
            try:
                await self.run_once()
            except Exception:
                logger.exception("registry sync failed; retrying")
            await asyncio.sleep(self.retry_seconds)
