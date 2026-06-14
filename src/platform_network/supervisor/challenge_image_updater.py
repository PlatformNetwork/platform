"""Supervisor challenge-image-updater — docker-fallback port of the CronJob.

The Kubernetes Helm chart runs a one-minute CronJob (``platform master
refresh-challenge-images``) that, per registered challenge, resolves the
public GHCR tag digest and (a) updates the challenge DB record to
``tag@sha256:<digest>`` when the digest changed and (b) rolls the running
workload to the new image. That CLI command already carries a docker
fallback branch: when ``settings.runtime.backend != "kubernetes"`` no
Kubernetes client is ever built and the per-challenge roll is
``await controller.restart(slug)`` through the existing
:class:`~platform_network.cli_app.main.DockerRuntimeController`.

This module is that docker branch, verbatim, as a supervisor
:class:`ScheduledTask`. The supervisor only ever runs in docker mode, so
NO Kubernetes client is constructed here — ever. Per challenge record the
tick reuses:

- the CLI's ``mutable_base`` policy verbatim: only ``ghcr.io`` images are
  auto-tracked and ``sha-*`` tags are skipped (immutable CI pins);
- the registry-only digest core from
  ``platform_network.validator.image_updater``
  (:func:`parse_image_reference` / :func:`resolve_remote_digest`);
- the same DB write (``registry.update(slug, ChallengeUpdate(image=...))``)
  and the same restart primitive
  (``DockerRuntimeController(registry, orchestrator).restart(slug)``).

Semantics preserved from the CLI command: DRAFT/DISABLED challenges are
skipped entirely; INACTIVE challenges get their DB record refreshed but are
never restarted; ACTIVE challenges are restarted only when the digest
actually changed. Idempotency is restart-safe for free — the comparison is
``desired != record.image`` against the DB record, never in-process state.

Pin policy (Task 18 parity): an update is only ever written with a full
``tag@sha256:<64-hex>`` reference; a resolver that fails or returns
anything else yields a logged per-challenge skip, and sibling challenges
are still processed. The tick itself never raises.

Health-gate note (decided, Task 18 precedent): this job talks to the
challenge DB registry and the public GHCR registry — it has NO broker HTTP
dependency — so the shared :class:`BrokerHealthGate` is accepted for
recipe parity but deliberately not consulted (``del``'d in the builder).

Interval: 60s, parity with the Helm chart's ``imageAutoUpdate.schedule``
of ``*/1 * * * *`` which drives the challenge-image-updater CronJob.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable
from typing import Any

from platform_network.config.settings import Settings
from platform_network.supervisor.health import BrokerHealthGate
from platform_network.supervisor.scheduler import ScheduledTask
from platform_network.validator.image_updater import (
    ImageReference,
    parse_image_reference,
    resolve_remote_digest,
)

logger = logging.getLogger(__name__)

# Parity with the Helm chart's one-minute imageAutoUpdate CronJob schedule.
CHALLENGE_IMAGE_UPDATER_INTERVAL_SECONDS = 60.0
# Parity with the CronJob's `--tag` default
# (values.yaml imageAutoUpdate.challenges.tag).
DEFAULT_MUTABLE_TAG = "latest"

_PINNED_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

DigestResolver = Callable[[ImageReference], str]
RegistryFactory = Callable[[], Any]
ControllerFactory = Callable[[Any], Any]


class ChallengeImageUpdater:
    """Digest-compare → DB update → restart loop body (docker fallback)."""

    def __init__(
        self,
        *,
        registry_factory: RegistryFactory,
        controller_factory: ControllerFactory,
        resolver: DigestResolver,
        tag: str = DEFAULT_MUTABLE_TAG,
    ) -> None:
        self._registry_factory = registry_factory
        self._controller_factory = controller_factory
        self._resolver = resolver
        self._tag = tag

    def run_once(self) -> None:
        """One synchronous tick; never raises (scheduler-thread friendly)."""
        try:
            asyncio.run(self._refresh())
        except Exception:
            logger.exception(
                "challenge-image-updater: tick failed; will retry next interval"
            )

    def _mutable_base(self, image: str) -> str | None:
        """The CLI command's ``mutable_base`` policy, verbatim.

        Only ``ghcr.io`` images participate in auto-update, and ``sha-*``
        tags (immutable CI pins) are never tracked.
        """
        parsed = parse_image_reference(image)
        if parsed.registry != "ghcr.io":
            return None
        if parsed.tag.startswith("sha-"):
            return None
        return f"{parsed.registry}/{parsed.repository}:{self._tag}"

    async def _refresh(self) -> None:
        registry = self._registry_factory()
        controller = self._controller_factory(registry)
        for record in await registry.list():
            try:
                await self._refresh_record(registry, controller, record)
            except Exception:
                logger.exception(
                    "challenge-image-updater: refresh failed for challenge %r; "
                    "continuing with remaining challenges",
                    record.slug,
                )

    async def _refresh_record(
        self, registry: Any, controller: Any, record: Any
    ) -> None:
        from platform_network.schemas.challenge import ChallengeStatus, ChallengeUpdate

        if record.status in {ChallengeStatus.DRAFT, ChallengeStatus.DISABLED}:
            return
        base = self._mutable_base(record.image)
        if base is None:
            logger.debug(
                "challenge-image-updater: %s: skipped %s (not auto-tracked)",
                record.slug,
                record.image,
            )
            return
        try:
            digest = self._resolver(parse_image_reference(base))
        except Exception:
            logger.warning(
                "challenge-image-updater: digest resolution failed for %s "
                "(challenge %r); skipping this tick",
                base,
                record.slug,
                exc_info=True,
            )
            return
        if not digest or not _PINNED_DIGEST_RE.match(digest):
            logger.error(
                "challenge-image-updater: resolver returned non-sha256 digest %r "
                "for %s; refusing un-pinned update (production pin policy)",
                digest,
                base,
            )
            return
        desired = f"{base}@{digest}"
        changed = desired != record.image
        if changed:
            await registry.update(record.slug, ChallengeUpdate(image=desired))
            logger.info("challenge-image-updater: %s: updated %s", record.slug, desired)
        else:
            logger.debug(
                "challenge-image-updater: %s: already-current %s",
                record.slug,
                desired,
            )
        if record.status == ChallengeStatus.ACTIVE and changed:
            result = await controller.restart(record.slug)
            logger.info(
                "challenge-image-updater: %s: restarted %s",
                record.slug,
                result.get("status") if isinstance(result, dict) else result,
            )


def build_challenge_image_updater_task(
    settings: Settings,
    *,
    health_gate: BrokerHealthGate | None = None,
    registry_factory: RegistryFactory | None = None,
    controller_factory: ControllerFactory | None = None,
    resolver: DigestResolver | None = None,
    tag: str = DEFAULT_MUTABLE_TAG,
    interval_seconds: float = CHALLENGE_IMAGE_UPDATER_INTERVAL_SECONDS,
) -> ScheduledTask:
    """Build the challenge-image-updater :class:`ScheduledTask`.

    ``health_gate`` follows the Task-16 builder recipe but is deliberately
    not consulted (Task 18 precedent): the job depends on the challenge DB
    registry and the public GHCR registry — it never talks to the Docker
    broker over HTTP — so broker health is not a meaningful gate here.

    ``registry_factory``/``controller_factory``/``resolver`` are test
    seams. The defaults construct, per tick, exactly what the CLI command
    constructs per invocation: ``_master_registry(settings)`` and
    ``DockerRuntimeController(registry, _challenge_orchestrator(settings))``
    (imported lazily inside the factories so importing the supervisor
    package stays light — Task 21 precedent). The default ``resolver`` is
    the REUSED :func:`resolve_remote_digest`.
    """
    del health_gate  # recipe parity; not broker-dependent (see docstring).

    def default_registry_factory() -> Any:
        from platform_network.cli_app.main import _master_registry

        return _master_registry(settings)

    def default_controller_factory(registry: Any) -> Any:
        from platform_network.cli_app.main import (
            DockerRuntimeController,
            _challenge_orchestrator,
        )

        return DockerRuntimeController(registry, _challenge_orchestrator(settings))

    updater = ChallengeImageUpdater(
        registry_factory=(
            registry_factory
            if registry_factory is not None
            else default_registry_factory
        ),
        controller_factory=(
            controller_factory
            if controller_factory is not None
            else default_controller_factory
        ),
        resolver=resolver if resolver is not None else resolve_remote_digest,
        tag=tag,
    )
    return ScheduledTask(
        name="challenge-image-updater",
        interval_seconds=interval_seconds,
        run=updater.run_once,
    )
