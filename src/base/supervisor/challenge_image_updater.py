"""Supervisor challenge-image-updater — per-challenge GHCR digest roll.

A supervisor :class:`ScheduledTask` that, per registered challenge, resolves
the public GHCR tag digest and (a) updates the challenge DB record to
``tag@sha256:<digest>`` when the digest changed and (b) rolls the running
Swarm workload to the new image via the existing
:class:`~base.cli_app.main.DockerRuntimeController`.

Per challenge record the tick reuses:

- the CLI's ``mutable_base`` policy verbatim: only ``ghcr.io`` images are
  auto-tracked and ``sha-*`` tags are skipped (immutable CI pins);
- the registry-only digest core from
  :mod:`base.supervisor.image_ref`
  (:func:`parse_image_reference` / :func:`resolve_remote_digest`);
- the same DB write (``registry.update(slug, ChallengeUpdate(image=...))``)
  and the same restart primitive
  (``DockerRuntimeController(registry, orchestrator).restart(slug)``).

Semantics preserved from the CLI command: DRAFT/DISABLED challenges are
skipped entirely; INACTIVE challenges get their DB record refreshed but are
never restarted.

The record update and the service roll are DECOUPLED. The DB record is
refreshed whenever the resolved digest differs from the record (unchanged),
but the ACTIVE challenge's service is rolled based on the SERVICE's
actually-running digest vs the desired digest — independently of whether the
record changed this tick. This fixes a live-observed desync: if a prior tick
advanced the record but its restart did not take effect (e.g. the docker
socket was not yet mounted), the record equals the resolved digest forever, so
a record-change-gated restart would never fire and the service would stay
behind. Convergence is idempotent — the roll is gated on the running service
image via ``controller.running_image`` (backed by
``SwarmChallengeOrchestrator.service_image``), so no ``--force`` redeploy
happens once the service already runs the desired digest. Each tick emits an
INFO-level per-challenge summary (slug, desired digest, action taken) so the
loop is observable in the proxy logs.

Pin policy (Task 18 parity): an update is only ever written with a full
``tag@sha256:<64-hex>`` reference; a resolver that fails or returns
anything else yields a logged per-challenge skip, and sibling challenges
are still processed. The tick itself never raises.

Health-gate note (decided, Task 18 precedent): this job talks to the
challenge DB registry and the public GHCR registry — it has NO broker HTTP
dependency — so the shared :class:`BrokerHealthGate` is accepted for
recipe parity but deliberately not consulted (``del``'d in the builder).

Interval: 60s — the one-minute challenge-image-updater cadence.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import TYPE_CHECKING, Any

from base.config.settings import Settings
from base.supervisor.health import BrokerHealthGate
from base.supervisor.image_ref import (
    ImageReference,
    extract_digest,
    parse_image_reference,
    resolve_remote_digest,
)
from base.supervisor.scheduler import ScheduledTask

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = logging.getLogger(__name__)

# One-minute challenge-image-updater cadence.
CHALLENGE_IMAGE_UPDATER_INTERVAL_SECONDS = 60.0
# Default tracking tag for challenge images.
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
        from base.schemas.challenge import ChallengeStatus, ChallengeUpdate

        if record.status in {ChallengeStatus.DRAFT, ChallengeStatus.DISABLED}:
            return
        base = self._mutable_base(record.image)
        if base is None:
            logger.info(
                "challenge-image-updater: %s: desired=<untracked> "
                "action=skipped-not-tracked (%s)",
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
        # (a) Keep the registry record current — DECOUPLED from the service roll
        # so a record already at the resolved digest does NOT suppress a roll of
        # a service still running an older digest.
        if desired != record.image:
            await registry.update(record.slug, ChallengeUpdate(image=desired))
            logger.info(
                "challenge-image-updater: %s: record updated to %s",
                record.slug,
                desired,
            )
        # (b) Converge the running service, gated on the SERVICE's actually-running
        # image (not the record) so a lagging service catches up even when the
        # record already equals the resolved digest.
        action = await self._converge_service(controller, record, desired, digest)
        logger.info(
            "challenge-image-updater: %s: desired=%s action=%s",
            record.slug,
            desired,
            action,
        )

    async def _converge_service(
        self, controller: Any, record: Any, desired: str, digest: str
    ) -> str:
        """Roll the ACTIVE challenge's service to ``desired`` iff it is behind.

        Returns the per-tick action for the observability summary: ``rolled``,
        ``already-current`` or ``skipped-inactive``.

        The roll decision is made against the service's ACTUALLY-running image
        digest via ``controller.running_image`` — idempotent, so no
        ``--force`` redeploy fires once the service already runs ``desired``. A
        controller without that introspection seam degrades to the legacy
        record-change gate (behaviour-preserving for such controllers).
        """
        from base.schemas.challenge import ChallengeStatus

        if record.status != ChallengeStatus.ACTIVE:
            return "skipped-inactive"
        accessor = getattr(controller, "running_image", None)
        if callable(accessor):
            running = await accessor(record.slug)
            if running is not None and extract_digest(running) == digest:
                return "already-current"
        elif desired == record.image:
            return "already-current"
        result = await controller.restart(record.slug)
        logger.info(
            "challenge-image-updater: %s: rolled service to %s (%s)",
            record.slug,
            desired,
            result.get("status") if isinstance(result, dict) else result,
        )
        return "rolled"


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
    updater = _build_challenge_image_updater(
        settings,
        registry_factory=registry_factory,
        controller_factory=controller_factory,
        resolver=resolver,
        tag=tag,
    )
    return ScheduledTask(
        name="challenge-image-updater",
        interval_seconds=interval_seconds,
        run=updater.run_once,
    )


def _build_challenge_image_updater(
    settings: Settings,
    *,
    registry_factory: RegistryFactory | None = None,
    controller_factory: ControllerFactory | None = None,
    resolver: DigestResolver | None = None,
    tag: str = DEFAULT_MUTABLE_TAG,
) -> ChallengeImageUpdater:
    """Build a :class:`ChallengeImageUpdater` with the production defaults.

    ``registry_factory``/``controller_factory``/``resolver`` are test seams; the
    defaults construct, per tick, exactly what the CLI command constructs per
    invocation: ``_master_registry(settings)`` and
    ``DockerRuntimeController(registry, _challenge_orchestrator(settings))``
    (imported lazily so importing the supervisor package stays light — Task 21
    precedent). The default ``resolver`` is the REUSED
    :func:`resolve_remote_digest`.
    """

    def default_registry_factory() -> Any:
        from base.cli_app.main import _master_registry

        return _master_registry(settings)

    def default_controller_factory(registry: Any) -> Any:
        from base.cli_app.main import (
            DockerRuntimeController,
            _challenge_orchestrator,
        )

        return DockerRuntimeController(registry, _challenge_orchestrator(settings))

    return ChallengeImageUpdater(
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


async def run_challenge_image_update_loop(
    updater: ChallengeImageUpdater,
    *,
    interval_seconds: float,
    shutdown_event: asyncio.Event,
) -> None:
    """Await :meth:`ChallengeImageUpdater._refresh` on ``interval_seconds`` until
    shutdown.

    A failing tick is logged and the loop continues, so one transient error
    (e.g. a challenge DB blip or a registry timeout) never stops the autonomous
    challenge-image auto-roll. Cancellation (lifespan shutdown) propagates the
    :class:`asyncio.CancelledError` cleanly out of the loop.
    """

    while not shutdown_event.is_set():
        try:
            await updater._refresh()
        except Exception:
            logger.exception(
                "challenge-image-update: tick failed; will retry next interval"
            )
        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=interval_seconds)
        except TimeoutError:
            continue


def build_challenge_image_update_lifespan(
    settings: Settings | None,
    interval_seconds: float | None,
    *,
    registry_factory: RegistryFactory | None = None,
    controller_factory: ControllerFactory | None = None,
    resolver: DigestResolver | None = None,
    tag: str = DEFAULT_MUTABLE_TAG,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]] | None:
    """Build a FastAPI lifespan that runs the challenge-image-update loop.

    Mirrors ``build_master_registry_reconcile_lifespan``: it starts the loop as a
    background task on app startup and cancels + awaits it before shutdown.
    Returns ``None`` (no lifespan) when ``settings`` is not configured or the
    interval is non-positive (opt-out seam; parity with the reconcile-interval
    gate — default-on for the master proxy).

    The updater is built from ``settings`` with the same default
    registry/controller/resolver factories as ``build_challenge_image_updater_task``;
    the factory arguments are test seams.
    """

    if settings is None or interval_seconds is None or interval_seconds <= 0:
        return None

    updater = _build_challenge_image_updater(
        settings,
        registry_factory=registry_factory,
        controller_factory=controller_factory,
        resolver=resolver,
        tag=tag,
    )
    loop_interval = interval_seconds

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        shutdown = asyncio.Event()
        task = asyncio.create_task(
            run_challenge_image_update_loop(
                updater,
                interval_seconds=loop_interval,
                shutdown_event=shutdown,
            )
        )
        try:
            yield
        finally:
            shutdown.set()
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    return lifespan
