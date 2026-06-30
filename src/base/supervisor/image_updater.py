"""Supervisor image-updater — master Swarm service digest pinning.

A :class:`ScheduledTask` that resolves the public GHCR tag digest and pins
the first-party master Swarm services (proxy/broker/...) to
``tag@sha256:<digest>`` only when the digest changes. It reuses the
registry-only digest-resolution core (:func:`resolve_remote_digest` /
:func:`parse_image_reference` / :func:`extract_digest` from
:mod:`base.supervisor.image_ref`) and rolls the first-party
Swarm services via ``docker service update --image tag@sha256:<digest>``
through the existing :class:`SwarmCommandRunner` seam.

Idempotency is RESTART-SAFE by design: instead of remembering the
last-applied digest in process memory, each tick inspects the service's
currently-pinned image (``docker service inspect --format
'{{.Spec.TaskTemplate.ContainerSpec.Image}}'``) and compares digests — a
supervisor restart can therefore never re-issue an update for an
already-current service.

Production pin policy (README "Deployment Policy") is enforced on the way
out: targets without an explicit tag are rejected, and an update is only
ever emitted with a full ``tag@sha256:<64-hex>`` reference — a resolver
that fails or returns anything but a sha256 digest yields a logged no-op,
never an un-pinned ``service update``.

Health-gate note: this job talks to dockerd and the public GHCR registry,
NOT the broker, so the shared :class:`BrokerHealthGate` is accepted for
recipe parity but deliberately not consulted.

Swarm service naming: the defaults below name the installer-created
master-side services (``base-master-proxy`` + ``base-docker-broker``, both
tracking the master image, per deploy/swarm/install-swarm.sh); production
overrides these via ``build_scheduled_tasks`` (same names), so they are a
test/fallback default that nevertheless points only at services the
installer actually creates. A service that does not exist on the daemon is
a logged skip, so partial deployments are safe.
The single-port consolidation removed the separate ``base-admin``
service (the admin/registry surface is served by the proxy), so it is no
longer a rollout target; ``base-config-sync`` is likewise not a Swarm
service (under the supervisor it is a periodic task), so it is not a target.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from base.config.settings import Settings
from base.master.swarm_backend import SwarmCliRunner, SwarmCommandRunner
from base.supervisor.health import BrokerHealthGate
from base.supervisor.image_ref import (
    ImageReference,
    extract_digest,
    parse_image_reference,
    resolve_remote_digest,
)
from base.supervisor.scheduler import ScheduledTask

logger = logging.getLogger(__name__)

# One-minute image-updater cadence.
IMAGE_UPDATER_INTERVAL_SECONDS = 60.0
DEFAULT_COMMAND_TIMEOUT_SECONDS = 60.0
DEFAULT_MASTER_IMAGE = "ghcr.io/baseintelligence/base-master:latest"

_PINNED_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

DigestResolver = Callable[[ImageReference], str]


@dataclass(frozen=True)
class ImageUpdateTarget:
    """One Swarm service tracking a mutable (tagged, un-pinned) image."""

    service: str
    image: str


DEFAULT_FIRST_PARTY_TARGETS: tuple[ImageUpdateTarget, ...] = (
    ImageUpdateTarget(service="base-master-proxy", image=DEFAULT_MASTER_IMAGE),
    ImageUpdateTarget(service="base-docker-broker", image=DEFAULT_MASTER_IMAGE),
)


def resolve_image_update_targets(settings: Settings) -> tuple[ImageUpdateTarget, ...]:
    """Resolve the effective image-updater targets from supervisor settings.

    Settings-driven (G-A5): ``supervisor.image_updater_targets`` overrides the
    target list when set; when unset (``None``) the built-in
    :data:`DEFAULT_FIRST_PARTY_TARGETS` (the two master services) are used, so a
    deploy that never configures targets keeps its prior behaviour (back-compat).

    When ``supervisor.validator_agent_target_enabled`` is True a validator-agent
    target tracking the mutable validator runtime image is appended (skipped if
    the same service name is already present), so a validator NODE running the
    agent as a swarm service auto-rolls on a new digest.
    """
    sup = settings.supervisor
    if sup.image_updater_targets is not None:
        targets = tuple(
            ImageUpdateTarget(service=t.service, image=t.image)
            for t in sup.image_updater_targets
        )
    else:
        targets = DEFAULT_FIRST_PARTY_TARGETS
    if sup.validator_agent_target_enabled and not any(
        t.service == sup.validator_agent_service for t in targets
    ):
        targets = (
            *targets,
            ImageUpdateTarget(
                service=sup.validator_agent_service,
                image=sup.validator_agent_image,
            ),
        )
    return targets


def _has_explicit_tag(image: str) -> bool:
    """True when the raw image string carries an explicit tag.

    :func:`parse_image_reference` silently defaults a missing tag to
    ``latest``; production policy rejects untagged images, so the check
    must look at the raw string before parsing.
    """
    name, _, _ = image.partition("@")
    return ":" in name.rsplit("/", 1)[-1]


class SwarmImageUpdater:
    """Digest-compare-and-update loop body for first-party Swarm services."""

    def __init__(
        self,
        targets: Sequence[ImageUpdateTarget],
        *,
        runner: SwarmCommandRunner,
        resolver: DigestResolver,
        docker_bin: str = "docker",
        command_timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    ) -> None:
        self._targets = tuple(targets)
        self._runner = runner
        self._resolver = resolver
        self._docker_bin = docker_bin
        self._command_timeout_seconds = command_timeout_seconds

    def run_once(self) -> None:
        """One tick: refresh every target; per-target failures are isolated."""
        for target in self._targets:
            try:
                self._refresh_target(target)
            except Exception:
                logger.exception(
                    "image-updater: refresh failed for service %r (image %r); "
                    "continuing with remaining targets",
                    target.service,
                    target.image,
                )

    def _refresh_target(self, target: ImageUpdateTarget) -> bool:
        if not _has_explicit_tag(target.image):
            logger.error(
                "image-updater: rejecting untagged image %r for service %r "
                "(production pin policy requires an explicit tag)",
                target.image,
                target.service,
            )
            return False
        reference = parse_image_reference(target.image)
        try:
            digest = self._resolver(reference)
        except Exception:
            logger.warning(
                "image-updater: digest resolution failed for %s (service %r); "
                "skipping this tick",
                reference.tagged,
                target.service,
                exc_info=True,
            )
            return False
        if not digest or not _PINNED_DIGEST_RE.match(digest):
            logger.error(
                "image-updater: resolver returned non-sha256 digest %r for %s; "
                "refusing un-pinned update (production pin policy)",
                digest,
                reference.tagged,
            )
            return False
        current_image = self._current_service_image(target.service)
        if current_image is None:
            return False
        if extract_digest(current_image) == digest:
            logger.debug(
                "image-updater: service %r already at %s; no-op",
                target.service,
                digest,
            )
            return False
        pinned = reference.pinned(digest)
        result = self._runner.run(
            [
                self._docker_bin,
                "service",
                "update",
                "--detach",
                "--image",
                pinned,
                target.service,
            ],
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            logger.error(
                "image-updater: docker service update failed for %r (rc=%d): %s",
                target.service,
                result.returncode,
                result.stderr.strip(),
            )
            return False
        logger.info("image-updater: updated service %r to %s", target.service, pinned)
        return True

    def _current_service_image(self, service: str) -> str | None:
        result = self._runner.run(
            [
                self._docker_bin,
                "service",
                "inspect",
                "--format",
                "{{.Spec.TaskTemplate.ContainerSpec.Image}}",
                service,
            ],
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            logger.warning(
                "image-updater: cannot inspect service %r (rc=%d): %s; skipping",
                service,
                result.returncode,
                result.stderr.strip(),
            )
            return None
        return result.stdout.strip()


def build_image_updater_task(
    settings: Settings,
    *,
    health_gate: BrokerHealthGate | None = None,
    targets: Sequence[ImageUpdateTarget] | None = None,
    resolver: DigestResolver | None = None,
    runner: SwarmCommandRunner | None = None,
    docker_bin: str = "docker",
    interval_seconds: float = IMAGE_UPDATER_INTERVAL_SECONDS,
) -> ScheduledTask:
    """Build the first-party image-updater :class:`ScheduledTask`.

    ``settings`` and ``health_gate`` follow the Task-16 builder recipe;
    neither is consulted today (the job depends on dockerd + GHCR, not the
    broker — see module docstring). ``resolver`` defaults to the REUSED
    :func:`resolve_remote_digest`; ``runner`` defaults to the existing
    :class:`SwarmCliRunner` subprocess seam.
    """
    del settings, health_gate  # recipe parity; not broker-dependent.
    updater = SwarmImageUpdater(
        targets if targets is not None else DEFAULT_FIRST_PARTY_TARGETS,
        runner=runner if runner is not None else SwarmCliRunner(),
        resolver=resolver if resolver is not None else resolve_remote_digest,
        docker_bin=docker_bin,
    )
    return ScheduledTask(
        name="image-updater",
        interval_seconds=interval_seconds,
        run=updater.run_once,
    )
