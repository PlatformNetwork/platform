"""Supervisor image-updater — Swarm port of the master image-updater CronJobs.

The Kubernetes Helm chart runs one-minute CronJobs (``platform validator
refresh-image``) that resolve the public GHCR tag digest and patch the
first-party master Deployments (admin/proxy/broker/...) to
``tag@sha256:<digest>`` only when the digest changes. This module is the
docker-backend analogue: a :class:`ScheduledTask` that REUSES the exact same
digest-resolution core (:func:`resolve_remote_digest` /
:func:`parse_image_reference` / :func:`extract_digest` from
``platform_network.validator.image_updater`` — already registry-only, zero
Kubernetes coupling; the k8s callers keep using it unchanged) and rolls the
first-party Swarm services via ``docker service update --image
tag@sha256:<digest>`` through the existing :class:`SwarmCommandRunner` seam.

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

Swarm service naming: the master-side first-party service names are not yet
pinned by deployment (Task 24/27 territory). The defaults below
(``platform-admin``/``platform-proxy``/``platform-broker``/
``platform-config-sync``, all tracking the master image) are the chosen
convention; a service that does not exist on the daemon is a logged skip,
so partial deployments are safe.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from platform_network.config.settings import Settings
from platform_network.master.swarm_backend import SwarmCliRunner, SwarmCommandRunner
from platform_network.supervisor.health import BrokerHealthGate
from platform_network.supervisor.scheduler import ScheduledTask
from platform_network.validator.image_updater import (
    ImageReference,
    extract_digest,
    parse_image_reference,
    resolve_remote_digest,
)

logger = logging.getLogger(__name__)

# Parity with the Helm chart's one-minute image-updater CronJob schedule.
IMAGE_UPDATER_INTERVAL_SECONDS = 60.0
DEFAULT_COMMAND_TIMEOUT_SECONDS = 60.0
DEFAULT_MASTER_IMAGE = "ghcr.io/platformnetwork/platform-master:latest"

_PINNED_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

DigestResolver = Callable[[ImageReference], str]


@dataclass(frozen=True)
class ImageUpdateTarget:
    """One Swarm service tracking a mutable (tagged, un-pinned) image."""

    service: str
    image: str


DEFAULT_FIRST_PARTY_TARGETS: tuple[ImageUpdateTarget, ...] = (
    ImageUpdateTarget(service="platform-admin", image=DEFAULT_MASTER_IMAGE),
    ImageUpdateTarget(service="platform-proxy", image=DEFAULT_MASTER_IMAGE),
    ImageUpdateTarget(service="platform-broker", image=DEFAULT_MASTER_IMAGE),
    ImageUpdateTarget(service="platform-config-sync", image=DEFAULT_MASTER_IMAGE),
)


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
