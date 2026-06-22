"""Scheduled-task registry — the SINGLE registration seam for Tasks 17-22.

Recipe for adding a new periodic job (reaper, image-updater,
challenge-image-updater, config-sync, weights, self-update):

1. Create ``src/platform_network/supervisor/<job>.py`` exporting a builder::

       def build_<job>_task(settings: Settings) -> ScheduledTask: ...

   The builder closes over whatever clients/ledgers the job needs; the
   callable it returns must be synchronous, must tolerate being called from
   a non-main daemon thread, and may consult the shared
   :class:`~platform_network.supervisor.health.BrokerHealthGate` (passed into
   the builder) to skip broker-dependent work while the gate is unhealthy.

2. Append EXACTLY ONE registration line to :func:`build_scheduled_tasks`
   below at the marked slot. Do NOT edit ``loop.py`` or ``scheduler.py``.

The supervisor always schedules the broker ``/health`` probe itself; it is
built here so the gate instance can be shared with future job builders.
"""

from __future__ import annotations

from platform_network.config.settings import Settings
from platform_network.supervisor.challenge_image_updater import (
    build_challenge_image_updater_task,
)
from platform_network.supervisor.config_sync import build_config_sync_task
from platform_network.supervisor.health import (
    DEFAULT_FAILURE_THRESHOLD,
    DEFAULT_PROBE_TIMEOUT_SECONDS,
    BrokerHealthGate,
    http_health_prober,
)
from platform_network.supervisor.image_updater import (
    DEFAULT_MASTER_IMAGE,
    ImageUpdateTarget,
    build_image_updater_task,
)
from platform_network.supervisor.reaper import build_reaper_task
from platform_network.supervisor.scheduler import ScheduledTask
from platform_network.supervisor.self_update import (
    build_self_update_task,
    run_startup_rollback_check,
)

BROKER_HEALTH_PROBE_INTERVAL_SECONDS = 10.0


def build_broker_health_task(
    settings: Settings,
    *,
    gate: BrokerHealthGate | None = None,
) -> tuple[ScheduledTask, BrokerHealthGate]:
    """Build the broker ``/health`` probe task plus its shared gate."""
    if gate is None:
        gate = BrokerHealthGate(
            http_health_prober(
                f"{settings.docker.broker_url.rstrip('/')}/health",
                DEFAULT_PROBE_TIMEOUT_SECONDS,
            ),
            failure_threshold=DEFAULT_FAILURE_THRESHOLD,
        )
    task = ScheduledTask(
        name="broker-health-probe",
        interval_seconds=BROKER_HEALTH_PROBE_INTERVAL_SECONDS,
        run=gate.probe_once,
    )
    return task, gate


def build_scheduled_tasks(
    settings: Settings,
    *,
    health_gate: BrokerHealthGate | None = None,
) -> tuple[tuple[ScheduledTask, ...], BrokerHealthGate]:
    """Assemble every scheduled task for the supervisor.

    Returns the task tuple plus the shared broker health gate so job
    builders (and tests) can observe/share it.
    """
    health_task, gate = build_broker_health_task(settings, gate=health_gate)
    tasks: list[ScheduledTask] = [health_task]

    # ------------------------------------------------------------------
    # Task 17 registration point (reaper):
    # The reaper builder owns WorkloadLedger.reconstruct on first tick and
    # ledger access thereafter (see Task 7/14 notepad contracts).
    tasks.append(build_reaper_task(settings, health_gate=gate))
    # ------------------------------------------------------------------
    # Task 18 registration point (image-updater):
    # Task 28 #1: call-site override targets the broker by its CANONICAL name
    # `platform-docker-broker` (the settings.docker.broker_url host) and drops
    # the non-service `platform-config-sync`. The single-port consolidation also
    # dropped the separate `platform-admin` service (proxy serves admin/registry).
    # DEFAULT_FIRST_PARTY_TARGETS stays as-is for the regression tests; do not
    # "simplify" back to the default.
    tasks.append(
        build_image_updater_task(
            settings,
            health_gate=gate,
            targets=(
                ImageUpdateTarget(service="platform-proxy", image=DEFAULT_MASTER_IMAGE),
                ImageUpdateTarget(
                    service="platform-docker-broker", image=DEFAULT_MASTER_IMAGE
                ),
            ),
        )
    )
    # Task 19 registration point (challenge-image-updater).
    tasks.append(build_challenge_image_updater_task(settings, health_gate=gate))
    # Task 20 registration point (config-sync).
    # Task 28 #1: same canonical-broker call-site override; single-port
    # consolidation drops the removed `platform-admin` rollout target.
    # DEFAULT_ROLLOUT_SERVICES stays as-is.
    tasks.append(
        build_config_sync_task(
            settings,
            health_gate=gate,
            rollout_services=(
                "platform-proxy",
                "platform-docker-broker",
            ),
        )
    )
    # Task 21 weights: DISABLED for docker cutover — orphaned (output discarded;
    # admin serves /v1/weights/latest on-demand). Re-enable only for on-chain submit.
    # tasks.append(build_weights_task(settings, health_gate=gate))
    # Task 22 registration point (self-update).
    # Startup-side rollback agent (Task 22): MUST run once before workers
    # start — it flips `current` back + exits when a pending update is
    # restart-storming (post-swap health gate). No-op outside a staged
    # release / without a pending update.
    run_startup_rollback_check()
    tasks.append(build_self_update_task(settings, health_gate=gate))
    # ------------------------------------------------------------------

    return tuple(tasks), gate
