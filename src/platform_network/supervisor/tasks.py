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
from platform_network.supervisor.image_updater import build_image_updater_task
from platform_network.supervisor.reaper import build_reaper_task
from platform_network.supervisor.scheduler import ScheduledTask
from platform_network.supervisor.self_update import (
    build_self_update_task,
    run_startup_rollback_check,
)
from platform_network.supervisor.weights import build_weights_task

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
    tasks.append(build_image_updater_task(settings, health_gate=gate))
    # Task 19 registration point (challenge-image-updater).
    tasks.append(build_challenge_image_updater_task(settings, health_gate=gate))
    # Task 20 registration point (config-sync).
    tasks.append(build_config_sync_task(settings, health_gate=gate))
    # Task 21 registration point (weights, `master weights --once` port).
    tasks.append(build_weights_task(settings, health_gate=gate))
    # Task 22 registration point (self-update, helm-upgrader replacement).
    # Startup-side rollback agent (Task 22): MUST run once before workers
    # start — it flips `current` back + exits when a pending update is
    # restart-storming (post-swap health gate). No-op outside a staged
    # release / without a pending update.
    run_startup_rollback_check()
    tasks.append(build_self_update_task(settings, health_gate=gate))
    # ------------------------------------------------------------------

    return tuple(tasks), gate
