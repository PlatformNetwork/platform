"""Scheduled-task registry — the SINGLE registration seam for Tasks 17-22.

Recipe for adding a new periodic job (reaper, image-updater,
challenge-image-updater, config-sync, weights, self-update):

1. Create ``src/base/supervisor/<job>.py`` exporting a builder::

       def build_<job>_task(settings: Settings) -> ScheduledTask: ...

   The builder closes over whatever clients/ledgers the job needs; the
   callable it returns must be synchronous, must tolerate being called from
   a non-main daemon thread, and may consult the shared
   :class:`~base.supervisor.health.BrokerHealthGate` (passed into
   the builder) to skip broker-dependent work while the gate is unhealthy.

2. Append EXACTLY ONE registration line to :func:`build_scheduled_tasks`
   below at the marked slot. Do NOT edit ``loop.py`` or ``scheduler.py``.

The supervisor always schedules the broker ``/health`` probe itself; it is
built here so the gate instance can be shared with future job builders.
"""

from __future__ import annotations

import logging

from base.config.settings import Settings
from base.supervisor.alerts import build_alert_hook, build_health_probe_task
from base.supervisor.challenge_image_updater import (
    build_challenge_image_updater_task,
)
from base.supervisor.config_sync import build_config_sync_task
from base.supervisor.health import (
    DEFAULT_FAILURE_THRESHOLD,
    DEFAULT_PROBE_TIMEOUT_SECONDS,
    BrokerHealthGate,
    http_health_prober,
)
from base.supervisor.image_ref import (
    build_registry_digest_resolver,
    load_registry_credentials,
)
from base.supervisor.image_updater import (
    DigestResolver,
    build_image_updater_task,
    resolve_image_update_targets,
)
from base.supervisor.reaper import build_reaper_task
from base.supervisor.scheduler import ScheduledTask
from base.supervisor.self_update import (
    build_self_update_task,
    run_startup_rollback_check,
)
from base.supervisor.weight_submit import build_weight_submit_task

logger = logging.getLogger(__name__)

BROKER_HEALTH_PROBE_INTERVAL_SECONDS = 10.0


def _build_digest_resolver(settings: Settings) -> DigestResolver | None:
    """Authenticated GHCR digest resolver wired from supervisor settings.

    Returns None (so the image-updaters fall back to the anonymous
    :func:`resolve_remote_digest`) unless registry credentials are resolvable —
    keeping the PUBLIC-package path behaviour-preserving when nothing is wired.
    """
    sup = settings.supervisor
    credentials = load_registry_credentials(
        sup.registry,
        username=sup.registry_username,
        password=sup.registry_password,
        password_file=sup.registry_password_file,
        docker_config_path=sup.registry_docker_config_path,
    )
    if credentials is None:
        return None
    logger.info(
        "image-updater: resolving %s digests with authenticated registry "
        "credentials (private packages supported)",
        sup.registry,
    )
    return build_registry_digest_resolver(credentials, registry=sup.registry)


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

    # Authenticated GHCR digest resolver (G4): private ghcr.io/baseintelligence/*
    # packages need a credentialed token to resolve their tag digest; None falls
    # back to the anonymous resolver (public-package path, unchanged).
    digest_resolver = _build_digest_resolver(settings)

    # Task 16 alert hook: a single config-driven webhook hook (no-op until
    # settings.observability.alert_webhook_url is set) shared by every failure
    # surface below. It IS the Task-8 AlertEmitter seam, so wiring it here makes
    # the existing commit-reject/backoff path emit to the webhook with no
    # duplication.
    alert_hook = build_alert_hook(settings)

    # ------------------------------------------------------------------
    # Task 17 registration point (reaper):
    # The reaper builder owns WorkloadLedger.reconstruct on first tick and
    # ledger access thereafter (see Task 7/14 notepad contracts).
    tasks.append(build_reaper_task(settings, health_gate=gate))
    # ------------------------------------------------------------------
    # Task 18 registration point (image-updater):
    # Targets are SETTINGS-DRIVEN (G-A5): resolve_image_update_targets defaults to
    # the installer-created master services (base-master-proxy + base-docker-broker)
    # when supervisor.image_updater_targets is unset, so the production targets
    # never silently drift, and appends a validator-agent target tracking the
    # mutable validator runtime image when supervisor.validator_agent_target_enabled
    # is set (so a validator NODE running the agent as a swarm service auto-rolls).
    tasks.append(
        build_image_updater_task(
            settings,
            health_gate=gate,
            resolver=digest_resolver,
            targets=resolve_image_update_targets(settings),
        )
    )
    # Task 19 registration point (challenge-image-updater).
    tasks.append(
        build_challenge_image_updater_task(
            settings, health_gate=gate, resolver=digest_resolver
        )
    )
    # Task 20 registration point (config-sync).
    # Task 28 #1: same canonical-broker call-site override; single-port
    # consolidation drops the removed `base-admin` rollout target. The proxy
    # rollout target MUST match the installer-created `base-master-proxy`. The
    # module-default DEFAULT_ROLLOUT_SERVICES is now realigned to the SAME
    # installer-created names (base-master-proxy + base-docker-broker); this
    # explicit override is retained so the production targets never silently drift.
    tasks.append(
        build_config_sync_task(
            settings,
            health_gate=gate,
            rollout_services=(
                "base-master-proxy",
                "base-docker-broker",
            ),
        )
    )
    # Task 21 weights (on-chain submit): code-CAPABLE, RUNTIME-OFF by default.
    # The submit path only fires when settings.validator.submit_on_chain_enabled
    # is True (defaults False), so a deploy never auto-commits; the first commit
    # is human-gated (plan Task 27). It health-gates on eval-pipeline scores and
    # backs off + alerts (Task-16 seam) on a commit-reveal rejection, never
    # silently dropping an epoch.
    tasks.append(
        build_weight_submit_task(settings, health_gate=gate, alert_emit=alert_hook)
    )
    # Task 22 registration point (self-update).
    # Startup-side rollback agent (Task 22): MUST run once before workers
    # start — it flips `current` back + exits when a pending update is
    # restart-storming (post-swap health gate). No-op outside a staged
    # release / without a pending update. Runs UNCONDITIONALLY so a swap left
    # pending by a previously-enabled self-update can still be rolled back even
    # if self-update was since disabled.
    run_startup_rollback_check()
    # Self-update is registered ONLY when explicitly enabled AND wired to a
    # manifest URL — never registered-but-inert (no silent half-state). When
    # disabled the task is simply absent; the supervisor performs no self-update.
    if settings.supervisor.self_update_enabled:
        manifest_url = settings.supervisor.self_update_manifest_url
        if not manifest_url:
            raise ValueError(
                "supervisor.self_update_enabled=true requires "
                "supervisor.self_update_manifest_url (refusing to register an "
                "inert self-update task)"
            )
        tasks.append(
            build_self_update_task(
                settings, health_gate=gate, manifest_url=manifest_url
            )
        )
        logger.info("self-update: enabled (manifest_url wired)")
    else:
        logger.info(
            "self-update: disabled (supervisor.self_update_enabled=false); "
            "task not registered"
        )
    # Task 16 reachability probe: fires gpu_down / drand_unreachable alerts when
    # the configured GPU/drand health URLs fail. Skips each probe whose URL is
    # unset, so it is a no-op in a default deploy.
    tasks.append(build_health_probe_task(settings, hook=alert_hook))
    # ------------------------------------------------------------------

    return tuple(tasks), gate
