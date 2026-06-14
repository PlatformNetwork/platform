"""Timeout reaper — supervisor scheduled task (plan Task 17).

At each tick the reaper:

1. On its FIRST tick (and on every tick until one succeeds), reconstructs the
   shared :class:`~platform_network.master.workload_ledger.WorkloadLedger`
   from BOTH node daemons (manager: ``docker service ls``/``inspect``;
   worker: ``docker ps`` for escape-hatch containers) via the ledger's
   :meth:`~platform_network.master.workload_ledger.WorkloadLedger.reconstruct`
   / ``WorkloadSource`` protocol. NO reap decision is ever made before a
   reconstruct has completed successfully at least once.
2. On subsequent ticks, refreshes daemon-reported ``StartedAt`` timestamps
   into the ledger via ``observe_started_at`` (first observation wins).
3. Takes ``ledger.expired(now)`` — where ``now`` derives from the daemons'
   own clocks (``docker info`` ``SystemTime``), NEVER this host's wall clock
   compared against another host's ``StartedAt`` — and removes past-deadline
   workloads: ``docker service rm`` for ``kind="swarm_service"`` and
   ``docker rm -f`` for ``kind="escape_hatch_container"``. Successful
   removal releases the ledger entry (idempotent), immediately freeing the
   Task-14 quota slot.

Safety invariants (plan Task 17 "Must NOT do"):

- ``workload_class="service"`` entries (long-lived PRISM challenge services)
  are NEVER reaped. ``WorkloadLedger.expired`` already excludes them by
  construction (their ``deadline`` is always ``None``); :meth:`TimeoutReaper.tick`
  additionally re-checks the class before any removal (defense in depth).
- Entries without a daemon-observed ``started_at`` are never reaped (their
  deadline is ``None``).
- When two daemons disagree about "now", the MINIMUM observed daemon time is
  used, so clock skew can only delay a reap — never trigger one early.

Health gate: the reaper performs daemon-scoped cleanup and has NO broker
HTTP dependency, so an unhealthy :class:`BrokerHealthGate` does not disable
it — the reaper is precisely the crash-recovery backstop for workloads whose
in-process broker timeout enforcement died with the broker (Task 13 note).

Reconstructed entries carry ``timeout_seconds=None`` (the daemons do not
persist the author timeout), so unknown-but-valid workloads discovered at
reconstruct are never spuriously reaped. Reaping engages for entries whose
timeout is known to this process's ledger (registered by the broker when the
ledger is shared, or restored by an owner that knows the timeout).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from platform_network.config.settings import Settings
from platform_network.master.docker_broker import (
    EscapeHatchCliRunner,
    EscapeHatchCommandRunner,
)
from platform_network.master.swarm_backend import (
    JOB_TERMINAL_STATES,
    SwarmCliRunner,
    SwarmCommandRunner,
    _parse_docker_timestamp,
)
from platform_network.master.workload_ledger import (
    WorkloadEntry,
    WorkloadKind,
    WorkloadLedger,
)
from platform_network.supervisor.health import BrokerHealthGate
from platform_network.supervisor.scheduler import ScheduledTask

logger = logging.getLogger(__name__)

REAPER_TASK_NAME = "timeout-reaper"
REAPER_INTERVAL_SECONDS = 30.0
DEFAULT_COMMAND_TIMEOUT_SECONDS = 30.0

#: stderr markers meaning "the workload is already gone" — removal of an
#: already-removed workload counts as success (release stays idempotent).
_GONE_MARKERS = ("no such", "not found")

#: Task states in which the Swarm task ``.Status.Timestamp`` reflects an
#: actual start (same convention as ``SwarmBrokerService._wait_for_job``).
_STARTED_STATES = JOB_TERMINAL_STATES | {"running"}


class ReaperSourceError(RuntimeError):
    """Raised when a daemon listing fails (reconstruct must not proceed)."""


class ReaperSource(Protocol):
    """One node daemon: list platform workloads, tell time, remove by key.

    Extends the ledger's ``WorkloadSource`` protocol (``list_workloads``)
    with the reaper-specific operations. Tests inject fakes; production uses
    :class:`SwarmServiceSource` (manager) and
    :class:`EscapeHatchContainerSource` (worker).
    """

    @property
    def kind(self) -> WorkloadKind: ...

    def list_workloads(self) -> Sequence[WorkloadEntry]: ...

    def daemon_now(self) -> datetime | None: ...

    def remove(self, key: str) -> bool: ...


def _removal_succeeded(returncode: int, stderr: str) -> bool:
    if returncode == 0:
        return True
    lowered = stderr.lower()
    return any(marker in lowered for marker in _GONE_MARKERS)


def _zero_timestamp_to_none(value: datetime | None) -> datetime | None:
    """Docker reports ``0001-01-01T00:00:00Z`` for never-started workloads."""
    if value is not None and value.year <= 1:
        return None
    return value


@dataclass
class SwarmServiceSource:
    """Manager-daemon adapter: Swarm services → :class:`WorkloadEntry`.

    ``docker service ls`` prints TRUNCATED IDs (Task 9 gotcha); entries are
    keyed by the FULL ``.ID`` from ``docker service inspect``. The workload
    class derives from ``Spec.Mode`` (``ReplicatedJob``/``GlobalJob`` → job,
    otherwise service) — NEVER from labels (Task 5 contract).
    """

    runner: SwarmCommandRunner
    docker_bin: str = "docker"
    command_timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS
    kind: WorkloadKind = "swarm_service"

    def _run(self, *args: str) -> tuple[int, str, str]:
        result = self.runner.run(
            [self.docker_bin, *args],
            timeout_seconds=self.command_timeout_seconds,
        )
        return result.returncode, result.stdout, result.stderr

    def list_workloads(self) -> Sequence[WorkloadEntry]:
        returncode, stdout, stderr = self._run("service", "ls", "-q")
        if returncode != 0:
            raise ReaperSourceError(
                f"docker service ls failed (rc={returncode}): {stderr.strip()}"
            )
        entries: list[WorkloadEntry] = []
        for service_id in _nonempty_lines(stdout):
            entry = self._inspect_service(service_id)
            if entry is not None:
                entries.append(entry)
        return entries

    def _inspect_service(self, service_id: str) -> WorkloadEntry | None:
        returncode, stdout, _ = self._run(
            "service", "inspect", "--format", "{{json .}}", service_id
        )
        if returncode != 0:
            # Service vanished between ls and inspect — not a listing failure.
            return None
        parsed = _load_json_object(stdout)
        if parsed is None:
            return None
        spec = parsed.get("Spec")
        spec = spec if isinstance(spec, dict) else {}
        labels = spec.get("Labels")
        labels = labels if isinstance(labels, dict) else {}
        slug = labels.get("platform.challenge") or labels.get("platform.challenge.slug")
        full_id = str(parsed.get("ID") or "").strip()
        if not slug or not full_id:
            return None
        mode = spec.get("Mode")
        mode = mode if isinstance(mode, dict) else {}
        is_job = "ReplicatedJob" in mode or "GlobalJob" in mode
        return WorkloadEntry(
            key=full_id,
            kind="swarm_service",
            challenge_slug=str(slug),
            workload_class="job" if is_job else "service",
            started_at=self._task_started_at(full_id),
            timeout_seconds=None,
        )

    def _task_started_at(self, service_id: str) -> datetime | None:
        returncode, stdout, _ = self._run(
            "service", "ps", service_id, "-q", "--no-trunc"
        )
        task_ids = _nonempty_lines(stdout)
        if returncode != 0 or not task_ids:
            return None
        returncode, stdout, _ = self._run(
            "inspect", "--format", "{{json .Status}}", task_ids[0]
        )
        if returncode != 0:
            return None
        status = _load_json_object(stdout)
        if status is None:
            return None
        state = str(status.get("State") or "")
        if state not in _STARTED_STATES:
            return None
        return _zero_timestamp_to_none(_parse_docker_timestamp(status.get("Timestamp")))

    def daemon_now(self) -> datetime | None:
        returncode, stdout, _ = self._run("info", "--format", "{{json .SystemTime}}")
        if returncode != 0:
            return None
        return _parse_json_timestamp(stdout)

    def remove(self, key: str) -> bool:
        returncode, _, stderr = self._run("service", "rm", key)
        return _removal_succeeded(returncode, stderr)


@dataclass
class EscapeHatchContainerSource:
    """Worker-daemon adapter: escape-hatch containers → :class:`WorkloadEntry`.

    Lists ``docker ps`` containers carrying the broker's
    ``platform.challenge`` label (escape-hatch/broker job containers). The
    long-lived DockerOrchestrator challenge API containers use the DIFFERENT
    ``platform.challenge.slug`` label and are deliberately excluded.
    ``StartedAt`` comes from the worker daemon's ``.State.StartedAt`` (Task
    13: this is what makes crashed-broker leftovers observable). Removal verb
    is ``docker rm -f``.

    ``host`` (optional ``docker -H <host>`` target) selects the worker
    daemon when the supervisor runs elsewhere; wiring a real value belongs to
    deployment (Tasks 24/28). ``None`` targets the local daemon.
    """

    runner: EscapeHatchCommandRunner
    docker_bin: str = "docker"
    host: str | None = None
    command_timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS
    kind: WorkloadKind = "escape_hatch_container"

    def _run(self, *args: str) -> tuple[int, str, str]:
        argv = [self.docker_bin]
        if self.host:
            argv += ["-H", self.host]
        argv.extend(args)
        result = self.runner.run(argv, timeout_seconds=self.command_timeout_seconds)
        return result.returncode, result.stdout, result.stderr

    def list_workloads(self) -> Sequence[WorkloadEntry]:
        returncode, stdout, stderr = self._run(
            "ps", "-q", "--no-trunc", "--filter", "label=platform.challenge"
        )
        if returncode != 0:
            raise ReaperSourceError(
                f"docker ps failed (rc={returncode}): {stderr.strip()}"
            )
        entries: list[WorkloadEntry] = []
        for container_id in _nonempty_lines(stdout):
            entry = self._inspect_container(container_id)
            if entry is not None:
                entries.append(entry)
        return entries

    def _inspect_container(self, container_id: str) -> WorkloadEntry | None:
        returncode, stdout, _ = self._run(
            "inspect", "--format", "{{json .}}", container_id
        )
        if returncode != 0:
            return None
        parsed = _load_json_object(stdout)
        if parsed is None:
            return None
        config = parsed.get("Config")
        config = config if isinstance(config, dict) else {}
        labels = config.get("Labels")
        labels = labels if isinstance(labels, dict) else {}
        slug = labels.get("platform.challenge")
        if not slug:
            return None
        state = parsed.get("State")
        state = state if isinstance(state, dict) else {}
        started_at = _zero_timestamp_to_none(
            _parse_docker_timestamp(state.get("StartedAt"))
        )
        return WorkloadEntry(
            key=container_id,
            kind="escape_hatch_container",
            challenge_slug=str(slug),
            workload_class="job",
            started_at=started_at,
            timeout_seconds=None,
        )

    def daemon_now(self) -> datetime | None:
        returncode, stdout, _ = self._run("info", "--format", "{{json .SystemTime}}")
        if returncode != 0:
            return None
        return _parse_json_timestamp(stdout)

    def remove(self, key: str) -> bool:
        returncode, _, stderr = self._run("rm", "-f", key)
        return _removal_succeeded(returncode, stderr)


class TimeoutReaper:
    """Class-aware, clock-skew-safe, restart-safe workload reaper."""

    def __init__(
        self,
        *,
        ledger: WorkloadLedger,
        sources: Sequence[ReaperSource],
        clock: Callable[[], datetime | None] | None = None,
        health_gate: BrokerHealthGate | None = None,
    ) -> None:
        self._ledger = ledger
        self._sources = tuple(sources)
        self._clock = clock
        self._health_gate = health_gate
        self._reconstructed = False
        by_kind: dict[WorkloadKind, ReaperSource] = {}
        for source in self._sources:
            by_kind.setdefault(source.kind, source)
        self._by_kind = by_kind

    @property
    def reconstructed(self) -> bool:
        return self._reconstructed

    @property
    def ledger(self) -> WorkloadLedger:
        return self._ledger

    def tick(self) -> None:
        if self._health_gate is not None and not self._health_gate.healthy:
            # The reaper has no broker-dependent work to skip: it talks to
            # the docker daemons directly and is the crash-recovery backstop
            # that matters MOST while the broker is down. Log and continue.
            logger.info(
                "broker health gate unhealthy; reaper continues "
                "(daemon-scoped cleanup has no broker dependency)"
            )
        if not self._reconstructed:
            try:
                restored = self._ledger.reconstruct(self._sources)
            except Exception:
                logger.exception(
                    "workload ledger reconstruct failed; reaping stays "
                    "disabled until a reconstruct succeeds"
                )
                return
            self._reconstructed = True
            logger.info(
                "workload ledger reconstructed from %d daemon(s): %d entries",
                len(self._sources),
                restored,
            )
        else:
            self._refresh_started_at()
        now = self._observed_now()
        if now is None:
            logger.warning("no daemon-derived clock available; skipping reap this tick")
            return
        for entry in self._ledger.expired(now):
            self._reap(entry)

    def _refresh_started_at(self) -> None:
        for source in self._sources:
            try:
                listing = source.list_workloads()
            except Exception:
                logger.warning(
                    "daemon listing failed during StartedAt refresh; "
                    "continuing with remaining daemons",
                    exc_info=True,
                )
                continue
            for entry in listing:
                if entry.started_at is not None:
                    self._ledger.observe_started_at(entry.key, entry.started_at)

    def _observed_now(self) -> datetime | None:
        if self._clock is not None:
            return self._clock()
        times: list[datetime] = []
        for source in self._sources:
            try:
                observed = source.daemon_now()
            except Exception:
                logger.warning("daemon clock query failed", exc_info=True)
                observed = None
            if observed is not None:
                times.append(observed)
        # Minimum across daemons: clock skew can only DELAY a reap.
        return min(times) if times else None

    def _reap(self, entry: WorkloadEntry) -> None:
        if entry.workload_class != "job":
            # Defense in depth: expired() never returns service-class
            # entries, but a long-lived service must NEVER be removed even
            # if that invariant regresses.
            logger.error(
                "refusing to reap workload %s: workload_class=%r is never "
                "reaper-eligible",
                entry.key,
                entry.workload_class,
            )
            return
        if entry.started_at is None:
            logger.error(
                "refusing to reap workload %s: no daemon-observed StartedAt",
                entry.key,
            )
            return
        source = self._by_kind.get(entry.kind)
        if source is None:
            logger.error(
                "no removal source configured for kind %r (workload %s)",
                entry.kind,
                entry.key,
            )
            return
        try:
            removed = source.remove(entry.key)
        except Exception:
            logger.warning(
                "removal of past-deadline workload %s raised; retrying next tick",
                entry.key,
                exc_info=True,
            )
            return
        if removed:
            self._ledger.release(entry.key)
            logger.info(
                "reaped past-deadline %s %s (challenge=%s, deadline=%s)",
                entry.kind,
                entry.key,
                entry.challenge_slug,
                entry.deadline,
            )
        else:
            logger.warning(
                "removal of past-deadline workload %s failed; retrying next tick",
                entry.key,
            )


def build_reaper_task(
    settings: Settings,
    *,
    health_gate: BrokerHealthGate | None = None,
    ledger: WorkloadLedger | None = None,
    manager_runner: SwarmCommandRunner | None = None,
    worker_runner: EscapeHatchCommandRunner | None = None,
    worker_docker_host: str | None = None,
    clock: Callable[[], datetime | None] | None = None,
    interval_seconds: float = REAPER_INTERVAL_SECONDS,
) -> ScheduledTask:
    """Build the supervisor's timeout-reaper :class:`ScheduledTask`.

    Follows the Task-16 registration recipe: synchronous callable, safe on a
    non-main daemon thread, tolerates its own transient errors. Runners,
    ledger, and clock are injectable for tests; defaults are the real docker
    CLI runners and the daemon-derived clock.
    """
    del settings  # reserved for future config (interval/worker host wiring)
    manager = SwarmServiceSource(runner=manager_runner or SwarmCliRunner())
    worker = EscapeHatchContainerSource(
        runner=worker_runner or EscapeHatchCliRunner(),
        host=worker_docker_host,
    )
    reaper = TimeoutReaper(
        ledger=ledger or WorkloadLedger(),
        sources=(manager, worker),
        clock=clock,
        health_gate=health_gate,
    )
    return ScheduledTask(
        name=REAPER_TASK_NAME,
        interval_seconds=interval_seconds,
        run=reaper.tick,
    )


def _nonempty_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _load_json_object(raw: str) -> dict[str, object] | None:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _parse_json_timestamp(raw: str) -> datetime | None:
    text = raw.strip()
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        decoded = text
    return _parse_docker_timestamp(decoded)
