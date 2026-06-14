"""Unit tests for the supervisor timeout reaper (plan Task 17).

Everything runs against fake runners/sources and an injected clock — no
dockerd required. Covers the Task 17 safety invariants: correct removal verb
per kind, service-class never reaped, no reap without daemon-observed
StartedAt, reconstruct-before-reap, reconstruct-failure retry, and
gate-unhealthy behavior.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta

from platform_network.config.settings import Settings
from platform_network.master.docker_broker import EscapeHatchCommandResult
from platform_network.master.swarm_backend import SwarmCommandResult
from platform_network.master.workload_ledger import (
    WorkloadEntry,
    WorkloadKind,
    WorkloadLedger,
)
from platform_network.supervisor.health import BrokerHealthGate
from platform_network.supervisor.reaper import (
    REAPER_TASK_NAME,
    EscapeHatchContainerSource,
    ReaperSourceError,
    SwarmServiceSource,
    TimeoutReaper,
    build_reaper_task,
)
from platform_network.supervisor.tasks import build_scheduled_tasks

UTC = UTC
T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)

_Handler = Callable[[tuple[str, ...]], tuple[int, str, str]]


class FakeSwarmRunner:
    """Argv-capturing SwarmCommandRunner fake (mirrors test_swarm_backend)."""

    def __init__(self, handler: _Handler) -> None:
        self.handler = handler
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        input_text: str | None = None,
        timeout_seconds: float | None = None,
    ) -> SwarmCommandResult:
        call = tuple(argv)
        self.calls.append(call)
        returncode, stdout, stderr = self.handler(call)
        return SwarmCommandResult(
            argv=call, returncode=returncode, stdout=stdout, stderr=stderr
        )


class FakeEscapeRunner:
    """Argv-capturing EscapeHatchCommandRunner fake."""

    def __init__(self, handler: _Handler) -> None:
        self.handler = handler
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float | None = None,
    ) -> EscapeHatchCommandResult:
        call = tuple(argv)
        self.calls.append(call)
        returncode, stdout, stderr = self.handler(call)
        return EscapeHatchCommandResult(
            argv=call, returncode=returncode, stdout=stdout, stderr=stderr
        )


class FakeSource:
    """In-memory ReaperSource fake for TimeoutReaper logic tests."""

    def __init__(
        self,
        kind: WorkloadKind,
        entries: Sequence[WorkloadEntry] = (),
        *,
        now: datetime | None = None,
        fail_listing: bool = False,
        remove_result: bool = True,
    ) -> None:
        self.kind = kind
        self.entries = list(entries)
        self.now = now
        self.fail_listing = fail_listing
        self.remove_result = remove_result
        self.removed: list[str] = []
        self.list_calls = 0

    def list_workloads(self) -> Sequence[WorkloadEntry]:
        self.list_calls += 1
        if self.fail_listing:
            raise ReaperSourceError("daemon unreachable")
        return tuple(self.entries)

    def daemon_now(self) -> datetime | None:
        return self.now

    def remove(self, key: str) -> bool:
        self.removed.append(key)
        return self.remove_result


def _job(
    key: str,
    *,
    kind: WorkloadKind = "swarm_service",
    started_at: datetime | None = T0,
    timeout_seconds: int | None = 10,
    workload_class: str = "job",
) -> WorkloadEntry:
    return WorkloadEntry(
        key=key,
        kind=kind,
        challenge_slug="demo",
        workload_class=workload_class,  # type: ignore[arg-type]
        started_at=started_at,
        timeout_seconds=timeout_seconds,
    )


def _reaper(
    *sources: FakeSource,
    ledger: WorkloadLedger | None = None,
    clock: Callable[[], datetime | None] | None = None,
    health_gate: BrokerHealthGate | None = None,
) -> tuple[TimeoutReaper, WorkloadLedger]:
    ledger = ledger or WorkloadLedger()
    reaper = TimeoutReaper(
        ledger=ledger,
        sources=sources,
        clock=clock,
        health_gate=health_gate,
    )
    return reaper, ledger


def _past_deadline_clock() -> datetime | None:
    return T0 + timedelta(minutes=5)


# ---------------------------------------------------------------------------
# Reap semantics
# ---------------------------------------------------------------------------


def test_past_deadline_job_reaped_and_released() -> None:
    source = FakeSource("swarm_service")
    reaper, ledger = _reaper(source, clock=_past_deadline_clock)
    reaper.tick()  # first tick: reconstruct (empty daemon)
    ledger.register(_job("svc1"))
    reaper.tick()
    assert source.removed == ["svc1"]
    assert ledger.get("svc1") is None  # released after successful removal


def test_service_class_entry_is_never_reaped() -> None:
    source = FakeSource("swarm_service")
    reaper, ledger = _reaper(source, clock=_past_deadline_clock)
    reaper.tick()
    # Long-lived PRISM-style service, registered ages ago with a timeout
    # value present: expired() excludes it by construction.
    ledger.register(_job("prism", workload_class="service", timeout_seconds=1))
    reaper.tick()
    assert source.removed == []
    assert ledger.get("prism") is not None


def test_service_class_defense_in_depth_blocks_forged_expired() -> None:
    """Even if expired() regressed, the reaper re-checks the class."""

    class BrokenLedger(WorkloadLedger):
        def expired(self, now: datetime) -> tuple[WorkloadEntry, ...]:
            return (_job("prism", workload_class="service"),)

    source = FakeSource("swarm_service")
    reaper, _ = _reaper(source, ledger=BrokenLedger(), clock=_past_deadline_clock)
    reaper.tick()
    reaper.tick()
    assert source.removed == []


def test_entry_without_started_at_is_not_reaped() -> None:
    source = FakeSource("swarm_service")
    reaper, ledger = _reaper(source, clock=_past_deadline_clock)
    reaper.tick()
    ledger.register(_job("svc1", started_at=None))
    reaper.tick()
    assert source.removed == []
    assert ledger.get("svc1") is not None


def test_failed_removal_keeps_entry_for_retry() -> None:
    source = FakeSource("swarm_service", remove_result=False)
    reaper, ledger = _reaper(source, clock=_past_deadline_clock)
    reaper.tick()
    ledger.register(_job("svc1"))
    reaper.tick()
    assert source.removed == ["svc1"]
    assert ledger.get("svc1") is not None
    source.remove_result = True
    reaper.tick()
    assert source.removed == ["svc1", "svc1"]
    assert ledger.get("svc1") is None


# ---------------------------------------------------------------------------
# Reconstruct-before-reap
# ---------------------------------------------------------------------------


def test_no_reap_before_reconstruct_completes() -> None:
    source = FakeSource("swarm_service", fail_listing=True)
    ledger = WorkloadLedger()
    ledger.register(_job("svc1"))  # past-deadline entry already present
    reaper, _ = _reaper(source, ledger=ledger, clock=_past_deadline_clock)
    reaper.tick()
    assert not reaper.reconstructed
    assert source.removed == []
    assert ledger.get("svc1") is not None


def test_reconstruct_failure_retried_next_tick_then_reaps() -> None:
    source = FakeSource(
        "swarm_service",
        entries=[_job("svc1")],
        fail_listing=True,
    )
    reaper, ledger = _reaper(source, clock=_past_deadline_clock)
    reaper.tick()
    assert not reaper.reconstructed
    source.fail_listing = False
    reaper.tick()  # retry succeeds, then evaluates in the same tick
    assert reaper.reconstructed
    assert source.removed == ["svc1"]
    assert ledger.get("svc1") is None


def test_reconstruct_populates_without_spurious_reap() -> None:
    """Unknown-but-valid daemon workloads (no recoverable timeout) survive."""
    daemon_entries = [
        _job("svc1", timeout_seconds=None),
        _job(
            "prism",
            workload_class="service",
            timeout_seconds=None,
        ),
    ]
    source = FakeSource("swarm_service", entries=daemon_entries)
    reaper, ledger = _reaper(source, clock=_past_deadline_clock)
    reaper.tick()
    assert reaper.reconstructed
    assert source.removed == []
    assert ledger.get("svc1") is not None
    assert ledger.get("prism") is not None


def test_reconstruct_enumerates_both_daemons() -> None:
    manager = FakeSource("swarm_service", entries=[_job("svc1")])
    worker = FakeSource(
        "escape_hatch_container",
        entries=[_job("c1", kind="escape_hatch_container")],
    )
    reaper, ledger = _reaper(manager, worker, clock=lambda: T0)
    reaper.tick()
    assert ledger.get("svc1") is not None
    assert ledger.get("c1") is not None


def test_started_at_refreshed_from_daemon_each_tick() -> None:
    """Broker-registered entry (started_at=None) becomes reapable once the
    daemon reports StartedAt — the shared-ledger Task 13/14 flow."""
    source = FakeSource("swarm_service")
    reaper, ledger = _reaper(source, clock=_past_deadline_clock)
    reaper.tick()
    ledger.register(_job("svc1", started_at=None, timeout_seconds=2))
    reaper.tick()
    assert source.removed == []  # no StartedAt observed yet
    source.entries = [_job("svc1", timeout_seconds=None)]  # daemon reports T0
    reaper.tick()
    assert source.removed == ["svc1"]
    assert ledger.get("svc1") is None


# ---------------------------------------------------------------------------
# Removal verbs (argv level, via the real sources + fake runners)
# ---------------------------------------------------------------------------


def test_swarm_service_removed_via_docker_service_rm() -> None:
    def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
        if argv[:3] == ("docker", "service", "ls"):
            return 0, "", ""
        if argv[:3] == ("docker", "service", "rm"):
            return 0, argv[-1], ""
        return 0, "", ""

    runner = FakeSwarmRunner(handler)
    source = SwarmServiceSource(runner=runner)
    reaper = TimeoutReaper(
        ledger=WorkloadLedger(),
        sources=(source,),
        clock=_past_deadline_clock,
    )
    reaper.tick()
    reaper.ledger.register(_job("fullserviceid123"))
    reaper.tick()
    assert ("docker", "service", "rm", "fullserviceid123") in runner.calls
    assert reaper.ledger.get("fullserviceid123") is None


def test_escape_hatch_removed_via_docker_rm_f() -> None:
    def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
        if argv[:2] == ("docker", "ps"):
            return 0, "", ""
        if argv[:3] == ("docker", "rm", "-f"):
            return 0, argv[-1], ""
        return 0, "", ""

    runner = FakeEscapeRunner(handler)
    source = EscapeHatchContainerSource(runner=runner)
    reaper = TimeoutReaper(
        ledger=WorkloadLedger(),
        sources=(source,),
        clock=_past_deadline_clock,
    )
    reaper.tick()
    reaper.ledger.register(_job("c0ffee" * 10 + "abcd", kind="escape_hatch_container"))
    reaper.tick()
    container_id = "c0ffee" * 10 + "abcd"
    assert ("docker", "rm", "-f", container_id) in runner.calls
    assert reaper.ledger.get(container_id) is None


def test_removal_of_already_gone_workload_counts_as_success() -> None:
    def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
        if argv[:3] == ("docker", "service", "rm"):
            return 1, "", "Error: no such service: svc1"
        return 0, "", ""

    runner = FakeSwarmRunner(handler)
    source = SwarmServiceSource(runner=runner)
    reaper = TimeoutReaper(
        ledger=WorkloadLedger(),
        sources=(source,),
        clock=_past_deadline_clock,
    )
    reaper.tick()
    reaper.ledger.register(_job("svc1"))
    reaper.tick()
    assert reaper.ledger.get("svc1") is None


# ---------------------------------------------------------------------------
# Daemon-derived clock (never cross-host wall clock)
# ---------------------------------------------------------------------------


def test_reap_skipped_when_no_daemon_clock_available() -> None:
    source = FakeSource("swarm_service", now=None)
    reaper, ledger = _reaper(source)  # no injected clock
    reaper.tick()
    ledger.register(_job("svc1"))
    reaper.tick()
    assert source.removed == []
    assert ledger.get("svc1") is not None


def test_daemon_clock_uses_minimum_across_daemons() -> None:
    # Worker clock is far ahead; manager clock is before the deadline.
    # min() must win, so skew can only delay a reap, never cause one early.
    manager = FakeSource("swarm_service", now=T0 + timedelta(seconds=5))
    worker = FakeSource("escape_hatch_container", now=T0 + timedelta(hours=1))
    reaper, ledger = _reaper(manager, worker)
    reaper.tick()
    ledger.register(_job("svc1", timeout_seconds=10))  # deadline T0+10s
    reaper.tick()
    assert manager.removed == []
    manager.now = T0 + timedelta(seconds=11)
    reaper.tick()
    assert manager.removed == ["svc1"]


# ---------------------------------------------------------------------------
# Health gate
# ---------------------------------------------------------------------------


def test_unhealthy_gate_does_not_disable_reaping() -> None:
    """The reaper has NO broker-dependent work to skip: it is the
    crash-recovery backstop that matters most while the broker is down
    (Task 13 contract), and it talks to dockerd directly."""
    gate = BrokerHealthGate(lambda: False, failure_threshold=1)
    gate.probe_once()
    assert not gate.healthy
    source = FakeSource("swarm_service")
    reaper, ledger = _reaper(source, clock=_past_deadline_clock, health_gate=gate)
    reaper.tick()
    ledger.register(_job("svc1"))
    reaper.tick()
    assert source.removed == ["svc1"]


# ---------------------------------------------------------------------------
# Real source adapters (docker CLI output parsing)
# ---------------------------------------------------------------------------

_SERVICE_INSPECT_JOB = (
    '{"ID": "fullid0123456789abcdef00x", "Spec": {"Labels": '
    '{"platform.challenge": "demo", "platform.job": "j1"}, '
    '"Mode": {"ReplicatedJob": {"MaxConcurrent": 1}}}}'
)
_SERVICE_INSPECT_SERVICE = (
    '{"ID": "svcfullid0123456789abcdef", "Spec": {"Labels": '
    '{"platform.component": "challenge", '
    '"platform.challenge.slug": "prism"}, '
    '"Mode": {"Replicated": {"Replicas": 1}}}}'
)
_TASK_STATUS_RUNNING = (
    '{"State": "running", "Timestamp": "2026-01-01T00:00:00.123456789Z"}'
)


def test_swarm_source_lists_full_ids_class_from_mode_and_started_at() -> None:
    def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
        if argv[:3] == ("docker", "service", "ls"):
            return 0, "shortjob\nshortsvc\nshortalien\n", ""
        if argv[:3] == ("docker", "service", "inspect"):
            if argv[-1] == "shortjob":
                return 0, _SERVICE_INSPECT_JOB, ""
            if argv[-1] == "shortsvc":
                return 0, _SERVICE_INSPECT_SERVICE, ""
            return 0, '{"ID": "alien", "Spec": {"Labels": {}}}', ""
        if argv[:3] == ("docker", "service", "ps"):
            return 0, "taskid1\n", ""
        if argv[:2] == ("docker", "inspect"):
            return 0, _TASK_STATUS_RUNNING, ""
        return 1, "", "unexpected"

    source = SwarmServiceSource(runner=FakeSwarmRunner(handler))
    entries = {entry.key: entry for entry in source.list_workloads()}
    assert set(entries) == {
        "fullid0123456789abcdef00x",
        "svcfullid0123456789abcdef",
    }  # alien (non-platform) service skipped; keys are FULL ids
    job = entries["fullid0123456789abcdef00x"]
    assert job.kind == "swarm_service"
    assert job.workload_class == "job"  # from Spec.Mode, never labels
    assert job.challenge_slug == "demo"
    assert job.timeout_seconds is None  # not recoverable from the daemon
    assert job.started_at == datetime(2026, 1, 1, 0, 0, 0, 123456, tzinfo=UTC)
    svc = entries["svcfullid0123456789abcdef"]
    assert svc.workload_class == "service"
    assert svc.challenge_slug == "prism"


def test_swarm_source_raises_when_listing_fails() -> None:
    def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
        return 1, "", "daemon down"

    source = SwarmServiceSource(runner=FakeSwarmRunner(handler))
    try:
        source.list_workloads()
    except ReaperSourceError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected ReaperSourceError")


_CONTAINER_INSPECT = (
    '{"Config": {"Labels": {"platform.challenge": "demo", '
    '"platform.job": "j1"}}, '
    '"State": {"StartedAt": "2026-01-01T00:00:00.5Z"}}'
)
_CONTAINER_INSPECT_NO_SLUG = (
    '{"Config": {"Labels": {"platform.challenge.slug": "prism"}}, '
    '"State": {"StartedAt": "2026-01-01T00:00:00Z"}}'
)
_CONTAINER_INSPECT_NOT_STARTED = (
    '{"Config": {"Labels": {"platform.challenge": "demo"}}, '
    '"State": {"StartedAt": "0001-01-01T00:00:00Z"}}'
)


def test_escape_hatch_source_lists_started_containers() -> None:
    def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
        if argv[:2] == ("docker", "ps"):
            assert "--no-trunc" in argv  # ledger keys are FULL container ids
            return 0, "full1\nfull2\nfull3\n", ""
        if argv[:2] == ("docker", "inspect"):
            if argv[-1] == "full1":
                return 0, _CONTAINER_INSPECT, ""
            if argv[-1] == "full2":
                return 0, _CONTAINER_INSPECT_NO_SLUG, ""
            return 0, _CONTAINER_INSPECT_NOT_STARTED, ""
        return 1, "", "unexpected"

    source = EscapeHatchContainerSource(runner=FakeEscapeRunner(handler))
    entries = {entry.key: entry for entry in source.list_workloads()}
    # full2 has no platform.challenge label (long-lived challenge API
    # container) and is excluded.
    assert set(entries) == {"full1", "full3"}
    assert entries["full1"].kind == "escape_hatch_container"
    assert entries["full1"].workload_class == "job"
    assert entries["full1"].started_at == datetime(
        2026, 1, 1, 0, 0, 0, 500000, tzinfo=UTC
    )
    # zero-value StartedAt means "never started" → not reapable
    assert entries["full3"].started_at is None


def test_escape_hatch_source_targets_worker_host_when_configured() -> None:
    def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
        return 0, "", ""

    runner = FakeEscapeRunner(handler)
    source = EscapeHatchContainerSource(runner=runner, host="ssh://worker.example")
    source.list_workloads()
    assert runner.calls[0][:3] == ("docker", "-H", "ssh://worker.example")


def test_daemon_now_parses_docker_info_system_time() -> None:
    def handler(argv: tuple[str, ...]) -> tuple[int, str, str]:
        if argv[:2] == ("docker", "info"):
            return 0, '"2026-01-01T12:00:00.000000001Z"\n', ""
        return 0, "", ""

    source = SwarmServiceSource(runner=FakeSwarmRunner(handler))
    assert source.daemon_now() == datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Builder + registration
# ---------------------------------------------------------------------------


def test_build_reaper_task_returns_scheduled_task() -> None:
    task = build_reaper_task(Settings())
    assert task.name == REAPER_TASK_NAME
    assert task.interval_seconds > 0
    assert callable(task.run)


def test_reaper_registered_in_build_scheduled_tasks() -> None:
    tasks, _ = build_scheduled_tasks(Settings())
    assert REAPER_TASK_NAME in {task.name for task in tasks}
