"""Tests for the authoritative Docker/Swarm active-workload ledger."""

from __future__ import annotations

import threading
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import pytest

from platform_network.master.workload_ledger import (
    WorkloadCapacityError,
    WorkloadEntry,
    WorkloadLedger,
    WorkloadLedgerError,
)

STARTED_AT = datetime(2026, 6, 12, 10, 0, 0, tzinfo=UTC)


def _entry(
    key: str,
    *,
    challenge_slug: str = "challenge-x",
    kind: str = "swarm_service",
    workload_class: str = "job",
    started_at: datetime | None = None,
    timeout_seconds: int | None = None,
) -> WorkloadEntry:
    return WorkloadEntry(
        key=key,
        kind=kind,  # type: ignore[arg-type]
        challenge_slug=challenge_slug,
        workload_class=workload_class,  # type: ignore[arg-type]
        started_at=started_at,
        timeout_seconds=timeout_seconds,
    )


class _FakeDaemon:
    """Fake daemon-listing adapter satisfying the WorkloadSource protocol."""

    def __init__(self, entries: Sequence[WorkloadEntry]) -> None:
        self._entries = tuple(entries)

    def list_workloads(self) -> Sequence[WorkloadEntry]:
        return self._entries


class TestEntryValidation:
    def test_empty_key_rejected(self) -> None:
        with pytest.raises(WorkloadLedgerError):
            _entry("")

    def test_empty_challenge_slug_rejected(self) -> None:
        with pytest.raises(WorkloadLedgerError):
            _entry("svc-1", challenge_slug="")

    def test_non_positive_timeout_rejected(self) -> None:
        with pytest.raises(WorkloadLedgerError):
            _entry("svc-1", timeout_seconds=0)

    def test_naive_started_at_rejected(self) -> None:
        with pytest.raises(WorkloadLedgerError):
            _entry("svc-1", started_at=datetime(2026, 6, 12, 10, 0, 0))


class TestRegisterRelease:
    def test_register_and_count_by_challenge(self) -> None:
        ledger = WorkloadLedger()
        ledger.register(_entry("svc-1"))
        ledger.register(_entry("svc-2"))
        ledger.register(_entry("svc-3", challenge_slug="challenge-y"))
        assert ledger.count("challenge-x") == 2
        assert ledger.count("challenge-y") == 1
        assert ledger.count("challenge-unknown") == 0

    def test_register_duplicate_key_rejected(self) -> None:
        ledger = WorkloadLedger()
        ledger.register(_entry("svc-1"))
        with pytest.raises(WorkloadLedgerError):
            ledger.register(_entry("svc-1"))

    def test_release_is_idempotent(self) -> None:
        ledger = WorkloadLedger()
        ledger.register(_entry("svc-1"))
        assert ledger.release("svc-1") is True
        assert ledger.release("svc-1") is False
        assert ledger.release("never-registered") is False
        assert ledger.count("challenge-x") == 0

    def test_escape_hatch_container_entries_count_alongside_services(self) -> None:
        ledger = WorkloadLedger()
        ledger.register(_entry("svc-1", kind="swarm_service"))
        ledger.register(_entry("ctr-abcdef", kind="escape_hatch_container"))
        assert ledger.count("challenge-x") == 2

    def test_register_at_cap_refused_and_release_frees_slot(self) -> None:
        ledger = WorkloadLedger()
        ledger.register(_entry("svc-1"), max_concurrent=2)
        ledger.register(_entry("svc-2"), max_concurrent=2)
        with pytest.raises(WorkloadCapacityError):
            ledger.register(_entry("svc-3"), max_concurrent=2)
        assert ledger.release("svc-1") is True
        ledger.register(_entry("svc-3"), max_concurrent=2)
        assert ledger.count("challenge-x") == 2

    def test_cap_is_per_challenge(self) -> None:
        ledger = WorkloadLedger()
        ledger.register(_entry("svc-1"), max_concurrent=1)
        ledger.register(_entry("svc-2", challenge_slug="challenge-y"), max_concurrent=1)
        assert ledger.count("challenge-x") == 1
        assert ledger.count("challenge-y") == 1


class TestConcurrency:
    def test_concurrent_register_up_to_cap(self) -> None:
        """32 real threads race to register; exactly cap=5 win."""

        ledger = WorkloadLedger()
        cap = 5
        attempts = 32
        barrier = threading.Barrier(attempts)
        successes: list[str] = []
        refusals: list[str] = []
        results_lock = threading.Lock()

        def worker(index: int) -> None:
            entry = _entry(f"svc-{index}")
            barrier.wait()
            try:
                ledger.register(entry, max_concurrent=cap)
            except WorkloadCapacityError:
                with results_lock:
                    refusals.append(entry.key)
            else:
                with results_lock:
                    successes.append(entry.key)

        threads = [
            threading.Thread(target=worker, args=(index,)) for index in range(attempts)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(successes) == cap
        assert len(refusals) == attempts - cap
        assert ledger.count("challenge-x") == cap

    def test_concurrent_double_release_exactly_one_wins(self) -> None:
        ledger = WorkloadLedger()
        ledger.register(_entry("svc-1"))
        barrier = threading.Barrier(2)
        outcomes: list[bool] = []
        results_lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            released = ledger.release("svc-1")
            with results_lock:
                outcomes.append(released)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sorted(outcomes) == [False, True]
        assert ledger.count("challenge-x") == 0


class TestDeadlines:
    def test_deadline_is_started_at_plus_timeout(self) -> None:
        entry = _entry("svc-1", started_at=STARTED_AT, timeout_seconds=600)
        assert entry.deadline == STARTED_AT + timedelta(seconds=600)

    def test_service_class_never_has_deadline(self) -> None:
        entry = _entry(
            "svc-1",
            workload_class="service",
            started_at=STARTED_AT,
            timeout_seconds=600,
        )
        assert entry.deadline is None

    def test_no_timeout_means_no_deadline(self) -> None:
        entry = _entry("svc-1", started_at=STARTED_AT)
        assert entry.deadline is None

    def test_deadline_unknown_until_daemon_reports_started_at(self) -> None:
        ledger = WorkloadLedger()
        ledger.register(_entry("svc-1", timeout_seconds=600))
        assert ledger.deadline("svc-1") is None

        observed = ledger.observe_started_at("svc-1", STARTED_AT)
        assert observed is not None
        assert observed.started_at == STARTED_AT
        assert ledger.deadline("svc-1") == STARTED_AT + timedelta(seconds=600)

    def test_observe_started_at_keeps_first_daemon_report(self) -> None:
        ledger = WorkloadLedger()
        ledger.register(_entry("svc-1", started_at=STARTED_AT, timeout_seconds=60))
        later = STARTED_AT + timedelta(seconds=30)
        observed = ledger.observe_started_at("svc-1", later)
        assert observed is not None
        assert observed.started_at == STARTED_AT

    def test_observe_started_at_unknown_key_returns_none(self) -> None:
        ledger = WorkloadLedger()
        assert ledger.observe_started_at("missing", STARTED_AT) is None

    def test_deadline_for_unknown_key_is_none(self) -> None:
        ledger = WorkloadLedger()
        assert ledger.deadline("missing") is None

    def test_expired_returns_only_past_deadline_jobs(self) -> None:
        ledger = WorkloadLedger()
        ledger.register(_entry("svc-old", started_at=STARTED_AT, timeout_seconds=60))
        ledger.register(
            _entry("svc-fresh", started_at=STARTED_AT, timeout_seconds=3600)
        )
        ledger.register(
            _entry(
                "svc-longlived",
                workload_class="service",
                started_at=STARTED_AT,
                timeout_seconds=60,
            )
        )
        ledger.register(_entry("svc-unstarted", timeout_seconds=60))

        now = STARTED_AT + timedelta(seconds=120)
        expired_keys = {entry.key for entry in ledger.expired(now)}
        assert expired_keys == {"svc-old"}

    def test_expired_requires_aware_now(self) -> None:
        ledger = WorkloadLedger()
        with pytest.raises(WorkloadLedgerError):
            ledger.expired(datetime(2026, 6, 12, 10, 0, 0))


class TestReconstruct:
    def test_reconstruct_counts_across_multiple_daemons(self) -> None:
        """3 active services for challenge X spread over 2 daemons -> count==3."""

        daemon_validator = _FakeDaemon(
            [
                _entry("svc-1", started_at=STARTED_AT, timeout_seconds=600),
                _entry("svc-2", started_at=STARTED_AT, timeout_seconds=600),
            ]
        )
        daemon_worker = _FakeDaemon(
            [
                _entry("svc-3", started_at=STARTED_AT, timeout_seconds=600),
                _entry(
                    "ctr-deadbeef",
                    challenge_slug="challenge-y",
                    kind="escape_hatch_container",
                ),
            ]
        )

        ledger = WorkloadLedger()
        restored = ledger.reconstruct([daemon_validator, daemon_worker])

        assert restored == 4
        assert ledger.count("challenge-x") == 3
        assert ledger.count("challenge-y") == 1

    def test_reconstruct_replaces_stale_memory_state(self) -> None:
        ledger = WorkloadLedger()
        ledger.register(_entry("svc-stale"))
        ledger.reconstruct([_FakeDaemon([_entry("svc-real")])])
        assert ledger.get("svc-stale") is None
        assert ledger.get("svc-real") is not None
        assert ledger.count("challenge-x") == 1

    def test_reconstruct_prefers_entry_with_started_at_on_duplicate_key(self) -> None:
        without_start = _FakeDaemon([_entry("svc-1", timeout_seconds=600)])
        with_start = _FakeDaemon(
            [_entry("svc-1", started_at=STARTED_AT, timeout_seconds=600)]
        )

        ledger = WorkloadLedger()
        ledger.reconstruct([without_start, with_start])
        assert ledger.deadline("svc-1") == STARTED_AT + timedelta(seconds=600)
        assert ledger.count("challenge-x") == 1

        reversed_ledger = WorkloadLedger()
        reversed_ledger.reconstruct([with_start, without_start])
        assert reversed_ledger.deadline("svc-1") == STARTED_AT + timedelta(seconds=600)

    def test_reconstruct_preserves_deadlines_for_reaper(self) -> None:
        daemon = _FakeDaemon(
            [
                _entry("svc-expired", started_at=STARTED_AT, timeout_seconds=60),
                _entry(
                    "svc-prism",
                    workload_class="service",
                    started_at=STARTED_AT,
                ),
            ]
        )
        ledger = WorkloadLedger()
        ledger.reconstruct([daemon])

        now = STARTED_AT + timedelta(seconds=3600)
        assert {entry.key for entry in ledger.expired(now)} == {"svc-expired"}

    def test_entries_snapshot_is_detached(self) -> None:
        ledger = WorkloadLedger()
        ledger.register(_entry("svc-1"))
        snapshot = ledger.entries()
        ledger.release("svc-1")
        assert [entry.key for entry in snapshot] == ["svc-1"]
        assert ledger.entries() == ()
