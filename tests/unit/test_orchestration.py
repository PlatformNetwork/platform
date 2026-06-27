"""Behavioral tests for the live master orchestration driver.

Covers the M6 master-orchestration-driver feature (architecture.md sec 4): the
driver bridges challenge pending work units into ``work_assignments``, runs the
balanced assignment + full reassignment pass live, and folds retry-exhausted
agent-challenge units back into their EvaluationJob via the challenge-side
trigger. The challenge work source + fold trigger are mocked here.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from base.db import (
    Base,
    Validator,
    ValidatorStatus,
    create_engine,
    create_session_factory,
    session_scope,
)
from base.db.models import WorkAssignment, WorkAssignmentStatus
from base.master.assignment import AssignmentService
from base.master.orchestration import (
    WORK_UNIT_MAX_ATTEMPTS_REASON,
    ChallengePendingWork,
    MasterOrchestrationDriver,
    build_master_orchestration_lifespan,
    run_orchestration_loop,
)
from base.master.validator_coordination import ValidatorCoordinationService

NOW = datetime(2026, 6, 27, 12, 0, 0, tzinfo=UTC)
LATER = NOW + timedelta(seconds=1000)


class _Clock:
    """A mutable, callable clock so a single pass can advance time."""

    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


async def _setup():
    engine = create_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = create_session_factory(engine)
    return engine, factory


async def _add_validator(
    factory,
    hotkey: str,
    capabilities: list[str],
    *,
    status: ValidatorStatus = ValidatorStatus.ONLINE,
    last_heartbeat_at: datetime = NOW,
) -> None:
    async with session_scope(factory) as session:
        session.add(
            Validator(
                hotkey=hotkey,
                uid=None,
                status=status,
                capabilities=list(capabilities),
                version="1.0.0",
                registered_at=NOW,
                last_heartbeat_at=last_heartbeat_at,
            )
        )


async def _set_status(factory, hotkey: str, status: ValidatorStatus) -> None:
    async with session_scope(factory) as session:
        validator = (
            await session.execute(select(Validator).where(Validator.hotkey == hotkey))
        ).scalar_one()
        validator.status = status


async def _rows(factory) -> list[WorkAssignment]:
    async with factory() as session:
        result = await session.execute(
            select(WorkAssignment).order_by(WorkAssignment.work_unit_id)
        )
        return list(result.scalars().all())


@dataclass
class FakeWorkSource:
    """A mocked :class:`ChallengeWorkSource` returning a fixed pending set."""

    works: list[ChallengePendingWork] = field(default_factory=list)
    calls: int = 0

    async def fetch_pending_work(self) -> list[ChallengePendingWork]:
        self.calls += 1
        return list(self.works)


@dataclass
class FakeFoldTrigger:
    """Records fold calls; optionally raises to exercise the failure path."""

    raises: bool = False
    calls: list[tuple[str, str, str, str]] = field(default_factory=list)

    async def fold(
        self, *, challenge_slug: str, job_id: str, task_id: str, reason: str
    ) -> None:
        self.calls.append((challenge_slug, job_id, task_id, reason))
        if self.raises:
            raise RuntimeError("challenge unreachable")


def _agent_work() -> ChallengePendingWork:
    return ChallengePendingWork(
        challenge_slug="agent-challenge",
        submission_id="7",
        submission_ref="miner-hk",
        task_ids=("t1", "t2"),
        job_id="job-abc",
    )


def _prism_work() -> ChallengePendingWork:
    return ChallengePendingWork(
        challenge_slug="prism",
        submission_id="psub-1",
        submission_ref="miner-hk-p",
        checkpoint_ref="hf://ckpt/step-3",
    )


# --------------------------------------------------------------------------- #
# Bridging challenge pending work into work_assignments
# --------------------------------------------------------------------------- #
async def test_bridge_creates_agent_and_prism_units_with_payload() -> None:
    engine, factory = await _setup()
    try:
        service = AssignmentService(factory, now_fn=lambda: NOW)
        validators = ValidatorCoordinationService(factory, now_fn=lambda: NOW)
        source = FakeWorkSource(works=[_agent_work(), _prism_work()])
        driver = MasterOrchestrationDriver(
            assignment_service=service,
            validator_service=validators,
            work_source=source,
        )

        bridged = await driver.bridge_pending_work()
        assert set(bridged["agent-challenge"]) == {"7:t1", "7:t2"}
        assert bridged["prism"] == ["psub-1"]

        rows = await _rows(factory)
        by_id = {r.work_unit_id: r for r in rows}
        # agent-challenge: one cpu unit per task, payload carries job_id + task_id.
        assert by_id["7:t1"].required_capability == "cpu"
        assert by_id["7:t1"].payload["job_id"] == "job-abc"
        assert by_id["7:t1"].payload["task_id"] == "t1"
        assert by_id["7:t2"].payload["task_id"] == "t2"
        # prism: exactly one gpu unit, resume checkpoint preserved.
        assert by_id["psub-1"].required_capability == "gpu"
        assert by_id["psub-1"].checkpoint_ref == "hf://ckpt/step-3"
    finally:
        await engine.dispose()


async def test_bridge_is_idempotent_across_passes() -> None:
    engine, factory = await _setup()
    try:
        service = AssignmentService(factory, now_fn=lambda: NOW)
        validators = ValidatorCoordinationService(factory, now_fn=lambda: NOW)
        source = FakeWorkSource(works=[_agent_work()])
        driver = MasterOrchestrationDriver(
            assignment_service=service,
            validator_service=validators,
            work_source=source,
        )

        await driver.bridge_pending_work()
        second = await driver.bridge_pending_work()
        # Re-bridging an already-present submission creates nothing new.
        assert second == {}
        assert len(await _rows(factory)) == 2
    finally:
        await engine.dispose()


# --------------------------------------------------------------------------- #
# run_once: bridge + balanced assignment without a manual trigger
# --------------------------------------------------------------------------- #
async def test_run_once_bridges_and_assigns_to_online_validators() -> None:
    engine, factory = await _setup()
    try:
        service = AssignmentService(factory, now_fn=lambda: NOW)
        validators = ValidatorCoordinationService(factory, now_fn=lambda: NOW)
        await _add_validator(factory, "v1", ["cpu"])
        await _add_validator(factory, "v2", ["cpu"])
        source = FakeWorkSource(works=[_agent_work()])
        driver = MasterOrchestrationDriver(
            assignment_service=service,
            validator_service=validators,
            work_source=source,
            seed=1,
        )

        result = await driver.run_once()
        assert set(result.reassignment.assigned) == {"7:t1", "7:t2"}
        rows = await _rows(factory)
        assert all(r.status == WorkAssignmentStatus.ASSIGNED for r in rows)
        # Two tasks split across two online validators (balanced).
        assert {r.assigned_validator_hotkey for r in rows} == {"v1", "v2"}
        assert result.folded == []
    finally:
        await engine.dispose()


async def test_run_once_assigns_newly_online_validator_next_pass() -> None:
    engine, factory = await _setup()
    try:
        service = AssignmentService(factory, now_fn=lambda: NOW)
        validators = ValidatorCoordinationService(factory, now_fn=lambda: NOW)
        source = FakeWorkSource(works=[_agent_work()])
        driver = MasterOrchestrationDriver(
            assignment_service=service,
            validator_service=validators,
            work_source=source,
            seed=1,
        )

        # No validators online yet: work is bridged but stays pending.
        await driver.run_once()
        rows = await _rows(factory)
        assert all(r.status == WorkAssignmentStatus.PENDING for r in rows)

        # A validator comes online; the next pass assigns without manual trigger.
        await _add_validator(factory, "v1", ["cpu"])
        await driver.run_once()
        rows = await _rows(factory)
        assert all(r.status == WorkAssignmentStatus.ASSIGNED for r in rows)
        assert all(r.assigned_validator_hotkey == "v1" for r in rows)
    finally:
        await engine.dispose()


# --------------------------------------------------------------------------- #
# run_once: full reassignment pass runs live
# --------------------------------------------------------------------------- #
async def test_run_once_reassigns_crashed_validator_work() -> None:
    engine, factory = await _setup()
    try:
        clock = _Clock(NOW)
        service = AssignmentService(factory, now_fn=clock)
        validators = ValidatorCoordinationService(
            factory, heartbeat_timeout_seconds=180, now_fn=clock
        )
        await _add_validator(factory, "v1", ["cpu"], last_heartbeat_at=NOW)
        source = FakeWorkSource(works=[_agent_work()])
        driver = MasterOrchestrationDriver(
            assignment_service=service,
            validator_service=validators,
            work_source=source,
            seed=1,
        )

        # Pass 1 at NOW: v1 is fresh and receives the bridged work.
        await driver.run_once()
        rows = await _rows(factory)
        assert all(r.status == WorkAssignmentStatus.ASSIGNED for r in rows)
        assert all(r.assigned_validator_hotkey == "v1" for r in rows)

        # Time advances past the heartbeat timeout; v2 registers fresh.
        clock.value = LATER
        await _add_validator(factory, "v2", ["cpu"], last_heartbeat_at=LATER)

        # Pass 2: v1 is detected offline, its work reverts and reassigns to v2.
        result = await driver.run_once()

        assert "v1" in result.reassignment.offline
        rows = await _rows(factory)
        assert all(r.status == WorkAssignmentStatus.ASSIGNED for r in rows)
        assert all(r.assigned_validator_hotkey == "v2" for r in rows)
        assert all(r.attempt_count == 2 for r in rows)
    finally:
        await engine.dispose()


# --------------------------------------------------------------------------- #
# run_once: retry-exhausted agent-challenge units are folded on the challenge
# --------------------------------------------------------------------------- #
async def test_run_once_folds_retry_exhausted_agent_unit() -> None:
    engine, factory = await _setup()
    try:
        service = AssignmentService(factory, now_fn=lambda: NOW, default_max_attempts=1)
        validators = ValidatorCoordinationService(factory, now_fn=lambda: NOW)
        await _add_validator(factory, "v1", ["cpu"])
        source = FakeWorkSource(
            works=[
                ChallengePendingWork(
                    challenge_slug="agent-challenge",
                    submission_id="7",
                    submission_ref="hk",
                    task_ids=("t1",),
                    job_id="job-abc",
                )
            ]
        )
        fold = FakeFoldTrigger()
        driver = MasterOrchestrationDriver(
            assignment_service=service,
            validator_service=validators,
            work_source=source,
            fold_trigger=fold,
            seed=1,
        )

        # Pass 1: bridge + assign (attempt_count == 1, max_attempts == 1).
        first = await driver.run_once()
        assert first.folded == []
        assert fold.calls == []

        # v1 crashes; pass 2 reclaims -> retries exhausted -> failed -> folded.
        await _set_status(factory, "v1", ValidatorStatus.OFFLINE)
        second = await driver.run_once()
        assert second.reassignment.failed == ["7:t1"]
        assert second.folded == ["7:t1"]
        assert fold.calls == [
            ("agent-challenge", "job-abc", "t1", WORK_UNIT_MAX_ATTEMPTS_REASON)
        ]

        row = (await _rows(factory))[0]
        assert row.status == WorkAssignmentStatus.FAILED

        # Pass 3 does not re-fold an already-terminal unit.
        await _set_status(factory, "v1", ValidatorStatus.ONLINE)
        third = await driver.run_once()
        assert third.folded == []
        assert len(fold.calls) == 1
    finally:
        await engine.dispose()


async def test_fold_trigger_failure_does_not_crash_pass() -> None:
    engine, factory = await _setup()
    try:
        service = AssignmentService(factory, now_fn=lambda: NOW, default_max_attempts=1)
        validators = ValidatorCoordinationService(factory, now_fn=lambda: NOW)
        await _add_validator(factory, "v1", ["cpu"])
        source = FakeWorkSource(
            works=[
                ChallengePendingWork(
                    challenge_slug="agent-challenge",
                    submission_id="7",
                    submission_ref="hk",
                    task_ids=("t1",),
                    job_id="job-abc",
                )
            ]
        )
        fold = FakeFoldTrigger(raises=True)
        driver = MasterOrchestrationDriver(
            assignment_service=service,
            validator_service=validators,
            work_source=source,
            fold_trigger=fold,
            seed=1,
        )

        await driver.run_once()
        await _set_status(factory, "v1", ValidatorStatus.OFFLINE)
        result = await driver.run_once()
        # The fold was attempted but failed; the pass still completes and the
        # unit stays failed (it is re-folded on a later pass, idempotently).
        assert result.reassignment.failed == ["7:t1"]
        assert result.folded == []
        assert len(fold.calls) == 1
    finally:
        await engine.dispose()


async def test_failed_fold_is_durably_retried_on_a_later_pass() -> None:
    engine, factory = await _setup()
    try:
        service = AssignmentService(factory, now_fn=lambda: NOW, default_max_attempts=1)
        validators = ValidatorCoordinationService(factory, now_fn=lambda: NOW)
        await _add_validator(factory, "v1", ["cpu"])
        source = FakeWorkSource(
            works=[
                ChallengePendingWork(
                    challenge_slug="agent-challenge",
                    submission_id="7",
                    submission_ref="hk",
                    task_ids=("t1",),
                    job_id="job-abc",
                )
            ]
        )
        # The challenge is unreachable (fold POST fails) during the first attempt.
        fold = FakeFoldTrigger(raises=True)
        driver = MasterOrchestrationDriver(
            assignment_service=service,
            validator_service=validators,
            work_source=source,
            fold_trigger=fold,
            seed=1,
        )

        # Pass 1: bridge + assign (attempt 1, max 1).
        await driver.run_once()

        # v1 crashes; pass 2 fails the unit, but the fold POST fails (outage).
        await _set_status(factory, "v1", ValidatorStatus.OFFLINE)
        second = await driver.run_once()
        assert second.reassignment.failed == ["7:t1"]
        assert second.folded == []  # fold attempted but the challenge was down
        assert len(fold.calls) == 1

        # The challenge recovers. A later pass durably re-folds the still-failed
        # unit even though it did NOT newly fail this pass.
        fold.raises = False
        third = await driver.run_once()
        assert third.reassignment.failed == []  # not newly failed this pass
        assert third.folded == ["7:t1"]
        assert len(fold.calls) == 2

        # Once folded, the sweep does not fold it again.
        fourth = await driver.run_once()
        assert fourth.folded == []
        assert len(fold.calls) == 2
    finally:
        await engine.dispose()


async def test_prism_failed_unit_is_not_folded() -> None:
    engine, factory = await _setup()
    try:
        service = AssignmentService(factory, now_fn=lambda: NOW, default_max_attempts=1)
        validators = ValidatorCoordinationService(factory, now_fn=lambda: NOW)
        await _add_validator(factory, "g1", ["gpu"])
        source = FakeWorkSource(works=[_prism_work()])
        fold = FakeFoldTrigger()
        driver = MasterOrchestrationDriver(
            assignment_service=service,
            validator_service=validators,
            work_source=source,
            fold_trigger=fold,
            seed=1,
        )

        await driver.run_once()
        await _set_status(factory, "g1", ValidatorStatus.OFFLINE)
        result = await driver.run_once()
        assert result.reassignment.failed == ["psub-1"]
        # prism has no fold seam: a failed gpu unit is never folded.
        assert result.folded == []
        assert fold.calls == []
    finally:
        await engine.dispose()


# --------------------------------------------------------------------------- #
# Live loop + lifespan wiring
# --------------------------------------------------------------------------- #
async def test_run_orchestration_loop_runs_then_stops() -> None:
    engine, factory = await _setup()
    try:
        service = AssignmentService(factory, now_fn=lambda: NOW)
        validators = ValidatorCoordinationService(factory, now_fn=lambda: NOW)
        await _add_validator(factory, "v1", ["cpu"])
        source = FakeWorkSource(works=[_agent_work()])
        driver = MasterOrchestrationDriver(
            assignment_service=service,
            validator_service=validators,
            work_source=source,
            seed=1,
        )
        shutdown = asyncio.Event()
        task = asyncio.create_task(
            run_orchestration_loop(
                driver, interval_seconds=0.01, shutdown_event=shutdown
            )
        )
        # Let at least one pass run, then stop the loop.
        for _ in range(200):
            await asyncio.sleep(0.005)
            if source.calls >= 1:
                break
        shutdown.set()
        await asyncio.wait_for(task, timeout=2.0)

        assert source.calls >= 1
        rows = await _rows(factory)
        assert rows and all(r.status == WorkAssignmentStatus.ASSIGNED for r in rows)
    finally:
        await engine.dispose()


def test_lifespan_is_none_when_disabled() -> None:
    assert build_master_orchestration_lifespan(None, 30.0) is None
    # A configured driver but a non-positive interval also disables the loop.
    dummy = object()
    assert build_master_orchestration_lifespan(dummy, 0) is None  # type: ignore[arg-type]
    assert build_master_orchestration_lifespan(dummy, None) is None  # type: ignore[arg-type]
