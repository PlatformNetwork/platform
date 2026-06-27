"""Behavioral tests for crash/deadline reassignment of work units.

Covers VAL-ASSIGN-023..028: heartbeat-timeout offline + crash_detected drives a
reassignment pass; a crashed validator's running/assigned work reverts to
pending and reassigns to a different online validator; past-deadline leases are
reclaimed even before the validator is marked offline; reassignment increments
``attempt_count`` by exactly 1 per cycle; prism reassignment carries the last
``checkpoint_ref`` into the new validator's pull payload; and retries are bounded
by ``max_attempts`` (exhausted -> failed, no infinite loop).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from base.db import (
    Base,
    Validator,
    ValidatorHealthEvent,
    ValidatorHealthEventType,
    ValidatorStatus,
    create_engine,
    create_session_factory,
    session_scope,
)
from base.db.models import WorkAssignment, WorkAssignmentStatus
from base.master.assignment import (
    RESUME_CHECKPOINT_PAYLOAD_KEY,
    AssignmentService,
)
from base.master.assignment_coordination import AssignmentCoordinationService
from base.master.reassignment import run_reassignment_pass
from base.master.validator_coordination import ValidatorCoordinationService

NOW = datetime(2026, 6, 27, 12, 0, 0, tzinfo=UTC)
LATER = NOW + timedelta(seconds=1000)


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


async def _one(factory) -> WorkAssignment:
    rows = await _rows(factory)
    assert len(rows) == 1
    return rows[0]


# VAL-ASSIGN-024
async def test_offline_validator_work_reverts_and_reassigns() -> None:
    engine, factory = await _setup()
    try:
        service = AssignmentService(factory, now_fn=lambda: NOW)
        await _add_validator(factory, "v1", ["cpu"])
        await service.create_agent_challenge_work_units(
            submission_id="sub-1", submission_ref="hk", task_ids=["a", "b"]
        )
        await service.assign_pending(seed=1)

        coordination = AssignmentCoordinationService(factory, now_fn=lambda: NOW)
        await coordination.pull(hotkey="v1")  # assigned -> running
        rows = await _rows(factory)
        assert all(r.status == WorkAssignmentStatus.RUNNING for r in rows)
        assert all(r.assigned_validator_hotkey == "v1" for r in rows)

        # v1 crashes; v2 comes online to take over.
        await _set_status(factory, "v1", ValidatorStatus.OFFLINE)
        await _add_validator(factory, "v2", ["cpu"])

        outcome = await service.reclaim_stale_assignments()
        assert set(outcome.reverted) == {"sub-1:a", "sub-1:b"}
        rows = await _rows(factory)
        assert all(r.status == WorkAssignmentStatus.PENDING for r in rows)
        assert all(r.assigned_validator_hotkey is None for r in rows)

        await service.assign_pending(seed=1)
        rows = await _rows(factory)
        assert all(r.status == WorkAssignmentStatus.ASSIGNED for r in rows)
        assert all(r.assigned_validator_hotkey == "v2" for r in rows)
    finally:
        await engine.dispose()


async def test_healthy_inflight_work_is_not_reclaimed() -> None:
    engine, factory = await _setup()
    try:
        service = AssignmentService(factory, now_fn=lambda: NOW)
        await _add_validator(factory, "v1", ["cpu"])
        await service.create_agent_challenge_work_units(
            submission_id="sub-1", submission_ref="hk", task_ids=["a"]
        )
        await service.assign_pending(seed=1)
        coordination = AssignmentCoordinationService(factory, now_fn=lambda: NOW)
        await coordination.pull(hotkey="v1")

        outcome = await service.reclaim_stale_assignments()
        assert outcome.reverted == []
        assert outcome.failed == []
        row = await _one(factory)
        assert row.status == WorkAssignmentStatus.RUNNING
        assert row.assigned_validator_hotkey == "v1"
    finally:
        await engine.dispose()


# VAL-ASSIGN-025
async def test_past_deadline_unit_is_reclaimed_even_if_validator_online() -> None:
    engine, factory = await _setup()
    try:
        # Lease expires between the pull (NOW) and the reclaim (LATER).
        service = AssignmentService(factory, now_fn=lambda: LATER)
        await _add_validator(factory, "v1", ["cpu"])
        await _add_validator(factory, "v2", ["cpu"])
        await service.create_agent_challenge_work_units(
            submission_id="sub-1", submission_ref="hk", task_ids=["a"]
        )
        # Assign to v1 only (v2 added after) by pinning the pool.
        await _set_status(factory, "v2", ValidatorStatus.OFFLINE)
        await service.assign_pending(seed=1)
        await _set_status(factory, "v2", ValidatorStatus.ONLINE)

        coordination = AssignmentCoordinationService(
            factory, lease_seconds=10, now_fn=lambda: NOW
        )
        await coordination.pull(hotkey="v1")  # deadline = NOW + 10s, < LATER
        row = await _one(factory)
        assert row.status == WorkAssignmentStatus.RUNNING
        assert row.deadline_at is not None

        # v1 is still online, but its lease has expired -> reclaimed.
        outcome = await service.reclaim_stale_assignments()
        assert outcome.reverted == ["sub-1:a"]
        row = await _one(factory)
        assert row.status == WorkAssignmentStatus.PENDING
        assert row.assigned_validator_hotkey is None
        assert row.deadline_at is None

        await service.assign_pending(seed=1)
        row = await _one(factory)
        assert row.status == WorkAssignmentStatus.ASSIGNED
    finally:
        await engine.dispose()


# VAL-ASSIGN-026
async def test_reassignment_increments_attempt_count_by_one_per_cycle() -> None:
    engine, factory = await _setup()
    try:
        service = AssignmentService(factory, now_fn=lambda: NOW)
        await _add_validator(factory, "v1", ["cpu"])
        await _add_validator(factory, "v2", ["cpu"])
        await service.create_agent_challenge_work_units(
            submission_id="sub-1", submission_ref="hk", task_ids=["a"]
        )

        await service.assign_pending(seed=1)
        row = await _one(factory)
        assert row.attempt_count == 1  # initial assignment

        for expected in (2, 3):
            before = (await _one(factory)).attempt_count
            # The owner crashes; reclaim reverts, reassign increments by one.
            await _set_status(factory, "v1", ValidatorStatus.OFFLINE)
            await _set_status(factory, "v2", ValidatorStatus.OFFLINE)
            await service.reclaim_stale_assignments()
            await _set_status(factory, "v1", ValidatorStatus.ONLINE)
            await _set_status(factory, "v2", ValidatorStatus.ONLINE)
            await service.assign_pending(seed=1)
            row = await _one(factory)
            assert row.attempt_count == before + 1 == expected
    finally:
        await engine.dispose()


# VAL-ASSIGN-027
async def test_prism_reassignment_carries_checkpoint_ref_into_pull_payload() -> None:
    engine, factory = await _setup()
    try:
        service = AssignmentService(factory, now_fn=lambda: NOW)
        await _add_validator(factory, "g1", ["gpu"])
        await service.create_prism_work_unit(
            submission_id="psub-1", submission_ref="hk-p"
        )
        await service.assign_pending(seed=1)

        coordination = AssignmentCoordinationService(factory, now_fn=lambda: NOW)
        pulled = await coordination.pull(hotkey="g1")
        assignment_id = str(pulled[0].id)
        await coordination.progress(
            assignment_id=assignment_id,
            hotkey="g1",
            checkpoint_ref="hf://ckpt/step-5",
        )

        # g1 crashes; g2 takes over the resumed run.
        await _set_status(factory, "g1", ValidatorStatus.OFFLINE)
        await _add_validator(factory, "g2", ["gpu"])

        outcome = await service.reclaim_stale_assignments()
        assert outcome.reverted == ["psub-1"]
        row = await _one(factory)
        assert row.checkpoint_ref == "hf://ckpt/step-5"  # preserved on revert
        assert row.payload[RESUME_CHECKPOINT_PAYLOAD_KEY] == "hf://ckpt/step-5"

        await service.assign_pending(seed=1)
        row = await _one(factory)
        assert row.assigned_validator_hotkey == "g2"

        resumed = await coordination.pull(hotkey="g2")
        assert len(resumed) == 1
        view = resumed[0]
        assert view.checkpoint_ref == "hf://ckpt/step-5"
        assert view.payload[RESUME_CHECKPOINT_PAYLOAD_KEY] == "hf://ckpt/step-5"
    finally:
        await engine.dispose()


# VAL-ASSIGN-028
async def test_max_attempts_bounds_reassignment_then_fails() -> None:
    engine, factory = await _setup()
    try:
        service = AssignmentService(factory, now_fn=lambda: NOW, default_max_attempts=2)
        await _add_validator(factory, "v1", ["cpu"])
        await service.create_agent_challenge_work_units(
            submission_id="sub-1", submission_ref="hk", task_ids=["a"]
        )

        # Attempt 1.
        await service.assign_pending(seed=1)
        assert (await _one(factory)).attempt_count == 1

        # Crash -> reclaim reverts (1 < 2) -> reassign attempt 2.
        await _set_status(factory, "v1", ValidatorStatus.OFFLINE)
        outcome = await service.reclaim_stale_assignments()
        assert outcome.reverted == ["sub-1:a"]
        assert outcome.failed == []
        await _set_status(factory, "v1", ValidatorStatus.ONLINE)
        await service.assign_pending(seed=1)
        assert (await _one(factory)).attempt_count == 2

        # Crash again -> retries exhausted (2 >= 2) -> terminally failed.
        await _set_status(factory, "v1", ValidatorStatus.OFFLINE)
        outcome = await service.reclaim_stale_assignments()
        assert outcome.reverted == []
        assert outcome.failed == ["sub-1:a"]
        row = await _one(factory)
        assert row.status == WorkAssignmentStatus.FAILED
        assert row.attempt_count == 2

        # No further assignment in later passes (no infinite loop).
        await _set_status(factory, "v1", ValidatorStatus.ONLINE)
        again = await service.reclaim_stale_assignments()
        assert again.reverted == [] and again.failed == []
        await service.assign_pending(seed=1)
        row = await _one(factory)
        assert row.status == WorkAssignmentStatus.FAILED
    finally:
        await engine.dispose()


# VAL-ASSIGN-023 + 024 end-to-end via the orchestration pass
async def test_run_reassignment_pass_detects_crash_and_reassigns() -> None:
    engine, factory = await _setup()
    try:
        assignment_service = AssignmentService(factory, now_fn=lambda: LATER)
        validator_service = ValidatorCoordinationService(
            factory, heartbeat_timeout_seconds=180, now_fn=lambda: LATER
        )

        # v1 last heartbeat at NOW (stale relative to LATER) -> will be detected.
        await _add_validator(factory, "v1", ["cpu"], last_heartbeat_at=NOW)
        await assignment_service.create_agent_challenge_work_units(
            submission_id="sub-1", submission_ref="hk", task_ids=["a", "b"]
        )
        await assignment_service.assign_pending(seed=1)
        coordination = AssignmentCoordinationService(factory, now_fn=lambda: NOW)
        await coordination.pull(hotkey="v1")

        # v2 heartbeats fresh at LATER -> stays online and takes over.
        await _add_validator(factory, "v2", ["cpu"], last_heartbeat_at=LATER)

        result = await run_reassignment_pass(
            validator_service=validator_service,
            assignment_service=assignment_service,
            seed=1,
        )

        assert result.offline == ["v1"]
        assert set(result.reverted) == {"sub-1:a", "sub-1:b"}
        assert set(result.assigned) == {"sub-1:a", "sub-1:b"}
        assert set(result.assigned.values()) == {"v2"}

        # v1 went offline with a crash_detected event (VAL-ASSIGN-023).
        async with factory() as session:
            v1 = (
                await session.execute(select(Validator).where(Validator.hotkey == "v1"))
            ).scalar_one()
            assert v1.status == ValidatorStatus.OFFLINE
            events = (
                (
                    await session.execute(
                        select(ValidatorHealthEvent).where(
                            ValidatorHealthEvent.validator_hotkey == "v1",
                            ValidatorHealthEvent.event
                            == ValidatorHealthEventType.CRASH_DETECTED,
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert len(events) == 1

        rows = await _rows(factory)
        assert all(r.status == WorkAssignmentStatus.ASSIGNED for r in rows)
        assert all(r.assigned_validator_hotkey == "v2" for r in rows)
        assert all(r.attempt_count == 2 for r in rows)
    finally:
        await engine.dispose()


# The full pass (detect -> reclaim -> assign) is one atomic transaction.
async def test_run_reassignment_pass_rolls_back_atomically_on_failure() -> None:
    engine, factory = await _setup()
    try:
        assignment_service = AssignmentService(factory, now_fn=lambda: LATER)
        validator_service = ValidatorCoordinationService(
            factory, heartbeat_timeout_seconds=180, now_fn=lambda: LATER
        )
        # v1 is stale (heartbeat at NOW, evaluated at LATER) and holds running work.
        await _add_validator(factory, "v1", ["cpu"], last_heartbeat_at=NOW)
        await assignment_service.create_agent_challenge_work_units(
            submission_id="sub-1", submission_ref="hk", task_ids=["a"]
        )
        await assignment_service.assign_pending(seed=1)
        coordination = AssignmentCoordinationService(factory, now_fn=lambda: NOW)
        await coordination.pull(hotkey="v1")  # assigned -> running

        # The assign step blows up mid-pass; the whole transaction must roll back.
        async def _boom(**_: object) -> dict[str, str]:
            raise RuntimeError("assign failed")

        assignment_service.assign_pending = _boom  # type: ignore[method-assign]

        with pytest.raises(RuntimeError):
            await run_reassignment_pass(
                validator_service=validator_service,
                assignment_service=assignment_service,
                seed=1,
            )

        # Detect's offline flip and reclaim's revert both rolled back.
        async with factory() as session:
            v1 = (
                await session.execute(select(Validator).where(Validator.hotkey == "v1"))
            ).scalar_one()
            assert v1.status == ValidatorStatus.ONLINE
            crash_events = (
                (
                    await session.execute(
                        select(ValidatorHealthEvent).where(
                            ValidatorHealthEvent.validator_hotkey == "v1",
                            ValidatorHealthEvent.event
                            == ValidatorHealthEventType.CRASH_DETECTED,
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert crash_events == []
        row = await _one(factory)
        assert row.status == WorkAssignmentStatus.RUNNING
        assert row.assigned_validator_hotkey == "v1"
    finally:
        await engine.dispose()
