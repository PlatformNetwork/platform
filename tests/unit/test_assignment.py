"""Behavioral tests for the random balanced capability-aware assignment engine.

Covers VAL-ASSIGN-001..009: balanced distribution across ONLINE validators,
offline exclusion, seeded deterministic tie-breaking, capability routing
(gpu->gpu, cpu->cpu, gpu-superset-of-cpu when configured), no-eligible ->
stays pending, agent-challenge fan-out, and prism single-unit semantics.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

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

NOW = datetime(2026, 6, 27, 12, 0, 0, tzinfo=UTC)


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
                last_heartbeat_at=NOW,
            )
        )


async def _rows(factory) -> list[WorkAssignment]:
    async with factory() as session:
        result = await session.execute(
            select(WorkAssignment).order_by(WorkAssignment.work_unit_id)
        )
        return list(result.scalars().all())


def _service(factory, **kwargs) -> AssignmentService:
    return AssignmentService(factory, now_fn=lambda: NOW, **kwargs)


# VAL-ASSIGN-008
async def test_agent_challenge_fans_out_one_unit_per_task_across_validators() -> None:
    engine, factory = await _setup()
    try:
        service = _service(factory)
        await _add_validator(factory, "v1", ["cpu"])
        await _add_validator(factory, "v2", ["cpu"])
        task_ids = [f"task-{i}" for i in range(6)]

        created = await service.create_agent_challenge_work_units(
            submission_id="sub-1",
            submission_ref="hk-abc",
            task_ids=task_ids,
        )
        assert len(created) == 6

        await service.assign_pending(seed=1)
        rows = await _rows(factory)

        assert len(rows) == 6
        assert {r.work_unit_id for r in rows} == {f"sub-1:{t}" for t in task_ids}
        assert all(r.required_capability == "cpu" for r in rows)
        assert all(r.status == WorkAssignmentStatus.ASSIGNED for r in rows)
        # Spread across more than one validator.
        assert len({r.assigned_validator_hotkey for r in rows}) > 1
    finally:
        await engine.dispose()


# VAL-ASSIGN-009
async def test_prism_creates_exactly_one_unit_on_one_validator() -> None:
    engine, factory = await _setup()
    try:
        service = _service(factory)
        await _add_validator(factory, "g1", ["cpu", "gpu"])
        await _add_validator(factory, "g2", ["cpu", "gpu"])

        await service.create_prism_work_unit(
            submission_id="psub-1", submission_ref="hk-p"
        )
        await service.assign_pending(seed=1)

        rows = await _rows(factory)
        assert len(rows) == 1
        assert rows[0].work_unit_id == "psub-1"
        assert rows[0].required_capability == "gpu"
        assert rows[0].status == WorkAssignmentStatus.ASSIGNED
        assert rows[0].assigned_validator_hotkey in {"g1", "g2"}
    finally:
        await engine.dispose()


async def test_prism_work_unit_creation_is_idempotent() -> None:
    engine, factory = await _setup()
    try:
        service = _service(factory)
        await _add_validator(factory, "g1", ["gpu"])

        first = await service.create_prism_work_unit(
            submission_id="psub-1", submission_ref="hk-p"
        )
        second = await service.create_prism_work_unit(
            submission_id="psub-1", submission_ref="hk-p"
        )
        assert first == second

        rows = await _rows(factory)
        assert len(rows) == 1
    finally:
        await engine.dispose()


async def test_agent_challenge_work_unit_creation_is_idempotent() -> None:
    engine, factory = await _setup()
    try:
        service = _service(factory)
        await _add_validator(factory, "v1", ["cpu"])

        first = await service.create_agent_challenge_work_units(
            submission_id="sub-1", submission_ref="hk", task_ids=["a", "b"]
        )
        second = await service.create_agent_challenge_work_units(
            submission_id="sub-1", submission_ref="hk", task_ids=["a", "b", "c"]
        )
        assert len(first) == 2
        # Only the new task creates a unit on the second call.
        assert second == ["sub-1:c"]

        rows = await _rows(factory)
        assert len(rows) == 3
    finally:
        await engine.dispose()


# VAL-ASSIGN-001
async def test_balanced_distribution_across_online_validators() -> None:
    engine, factory = await _setup()
    try:
        service = _service(factory)
        for hotkey in ("v1", "v2", "v3"):
            await _add_validator(factory, hotkey, ["cpu"])
        await service.create_agent_challenge_work_units(
            submission_id="sub-1",
            submission_ref="hk",
            task_ids=[f"task-{i}" for i in range(9)],
        )

        await service.assign_pending(seed=7)
        rows = await _rows(factory)

        counts = Counter(r.assigned_validator_hotkey for r in rows)
        assert sum(counts.values()) == 9
        # K=9 over M=3 -> exactly 3 each; counts differ by at most 1.
        assert max(counts.values()) - min(counts.values()) <= 1
        assert set(counts) == {"v1", "v2", "v3"}
    finally:
        await engine.dispose()


# VAL-ASSIGN-002
async def test_offline_validators_never_receive_work() -> None:
    engine, factory = await _setup()
    try:
        service = _service(factory)
        await _add_validator(factory, "online", ["cpu"])
        await _add_validator(
            factory, "offline", ["cpu"], status=ValidatorStatus.OFFLINE
        )
        await service.create_agent_challenge_work_units(
            submission_id="sub-1",
            submission_ref="hk",
            task_ids=[f"task-{i}" for i in range(4)],
        )

        await service.assign_pending(seed=3)
        rows = await _rows(factory)

        assert {r.assigned_validator_hotkey for r in rows} == {"online"}
        assert all(r.status == WorkAssignmentStatus.ASSIGNED for r in rows)
    finally:
        await engine.dispose()


async def test_no_validators_online_leaves_work_pending() -> None:
    engine, factory = await _setup()
    try:
        service = _service(factory)
        await _add_validator(
            factory, "offline", ["cpu"], status=ValidatorStatus.OFFLINE
        )
        await service.create_agent_challenge_work_units(
            submission_id="sub-1", submission_ref="hk", task_ids=["a", "b"]
        )

        mapping = await service.assign_pending(seed=1)
        assert mapping == {}

        rows = await _rows(factory)
        assert all(r.status == WorkAssignmentStatus.PENDING for r in rows)
        assert all(r.assigned_validator_hotkey is None for r in rows)
    finally:
        await engine.dispose()


# VAL-ASSIGN-003
async def test_seeded_tie_breaking_is_deterministic_and_seed_sensitive() -> None:
    async def run(seed: int) -> dict[str, str]:
        engine, factory = await _setup()
        try:
            service = _service(factory)
            for hotkey in ("v1", "v2", "v3"):
                await _add_validator(factory, hotkey, ["cpu"])
            await service.create_agent_challenge_work_units(
                submission_id="sub-1",
                submission_ref="hk",
                task_ids=[f"task-{i}" for i in range(6)],
            )
            return await service.assign_pending(seed=seed)
        finally:
            await engine.dispose()

    base = await run(1)
    again = await run(1)
    assert base == again  # identical seed + inputs => identical mapping

    differs = False
    for seed in range(2, 40):
        if await run(seed) != base:
            differs = True
            break
    assert differs  # changing the seed changes the mapping
    # Same set of work units regardless of seed.
    assert set(base) == {f"sub-1:task-{i}" for i in range(6)}
    assert set(base.values()) <= {"v1", "v2", "v3"}
    assert set(again) == set(base)


# VAL-ASSIGN-004
async def test_gpu_work_routed_only_to_gpu_validators() -> None:
    engine, factory = await _setup()
    try:
        service = _service(factory)
        await _add_validator(factory, "gpu1", ["cpu", "gpu"])
        await _add_validator(factory, "cpu1", ["cpu"])
        await service.create_prism_work_unit(
            submission_id="psub-1", submission_ref="hk"
        )

        await service.assign_pending(seed=5)
        rows = await _rows(factory)

        assert len(rows) == 1
        assert rows[0].assigned_validator_hotkey == "gpu1"
    finally:
        await engine.dispose()


# VAL-ASSIGN-005
async def test_cpu_work_routed_to_cpu_validators() -> None:
    engine, factory = await _setup()
    try:
        service = _service(factory)
        await _add_validator(factory, "cpu1", ["cpu"])
        await service.create_agent_challenge_work_units(
            submission_id="sub-1", submission_ref="hk", task_ids=["a", "b", "c"]
        )

        await service.assign_pending(seed=2)
        rows = await _rows(factory)

        assert all(r.assigned_validator_hotkey == "cpu1" for r in rows)
        assert all(r.status == WorkAssignmentStatus.ASSIGNED for r in rows)
    finally:
        await engine.dispose()


# VAL-ASSIGN-006
async def test_gpu_validators_take_cpu_work_when_configured() -> None:
    engine, factory = await _setup()
    try:
        service = _service(factory, gpu_serves_cpu=True)
        await _add_validator(factory, "gpu1", ["gpu"])  # no cpu-only validators
        await service.create_agent_challenge_work_units(
            submission_id="sub-1", submission_ref="hk", task_ids=["a", "b"]
        )

        await service.assign_pending(seed=1)
        rows = await _rows(factory)

        assert all(r.assigned_validator_hotkey == "gpu1" for r in rows)
        assert all(r.status == WorkAssignmentStatus.ASSIGNED for r in rows)
    finally:
        await engine.dispose()


async def test_gpu_validators_excluded_from_cpu_when_not_configured() -> None:
    engine, factory = await _setup()
    try:
        service = _service(factory, gpu_serves_cpu=False)
        await _add_validator(factory, "gpu1", ["gpu"])
        await service.create_agent_challenge_work_units(
            submission_id="sub-1", submission_ref="hk", task_ids=["a", "b"]
        )

        mapping = await service.assign_pending(seed=1)
        assert mapping == {}

        rows = await _rows(factory)
        assert all(r.status == WorkAssignmentStatus.PENDING for r in rows)
    finally:
        await engine.dispose()


# VAL-ASSIGN-007
async def test_no_eligible_validator_stays_pending_then_assigns_later() -> None:
    engine, factory = await _setup()
    try:
        service = _service(factory)
        await _add_validator(factory, "cpu1", ["cpu"])  # cannot serve gpu work
        await service.create_prism_work_unit(
            submission_id="psub-1", submission_ref="hk"
        )

        await service.assign_pending(seed=1)
        rows = await _rows(factory)
        assert rows[0].status == WorkAssignmentStatus.PENDING
        assert rows[0].assigned_validator_hotkey is None

        # A gpu-capable validator comes online; the unit assigns on a later pass.
        await _add_validator(factory, "gpu1", ["cpu", "gpu"])
        await service.assign_pending(seed=1)

        rows = await _rows(factory)
        assert rows[0].status == WorkAssignmentStatus.ASSIGNED
        assert rows[0].assigned_validator_hotkey == "gpu1"
    finally:
        await engine.dispose()


async def test_initial_assignment_sets_attempt_count_to_one() -> None:
    engine, factory = await _setup()
    try:
        service = _service(factory)
        await _add_validator(factory, "v1", ["cpu"])
        await service.create_agent_challenge_work_units(
            submission_id="sub-1", submission_ref="hk", task_ids=["a"]
        )

        rows = await _rows(factory)
        assert rows[0].attempt_count == 0  # not yet assigned

        await service.assign_pending(seed=1)
        rows = await _rows(factory)
        assert rows[0].attempt_count == 1
    finally:
        await engine.dispose()


async def test_balance_accounts_for_existing_load_across_passes() -> None:
    engine, factory = await _setup()
    try:
        service = _service(factory)
        await _add_validator(factory, "v1", ["cpu"])
        await _add_validator(factory, "v2", ["cpu"])

        await service.create_agent_challenge_work_units(
            submission_id="sub-1", submission_ref="hk", task_ids=["a", "b"]
        )
        await service.assign_pending(seed=1)

        # A second batch is balanced against the in-flight load from pass one.
        await service.create_agent_challenge_work_units(
            submission_id="sub-2", submission_ref="hk", task_ids=["c", "d"]
        )
        await service.assign_pending(seed=1)

        rows = await _rows(factory)
        counts = Counter(r.assigned_validator_hotkey for r in rows)
        assert counts == Counter({"v1": 2, "v2": 2})
    finally:
        await engine.dispose()


async def test_generic_required_capability_matches_validator_capability() -> None:
    engine, factory = await _setup()
    try:
        service = _service(factory)
        await _add_validator(factory, "tpu1", ["tpu"])
        async with session_scope(factory) as session:
            session.add(
                WorkAssignment(
                    challenge_slug="custom",
                    work_unit_id="cu-1",
                    submission_ref="hk",
                    payload={},
                    required_capability="tpu",
                    status=WorkAssignmentStatus.PENDING,
                    attempt_count=0,
                    max_attempts=3,
                )
            )

        await service.assign_pending(seed=1)
        rows = await _rows(factory)
        assert rows[0].assigned_validator_hotkey == "tpu1"
        assert rows[0].status == WorkAssignmentStatus.ASSIGNED
    finally:
        await engine.dispose()


async def test_prism_concurrency_one_per_validator() -> None:
    engine, factory = await _setup()
    try:
        service = _service(factory)
        await _add_validator(factory, "gpu1", ["gpu"])
        await service.create_prism_work_unit(
            submission_id="psub-1", submission_ref="hk1"
        )
        await service.create_prism_work_unit(
            submission_id="psub-2", submission_ref="hk2"
        )

        await service.assign_pending(seed=1)
        rows = await _rows(factory)

        assigned = [r for r in rows if r.status == WorkAssignmentStatus.ASSIGNED]
        pending = [r for r in rows if r.status == WorkAssignmentStatus.PENDING]
        # Only one prism unit may run on the single gpu validator at a time.
        assert len(assigned) == 1
        assert len(pending) == 1
    finally:
        await engine.dispose()
