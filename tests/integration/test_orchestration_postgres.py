"""Postgres parity for the live master orchestration driver.

Mirrors the SQLite unit behavior of :class:`MasterOrchestrationDriver` (bridge
challenge pending work -> balanced assign -> crash reclaim/reassign -> fold
retry-exhausted units) against the throwaway Postgres at 127.0.0.1:15490,
confirming the driver bridges, assigns, reassigns, and folds identically across
backends (VAL-ASSIGN-029).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from base.db import (
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
)
from base.master.validator_coordination import ValidatorCoordinationService

pytestmark = pytest.mark.postgres

NOW = datetime(2026, 6, 27, 12, 0, 0, tzinfo=UTC)


@dataclass
class FakeWorkSource:
    works: list[ChallengePendingWork] = field(default_factory=list)

    async def fetch_pending_work(self) -> list[ChallengePendingWork]:
        return list(self.works)


@dataclass
class FakeFoldTrigger:
    calls: list[tuple[str, str, str, str]] = field(default_factory=list)

    async def fold(
        self, *, challenge_slug: str, job_id: str, task_id: str, reason: str
    ) -> None:
        self.calls.append((challenge_slug, job_id, task_id, reason))


async def _add_validator(factory, hotkey: str, capabilities: list[str]) -> None:
    async with session_scope(factory) as session:
        session.add(
            Validator(
                hotkey=hotkey,
                uid=None,
                status=ValidatorStatus.ONLINE,
                capabilities=list(capabilities),
                version="1.0.0",
                registered_at=NOW,
                last_heartbeat_at=NOW,
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


async def test_driver_bridge_assign_and_fold_parity_on_postgres(
    migrated_postgres_database: str,
    cleanup_postgres_database: Callable[[], Awaitable[None]],
) -> None:
    engine = create_engine(migrated_postgres_database)
    factory = create_session_factory(engine)
    service = AssignmentService(factory, now_fn=lambda: NOW, default_max_attempts=1)
    validators = ValidatorCoordinationService(factory, now_fn=lambda: NOW)
    fold = FakeFoldTrigger()
    driver = MasterOrchestrationDriver(
        assignment_service=service,
        validator_service=validators,
        work_source=FakeWorkSource(
            works=[
                ChallengePendingWork(
                    challenge_slug="agent-challenge",
                    submission_id="sub-pg",
                    submission_ref="hk",
                    task_ids=("a", "b"),
                    job_id="job-pg",
                ),
                ChallengePendingWork(
                    challenge_slug="prism",
                    submission_id="psub-pg",
                    submission_ref="hk-p",
                ),
            ]
        ),
        fold_trigger=fold,
        seed=1,
    )
    try:
        await _add_validator(factory, "v1", ["cpu"])
        await _add_validator(factory, "g1", ["gpu"])

        # Pass 1: bridge + balanced assignment across capability-matched validators.
        first = await driver.run_once()
        assert set(first.bridged["agent-challenge"]) == {"sub-pg:a", "sub-pg:b"}
        rows = {r.work_unit_id: r for r in await _rows(factory)}
        assert rows["sub-pg:a"].status == WorkAssignmentStatus.ASSIGNED
        assert rows["sub-pg:a"].assigned_validator_hotkey == "v1"
        assert rows["psub-pg"].assigned_validator_hotkey == "g1"
        assert fold.calls == []

        # The cpu validator crashes; the gpu validator stays healthy.
        await _set_status(factory, "v1", ValidatorStatus.OFFLINE)

        # Pass 2: retry-exhausted cpu units fail and are folded on the challenge.
        second = await driver.run_once()
        assert set(second.reassignment.failed) == {"sub-pg:a", "sub-pg:b"}
        assert set(second.folded) == {"sub-pg:a", "sub-pg:b"}
        assert sorted(fold.calls) == [
            ("agent-challenge", "job-pg", "a", WORK_UNIT_MAX_ATTEMPTS_REASON),
            ("agent-challenge", "job-pg", "b", WORK_UNIT_MAX_ATTEMPTS_REASON),
        ]
        rows = {r.work_unit_id: r for r in await _rows(factory)}
        assert rows["sub-pg:a"].status == WorkAssignmentStatus.FAILED
        assert rows["sub-pg:b"].status == WorkAssignmentStatus.FAILED
        # prism unit is untouched on the healthy gpu validator.
        assert rows["psub-pg"].status == WorkAssignmentStatus.ASSIGNED
    finally:
        await engine.dispose()
