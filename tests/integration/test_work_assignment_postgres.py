"""Postgres parity tests for the work_assignments table + assignment engine.

Covers VAL-ASSIGN-030 (migration creates the table on Postgres) and the
assignment-engine lifecycle parity with SQLite: create -> assign produces the
same observable balanced/capability-aware behavior on the throwaway Postgres at
127.0.0.1:15490.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text

from base.db import (
    Validator,
    ValidatorStatus,
    create_engine,
    create_session_factory,
    session_scope,
)
from base.db.models import WorkAssignment, WorkAssignmentStatus
from base.master.assignment import AssignmentService

pytestmark = pytest.mark.postgres

NOW = datetime(2026, 6, 27, 12, 0, 0, tzinfo=UTC)


async def test_work_assignments_table_exists_on_postgres(
    migrated_postgres_database: str,
    cleanup_postgres_database: Callable[[], Awaitable[None]],
) -> None:
    engine = create_engine(migrated_postgres_database)
    try:
        async with engine.connect() as connection:
            columns = (
                (
                    await connection.execute(
                        text(
                            """
                            SELECT column_name
                            FROM information_schema.columns
                            WHERE table_schema = current_schema()
                              AND table_name = 'work_assignments'
                            """
                        )
                    )
                )
                .scalars()
                .all()
            )
    finally:
        await engine.dispose()

    assert {
        "id",
        "challenge_slug",
        "work_unit_id",
        "submission_ref",
        "payload",
        "required_capability",
        "assigned_validator_hotkey",
        "status",
        "attempt_count",
        "max_attempts",
        "deadline_at",
        "last_progress_at",
        "checkpoint_ref",
        "result_ref",
        "created_at",
        "updated_at",
    } <= set(columns)


async def test_assignment_lifecycle_parity_on_postgres(
    migrated_postgres_database: str,
    cleanup_postgres_database: Callable[[], Awaitable[None]],
) -> None:
    engine = create_engine(migrated_postgres_database)
    session_factory = create_session_factory(engine)
    service = AssignmentService(session_factory, now_fn=lambda: NOW)

    try:
        async with session_scope(session_factory) as session:
            for hotkey in ("vp1", "vp2", "vp3"):
                session.add(
                    Validator(
                        hotkey=hotkey,
                        uid=None,
                        status=ValidatorStatus.ONLINE,
                        capabilities=["cpu"],
                        version="1.0.0",
                        registered_at=NOW,
                        last_heartbeat_at=NOW,
                    )
                )
            session.add(
                Validator(
                    hotkey="vp-offline",
                    uid=None,
                    status=ValidatorStatus.OFFLINE,
                    capabilities=["cpu"],
                    version="1.0.0",
                    registered_at=NOW,
                    last_heartbeat_at=NOW,
                )
            )

        created = await service.create_agent_challenge_work_units(
            submission_id="sub-pg",
            submission_ref="hk-pg",
            task_ids=[f"task-{i}" for i in range(9)],
        )
        assert len(created) == 9

        await service.assign_pending(seed=11)

        async with session_factory() as session:
            rows = (await session.execute(select(WorkAssignment))).scalars().all()

        assert len(rows) == 9
        assert all(r.status == WorkAssignmentStatus.ASSIGNED for r in rows)
        counts = Counter(r.assigned_validator_hotkey for r in rows)
        assert "vp-offline" not in counts
        assert set(counts) == {"vp1", "vp2", "vp3"}
        assert max(counts.values()) - min(counts.values()) <= 1
    finally:
        await engine.dispose()
