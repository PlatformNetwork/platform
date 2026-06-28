"""Postgres parity for the LLM usage metering table (VAL-LLM-018)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest
from sqlalchemy import select, text

from base.db import (
    LlmUsageRecord,
    create_engine,
    create_session_factory,
)
from base.master.llm_gateway.usage import SqlAlchemyUsageRecorder, UsageRecord

pytestmark = pytest.mark.postgres


async def test_migration_creates_usage_table(
    migrated_postgres_database: str,
    cleanup_postgres_database: Callable[[], Awaitable[None]],
) -> None:
    engine = create_engine(migrated_postgres_database)
    try:
        async with engine.connect() as connection:
            present = {
                row[0]
                for row in (
                    await connection.execute(
                        text(
                            "SELECT table_name FROM information_schema.tables "
                            "WHERE table_schema = current_schema()"
                        )
                    )
                ).all()
            }
    finally:
        await engine.dispose()
    assert "llm_usage_records" in present


async def test_usage_recorder_persists_on_postgres(
    migrated_postgres_database: str,
    cleanup_postgres_database: Callable[[], Awaitable[None]],
) -> None:
    engine = create_engine(migrated_postgres_database)
    session_factory = create_session_factory(engine)
    try:
        recorder = SqlAlchemyUsageRecorder(session_factory)
        await recorder.record(
            UsageRecord(
                validator_hotkey="5FpgUsage",
                assignment_id="assignment-pg-1",
                provider="openrouter",
                model="anthropic/claude-opus-4.8",
                status_code=200,
                prompt_tokens=10,
                completion_tokens=20,
                total_tokens=30,
            )
        )
        async with session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(LlmUsageRecord).where(
                            LlmUsageRecord.validator_hotkey == "5FpgUsage"
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert len(rows) == 1
        assert rows[0].assignment_id == "assignment-pg-1"
        assert rows[0].total_tokens == 30
    finally:
        await engine.dispose()
