"""Unit tests for gateway usage metering (VAL-LLM-018) - no secret stored."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from base.db import Base, LlmUsageRecord
from base.db.session import create_engine, create_session_factory
from base.master.llm_gateway.usage import (
    InMemoryUsageRecorder,
    NullUsageRecorder,
    SqlAlchemyUsageRecorder,
    UsageRecord,
    parse_usage,
)


def test_parse_usage_extracts_token_counts() -> None:
    body = json.dumps(
        {"usage": {"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12}}
    ).encode()
    usage = parse_usage(body)
    assert usage == (7, 5, 12)


@pytest.mark.parametrize("body", [b"", b"not-json", b"{}", b'{"usage": "x"}'])
def test_parse_usage_defaults_zero_for_missing_or_invalid(body: bytes) -> None:
    assert parse_usage(body) == (0, 0, 0)


async def test_in_memory_recorder_collects_records() -> None:
    recorder = InMemoryUsageRecorder()
    record = UsageRecord(
        validator_hotkey="v1",
        assignment_id="a1",
        provider="deepseek",
        model="deepseek-v4-pro",
        status_code=200,
        prompt_tokens=1,
        completion_tokens=1,
        total_tokens=2,
    )
    await recorder.record(record)
    assert recorder.records == [record]


async def test_null_recorder_is_noop() -> None:
    await NullUsageRecorder().record(
        UsageRecord(
            validator_hotkey="v1",
            assignment_id="a1",
            provider="deepseek",
            model="deepseek-v4-pro",
            status_code=200,
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=0,
        )
    )


def test_usage_record_has_no_secret_fields() -> None:
    field_names = set(UsageRecord.__dataclass_fields__)
    assert not (field_names & {"token", "api_key", "key", "authorization", "secret"})


def test_usage_model_columns_carry_no_secret() -> None:
    columns = {column.name for column in LlmUsageRecord.__table__.columns}
    assert columns == {
        "id",
        "validator_hotkey",
        "assignment_id",
        "provider",
        "model",
        "status_code",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "created_at",
    }


async def test_sqlalchemy_recorder_persists_row_keyed_by_scope() -> None:
    engine = create_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_factory = create_session_factory(engine)
    try:
        recorder = SqlAlchemyUsageRecorder(session_factory)
        await recorder.record(
            UsageRecord(
                validator_hotkey="validator-hotkey-1",
                assignment_id="assignment-1",
                provider="deepseek",
                model="deepseek-v4-pro",
                status_code=200,
                prompt_tokens=3,
                completion_tokens=4,
                total_tokens=7,
            )
        )
        async with session_factory() as session:
            rows = (await session.execute(select(LlmUsageRecord))).scalars().all()
        assert len(rows) == 1
        row = rows[0]
        assert row.validator_hotkey == "validator-hotkey-1"
        assert row.assignment_id == "assignment-1"
        assert row.provider == "deepseek"
        assert row.model == "deepseek-v4-pro"
        assert row.total_tokens == 7
        assert row.created_at is not None
    finally:
        await engine.dispose()
