"""Usage metering for the master LLM gateway.

A successful gateway call records an accounting row keyed by
``(validator_hotkey, assignment_id)`` carrying the provider, model, and token
usage (architecture.md sec 5). No secret material (provider key or gateway
token) is ever stored. The recorder is an interface so tests use an in-memory
implementation and the master persists via SQLAlchemy.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from base.db.models import LlmUsageRecord
from base.db.session import session_scope


@dataclass(frozen=True)
class UsageRecord:
    """A single metered gateway call. Carries no secret material."""

    validator_hotkey: str
    assignment_id: str
    provider: str
    model: str
    status_code: int
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class UsageRecorder(Protocol):
    """Persists a :class:`UsageRecord` for a successful gateway call."""

    async def record(self, record: UsageRecord) -> None: ...


class NullUsageRecorder:
    """A recorder that drops records (used when metering is not configured)."""

    async def record(self, record: UsageRecord) -> None:
        return None


class InMemoryUsageRecorder:
    """Collects records in memory for tests/observability."""

    def __init__(self) -> None:
        self.records: list[UsageRecord] = []

    async def record(self, record: UsageRecord) -> None:
        self.records.append(record)


class SqlAlchemyUsageRecorder:
    """Persists usage rows into the control-plane ``llm_usage_records`` table."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        now_fn: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._session_factory = session_factory
        self._now_fn = now_fn

    async def record(self, record: UsageRecord) -> None:
        async with session_scope(self._session_factory) as session:
            session.add(
                LlmUsageRecord(
                    id=uuid.uuid4(),
                    validator_hotkey=record.validator_hotkey,
                    assignment_id=record.assignment_id,
                    provider=record.provider,
                    model=record.model,
                    status_code=record.status_code,
                    prompt_tokens=record.prompt_tokens,
                    completion_tokens=record.completion_tokens,
                    total_tokens=record.total_tokens,
                    created_at=self._now_fn(),
                )
            )


def parse_usage(body: bytes) -> tuple[int, int, int]:
    """Extract ``(prompt, completion, total)`` token counts from a response body.

    Returns zeros when the body is empty, not JSON, or carries no usage block.
    """

    if not body:
        return (0, 0, 0)
    try:
        payload = json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return (0, 0, 0)
    if not isinstance(payload, dict):
        return (0, 0, 0)
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return (0, 0, 0)
    return (
        _as_int(usage.get("prompt_tokens")),
        _as_int(usage.get("completion_tokens")),
        _as_int(usage.get("total_tokens")),
    )


def _as_int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
