"""Long-running validator agent loop (architecture.md sec 2.2).

The agent hotkey-registers + heartbeats with the master on a configurable
interval (recovering across restarts because registration is an idempotent
server-side upsert and all assignment state lives on the master), pulls its
assignments, executes each via its OWN broker, and posts results. Every LLM call
routes through the master gateway using a per-assignment scoped token; the agent
holds no provider key.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from base.validator.agent.coordination_client import CoordinationClient
from base.validator.agent.executor import (
    AssignmentContext,
    AssignmentExecutor,
    BrokerConfig,
    ExecutionResult,
    gateway_env_for_assignment,
)

logger = logging.getLogger(__name__)

_ACTIVE_STATUSES = frozenset({"assigned", "running"})
_DEFAULT_HEARTBEAT_INTERVAL = 60


@dataclass(frozen=True)
class BackoffPolicy:
    """Bounded exponential backoff for transient master/coordination failures.

    The delay grows geometrically with the number of consecutive failures and is
    capped at ``max_seconds`` so the agent retries a briefly-unavailable master
    without either giving up or busy-looping (architecture.md sec 2.2).
    """

    initial_seconds: float = 1.0
    max_seconds: float = 60.0
    multiplier: float = 2.0

    def delay(self, consecutive_failures: int) -> float:
        """Backoff delay after ``consecutive_failures`` failures (>=1)."""

        if consecutive_failures <= 0:
            return 0.0
        raw = self.initial_seconds * (self.multiplier ** (consecutive_failures - 1))
        return min(self.max_seconds, max(0.0, raw))


def _is_transient_error(exc: BaseException) -> bool:
    """Whether a coordination failure is worth retrying with backoff.

    Transport errors (no status code) and ``429``/``5xx`` master responses are
    transient; a ``4xx`` (e.g. ``403`` ineligible, ``404`` not registered,
    ``401`` auth) is a permanent client error that should fail fast.
    """

    status_code = getattr(exc, "status_code", None)
    if status_code is None:
        return True
    return status_code == 429 or status_code >= 500


@dataclass(frozen=True)
class AgentCycleSummary:
    """Counts from one assignment-processing pass."""

    pulled: int
    completed: int
    failed: int


class ValidatorAgent:
    """Coordinated executor: register, heartbeat, pull, execute, post results."""

    def __init__(
        self,
        *,
        client: CoordinationClient,
        executor: AssignmentExecutor,
        broker: BrokerConfig,
        capabilities: list[str],
        version: str | None,
        gateway_url: str,
        heartbeat_interval_seconds: int | None = None,
        poll_interval_seconds: float = 5.0,
        last_seen_meta_factory: Callable[[], Mapping[str, Any]] | None = None,
        backoff: BackoffPolicy | None = None,
    ) -> None:
        self._client = client
        self._executor = executor
        self._broker = broker
        self._capabilities = list(capabilities)
        self._version = version
        self._gateway_url = gateway_url
        self._configured_interval = heartbeat_interval_seconds
        self._poll_interval = poll_interval_seconds
        self._last_seen_meta_factory = last_seen_meta_factory
        self._backoff = backoff or BackoffPolicy()
        self._registered_interval: int | None = None

    @property
    def hotkey(self) -> str:
        return self._client.hotkey

    @property
    def heartbeat_interval(self) -> int:
        if self._configured_interval is not None:
            return self._configured_interval
        return self._registered_interval or _DEFAULT_HEARTBEAT_INTERVAL

    async def register(self, shutdown_event: asyncio.Event | None = None) -> int:
        """Register (idempotent upsert) and resolve the heartbeat interval.

        Transient master failures (transport errors / ``429``/``5xx``) are
        retried with bounded exponential backoff so a briefly-unavailable master
        at startup does not crash the agent; a permanent error (``4xx``, e.g.
        ineligible hotkey) fails fast. A set ``shutdown_event`` aborts the retry
        loop (re-raising the last error).
        """

        failures = 0
        while True:
            try:
                response = await self._client.register(
                    capabilities=self._capabilities,
                    version=self._version,
                    last_seen_meta=self._meta(),
                )
            except Exception as exc:
                if not _is_transient_error(exc):
                    raise
                failures += 1
                delay = self._backoff.delay(failures)
                logger.warning(
                    "validator agent register attempt %d failed (%s); "
                    "retrying in %.1fs",
                    failures,
                    exc,
                    delay,
                )
                if not await self._backoff_sleep(shutdown_event, delay):
                    raise
                continue
            self._registered_interval = response.heartbeat_interval_seconds
            return self.heartbeat_interval

    async def heartbeat_once(self) -> None:
        await self._client.heartbeat(last_seen_meta=self._meta())

    async def process_pending_assignments(self) -> AgentCycleSummary:
        """Pull, execute, and post results for all currently-assigned units."""

        assignments = await self._client.pull()
        completed = 0
        failed = 0
        for assignment in assignments:
            if assignment.status not in _ACTIVE_STATUSES:
                continue
            if await self._execute_one(assignment):
                completed += 1
            else:
                failed += 1
        return AgentCycleSummary(
            pulled=len(assignments), completed=completed, failed=failed
        )

    async def run_heartbeat_loop(self, shutdown_event: asyncio.Event) -> None:
        failures = 0
        while not shutdown_event.is_set():
            try:
                await self.heartbeat_once()
                failures = 0
            except Exception:
                failures += 1
                logger.exception("validator agent heartbeat failed")
            delay = (
                self._backoff.delay(failures) if failures else self.heartbeat_interval
            )
            await self._sleep_until(shutdown_event, delay)

    async def run_assignment_loop(self, shutdown_event: asyncio.Event) -> None:
        failures = 0
        while not shutdown_event.is_set():
            try:
                await self.process_pending_assignments()
                failures = 0
            except Exception:
                failures += 1
                logger.exception("validator agent assignment pass failed")
            delay = self._backoff.delay(failures) if failures else self._poll_interval
            await self._sleep_until(shutdown_event, delay)

    async def run_forever(self, shutdown_event: asyncio.Event | None = None) -> None:
        shutdown_event = shutdown_event or asyncio.Event()
        await self.register(shutdown_event)
        await asyncio.gather(
            self.run_heartbeat_loop(shutdown_event),
            self.run_assignment_loop(shutdown_event),
        )

    async def _execute_one(self, assignment: Any) -> bool:
        gateway_env = gateway_env_for_assignment(
            assignment, gateway_url=self._gateway_url
        )
        context = AssignmentContext(
            assignment=assignment, gateway_env=gateway_env, broker=self._broker
        )

        async def report_progress(
            *,
            checkpoint_ref: str | None = None,
            meta: Mapping[str, Any] | None = None,
        ) -> None:
            try:
                await self._client.progress(
                    assignment.id, checkpoint_ref=checkpoint_ref, meta=meta
                )
            except Exception:
                logger.warning(
                    "validator agent progress heartbeat failed for %s",
                    assignment.id,
                )

        try:
            result = await self._executor.execute(context, progress=report_progress)
        except Exception as exc:
            logger.exception("validator agent execution failed for %s", assignment.id)
            await self._client.post_result(
                assignment.id, success=False, payload={"error": str(exc)}
            )
            return False

        await self._client.post_result(
            assignment.id,
            success=result.success,
            payload=dict(result.payload),
            checkpoint_ref=result.checkpoint_ref,
        )
        return result.success

    def _meta(self) -> dict[str, Any]:
        meta: dict[str, Any] = {
            "capabilities": list(self._capabilities),
            "broker_url": self._broker.broker_url,
        }
        if self._last_seen_meta_factory is not None:
            meta.update(dict(self._last_seen_meta_factory()))
        return meta

    @staticmethod
    async def _sleep_until(shutdown_event: asyncio.Event, seconds: float) -> None:
        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=seconds)
        except TimeoutError:
            return

    @staticmethod
    async def _backoff_sleep(
        shutdown_event: asyncio.Event | None, seconds: float
    ) -> bool:
        """Sleep ``seconds``; return ``False`` if shutdown fired during the wait."""

        if shutdown_event is None:
            await asyncio.sleep(seconds)
            return True
        if shutdown_event.is_set():
            return False
        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=seconds)
        except TimeoutError:
            return True
        return False


__all__ = [
    "AgentCycleSummary",
    "BackoffPolicy",
    "ExecutionResult",
    "ValidatorAgent",
]
