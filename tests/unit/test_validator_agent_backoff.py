"""Bounded exponential backoff tests for the validator agent.

Covers the coordination-hardening behavior: the initial ``register`` and the
heartbeat/assignment loops retry transient master failures with bounded
exponential backoff instead of failing immediately or busy-looping, while a
permanent (``4xx``) master error still fails fast.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest

from base.validator.agent import BackoffPolicy, BrokerConfig, ValidatorAgent
from base.validator.agent.coordination_client import CoordinationClientError

# Zero-delay backoff keeps the retry tests instant while still exercising the
# bounded retry control flow.
FAST_BACKOFF = BackoffPolicy(initial_seconds=0.0, max_seconds=0.0, multiplier=2.0)


def _register_response(interval: int = 30) -> Any:
    return type("Resp", (), {"heartbeat_interval_seconds": interval})()


class _StubExecutor:
    async def execute(self, context: Any, *, progress: Any) -> Any:  # pragma: no cover
        raise AssertionError("executor must not run in register tests")


class _FlakyRegisterClient:
    """Fails ``failures`` times with ``error`` then registers successfully."""

    def __init__(self, *, failures: int, error: Exception, interval: int = 30) -> None:
        self._remaining = failures
        self._error = error
        self._interval = interval
        self.attempts = 0

    @property
    def hotkey(self) -> str:
        return "validator-hk"

    async def register(self, **_: Any) -> Any:
        self.attempts += 1
        if self._remaining > 0:
            self._remaining -= 1
            raise self._error
        return _register_response(self._interval)


class _CountingHeartbeatClient:
    """Heartbeats fail ``failures`` times then succeed; records call count."""

    def __init__(self, *, failures: int) -> None:
        self._remaining = failures
        self.calls = 0

    @property
    def hotkey(self) -> str:
        return "validator-hk"

    async def heartbeat(self, **_: Any) -> Any:
        self.calls += 1
        if self._remaining > 0:
            self._remaining -= 1
            raise CoordinationClientError("boom", status_code=503)
        return type("HB", (), {"status": "online", "now": datetime.now(UTC)})()


def _agent(
    client: Any,
    *,
    backoff: BackoffPolicy = FAST_BACKOFF,
    heartbeat_interval_seconds: int | None = None,
) -> ValidatorAgent:
    return ValidatorAgent(
        client=client,
        executor=_StubExecutor(),
        broker=BrokerConfig(broker_url="http://127.0.0.1:8082"),
        capabilities=["cpu"],
        version="0.1.0",
        gateway_url="http://master",
        heartbeat_interval_seconds=heartbeat_interval_seconds,
        poll_interval_seconds=0.0,
        backoff=backoff,
    )


def test_backoff_policy_grows_and_caps() -> None:
    policy = BackoffPolicy(initial_seconds=1.0, max_seconds=10.0, multiplier=2.0)
    assert policy.delay(0) == 0.0
    assert policy.delay(1) == 1.0
    assert policy.delay(2) == 2.0
    assert policy.delay(3) == 4.0
    assert policy.delay(4) == 8.0
    # Capped at max_seconds.
    assert policy.delay(5) == 10.0
    assert policy.delay(99) == 10.0


async def test_register_retries_transient_then_succeeds() -> None:
    client = _FlakyRegisterClient(
        failures=2, error=CoordinationClientError("upstream", status_code=503)
    )
    agent = _agent(client)

    interval = await agent.register()

    assert interval == 30
    assert agent.heartbeat_interval == 30
    assert client.attempts == 3  # two failures retried, third succeeded


async def test_register_retries_on_transport_error() -> None:
    # A transport error carries no status code and is treated as transient.
    client = _FlakyRegisterClient(
        failures=1, error=CoordinationClientError("connection refused")
    )
    agent = _agent(client)

    await agent.register()

    assert client.attempts == 2


async def test_register_fails_fast_on_permanent_error() -> None:
    # A 403 (ineligible hotkey) is a permanent error: do not retry.
    client = _FlakyRegisterClient(
        failures=5, error=CoordinationClientError("forbidden", status_code=403)
    )
    agent = _agent(client)

    with pytest.raises(CoordinationClientError) as excinfo:
        await agent.register()

    assert excinfo.value.status_code == 403
    assert client.attempts == 1  # no retry on a permanent error


async def test_register_aborts_when_shutdown_signaled() -> None:
    client = _FlakyRegisterClient(
        failures=100, error=CoordinationClientError("upstream", status_code=500)
    )
    # A non-zero backoff so the shutdown is observed during the sleep window.
    agent = _agent(
        client, backoff=BackoffPolicy(initial_seconds=0.05, max_seconds=0.05)
    )
    shutdown = asyncio.Event()
    shutdown.set()

    with pytest.raises(CoordinationClientError):
        await agent.register(shutdown)

    # The first attempt ran, then the set shutdown aborted before more retries.
    assert client.attempts == 1


async def test_heartbeat_loop_recovers_after_transient_failures() -> None:
    client = _CountingHeartbeatClient(failures=2)
    agent = _agent(client, heartbeat_interval_seconds=0)
    shutdown = asyncio.Event()

    async def _stop_after_recovery() -> None:
        # Wait until at least one successful heartbeat (3 calls) is observed.
        for _ in range(2000):
            if client.calls >= 3:
                break
            await asyncio.sleep(0.001)
        shutdown.set()

    await asyncio.gather(
        agent.run_heartbeat_loop(shutdown),
        _stop_after_recovery(),
    )

    # The loop survived the transient failures and kept heartbeating.
    assert client.calls >= 3
