"""Unit tests for the platform per-challenge dispatch adapters (G2).

The adapters map a pulled :class:`AssignmentContext` onto the sibling challenge
package's ``validator_dispatch.dispatch_assignment`` entrypoint, run on the
validator's OWN broker. These tests inject a fake dispatch function (the sibling
packages are not installed in the platform env) and lock the contract:

- the validator's broker config + the assignment work unit + payload (carrying
  the scoped gateway token) are passed through to the sibling cycle;
- the cycle's counts are surfaced on the :class:`ExecutionResult`;
- an unavailable sibling package surfaces a clear dispatch failure (never a
  silent drop).
"""

from __future__ import annotations

from typing import Any

import pytest

from base.schemas.assignment import AssignmentView
from base.validator.agent import (
    AssignmentContext,
    AssignmentExecutionError,
    BrokerConfig,
)
from base.validator.agent.adapters import (
    AgentChallengeCycleExecutor,
    PrismCycleExecutor,
)


def _assignment(slug: str, *, capability: str) -> AssignmentView:
    return AssignmentView(
        id="11111111-1111-1111-1111-111111111111",
        challenge_slug=slug,
        work_unit_id=f"sub:{slug}",
        submission_ref="sub",
        payload={
            "gateway_token": "scoped-token",
            "gateway_url": "https://master.example/gateway",
            "task_id": "task-1",
        },
        required_capability=capability,
        status="running",
        attempt_count=1,
        max_attempts=3,
    )


def _context(assignment: AssignmentView) -> AssignmentContext:
    return AssignmentContext(
        assignment=assignment,
        gateway_env={"BASE_GATEWAY_TOKEN": "scoped-token"},
        broker=BrokerConfig(
            broker_url="http://broker-val:8082",
            broker_token="bt",
            broker_token_file="/run/bt",
            allowed_images=("img:1",),
        ),
    )


async def _noop_progress(**_: Any) -> None:
    return None


async def test_agent_challenge_adapter_passes_broker_and_payload() -> None:
    calls: list[dict[str, Any]] = []

    async def _fake_dispatch(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {"pulled": 1, "executed": 1, "posted": 1, "skipped": 0}

    adapter = AgentChallengeCycleExecutor(dispatch=_fake_dispatch)
    context = _context(_assignment("agent-challenge", capability="cpu"))

    result = await adapter.execute(context, progress=_noop_progress)

    assert result.success is True
    assert result.payload["executed"] == 1
    assert len(calls) == 1
    sent = calls[0]
    assert sent["work_unit_id"] == "sub:agent-challenge"
    assert sent["broker_url"] == "http://broker-val:8082"
    assert sent["broker_token"] == "bt"
    assert sent["broker_token_file"] == "/run/bt"
    assert sent["broker_allowed_images"] == ("img:1",)
    # The scoped gateway token rides in the payload (never gateway=None).
    assert sent["payload"]["gateway_token"] == "scoped-token"


async def test_agent_challenge_adapter_unavailable_raises() -> None:
    # No dispatch injected and the sibling package is not installed -> clear
    # dispatch failure (never silently succeeds).
    adapter = AgentChallengeCycleExecutor()
    with pytest.raises(AssignmentExecutionError) as excinfo:
        await adapter.execute(
            _context(_assignment("agent-challenge", capability="cpu")),
            progress=_noop_progress,
        )
    assert "agent-challenge" in str(excinfo.value)
    assert "unavailable" in str(excinfo.value)


async def test_agent_challenge_adapter_propagates_dispatch_error() -> None:
    async def _boom(**_: Any) -> dict[str, Any]:
        raise AssignmentExecutionError("gateway token missing")

    adapter = AgentChallengeCycleExecutor(dispatch=_boom)
    with pytest.raises(AssignmentExecutionError):
        await adapter.execute(
            _context(_assignment("agent-challenge", capability="cpu")),
            progress=_noop_progress,
        )


async def test_prism_adapter_passes_broker_and_payload() -> None:
    calls: list[dict[str, Any]] = []

    async def _fake_dispatch(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {"pulled": 1, "executed": 1, "skipped": 0}

    adapter = PrismCycleExecutor(dispatch=_fake_dispatch)
    context = _context(_assignment("prism", capability="gpu"))

    result = await adapter.execute(context, progress=_noop_progress)

    assert result.success is True
    assert result.payload["executed"] == 1
    assert len(calls) == 1
    sent = calls[0]
    assert sent["work_unit_id"] == "sub:prism"
    assert sent["broker_url"] == "http://broker-val:8082"
    assert sent["broker_token"] == "bt"
    assert sent["broker_token_file"] == "/run/bt"
    assert sent["payload"]["gateway_token"] == "scoped-token"


async def test_prism_adapter_unavailable_raises() -> None:
    adapter = PrismCycleExecutor()
    with pytest.raises(AssignmentExecutionError) as excinfo:
        await adapter.execute(
            _context(_assignment("prism", capability="gpu")),
            progress=_noop_progress,
        )
    assert "prism" in str(excinfo.value)
    assert "unavailable" in str(excinfo.value)
