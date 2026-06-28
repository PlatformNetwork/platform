"""Unit tests for the validator agent's challenge-dispatching executor (G2).

The decentralized validator pulls a work unit and dispatches it to the
per-challenge execution cycle selected by ``challenge_slug``. These tests lock
the dispatch seam itself: routing by slug, the generic ``run_spec`` fallback, the
explicit-registration override, and the clear failures (unknown slug with no
``run_spec``; an unavailable challenge adapter). The real per-challenge container
shapes are covered in the sibling challenge repos' adapter tests.
"""

from __future__ import annotations

from typing import Any

import pytest

from base.challenge_sdk.executors.docker import DockerRunResult
from base.schemas.assignment import AssignmentView
from base.validator.agent import (
    AssignmentContext,
    AssignmentExecutionError,
    BrokerConfig,
    ChallengeDispatchExecutor,
    ExecutionResult,
)
from base.validator.agent import executor as executor_module
from base.validator.agent.executor import ProgressCallback


def _assignment(
    slug: str, *, payload: dict[str, Any] | None = None, capability: str = "cpu"
) -> AssignmentView:
    return AssignmentView(
        id="11111111-1111-1111-1111-111111111111",
        challenge_slug=slug,
        work_unit_id=f"sub:{slug}",
        submission_ref="sub",
        payload=payload or {},
        required_capability=capability,
        status="running",
        attempt_count=1,
        max_attempts=3,
    )


def _context(assignment: AssignmentView) -> AssignmentContext:
    return AssignmentContext(
        assignment=assignment,
        gateway_env={"BASE_GATEWAY_TOKEN": "scoped", "DEEPSEEK_BASE_URL": "g/d"},
        broker=BrokerConfig(broker_url="http://broker-val:8082"),
    )


async def _noop_progress(**_: Any) -> None:
    return None


class _RecordingChallengeExecutor:
    """Per-slug executor double that records the dispatched context."""

    def __init__(self) -> None:
        self.contexts: list[AssignmentContext] = []

    async def execute(
        self, context: AssignmentContext, *, progress: ProgressCallback
    ) -> ExecutionResult:
        self.contexts.append(context)
        return ExecutionResult(
            success=True, payload={"slug": context.assignment.challenge_slug}
        )


async def test_dispatches_by_challenge_slug() -> None:
    agent_challenge = _RecordingChallengeExecutor()
    prism = _RecordingChallengeExecutor()
    dispatcher = ChallengeDispatchExecutor(
        executors={"agent-challenge": agent_challenge, "prism": prism}
    )

    ac_result = await dispatcher.execute(
        _context(_assignment("agent-challenge")), progress=_noop_progress
    )
    prism_result = await dispatcher.execute(
        _context(_assignment("prism", capability="gpu")), progress=_noop_progress
    )

    assert ac_result.payload["slug"] == "agent-challenge"
    assert prism_result.payload["slug"] == "prism"
    assert len(agent_challenge.contexts) == 1
    assert len(prism.contexts) == 1
    # The prism unit never reached the agent-challenge executor and vice versa.
    assert agent_challenge.contexts[0].assignment.challenge_slug == "agent-challenge"
    assert prism.contexts[0].assignment.challenge_slug == "prism"


async def test_register_overrides_default_factory() -> None:
    # A registered executor for a default-mapped slug is used WITHOUT building
    # (and thus lazily importing) the sibling-package adapter.
    def _explode() -> Any:
        raise AssertionError(
            "the challenge adapter must not be built when an executor is registered"
        )

    dispatcher = ChallengeDispatchExecutor(factories={"agent-challenge": _explode})
    fake = _RecordingChallengeExecutor()
    dispatcher.register("agent-challenge", fake)

    result = await dispatcher.execute(
        _context(_assignment("agent-challenge")), progress=_noop_progress
    )
    assert result.success is True
    assert len(fake.contexts) == 1


async def test_default_factories_map_to_adapters() -> None:
    from base.validator.agent.adapters import (
        AgentChallengeCycleExecutor,
        PrismCycleExecutor,
    )
    from base.validator.agent.challenge_dispatch import (
        DEFAULT_CHALLENGE_EXECUTOR_FACTORIES,
    )

    assert isinstance(
        DEFAULT_CHALLENGE_EXECUTOR_FACTORIES["agent-challenge"](),
        AgentChallengeCycleExecutor,
    )
    assert isinstance(
        DEFAULT_CHALLENGE_EXECUTOR_FACTORIES["prism"](), PrismCycleExecutor
    )


async def test_factory_executor_is_resolved_once() -> None:
    builds = {"count": 0}

    def _factory() -> Any:
        builds["count"] += 1
        return _RecordingChallengeExecutor()

    dispatcher = ChallengeDispatchExecutor(factories={"agent-challenge": _factory})
    await dispatcher.execute(
        _context(_assignment("agent-challenge")), progress=_noop_progress
    )
    await dispatcher.execute(
        _context(_assignment("agent-challenge")), progress=_noop_progress
    )
    assert builds["count"] == 1


async def test_generic_run_spec_fallback_for_unmapped_slug(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class _FakeDockerExecutor:
        def __init__(self, **kwargs: Any) -> None:
            captured["kwargs"] = kwargs

        def run(self, spec: Any, timeout_seconds: int) -> DockerRunResult:
            captured["spec"] = spec
            return DockerRunResult(
                container_name="c1", stdout="ok", stderr="", returncode=0
            )

    monkeypatch.setattr(executor_module, "DockerExecutor", _FakeDockerExecutor)
    dispatcher = ChallengeDispatchExecutor()
    assignment = _assignment(
        "swe-forge",
        payload={"run_spec": {"image": "img:1", "command": ["run"]}},
    )

    result = await dispatcher.execute(_context(assignment), progress=_noop_progress)

    assert result.success is True
    # A slug with no adapter but a generic run_spec runs on the broker-backed
    # generic executor (the broker was actually dispatched).
    assert captured["spec"].image == "img:1"
    assert captured["kwargs"]["backend"] == "broker"


async def test_unmapped_slug_without_run_spec_raises() -> None:
    dispatcher = ChallengeDispatchExecutor()
    with pytest.raises(AssignmentExecutionError) as excinfo:
        await dispatcher.execute(
            _context(_assignment("swe-forge")), progress=_noop_progress
        )
    assert "no challenge executor" in str(excinfo.value)
    assert "run_spec" in str(excinfo.value)


async def test_unavailable_challenge_adapter_raises() -> None:
    # The sibling challenge packages are NOT installed in the platform env, so a
    # default-mapped slug with no registered executor surfaces a clear dispatch
    # failure (never a silent drop, never "no run_spec").
    dispatcher = ChallengeDispatchExecutor()
    with pytest.raises(AssignmentExecutionError) as excinfo:
        await dispatcher.execute(
            _context(_assignment("agent-challenge")), progress=_noop_progress
        )
    message = str(excinfo.value)
    assert "agent-challenge" in message
    assert "unavailable" in message
