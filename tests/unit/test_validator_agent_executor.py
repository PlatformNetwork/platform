"""Unit tests for the validator agent execution seam."""

from __future__ import annotations

from typing import Any

import pytest

from base.challenge_sdk.executors.docker import DockerRunResult
from base.schemas.assignment import AssignmentView
from base.validator.agent import executor as executor_module
from base.validator.agent.executor import (
    AssignmentContext,
    AssignmentExecutionError,
    BrokerAssignmentExecutor,
    BrokerConfig,
    gateway_env_for_assignment,
)


def _assignment(payload: dict[str, Any], *, capability: str = "cpu") -> AssignmentView:
    return AssignmentView(
        id="11111111-1111-1111-1111-111111111111",
        challenge_slug="agent-challenge",
        work_unit_id="sub:task-1",
        submission_ref="sub",
        payload=payload,
        required_capability=capability,
        status="running",
        attempt_count=1,
        max_attempts=3,
    )


def test_gateway_env_points_at_gateway_and_carries_token_no_provider_key() -> None:
    assignment = _assignment({"gateway_token": "scoped-token"})
    env = gateway_env_for_assignment(assignment, gateway_url="https://master/")

    assert env["DEEPSEEK_BASE_URL"] == "https://master/llm/deepseek"
    assert env["OPENROUTER_BASE_URL"] == "https://master/llm/openrouter"
    assert env["BASE_GATEWAY_TOKEN"] == "scoped-token"
    assert "DEEPSEEK_API_KEY" not in env
    assert "OPENROUTER_API_KEY" not in env


def test_gateway_env_without_token_omits_token_key() -> None:
    env = gateway_env_for_assignment(_assignment({}), gateway_url="https://master")
    assert "BASE_GATEWAY_TOKEN" not in env


class _FakeDockerExecutor:
    last: _FakeDockerExecutor | None = None

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.spec: Any = None
        self.timeout: int | None = None
        _FakeDockerExecutor.last = self

    def run(self, spec: Any, timeout_seconds: int) -> DockerRunResult:
        self.spec = spec
        self.timeout = timeout_seconds
        return DockerRunResult(
            container_name="c1", stdout="ok", stderr="", returncode=0
        )


async def test_broker_executor_dispatches_run_spec_with_gateway_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(executor_module, "DockerExecutor", _FakeDockerExecutor)
    assignment = _assignment(
        {
            "run_spec": {
                "image": "ghcr.io/baseintelligence/runner:1",
                "command": ["run", "--task", "task-1"],
                "env": {"FOO": "bar", "DEEPSEEK_API_KEY": "leaked"},
            }
        }
    )
    context = AssignmentContext(
        assignment=assignment,
        gateway_env={"BASE_GATEWAY_TOKEN": "scoped", "DEEPSEEK_BASE_URL": "g/d"},
        broker=BrokerConfig(broker_url="http://127.0.0.1:8082", broker_token="t"),
    )

    async def _noop_progress(**_: Any) -> None:
        return None

    result = await BrokerAssignmentExecutor(run_timeout_seconds=120).execute(
        context, progress=_noop_progress
    )

    assert result.success is True
    assert result.payload["returncode"] == 0
    fake = _FakeDockerExecutor.last
    assert fake is not None
    assert fake.kwargs["backend"] == "broker"
    assert fake.kwargs["broker_url"] == "http://127.0.0.1:8082"
    assert fake.timeout == 120
    spec = fake.spec
    assert spec.image == "ghcr.io/baseintelligence/runner:1"
    assert spec.command == ("run", "--task", "task-1")
    # gateway env injected; the provider key from run_spec env is stripped.
    assert spec.env["FOO"] == "bar"
    assert spec.env["BASE_GATEWAY_TOKEN"] == "scoped"
    assert "DEEPSEEK_API_KEY" not in spec.env


class _LeakingDockerExecutor:
    """Fake broker executor whose container echoes the gateway token."""

    last: _LeakingDockerExecutor | None = None

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        _LeakingDockerExecutor.last = self

    def run(self, spec: Any, timeout_seconds: int) -> DockerRunResult:
        token = spec.env["BASE_GATEWAY_TOKEN"]
        return DockerRunResult(
            container_name="c1",
            stdout=f"using token {token} to call gateway",
            stderr=f"error with auth header Bearer {token}",
            returncode=0,
        )


async def test_broker_executor_redacts_gateway_token_from_captured_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(executor_module, "DockerExecutor", _LeakingDockerExecutor)
    secret_token = "scoped-gateway-token-abc123"
    assignment = _assignment({"run_spec": {"image": "img:1", "command": ["run"]}})
    context = AssignmentContext(
        assignment=assignment,
        gateway_env={
            "BASE_GATEWAY_TOKEN": secret_token,
            "DEEPSEEK_BASE_URL": "http://master/llm/deepseek",
        },
        broker=BrokerConfig(broker_url="http://127.0.0.1:8082"),
    )

    async def _noop_progress(**_: Any) -> None:
        return None

    result = await BrokerAssignmentExecutor().execute(context, progress=_noop_progress)

    # The container surfaced the token, but it is redacted from captured output.
    assert secret_token not in result.payload["stdout"]
    assert secret_token not in result.payload["stderr"]
    assert "[REDACTED_GATEWAY_TOKEN]" in result.payload["stdout"]
    assert "[REDACTED_GATEWAY_TOKEN]" in result.payload["stderr"]
    # Non-secret content is preserved.
    assert "to call gateway" in result.payload["stdout"]


async def test_broker_executor_gpu_capability_requests_gpu(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(executor_module, "DockerExecutor", _FakeDockerExecutor)
    assignment = _assignment(
        {"run_spec": {"image": "img:1", "command": ["x"], "gpu_count": 2}},
        capability="gpu",
    )
    context = AssignmentContext(
        assignment=assignment,
        gateway_env={},
        broker=BrokerConfig(broker_url="http://127.0.0.1:8082"),
    )

    async def _noop_progress(**_: Any) -> None:
        return None

    await BrokerAssignmentExecutor().execute(context, progress=_noop_progress)
    assert _FakeDockerExecutor.last is not None
    assert _FakeDockerExecutor.last.spec.limits.gpu_count == 2


async def test_broker_executor_missing_run_spec_raises() -> None:
    context = AssignmentContext(
        assignment=_assignment({}),
        gateway_env={},
        broker=BrokerConfig(broker_url="http://127.0.0.1:8082"),
    )

    async def _noop_progress(**_: Any) -> None:
        return None

    with pytest.raises(AssignmentExecutionError):
        await BrokerAssignmentExecutor().execute(context, progress=_noop_progress)
