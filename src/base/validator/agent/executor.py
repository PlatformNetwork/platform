"""Assignment execution seam for the validator agent.

The agent dispatches each pulled assignment to an :class:`AssignmentExecutor`
running on the validator's OWN broker + Docker (the master never executes tasks).
Challenge-specific executors (agent-challenge Terminal-Bench, prism GPU
re-execution) plug in here; :class:`BrokerAssignmentExecutor` is the default
generic broker-backed executor.

LLM credentials are never placed in the execution environment: the agent builds a
gateway env carrying only the master gateway base URLs and a scoped per-assignment
gateway token (architecture.md sec 5), and provider-key env vars are stripped
defensively.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from base.challenge_sdk.executors.docker import (
    DockerExecutor,
    DockerLimits,
    DockerRunSpec,
)
from base.master.llm_gateway import (
    DEEPSEEK_BASE_URL_ENV,
    GATEWAY_TOKEN_ENV,
    OPENROUTER_BASE_URL_ENV,
)
from base.schemas.assignment import AssignmentView

#: Assignment-payload key carrying the scoped gateway token issued by the master.
GATEWAY_TOKEN_PAYLOAD_KEY = "gateway_token"
#: Assignment-payload key carrying the generic Docker run descriptor.
RUN_SPEC_PAYLOAD_KEY = "run_spec"

#: Placeholder substituted for the scoped gateway token in captured container
#: output so the short-lived token is never surfaced via stdout/stderr or logs.
GATEWAY_TOKEN_REDACTION = "[REDACTED_GATEWAY_TOKEN]"

#: Provider-key env vars that must never reach an eval container on a validator.
_PROVIDER_KEY_ENV = frozenset(
    {
        "DEEPSEEK_API_KEY",
        "OPENROUTER_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    }
)

#: Async callback an executor uses to heartbeat progress on a running unit.
ProgressCallback = Callable[..., Awaitable[None]]


class AssignmentExecutionError(RuntimeError):
    """An assignment could not be executed (maps to a failed result post)."""


@dataclass(frozen=True)
class ExecutionResult:
    """Outcome of executing one assignment work unit."""

    success: bool
    payload: Mapping[str, Any] = field(default_factory=dict)
    checkpoint_ref: str | None = None


@dataclass(frozen=True)
class BrokerConfig:
    """The validator's OWN Docker broker the executor dispatches runs to."""

    broker_url: str
    broker_token: str | None = None
    broker_token_file: str | None = None
    allowed_images: tuple[str, ...] = ()

    def docker_executor(self, challenge: str) -> DockerExecutor:
        """Build a broker-backed :class:`DockerExecutor` for ``challenge``."""

        return DockerExecutor(
            challenge=challenge,
            backend="broker",
            broker_url=self.broker_url,
            broker_token=self.broker_token,
            broker_token_file=self.broker_token_file,
            allowed_images=self.allowed_images,
        )


@dataclass(frozen=True)
class AssignmentContext:
    """Everything an executor needs to run one pulled assignment."""

    assignment: AssignmentView
    gateway_env: Mapping[str, str]
    broker: BrokerConfig


@runtime_checkable
class AssignmentExecutor(Protocol):
    """Executes a pulled assignment on the validator's own broker."""

    async def execute(
        self, context: AssignmentContext, *, progress: ProgressCallback
    ) -> ExecutionResult: ...


def gateway_env_for_assignment(
    assignment: AssignmentView, *, gateway_url: str
) -> dict[str, str]:
    """Build the LLM-gateway env for an eval runtime (no provider key).

    Points ``DEEPSEEK_BASE_URL``/``OPENROUTER_BASE_URL`` at the master gateway and
    carries the per-assignment scoped gateway token from the assignment payload.
    """

    base = gateway_url.rstrip("/")
    env = {
        DEEPSEEK_BASE_URL_ENV: f"{base}/llm/deepseek",
        OPENROUTER_BASE_URL_ENV: f"{base}/llm/openrouter",
    }
    token = (assignment.payload or {}).get(GATEWAY_TOKEN_PAYLOAD_KEY)
    if token:
        env[GATEWAY_TOKEN_ENV] = str(token)
    return env


class BrokerAssignmentExecutor:
    """Generic executor: run the payload's Docker spec on the own broker.

    The assignment payload's ``run_spec`` (image + command, optional env/workdir)
    is run through the validator's broker-backed :class:`DockerExecutor` with the
    gateway env merged in and provider-key env vars stripped. Returns
    success/failure from the container return code. Challenge-specific result
    parsing is layered on top by the per-challenge executors (m4/m5).
    """

    def __init__(self, *, run_timeout_seconds: int = 3_600) -> None:
        self._run_timeout = run_timeout_seconds

    async def execute(
        self, context: AssignmentContext, *, progress: ProgressCallback
    ) -> ExecutionResult:
        spec = _build_run_spec(context)
        executor = context.broker.docker_executor(context.assignment.challenge_slug)
        result = await asyncio.to_thread(executor.run, spec, self._run_timeout)
        secrets = _gateway_secrets(context.gateway_env)
        return ExecutionResult(
            success=result.returncode == 0,
            payload={
                "returncode": result.returncode,
                "stdout": _redact_secrets(result.stdout, secrets),
                "stderr": _redact_secrets(result.stderr, secrets),
                "container_name": result.container_name,
                "timed_out": result.timed_out,
            },
        )


def _gateway_secrets(gateway_env: Mapping[str, str]) -> tuple[str, ...]:
    """Collect the scoped gateway token from the gateway env for redaction."""

    token = gateway_env.get(GATEWAY_TOKEN_ENV)
    return (token,) if token else ()


def _redact_secrets(text: str | None, secrets: Iterable[str]) -> str | None:
    """Replace each secret occurrence in captured output with a placeholder."""

    if not text:
        return text
    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, GATEWAY_TOKEN_REDACTION)
    return redacted


def _build_run_spec(context: AssignmentContext) -> DockerRunSpec:
    payload = context.assignment.payload or {}
    raw = payload.get(RUN_SPEC_PAYLOAD_KEY)
    if not isinstance(raw, Mapping):
        raise AssignmentExecutionError("assignment payload has no run_spec")
    image = raw.get("image")
    command = raw.get("command")
    if not image or not command:
        raise AssignmentExecutionError("run_spec requires image and command")

    env = {
        key: str(value)
        for key, value in dict(raw.get("env") or {}).items()
        if key not in _PROVIDER_KEY_ENV
    }
    env.update(context.gateway_env)

    gpu = context.assignment.required_capability == "gpu"
    limits = DockerLimits(gpu_count=int(raw.get("gpu_count", 1)) if gpu else None)
    return DockerRunSpec(
        image=str(image),
        command=tuple(str(part) for part in command),
        env=env,
        workdir=raw.get("workdir"),
        labels={"base.job": context.assignment.work_unit_id},
        limits=limits,
    )
