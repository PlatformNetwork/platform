"""Validator agent runtime: the decentralized client-side executor.

A long-running loop that hotkey-registers + heartbeats with the master, pulls
assignments, executes them on its OWN broker + Docker, posts results, and routes
all LLM calls through the master gateway (holding no provider key).
"""

from __future__ import annotations

from base.validator.agent.challenge_dispatch import (
    DEFAULT_CHALLENGE_EXECUTOR_FACTORIES,
    ChallengeDispatchExecutor,
)
from base.validator.agent.coordination_client import (
    CoordinationClient,
    CoordinationClientError,
)
from base.validator.agent.executor import (
    GATEWAY_TOKEN_PAYLOAD_KEY,
    RUN_SPEC_PAYLOAD_KEY,
    AssignmentContext,
    AssignmentExecutionError,
    AssignmentExecutor,
    BrokerAssignmentExecutor,
    BrokerConfig,
    ExecutionResult,
    gateway_env_for_assignment,
)
from base.validator.agent.runtime import (
    AgentCycleSummary,
    BackoffPolicy,
    ValidatorAgent,
)
from base.validator.agent.signing import (
    KeypairRequestSigner,
    RequestSigner,
    build_signed_headers,
)

__all__ = [
    "GATEWAY_TOKEN_PAYLOAD_KEY",
    "RUN_SPEC_PAYLOAD_KEY",
    "DEFAULT_CHALLENGE_EXECUTOR_FACTORIES",
    "AgentCycleSummary",
    "AssignmentContext",
    "AssignmentExecutionError",
    "AssignmentExecutor",
    "BackoffPolicy",
    "BrokerAssignmentExecutor",
    "BrokerConfig",
    "ChallengeDispatchExecutor",
    "CoordinationClient",
    "CoordinationClientError",
    "ExecutionResult",
    "KeypairRequestSigner",
    "RequestSigner",
    "ValidatorAgent",
    "build_signed_headers",
    "gateway_env_for_assignment",
]
