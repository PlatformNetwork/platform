"""Challenge-aware assignment executor for the validator agent (architecture sec 4, G2).

The decentralized validator pulls a work unit from the master coordination plane
and must actually run it on its OWN broker. The chosen G2 path (option b,
architecture.md sec 4) dispatches each pulled assignment to the per-challenge
validator execution cycle selected by ``challenge_slug``:

- ``agent-challenge`` -> ``agent_challenge`` runs Terminal-Bench 2.1 ``own_runner``
  CPU containers on the validator's broker (per-task, idempotent).
- ``prism`` -> ``prism_challenge`` runs the GPU re-execution (``network=none``,
  only the locked train split + writable artifacts mounted, concurrency 1).

Why dispatch (not a master-emitted ``run_spec``): the concrete container shape,
the miner artifact load, and the idempotent result posting all live inside the
sibling challenge packages (DB-/artifact-coupled). The master is a coordinator
and cannot synthesize a complete per-challenge run spec. The challenge cycles
already build the correct spec and dispatch to the validator's own broker.

Platform stays decoupled from the sibling packages: each per-slug adapter imports
its sibling package LAZILY (only when a matching assignment is dispatched) and can
be overridden in tests. A slug that instead ships a generic ``run_spec`` in its
payload still runs through :class:`BrokerAssignmentExecutor`.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping

from base.validator.agent.adapters import (
    AgentChallengeCycleExecutor,
    PrismCycleExecutor,
)
from base.validator.agent.executor import (
    RUN_SPEC_PAYLOAD_KEY,
    AssignmentContext,
    AssignmentExecutionError,
    AssignmentExecutor,
    BrokerAssignmentExecutor,
    ExecutionResult,
    ProgressCallback,
)

logger = logging.getLogger(__name__)

#: Per-slug adapter factories. Each builds an :class:`AssignmentExecutor` that
#: imports its sibling challenge package lazily on first dispatch.
DEFAULT_CHALLENGE_EXECUTOR_FACTORIES: dict[str, Callable[[], AssignmentExecutor]] = {
    "agent-challenge": AgentChallengeCycleExecutor,
    "prism": PrismCycleExecutor,
}


class ChallengeDispatchExecutor:
    """Dispatch a pulled assignment to its per-challenge execution cycle.

    Resolution order for a given ``challenge_slug``:

    1. an executor registered explicitly via :meth:`register` (used by tests and
       by a deployment that wires adapters in-process);
    2. the per-slug adapter built from
       :data:`DEFAULT_CHALLENGE_EXECUTOR_FACTORIES`;
    3. the generic :class:`BrokerAssignmentExecutor` -- ONLY when the assignment
       payload carries a ``run_spec`` (e.g. a template-generated challenge).

    A slug with no resolvable executor and no ``run_spec`` raises
    :class:`AssignmentExecutionError` with a clear message rather than silently
    succeeding, so a misconfigured validator surfaces the gap instead of dropping
    work.
    """

    def __init__(
        self,
        *,
        executors: Mapping[str, AssignmentExecutor] | None = None,
        factories: Mapping[str, Callable[[], AssignmentExecutor]] | None = None,
        generic: AssignmentExecutor | None = None,
    ) -> None:
        self._explicit: dict[str, AssignmentExecutor] = dict(executors or {})
        self._factories: dict[str, Callable[[], AssignmentExecutor]] = dict(
            DEFAULT_CHALLENGE_EXECUTOR_FACTORIES if factories is None else factories
        )
        self._generic: AssignmentExecutor = generic or BrokerAssignmentExecutor()
        self._resolved: dict[str, AssignmentExecutor] = {}

    def register(self, slug: str, executor: AssignmentExecutor) -> None:
        """Register an explicit per-slug executor (highest precedence)."""

        self._explicit[slug] = executor
        self._resolved.pop(slug, None)

    async def execute(
        self, context: AssignmentContext, *, progress: ProgressCallback
    ) -> ExecutionResult:
        slug = context.assignment.challenge_slug
        executor = self._resolve(slug)
        if executor is not None:
            return await executor.execute(context, progress=progress)
        payload = context.assignment.payload or {}
        if RUN_SPEC_PAYLOAD_KEY in payload:
            return await self._generic.execute(context, progress=progress)
        raise AssignmentExecutionError(
            f"no challenge executor registered for slug {slug!r} and assignment "
            "payload has no run_spec"
        )

    def _resolve(self, slug: str) -> AssignmentExecutor | None:
        if slug in self._explicit:
            return self._explicit[slug]
        if slug in self._resolved:
            return self._resolved[slug]
        factory = self._factories.get(slug)
        if factory is None:
            return None
        executor = factory()
        self._resolved[slug] = executor
        return executor


__all__ = [
    "DEFAULT_CHALLENGE_EXECUTOR_FACTORIES",
    "ChallengeDispatchExecutor",
]
