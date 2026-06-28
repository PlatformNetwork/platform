"""prism validator-execution adapter (architecture sec 4, G2).

Dispatches a pulled prism assignment to the sibling package's decentralized GPU
re-execution cycle on the validator's OWN broker (``network=none``, concurrency
1). The sibling package's dispatch entrypoint is imported LAZILY so platform does
not hard-depend on ``prism_challenge``; an unavailable package surfaces a clear
:class:`AssignmentExecutionError` rather than a silent drop.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from base.validator.agent.executor import (
    AssignmentContext,
    AssignmentExecutionError,
    ExecutionResult,
    ProgressCallback,
)

CHALLENGE_SLUG = "prism"

#: Signature of the sibling package's dispatch entrypoint
#: (``prism_challenge.validator_dispatch.dispatch_assignment``).
DispatchFn = Callable[..., Awaitable[Mapping[str, Any]]]


class PrismCycleExecutor:
    """Run a pulled prism assignment via the sibling GPU re-execution cycle."""

    def __init__(self, *, dispatch: DispatchFn | None = None) -> None:
        self._dispatch = dispatch

    async def execute(
        self, context: AssignmentContext, *, progress: ProgressCallback
    ) -> ExecutionResult:
        dispatch = self._dispatch or _load_dispatch()
        broker = context.broker
        result = await dispatch(
            work_unit_id=context.assignment.work_unit_id,
            payload=dict(context.assignment.payload or {}),
            broker_url=broker.broker_url,
            broker_token=broker.broker_token,
            broker_token_file=broker.broker_token_file,
        )
        return ExecutionResult(success=True, payload=dict(result))


def _load_dispatch() -> DispatchFn:
    try:
        from prism_challenge.validator_dispatch import dispatch_assignment
    except Exception as exc:  # noqa: BLE001 - surfaced as a dispatch failure
        raise AssignmentExecutionError(
            f"prism dispatch adapter is unavailable: {exc}"
        ) from exc
    return dispatch_assignment


__all__ = ["CHALLENGE_SLUG", "PrismCycleExecutor"]
