"""Live master orchestration driver (architecture.md sec 4, "Master orchestration").

The master is autonomous in production: a background driver periodically

1. bridges each challenge's gated *pending work units* into ``work_assignments``
   (agent-challenge: one cpu unit per selected task; prism: exactly one gpu unit
   per submission), then
2. runs the full reassignment pass (``detect_offline`` -> reclaim
   stale/deadline-expired in-flight units -> ``assign_pending``), so newly
   eligible work and newly-online validators get balanced assignments and
   crashed/expired work is reclaimed and reassigned without any manual trigger,
   then
3. folds permanently-failed (retry-exhausted, ``attempt_count == max_attempts``)
   agent-challenge work units on the challenge side so their evaluation jobs
   finalize instead of hanging forever waiting for a result that will never
   come. The fold is a durable sweep over still-failed-but-unfolded units, so a
   fold that fails during a challenge outage is retried on a later pass.

The source of challenge pending work and the challenge-side fold are abstracted
behind :class:`ChallengeWorkSource` / :class:`ChallengeFoldTrigger` so they can
be mocked in tests; the production HTTP implementations live in
:mod:`base.master.challenge_work_source`.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Protocol

from fastapi import FastAPI

from base.master.assignment import (
    AGENT_CHALLENGE_SLUG,
    AssignmentService,
)
from base.master.reassignment import ReassignmentPassResult, run_reassignment_pass
from base.master.validator_coordination import ValidatorCoordinationService

logger = logging.getLogger(__name__)

#: Payload keys the driver stamps onto bridged agent-challenge work units so a
#: permanently-failed unit can be folded back into its EvaluationJob. ``task_id``
#: is already stamped per-unit by ``create_agent_challenge_work_units``.
PAYLOAD_JOB_ID_KEY = "job_id"
PAYLOAD_TASK_ID_KEY = "task_id"

#: Reason recorded when the driver folds a retry-exhausted work unit (kept in
#: sync with agent-challenge ``WORK_UNIT_MAX_ATTEMPTS_REASON``).
WORK_UNIT_MAX_ATTEMPTS_REASON = "work_unit_max_attempts_exhausted"


@dataclass(frozen=True)
class ChallengePendingWork:
    """A challenge submission's pending work to bridge into ``work_assignments``.

    A unit with non-empty ``task_ids`` is fanned out into one cpu work unit per
    task (agent-challenge); otherwise it becomes exactly one gpu work unit for
    the submission (prism). ``job_id`` is the agent-challenge EvaluationJob id,
    stamped into each unit's payload so a retry-exhausted unit can be folded.
    ``checkpoint_ref`` is the prism resume checkpoint.
    """

    challenge_slug: str
    submission_id: str
    submission_ref: str
    task_ids: tuple[str, ...] = ()
    job_id: str | None = None
    checkpoint_ref: str | None = None
    payload: Mapping[str, Any] = field(default_factory=dict)


class ChallengeWorkSource(Protocol):
    """Source of each challenge's currently-assignable pending work units."""

    async def fetch_pending_work(self) -> Sequence[ChallengePendingWork]: ...


class ChallengeFoldTrigger(Protocol):
    """Challenge-side trigger to fold a permanently-failed work unit.

    The master calls this when a unit exhausts ``max_attempts`` so the challenge
    records the failed task once and its EvaluationJob can finalize.
    """

    async def fold(
        self,
        *,
        challenge_slug: str,
        job_id: str,
        task_id: str,
        reason: str,
    ) -> None: ...


@dataclass(frozen=True)
class OrchestrationPassResult:
    """Observable outcome of one orchestration pass."""

    #: slug -> work-unit ids bridged this pass (agent-challenge: newly created;
    #: prism: the submission's unit ensured present).
    bridged: dict[str, list[str]]
    reassignment: ReassignmentPassResult
    #: work-unit ids of agent-challenge units folded this pass (newly failed, or
    #: re-folded after a prior fold attempt failed).
    folded: list[str]


class MasterOrchestrationDriver:
    """Bridge pending work, run assignment + reassignment, and fold dead units."""

    def __init__(
        self,
        *,
        assignment_service: AssignmentService,
        validator_service: ValidatorCoordinationService,
        work_source: ChallengeWorkSource,
        fold_trigger: ChallengeFoldTrigger | None = None,
        seed: int | None = None,
    ) -> None:
        self._assignment_service = assignment_service
        self._validator_service = validator_service
        self._work_source = work_source
        self._fold_trigger = fold_trigger
        self._seed = seed

    async def bridge_pending_work(self) -> dict[str, list[str]]:
        """Create ``work_assignments`` rows from challenge pending work units.

        Idempotent: a unit that already exists is skipped (the underlying
        creators upsert on ``(challenge_slug, work_unit_id)``).
        """

        works = await self._work_source.fetch_pending_work()
        bridged: dict[str, list[str]] = {}
        for work in works:
            if work.task_ids:
                payload = dict(work.payload)
                if work.job_id is not None:
                    payload[PAYLOAD_JOB_ID_KEY] = work.job_id
                created = (
                    await self._assignment_service.create_agent_challenge_work_units(
                        submission_id=work.submission_id,
                        submission_ref=work.submission_ref,
                        task_ids=list(work.task_ids),
                        payload=payload,
                        challenge_slug=work.challenge_slug,
                    )
                )
                if created:
                    bridged.setdefault(work.challenge_slug, []).extend(created)
            else:
                payload = dict(work.payload)
                if work.job_id is not None:
                    payload[PAYLOAD_JOB_ID_KEY] = work.job_id
                work_unit_id = await self._assignment_service.create_prism_work_unit(
                    submission_id=work.submission_id,
                    submission_ref=work.submission_ref,
                    payload=payload,
                    checkpoint_ref=work.checkpoint_ref,
                    challenge_slug=work.challenge_slug,
                )
                bridged.setdefault(work.challenge_slug, []).append(work_unit_id)
        return bridged

    async def run_once(self) -> OrchestrationPassResult:
        """Bridge pending work, run the reassignment pass, then fold dead units."""

        bridged = await self.bridge_pending_work()
        reassignment = await run_reassignment_pass(
            validator_service=self._validator_service,
            assignment_service=self._assignment_service,
            seed=self._seed,
        )
        folded = await self._fold_failed()
        return OrchestrationPassResult(
            bridged=bridged,
            reassignment=reassignment,
            folded=folded,
        )

    async def _fold_failed(self) -> list[str]:
        """Durably fold every still-failed, unfolded agent-challenge unit.

        A unit terminally ``failed`` after ``max_attempts`` never produces a
        validator-reported result, which would otherwise hang its EvaluationJob
        forever. Rather than fold only the units that flipped to ``failed`` in
        the current pass, this sweeps ALL agent-challenge units currently in
        ``failed`` that have not yet been folded and (re)attempts the fold. A
        fold that fails (e.g. a sustained challenge outage past its in-call HTTP
        retry budget) leaves the unit unmarked, so it is retried on the next
        pass; a successful fold marks the unit folded so it is not folded again
        (the fold is also idempotent on the challenge side).
        """

        if self._fold_trigger is None:
            return []
        failed = await self._assignment_service.get_unfolded_failed_work_units()
        folded: list[str] = []
        for unit in failed:
            if unit.challenge_slug != AGENT_CHALLENGE_SLUG:
                continue
            job_id = unit.payload.get(PAYLOAD_JOB_ID_KEY)
            task_id = unit.payload.get(PAYLOAD_TASK_ID_KEY)
            if not job_id or not task_id:
                logger.warning(
                    "cannot fold failed work unit %s: missing job_id/task_id",
                    unit.work_unit_id,
                )
                continue
            try:
                await self._fold_trigger.fold(
                    challenge_slug=unit.challenge_slug,
                    job_id=str(job_id),
                    task_id=str(task_id),
                    reason=WORK_UNIT_MAX_ATTEMPTS_REASON,
                )
            except Exception:
                logger.exception(
                    "failed to fold permanently-failed work unit %s",
                    unit.work_unit_id,
                )
                continue
            folded.append(unit.work_unit_id)
        if folded:
            await self._assignment_service.mark_work_units_folded(folded)
        return folded


async def run_orchestration_loop(
    driver: MasterOrchestrationDriver,
    *,
    interval_seconds: float,
    shutdown_event: asyncio.Event,
) -> None:
    """Run :meth:`MasterOrchestrationDriver.run_once` until shutdown.

    A failing pass is logged and the loop continues, so one transient error
    never stops autonomous assignment/reassignment.
    """

    while not shutdown_event.is_set():
        try:
            await driver.run_once()
        except Exception:
            logger.exception("master orchestration pass failed")
        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=interval_seconds)
        except TimeoutError:
            continue


def build_master_orchestration_lifespan(
    driver: MasterOrchestrationDriver | None,
    interval_seconds: float | None,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]] | None:
    """Build a FastAPI lifespan that runs the orchestration loop.

    Returns ``None`` (no lifespan) when the driver is not configured or the
    interval is non-positive.
    """

    if driver is None or interval_seconds is None or interval_seconds <= 0:
        return None

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> Any:
        shutdown = asyncio.Event()
        task = asyncio.create_task(
            run_orchestration_loop(
                driver,
                interval_seconds=interval_seconds,
                shutdown_event=shutdown,
            )
        )
        try:
            yield
        finally:
            shutdown.set()
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    return lifespan


__all__ = [
    "ChallengeFoldTrigger",
    "ChallengePendingWork",
    "ChallengeWorkSource",
    "MasterOrchestrationDriver",
    "OrchestrationPassResult",
    "WORK_UNIT_MAX_ATTEMPTS_REASON",
    "build_master_orchestration_lifespan",
    "run_orchestration_loop",
]
