"""Random, balanced, capability-aware work assignment for the master.

The master coordinates evaluation work but never executes it. Submissions are
fanned out into ``work_assignments`` rows (agent-challenge: one work unit per
selected task; prism: exactly one work unit per submission) and a balanced,
seeded-random, capability-aware pass assigns pending units to ONLINE validators
of the matching capability. Offline/ineligible validators never receive work;
a unit with no eligible validator stays ``pending`` (it is never lost).
"""

from __future__ import annotations

import random
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from base.db.models import (
    Validator,
    ValidatorStatus,
    WorkAssignment,
    WorkAssignmentStatus,
)
from base.db.session import session_scope

CAPABILITY_CPU = "cpu"
CAPABILITY_GPU = "gpu"

AGENT_CHALLENGE_SLUG = "agent-challenge"
PRISM_SLUG = "prism"

DEFAULT_MAX_ATTEMPTS = 3

#: Payload marker set on a terminally-``failed`` work unit once it has been
#: successfully folded back into its challenge EvaluationJob, so a durable
#: re-fold sweep skips it (architecture.md sec 4, durable fold).
FOLDED_PAYLOAD_KEY = "folded"

#: Payload marker set on a terminally-``failed`` work unit that can NEVER be
#: folded because it permanently lacks the ``job_id``/``task_id`` needed for the
#: challenge-side fold. The durable re-fold sweep skips it so an un-foldable unit
#: is not re-fetched and re-warned on every pass (it is distinct from
#: :data:`FOLDED_PAYLOAD_KEY`, which marks a unit that WAS folded).
FOLD_SKIPPED_PAYLOAD_KEY = "fold_skipped"

#: Per-validator concurrency cap by required capability. prism (gpu) runs one
#: work unit per validator at a time (concurrency 1); cpu work is unbounded.
DEFAULT_CAPABILITY_CONCURRENCY: dict[str, int] = {CAPABILITY_GPU: 1}

_ACTIVE_STATUSES = (WorkAssignmentStatus.ASSIGNED, WorkAssignmentStatus.RUNNING)

#: Payload key carrying the resume checkpoint ref to a reassigned prism unit so
#: the new validator resumes from the last public HF checkpoint (architecture
#: sec 3.3 / 4) rather than restarting from scratch.
RESUME_CHECKPOINT_PAYLOAD_KEY = "resume_checkpoint_ref"


@dataclass(frozen=True)
class ReclaimOutcome:
    """Result of a reclaim pass over stale/offline in-flight work units.

    ``reverted`` holds the work-unit ids returned to the pending pool for
    reassignment; ``failed`` holds the ids terminally failed because their
    retries were exhausted (``attempt_count`` reached ``max_attempts``).
    """

    reverted: list[str]
    failed: list[str]


@dataclass(frozen=True)
class FailedWorkUnit:
    """Detached descriptor of a terminally-``failed`` work unit.

    Carries the challenge slug, work-unit id, and the unit's payload (e.g. the
    agent-challenge ``job_id``/``task_id``) so the orchestration driver can fold
    the permanently-failed unit on the challenge side without holding an ORM row
    across a session boundary.
    """

    challenge_slug: str
    work_unit_id: str
    payload: dict[str, Any]


def capability_matches(
    required: str, capabilities: set[str], *, gpu_serves_cpu: bool = True
) -> bool:
    """Whether a validator advertising ``capabilities`` can run ``required``.

    ``gpu`` work only matches gpu validators; ``cpu`` work matches cpu
    validators and (when ``gpu_serves_cpu``) gpu validators too. Any other
    capability matches an exactly-advertised capability.
    """

    if required == CAPABILITY_GPU:
        return CAPABILITY_GPU in capabilities
    if required == CAPABILITY_CPU:
        if CAPABILITY_CPU in capabilities:
            return True
        return gpu_serves_cpu and CAPABILITY_GPU in capabilities
    return required in capabilities


class AssignmentService:
    """Create work units and assign pending ones across online validators."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        now_fn: Callable[[], datetime] = lambda: datetime.now(UTC),
        gpu_serves_cpu: bool = True,
        capability_concurrency: Mapping[str, int] | None = None,
        default_max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    ) -> None:
        self._session_factory = session_factory
        self._now_fn = now_fn
        self._gpu_serves_cpu = gpu_serves_cpu
        self._capability_concurrency = dict(
            DEFAULT_CAPABILITY_CONCURRENCY
            if capability_concurrency is None
            else capability_concurrency
        )
        self._default_max_attempts = default_max_attempts

    async def create_agent_challenge_work_units(
        self,
        *,
        submission_id: str,
        submission_ref: str,
        task_ids: list[str],
        payload: Mapping[str, Any] | None = None,
        max_attempts: int | None = None,
        challenge_slug: str = AGENT_CHALLENGE_SLUG,
    ) -> list[str]:
        """Fan a submission's selected tasks out into one pending unit per task.

        Each task becomes a ``cpu`` work unit with ``work_unit_id`` of
        ``{submission_id}:{task_id}``. Idempotent: tasks that already have a
        unit for this challenge are skipped. Returns the work-unit ids created
        by this call.
        """

        now = self._now_fn()
        max_att = self._default_max_attempts if max_attempts is None else max_attempts
        target = [(tid, f"{submission_id}:{tid}") for tid in task_ids]
        created: list[str] = []
        async with session_scope(self._session_factory) as session:
            existing = set(
                (
                    await session.execute(
                        select(WorkAssignment.work_unit_id).where(
                            WorkAssignment.challenge_slug == challenge_slug,
                            WorkAssignment.work_unit_id.in_(
                                [work_unit_id for _, work_unit_id in target]
                            ),
                        )
                    )
                )
                .scalars()
                .all()
            )
            for task_id, work_unit_id in target:
                if work_unit_id in existing:
                    continue
                unit_payload = dict(payload or {})
                unit_payload.setdefault("task_id", task_id)
                session.add(
                    WorkAssignment(
                        challenge_slug=challenge_slug,
                        work_unit_id=work_unit_id,
                        submission_ref=submission_ref,
                        payload=unit_payload,
                        required_capability=CAPABILITY_CPU,
                        status=WorkAssignmentStatus.PENDING,
                        attempt_count=0,
                        max_attempts=max_att,
                        created_at=now,
                        updated_at=now,
                    )
                )
                created.append(work_unit_id)
        return created

    async def create_prism_work_unit(
        self,
        *,
        submission_id: str,
        submission_ref: str,
        payload: Mapping[str, Any] | None = None,
        checkpoint_ref: str | None = None,
        max_attempts: int | None = None,
        challenge_slug: str = PRISM_SLUG,
    ) -> str:
        """Create exactly one ``gpu`` work unit for a prism submission.

        ``work_unit_id`` is the submission id. Idempotent: a submission that
        already has a unit returns the existing id without creating a second
        (one submission -> one unit -> one validator, concurrency 1).
        """

        now = self._now_fn()
        max_att = self._default_max_attempts if max_attempts is None else max_attempts
        work_unit_id = str(submission_id)
        async with session_scope(self._session_factory) as session:
            existing = (
                await session.execute(
                    select(WorkAssignment).where(
                        WorkAssignment.challenge_slug == challenge_slug,
                        WorkAssignment.work_unit_id == work_unit_id,
                    )
                )
            ).scalar_one_or_none()
            if existing is not None:
                return existing.work_unit_id
            session.add(
                WorkAssignment(
                    challenge_slug=challenge_slug,
                    work_unit_id=work_unit_id,
                    submission_ref=submission_ref,
                    payload=dict(payload or {}),
                    required_capability=CAPABILITY_GPU,
                    status=WorkAssignmentStatus.PENDING,
                    attempt_count=0,
                    max_attempts=max_att,
                    checkpoint_ref=checkpoint_ref,
                    created_at=now,
                    updated_at=now,
                )
            )
        return work_unit_id

    def transaction(self) -> AbstractAsyncContextManager[AsyncSession]:
        """Open a single committed transaction over the control-plane DB.

        Used to compose the full reassignment pass (detect -> reclaim -> assign)
        into one atomic transaction instead of three separate ones.
        """

        return session_scope(self._session_factory)

    async def assign_pending(
        self, *, seed: int | None = None, session: AsyncSession | None = None
    ) -> dict[str, str]:
        """Assign pending work units across eligible ONLINE validators.

        Distribution is balanced (least-loaded first) with seeded-random
        tie-breaking, so a fixed ``seed`` + identical inputs yields an identical
        ``{work_unit_id: validator_hotkey}`` mapping. Capability-aware:
        ``gpu`` units only go to gpu validators; ``cpu`` units go to cpu
        validators (and to gpu validators when ``gpu_serves_cpu`` is set). A
        unit with no eligible validator is left ``pending``.

        When ``session`` is provided the work runs inside the caller's
        transaction (the caller commits); otherwise a fresh transaction is
        opened and committed here.
        """

        if session is not None:
            return await self._assign_pending_in_session(session, seed=seed)
        async with session_scope(self._session_factory) as own_session:
            return await self._assign_pending_in_session(own_session, seed=seed)

    async def _assign_pending_in_session(
        self, session: AsyncSession, *, seed: int | None
    ) -> dict[str, str]:
        rng = random.Random(seed)
        assigned: dict[str, str] = {}
        online = list(
            (
                await session.execute(
                    select(Validator)
                    .where(Validator.status == ValidatorStatus.ONLINE)
                    .order_by(Validator.hotkey)
                )
            )
            .scalars()
            .all()
        )
        if not online:
            return {}

        caps_by_hotkey = {v.hotkey: set(v.capabilities) for v in online}
        hotkeys = [v.hotkey for v in online]
        load = {hotkey: 0 for hotkey in hotkeys}
        cap_load: dict[tuple[str, str], int] = {}

        inflight_counts = (
            await session.execute(
                select(
                    WorkAssignment.assigned_validator_hotkey,
                    WorkAssignment.required_capability,
                    func.count(),
                )
                .where(
                    WorkAssignment.status.in_(_ACTIVE_STATUSES),
                    WorkAssignment.assigned_validator_hotkey.is_not(None),
                )
                .group_by(
                    WorkAssignment.assigned_validator_hotkey,
                    WorkAssignment.required_capability,
                )
            )
        ).all()
        for hotkey, capability, count in inflight_counts:
            if hotkey is None:
                continue
            if hotkey in load:
                load[hotkey] += count
            key = (hotkey, capability)
            cap_load[key] = cap_load.get(key, 0) + count

        pending = list(
            (
                await session.execute(
                    select(WorkAssignment)
                    .where(WorkAssignment.status == WorkAssignmentStatus.PENDING)
                    .order_by(WorkAssignment.created_at, WorkAssignment.work_unit_id)
                )
            )
            .scalars()
            .all()
        )

        for unit in pending:
            capability = unit.required_capability
            limit = self._capability_concurrency.get(capability)
            eligible = [
                hotkey
                for hotkey in hotkeys
                if self._capability_matches(capability, caps_by_hotkey[hotkey])
                and (limit is None or cap_load.get((hotkey, capability), 0) < limit)
            ]
            if not eligible:
                continue

            min_load = min(load[hotkey] for hotkey in eligible)
            candidates = sorted(
                hotkey for hotkey in eligible if load[hotkey] == min_load
            )
            chosen = rng.choice(candidates)

            unit.assigned_validator_hotkey = chosen
            unit.status = WorkAssignmentStatus.ASSIGNED
            unit.attempt_count = (unit.attempt_count or 0) + 1
            load[chosen] += 1
            cap_load[(chosen, capability)] = cap_load.get((chosen, capability), 0) + 1
            assigned[unit.work_unit_id] = chosen

        await session.flush()
        return assigned

    async def reclaim_stale_assignments(
        self, *, session: AsyncSession | None = None
    ) -> ReclaimOutcome:
        """Revert in-flight work whose validator is offline or lease expired.

        A unit is reassignable when its assigned validator is offline/unknown OR
        its ``deadline_at`` is in the past. Reassignable units are returned to
        the pending pool (``assigned_validator_hotkey`` cleared, lease cleared)
        UNLESS their retries are exhausted (``attempt_count >= max_attempts``),
        in which case they are terminally marked ``failed`` so retries are
        bounded and never loop forever. The reverted unit keeps its
        ``checkpoint_ref`` and surfaces it under
        :data:`RESUME_CHECKPOINT_PAYLOAD_KEY` so a reassigned prism validator can
        resume from the last public HF checkpoint. ``attempt_count`` is not
        touched here; the subsequent :meth:`assign_pending` increments it as part
        of the reassignment.

        When ``session`` is provided the work runs inside the caller's
        transaction; otherwise a fresh transaction is opened and committed here.
        """

        if session is not None:
            return await self._reclaim_in_session(session)
        async with session_scope(self._session_factory) as own_session:
            return await self._reclaim_in_session(own_session)

    async def _reclaim_in_session(self, session: AsyncSession) -> ReclaimOutcome:
        now = self._now_fn()
        reverted: list[str] = []
        failed: list[str] = []
        online = set(
            (
                await session.execute(
                    select(Validator.hotkey).where(
                        Validator.status == ValidatorStatus.ONLINE
                    )
                )
            )
            .scalars()
            .all()
        )

        inflight = (
            (
                await session.execute(
                    select(WorkAssignment).where(
                        WorkAssignment.status.in_(_ACTIVE_STATUSES)
                    )
                )
            )
            .scalars()
            .all()
        )

        for unit in inflight:
            hotkey = unit.assigned_validator_hotkey
            validator_offline = hotkey is None or hotkey not in online
            deadline = unit.deadline_at
            if deadline is not None and deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=UTC)
            deadline_passed = deadline is not None and deadline < now
            if not (validator_offline or deadline_passed):
                continue

            if (unit.attempt_count or 0) >= unit.max_attempts:
                unit.status = WorkAssignmentStatus.FAILED
                unit.last_progress_at = now
                failed.append(unit.work_unit_id)
                continue

            unit.status = WorkAssignmentStatus.PENDING
            unit.assigned_validator_hotkey = None
            unit.deadline_at = None
            if unit.checkpoint_ref is not None:
                payload = dict(unit.payload or {})
                payload[RESUME_CHECKPOINT_PAYLOAD_KEY] = unit.checkpoint_ref
                unit.payload = payload
            reverted.append(unit.work_unit_id)

        await session.flush()
        return ReclaimOutcome(reverted=reverted, failed=failed)

    async def get_unfolded_failed_work_units(
        self, *, challenge_slug: str = AGENT_CHALLENGE_SLUG
    ) -> list[FailedWorkUnit]:
        """Return still-``failed`` units of ``challenge_slug`` not yet folded.

        Backs the orchestration driver's durable re-fold sweep: every pass it
        re-attempts to fold any terminally-``failed`` unit that has not been
        marked folded (e.g. because a prior fold POST failed during a challenge
        outage), so a permanently-failed unit's EvaluationJob never hangs
        forever waiting for a result that will never come. Units flagged
        :data:`FOLD_SKIPPED_PAYLOAD_KEY` (permanently un-foldable) are excluded
        too so they are not re-fetched and re-warned every pass.
        """

        async with session_scope(self._session_factory) as session:
            rows = (
                (
                    await session.execute(
                        select(WorkAssignment).where(
                            WorkAssignment.challenge_slug == challenge_slug,
                            WorkAssignment.status == WorkAssignmentStatus.FAILED,
                        )
                    )
                )
                .scalars()
                .all()
            )
            return [
                FailedWorkUnit(
                    challenge_slug=row.challenge_slug,
                    work_unit_id=row.work_unit_id,
                    payload=dict(row.payload or {}),
                )
                for row in rows
                if not (row.payload or {}).get(FOLDED_PAYLOAD_KEY)
                and not (row.payload or {}).get(FOLD_SKIPPED_PAYLOAD_KEY)
            ]

    async def mark_work_units_folded(self, work_unit_ids: Sequence[str]) -> None:
        """Mark terminally-``failed`` units as folded so the sweep skips them.

        Sets :data:`FOLDED_PAYLOAD_KEY` on each still-``failed`` unit; only units
        currently in ``failed`` are touched so a since-recreated unit with the
        same id is never marked.
        """

        await self._set_failed_payload_flag(work_unit_ids, FOLDED_PAYLOAD_KEY)

    async def mark_work_units_fold_skipped(self, work_unit_ids: Sequence[str]) -> None:
        """Mark terminally-``failed`` units as permanently un-foldable.

        Sets :data:`FOLD_SKIPPED_PAYLOAD_KEY` on each still-``failed`` unit so the
        durable re-fold sweep no longer returns it (and no longer re-warns about
        it) every pass; only units currently in ``failed`` are touched.
        """

        await self._set_failed_payload_flag(work_unit_ids, FOLD_SKIPPED_PAYLOAD_KEY)

    async def _set_failed_payload_flag(
        self, work_unit_ids: Sequence[str], key: str
    ) -> None:
        ids = list(work_unit_ids)
        if not ids:
            return
        async with session_scope(self._session_factory) as session:
            rows = (
                (
                    await session.execute(
                        select(WorkAssignment).where(
                            WorkAssignment.work_unit_id.in_(ids),
                            WorkAssignment.status == WorkAssignmentStatus.FAILED,
                        )
                    )
                )
                .scalars()
                .all()
            )
            for row in rows:
                payload = dict(row.payload or {})
                payload[key] = True
                row.payload = payload

    def _capability_matches(self, required: str, capabilities: set[str]) -> bool:
        return capability_matches(
            required, capabilities, gpu_serves_cpu=self._gpu_serves_cpu
        )
