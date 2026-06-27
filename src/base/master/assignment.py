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
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
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

#: Per-validator concurrency cap by required capability. prism (gpu) runs one
#: work unit per validator at a time (concurrency 1); cpu work is unbounded.
DEFAULT_CAPABILITY_CONCURRENCY: dict[str, int] = {CAPABILITY_GPU: 1}

_ACTIVE_STATUSES = (WorkAssignmentStatus.ASSIGNED, WorkAssignmentStatus.RUNNING)


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

    async def assign_pending(self, *, seed: int | None = None) -> dict[str, str]:
        """Assign pending work units across eligible ONLINE validators.

        Distribution is balanced (least-loaded first) with seeded-random
        tie-breaking, so a fixed ``seed`` + identical inputs yields an identical
        ``{work_unit_id: validator_hotkey}`` mapping. Capability-aware:
        ``gpu`` units only go to gpu validators; ``cpu`` units go to cpu
        validators (and to gpu validators when ``gpu_serves_cpu`` is set). A
        unit with no eligible validator is left ``pending``.
        """

        rng = random.Random(seed)
        assigned: dict[str, str] = {}
        async with session_scope(self._session_factory) as session:
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

            inflight = (
                (
                    await session.execute(
                        select(WorkAssignment).where(
                            WorkAssignment.status.in_(_ACTIVE_STATUSES),
                            WorkAssignment.assigned_validator_hotkey.is_not(None),
                        )
                    )
                )
                .scalars()
                .all()
            )
            for unit in inflight:
                hotkey = unit.assigned_validator_hotkey
                if hotkey is None:
                    continue
                if hotkey in load:
                    load[hotkey] += 1
                key = (hotkey, unit.required_capability)
                cap_load[key] = cap_load.get(key, 0) + 1

            pending = list(
                (
                    await session.execute(
                        select(WorkAssignment)
                        .where(WorkAssignment.status == WorkAssignmentStatus.PENDING)
                        .order_by(
                            WorkAssignment.created_at, WorkAssignment.work_unit_id
                        )
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
                cap_load[(chosen, capability)] = (
                    cap_load.get((chosen, capability), 0) + 1
                )
                assigned[unit.work_unit_id] = chosen

        return assigned

    def _capability_matches(self, required: str, capabilities: set[str]) -> bool:
        if required == CAPABILITY_GPU:
            return CAPABILITY_GPU in capabilities
        if required == CAPABILITY_CPU:
            if CAPABILITY_CPU in capabilities:
                return True
            return self._gpu_serves_cpu and CAPABILITY_GPU in capabilities
        return required in capabilities
