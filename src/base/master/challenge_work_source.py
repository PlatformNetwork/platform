"""Production HTTP implementations of the orchestration driver's challenge seams.

The live master driver (:mod:`base.master.orchestration`) is challenge-agnostic;
these adapters realize its :class:`ChallengeWorkSource` /
:class:`ChallengeFoldTrigger` protocols against the challenge services over their
internal-token-gated HTTP routes:

- ``GET /internal/v1/work_units`` exposes each challenge's currently-assignable
  pending work units (agent-challenge: one descriptor per selected task carrying
  ``job_id``/``task_id``; prism: one descriptor per submission carrying its
  resume ``checkpoint_ref`` in the payload).
- ``POST /internal/v1/work_units/fold`` folds a permanently-failed agent-challenge
  work unit back into its EvaluationJob.

The challenge base URL + bearer token are resolved from the master challenge
registry exactly as the weight-collection path does.
"""

from __future__ import annotations

import inspect
import logging
from typing import Any

import httpx

from base.master.orchestration import (
    WORK_UNIT_MAX_ATTEMPTS_REASON,
    ChallengePendingWork,
)

logger = logging.getLogger(__name__)

#: Payload key prism uses to carry a resume checkpoint to a reassigned unit.
RESUME_CHECKPOINT_PAYLOAD_KEY = "resume_checkpoint_ref"


async def _resolve(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


class HttpChallengeWorkSource:
    """Fetch pending work units from every active challenge over HTTP."""

    def __init__(
        self,
        registry: Any,
        *,
        timeout_seconds: float = 10.0,
        retries: int = 3,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._registry = registry
        self._timeout_seconds = timeout_seconds
        self._retries = retries
        self._transport = transport

    async def fetch_pending_work(self) -> list[ChallengePendingWork]:
        records = await _resolve(self._registry.list(active_only=True))
        works: list[ChallengePendingWork] = []
        for record in records:
            token = await _resolve(self._registry.get_token(record.slug))
            if not token:
                logger.warning(
                    "challenge %s has no token; skipping work-unit bridge",
                    record.slug,
                )
                continue
            payload = await self._fetch_work_units(
                slug=record.slug,
                base_url=record.internal_base_url,
                token=str(token),
            )
            if payload is None:
                continue
            works.extend(_parse_work_units(record.slug, payload))
        return works

    async def _fetch_work_units(
        self, *, slug: str, base_url: str, token: str
    ) -> dict[str, Any] | None:
        url = f"{base_url.rstrip('/')}/internal/v1/work_units"
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Base-Challenge-Slug": slug,
            "Accept": "application/json",
        }
        last_error = "unknown error"
        for _attempt in range(max(self._retries, 1)):
            try:
                async with httpx.AsyncClient(
                    timeout=self._timeout_seconds, transport=self._transport
                ) as client:
                    response = await client.get(url, headers=headers)
                    response.raise_for_status()
                    return dict(response.json())
            except Exception as exc:  # noqa: BLE001 - logged, retried, then skipped
                last_error = str(exc)
        logger.warning(
            "failed to fetch work units for challenge %s: %s", slug, last_error
        )
        return None


def _parse_work_units(slug: str, payload: dict[str, Any]) -> list[ChallengePendingWork]:
    """Map a challenge ``work_units`` response into bridgeable pending work.

    agent-challenge units (which carry ``task_id``/``job_id``) are grouped per
    ``(submission, job)`` into one cpu fan-out; prism units (one per submission)
    become a single gpu unit each, surfacing any resume checkpoint ref.
    """

    units = payload.get("work_units") or []
    agent_groups: dict[tuple[str, str], dict[str, Any]] = {}
    works: list[ChallengePendingWork] = []
    for unit in units:
        task_id = unit.get("task_id")
        job_id = unit.get("job_id")
        submission_id = str(unit.get("submission_id"))
        submission_ref = str(unit.get("submission_ref") or "")
        if task_id and job_id:
            key = (submission_id, str(job_id))
            group = agent_groups.get(key)
            if group is None:
                group = {
                    "submission_ref": submission_ref,
                    "task_ids": [],
                }
                agent_groups[key] = group
            group["task_ids"].append(str(task_id))
        else:
            unit_payload = dict(unit.get("payload") or {})
            checkpoint_ref = unit_payload.pop(RESUME_CHECKPOINT_PAYLOAD_KEY, None)
            works.append(
                ChallengePendingWork(
                    challenge_slug=slug,
                    submission_id=submission_id,
                    submission_ref=submission_ref,
                    task_ids=(),
                    checkpoint_ref=str(checkpoint_ref) if checkpoint_ref else None,
                    payload=unit_payload,
                )
            )
    for (submission_id, job_id), group in agent_groups.items():
        works.append(
            ChallengePendingWork(
                challenge_slug=slug,
                submission_id=submission_id,
                submission_ref=str(group["submission_ref"]),
                task_ids=tuple(group["task_ids"]),
                job_id=job_id,
            )
        )
    return works


class HttpChallengeFoldTrigger:
    """Fold a permanently-failed agent-challenge work unit over HTTP."""

    def __init__(
        self,
        registry: Any,
        *,
        timeout_seconds: float = 10.0,
        retries: int = 3,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._registry = registry
        self._timeout_seconds = timeout_seconds
        self._retries = retries
        self._transport = transport

    async def fold(
        self,
        *,
        challenge_slug: str,
        job_id: str,
        task_id: str,
        reason: str = WORK_UNIT_MAX_ATTEMPTS_REASON,
    ) -> None:
        record = await _resolve(self._registry.get(challenge_slug))
        token = await _resolve(self._registry.get_token(challenge_slug))
        if not token:
            raise RuntimeError(f"challenge {challenge_slug!r} has no token for fold")
        url = f"{record.internal_base_url.rstrip('/')}/internal/v1/work_units/fold"
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Base-Challenge-Slug": challenge_slug,
            "Accept": "application/json",
        }
        body = {"job_id": job_id, "task_id": task_id, "reason": reason}
        last_error = "unknown error"
        for _attempt in range(max(self._retries, 1)):
            try:
                async with httpx.AsyncClient(
                    timeout=self._timeout_seconds, transport=self._transport
                ) as client:
                    response = await client.post(url, json=body, headers=headers)
                    response.raise_for_status()
                return
            except Exception as exc:  # noqa: BLE001 - raised after retries exhausted
                last_error = str(exc)
        raise RuntimeError(
            f"failed to fold work unit {job_id}:{task_id} on {challenge_slug}: "
            f"{last_error}"
        )


__all__ = [
    "HttpChallengeFoldTrigger",
    "HttpChallengeWorkSource",
]
