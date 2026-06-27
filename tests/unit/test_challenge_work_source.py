"""Tests for the production HTTP challenge work source + fold trigger.

These adapters realize the orchestration driver's :class:`ChallengeWorkSource` /
:class:`ChallengeFoldTrigger` protocols against the challenge services'
``GET /internal/v1/work_units`` and ``POST /internal/v1/work_units/fold`` routes.
HTTP is exercised with an in-process :class:`httpx.MockTransport`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import httpx
import pytest

from base.master.challenge_work_source import (
    HttpChallengeFoldTrigger,
    HttpChallengeWorkSource,
    _parse_work_units,
)


@dataclass
class _Record:
    slug: str
    internal_base_url: str


class _FakeRegistry:
    """Minimal challenge registry slice the HTTP adapters depend on."""

    def __init__(self, records: list[_Record], tokens: dict[str, str]) -> None:
        self._records = records
        self._tokens = tokens

    async def list(self, *, active_only: bool = False) -> list[_Record]:
        return list(self._records)

    async def get(self, slug: str) -> _Record:
        for record in self._records:
            if record.slug == slug:
                return record
        raise KeyError(slug)

    async def get_token(self, slug: str) -> str:
        return self._tokens.get(slug, "")


# --------------------------------------------------------------------------- #
# Pure response parsing
# --------------------------------------------------------------------------- #
def test_parse_groups_agent_challenge_tasks_per_job() -> None:
    payload = {
        "challenge_slug": "agent-challenge",
        "work_units": [
            {
                "work_unit_id": "7:t1",
                "submission_id": 7,
                "submission_ref": "agent-hash",
                "job_id": "job-1",
                "task_id": "t1",
                "required_capability": "cpu",
            },
            {
                "work_unit_id": "7:t2",
                "submission_id": 7,
                "submission_ref": "agent-hash",
                "job_id": "job-1",
                "task_id": "t2",
                "required_capability": "cpu",
            },
        ],
    }
    works = _parse_work_units("agent-challenge", payload)
    assert len(works) == 1
    work = works[0]
    assert work.challenge_slug == "agent-challenge"
    assert work.submission_id == "7"
    assert work.submission_ref == "agent-hash"
    assert set(work.task_ids) == {"t1", "t2"}
    assert work.job_id == "job-1"


def test_parse_prism_unit_surfaces_checkpoint_ref() -> None:
    payload = {
        "challenge_slug": "prism",
        "work_units": [
            {
                "work_unit_id": "psub-1",
                "submission_id": "psub-1",
                "submission_ref": "miner-hk",
                "required_capability": "gpu",
                "payload": {"resume_checkpoint_ref": "hf://ckpt/step-9"},
            }
        ],
    }
    works = _parse_work_units("prism", payload)
    assert len(works) == 1
    work = works[0]
    assert work.task_ids == ()
    assert work.checkpoint_ref == "hf://ckpt/step-9"
    # The resume key is consumed into checkpoint_ref, not duplicated in payload.
    assert "resume_checkpoint_ref" not in work.payload


# --------------------------------------------------------------------------- #
# HTTP work source
# --------------------------------------------------------------------------- #
async def test_http_work_source_fetches_active_challenges() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.headers.get("authorization", "")))
        if "agent-challenge" in str(request.url):
            body = {
                "challenge_slug": "agent-challenge",
                "work_units": [
                    {
                        "work_unit_id": "1:t0",
                        "submission_id": 1,
                        "submission_ref": "ref",
                        "job_id": "job-x",
                        "task_id": "t0",
                        "required_capability": "cpu",
                    }
                ],
            }
        else:
            body = {
                "challenge_slug": "prism",
                "work_units": [
                    {
                        "work_unit_id": "9",
                        "submission_id": "9",
                        "submission_ref": "ref-p",
                        "required_capability": "gpu",
                        "payload": {},
                    }
                ],
            }
        return httpx.Response(200, content=json.dumps(body))

    registry = _FakeRegistry(
        records=[
            _Record("agent-challenge", "http://challenge-agent-challenge:8000"),
            _Record("prism", "http://challenge-prism:8080"),
        ],
        tokens={"agent-challenge": "ac-token", "prism": "prism-token"},
    )
    source = HttpChallengeWorkSource(registry, transport=httpx.MockTransport(handler))

    works = await source.fetch_pending_work()
    by_slug = {w.challenge_slug: w for w in works}
    assert by_slug["agent-challenge"].task_ids == ("t0",)
    assert by_slug["agent-challenge"].job_id == "job-x"
    assert by_slug["prism"].submission_id == "9"
    # The internal bearer token is attached per challenge.
    assert any("Bearer ac-token" == auth for _, auth in seen)
    assert any("Bearer prism-token" == auth for _, auth in seen)


async def test_http_work_source_skips_tokenless_and_unreachable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    registry = _FakeRegistry(
        records=[_Record("agent-challenge", "http://ac:8000")],
        tokens={"agent-challenge": "tok"},
    )
    source = HttpChallengeWorkSource(
        registry, retries=1, transport=httpx.MockTransport(handler)
    )
    # An unreachable/5xx challenge is skipped (returns no work, does not raise).
    assert await source.fetch_pending_work() == []

    tokenless = _FakeRegistry(
        records=[_Record("agent-challenge", "http://ac:8000")],
        tokens={},
    )
    source2 = HttpChallengeWorkSource(tokenless, transport=httpx.MockTransport(handler))
    assert await source2.fetch_pending_work() == []


# --------------------------------------------------------------------------- #
# HTTP fold trigger
# --------------------------------------------------------------------------- #
async def test_http_fold_trigger_posts_to_fold_route() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, content=json.dumps({"finalized": True}))

    registry = _FakeRegistry(
        records=[_Record("agent-challenge", "http://challenge-agent-challenge:8000")],
        tokens={"agent-challenge": "ac-token"},
    )
    trigger = HttpChallengeFoldTrigger(registry, transport=httpx.MockTransport(handler))

    await trigger.fold(
        challenge_slug="agent-challenge",
        job_id="job-1",
        task_id="t1",
        reason="exhausted",
    )

    assert str(captured["url"]).endswith("/internal/v1/work_units/fold")
    assert captured["auth"] == "Bearer ac-token"
    assert captured["body"] == {
        "job_id": "job-1",
        "task_id": "t1",
        "reason": "exhausted",
    }


async def test_http_fold_trigger_raises_after_retries() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    registry = _FakeRegistry(
        records=[_Record("agent-challenge", "http://ac:8000")],
        tokens={"agent-challenge": "tok"},
    )
    trigger = HttpChallengeFoldTrigger(
        registry, retries=1, transport=httpx.MockTransport(handler)
    )
    with pytest.raises(RuntimeError):
        await trigger.fold(
            challenge_slug="agent-challenge", job_id="j", task_id="t", reason="x"
        )
