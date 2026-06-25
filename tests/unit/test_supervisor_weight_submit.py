"""Tests for the supervisor on-chain weights submit task (plan Task 8).

The on-chain weights task drives the Task-7 submit primitive
(``WeightSetter.set_weights``) on cadence, but ONLY when:

1. ``settings.validator.submit_on_chain_enabled`` is True (runtime-off gate;
   the first on-chain commit is human-gated, plan Task 27), AND
2. both challenges' eval pipelines are healthy (recent successful scores) — no
   commit on partial/garbage scores.

On a commit-reveal rejection it schedules an exponential backoff (never faster
than the on-chain rate limit) and emits an ALERT through an injectable seam
(plan Task 16 wires the concrete webhook). An epoch is NEVER silently dropped.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from base.config.settings import Settings
from base.schemas.weights import ChallengeWeightsResult, MasterWeightsResponse
from base.supervisor import weight_submit as ws


def _healthy_response(
    *,
    uids: list[int] | None = None,
    weights: list[float] | None = None,
) -> MasterWeightsResponse:
    now = datetime.now(UTC)
    return MasterWeightsResponse(
        netuid=100,
        chain_endpoint="",
        uids=uids if uids is not None else [0, 1],
        weights=weights if weights is not None else [0.5, 0.5],
        computed_at=now,
        expires_at=now + timedelta(seconds=1260),
        source_challenges=[
            ChallengeWeightsResult(
                slug="prism",
                emission_percent=50.0,
                weights={"hk-a": 0.5},
                ok=True,
            ),
            ChallengeWeightsResult(
                slug="agent-challenge",
                emission_percent=50.0,
                weights={"hk-b": 0.5},
                ok=True,
            ),
        ],
        metagraph_updated_at=now,
    )


class _RecordingSetter:
    """Stand-in for the Task-7 WeightSetter.

    ``mode``: "ok" returns a success result, "raise" raises RuntimeError (the
    real WeightSetter behaviour on a rejected ExtrinsicResponse), "reject"
    returns a rejected result object (defence-in-depth path).
    """

    def __init__(self, mode: str = "ok") -> None:
        self.mode = mode
        self.calls: list[tuple[list[int], list[float]]] = []

    def set_weights(self, uids: list[int], weights: list[float]) -> Any:
        self.calls.append((list(uids), list(weights)))
        if self.mode == "raise":
            raise RuntimeError("subtensor rejected weight submission: too fast")
        from types import SimpleNamespace

        if self.mode == "reject":
            return SimpleNamespace(success=False, message="too fast")
        return SimpleNamespace(success=True, message="ok")


def _make_submitter(
    *,
    setter: _RecordingSetter,
    response: MasterWeightsResponse | Exception,
    submit_enabled: bool = True,
    alerts: list[ws.WeightsAlert] | None = None,
    clock: Any = None,
    health_check: Any = None,
    backoff: ws.BackoffPolicy | None = None,
) -> ws.OnChainWeightSubmitter:
    def _compute(settings: Settings) -> MasterWeightsResponse:
        if isinstance(response, Exception):
            raise response
        return response

    def _runtime(settings: Settings) -> Any:
        from types import SimpleNamespace

        return SimpleNamespace(weight_setter=setter)

    sink = alerts if alerts is not None else []

    return ws.OnChainWeightSubmitter(
        Settings(),
        submit_enabled=submit_enabled,
        health_check=health_check or ws.default_pipeline_health,
        alert_emit=sink.append,
        backoff=backoff or ws.BackoffPolicy(),
        compute=_compute,
        submit_runtime_factory=_runtime,
        clock=clock or (lambda: datetime.now(UTC)),
    )


def test_healthy_pipeline_submits_on_chain() -> None:
    setter = _RecordingSetter(mode="ok")
    alerts: list[ws.WeightsAlert] = []
    submitter = _make_submitter(
        setter=setter, response=_healthy_response(), alerts=alerts
    )

    submitter.run_once()

    assert setter.calls == [([0, 1], [0.5, 0.5])]
    assert alerts == []
    assert submitter.in_backoff is False


def test_unhealthy_pipeline_skips_with_reason_and_no_submit(
    caplog: pytest.LogCaptureFixture,
) -> None:
    setter = _RecordingSetter(mode="ok")
    unhealthy = _healthy_response()
    unhealthy.source_challenges[1].ok = False
    unhealthy.source_challenges[1].error = "eval workers down"

    submitter = _make_submitter(setter=setter, response=unhealthy)

    handler = _AttachedHandler("base.supervisor.weight_submit")
    with handler:
        submitter.run_once()

    assert setter.calls == []  # NO submit on unhealthy pipeline
    assert any("skipped" in m and "agent-challenge" in m for m in handler.messages), (
        handler.messages
    )


def test_partial_scores_skip_no_submit() -> None:
    """Empty weights from a challenge = partial/garbage scores -> no commit."""
    setter = _RecordingSetter(mode="ok")
    partial = _healthy_response()
    partial.source_challenges[0].weights = {}

    submitter = _make_submitter(setter=setter, response=partial)
    submitter.run_once()

    assert setter.calls == []


def test_compute_failure_skips_without_submit() -> None:
    setter = _RecordingSetter(mode="ok")
    submitter = _make_submitter(
        setter=setter, response=RuntimeError("challenge 'prism' failed")
    )
    submitter.run_once()
    assert setter.calls == []


def test_rejection_raised_schedules_backoff_and_alert() -> None:
    setter = _RecordingSetter(mode="raise")
    alerts: list[ws.WeightsAlert] = []
    submitter = _make_submitter(
        setter=setter, response=_healthy_response(), alerts=alerts
    )

    submitter.run_once()

    assert len(setter.calls) == 1  # attempted exactly once
    assert submitter.in_backoff is True  # epoch retained for retry, not dropped
    assert submitter.retry_not_before is not None
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.kind == "weights_submission_rejected"
    assert "too fast" in alert.message
    assert alert.details["consecutive_failures"] == 1
    assert alert.details["backoff_seconds"] >= ws.ON_CHAIN_RATE_LIMIT_FLOOR_SECONDS


def test_rejection_via_rejected_result_also_backs_off_and_alerts() -> None:
    setter = _RecordingSetter(mode="reject")
    alerts: list[ws.WeightsAlert] = []
    submitter = _make_submitter(
        setter=setter, response=_healthy_response(), alerts=alerts
    )

    submitter.run_once()

    assert len(setter.calls) == 1
    assert submitter.in_backoff is True
    assert len(alerts) == 1
    assert "too fast" in alerts[0].message


def test_backoff_window_blocks_next_tick_then_resumes() -> None:
    setter = _RecordingSetter(mode="raise")
    fake_now = {"t": datetime(2026, 1, 1, tzinfo=UTC)}
    submitter = _make_submitter(
        setter=setter,
        response=_healthy_response(),
        clock=lambda: fake_now["t"],
    )

    submitter.run_once()  # rejection -> backoff scheduled
    assert len(setter.calls) == 1
    not_before = submitter.retry_not_before
    assert not_before is not None

    # Still inside the backoff window: the tick is skipped, no new submit.
    fake_now["t"] = not_before - timedelta(seconds=1)
    submitter.run_once()
    assert len(setter.calls) == 1  # no second attempt during backoff

    # Backoff elapsed: a submit is attempted again (epoch never dropped).
    fake_now["t"] = not_before + timedelta(seconds=1)
    submitter.run_once()
    assert len(setter.calls) == 2


def test_success_after_rejection_resets_backoff() -> None:
    setter = _RecordingSetter(mode="raise")
    fake_now = {"t": datetime(2026, 1, 1, tzinfo=UTC)}
    submitter = _make_submitter(
        setter=setter,
        response=_healthy_response(),
        clock=lambda: fake_now["t"],
    )
    submitter.run_once()
    assert submitter.in_backoff is True

    setter.mode = "ok"
    assert submitter.retry_not_before is not None
    fake_now["t"] = submitter.retry_not_before + timedelta(seconds=1)
    submitter.run_once()
    assert submitter.in_backoff is False
    assert submitter.consecutive_failures == 0


def test_runtime_off_gate_skips_compute_and_submit() -> None:
    setter = _RecordingSetter(mode="ok")
    computed = {"n": 0}

    def _compute(settings: Settings) -> MasterWeightsResponse:
        computed["n"] += 1
        return _healthy_response()

    def _runtime(settings: Settings) -> Any:
        from types import SimpleNamespace

        return SimpleNamespace(weight_setter=setter)

    submitter = ws.OnChainWeightSubmitter(
        Settings(),
        submit_enabled=False,
        health_check=ws.default_pipeline_health,
        alert_emit=lambda alert: None,
        backoff=ws.BackoffPolicy(),
        compute=_compute,
        submit_runtime_factory=_runtime,
        clock=lambda: datetime.now(UTC),
    )
    submitter.run_once()

    assert computed["n"] == 0  # runtime-off: no compute side effects at all
    assert setter.calls == []


def test_backoff_policy_floor_exponential_and_cap() -> None:
    policy = ws.BackoffPolicy(floor_seconds=1260.0, multiplier=2.0, max_seconds=21600.0)
    assert policy.delay_for(1) == 1260.0  # never faster than the rate limit
    assert policy.delay_for(2) == 2520.0
    assert policy.delay_for(3) == 5040.0
    assert policy.delay_for(100) == 21600.0  # capped


def test_default_pipeline_health_branches() -> None:
    assert ws.default_pipeline_health(_healthy_response()).healthy is True

    empty = _healthy_response()
    empty.source_challenges = []
    assert ws.default_pipeline_health(empty).healthy is False

    no_vector = _healthy_response(uids=[], weights=[])
    assert ws.default_pipeline_health(no_vector).healthy is False


def test_build_task_defaults_runtime_off_and_uses_interval() -> None:
    settings = Settings()
    task = ws.build_weight_submit_task(settings)
    assert task.name == ws.WEIGHT_SUBMIT_TASK_NAME
    assert task.interval_seconds == float(settings.validator.weights_interval_seconds)
    # default Settings has submit_on_chain_enabled=False -> running is a no-op
    task.run()  # must not raise


class _AttachedHandler:
    """Capture records on a named logger, immune to root-logging churn.

    Mirrors the pattern in test_supervisor_weights.py: other tests reconfigure
    root logging / disable loggers (alembic env.py), which breaks caplog in a
    full-suite run, so we attach directly to the target logger.
    """

    def __init__(self, logger_name: str) -> None:
        self._logger = logging.getLogger(logger_name)
        self.messages: list[str] = []
        self._lock = threading.Lock()
        self._was_disabled = False

        class _H(logging.Handler):
            def __init__(inner) -> None:
                super().__init__(level=logging.DEBUG)

            def emit(inner, record: logging.LogRecord) -> None:
                with self._lock:
                    self.messages.append(record.getMessage())

        self._handler = _H()

    def __enter__(self) -> _AttachedHandler:
        self._was_disabled = self._logger.disabled
        self._logger.disabled = False
        self._logger.setLevel(logging.DEBUG)
        self._logger.addHandler(self._handler)
        return self

    def __exit__(self, *exc: object) -> None:
        self._logger.removeHandler(self._handler)
        self._logger.disabled = self._was_disabled
