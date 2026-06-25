"""Tests for the supervisor webhook alerting hook (plan Task 16).

Each of the five alert conditions must invoke the (mocked) webhook transport
with the correct stable ``kind`` and payload — NO real network. The conditions:

- ``weights_submission_rejected`` — wired through the Task-8 backoff/rejection
  path (``OnChainWeightSubmitter`` with the hook as its ``alert_emit`` seam).
- ``eval_pipeline_failure`` — weight compute raises / pipeline unhealthy.
- ``zero_miner_abort`` — compute raises ``ZeroMinerWeightError`` (Task 9).
- ``gpu_down`` / ``drand_unreachable`` — the reachability probe's health check
  fails for the configured GPU/drand URL.

The webhook must be a structured-log-only no-op when the URL is unset so default
deploys and the suite never make network calls.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from base.config.settings import ObservabilitySettings, Settings
from base.schemas.weights import ChallengeWeightsResult, MasterWeightsResponse
from base.supervisor import alerts
from base.supervisor.tasks import build_scheduled_tasks
from base.supervisor.weight_submit import (
    BackoffPolicy,
    OnChainWeightSubmitter,
    WeightsAlert,
    default_pipeline_health,
)


class _RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any], float]] = []

    def __call__(
        self, url: str, payload: dict[str, Any], timeout_seconds: float
    ) -> None:
        self.calls.append((url, payload, timeout_seconds))

    @property
    def kinds(self) -> list[str]:
        return [payload["kind"] for _url, payload, _t in self.calls]


class _ExplodingTransport:
    def __call__(
        self, url: str, payload: dict[str, Any], timeout_seconds: float
    ) -> None:
        raise AssertionError(
            "transport must not be called when the webhook URL is unset"
        )


_WEBHOOK_URL = "https://hooks.example/alert"


def _hook(transport: _RecordingTransport | None = None) -> alerts.WebhookAlertHook:
    return alerts.WebhookAlertHook(
        webhook_url=_WEBHOOK_URL,
        transport=transport or _RecordingTransport(),
        timeout_seconds=5.0,
    )


def _healthy_response() -> MasterWeightsResponse:
    now = datetime.now(UTC)
    return MasterWeightsResponse(
        netuid=100,
        chain_endpoint="",
        uids=[0, 1],
        weights=[0.5, 0.5],
        computed_at=now,
        expires_at=now + timedelta(seconds=1260),
        source_challenges=[
            ChallengeWeightsResult(
                slug="prism", emission_percent=50.0, weights={"hk-a": 0.5}, ok=True
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
    def __init__(self, mode: str = "ok") -> None:
        self.mode = mode

    def set_weights(self, uids: list[int], weights: list[float]) -> Any:
        from types import SimpleNamespace

        if self.mode == "raise":
            raise RuntimeError("subtensor rejected weight submission: too fast")
        return SimpleNamespace(success=True, message="ok")


def _submitter(
    *,
    hook: alerts.WebhookAlertHook,
    response: MasterWeightsResponse | Exception,
    setter_mode: str = "ok",
) -> OnChainWeightSubmitter:
    def _compute(settings: Settings) -> MasterWeightsResponse:
        if isinstance(response, Exception):
            raise response
        return response

    def _runtime(settings: Settings) -> Any:
        from types import SimpleNamespace

        return SimpleNamespace(weight_setter=_RecordingSetter(mode=setter_mode))

    return OnChainWeightSubmitter(
        Settings(),
        submit_enabled=True,
        health_check=default_pipeline_health,
        alert_emit=hook,
        backoff=BackoffPolicy(),
        compute=_compute,
        submit_runtime_factory=_runtime,
        clock=lambda: datetime.now(UTC),
    )


def test_commit_rejected_invokes_webhook_through_task8_seam() -> None:
    transport = _RecordingTransport()
    submitter = _submitter(
        hook=_hook(transport), response=_healthy_response(), setter_mode="raise"
    )

    submitter.run_once()

    assert transport.kinds == [alerts.ALERT_COMMIT_REJECTED]
    _url, payload, _t = transport.calls[0]
    assert _url == _WEBHOOK_URL
    assert "too fast" in payload["message"]
    assert payload["details"]["consecutive_failures"] == 1
    assert payload["details"]["netuid"] == 100


def test_eval_failure_compute_exception_invokes_webhook() -> None:
    transport = _RecordingTransport()
    submitter = _submitter(
        hook=_hook(transport),
        response=RuntimeError("challenge 'prism' failed to provide weights"),
    )

    submitter.run_once()

    assert transport.kinds == [alerts.ALERT_EVAL_FAILURE]
    _url, payload, _t = transport.calls[0]
    assert payload["details"]["phase"] == "compute"
    assert "prism" in payload["message"]


def test_eval_failure_unhealthy_pipeline_invokes_webhook() -> None:
    transport = _RecordingTransport()
    unhealthy = _healthy_response()
    unhealthy.source_challenges[1].ok = False
    unhealthy.source_challenges[1].error = "eval workers down"
    submitter = _submitter(hook=_hook(transport), response=unhealthy)

    submitter.run_once()

    assert transport.kinds == [alerts.ALERT_EVAL_FAILURE]
    assert transport.calls[0][1]["details"]["phase"] == "health_gate"


def test_zero_miner_abort_invokes_webhook() -> None:
    from base.master.aggregator import ZeroMinerWeightError

    transport = _RecordingTransport()
    submitter = _submitter(
        hook=_hook(transport),
        response=ZeroMinerWeightError("cannot build a chain-valid zero-miner vector"),
    )

    submitter.run_once()

    assert transport.kinds == [alerts.ALERT_ZERO_MINER_ABORT]
    assert "zero-miner" in transport.calls[0][1]["message"]


def test_gpu_down_probe_invokes_webhook() -> None:
    transport = _RecordingTransport()
    probe = alerts.ValidatorHealthProbe(
        hook=_hook(transport),
        drand_url=None,
        gpu_url="http://gpu-worker:9000/health",
        http_probe=lambda url, timeout: False,
    )

    probe.probe_once()

    assert transport.kinds == [alerts.ALERT_GPU_DOWN]
    assert transport.calls[0][1]["details"]["url"] == "http://gpu-worker:9000/health"


def test_drand_unreachable_probe_invokes_webhook() -> None:
    transport = _RecordingTransport()
    probe = alerts.ValidatorHealthProbe(
        hook=_hook(transport),
        drand_url="https://drand.example/health",
        gpu_url=None,
        http_probe=lambda url, timeout: False,
    )

    probe.probe_once()

    assert transport.kinds == [alerts.ALERT_DRAND_UNREACHABLE]


def test_probe_does_not_alert_when_healthy() -> None:
    transport = _RecordingTransport()
    probe = alerts.ValidatorHealthProbe(
        hook=_hook(transport),
        drand_url="https://drand.example/health",
        gpu_url="http://gpu-worker:9000/health",
        http_probe=lambda url, timeout: True,
    )

    probe.probe_once()

    assert transport.calls == []


def test_webhook_is_noop_when_url_unset() -> None:
    hook = alerts.WebhookAlertHook(webhook_url=None, transport=_ExplodingTransport())
    assert hook.enabled is False

    hook.commit_rejected("rejected")
    hook.eval_failure("eval down")
    hook.gpu_down("gpu down")
    hook.drand_unreachable("drand down")
    hook.zero_miner_abort("aborted")


def test_alert_is_always_structured_logged() -> None:
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    emitter_logger = logging.getLogger("base.supervisor.weight_submit")
    handler = _Capture()
    emitter_logger.addHandler(handler)
    previous_level = emitter_logger.level
    previous_disabled = emitter_logger.disabled
    previous_global_disable = logging.root.manager.disable
    emitter_logger.setLevel(logging.ERROR)
    emitter_logger.disabled = False
    logging.disable(logging.NOTSET)
    try:
        hook = alerts.WebhookAlertHook(
            webhook_url=None, transport=_RecordingTransport()
        )
        hook(WeightsAlert(kind=alerts.ALERT_GPU_DOWN, message="gpu down", details={}))
    finally:
        emitter_logger.removeHandler(handler)
        emitter_logger.setLevel(previous_level)
        emitter_logger.disabled = previous_disabled
        logging.disable(previous_global_disable)

    assert any(alerts.ALERT_GPU_DOWN in rec.getMessage() for rec in records)


def test_build_alert_hook_disabled_by_default() -> None:
    assert build_alert_hook_enabled(Settings()) is False


def build_alert_hook_enabled(settings: Settings) -> bool:
    return alerts.build_alert_hook(settings).enabled


def test_webhook_enabled_when_configured_via_settings() -> None:
    settings = Settings(
        observability=ObservabilitySettings(alert_webhook_url=_WEBHOOK_URL)
    )
    transport = _RecordingTransport()
    hook = alerts.build_alert_hook(settings, transport=transport)
    assert hook.enabled is True

    hook.gpu_down("gpu down", uuid="GPU-x")

    assert transport.kinds == [alerts.ALERT_GPU_DOWN]
    assert transport.calls[0][2] == settings.observability.alert_webhook_timeout_seconds


def test_health_probe_task_registered_in_supervisor() -> None:
    tasks, _gate = build_scheduled_tasks(Settings())
    names = [task.name for task in tasks]
    assert alerts.HEALTH_PROBE_TASK_NAME in names
    probe_task = next(t for t in tasks if t.name == alerts.HEALTH_PROBE_TASK_NAME)
    probe_task.run()  # default settings: both URLs unset -> no-op, must not raise
