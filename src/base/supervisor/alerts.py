"""Lightweight webhook alerting for the supervisor (plan Task 16).

A config-driven alert webhook hook plus structured logs — NO Prometheus/Grafana.
This module REUSES the Task-8 alert seam
(:class:`base.supervisor.weight_submit.WeightsAlert` /
:data:`base.supervisor.weight_submit.AlertEmitter`) rather than duplicating it:
the concrete :class:`WebhookAlertHook` IS an ``AlertEmitter``, so it plugs
straight into ``build_weight_submit_task(alert_emit=...)`` and every alert the
Task-8 backoff/rejection path already emits now reaches the webhook.

Stable alert ``kind`` tokens (a downstream webhook routes/thresholds on these
without parsing the human message):

- ``weights_submission_rejected`` — failed/rejected on-chain commit (Task 8).
- ``eval_pipeline_failure`` — eval/weight computation failed or scored partial.
- ``zero_miner_abort`` — chain-invalid zero-miner fallback aborted (Task 9).
- ``gpu_down`` — GPU liveness probe failed (Task 15 GPU failures).
- ``drand_unreachable`` — drand beacon reachability probe failed.

When ``alert_webhook_url`` is unset the hook is a structured-log-only NO-OP and
makes NO network call, so default deploys and the test suite never touch the
network. The drand/GPU probes are likewise skipped until their health URLs are
configured.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from base.config.settings import Settings
from base.supervisor.scheduler import ScheduledTask
from base.supervisor.weight_submit import (
    AlertEmitter,
    WeightsAlert,
    logging_alert_emitter,
)

logger = logging.getLogger(__name__)

ALERT_COMMIT_REJECTED = "weights_submission_rejected"
ALERT_EVAL_FAILURE = "eval_pipeline_failure"
ALERT_ZERO_MINER_ABORT = "zero_miner_abort"
ALERT_GPU_DOWN = "gpu_down"
ALERT_DRAND_UNREACHABLE = "drand_unreachable"

HEALTH_PROBE_TASK_NAME = "validator-health-probe"

DEFAULT_PROBE_TIMEOUT_SECONDS = 3.0

#: Webhook transport seam: ``(url, json_payload, timeout_seconds) -> None``.
#: Injectable so tests assert calls without real HTTP.
WebhookTransport = Callable[[str, dict[str, Any], float], None]

#: Reachability check seam: ``(url, timeout_seconds) -> bool`` (True == healthy).
HttpProbe = Callable[[str, float], bool]


def default_webhook_transport(
    url: str, payload: dict[str, Any], timeout_seconds: float
) -> None:
    """POST ``payload`` as JSON to ``url`` with a hard socket timeout.

    Failures are logged, never raised: a down webhook must not take down the
    supervisor task thread that emitted the alert.
    """
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            if not 200 <= response.status < 300:
                logger.warning(
                    "alert webhook POST returned non-2xx (%s) for %s",
                    response.status,
                    url,
                )
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        logger.warning("alert webhook POST failed for %s: %s", url, exc)


def default_http_probe(url: str, timeout_seconds: float) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout_seconds) as response:
            return bool(200 <= response.status < 300)
    except (urllib.error.URLError, OSError, TimeoutError):
        return False


def _alert_payload(alert: WeightsAlert) -> dict[str, Any]:
    return {
        "kind": alert.kind,
        "message": alert.message,
        "details": dict(alert.details),
    }


class WebhookAlertHook:
    """An :data:`AlertEmitter` that structured-logs every alert and POSTs it.

    NO-OP transport when ``webhook_url`` is None: the alert is still logged
    (the lightweight observability floor) but no network call is made.
    """

    def __init__(
        self,
        *,
        webhook_url: str | None,
        transport: WebhookTransport | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._webhook_url = webhook_url
        self._transport = transport or default_webhook_transport
        self._timeout_seconds = timeout_seconds

    @property
    def enabled(self) -> bool:
        return bool(self._webhook_url)

    def __call__(self, alert: WeightsAlert) -> None:
        logging_alert_emitter(alert)
        if not self._webhook_url:
            return
        try:
            self._transport(
                self._webhook_url, _alert_payload(alert), self._timeout_seconds
            )
        except Exception:
            logger.exception("alert webhook transport raised for kind=%s", alert.kind)

    def emit(self, kind: str, message: str, **details: Any) -> None:
        self(WeightsAlert(kind=kind, message=message, details=details))

    def commit_rejected(self, message: str, **details: Any) -> None:
        self.emit(ALERT_COMMIT_REJECTED, message, **details)

    def eval_failure(self, message: str, **details: Any) -> None:
        self.emit(ALERT_EVAL_FAILURE, message, **details)

    def zero_miner_abort(self, message: str, **details: Any) -> None:
        self.emit(ALERT_ZERO_MINER_ABORT, message, **details)

    def gpu_down(self, message: str, **details: Any) -> None:
        self.emit(ALERT_GPU_DOWN, message, **details)

    def drand_unreachable(self, message: str, **details: Any) -> None:
        self.emit(ALERT_DRAND_UNREACHABLE, message, **details)


def build_alert_hook(
    settings: Settings, *, transport: WebhookTransport | None = None
) -> WebhookAlertHook:
    obs = settings.observability
    return WebhookAlertHook(
        webhook_url=obs.alert_webhook_url,
        transport=transport,
        timeout_seconds=obs.alert_webhook_timeout_seconds,
    )


class ValidatorHealthProbe:
    """Probes drand + GPU reachability and alerts on failure.

    Each probe is skipped when its URL is unset (None), so a default deploy
    performs no network I/O. The reachability check is injectable for tests.
    """

    def __init__(
        self,
        *,
        hook: WebhookAlertHook,
        drand_url: str | None,
        gpu_url: str | None,
        http_probe: HttpProbe | None = None,
        timeout_seconds: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
    ) -> None:
        self._hook = hook
        self._drand_url = drand_url
        self._gpu_url = gpu_url
        self._http_probe = http_probe or default_http_probe
        self._timeout_seconds = timeout_seconds

    def probe_once(self) -> None:
        if self._drand_url and not self._http_probe(
            self._drand_url, self._timeout_seconds
        ):
            self._hook.drand_unreachable(
                f"drand beacon unreachable at {self._drand_url}",
                url=self._drand_url,
            )
        if self._gpu_url and not self._http_probe(self._gpu_url, self._timeout_seconds):
            self._hook.gpu_down(
                f"GPU health endpoint unreachable at {self._gpu_url}",
                url=self._gpu_url,
            )


def build_health_probe_task(
    settings: Settings,
    *,
    hook: WebhookAlertHook,
    http_probe: HttpProbe | None = None,
) -> ScheduledTask:
    obs = settings.observability
    probe = ValidatorHealthProbe(
        hook=hook,
        drand_url=obs.drand_health_url,
        gpu_url=obs.gpu_health_url,
        http_probe=http_probe,
    )
    return ScheduledTask(
        name=HEALTH_PROBE_TASK_NAME,
        interval_seconds=float(obs.health_probe_interval_seconds),
        run=probe.probe_once,
    )


__all__ = [
    "ALERT_COMMIT_REJECTED",
    "ALERT_DRAND_UNREACHABLE",
    "ALERT_EVAL_FAILURE",
    "ALERT_GPU_DOWN",
    "ALERT_ZERO_MINER_ABORT",
    "HEALTH_PROBE_TASK_NAME",
    "AlertEmitter",
    "HttpProbe",
    "ValidatorHealthProbe",
    "WebhookAlertHook",
    "WebhookTransport",
    "build_alert_hook",
    "build_health_probe_task",
    "default_http_probe",
    "default_webhook_transport",
]
