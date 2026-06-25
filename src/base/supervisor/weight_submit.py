"""On-chain weights submit task for the supervisor (plan Task 8).

This is the supervisor's on-chain weight submitter. Each tick it drives the
Task-7 submit primitive (:meth:`base.bittensor.weight_setter.WeightSetter.set_weights`,
which RAISES ``RuntimeError`` on a rejected commit-reveal ``ExtrinsicResponse``)
on the supervisor scheduler's cadence, behind three gates:

1. RUNTIME-OFF gate (``settings.validator.submit_on_chain_enabled``): the code
   path is code-CAPABLE but inert by default. A deploy never auto-commits; the
   first on-chain commit is human-gated (plan Task 27) by flipping the flag.
   While off, the tick performs NO compute and NO submission.
2. PIPELINE-HEALTHY gate: weights are computed compute-only (no ``WeightSetter``
   on the compute service), and submission is skipped unless BOTH challenges'
   eval pipelines produced recent successful scores. No commit on partial or
   garbage scores.
3. BACKOFF gate: on a commit-reveal rejection the submitter schedules an
   exponential backoff (never faster than the on-chain rate limit) and emits an
   ALERT through an injectable seam (plan Task 16 wires the concrete webhook).
   A rejected epoch is retried after the backoff, never silently dropped.

Compute and submit use SEPARATE runtimes: the compute runtime
(:func:`base.bittensor.factory.create_bittensor_runtime`) never holds a
``WeightSetter`` (read-only), while submission goes through the dedicated
submit runtime (:func:`create_bittensor_submit_runtime`). The broker health
gate from the Task-16 builder recipe is accepted but not consulted — on-chain
submission has no Docker-broker dependency.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from base.bittensor.factory import create_bittensor_submit_runtime
from base.bittensor.weight_setter import (
    is_rejected_set_weights_result,
    set_weights_rejection_message,
)
from base.config.settings import Settings
from base.master.aggregator import ZeroMinerWeightError
from base.schemas.weights import MasterWeightsResponse
from base.supervisor.health import BrokerHealthGate
from base.supervisor.scheduler import ScheduledTask

logger = logging.getLogger(__name__)

WEIGHT_SUBMIT_TASK_NAME = "weights-onchain-submit"

#: netuid 100 on-chain ``weights_rate_limit`` = 100 blocks (~1200s @12s/block).
#: Retries must never be spaced tighter than this or commit-reveal submissions
#: are rejected as "too fast"; 1260s adds margin above the ~1200s floor (matches
#: the Task-7 submitter.yaml cadence).
ON_CHAIN_RATE_LIMIT_FLOOR_SECONDS = 1260.0

#: Cap on a single backoff delay (6h) so an outage does not push the next retry
#: arbitrarily far into the future.
DEFAULT_BACKOFF_MAX_SECONDS = 21_600.0


@dataclass(frozen=True)
class WeightsAlert:
    """An alert payload emitted through the Task-16 alert seam.

    ``kind`` is a stable machine token (e.g. ``"weights_submission_rejected"``)
    so a downstream webhook can route/threshold without parsing ``message``.
    """

    kind: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)


#: The alert seam Task 16 wires to a concrete webhook. Default emits a log line.
AlertEmitter = Callable[[WeightsAlert], None]


def logging_alert_emitter(alert: WeightsAlert) -> None:
    logger.error("ALERT[%s] %s | %s", alert.kind, alert.message, alert.details)


@dataclass(frozen=True)
class PipelineHealth:
    healthy: bool
    reason: str


#: Decides whether the computed weights reflect a healthy eval pipeline.
PipelineHealthCheck = Callable[[MasterWeightsResponse], PipelineHealth]


def default_pipeline_health(response: MasterWeightsResponse) -> PipelineHealth:
    """Healthy iff every challenge produced recent successful, non-empty scores.

    An unhealthy or missing eval pipeline surfaces as a challenge result that is
    not ``ok`` or has empty per-hotkey scores (partial/garbage), or an empty
    aggregated vector — any of which blocks the commit.
    """
    if not response.source_challenges:
        return PipelineHealth(
            False, "no challenge results (eval pipeline produced no scores)"
        )
    for result in response.source_challenges:
        if not result.ok:
            return PipelineHealth(
                False,
                f"challenge {result.slug!r} unhealthy: {result.error or 'not ok'}",
            )
        if not result.weights:
            return PipelineHealth(
                False,
                f"challenge {result.slug!r} produced no scores "
                "(eval workers down or partial scores)",
            )
    if not response.uids or not response.weights:
        return PipelineHealth(False, "aggregated weight vector is empty")
    return PipelineHealth(True, "all challenge eval pipelines healthy")


@dataclass(frozen=True)
class BackoffPolicy:
    floor_seconds: float = ON_CHAIN_RATE_LIMIT_FLOOR_SECONDS
    multiplier: float = 2.0
    max_seconds: float = DEFAULT_BACKOFF_MAX_SECONDS

    def delay_for(self, attempt: int) -> float:
        if attempt < 1:
            return self.floor_seconds
        raw = self.floor_seconds * (self.multiplier ** (attempt - 1))
        return min(self.max_seconds, max(self.floor_seconds, raw))


ComputeResponse = Callable[[Settings], MasterWeightsResponse]
SubmitRuntimeFactory = Callable[[Settings], Any]
Clock = Callable[[], datetime]


def compute_weights_response(settings: Settings) -> MasterWeightsResponse:
    """Run one compute-only master weight epoch and return the full response.

    Mirrors ``base.supervisor.weights.compute_weights_once`` (same cli_app
    helpers, idempotent startup migrations, no ``WeightSetter`` on the compute
    service) but returns the :class:`MasterWeightsResponse` so the caller can
    health-gate on per-challenge ``source_challenges`` before submitting.
    """
    from base.cli_app import main as cli_main

    cli_main._run_startup_migrations(settings)
    registry = cli_main._master_registry(settings)
    runtime = cli_main.create_bittensor_runtime(settings)
    service = cli_main._master_weight_service(
        settings,
        metagraph_cache=runtime.metagraph_cache,
    )
    if service.weight_setter is not None:
        raise RuntimeError(
            "compute service must never hold a WeightSetter; on-chain submission "
            "goes through the dedicated submit runtime"
        )
    return asyncio.run(
        cli_main._run_master_weight_epoch_response(
            service,
            registry,
            netuid=settings.network.netuid,
            chain_endpoint=settings.network.chain_endpoint or "",
        )
    )


class OnChainWeightSubmitter:
    """Cadence-driven on-chain weight submitter with health gate + backoff."""

    def __init__(
        self,
        settings: Settings,
        *,
        submit_enabled: bool,
        health_check: PipelineHealthCheck,
        alert_emit: AlertEmitter,
        backoff: BackoffPolicy,
        compute: ComputeResponse,
        submit_runtime_factory: SubmitRuntimeFactory,
        clock: Clock,
    ) -> None:
        self._settings = settings
        self._submit_enabled = submit_enabled
        self._health_check = health_check
        self._alert_emit = alert_emit
        self._backoff = backoff
        self._compute = compute
        self._submit_runtime_factory = submit_runtime_factory
        self._clock = clock
        self._consecutive_failures = 0
        self._retry_not_before: datetime | None = None

    @property
    def in_backoff(self) -> bool:
        return self._retry_not_before is not None

    @property
    def retry_not_before(self) -> datetime | None:
        return self._retry_not_before

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    def run_once(self) -> None:
        if not self._submit_enabled:
            logger.info(
                "on-chain weight submission is DISABLED (runtime-off; first "
                "commit is human-gated, plan Task 27); skipping tick"
            )
            return
        now = self._clock()
        if self._retry_not_before is not None and now < self._retry_not_before:
            logger.info(
                "weight submission in backoff until %s; skipping tick "
                "(epoch retained for retry)",
                self._retry_not_before.isoformat(),
            )
            return
        try:
            response = self._compute(self._settings)
        except ZeroMinerWeightError as exc:
            logger.warning(
                "weights submission skipped: zero-miner fallback aborted "
                "(refusing to submit a chain-invalid vector): %s",
                exc,
            )
            self._alert_emit(
                WeightsAlert(
                    kind="zero_miner_abort",
                    message=str(exc),
                    details={"netuid": self._settings.network.netuid},
                )
            )
            return
        except Exception as exc:
            logger.warning(
                "weights submission skipped: weight computation failed "
                "(eval pipeline error): %s",
                exc,
            )
            self._alert_emit(
                WeightsAlert(
                    kind="eval_pipeline_failure",
                    message=str(exc),
                    details={
                        "netuid": self._settings.network.netuid,
                        "phase": "compute",
                    },
                )
            )
            return
        health = self._health_check(response)
        if not health.healthy:
            logger.warning(
                "weights submission skipped: pipeline unhealthy: %s", health.reason
            )
            self._alert_emit(
                WeightsAlert(
                    kind="eval_pipeline_failure",
                    message=health.reason,
                    details={
                        "netuid": self._settings.network.netuid,
                        "phase": "health_gate",
                    },
                )
            )
            return
        self._submit(response)

    def _submit(self, response: MasterWeightsResponse) -> None:
        runtime = self._submit_runtime_factory(self._settings)
        setter = getattr(runtime, "weight_setter", None)
        if setter is None:
            raise RuntimeError("submit runtime did not provide a WeightSetter")
        try:
            result = setter.set_weights(response.uids, response.weights)
        except Exception as exc:
            self._handle_rejection(str(exc), response)
            return
        if is_rejected_set_weights_result(result):
            self._handle_rejection(set_weights_rejection_message(result), response)
            return
        self._reset_backoff()
        logger.info(
            "weights submitted on-chain: netuid=%s n_weights=%s",
            response.netuid,
            len(response.weights),
        )

    def _handle_rejection(self, message: str, response: MasterWeightsResponse) -> None:
        self._consecutive_failures += 1
        delay = self._backoff.delay_for(self._consecutive_failures)
        self._retry_not_before = self._clock() + timedelta(seconds=delay)
        logger.warning(
            "weights submission REJECTED (failure #%d): %s; backing off %.0fs "
            "(retry not before %s); epoch retained, NOT dropped",
            self._consecutive_failures,
            message,
            delay,
            self._retry_not_before.isoformat(),
        )
        self._alert_emit(
            WeightsAlert(
                kind="weights_submission_rejected",
                message=message,
                details={
                    "consecutive_failures": self._consecutive_failures,
                    "backoff_seconds": delay,
                    "retry_not_before": self._retry_not_before.isoformat(),
                    "netuid": response.netuid,
                    "n_weights": len(response.weights),
                },
            )
        )

    def _reset_backoff(self) -> None:
        if self._retry_not_before is not None or self._consecutive_failures:
            logger.info("weights submission recovered; clearing backoff")
        self._consecutive_failures = 0
        self._retry_not_before = None


def build_weight_submit_task(
    settings: Settings,
    *,
    health_gate: BrokerHealthGate | None = None,
    alert_emit: AlertEmitter | None = None,
    health_check: PipelineHealthCheck | None = None,
    compute: ComputeResponse | None = None,
    submit_runtime_factory: SubmitRuntimeFactory | None = None,
    clock: Clock | None = None,
    interval_seconds: float | None = None,
) -> ScheduledTask:
    """Build the supervisor's on-chain weight-submit :class:`ScheduledTask`.

    Follows the Task-16 registration recipe (synchronous callable, safe on a
    non-main daemon thread, tolerates its own transient errors). ``alert_emit``
    is the injectable Task-16 seam; all other callables are injectable for
    tests. ``health_gate`` is accepted for the shared builder signature but not
    consulted — see the module docstring.
    """
    del health_gate  # on-chain submit has no broker dependency
    submitter = OnChainWeightSubmitter(
        settings,
        submit_enabled=settings.validator.submit_on_chain_enabled,
        health_check=health_check or default_pipeline_health,
        alert_emit=alert_emit or logging_alert_emitter,
        backoff=BackoffPolicy(),
        compute=compute or compute_weights_response,
        submit_runtime_factory=submit_runtime_factory
        or create_bittensor_submit_runtime,
        clock=clock or (lambda: datetime.now(UTC)),
    )
    interval = (
        interval_seconds
        if interval_seconds is not None
        else float(settings.validator.weights_interval_seconds)
    )
    return ScheduledTask(
        name=WEIGHT_SUBMIT_TASK_NAME,
        interval_seconds=interval,
        run=submitter.run_once,
    )
