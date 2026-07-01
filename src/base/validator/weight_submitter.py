"""Per-validator on-chain weight submitter (architecture.md sec 9.3).

Each validator node runs its OWN submitter loop with its OWN wallet/hotkey. The
submitter fetches the MASTER-aggregated weight vector over HTTP
(``GET /v1/weights/latest``) and commits that SAME vector on-chain under this
validator's hotkey. The validator NEVER computes or aggregates its own vector -
aggregation lives entirely on the master (``base.master.aggregator`` /
``MasterWeightService``); the validator side only fetches and submits. This is
the legacy ``submit_latest_weights`` relay pattern, run per-validator instead of
from a single global submitter.

Invariants (VAL-CODE-VWGT-001/002/003):

- **Per-validator, own keypair.** The ``WeightSetter`` is built from this node's
  wallet, so every validator submits under its OWN hotkey.
- **No validator-side aggregation.** The vector always comes from the master via
  :class:`base.validator.weights_client.WeightsClient`; there is no aggregator
  import or scoring on this path.
- **Independent, no shared state.** Each :class:`ValidatorWeightSubmitter` holds
  its own in-memory idempotency marker; two validators submitting concurrently
  share nothing.
- **Idempotent / crash-re-run safe.** A running node never re-submits the same
  master vector twice: the master stamps each computed vector with ``computed_at``
  and the submitter tracks the last vector it committed, so repeated ticks over an
  unchanged vector are a no-op. Across a crash/restart the on-chain commit-reveal
  rate limit rejects a too-fast re-commit, which is handled as a
  :attr:`ValidatorSubmitOutcome.REJECTED` (logged, retried next tick, never
  double-counted) rather than an error.
- **Gate-off no-op.** When ``submit_on_chain_enabled`` is ``False`` the tick does
  NO fetch, NO submit-runtime construction (so no live ``Subtensor`` is built),
  and NO submission. Live on-chain enablement is human-gated.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum

from base.bittensor.weight_setter import (
    WeightSetter,
    is_rejected_set_weights_result,
    set_weights_rejection_message,
)
from base.schemas.weights import MasterWeightsResponse
from base.validator.weights_client import (
    WeightsClient,
    validate_master_weights_payload,
)

logger = logging.getLogger(__name__)


class ValidatorSubmitOutcome(StrEnum):
    """Outcome of a single :meth:`ValidatorWeightSubmitter.run_once` tick."""

    #: The on-chain gate is off; no fetch and no submission were performed.
    DISABLED = "disabled"
    #: No usable master vector this tick (fetch failed or payload invalid/stale).
    NO_VECTOR = "no_vector"
    #: This exact master vector was already committed by this node; no-op.
    ALREADY_SUBMITTED = "already_submitted"
    #: The master vector was committed on-chain under this validator's hotkey.
    SUBMITTED = "submitted"
    #: The chain rejected the commit (e.g. rate-limited); retried next tick.
    REJECTED = "rejected"


#: Builds this validator's ``WeightSetter`` (own wallet/hotkey) lazily, so the
#: gate-off path never constructs a live ``Subtensor`` / touches chain material.
WeightSetterFactory = Callable[[], WeightSetter | None]
Clock = Callable[[], datetime]


class ValidatorWeightSubmitter:
    """Fetch the master vector and commit it on-chain with this node's hotkey."""

    def __init__(
        self,
        *,
        submit_enabled: bool,
        netuid: int,
        weights_client: WeightsClient,
        weight_setter_factory: WeightSetterFactory,
        weights_freshness_seconds: int = 720,
        clock: Clock | None = None,
    ) -> None:
        self._submit_enabled = submit_enabled
        self._netuid = netuid
        self._weights_client = weights_client
        self._weight_setter_factory = weight_setter_factory
        self._weights_freshness_seconds = weights_freshness_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self._weight_setter: WeightSetter | None = None
        self._last_submitted_key: tuple[int, datetime] | None = None

    @property
    def submit_enabled(self) -> bool:
        return self._submit_enabled

    @property
    def last_submitted_key(self) -> tuple[int, datetime] | None:
        return self._last_submitted_key

    async def run_once(self) -> ValidatorSubmitOutcome:
        if not self._submit_enabled:
            logger.debug(
                "validator on-chain weight submission is DISABLED "
                "(submit_on_chain_enabled=False); skipping tick"
            )
            return ValidatorSubmitOutcome.DISABLED

        try:
            payload = await self._weights_client.fetch_latest()
        except Exception:
            logger.exception("validator weights fetch failed")
            return ValidatorSubmitOutcome.NO_VECTOR

        failure = validate_master_weights_payload(
            payload,
            netuid=self._netuid,
            weights_freshness_seconds=self._weights_freshness_seconds,
            now=self._clock(),
        )
        if failure is not None:
            logger.warning("validator weights submission skipped: %s", failure)
            return ValidatorSubmitOutcome.NO_VECTOR

        key = self._vector_key(payload)
        if key == self._last_submitted_key:
            logger.info(
                "validator weights already submitted for computed_at=%s; "
                "skipping (idempotent no-op)",
                payload.computed_at.isoformat(),
            )
            return ValidatorSubmitOutcome.ALREADY_SUBMITTED

        setter = self._ensure_weight_setter()
        try:
            result = setter.set_weights(payload.uids, payload.weights)
        except Exception:
            logger.exception(
                "validator weights submission failed (incl. on-chain rejection); "
                "will retry next tick"
            )
            return ValidatorSubmitOutcome.REJECTED
        if is_rejected_set_weights_result(result):
            logger.warning(
                "validator weights submission rejected by subtensor: %s; "
                "will retry next tick",
                set_weights_rejection_message(result),
            )
            return ValidatorSubmitOutcome.REJECTED

        self._last_submitted_key = key
        logger.info(
            "validator weights submitted on-chain: netuid=%s n_weights=%s "
            "computed_at=%s",
            payload.netuid,
            len(payload.weights),
            payload.computed_at.isoformat(),
        )
        return ValidatorSubmitOutcome.SUBMITTED

    def _vector_key(self, payload: MasterWeightsResponse) -> tuple[int, datetime]:
        return (payload.netuid, payload.computed_at)

    def _ensure_weight_setter(self) -> WeightSetter:
        if self._weight_setter is None:
            self._weight_setter = self._weight_setter_factory()
        if self._weight_setter is None:
            raise RuntimeError(
                "validator submit runtime did not provide a WeightSetter"
            )
        return self._weight_setter


__all__ = ["ValidatorSubmitOutcome", "ValidatorWeightSubmitter"]
