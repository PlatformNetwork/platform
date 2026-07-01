"""Per-validator on-chain weight submitter tests (VAL-CODE-VWGT-001/002/003).

The validator runtime fetches the MASTER-aggregated vector (``/v1/weights/latest``)
and commits it under ITS OWN hotkey - it never aggregates its own vector. These
tests cover: fetch-master-vector + own-keypair submit, two independent validators
each submitting with their own hotkey, idempotent re-run no-op, gate-off no-op,
crash/rejection retry safety, and clean master/validator separation.
"""

from __future__ import annotations

import ast
import inspect
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from base.schemas.weights import MasterWeightsResponse
from base.validator.weight_submitter import (
    ValidatorSubmitOutcome,
    ValidatorWeightSubmitter,
)

# Fixed reference time. Payloads anchor their computed_at/expires_at to REF and the
# submitter clock is pinned to REF, so freshness/expiry are deterministic. REF is in
# the future so MasterWeightsResponse's construction-time not-expired validator passes.
REF = datetime(2030, 1, 1, 12, 0, tzinfo=UTC)


def _fresh_payload(
    *,
    netuid: int = 100,
    computed_offset_seconds: int = 0,
    uids: list[int] | None = None,
    weights: list[float] | None = None,
) -> MasterWeightsResponse:
    """A valid, fresh master vector whose computed_at is ``offset`` secs before REF."""

    return MasterWeightsResponse(
        netuid=netuid,
        chain_endpoint="",
        uids=uids if uids is not None else [0, 1],
        weights=weights if weights is not None else [0.5, 0.5],
        computed_at=REF - timedelta(seconds=computed_offset_seconds),
        expires_at=REF + timedelta(seconds=1260),
        source_challenges=[],
        metagraph_updated_at=REF,
    )


class _FetchClient:
    """Stand-in ``WeightsClient`` returning a (mutable) canned master vector."""

    def __init__(self, payload: MasterWeightsResponse) -> None:
        self._payload = payload
        self.calls = 0

    async def fetch_latest(self) -> MasterWeightsResponse:
        self.calls += 1
        return self._payload

    def set_payload(self, payload: MasterWeightsResponse) -> None:
        self._payload = payload


class _RecordingSetter:
    """A ``WeightSetter`` stand-in bound to THIS validator's own hotkey."""

    def __init__(
        self,
        hotkey: str,
        *,
        result: Any = None,
        raises: BaseException | None = None,
    ) -> None:
        # Mirrors the real WeightSetter, which holds the node's own wallet/hotkey.
        self.wallet = SimpleNamespace(hotkey=SimpleNamespace(ss58_address=hotkey))
        self.calls: list[tuple[list[int], list[float]]] = []
        self._result = (
            result
            if result is not None
            else SimpleNamespace(success=True, message="ok")
        )
        self._raises = raises

    def set_weights(self, uids: list[int], weights: list[float]) -> Any:
        self.calls.append((list(uids), list(weights)))
        if self._raises is not None:
            raise self._raises
        return self._result


def _submitter(
    *,
    client: Any,
    setter: Any = None,
    factory: Any = None,
    submit_enabled: bool = True,
    netuid: int = 100,
) -> ValidatorWeightSubmitter:
    def default_factory() -> Any:
        return setter

    return ValidatorWeightSubmitter(
        submit_enabled=submit_enabled,
        netuid=netuid,
        weights_client=client,
        weight_setter_factory=factory or default_factory,
        clock=lambda: REF,
    )


# --- VAL-CODE-VWGT-001: fetch master vector, submit with OWN keypair ----------


async def test_fetches_master_vector_and_submits_with_own_keypair() -> None:
    payload = _fresh_payload(uids=[0, 3, 7], weights=[0.2, 0.3, 0.5])
    client = _FetchClient(payload)
    setter = _RecordingSetter("validator-a-hotkey")
    built = {"n": 0}

    def factory() -> _RecordingSetter:
        built["n"] += 1
        return setter

    submitter = _submitter(client=client, factory=factory)

    outcome = await submitter.run_once()

    assert outcome is ValidatorSubmitOutcome.SUBMITTED
    # It FETCHED the master vector (single source of truth) and committed that
    # SAME vector - it did NOT compute its own.
    assert client.calls == 1
    assert setter.calls == [([0, 3, 7], [0.2, 0.3, 0.5])]
    # Submitted under THIS validator's own hotkey.
    assert setter.wallet.hotkey.ss58_address == "validator-a-hotkey"
    assert built["n"] == 1


# --- VAL-CODE-VWGT-002: two independent validators; idempotent; gate off ------


async def test_two_independent_validators_each_submit_with_own_hotkey() -> None:
    # BOTH validators fetch the SAME master vector (single source of truth) and
    # each commits it under its OWN hotkey, sharing no state.
    payload = _fresh_payload(uids=[0, 1], weights=[0.4, 0.6])
    setter_a = _RecordingSetter("hotkey-A")
    setter_b = _RecordingSetter("hotkey-B")
    sub_a = _submitter(client=_FetchClient(payload), setter=setter_a)
    sub_b = _submitter(client=_FetchClient(payload), setter=setter_b)

    assert await sub_a.run_once() is ValidatorSubmitOutcome.SUBMITTED
    assert await sub_b.run_once() is ValidatorSubmitOutcome.SUBMITTED

    assert setter_a.calls == [([0, 1], [0.4, 0.6])]
    assert setter_b.calls == [([0, 1], [0.4, 0.6])]
    assert setter_a.wallet.hotkey.ss58_address == "hotkey-A"
    assert setter_b.wallet.hotkey.ss58_address == "hotkey-B"

    # Independent in-memory idempotency state: A re-running is a no-op for A and
    # does not touch B (no shared submission marker).
    assert await sub_a.run_once() is ValidatorSubmitOutcome.ALREADY_SUBMITTED
    assert len(setter_a.calls) == 1
    assert len(setter_b.calls) == 1


async def test_idempotent_rerun_is_noop_until_master_publishes_new_vector() -> None:
    client = _FetchClient(
        _fresh_payload(computed_offset_seconds=30, weights=[0.5, 0.5])
    )
    setter = _RecordingSetter("hotkey-A")
    submitter = _submitter(client=client, setter=setter)

    assert await submitter.run_once() is ValidatorSubmitOutcome.SUBMITTED
    # Same master vector (same computed_at) -> idempotent no-op, NO second commit.
    assert await submitter.run_once() is ValidatorSubmitOutcome.ALREADY_SUBMITTED
    assert await submitter.run_once() is ValidatorSubmitOutcome.ALREADY_SUBMITTED
    assert len(setter.calls) == 1

    # The master publishes a NEW vector (new computed_at) -> committed again.
    client.set_payload(_fresh_payload(computed_offset_seconds=10, weights=[0.3, 0.7]))
    assert await submitter.run_once() is ValidatorSubmitOutcome.SUBMITTED
    assert setter.calls == [([0, 1], [0.5, 0.5]), ([0, 1], [0.3, 0.7])]


async def test_gate_off_is_a_full_noop_no_fetch_no_setter_build() -> None:
    client = _FetchClient(_fresh_payload())

    def exploding_factory() -> Any:
        raise AssertionError("gate off must NOT build a WeightSetter / live Subtensor")

    submitter = _submitter(
        client=client, factory=exploding_factory, submit_enabled=False
    )

    outcome = await submitter.run_once()

    assert outcome is ValidatorSubmitOutcome.DISABLED
    assert submitter.submit_enabled is False
    assert client.calls == 0  # no fetch when gated off
    assert submitter.last_submitted_key is None


async def test_rejected_commit_is_retried_and_not_marked_submitted() -> None:
    # Crash/rate-limit safety: a rejected commit-reveal (chain rejects a too-fast
    # re-commit) is surfaced as REJECTED, not recorded, and retried next tick -
    # never a silent success, never double-counted.
    client = _FetchClient(_fresh_payload(computed_offset_seconds=30))
    setter = _RecordingSetter(
        "hotkey-A",
        raises=RuntimeError("subtensor rejected weight submission: TooFast"),
    )
    submitter = _submitter(client=client, setter=setter)

    assert await submitter.run_once() is ValidatorSubmitOutcome.REJECTED
    assert submitter.last_submitted_key is None
    assert len(setter.calls) == 1
    # Next tick attempts the same vector again (retained, not dropped).
    assert await submitter.run_once() is ValidatorSubmitOutcome.REJECTED
    assert len(setter.calls) == 2


async def test_rejected_result_object_also_retries() -> None:
    client = _FetchClient(_fresh_payload(computed_offset_seconds=30))
    setter = _RecordingSetter(
        "hotkey-A", result=SimpleNamespace(success=False, message="too fast")
    )
    submitter = _submitter(client=client, setter=setter)

    assert await submitter.run_once() is ValidatorSubmitOutcome.REJECTED
    assert submitter.last_submitted_key is None
    assert len(setter.calls) == 1


async def test_fetch_failure_is_no_vector_and_no_submit() -> None:
    class _BoomClient:
        def __init__(self) -> None:
            self.calls = 0

        async def fetch_latest(self) -> MasterWeightsResponse:
            self.calls += 1
            raise RuntimeError("master unreachable")

    setter = _RecordingSetter("hotkey-A")
    submitter = _submitter(client=_BoomClient(), setter=setter)

    assert await submitter.run_once() is ValidatorSubmitOutcome.NO_VECTOR
    assert setter.calls == []


async def test_invalid_master_vector_is_skipped() -> None:
    # A vector for the wrong netuid must never be committed.
    client = _FetchClient(_fresh_payload(netuid=999))
    setter = _RecordingSetter("hotkey-A")
    submitter = _submitter(client=client, setter=setter, netuid=100)

    assert await submitter.run_once() is ValidatorSubmitOutcome.NO_VECTOR
    assert setter.calls == []


# --- VAL-CODE-VWGT-003: clean master/validator separation ---------------------


def test_validator_submit_path_has_no_aggregation_dependency() -> None:
    import base.validator.weight_submitter as mod

    tree = ast.parse(inspect.getsource(mod))
    imported_modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.append(node.module)
        elif isinstance(node, ast.Import):
            imported_modules.extend(alias.name for alias in node.names)

    # Aggregation lives ONLY on the master; the validator submit path imports NO
    # master module (no validator-side aggregation / MasterWeightService).
    assert not any(m.startswith("base.master") for m in imported_modules), (
        imported_modules
    )
    # The validator obtains the canonical vector by FETCHING it (WeightsClient),
    # never by computing/aggregating it.
    assert "base.validator.weights_client" in imported_modules
