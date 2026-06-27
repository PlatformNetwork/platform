"""Weight-response freshness/expiry, submitter validation, dry-run vs mock-chain
submit, and multi-challenge emission-share aggregation.

Covers VAL-WEIGHTS-018..031:
- C. freshness/expiry fields on ``MasterWeightsResponse`` (018, 019).
- D. the single submitter fetches ``/v1/weights/latest`` and validates the
  vector (netuid match, not expired/stale, non-empty, equal-length) (020..024).
- E. dry-run/submit-disabled never calls the chain; submit-enabled + mock
  subtensor calls ``set_weights`` exactly once with the fetched vector; on-chain
  rejection is logged as failure; unhealthy/partial pipeline skips submit
  (025..028).
- F. agent-challenge + prism combine by emission share; only ACTIVE challenges
  are queried; the read path never submits on-chain (029..031).

All external systems are mocked (chain via a recording setter / mock subtensor,
challenge ``get_weights`` via a stub client, metagraph via a stub cache).
"""

from __future__ import annotations

import asyncio
import importlib.util
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from base.bittensor.metagraph_cache import MetagraphCache
from base.config.settings import Settings
from base.master.aggregator import aggregate_challenge_weights
from base.master.app_admin import create_admin_app
from base.master.challenge_client import ChallengeClient
from base.master.registry import ChallengeRegistry
from base.master.service import MasterWeightService, active_challenge_inputs
from base.schemas.challenge import (
    ChallengeCreate,
    ChallengeStatus,
    RuntimeOperationResponse,
)
from base.schemas.weights import (
    MASTER_WEIGHTS_FRESHNESS_SECONDS,
    ChallengeWeightsResult,
    MasterWeightsResponse,
)
from base.supervisor import weight_submit as ws
from base.validator.normal_runner import NormalValidatorRunner
from base.validator.weights_client import WeightsClient

FIXED_NOW = datetime(2030, 1, 1, 12, 0, tzinfo=UTC)

_ROOT = Path(__file__).resolve().parents[2]
_RUN_SUBMITTER = _ROOT / "deploy" / "swarm" / "submitter" / "run_submitter.py"


def _load_run_submitter() -> Any:
    spec = importlib.util.spec_from_file_location("run_submitter", _RUN_SUBMITTER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _master_response(
    now: datetime,
    *,
    netuid: int = 100,
    computed_at: datetime | None = None,
    expires_at: datetime | None = None,
    uids: list[int] | None = None,
    weights: list[float] | None = None,
) -> MasterWeightsResponse:
    """Build a real :class:`MasterWeightsResponse` (defaults: fresh + valid)."""
    return MasterWeightsResponse(
        netuid=netuid,
        chain_endpoint="wss://chain.example:9944",
        uids=[0, 1] if uids is None else uids,
        weights=[0.5, 0.5] if weights is None else weights,
        computed_at=computed_at if computed_at is not None else now,
        expires_at=(
            expires_at
            if expires_at is not None
            else now + timedelta(seconds=MASTER_WEIGHTS_FRESHNESS_SECONDS)
        ),
        source_challenges=[],
        metagraph_updated_at=now,
    )


class _RecordingSetter:
    """Mock subtensor weight setter recording every ``set_weights`` call."""

    def __init__(self, *, result: Any = None, raises: BaseException | None = None):
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


class _FetchClient:
    """Stand-in ``WeightsClient`` returning a canned payload from fetch_latest."""

    def __init__(self, payload: MasterWeightsResponse) -> None:
        self._payload = payload

    async def fetch_latest(self) -> MasterWeightsResponse:
        return self._payload


def _runner(
    *,
    netuid: int = 100,
    weights_client: Any = None,
    weight_setter: Any = None,
    weights_freshness_seconds: int = 720,
) -> NormalValidatorRunner:
    return NormalValidatorRunner(
        registry_client=cast(Any, None),
        orchestrator=cast(Any, None),
        weights_client=weights_client,
        weight_setter=weight_setter,
        netuid=netuid,
        weights_freshness_seconds=weights_freshness_seconds,
    )


# --- Multi-challenge integration helpers (mirror the get_weights lock tests) --


class StubMetagraphCache:
    def __init__(self, mapping: dict[str, int]) -> None:
        self._mapping = dict(mapping)
        self._updated_at = 0.0

    def get(self, *, force: bool = False) -> dict[str, int]:
        return dict(self._mapping)


class RecordingChallengeClient:
    """Records ``get_weights`` calls and returns canned validator-reported scores."""

    def __init__(self, weights_by_slug: dict[str, dict[str, float]]) -> None:
        self.weights_by_slug = weights_by_slug
        self.calls: list[str] = []

    async def get_weights(
        self,
        *,
        slug: str,
        base_url: str,
        token: str,
        emission_percent: float,
    ) -> ChallengeWeightsResult:
        self.calls.append(slug)
        return ChallengeWeightsResult(
            slug=slug,
            emission_percent=emission_percent,
            weights=dict(self.weights_by_slug.get(slug, {})),
            ok=True,
        )


class FakeRuntimeController:
    async def pull(self, slug: str) -> RuntimeOperationResponse:
        return RuntimeOperationResponse(slug=slug, operation="pull", status="ok")

    async def restart(self, slug: str) -> RuntimeOperationResponse:
        return RuntimeOperationResponse(slug=slug, operation="restart", status="ok")

    async def status(self, slug: str) -> RuntimeOperationResponse:
        return RuntimeOperationResponse(slug=slug, operation="status", status="ok")


def _make_registry(
    challenges: list[tuple[str, str, ChallengeStatus]],
) -> ChallengeRegistry:
    registry = ChallengeRegistry()
    for slug, emission, status in challenges:
        registry.create(
            ChallengeCreate(
                slug=slug,
                name=slug.title(),
                image=f"ghcr.io/baseintelligence/{slug}:1.0.0",
                version="1.0.0",
                emission_percent=emission,  # type: ignore[arg-type]
                status=status,
                internal_base_url=f"http://challenge-{slug}:8000",
            )
        )
    return registry


def _active_registry(challenges: list[tuple[str, str]]) -> ChallengeRegistry:
    return _make_registry(
        [(slug, emission, ChallengeStatus.ACTIVE) for slug, emission in challenges]
    )


def _service(
    *,
    mapping: dict[str, int],
    weights_by_slug: dict[str, dict[str, float]],
    weight_setter: Any = None,
) -> tuple[MasterWeightService, RecordingChallengeClient]:
    recorder = RecordingChallengeClient(weights_by_slug)
    service = MasterWeightService(
        metagraph_cache=cast(MetagraphCache, StubMetagraphCache(mapping)),
        weight_setter=weight_setter,
        challenge_client=cast(ChallengeClient, recorder),
    )
    return service, recorder


def _client(registry: ChallengeRegistry, service: MasterWeightService) -> TestClient:
    return TestClient(
        create_admin_app(
            registry=registry,
            runtime_controller=FakeRuntimeController(),
            weight_service=service,
            netuid=42,
            chain_endpoint="wss://chain.example:9944",
            now_fn=lambda: FIXED_NOW,
        )
    )


def _healthy_supervisor_response(
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


def _supervisor_submitter(
    *,
    setter: _RecordingSetter,
    response: MasterWeightsResponse | BaseException,
    submit_enabled: bool = True,
    clock: Any = None,
) -> tuple[ws.OnChainWeightSubmitter, list[ws.WeightsAlert]]:
    alerts: list[ws.WeightsAlert] = []

    def _compute(settings: Settings) -> MasterWeightsResponse:
        if isinstance(response, BaseException):
            raise response
        return response

    def _runtime(settings: Settings) -> Any:
        return SimpleNamespace(weight_setter=setter)

    submitter = ws.OnChainWeightSubmitter(
        Settings(),
        submit_enabled=submit_enabled,
        health_check=ws.default_pipeline_health,
        alert_emit=alerts.append,
        backoff=ws.BackoffPolicy(),
        compute=_compute,
        submit_runtime_factory=_runtime,
        clock=clock or (lambda: datetime.now(UTC)),
    )
    return submitter, alerts


# --- C. Freshness / expiry fields ---------------------------------------------


def test_compute_latest_response_sets_valid_freshness_window() -> None:
    """VAL-WEIGHTS-018."""
    registry = _active_registry([("agent-challenge", "40"), ("prism", "60")])
    service, _ = _service(
        mapping={"hkA": 1, "hkB": 2},
        weights_by_slug={"agent-challenge": {"hkA": 1.0}, "prism": {"hkB": 1.0}},
    )
    now = datetime.now(UTC)
    challenges, tokens = asyncio.run(active_challenge_inputs(registry))
    response = asyncio.run(
        service.compute_latest_response(
            challenges,
            tokens,
            netuid=42,
            chain_endpoint="wss://chain.example:9944",
            now_fn=lambda: now,
        )
    )

    assert response.computed_at == now
    assert response.expires_at == now + timedelta(
        seconds=MASTER_WEIGHTS_FRESHNESS_SECONDS
    )
    assert response.expires_at > response.computed_at
    assert (
        response.expires_at - response.computed_at
    ).total_seconds() == MASTER_WEIGHTS_FRESHNESS_SECONDS
    assert response.metagraph_updated_at is not None
    # A freshly computed response re-validates (not expired).
    revalidated = MasterWeightsResponse.model_validate(response.model_dump())
    assert revalidated.expires_at > datetime.now(UTC)


def test_expired_response_rejected_by_model() -> None:
    """VAL-WEIGHTS-019."""
    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        MasterWeightsResponse(
            netuid=42,
            chain_endpoint="wss://chain.example:9944",
            uids=[0],
            weights=[1.0],
            computed_at=now - timedelta(seconds=MASTER_WEIGHTS_FRESHNESS_SECONDS),
            expires_at=now - timedelta(seconds=1),
            source_challenges=[],
            metagraph_updated_at=now,
        )


# --- D. Submitter fetch + validation ------------------------------------------


def test_weights_client_fetches_latest_from_v1_weights_latest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """VAL-WEIGHTS-020."""
    now = datetime.now(UTC)
    payload = _master_response(now, netuid=100, uids=[0, 1], weights=[0.5, 0.5])
    body = payload.model_dump(mode="json")
    recorded: dict[str, str] = {}

    real_async_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        recorded["url"] = str(request.url)
        recorded["method"] = request.method
        return httpx.Response(200, json=body)

    transport = httpx.MockTransport(handler)

    def fake_async_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        return real_async_client(transport=transport)

    monkeypatch.setattr(httpx, "AsyncClient", fake_async_client)

    client = WeightsClient("http://master.example/")
    result = asyncio.run(client.fetch_latest())

    assert recorded["method"] == "GET"
    assert recorded["url"] == "http://master.example/v1/weights/latest"
    assert isinstance(result, MasterWeightsResponse)
    assert result.netuid == 100
    assert result.uids == [0, 1]
    assert result.weights == [0.5, 0.5]


def test_validate_rejects_netuid_mismatch() -> None:
    """VAL-WEIGHTS-021."""
    now = datetime.now(UTC)
    runner = _runner(netuid=100)
    failure = runner._validate_weights_payload(_master_response(now, netuid=999))
    assert failure is not None
    assert "netuid mismatch" in failure


def test_validate_rejects_expired_vector() -> None:
    """VAL-WEIGHTS-022 (expired)."""
    now = datetime.now(UTC)
    runner = _runner(netuid=100)
    payload = _master_response(now, netuid=100)
    payload.expires_at = now - timedelta(seconds=1)
    assert runner._validate_weights_payload(payload) == "payload expired"


def test_validate_rejects_stale_vector() -> None:
    """VAL-WEIGHTS-022 (stale)."""
    now = datetime.now(UTC)
    runner = _runner(netuid=100, weights_freshness_seconds=720)
    payload = _master_response(
        now,
        netuid=100,
        computed_at=now - timedelta(seconds=800),
        expires_at=now + timedelta(seconds=60),
    )
    assert runner._validate_weights_payload(payload) == "payload stale"


def test_validate_rejects_empty_uids() -> None:
    """VAL-WEIGHTS-023 (empty uids)."""
    now = datetime.now(UTC)
    runner = _runner(netuid=100)
    payload = _master_response(now, netuid=100, uids=[], weights=[])
    assert runner._validate_weights_payload(payload) == "uids vector is empty"


def test_validate_rejects_empty_weights() -> None:
    """VAL-WEIGHTS-023 (empty weights)."""
    now = datetime.now(UTC)
    runner = _runner(netuid=100)
    payload = _master_response(now, netuid=100, uids=[0], weights=[])
    assert runner._validate_weights_payload(payload) == "weights vector is empty"


def test_validate_rejects_unequal_lengths() -> None:
    """VAL-WEIGHTS-023 (unequal length)."""
    now = datetime.now(UTC)
    runner = _runner(netuid=100)
    payload = _master_response(now, netuid=100, uids=[0, 1], weights=[0.5])
    assert (
        runner._validate_weights_payload(payload)
        == "uids and weights vector lengths differ"
    )


def test_valid_payload_passes_validation() -> None:
    """VAL-WEIGHTS-024."""
    now = datetime.now(UTC)
    runner = _runner(netuid=100)
    payload = _master_response(now, netuid=100, uids=[0, 1], weights=[0.4, 0.6])
    assert runner._validate_weights_payload(payload) is None


@pytest.mark.parametrize("kind", ["netuid", "stale", "empty"])
def test_submit_latest_weights_skips_on_invalid_payload(kind: str) -> None:
    """VAL-WEIGHTS-021/022/023 (no submit when validation fails)."""
    now = datetime.now(UTC)
    if kind == "netuid":
        payload = _master_response(now, netuid=999)
    elif kind == "stale":
        payload = _master_response(
            now,
            netuid=100,
            computed_at=now - timedelta(seconds=800),
            expires_at=now + timedelta(seconds=60),
        )
    else:
        payload = _master_response(now, netuid=100, uids=[], weights=[])

    setter = _RecordingSetter()
    runner = _runner(
        netuid=100,
        weights_client=_FetchClient(payload),
        weight_setter=setter,
    )
    submitted = asyncio.run(runner.submit_latest_weights())

    assert submitted is False
    assert setter.calls == []


# --- E. Submitter dry-run vs mock-chain submit --------------------------------


def test_dry_run_submit_disabled_never_calls_chain(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """VAL-WEIGHTS-025."""
    setter = _RecordingSetter()
    computed = {"n": 0}

    def _compute(settings: Settings) -> MasterWeightsResponse:
        computed["n"] += 1
        return _healthy_supervisor_response()

    def _runtime(settings: Settings) -> Any:
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

    with caplog.at_level(logging.INFO, logger="base.supervisor.weight_submit"):
        submitter.run_once()

    assert setter.calls == []
    assert computed["n"] == 0
    assert not any(
        "weights submitted on-chain" in record.getMessage() for record in caplog.records
    )


def test_submitter_submits_fetched_vector_exactly_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """VAL-WEIGHTS-026 (the single submitter reads /v1/weights/latest)."""
    module = _load_run_submitter()
    now = datetime.now(UTC)
    payload = _master_response(now, netuid=100, uids=[0, 3, 7], weights=[0.2, 0.3, 0.5])
    setter = _RecordingSetter()
    runner = _runner(
        netuid=100,
        weights_client=_FetchClient(payload),
        weight_setter=setter,
    )

    with caplog.at_level(logging.INFO, logger="base.submitter"):
        asyncio.run(module._submit_once(runner))

    assert setter.calls == [([0, 3, 7], [0.2, 0.3, 0.5])]
    messages = [record.getMessage() for record in caplog.records]
    assert any("weights submitted on-chain" in message for message in messages)


def test_onchain_submitter_calls_set_weights_once_with_vector() -> None:
    """VAL-WEIGHTS-026 (supervisor OnChainWeightSubmitter path)."""
    setter = _RecordingSetter()
    response = _healthy_supervisor_response(uids=[0, 1], weights=[0.5, 0.5])
    submitter, alerts = _supervisor_submitter(setter=setter, response=response)

    submitter.run_once()

    assert setter.calls == [([0, 1], [0.5, 0.5])]
    assert alerts == []
    assert submitter.in_backoff is False


def test_submitter_logs_failure_on_chain_rejection_not_success(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """VAL-WEIGHTS-027."""
    module = _load_run_submitter()
    now = datetime.now(UTC)
    payload = _master_response(now, netuid=100)
    setter = _RecordingSetter(
        raises=RuntimeError("subtensor rejected weight submission: TooFast")
    )
    runner = _runner(
        netuid=100,
        weights_client=_FetchClient(payload),
        weight_setter=setter,
    )

    with caplog.at_level(logging.INFO, logger="base.submitter"):
        asyncio.run(module._submit_once(runner))

    messages = [record.getMessage() for record in caplog.records]
    assert any("weights submission failed" in message for message in messages)
    assert not any("weights submitted on-chain" in message for message in messages)


def test_onchain_submitter_rejected_result_backs_off_no_success() -> None:
    """VAL-WEIGHTS-027 (rejected result, supervisor path)."""
    setter = _RecordingSetter(result=SimpleNamespace(success=False, message="too fast"))
    response = _healthy_supervisor_response()
    submitter, alerts = _supervisor_submitter(setter=setter, response=response)

    submitter.run_once()

    assert len(setter.calls) == 1
    assert submitter.in_backoff is True
    assert len(alerts) == 1
    assert alerts[0].kind == "weights_submission_rejected"


def test_onchain_submitter_skips_unhealthy_pipeline() -> None:
    """VAL-WEIGHTS-028 (unhealthy challenge)."""
    setter = _RecordingSetter()
    response = _healthy_supervisor_response()
    response.source_challenges[1].ok = False
    response.source_challenges[1].error = "eval workers down"
    submitter, alerts = _supervisor_submitter(setter=setter, response=response)

    submitter.run_once()

    assert setter.calls == []
    assert len(alerts) == 1
    assert "agent-challenge" in alerts[0].message


def test_onchain_submitter_skips_partial_scores() -> None:
    """VAL-WEIGHTS-028 (partial/empty scores)."""
    setter = _RecordingSetter()
    response = _healthy_supervisor_response()
    response.source_challenges[0].weights = {}
    submitter, alerts = _supervisor_submitter(setter=setter, response=response)

    submitter.run_once()

    assert setter.calls == []
    assert len(alerts) == 1
    assert "prism" in alerts[0].message


# --- F. Multi-challenge integration (agent-challenge + prism) -----------------


def test_multichallenge_emission_share_combination() -> None:
    """VAL-WEIGHTS-029 (read path combines by emission share)."""
    registry = _active_registry(
        [("prism", "30"), ("agent-challenge", "15"), ("other", "5")]
    )
    service, _ = _service(
        mapping={"prism-hotkey": 30, "agent-hotkey": 15, "other-hotkey": 5},
        weights_by_slug={
            "prism": {"prism-hotkey": 1.0},
            "agent-challenge": {"agent-hotkey": 1.0},
            "other": {"other-hotkey": 1.0},
        },
    )
    client = _client(registry, service)

    response = client.get("/v1/weights/latest")
    assert response.status_code == 200
    body = response.json()

    assert body["uids"] == [5, 15, 30]
    assert [round(w, 8) for w in body["weights"]] == [0.1, 0.3, 0.6]
    hotkey_weights = {k: round(v, 8) for k, v in body["hotkey_weights"].items()}
    assert hotkey_weights == {
        "prism-hotkey": 0.6,
        "agent-hotkey": 0.3,
        "other-hotkey": 0.1,
    }
    emissions = {
        item["slug"]: item["emission_percent"] for item in body["source_challenges"]
    }
    assert emissions == {"prism": 30.0, "agent-challenge": 15.0, "other": 5.0}


def test_multichallenge_failed_challenge_excluded_from_denominator() -> None:
    """VAL-WEIGHTS-029 (ok=False challenge excluded from emission denominator)."""
    results = [
        ChallengeWeightsResult(
            slug="prism", emission_percent=30, weights={"prism-hotkey": 1}
        ),
        ChallengeWeightsResult(
            slug="agent-challenge", emission_percent=15, weights={"agent-hotkey": 1}
        ),
        ChallengeWeightsResult(
            slug="other", emission_percent=5, weights={"other-hotkey": 1}
        ),
        ChallengeWeightsResult(
            slug="down", emission_percent=50, weights={"down-hotkey": 1}, ok=False
        ),
    ]
    mapping = {
        "prism-hotkey": 30,
        "agent-hotkey": 15,
        "other-hotkey": 5,
        "down-hotkey": 99,
    }
    final = aggregate_challenge_weights(results, mapping)

    assert final.uids == [5, 15, 30]
    assert [round(w, 8) for w in final.weights] == [0.1, 0.3, 0.6]
    assert "down-hotkey" not in final.hotkey_weights


def test_only_active_challenges_queried_and_aggregated() -> None:
    """VAL-WEIGHTS-030."""
    registry = _make_registry(
        [
            ("active-one", "100", ChallengeStatus.ACTIVE),
            ("inactive-one", "50", ChallengeStatus.INACTIVE),
        ]
    )
    service, recorder = _service(
        mapping={"hkA": 1},
        weights_by_slug={"active-one": {"hkA": 1.0}},
    )
    client = _client(registry, service)

    response = client.get("/v1/weights/latest")
    assert response.status_code == 200
    body = response.json()

    assert recorder.calls == ["active-one"]
    slugs = [item["slug"] for item in body["source_challenges"]]
    assert slugs == ["active-one"]
    assert "inactive-one" not in slugs


def test_weights_latest_read_never_triggers_onchain_submit() -> None:
    """VAL-WEIGHTS-031."""
    registry = _active_registry([("agent-challenge", "40"), ("prism", "60")])
    setter = _RecordingSetter()
    service, _ = _service(
        mapping={"hkA": 1, "hkB": 2},
        weights_by_slug={"agent-challenge": {"hkA": 1.0}, "prism": {"hkB": 1.0}},
        weight_setter=cast(Any, setter),
    )
    client = _client(registry, service)

    for _ in range(3):
        assert client.get("/v1/weights/latest").status_code == 200

    assert setter.calls == []
