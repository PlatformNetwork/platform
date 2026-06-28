"""End-to-end integration tests for the decentralized evaluation flows.

These exercise the platform master's role as *coordinator + aggregator* across
the full decentralized lifecycle with every external system mocked (architecture
sec 10): the LLM gateway runs the mock provider, the broker / GPU re-execution is
faked, HuggingFace is an in-memory publisher, and the chain submit is a recording
mock. The "challenge service" parts that live in the sibling repos
(agent-challenge / prism) are represented by an in-process :class:`ChallengeFabric`
that obeys the preserved contracts: it exposes gated pending work units and
computes ``get_weights`` strictly from validator-reported results persisted in the
control-plane ``work_results`` table.

One real master proxy app (built via :func:`create_proxy_app`) carries the live
coordination plane (register/heartbeat/pull/progress/result), the LLM gateway, and
the recompute-on-read ``/v1/weights/latest`` endpoint over a shared control-plane
DB. Real :class:`ValidatorAgent` instances drive pull -> execute-on-own-broker ->
post; the real :class:`MasterOrchestrationDriver` bridges work units and runs the
balanced assignment + reassignment passes.

Covers VAL-CROSS-001..013:
- 001 agent-challenge full lifecycle to dry-run submit
- 002 prism full lifecycle to dry-run submit
- 003 gateway is the sole LLM path
- 004 agent-challenge crash + reassign, no double-count
- 005 prism crash + resume from last public HF checkpoint
- 006 result idempotency across reassignment
- 007 ineligible hotkey never influences weights
- 008 decentralization: execution never runs on the master
- 009 no-direct-weights burn fallback
- 010 agent-challenge + prism combine by emission share
- 011 capability routing across both challenges
- 012 preserved get_weights contract shape end-to-end
- 013 weights are recompute-on-read
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from base.bittensor.metagraph_cache import MetagraphCache
from base.db import (
    Base,
    Validator,
    ValidatorStatus,
    WorkResult,
    create_engine,
    create_session_factory,
    session_scope,
)
from base.db.models import WorkAssignment, WorkAssignmentStatus
from base.master.app_proxy import create_proxy_app
from base.master.assignment import (
    AGENT_CHALLENGE_SLUG,
    PRISM_SLUG,
    RESUME_CHECKPOINT_PAYLOAD_KEY,
    AssignmentService,
)
from base.master.assignment_coordination import (
    AssignmentCoordinationService,
    WorkAssignmentLifecycleResolver,
)
from base.master.llm_gateway import ProviderConfig, build_llm_gateway_service
from base.master.orchestration import (
    ChallengePendingWork,
    MasterOrchestrationDriver,
    OrchestrationPassResult,
)
from base.master.registry import ChallengeRegistry
from base.master.service import MasterWeightService
from base.master.validator_coordination import ValidatorCoordinationService
from base.schemas.challenge import (
    ChallengeCreate,
    ChallengeStatus,
    RuntimeOperationResponse,
)
from base.schemas.weights import (
    ChallengeWeightsResponse,
    ChallengeWeightsResult,
    MasterWeightsResponse,
)
from base.security.validator_auth import (
    MetagraphValidatorEligibility,
    SqlAlchemyValidatorNonceStore,
    ValidatorSignedRequestVerifier,
)
from base.validator.agent import (
    AssignmentContext,
    BrokerConfig,
    CoordinationClient,
    CoordinationClientError,
    ExecutionResult,
    ValidatorAgent,
)
from base.validator.agent.executor import ProgressCallback
from base.validator.normal_runner import NormalValidatorRunner

# A logical clock far in the future so every computed weights response stays
# valid against the real wall clock (mirrors the FIXED_NOW pattern in the
# weights tests). Crash tests advance this clock to trip the heartbeat timeout.
BASE_EPOCH = datetime(2035, 1, 1, 12, 0, tzinfo=UTC).timestamp()
HEARTBEAT_INTERVAL = 60
HEARTBEAT_TIMEOUT = 180
LEASE_SECONDS = 900
NETUID = 100
ADMIN_TOKEN = "admin-secret-token"
DEEPSEEK_KEY = "ds-provider-secret-key"
OPENROUTER_KEY = "or-provider-secret-key"
GATEWAY_TOKEN_SECRET = "gateway-hmac-secret"

# The secret val/test held-out split must NEVER leave the master; it is only
# referenced inside the master-side held-out scorer and is asserted absent from
# every validator-facing payload.
HELDOUT_SECRET = "SECRET_VALTEST_SPLIT_DO_NOT_LEAK"

MINER_AGENT = "miner-agent-hotkey"
MINER_PRISM = "miner-prism-hotkey"
MINER_UIDS = {MINER_AGENT: 11, MINER_PRISM: 22}

VAL_CPU_1 = "val-cpu-1"
VAL_CPU_2 = "val-cpu-2"
VAL_GPU_1 = "val-gpu-1"
VAL_GPU_2 = "val-gpu-2"
PERMITTED_VALIDATORS = (VAL_CPU_1, VAL_CPU_2, VAL_GPU_1, VAL_GPU_2)
INTRUDER = "intruder-hotkey"

AGENT_TASKS = ("t1", "t2", "t3", "t4")
GATEWAY_TOKEN_KEY = "gateway_token"


# --------------------------------------------------------------------------- #
# Stubs / mocks for external systems
# --------------------------------------------------------------------------- #
class MutableClock:
    """A callable logical clock shared by the coordination + weights services."""

    def __init__(self, epoch: float) -> None:
        self.epoch = float(epoch)

    def time(self) -> float:
        return self.epoch

    def now(self) -> datetime:
        return datetime.fromtimestamp(self.epoch, UTC)

    def advance(self, seconds: float) -> None:
        self.epoch += float(seconds)


class FakeNonceStore:
    """Miner-upload nonce store stub (the miner upload path is unused here)."""

    async def reserve(self, **_: Any) -> None:
        return None


class FakeMinerCache:
    """Miner-upload metagraph stub (the miner upload path is unused here)."""

    def get(self) -> dict[str, int]:
        return {}


class StubMetagraphCache:
    """hotkey->uid map for the weight service (architecture: hotkey->UID)."""

    def __init__(self, mapping: Mapping[str, int]) -> None:
        self._mapping = dict(mapping)
        self._updated_at = 0.0

    def get(self, *, force: bool = False) -> dict[str, int]:
        return dict(self._mapping)


class FakeRuntimeController:
    async def pull(self, slug: str) -> RuntimeOperationResponse:
        return RuntimeOperationResponse(slug=slug, operation="pull", status="ok")

    async def restart(self, slug: str) -> RuntimeOperationResponse:
        return RuntimeOperationResponse(slug=slug, operation="restart", status="ok")

    async def status(self, slug: str) -> RuntimeOperationResponse:
        return RuntimeOperationResponse(slug=slug, operation="status", status="ok")


def _sign(hotkey: str, canonical: str) -> str:
    return hashlib.sha256(f"{hotkey}:{canonical}".encode()).hexdigest()


def _signature_verifier(hotkey: str, message: bytes, signature: str) -> bool:
    return signature == _sign(hotkey, message.decode())


class FakeSigner:
    """Client signer matching the stubbed server signature verifier."""

    def __init__(self, hotkey: str) -> None:
        self._hotkey = hotkey

    @property
    def hotkey(self) -> str:
        return self._hotkey

    def sign(self, message: bytes) -> str:
        return _sign(self._hotkey, message.decode())


class ForgedSigner:
    """Signer that always emits a non-verifying signature (forged request)."""

    def __init__(self, hotkey: str) -> None:
        self._hotkey = hotkey

    @property
    def hotkey(self) -> str:
        return self._hotkey

    def sign(self, message: bytes) -> str:
        return "00" * 32


class RecordingWeightSetter:
    """Mock subtensor weight setter recording every set_weights call."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[int], list[float]]] = []

    def set_weights(self, uids: list[int], weights: list[float]) -> Any:
        self.calls.append((list(uids), list(weights)))
        return SimpleNamespace(success=True, message="ok")


@dataclass
class BrokerExecution:
    """A recorded broker dispatch, always attributed to a validator context."""

    validator_hotkey: str
    broker_url: str
    work_unit_id: str


class BrokerLedger:
    """Records every broker/GPU execution so we can prove validator attribution.

    The master coordinator never executes; only validator-side executors record
    here, so an empty ledger after a coordination/aggregation pass proves no
    master-side execution (VAL-CROSS-008).
    """

    def __init__(self) -> None:
        self.executions: list[BrokerExecution] = []

    def record(
        self, *, validator_hotkey: str, broker_url: str, work_unit_id: str
    ) -> None:
        self.executions.append(
            BrokerExecution(validator_hotkey, broker_url, work_unit_id)
        )


class MockHuggingFace:
    """In-memory HuggingFace checkpoint publisher/loader (no real network)."""

    def __init__(self) -> None:
        self.published: list[str] = []
        self.downloaded: list[str] = []
        self._store: dict[str, str] = {}

    def publish(self, ref: str, *, state: str) -> None:
        self.published.append(ref)
        self._store[ref] = state

    def download(self, ref: str) -> str:
        self.downloaded.append(ref)
        return self._store.get(ref, ref)


def heldout_scorer(
    loss_stream: Sequence[float], trained_state: str, *, secret: str
) -> float:
    """Master-only held-out score from the reported online-loss stream.

    Uses the secret val/test split (which never leaves the master). The score is
    a deterministic monotone function of the final reported loss.
    """

    assert secret == HELDOUT_SECRET  # only the master holds the held-out split
    final_loss = float(loss_stream[-1]) if loss_stream else 100.0
    return round(1.0 / (1.0 + final_loss), 6)


# --------------------------------------------------------------------------- #
# In-process challenge model (work source + report-backed get_weights)
# --------------------------------------------------------------------------- #
@dataclass
class Submission:
    slug: str
    submission_id: str
    hotkey: str
    task_ids: tuple[str, ...] = ()
    verdict: str = "allow"
    effective_status: str = "valid"
    checkpoint_ref: str | None = None


class ChallengeFabric:
    """Models the challenge services: gated work units + report-backed weights.

    Implements both the orchestration ``ChallengeWorkSource`` (gated pending
    work) and the weight service's ``ChallengeClient`` (``get_weights`` computed
    only from validator-reported ``work_results``), so the platform end-to-end
    flow runs against a faithful stand-in for the sibling challenge repos.
    """

    def __init__(self, session_factory: Any) -> None:
        self._session_factory = session_factory
        self._submissions: dict[str, Submission] = {}
        self.last_get_weights_payload: dict[str, dict[str, Any]] = {}

    def submit(self, submission: Submission) -> None:
        self._submissions[submission.submission_id] = submission

    # -- ChallengeWorkSource ------------------------------------------------- #
    async def fetch_pending_work(self) -> list[ChallengePendingWork]:
        works: list[ChallengePendingWork] = []
        for sub in self._submissions.values():
            if sub.verdict != "allow":
                continue
            if sub.slug == AGENT_CHALLENGE_SLUG:
                works.append(
                    ChallengePendingWork(
                        challenge_slug=sub.slug,
                        submission_id=sub.submission_id,
                        submission_ref=sub.hotkey,
                        task_ids=sub.task_ids,
                        job_id=f"job-{sub.submission_id}",
                    )
                )
            else:
                works.append(
                    ChallengePendingWork(
                        challenge_slug=sub.slug,
                        submission_id=sub.submission_id,
                        submission_ref=sub.hotkey,
                        checkpoint_ref=sub.checkpoint_ref,
                    )
                )
        return works

    # -- ChallengeClient ----------------------------------------------------- #
    async def get_weights(
        self,
        *,
        slug: str,
        base_url: str,
        token: str,
        emission_percent: float,
    ) -> ChallengeWeightsResult:
        payload = await self._compute_payload(slug)
        # Enforce the preserved get_weights contract shape on the way out.
        validated = ChallengeWeightsResponse.model_validate(payload)
        self.last_get_weights_payload[slug] = payload
        return ChallengeWeightsResult(
            slug=slug,
            emission_percent=emission_percent,
            weights=dict(validated.weights),
            ok=True,
        )

    async def _compute_payload(self, slug: str) -> dict[str, Any]:
        if slug == AGENT_CHALLENGE_SLUG:
            weights = await self._agent_challenge_weights()
        elif slug == PRISM_SLUG:
            weights = await self._prism_weights()
        else:
            weights = {}
        return {"challenge_slug": slug, "epoch": 1, "weights": weights}

    async def _completed_results_by_unit(self, slug: str) -> dict[str, WorkResult]:
        async with self._session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(WorkResult).where(
                            WorkResult.challenge_slug == slug,
                            WorkResult.success.is_(True),
                        )
                    )
                )
                .scalars()
                .all()
            )
        by_unit: dict[str, WorkResult] = {}
        for row in rows:
            by_unit[row.work_unit_id] = row
        return by_unit

    async def _agent_challenge_weights(self) -> dict[str, float]:
        by_unit = await self._completed_results_by_unit(AGENT_CHALLENGE_SLUG)
        weights: dict[str, float] = {}
        for sub in self._submissions.values():
            if sub.slug != AGENT_CHALLENGE_SLUG or sub.verdict != "allow":
                continue
            if sub.effective_status not in {"valid", "overridden_valid"}:
                continue
            unit_ids = [f"{sub.submission_id}:{task}" for task in sub.task_ids]
            scores = [
                float(by_unit[unit].payload.get("score", 0.0))
                for unit in unit_ids
                if unit in by_unit
            ]
            # The job only finalizes once every selected task has a result.
            if len(scores) < len(unit_ids):
                continue
            job_score = sum(scores) / len(scores)
            weights[sub.hotkey] = max(weights.get(sub.hotkey, 0.0), job_score)
        return weights

    async def _prism_weights(self) -> dict[str, float]:
        by_unit = await self._completed_results_by_unit(PRISM_SLUG)
        weights: dict[str, float] = {}
        for sub in self._submissions.values():
            if sub.slug != PRISM_SLUG or sub.verdict != "allow":
                continue
            if sub.effective_status not in {"valid", "overridden_valid"}:
                continue
            row = by_unit.get(sub.submission_id)
            if row is None:
                continue
            score = heldout_scorer(
                row.payload.get("loss_stream", []),
                str(row.payload.get("trained_state", "")),
                secret=HELDOUT_SECRET,
            )
            weights[sub.hotkey] = max(weights.get(sub.hotkey, 0.0), score)
        return weights


# --------------------------------------------------------------------------- #
# Validator-side executor (routes LLM via gateway, records own-broker dispatch)
# --------------------------------------------------------------------------- #
async def _call_gateway(
    transport: ASGITransport, path: str, model: str, token: str | None
) -> int:
    headers = {"X-Gateway-Token": token} if token else {}
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            path, json={"model": model, "messages": []}, headers=headers
        )
    return response.status_code


def _holds_provider_key(env: Mapping[str, str]) -> bool:
    return any(key.endswith("_API_KEY") for key in env)


class ValidatorWorkExecutor:
    """Challenge-aware validator executor (runs on the validator's OWN broker).

    Dispatches by ``challenge_slug`` so a single validator handles whatever it is
    assigned: agent-challenge tasks (DeepSeek via gateway, per-task score) and
    prism runs (mock CPU re-exec, anthropic/claude-opus-4.8 review via gateway,
    mock HF checkpoint, online-loss stream + trained_state). Every LLM call routes
    through the master gateway with the per-assignment scoped token; the runtime
    holds no provider key.
    """

    def __init__(
        self,
        *,
        hotkey: str,
        transport: ASGITransport,
        broker_ledger: BrokerLedger,
        hf: MockHuggingFace,
    ) -> None:
        self._hotkey = hotkey
        self._transport = transport
        self._broker_ledger = broker_ledger
        self._hf = hf

    async def execute(
        self, context: AssignmentContext, *, progress: ProgressCallback
    ) -> ExecutionResult:
        self._broker_ledger.record(
            validator_hotkey=self._hotkey,
            broker_url=context.broker.broker_url,
            work_unit_id=context.assignment.work_unit_id,
        )
        if context.assignment.challenge_slug == PRISM_SLUG:
            return await self._execute_prism(context, progress=progress)
        return await self._execute_agent_challenge(context)

    async def _execute_agent_challenge(
        self, context: AssignmentContext
    ) -> ExecutionResult:
        env = context.gateway_env
        held_provider_key = _holds_provider_key(env)
        gateway_status = await _call_gateway(
            self._transport,
            "/llm/deepseek/chat/completions",
            "deepseek-v4-pro",
            env.get("BASE_GATEWAY_TOKEN"),
        )
        payload = context.assignment.payload or {}
        task_id = (
            payload.get("task_id") or context.assignment.work_unit_id.split(":", 1)[-1]
        )
        return ExecutionResult(
            success=True,
            payload={
                "score": 1.0,
                "task_id": task_id,
                "gateway_status": gateway_status,
                "held_provider_key": held_provider_key,
                "deepseek_base_url": env.get("DEEPSEEK_BASE_URL"),
            },
        )

    async def _execute_prism(
        self, context: AssignmentContext, *, progress: ProgressCallback
    ) -> ExecutionResult:
        env = context.gateway_env
        held_provider_key = _holds_provider_key(env)
        gateway_status = await _call_gateway(
            self._transport,
            "/llm/openrouter/chat/completions",
            "anthropic/claude-opus-4.8",
            env.get("BASE_GATEWAY_TOKEN"),
        )
        payload = context.assignment.payload or {}
        resume_ref = payload.get(RESUME_CHECKPOINT_PAYLOAD_KEY)
        resumed = False
        if resume_ref:
            self._hf.download(str(resume_ref))
            resumed = True
        submission = context.assignment.work_unit_id
        checkpoint_ref = f"hf://prism/{submission}/step-1"
        self._hf.publish(checkpoint_ref, state=f"trained-{submission}")
        await progress(checkpoint_ref=checkpoint_ref)
        loss_stream = [1.0, 0.5, 0.25] if resumed else [3.0, 2.0, 1.0]
        return ExecutionResult(
            success=True,
            payload={
                "loss_stream": loss_stream,
                "trained_state": f"state-{submission}",
                "resumed": resumed,
                "gateway_status": gateway_status,
                "held_provider_key": held_provider_key,
            },
            checkpoint_ref=checkpoint_ref,
        )


# --------------------------------------------------------------------------- #
# Harness wiring the master app + coordination + gateway + weights + driver
# --------------------------------------------------------------------------- #
class Harness:
    def __init__(
        self,
        *,
        app: Any,
        engine: Any,
        session_factory: Any,
        clock: MutableClock,
        gateway_service: Any,
        fabric: ChallengeFabric,
        broker_ledger: BrokerLedger,
        hf: MockHuggingFace,
        driver: MasterOrchestrationDriver,
        registry: ChallengeRegistry,
    ) -> None:
        self.app = app
        self.transport = ASGITransport(app=app)
        self.engine = engine
        self.session_factory = session_factory
        self.clock = clock
        self.gateway_service = gateway_service
        self.fabric = fabric
        self.broker_ledger = broker_ledger
        self.hf = hf
        self.driver = driver
        self.registry = registry

    @classmethod
    async def build(
        cls, *, active: Sequence[tuple[str, str]] = (("agent-challenge", "100"),)
    ) -> Harness:
        engine = create_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        session_factory = create_session_factory(engine)

        clock = MutableClock(BASE_EPOCH)

        cache = MetagraphCache(netuid=NETUID, ttl_seconds=300)
        cache.update_from_metagraph(
            list(PERMITTED_VALIDATORS),
            validator_permits=[True] * len(PERMITTED_VALIDATORS),
            stakes=[100.0] * len(PERMITTED_VALIDATORS),
        )
        verifier = ValidatorSignedRequestVerifier(
            nonce_store=SqlAlchemyValidatorNonceStore(session_factory),
            eligibility=MetagraphValidatorEligibility(cache),
            signature_verifier=_signature_verifier,
            ttl_seconds=300,
            now_fn=clock.time,
        )
        validator_service = ValidatorCoordinationService(
            session_factory,
            heartbeat_interval_seconds=HEARTBEAT_INTERVAL,
            heartbeat_timeout_seconds=HEARTBEAT_TIMEOUT,
            now_fn=clock.now,
        )
        assignment_coordination_service = AssignmentCoordinationService(
            session_factory, lease_seconds=LEASE_SECONDS, now_fn=clock.now
        )
        assignment_service = AssignmentService(session_factory, now_fn=clock.now)
        gateway_service = build_llm_gateway_service(
            deepseek_api_key=DEEPSEEK_KEY,
            openrouter_api_key=OPENROUTER_KEY,
            token_secret=GATEWAY_TOKEN_SECRET,
            provider_config=ProviderConfig(mode="mock"),
            assignment_resolver=WorkAssignmentLifecycleResolver(session_factory),
        )
        fabric = ChallengeFabric(session_factory)
        driver = MasterOrchestrationDriver(
            assignment_service=assignment_service,
            validator_service=validator_service,
            work_source=fabric,
            seed=7,
        )
        weight_service = MasterWeightService(
            metagraph_cache=cast(MetagraphCache, StubMetagraphCache(MINER_UIDS)),
            challenge_client=cast(Any, fabric),
        )

        registry = ChallengeRegistry()
        for slug, emission in active:
            registry.create(
                ChallengeCreate(
                    slug=slug,
                    name=slug.title(),
                    image=f"ghcr.io/baseintelligence/{slug}:1.0.0",
                    version="1.0.0",
                    emission_percent=emission,  # type: ignore[arg-type]
                    status=ChallengeStatus.ACTIVE,
                    internal_base_url=f"http://challenge-{slug}:8000",
                )
            )

        app = create_proxy_app(
            registry=registry,
            nonce_store=cast(Any, FakeNonceStore()),
            metagraph_cache=cast(Any, FakeMinerCache()),
            runtime_controller=cast(Any, FakeRuntimeController()),
            weight_service=weight_service,
            netuid=NETUID,
            chain_endpoint="wss://chain.example:9944",
            now_fn=clock.now,
            admin_token_provider=lambda: ADMIN_TOKEN,
            validator_service=validator_service,
            validator_verifier=verifier,
            assignment_coordination_service=assignment_coordination_service,
            llm_gateway_service=gateway_service,
        )
        return cls(
            app=app,
            engine=engine,
            session_factory=session_factory,
            clock=clock,
            gateway_service=gateway_service,
            fabric=fabric,
            broker_ledger=BrokerLedger(),
            hf=MockHuggingFace(),
            driver=driver,
            registry=registry,
        )

    # -- validator agents ---------------------------------------------------- #
    def coordination_client(
        self, hotkey: str, *, signer: Any = None
    ) -> CoordinationClient:
        return CoordinationClient(
            "http://testserver",
            signer or FakeSigner(hotkey),
            transport=self.transport,
            now_fn=self.clock.time,
        )

    def work_executor(self, hotkey: str) -> ValidatorWorkExecutor:
        return ValidatorWorkExecutor(
            hotkey=hotkey,
            transport=self.transport,
            broker_ledger=self.broker_ledger,
            hf=self.hf,
        )

    def agent(self, *, hotkey: str, capabilities: list[str]) -> ValidatorAgent:
        return ValidatorAgent(
            client=self.coordination_client(hotkey),
            executor=self.work_executor(hotkey),
            broker=BrokerConfig(broker_url=f"http://broker-{hotkey}:8082"),
            capabilities=capabilities,
            version="1.0.0",
            gateway_url="http://testserver",
            heartbeat_interval_seconds=HEARTBEAT_INTERVAL,
            poll_interval_seconds=0.01,
        )

    # -- orchestration ------------------------------------------------------- #
    async def run_orchestration(self) -> OrchestrationPassResult:
        result = await self.driver.run_once()
        await self.stamp_gateway_tokens()
        return result

    async def stamp_gateway_tokens(self) -> None:
        """Issue a per-(validator, assignment) scoped gateway token at assign time.

        Models the master injecting a scoped token into each assignment payload so
        the validator surfaces it to its eval runtime (no provider key) and the
        token is re-scoped on reassignment. Other payload keys (e.g. the prism
        resume checkpoint ref) are preserved.
        """

        async with session_scope(self.session_factory) as session:
            rows = (
                (
                    await session.execute(
                        select(WorkAssignment).where(
                            WorkAssignment.assigned_validator_hotkey.is_not(None),
                            WorkAssignment.status.in_(
                                (
                                    WorkAssignmentStatus.ASSIGNED,
                                    WorkAssignmentStatus.RUNNING,
                                )
                            ),
                        )
                    )
                )
                .scalars()
                .all()
            )
            for row in rows:
                hotkey = row.assigned_validator_hotkey
                assert hotkey is not None
                payload = dict(row.payload or {})
                if payload.get("validator") == hotkey and payload.get(
                    GATEWAY_TOKEN_KEY
                ):
                    continue
                token = self.gateway_service.issue_token(
                    validator_hotkey=hotkey, assignment_id=str(row.id)
                )
                payload[GATEWAY_TOKEN_KEY] = token
                payload["validator"] = hotkey
                row.payload = payload

    # -- DB queries ---------------------------------------------------------- #
    async def assignments(self) -> list[WorkAssignment]:
        async with self.session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(WorkAssignment).order_by(WorkAssignment.work_unit_id)
                    )
                )
                .scalars()
                .all()
            )
            return list(rows)

    async def work_results(self) -> list[WorkResult]:
        async with self.session_factory() as session:
            rows = (await session.execute(select(WorkResult))).scalars().all()
            return list(rows)

    async def validator(self, hotkey: str) -> Validator | None:
        async with self.session_factory() as session:
            return (
                await session.execute(
                    select(Validator).where(Validator.hotkey == hotkey)
                )
            ).scalar_one_or_none()

    # -- weights + submitter ------------------------------------------------- #
    async def weights_latest(self) -> dict[str, Any]:
        async with AsyncClient(
            transport=self.transport, base_url="http://testserver"
        ) as client:
            response = await client.get("/v1/weights/latest")
        assert response.status_code == 200, response.text
        return response.json()

    async def submitter_dry_run(
        self,
    ) -> tuple[bool, list[tuple[list[int], list[float]]]]:
        body = await self.weights_latest()
        payload = MasterWeightsResponse.model_validate(body)
        setter = RecordingWeightSetter()
        runner = NormalValidatorRunner(
            registry_client=cast(Any, None),
            orchestrator=cast(Any, None),
            weights_client=cast(Any, _FetchClient(payload)),
            weight_setter=cast(Any, setter),
            netuid=NETUID,
            weights_freshness_seconds=720,
        )
        submitted = await runner.submit_latest_weights()
        return submitted, setter.calls


class _FetchClient:
    def __init__(self, payload: MasterWeightsResponse) -> None:
        self._payload = payload

    async def fetch_latest(self) -> MasterWeightsResponse:
        return self._payload


@pytest.fixture
async def harness_factory() -> AsyncIterator[Callable[..., Any]]:
    created: list[Harness] = []

    async def _factory(
        *, active: Sequence[tuple[str, str]] = (("agent-challenge", "100"),)
    ) -> Harness:
        harness = await Harness.build(active=active)
        created.append(harness)
        return harness

    try:
        yield _factory
    finally:
        for harness in created:
            await harness.engine.dispose()


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def _agent_submission(submission_id: str = "sub-agent") -> Submission:
    return Submission(
        slug=AGENT_CHALLENGE_SLUG,
        submission_id=submission_id,
        hotkey=MINER_AGENT,
        task_ids=AGENT_TASKS,
    )


def _prism_submission(submission_id: str = "psub-1") -> Submission:
    return Submission(
        slug=PRISM_SLUG,
        submission_id=submission_id,
        hotkey=MINER_PRISM,
    )


def _no_secret_leak(rows: Sequence[Any]) -> None:
    for row in rows:
        assert HELDOUT_SECRET not in str(row.payload or {})


async def _run_both_challenges(h: Harness) -> None:
    """Drive both lifecycles to completion (1 cpu + 1 gpu validator)."""

    cpu_agent = h.agent(hotkey=VAL_CPU_1, capabilities=["cpu"])
    gpu_agent = h.agent(hotkey=VAL_GPU_1, capabilities=["gpu"])
    await cpu_agent.register()
    await gpu_agent.register()
    h.fabric.submit(_agent_submission())
    h.fabric.submit(_prism_submission())
    await h.run_orchestration()
    await cpu_agent.process_pending_assignments()
    await gpu_agent.process_pending_assignments()


# --------------------------------------------------------------------------- #
# A. Full lifecycle - success paths
# --------------------------------------------------------------------------- #
async def test_agent_challenge_full_lifecycle_to_dry_run_submit(
    harness_factory: Callable[..., Any],
) -> None:
    """VAL-CROSS-001."""
    h: Harness = await harness_factory(active=[("agent-challenge", "100")])

    agent_a = h.agent(hotkey=VAL_CPU_1, capabilities=["cpu"])
    agent_b = h.agent(hotkey=VAL_CPU_2, capabilities=["cpu"])
    await agent_a.register()
    await agent_b.register()

    # (1)-(2) submission accepted, central gate returns allow.
    h.fabric.submit(_agent_submission())

    # (3)-(4) bridge to one work unit per task, assigned across BOTH validators.
    await h.run_orchestration()
    rows = await h.assignments()
    assert len(rows) == len(AGENT_TASKS)
    assert {r.work_unit_id for r in rows} == {f"sub-agent:{t}" for t in AGENT_TASKS}
    assert all(r.status == WorkAssignmentStatus.ASSIGNED for r in rows)
    assert {r.assigned_validator_hotkey for r in rows} == {VAL_CPU_1, VAL_CPU_2}

    # Before any result is posted, the miner has no weight (no fabricated value).
    pre = await h.weights_latest()
    assert MINER_UIDS[MINER_AGENT] not in pre["uids"]

    # (5) each validator pulls, executes via its OWN broker, posts results.
    summary_a = await agent_a.process_pending_assignments()
    summary_b = await agent_b.process_pending_assignments()
    assert summary_a.completed + summary_b.completed == len(AGENT_TASKS)
    rows = await h.assignments()
    assert all(r.status == WorkAssignmentStatus.COMPLETED for r in rows)

    # broker invoked once per task, all validator-attributed (own broker).
    assert len(h.broker_ledger.executions) == len(AGENT_TASKS)
    assert {e.work_unit_id for e in h.broker_ledger.executions} == {
        f"sub-agent:{t}" for t in AGENT_TASKS
    }
    assert all(
        e.validator_hotkey in {VAL_CPU_1, VAL_CPU_2} for e in h.broker_ledger.executions
    )

    # (6) challenge get_weights derives the miner score from reported results.
    body = await h.weights_latest()
    weights_map = h.fabric.last_get_weights_payload[AGENT_CHALLENGE_SLUG]["weights"]
    assert weights_map[MINER_AGENT] > 0

    # (7) aggregated UID vector has a non-zero weight for the miner's UID.
    uid = MINER_UIDS[MINER_AGENT]
    assert uid in body["uids"]
    assert body["weights"][body["uids"].index(uid)] > 0

    # (8) submitter dry-run validates and would submit exactly that vector.
    submitted, calls = await h.submitter_dry_run()
    assert submitted is True
    assert calls == [(body["uids"], body["weights"])]

    # No provider key leaked into reported results.
    _no_secret_leak(await h.work_results())
    for result in await h.work_results():
        assert result.payload.get("held_provider_key") is False
        assert DEEPSEEK_KEY not in str(result.payload)


async def test_prism_full_lifecycle_to_dry_run_submit(
    harness_factory: Callable[..., Any],
) -> None:
    """VAL-CROSS-002."""
    h: Harness = await harness_factory(active=[("prism", "100")])

    agent_g1 = h.agent(hotkey=VAL_GPU_1, capabilities=["gpu"])
    agent_g2 = h.agent(hotkey=VAL_GPU_2, capabilities=["gpu"])
    await agent_g1.register()
    await agent_g2.register()

    h.fabric.submit(_prism_submission())

    # (3) exactly ONE gpu work unit, assigned to exactly ONE validator.
    await h.run_orchestration()
    rows = await h.assignments()
    assert len(rows) == 1
    assert rows[0].required_capability == "gpu"
    assert rows[0].assigned_validator_hotkey in {VAL_GPU_1, VAL_GPU_2}

    # (4) the assigned validator runs the mock GPU path, reports loss + state.
    summary_g1 = await agent_g1.process_pending_assignments()
    summary_g2 = await agent_g2.process_pending_assignments()
    assert summary_g1.completed + summary_g2.completed == 1
    # exactly one validator executed the prism unit.
    assert len(h.broker_ledger.executions) == 1
    assert h.hf.published, "validator pushed at least one mock HF checkpoint"

    results = await h.work_results()
    assert len(results) == 1
    reported = results[0].payload
    # validator reports the online-loss stream + trained_state, NOT a final score.
    assert "loss_stream" in reported and "trained_state" in reported
    assert "score" not in reported

    # (5) the master alone computes the held-out score (val/test never leave it).
    for row in await h.assignments():
        assert HELDOUT_SECRET not in str(row.payload or {})
    _no_secret_leak(results)

    # (6)-(7) prism get_weights + aggregated vector carry the finalized score.
    body = await h.weights_latest()
    prism_weights = h.fabric.last_get_weights_payload[PRISM_SLUG]["weights"]
    assert prism_weights[MINER_PRISM] > 0
    uid = MINER_UIDS[MINER_PRISM]
    assert uid in body["uids"]
    assert body["weights"][body["uids"].index(uid)] > 0

    # (8) submitter dry-run would submit that vector.
    submitted, calls = await h.submitter_dry_run()
    assert submitted is True
    assert calls == [(body["uids"], body["weights"])]


async def test_gateway_is_sole_llm_path(
    harness_factory: Callable[..., Any],
) -> None:
    """VAL-CROSS-003."""
    h: Harness = await harness_factory(active=[("agent-challenge", "100")])
    agent = h.agent(hotkey=VAL_CPU_1, capabilities=["cpu"])
    await agent.register()
    h.fabric.submit(_agent_submission())
    await h.run_orchestration()
    await agent.process_pending_assignments()

    # Every reported result routed its LLM call through the gateway (200), and
    # the validator runtime never held a provider key.
    results = await h.work_results()
    assert results
    for result in results:
        assert result.payload["gateway_status"] == 200
        assert result.payload["held_provider_key"] is False
        assert str(result.payload["deepseek_base_url"]).endswith("/llm/deepseek")

    # The gateway injected the real provider key server-side (validator never saw it).
    deepseek = h.gateway_service.provider("deepseek")
    assert deepseek.requests, "the mock provider recorded gateway-forwarded calls"
    assert deepseek.requests[-1].header("authorization") == f"Bearer {DEEPSEEK_KEY}"

    # The assignment payload carries a token handle, not a provider key.
    for row in await h.assignments():
        assert GATEWAY_TOKEN_KEY in (row.payload or {})
        assert DEEPSEEK_KEY not in str(row.payload)
        assert OPENROUTER_KEY not in str(row.payload)

    # An unauthorized gateway request (no / bogus token) is rejected.
    async with AsyncClient(
        transport=h.transport, base_url="http://testserver"
    ) as client:
        missing = await client.post(
            "/llm/deepseek/chat/completions",
            json={"model": "deepseek-v4-pro", "messages": []},
        )
        bogus = await client.post(
            "/llm/deepseek/chat/completions",
            json={"model": "deepseek-v4-pro", "messages": []},
            headers={"X-Gateway-Token": "not-a-real-token"},
        )
    assert missing.status_code in (401, 403)
    assert bogus.status_code in (401, 403)
    assert DEEPSEEK_KEY not in missing.text
    assert DEEPSEEK_KEY not in bogus.text


# --------------------------------------------------------------------------- #
# B. Crash / failure paths
# --------------------------------------------------------------------------- #
async def test_agent_challenge_crash_reassign_no_double_count(
    harness_factory: Callable[..., Any],
) -> None:
    """VAL-CROSS-004."""
    h: Harness = await harness_factory(active=[("agent-challenge", "100")])
    agent_a = h.agent(hotkey=VAL_CPU_1, capabilities=["cpu"])
    agent_b = h.agent(hotkey=VAL_CPU_2, capabilities=["cpu"])
    await agent_a.register()
    await agent_b.register()
    h.fabric.submit(_agent_submission())
    await h.run_orchestration()

    # validator A pulls (its units -> running) then crashes before posting.
    client_a = h.coordination_client(VAL_CPU_1)
    pulled_a = await client_a.pull()
    a_assignment_ids = [view.id for view in pulled_a]
    assert a_assignment_ids
    rows = await h.assignments()
    a_units = {r.work_unit_id for r in rows if r.assigned_validator_hotkey == VAL_CPU_1}
    assert a_units

    # Time passes beyond the heartbeat timeout; only B keeps heartbeating.
    h.clock.advance(HEARTBEAT_TIMEOUT + 50)
    await agent_b.heartbeat_once()

    # The detector marks A offline (crash_detected) and reverts + reassigns to B.
    result = await h.run_orchestration()
    assert VAL_CPU_1 in result.reassignment.offline
    a_validator = await h.validator(VAL_CPU_1)
    assert a_validator is not None and a_validator.status == ValidatorStatus.OFFLINE

    rows = await h.assignments()
    assert all(r.assigned_validator_hotkey == VAL_CPU_2 for r in rows)
    # A's reverted units were reassigned, incrementing their attempt_count.
    reassigned = [r for r in rows if r.work_unit_id in a_units]
    assert all(r.attempt_count == 2 for r in reassigned)

    # B executes everything; all tasks complete.
    await agent_b.process_pending_assignments()
    rows = await h.assignments()
    assert all(r.status == WorkAssignmentStatus.COMPLETED for r in rows)

    # Each task counted exactly once - one result row per work unit.
    results = await h.work_results()
    assert sorted(r.work_unit_id for r in results) == sorted(
        f"sub-agent:{t}" for t in AGENT_TASKS
    )
    before = await h.weights_latest()

    # A's late post for a reassigned (now B-owned) unit is rejected, no change.
    with pytest.raises(CoordinationClientError) as excinfo:
        await client_a.post_result(
            a_assignment_ids[0], success=True, payload={"score": 1.0, "task_id": "t1"}
        )
    assert excinfo.value.status_code == 403
    after = await h.weights_latest()
    assert before["uids"] == after["uids"]
    assert before["weights"] == after["weights"]
    assert len(await h.work_results()) == len(AGENT_TASKS)


async def test_prism_crash_resume_from_hf_checkpoint(
    harness_factory: Callable[..., Any],
) -> None:
    """VAL-CROSS-005."""
    h: Harness = await harness_factory(active=[("prism", "100")])
    agent_g1 = h.agent(hotkey=VAL_GPU_1, capabilities=["gpu"])
    agent_g2 = h.agent(hotkey=VAL_GPU_2, capabilities=["gpu"])
    await agent_g1.register()
    await agent_g2.register()
    h.fabric.submit(_prism_submission())
    await h.run_orchestration()

    rows = await h.assignments()
    assert len(rows) == 1
    # Force the first owner to G1 for a deterministic resume onto G2.
    if rows[0].assigned_validator_hotkey != VAL_GPU_1:
        async with session_scope(h.session_factory) as session:
            row = (await session.execute(select(WorkAssignment))).scalar_one()
            row.assigned_validator_hotkey = VAL_GPU_1
        await h.stamp_gateway_tokens()

    # G1 pulls (-> running), pushes one mock HF checkpoint, then crashes.
    client_g1 = h.coordination_client(VAL_GPU_1)
    pulled = await client_g1.pull()
    assignment_id = pulled[0].id
    submission = pulled[0].work_unit_id
    checkpoint_ref = f"hf://prism/{submission}/step-1"
    h.hf.publish(checkpoint_ref, state="partial")
    await client_g1.progress(assignment_id, checkpoint_ref=checkpoint_ref)

    # Heartbeat timeout: G1 crashes, G2 stays online.
    h.clock.advance(HEARTBEAT_TIMEOUT + 50)
    await agent_g2.heartbeat_once()
    result = await h.run_orchestration()
    assert VAL_GPU_1 in result.reassignment.offline

    rows = await h.assignments()
    assert len(rows) == 1
    # checkpoint_ref preserved on revert; reassigned to G2 with a resume ref.
    assert rows[0].checkpoint_ref == checkpoint_ref
    assert rows[0].assigned_validator_hotkey == VAL_GPU_2
    assert rows[0].payload.get(RESUME_CHECKPOINT_PAYLOAD_KEY) == checkpoint_ref

    # G2 resumes from the last public HF checkpoint (not a cold start).
    h.hf.downloaded.clear()
    await agent_g2.process_pending_assignments()
    assert checkpoint_ref in h.hf.downloaded

    rows = await h.assignments()
    assert rows[0].status == WorkAssignmentStatus.COMPLETED
    results = await h.work_results()
    assert results[0].payload["resumed"] is True

    body = await h.weights_latest()
    uid = MINER_UIDS[MINER_PRISM]
    assert uid in body["uids"]
    assert body["weights"][body["uids"].index(uid)] > 0


async def test_result_idempotency_across_reassignment(
    harness_factory: Callable[..., Any],
) -> None:
    """VAL-CROSS-006."""
    h: Harness = await harness_factory(active=[("agent-challenge", "100")])
    agent_a = h.agent(hotkey=VAL_CPU_1, capabilities=["cpu"])
    await agent_a.register()
    # Single validator so all tasks land on A and complete.
    h.fabric.submit(_agent_submission())
    await h.run_orchestration()
    await agent_a.process_pending_assignments()

    rows = await h.assignments()
    assert all(r.status == WorkAssignmentStatus.COMPLETED for r in rows)
    completed_id = str(rows[0].id)
    before_results = len(await h.work_results())
    before_weights = await h.weights_latest()

    # Re-post the result for an already-completed assignment: idempotent no-op.
    client_a = h.coordination_client(VAL_CPU_1)
    response = await client_a.post_result(
        completed_id, success=True, payload={"score": 0.0, "task_id": "t1"}
    )
    assert response.idempotent is True

    # Re-pull after completion returns no re-execution (completed not pullable).
    repulled = await client_a.pull()
    completed_ids = {str(r.id) for r in rows}
    assert not (completed_ids & {view.id for view in repulled})

    after_results = len(await h.work_results())
    after_weights = await h.weights_latest()
    assert after_results == before_results
    assert before_weights["uids"] == after_weights["uids"]
    assert before_weights["weights"] == after_weights["weights"]


# --------------------------------------------------------------------------- #
# C. Eligibility & decentralization invariants
# --------------------------------------------------------------------------- #
async def test_ineligible_hotkey_never_influences_weights(
    harness_factory: Callable[..., Any],
) -> None:
    """VAL-CROSS-007."""
    h: Harness = await harness_factory(active=[("agent-challenge", "100")])

    # The ineligible hotkey signs correctly but is not a permitted validator.
    intruder = h.coordination_client(INTRUDER)
    with pytest.raises(CoordinationClientError) as register_exc:
        await intruder.register(capabilities=["cpu"], version="1.0.0")
    assert register_exc.value.status_code == 403
    with pytest.raises(CoordinationClientError) as heartbeat_exc:
        await intruder.heartbeat()
    assert heartbeat_exc.value.status_code == 403
    with pytest.raises(CoordinationClientError) as pull_exc:
        await intruder.pull()
    assert pull_exc.value.status_code == 403

    # A forged signature is rejected at auth (401), before eligibility.
    forged = h.coordination_client(VAL_CPU_1, signer=ForgedSigner(VAL_CPU_1))
    with pytest.raises(CoordinationClientError) as forged_exc:
        await forged.register(capabilities=["cpu"], version="1.0.0")
    assert forged_exc.value.status_code == 401

    # The ineligible hotkey never got a validators row.
    assert await h.validator(INTRUDER) is None

    # Run the full lifecycle with only eligible validators; weights are correct.
    agent = h.agent(hotkey=VAL_CPU_1, capabilities=["cpu"])
    await agent.register()
    h.fabric.submit(_agent_submission())
    await h.run_orchestration()
    await agent.process_pending_assignments()

    # No assignment ever referenced the intruder; no result carries its hotkey.
    rows = await h.assignments()
    assert all(r.assigned_validator_hotkey != INTRUDER for r in rows)
    assert all(r.validator_hotkey != INTRUDER for r in await h.work_results())

    body = await h.weights_latest()
    assert INTRUDER not in body["hotkey_weights"]
    # The control run vector is exactly the eligible-only outcome.
    assert body["uids"] == [MINER_UIDS[MINER_AGENT]]
    assert body["weights"] == [1.0]


async def test_decentralization_execution_never_on_master(
    harness_factory: Callable[..., Any],
) -> None:
    """VAL-CROSS-008."""
    # With ZERO online validators, the master performs no execution at all.
    h: Harness = await harness_factory(active=[("agent-challenge", "100")])
    h.fabric.submit(_agent_submission())
    await h.run_orchestration()
    rows = await h.assignments()
    assert rows and all(r.status == WorkAssignmentStatus.PENDING for r in rows)
    assert h.broker_ledger.executions == []
    body = await h.weights_latest()
    # No miner weight is produced without any validator executing.
    assert MINER_UIDS[MINER_AGENT] not in body["uids"]

    # A second coordinator pass still triggers zero master-side executions.
    await h.run_orchestration()
    assert h.broker_ledger.executions == []

    # When validators come online, execution happens ONLY in validator contexts.
    agent = h.agent(hotkey=VAL_CPU_1, capabilities=["cpu"])
    await agent.register()
    await h.run_orchestration()
    await agent.process_pending_assignments()
    assert h.broker_ledger.executions
    assert all(
        e.validator_hotkey in PERMITTED_VALIDATORS for e in h.broker_ledger.executions
    )
    assert all(
        e.broker_url.startswith("http://broker-") for e in h.broker_ledger.executions
    )


async def test_no_direct_weights_burn_fallback(
    harness_factory: Callable[..., Any],
) -> None:
    """VAL-CROSS-009."""
    h: Harness = await harness_factory(active=[("agent-challenge", "100")])
    agent_a = h.agent(hotkey=VAL_CPU_1, capabilities=["cpu"])
    agent_b = h.agent(hotkey=VAL_CPU_2, capabilities=["cpu"])
    await agent_a.register()
    await agent_b.register()
    h.fabric.submit(_agent_submission())
    await h.run_orchestration()

    # Validators are present and assigned but NO results reported yet.
    pre = await h.weights_latest()
    assert pre["uids"] == [0]
    assert pre["weights"] == [1.0]
    assert pre["hotkey_weights"] == {}
    assert h.fabric.last_get_weights_payload[AGENT_CHALLENGE_SLUG]["weights"] == {}

    # After results are posted, the same miner gains weight.
    await agent_a.process_pending_assignments()
    await agent_b.process_pending_assignments()
    post = await h.weights_latest()
    assert post["uids"] == [MINER_UIDS[MINER_AGENT]]
    assert post["weights"] == [1.0]


# --------------------------------------------------------------------------- #
# D. Multi-challenge combination
# --------------------------------------------------------------------------- #
async def test_multichallenge_emission_combination(
    harness_factory: Callable[..., Any],
) -> None:
    """VAL-CROSS-010."""
    h: Harness = await harness_factory(
        active=[("agent-challenge", "30"), ("prism", "10")]
    )
    await _run_both_challenges(h)

    body = await h.weights_latest()
    # Both challenges contributed a real validator-reported per-hotkey score.
    assert h.fabric.last_get_weights_payload[AGENT_CHALLENGE_SLUG]["weights"]
    assert h.fabric.last_get_weights_payload[PRISM_SLUG]["weights"]

    assert sorted(body["uids"]) == sorted(MINER_UIDS.values())
    weight_by_uid = dict(zip(body["uids"], body["weights"], strict=True))
    # Each challenge has a single miner, so per-challenge normalization gives 1.0;
    # the blended UID vector follows the emission split 30:10 == 0.75:0.25.
    assert round(weight_by_uid[MINER_UIDS[MINER_AGENT]], 6) == 0.75
    assert round(weight_by_uid[MINER_UIDS[MINER_PRISM]], 6) == 0.25
    assert round(sum(body["weights"]), 6) == 1.0

    # Perturbing the emission split shifts the blend predictably (25:25 -> 50:50).
    h2: Harness = await harness_factory(
        active=[("agent-challenge", "25"), ("prism", "25")]
    )
    await _run_both_challenges(h2)
    body2 = await h2.weights_latest()
    weight_by_uid2 = dict(zip(body2["uids"], body2["weights"], strict=True))
    assert round(weight_by_uid2[MINER_UIDS[MINER_AGENT]], 6) == 0.5
    assert round(weight_by_uid2[MINER_UIDS[MINER_PRISM]], 6) == 0.5


async def test_capability_routing_across_challenges(
    harness_factory: Callable[..., Any],
) -> None:
    """VAL-CROSS-011."""
    h: Harness = await harness_factory(
        active=[("agent-challenge", "50"), ("prism", "50")]
    )
    await _run_both_challenges(h)

    caps = {VAL_CPU_1: {"cpu"}, VAL_GPU_1: {"gpu"}}
    rows = await h.assignments()
    for row in rows:
        owner = row.assigned_validator_hotkey
        assert owner is not None
        owner_caps = caps[owner]
        if row.required_capability == "gpu":
            assert "gpu" in owner_caps
        else:
            # cpu work is cpu-eligible (gpu may also serve cpu when configured).
            assert "cpu" in owner_caps or "gpu" in owner_caps
    # The prism (gpu) unit landed only on the gpu validator.
    prism_rows = [r for r in rows if r.challenge_slug == PRISM_SLUG]
    assert len(prism_rows) == 1
    assert prism_rows[0].assigned_validator_hotkey == VAL_GPU_1

    body = await h.weights_latest()
    assert sorted(body["uids"]) == sorted(MINER_UIDS.values())


# --------------------------------------------------------------------------- #
# E. End-state / contract-shape guards
# --------------------------------------------------------------------------- #
async def test_preserved_get_weights_contract_shape(
    harness_factory: Callable[..., Any],
) -> None:
    """VAL-CROSS-012."""
    h: Harness = await harness_factory(
        active=[("agent-challenge", "50"), ("prism", "50")]
    )
    await _run_both_challenges(h)
    await h.weights_latest()

    for slug in (AGENT_CHALLENGE_SLUG, PRISM_SLUG):
        payload = h.fabric.last_get_weights_payload[slug]
        assert set(payload) == {"challenge_slug", "epoch", "weights"}
        assert payload["challenge_slug"] == slug
        assert payload["epoch"] is None or isinstance(payload["epoch"], int)
        assert isinstance(payload["weights"], dict)
        for hotkey, weight in payload["weights"].items():
            assert isinstance(hotkey, str)
            assert isinstance(weight, float)
        # Re-validation against the preserved contract schema must succeed.
        ChallengeWeightsResponse.model_validate(payload)

    # The reported scores trace to the validator-reported results.
    ac_weights = h.fabric.last_get_weights_payload[AGENT_CHALLENGE_SLUG]["weights"]
    prism_weights = h.fabric.last_get_weights_payload[PRISM_SLUG]["weights"]
    assert ac_weights[MINER_AGENT] > 0
    assert prism_weights[MINER_PRISM] > 0


async def test_weights_are_recompute_on_read(
    harness_factory: Callable[..., Any],
) -> None:
    """VAL-CROSS-013."""
    h: Harness = await harness_factory(active=[("agent-challenge", "100")])
    agent_a = h.agent(hotkey=VAL_CPU_1, capabilities=["cpu"])
    await agent_a.register()

    # First miner completes; read reflects it.
    first = Submission(
        slug=AGENT_CHALLENGE_SLUG,
        submission_id="sub-first",
        hotkey=MINER_AGENT,
        task_ids=("t1", "t2"),
    )
    h.fabric.submit(first)
    await h.run_orchestration()
    await agent_a.process_pending_assignments()
    read_one = await h.weights_latest()
    assert read_one["uids"] == [MINER_UIDS[MINER_AGENT]]

    # A second miner's submission completes; the NEXT read (no explicit recompute
    # trigger) reflects the freshly reported results.
    second = Submission(
        slug=AGENT_CHALLENGE_SLUG,
        submission_id="sub-second",
        hotkey=MINER_PRISM,
        task_ids=("t1", "t2"),
    )
    h.fabric.submit(second)
    await h.run_orchestration()
    await agent_a.process_pending_assignments()
    read_two = await h.weights_latest()

    assert sorted(read_two["uids"]) == sorted(MINER_UIDS.values())
    assert read_two["uids"] != read_one["uids"]
    weight_by_uid = dict(zip(read_two["uids"], read_two["weights"], strict=True))
    assert weight_by_uid[MINER_UIDS[MINER_AGENT]] > 0
    assert weight_by_uid[MINER_UIDS[MINER_PRISM]] > 0
