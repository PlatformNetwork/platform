"""End-to-end validator execution wiring (architecture sec 4, G2).

A pulled assignment must dispatch a REAL run on the validator's own broker for
each challenge through the PRODUCTION path: the ``ValidatorAgent`` runtime drives
pull -> execute -> post, the :class:`ChallengeDispatchExecutor` routes by
``challenge_slug``, and the real per-challenge adapters
(:class:`AgentChallengeCycleExecutor` / :class:`PrismCycleExecutor`) map the
assignment onto the sibling challenge cycle. Only the sibling
``dispatch_assignment`` (standing in for the challenge cycle) and the broker are
faked here:

- a pulled agent-challenge assignment dispatches a real (faked) broker run with
  the Terminal-Bench 2.1 runner image + ``own_runner`` command;
- a pulled prism assignment dispatches a real (faked) broker run that is
  ``network=none`` mounting only train (ro) + writable artifacts, gpu;
- the per-assignment scoped gateway token + gateway base URLs are injected into
  the eval env (never ``gateway=None``); no provider key is present;
- result posting is idempotent / re-run safe (a completed unit is not
  re-dispatched).

The concrete per-challenge container shapes are additionally proven in the
sibling challenge repos' ``validator_dispatch`` tests.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from base.challenge_sdk.executors.docker import (
    DockerLimits,
    DockerMount,
    DockerRunResult,
    DockerRunSpec,
)
from base.schemas.assignment import AssignmentView
from base.validator.agent import (
    BrokerConfig,
    ChallengeDispatchExecutor,
    ValidatorAgent,
)
from base.validator.agent.adapters import (
    AgentChallengeCycleExecutor,
    PrismCycleExecutor,
)

TBENCH_RUNNER_IMAGE = (
    "ghcr.io/baseintelligence/agent-challenge-terminal-bench-runner:latest"
)
PRISM_EVALUATOR_IMAGE = "ghcr.io/baseintelligence/prism-evaluator:latest"
GATEWAY_URL = "http://master:8081"
OWN_RUNNER = "agent_challenge.evaluation.own_runner_backend"


class FakeDockerExecutor:
    """Stands in for the validator's OWN broker-backed DockerExecutor."""

    captured: list[tuple[str, DockerRunSpec]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.challenge = kwargs.get("challenge", "")

    def run(self, spec: DockerRunSpec, timeout_seconds: int) -> DockerRunResult:
        FakeDockerExecutor.captured.append((self.challenge, spec))
        return DockerRunResult(
            container_name="broker-fake", stdout="ok", stderr="", returncode=0
        )


class FakeCoordinationClient:
    """In-memory master coordination client (pull/post/progress)."""

    def __init__(self, hotkey: str, assignments: list[AssignmentView]) -> None:
        self._hotkey = hotkey
        self._pending: dict[str, AssignmentView] = {a.id: a for a in assignments}
        self.posted: list[dict[str, Any]] = []
        self.progress_calls: list[str] = []

    @property
    def hotkey(self) -> str:
        return self._hotkey

    async def register(self, **_: Any) -> Any:
        return SimpleNamespace(heartbeat_interval_seconds=60)

    async def heartbeat(self, **_: Any) -> None:
        return None

    async def pull(self) -> list[AssignmentView]:
        return list(self._pending.values())

    async def progress(self, assignment_id: str, **_: Any) -> None:
        self.progress_calls.append(assignment_id)

    async def post_result(
        self,
        assignment_id: str,
        *,
        success: bool,
        payload: dict[str, Any],
        checkpoint_ref: str | None = None,
    ) -> Any:
        already_done = assignment_id not in self._pending
        # The master marks the unit terminal on a successful post, so it is no
        # longer pullable (re-run safe: no second dispatch).
        self._pending.pop(assignment_id, None)
        self.posted.append(
            {
                "assignment_id": assignment_id,
                "success": success,
                "payload": payload,
                "idempotent": already_done,
            }
        )
        return SimpleNamespace(idempotent=already_done, status="ok")


def _gateway_env_from_payload(payload: dict[str, Any]) -> dict[str, str]:
    """Mirror the sibling cycle: build gateway env from the scoped payload token.

    Raises if the scoped token is absent (the cycle never runs gateway=None).
    """

    token = payload["gateway_token"]
    base = str(payload["gateway_url"]).rstrip("/")
    return {
        "DEEPSEEK_BASE_URL": f"{base}/llm/deepseek",
        "OPENROUTER_BASE_URL": f"{base}/llm/openrouter",
        "BASE_GATEWAY_TOKEN": token,
    }


def _fake_agent_challenge_dispatch(**kwargs: Any) -> Any:
    """Fake of ``agent_challenge.validator_dispatch.dispatch_assignment``.

    Builds the tbench ``own_runner`` spec + gateway env from the scoped token and
    dispatches it on the validator's broker-backed DockerExecutor.
    """

    async def _run() -> dict[str, Any]:
        payload = kwargs["payload"]
        env = _gateway_env_from_payload(payload)
        executor = FakeDockerExecutor(
            challenge="agent-challenge",
            backend="broker",
            broker_url=kwargs["broker_url"],
            broker_token=kwargs.get("broker_token"),
            broker_token_file=kwargs.get("broker_token_file"),
            allowed_images=kwargs.get("broker_allowed_images", ()),
        )
        spec = DockerRunSpec(
            image=TBENCH_RUNNER_IMAGE,
            command=(
                "bash",
                "-lc",
                f"python -m {OWN_RUNNER} run --task {payload['task_id']}",
            ),
            env=env,
            limits=DockerLimits(network="default", read_only=False),
            labels={
                "base.job": kwargs["work_unit_id"],
                "base.task": payload["task_id"],
            },
        )
        result = executor.run(spec, 600)
        return {"pulled": 1, "executed": 1, "posted": int(result.returncode == 0)}

    return _run()


def _make_prism_dispatch(train_dir: Path, artifacts_dir: Path) -> Any:
    def _fake_prism_dispatch(**kwargs: Any) -> Any:
        async def _run() -> dict[str, Any]:
            payload = kwargs["payload"]
            env = _gateway_env_from_payload(payload)
            executor = FakeDockerExecutor(
                challenge="prism",
                backend="broker",
                broker_url=kwargs["broker_url"],
                broker_token=kwargs.get("broker_token"),
                broker_token_file=kwargs.get("broker_token_file"),
            )
            spec = DockerRunSpec(
                image=PRISM_EVALUATOR_IMAGE,
                command=("torchrun", "--nproc-per-node=1", "-m", "prism_eval"),
                mounts=(
                    DockerMount(source=train_dir, target="/data/train", read_only=True),
                    DockerMount(
                        source=artifacts_dir, target="/artifacts", read_only=False
                    ),
                ),
                env=env,
                limits=DockerLimits(network="none", gpu_count=1),
                labels={"base.job": kwargs["work_unit_id"]},
            )
            result = executor.run(spec, 600)
            return {"pulled": 1, "executed": 1, "skipped": int(result.returncode != 0)}

        return _run()

    return _fake_prism_dispatch


def _assignment(
    *, assignment_id: str, slug: str, work_unit_id: str, capability: str
) -> AssignmentView:
    # Mirrors what the master pull route stamps: the scoped gateway token + base
    # URLs (so the cycle builds gateway env, never gateway=None).
    return AssignmentView(
        id=assignment_id,
        challenge_slug=slug,
        work_unit_id=work_unit_id,
        submission_ref="miner-hotkey",
        payload={
            "task_id": "terminal-bench/task-0",
            "gateway_token": "scoped-token",
            "gateway_url": GATEWAY_URL,
        },
        required_capability=capability,
        status="assigned",
        attempt_count=1,
        max_attempts=3,
    )


def _agent(
    client: FakeCoordinationClient, dispatcher: ChallengeDispatchExecutor
) -> ValidatorAgent:
    return ValidatorAgent(
        client=client,  # type: ignore[arg-type]
        executor=dispatcher,
        broker=BrokerConfig(broker_url="http://broker-val:8082", broker_token="t"),
        capabilities=["gpu", "cpu"],
        version="1.0.0",
        gateway_url=GATEWAY_URL,
        heartbeat_interval_seconds=60,
        poll_interval_seconds=0.01,
    )


@pytest.fixture(autouse=True)
def _reset_capture() -> Any:
    FakeDockerExecutor.captured = []
    yield
    FakeDockerExecutor.captured = []


async def test_pulled_assignments_dispatch_real_runs_per_challenge(
    tmp_path: Path,
) -> None:
    train_dir = tmp_path / "train"
    artifacts_dir = tmp_path / "artifacts"
    train_dir.mkdir()
    artifacts_dir.mkdir()

    # The PRODUCTION adapters, with only the sibling cycle (dispatch) faked.
    dispatcher = ChallengeDispatchExecutor(
        executors={
            "agent-challenge": AgentChallengeCycleExecutor(
                dispatch=_fake_agent_challenge_dispatch
            ),
            "prism": PrismCycleExecutor(
                dispatch=_make_prism_dispatch(train_dir, artifacts_dir)
            ),
        }
    )
    client = FakeCoordinationClient(
        "val-gpu",
        [
            _assignment(
                assignment_id="a1",
                slug="agent-challenge",
                work_unit_id="sub:terminal-bench/task-0",
                capability="cpu",
            ),
            _assignment(
                assignment_id="p1",
                slug="prism",
                work_unit_id="psub-1",
                capability="gpu",
            ),
        ],
    )
    agent = _agent(client, dispatcher)

    summary = await agent.process_pending_assignments()

    assert summary.pulled == 2
    assert summary.completed == 2
    assert summary.failed == 0

    # Both challenges dispatched a real (faked) broker run on the validator's broker.
    by_challenge = {challenge: spec for challenge, spec in FakeDockerExecutor.captured}
    assert set(by_challenge) == {"agent-challenge", "prism"}

    ac_spec = by_challenge["agent-challenge"]
    assert ac_spec.image == TBENCH_RUNNER_IMAGE
    assert "own_runner_backend" in ac_spec.command[-1]

    prism_spec = by_challenge["prism"]
    assert prism_spec.image == PRISM_EVALUATOR_IMAGE
    assert prism_spec.limits.network == "none"
    assert prism_spec.limits.gpu_count == 1
    mount_targets = {(m.target, m.read_only) for m in prism_spec.mounts}
    assert mount_targets == {("/data/train", True), ("/artifacts", False)}

    # Gateway env injected for BOTH dispatches (never gateway=None); no provider key.
    for _challenge, spec in FakeDockerExecutor.captured:
        assert spec.env["BASE_GATEWAY_TOKEN"] == "scoped-token"
        assert spec.env["DEEPSEEK_BASE_URL"] == f"{GATEWAY_URL}/llm/deepseek"
        assert spec.env["OPENROUTER_BASE_URL"] == f"{GATEWAY_URL}/llm/openrouter"
        assert not any(key.upper().endswith("_API_KEY") for key in spec.env)

    # Both results were posted to the master.
    assert {p["assignment_id"] for p in client.posted} == {"a1", "p1"}
    assert all(p["success"] for p in client.posted)


async def test_completed_assignment_is_not_redispatched() -> None:
    dispatcher = ChallengeDispatchExecutor(
        executors={
            "agent-challenge": AgentChallengeCycleExecutor(
                dispatch=_fake_agent_challenge_dispatch
            )
        }
    )
    client = FakeCoordinationClient(
        "val-cpu",
        [
            _assignment(
                assignment_id="a1",
                slug="agent-challenge",
                work_unit_id="sub:terminal-bench/task-0",
                capability="cpu",
            )
        ],
    )
    agent = _agent(client, dispatcher)

    first = await agent.process_pending_assignments()
    assert first.completed == 1
    assert len(FakeDockerExecutor.captured) == 1

    # A second pass pulls nothing (completed unit no longer pullable): no re-run,
    # no duplicate broker dispatch, no double post.
    second = await agent.process_pending_assignments()
    assert second.pulled == 0
    assert second.completed == 0
    assert len(FakeDockerExecutor.captured) == 1
    assert len(client.posted) == 1
