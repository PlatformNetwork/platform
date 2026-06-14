"""Unit tests for per-challenge broker quota enforcement (Task 14).

``/v1/docker/run`` enforces ``max_concurrent_by_slug`` against the shared
``WorkloadLedger`` via the atomic ``register(entry, max_concurrent=N)`` call
on all three creation paths (Swarm job, privileged escape hatch, legacy
``docker run``). Over-cap requests get HTTP 429 with the stable
``docker_quota_exceeded`` code prefix inside the frozen ``{"detail": str}``
envelope. The docker CLI layer is replaced by argv-capturing fakes, so no
dockerd is required.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

import platform_network.master.docker_broker as broker_module
from platform_network.master.docker_broker import (
    DockerBrokerConfig,
    DockerBrokerService,
    EscapeHatchCommandResult,
    create_docker_broker_app,
)
from platform_network.master.swarm_backend import (
    SwarmBrokerConfig,
    SwarmBrokerService,
    SwarmCommandResult,
)
from platform_network.master.workload_ledger import (
    WorkloadCapacityError,
    WorkloadEntry,
    WorkloadLedger,
)
from platform_network.schemas.docker_broker import BrokerRunRequest

QUOTA_PREFIX = "docker_quota_exceeded: "
FULL_CONTAINER_ID = "c0ffee" + "0" * 58

AUTH_HEADERS = {
    "authorization": "Bearer tok",
    "x-platform-challenge-slug": "agent",
}


class Registry:
    def get_broker_token(self, slug: str) -> str:
        return "tok" if slug == "agent" else ""


class FakeSwarmRunner:
    """Minimal scripted docker CLI fake for successful Swarm job runs."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._counter = 0

    def run(
        self,
        argv: Any,
        *,
        input_text: str | None = None,
        timeout_seconds: float | None = None,
    ) -> SwarmCommandResult:
        argv = tuple(argv)
        self.calls.append(argv)
        return self._respond(argv)

    def _respond(self, argv: tuple[str, ...]) -> SwarmCommandResult:
        head = argv[1:3]
        if head == ("network", "inspect"):
            return _swarm_result(argv, out="netid\n")
        if head == ("service", "create"):
            self._counter += 1
            return _swarm_result(argv, out=f"svcid{self._counter:020d}\n")
        if head == ("service", "ps"):
            return _swarm_result(argv, out="task-abc\n")
        if head == ("service", "logs"):
            return _swarm_result(argv, out="ok\n")
        if argv[1] == "inspect":
            status = {
                "Timestamp": "2026-06-12T10:00:00.123456789Z",
                "State": "complete",
                "ContainerStatus": {"ExitCode": 0},
            }
            return _swarm_result(argv, out=json.dumps(status) + "\n")
        return _swarm_result(argv)

    def create_calls(self) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[1:3] == ("service", "create")]


class BlockingSwarmRunner(FakeSwarmRunner):
    """Holds ``service create`` open until released, to pin a quota slot."""

    def __init__(self) -> None:
        super().__init__()
        self.in_create = threading.Event()
        self.proceed = threading.Event()

    def _respond(self, argv: tuple[str, ...]) -> SwarmCommandResult:
        if argv[1:3] == ("service", "create"):
            self.in_create.set()
            assert self.proceed.wait(timeout=30), "blocked create never released"
        return super()._respond(argv)


class FakeEscapeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Any,
        *,
        timeout_seconds: float | None = None,
    ) -> EscapeHatchCommandResult:
        argv = tuple(argv)
        self.calls.append(argv)
        out = ""
        if argv[1] == "run":
            out = f"{FULL_CONTAINER_ID}\n"
        elif argv[1] == "wait":
            out = "0\n"
        return EscapeHatchCommandResult(argv=argv, returncode=0, stdout=out, stderr="")


def _swarm_result(
    argv: tuple[str, ...], rc: int = 0, out: str = "", err: str = ""
) -> SwarmCommandResult:
    return SwarmCommandResult(argv=argv, returncode=rc, stdout=out, stderr=err)


def _run_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "job_id": "job-1",
        "image": "ghcr.io/platformnetwork/challenge:1.2.3",
        "command": ["python", "-V"],
        "timeout_seconds": 900,
    }
    payload.update(overrides)
    return payload


def _swarm_broker(
    tmp_path: Path, runner: FakeSwarmRunner, **config_overrides: Any
) -> SwarmBrokerService:
    config = SwarmBrokerConfig(
        workspace_dir=tmp_path / "work",
        allowed_images=("ghcr.io/platformnetwork/",),
        **config_overrides,
    )
    return SwarmBrokerService(config, runner=runner, ledger=WorkloadLedger())


def _fill_ledger(ledger: WorkloadLedger, slug: str, count: int) -> None:
    for index in range(count):
        ledger.register(
            WorkloadEntry(
                key=f"held-{slug}-{index}",
                kind="swarm_service",
                challenge_slug=slug,
                timeout_seconds=900,
            )
        )


def test_swarm_run_over_cap_refused_with_429_and_code(tmp_path: Path) -> None:
    runner = FakeSwarmRunner()
    service = _swarm_broker(tmp_path, runner, max_concurrent_by_slug={"agent": 2})
    _fill_ledger(service.ledger, "agent", 2)
    client = TestClient(create_docker_broker_app(registry=Registry(), service=service))

    response = client.post("/v1/docker/run", headers=AUTH_HEADERS, json=_run_payload())

    assert response.status_code == 429
    body = response.json()
    assert set(body) == {"detail"}
    assert isinstance(body["detail"], str)
    assert body["detail"].startswith(QUOTA_PREFIX)
    assert "2/2" in body["detail"]
    assert runner.create_calls() == []
    assert service.ledger.count("agent") == 2


def test_swarm_release_frees_slot_and_next_accepted(tmp_path: Path) -> None:
    runner = FakeSwarmRunner()
    service = _swarm_broker(tmp_path, runner, max_concurrent_by_slug={"agent": 1})
    service.ledger.register(
        WorkloadEntry(key="svc-old", kind="swarm_service", challenge_slug="agent")
    )
    client = TestClient(create_docker_broker_app(registry=Registry(), service=service))

    refused = client.post("/v1/docker/run", headers=AUTH_HEADERS, json=_run_payload())
    assert refused.status_code == 429
    assert refused.json()["detail"].startswith(QUOTA_PREFIX)

    assert service.ledger.release("svc-old") is True
    accepted = client.post("/v1/docker/run", headers=AUTH_HEADERS, json=_run_payload())

    assert accepted.status_code == 200
    assert accepted.json()["returncode"] == 0
    assert len(runner.create_calls()) == 1
    assert service.ledger.count("agent") == 0


def test_swarm_quota_only_counts_owning_challenge(tmp_path: Path) -> None:
    runner = FakeSwarmRunner()
    service = _swarm_broker(tmp_path, runner, max_concurrent_by_slug={"agent": 1})
    _fill_ledger(service.ledger, "other-challenge", 3)
    client = TestClient(create_docker_broker_app(registry=Registry(), service=service))

    response = client.post("/v1/docker/run", headers=AUTH_HEADERS, json=_run_payload())

    assert response.status_code == 200


def test_unlimited_default_unchanged(tmp_path: Path) -> None:
    runner = FakeSwarmRunner()
    service = _swarm_broker(tmp_path, runner)
    _fill_ledger(service.ledger, "agent", 50)
    client = TestClient(create_docker_broker_app(registry=Registry(), service=service))

    response = client.post("/v1/docker/run", headers=AUTH_HEADERS, json=_run_payload())

    assert response.status_code == 200
    assert response.json()["returncode"] == 0


def test_swarm_gpu_lease_released_on_capacity_refusal(tmp_path: Path) -> None:
    runner = FakeSwarmRunner()
    service = _swarm_broker(tmp_path, runner, max_concurrent_by_slug={"agent": 1})
    _fill_ledger(service.ledger, "agent", 1)

    request = BrokerRunRequest.model_validate(_run_payload(limits={"gpu_count": 1}))
    with pytest.raises(WorkloadCapacityError):
        service.run("agent", request)

    assert service.gpu_leases.in_use == 0
    assert runner.create_calls() == []

    service.ledger.release("held-agent-0")
    response = service.run("agent", request)
    assert response.returncode == 0
    assert service.gpu_leases.in_use == 0


def test_escape_hatch_over_cap_removes_container_and_releases(
    tmp_path: Path,
) -> None:
    escape_runner = FakeEscapeRunner()
    config = SwarmBrokerConfig(
        workspace_dir=tmp_path / "work",
        allowed_images=("ghcr.io/platformnetwork/",),
        privileged_escape_slugs=frozenset({"agent"}),
        node_role="worker",
        max_concurrent_by_slug={"agent": 1},
    )
    service = SwarmBrokerService(
        config, runner=FakeSwarmRunner(), escape_runner=escape_runner
    )
    _fill_ledger(service.ledger, "agent", 1)
    client = TestClient(create_docker_broker_app(registry=Registry(), service=service))

    response = client.post(
        "/v1/docker/run",
        headers=AUTH_HEADERS,
        json=_run_payload(limits={"privileged": True}),
    )

    assert response.status_code == 429
    assert response.json()["detail"].startswith(QUOTA_PREFIX)
    # Create-then-register: the just-created container is removed in the
    # finally and the DinD volume cleaned up; the held slot is untouched.
    assert ("docker", "rm", "-f", FULL_CONTAINER_ID) in escape_runner.calls
    assert any(call[1:3] == ("volume", "rm") for call in escape_runner.calls)
    assert not any(call[1] == "wait" for call in escape_runner.calls)
    assert service.ledger.count("agent") == 1
    assert service.ledger.get(FULL_CONTAINER_ID) is None

    service.ledger.release("held-agent-0")
    accepted = client.post(
        "/v1/docker/run",
        headers=AUTH_HEADERS,
        json=_run_payload(limits={"privileged": True}),
    )
    assert accepted.status_code == 200
    assert service.ledger.count("agent") == 0


class _FakeExecutor:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs

    def container_name(self, job_id: str, task_id: str | None = None) -> str:
        return f"platform-agent-{job_id}-{task_id or 'job'}-a1b2c3d4"

    def run(self, spec: Any, timeout_seconds: int) -> SimpleNamespace:
        return SimpleNamespace(
            container_name=spec.name,
            stdout="ok\n",
            stderr="",
            returncode=0,
            timed_out=False,
        )


def test_legacy_run_enforces_quota_and_releases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(broker_module, "DockerExecutor", _FakeExecutor)
    service = DockerBrokerService(
        DockerBrokerConfig(
            workspace_dir=tmp_path / "work",
            allowed_images=("ghcr.io/platformnetwork/",),
            max_concurrent_by_slug={"agent": 1},
        )
    )
    _fill_ledger(service.ledger, "agent", 1)
    client = TestClient(create_docker_broker_app(registry=Registry(), service=service))

    refused = client.post("/v1/docker/run", headers=AUTH_HEADERS, json=_run_payload())
    assert refused.status_code == 429
    assert refused.json() == {"detail": refused.json()["detail"]}
    assert refused.json()["detail"].startswith(QUOTA_PREFIX)

    service.ledger.release("held-agent-0")
    accepted = client.post("/v1/docker/run", headers=AUTH_HEADERS, json=_run_payload())
    assert accepted.status_code == 200
    assert service.ledger.count("agent") == 0


def test_legacy_run_default_unlimited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(broker_module, "DockerExecutor", _FakeExecutor)
    service = DockerBrokerService(
        DockerBrokerConfig(
            workspace_dir=tmp_path / "work",
            allowed_images=("ghcr.io/platformnetwork/",),
        )
    )
    _fill_ledger(service.ledger, "agent", 50)
    client = TestClient(create_docker_broker_app(registry=Registry(), service=service))

    response = client.post("/v1/docker/run", headers=AUTH_HEADERS, json=_run_payload())

    assert response.status_code == 200


def test_two_threads_racing_at_cap_one_exactly_one_wins(tmp_path: Path) -> None:
    runner = BlockingSwarmRunner()
    service = _swarm_broker(tmp_path, runner, max_concurrent_by_slug={"agent": 1})
    request = BrokerRunRequest.model_validate(_run_payload())
    outcomes: list[str] = []
    lock = threading.Lock()

    def attempt() -> None:
        try:
            result = service.run("agent", request)
        except WorkloadCapacityError:
            with lock:
                outcomes.append("refused")
        else:
            with lock:
                outcomes.append(f"accepted:{result.returncode}")

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    # The winner holds its quota slot while blocked inside ``service
    # create``; the loser must observe the cap and fail fast.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with lock:
            if "refused" in outcomes:
                break
        time.sleep(0.01)
    runner.proceed.set()
    for thread in threads:
        thread.join(timeout=30)

    assert sorted(outcomes) == ["accepted:0", "refused"]
    assert len(runner.create_calls()) == 1
    assert service.ledger.count("agent") == 0
