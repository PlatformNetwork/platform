"""Unit tests for the Swarm-backed broker/orchestrator (Task 9).

The docker CLI layer is replaced by an argv-capturing fake runner, mirroring
how the broker is tested without dockerd. The golden parity tests replay the
contract-suite payloads against the Swarm service and compare the normalized
bytes against the FROZEN fixtures in ``tests/contract/golden/``.
"""

from __future__ import annotations

import base64
import io
import json
import tarfile
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from platform_network.challenge_sdk.executors.docker import DockerExecutorError
from platform_network.gpu.leases import (
    GpuCapacityError,
    GpuLeaseError,
    GpuLeaseLedger,
)
from platform_network.master.docker_broker import create_docker_broker_app
from platform_network.master.docker_orchestrator import (
    ChallengeResources,
    ChallengeSpec,
    DockerOrchestrationError,
)
from platform_network.master.swarm_backend import (
    SwarmBrokerConfig,
    SwarmBrokerService,
    SwarmChallengeOrchestrator,
    SwarmCommandResult,
    SwarmServicePlan,
    build_overlay_network_argv,
    build_service_create_argv,
)
from platform_network.master.workload_ledger import WorkloadEntry, WorkloadLedger
from platform_network.schemas.docker_broker import (
    BrokerCleanupRequest,
    BrokerListRequest,
    BrokerRunRequest,
)

GOLDEN_DIR = Path(__file__).resolve().parents[1] / "contract" / "golden"

AUTH_HEADERS = {
    "authorization": "Bearer tok",
    "x-platform-challenge-slug": "agent",
}

_VOLATILE_KEYS = {
    "container_id": "<ID>",
    "container_name": "<ID>",
    "created": "<TS>",
    "archive_b64": "<B64>",
}

_TASK_TIMESTAMP = "2026-06-12T10:00:00.123456789Z"


class Registry:
    def get_broker_token(self, slug: str) -> str:
        return "tok" if slug == "agent" else ""


def _result(
    argv: tuple[str, ...], rc: int = 0, out: str = "", err: str = ""
) -> SwarmCommandResult:
    return SwarmCommandResult(argv=argv, returncode=rc, stdout=out, stderr=err)


class FakeSwarmRunner:
    """Scripted docker CLI fake capturing every argv (and stdin payloads)."""

    def __init__(
        self,
        *,
        service_id: str = "svc0123456789abcdefgh1234",
        create_rc: int = 0,
        create_err: str = "boom: create failed",
        task_state: str = "complete",
        exit_code: int = 0,
        log_stdout: str = "",
        log_stderr: str = "",
        ls_rows: list[dict[str, str]] | None = None,
        inspect_details: list[dict[str, Any]] | None = None,
        network_exists: bool = True,
        secret_create_rc: int = 0,
        service_exists: bool = False,
    ) -> None:
        self.service_id = service_id
        self.create_rc = create_rc
        self.create_err = create_err
        self.task_state = task_state
        self.exit_code = exit_code
        self.log_stdout = log_stdout
        self.log_stderr = log_stderr
        self.ls_rows = ls_rows or []
        self.inspect_details = inspect_details or []
        self.network_exists = network_exists
        self.secret_create_rc = secret_create_rc
        self.service_exists = service_exists
        self.calls: list[tuple[str, ...]] = []
        self.inputs: list[str | None] = []
        self.ledger_count_at_create: int | None = None
        self.ledger: WorkloadLedger | None = None

    def run(
        self,
        argv: Any,
        *,
        input_text: str | None = None,
        timeout_seconds: float | None = None,
    ) -> SwarmCommandResult:
        argv = tuple(argv)
        self.calls.append(argv)
        self.inputs.append(input_text)
        head = argv[1:3]
        if head == ("network", "inspect"):
            return _result(argv, rc=0 if self.network_exists else 1)
        if head == ("network", "create"):
            return _result(argv, out="netid\n")
        if head == ("secret", "create"):
            return _result(argv, rc=self.secret_create_rc, err="already exists")
        if head == ("secret", "rm"):
            return _result(argv)
        if head == ("service", "create"):
            if self.ledger is not None:
                self.ledger_count_at_create = self.ledger.count("agent")
            if self.create_rc:
                return _result(argv, rc=self.create_rc, err=self.create_err)
            return _result(argv, out=f"{self.service_id}\n")
        if head == ("service", "ps"):
            return _result(argv, out="task-abc\n")
        if head == ("service", "logs"):
            return _result(argv, out=self.log_stdout, err=self.log_stderr)
        if head == ("service", "rm"):
            return _result(argv)
        if head == ("service", "ls"):
            out = "".join(json.dumps(row) + "\n" for row in self.ls_rows)
            return _result(argv, out=out)
        if head == ("service", "inspect"):
            if "{{.ID}}" in argv:
                if not self.service_exists:
                    return _result(argv, rc=1, err="no such service")
                return _result(argv, out=f"{self.service_id}\n")
            out = "".join(json.dumps(d) + "\n" for d in self.inspect_details)
            return _result(argv, out=out)
        if head == ("service", "update"):
            return _result(argv)
        if argv[1] == "inspect":
            status = {
                "Timestamp": _TASK_TIMESTAMP,
                "State": self.task_state,
                "Err": "task error" if self.task_state == "failed" else "",
                "ContainerStatus": {"ExitCode": self.exit_code},
            }
            return _result(argv, out=json.dumps(status) + "\n")
        if argv[1] == "pull":
            return _result(argv, out="pulled\n")
        return _result(argv)

    def create_argv(self) -> tuple[str, ...]:
        for call in self.calls:
            if call[1:3] == ("service", "create"):
                return call
        raise AssertionError("no service create call captured")


def _pairs(argv: tuple[str, ...]) -> list[tuple[str, str]]:
    return list(zip(argv, argv[1:], strict=False))


def _archive_member(name: str = "input.txt", data: bytes = b"ok") -> str:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return base64.b64encode(stream.getvalue()).decode("ascii")


def _broker(
    tmp_path: Path, runner: FakeSwarmRunner, **config_overrides: Any
) -> SwarmBrokerService:
    config = SwarmBrokerConfig(
        docker_bin="docker",
        workspace_dir=tmp_path / "work",
        allowed_images=("ghcr.io/platformnetwork/",),
        **config_overrides,
    )
    ledger = WorkloadLedger()
    runner.ledger = ledger
    return SwarmBrokerService(config, runner=runner, ledger=ledger)


def _run_request(**overrides: Any) -> BrokerRunRequest:
    payload: dict[str, Any] = {
        "job_id": "job-1",
        "task_id": "task-1",
        "image": "ghcr.io/platformnetwork/challenge:1.2.3",
        "command": ["python", "-V"],
        "workdir": "/workspace",
        "env": {"PLATFORM_ENV": "unit"},
        "labels": {"platform.challenge": "agent"},
        "mounts": [
            {
                "target": "/workspace/forge",
                "read_only": True,
                "source_type": "directory",
                "source_name": ".",
                "archive_b64": _archive_member(),
            }
        ],
        "timeout_seconds": 900,
    }
    payload.update(overrides)
    return BrokerRunRequest.model_validate(payload)


def test_run_job_emits_replicated_job_with_mandatory_flags(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="Python 3.12.4\n")
    service = _broker(tmp_path, runner)

    response = service.run("agent", _run_request())

    argv = runner.create_argv()
    pairs = _pairs(argv)
    assert ("--mode", "replicated-job") in pairs
    assert ("--restart-condition", "none") in pairs
    assert ("--constraint", "node.role==worker") in pairs
    assert ("--network", "platform_jobs_internal") in pairs
    assert ("--limit-cpu", "2.0") in pairs
    assert ("--limit-memory", "4g") in pairs
    assert ("--limit-pids", "512") in pairs
    assert ("--cap-drop", "ALL") in pairs
    assert ("--ulimit", "nofile=1024:1024") in pairs
    assert ("--workdir", "/workspace") in pairs
    assert ("--env", "PLATFORM_ENV=unit") in pairs
    assert ("--label", "platform.job=job-1") in pairs
    assert ("--container-label", "platform.task=task-1") in pairs
    assert "--read-only" in argv
    assert "--init" in argv
    assert "--privileged" not in argv
    assert "--gpus" not in argv
    assert "--generic-resource" not in argv
    assert "--security-opt" not in argv
    mounts = [value for flag, value in pairs if flag == "--mount"]
    assert any(
        m.startswith("type=bind,")
        and "destination=/workspace/forge" in m
        and m.endswith(",readonly")
        for m in mounts
    )
    assert argv[-3:] == ("ghcr.io/platformnetwork/challenge:1.2.3", "python", "-V")
    assert response.returncode == 0
    assert response.stdout == "Python 3.12.4\n"
    assert response.timed_out is False
    assert runner.ledger_count_at_create == 1
    assert service.ledger.count("agent") == 0


def test_run_job_emits_tmpfs_mounts(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="Python 3.12.4\n")
    service = _broker(tmp_path, runner)

    service.run("agent", _run_request())

    pairs = _pairs(runner.create_argv())
    mounts = [value for flag, value in pairs if flag == "--mount"]
    assert "type=tmpfs,destination=/tmp,tmpfs-size=512m" in mounts


def test_run_failed_create_releases_ledger_and_raises(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(create_rc=1)
    service = _broker(tmp_path, runner)

    with pytest.raises(DockerExecutorError, match="create failed"):
        service.run("agent", _run_request())

    assert runner.ledger_count_at_create == 1
    assert service.ledger.count("agent") == 0
    assert any(call[1:3] == ("service", "rm") for call in runner.calls)


def test_run_timeout_returns_124_and_removes_service(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(task_state="running")
    config_clock = iter(range(0, 10_000, 10))
    service = SwarmBrokerService(
        SwarmBrokerConfig(
            workspace_dir=tmp_path / "work",
            allowed_images=("ghcr.io/platformnetwork/",),
        ),
        runner=runner,
        ledger=WorkloadLedger(),
        clock=lambda: float(next(config_clock)),
        sleep=lambda _seconds: None,
    )

    response = service.run("agent", _run_request(timeout_seconds=5))

    assert response.returncode == 124
    assert response.timed_out is True
    assert any(call[1:3] == ("service", "rm") for call in runner.calls)
    assert service.ledger.count("agent") == 0


def test_run_failed_task_maps_exit_code_and_error(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(task_state="failed", exit_code=7)
    service = _broker(tmp_path, runner)

    response = service.run("agent", _run_request())

    assert response.returncode == 7
    assert response.timed_out is False
    assert response.stderr == "task error"


def test_run_rejects_disallowed_image(tmp_path: Path) -> None:
    runner = FakeSwarmRunner()
    service = _broker(tmp_path, runner)

    with pytest.raises(DockerExecutorError, match="not allowed"):
        service.run("agent", _run_request(image="docker.io/evil:latest"))

    assert not any(call[1:3] == ("service", "create") for call in runner.calls)
    assert service.ledger.count("agent") == 0


def test_cleanup_removes_services_and_releases_ledger(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(
        ls_rows=[
            {"ID": "svc-a", "Name": "agent-job-1-x", "Image": "i", "Replicas": "0/1"}
        ]
    )
    service = _broker(tmp_path, runner)
    service.ledger.register(
        WorkloadEntry(key="svc-a", kind="swarm_service", challenge_slug="agent")
    )

    result = service.cleanup("agent", BrokerCleanupRequest(job_id="job-1"))

    assert result.status == "ok"
    assert ("docker", "service", "rm", "svc-a") in runner.calls
    ls_call = next(call for call in runner.calls if call[1:3] == ("service", "ls"))
    assert "label=platform.challenge=agent" in ls_call
    assert "label=platform.job=job-1" in ls_call
    assert service.ledger.count("agent") == 0


def test_list_maps_services_to_frozen_container_shape(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(
        ls_rows=[
            {
                "ID": "svc-a",
                "Name": "agent-job-1-x",
                "Image": "ghcr.io/platformnetwork/challenge:1.2.3",
                "Replicas": "0/1 (1/1 completed)",
            }
        ],
        inspect_details=[
            {
                "CreatedAt": "2026-06-12T10:00:00.000000000Z",
                "Spec": {
                    "Name": "agent-job-1-x",
                    "Labels": {
                        "platform.challenge": "agent",
                        "platform.job": "job-1",
                        "platform.task": "task-1",
                        "com.docker.stack.namespace": "filtered-out",
                    },
                },
            }
        ],
    )
    service = _broker(tmp_path, runner)

    listing = service.list_containers("agent", BrokerListRequest(job_id="job-1"))

    assert len(listing.containers) == 1
    container = listing.containers[0]
    assert container.container_id == "svc-a"
    assert container.container_name == "agent-job-1-x"
    assert container.image == "ghcr.io/platformnetwork/challenge:1.2.3"
    assert container.status == "0/1 (1/1 completed)"
    assert container.job_id == "job-1"
    assert container.task_id == "task-1"
    assert container.created == "2026-06-12T10:00:00.000000000Z"
    assert container.labels == {
        "platform.challenge": "agent",
        "platform.job": "job-1",
        "platform.task": "task-1",
    }


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _VOLATILE_KEYS[key]
            if key in _VOLATILE_KEYS and isinstance(item, str) and item
            else _normalize(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    return value


def _canonical_bytes(record: dict[str, Any]) -> bytes:
    return (json.dumps(_normalize(record), sort_keys=True, indent=2) + "\n").encode()


def _golden_request(name: str) -> dict[str, Any]:
    request = json.loads((GOLDEN_DIR / f"{name}.json").read_text())["request"]
    for mount in request.get("mounts") or []:
        if mount.get("archive_b64") == "<B64>":
            mount["archive_b64"] = _archive_member(data=b"contract")
    return request


def _swarm_client(tmp_path: Path, runner: FakeSwarmRunner) -> TestClient:
    return TestClient(
        create_docker_broker_app(registry=Registry(), service=_broker(tmp_path, runner))
    )


@pytest.mark.parametrize(
    ("fixture", "endpoint", "runner_kwargs"),
    [
        ("run_normal", "/v1/docker/run", {"log_stdout": "Python 3.12.4\n"}),
        ("run_gpu", "/v1/docker/run", {"log_stdout": "Python 3.12.4\n"}),
        ("run_privileged", "/v1/docker/run", {}),
        ("cleanup", "/v1/docker/cleanup", {}),
        (
            "list",
            "/v1/docker/list",
            {
                "ls_rows": [
                    {
                        "ID": "svc-a",
                        "Name": "agent-job-1-x",
                        "Image": "ghcr.io/platformnetwork/challenge:1.2.3",
                        "Replicas": "Exited (0) 2 minutes ago",
                    }
                ],
                "inspect_details": [
                    {
                        "CreatedAt": "2026-06-12T10:00:00.000000000Z",
                        "Spec": {
                            "Name": "agent-job-1-x",
                            "Labels": {
                                "platform.job": "job-1",
                                "platform.task": "task-1",
                                "com.docker.internal": "must-be-filtered-out",
                            },
                        },
                    }
                ],
            },
        ),
    ],
)
def test_swarm_broker_matches_frozen_golden_shapes(
    tmp_path: Path, fixture: str, endpoint: str, runner_kwargs: dict[str, Any]
) -> None:
    """The Swarm backend must reproduce the FROZEN contract byte-for-byte.

    Replays each golden request against the Swarm-backed broker app (fake
    runner scripted to yield backend-equivalent data) and asserts the
    normalized exchange equals the contract fixture captured from the
    legacy ``docker run`` backend.
    """

    runner = FakeSwarmRunner(**runner_kwargs)
    client = _swarm_client(tmp_path, runner)
    payload = _golden_request(fixture)

    response = client.post(endpoint, headers=AUTH_HEADERS, json=payload)
    record = {
        "endpoint": endpoint,
        "request": payload,
        "status_code": response.status_code,
        "response": response.json(),
    }

    expected = (GOLDEN_DIR / f"{fixture}.json").read_bytes()
    assert _canonical_bytes(record) == expected


def test_run_gpu_request_emits_generic_resource_not_gpus(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="Python 3.12.4\n")
    service = _broker(tmp_path, runner)

    response = service.run("agent", _run_request(limits={"gpu_count": 1}))

    argv = runner.create_argv()
    pairs = _pairs(argv)
    assert ("--generic-resource", "NVIDIA-GPU=1") in pairs
    assert "--gpus" not in argv
    assert argv[-3:] == ("ghcr.io/platformnetwork/challenge:1.2.3", "python", "-V")
    assert response.returncode == 0
    # The GPU lease is held only for the duration of the job.
    assert service.gpu_leases.in_use == 0


def test_run_gpu_capacity_one_refuses_second_and_release_frees(
    tmp_path: Path,
) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(tmp_path, runner)
    assert service.gpu_leases.capacity == 1
    service.gpu_leases.acquire("concurrent-gpu-job", 1)

    with pytest.raises(DockerExecutorError, match="gpu_capacity_insufficient"):
        service.run("agent", _run_request(limits={"gpu_count": 1}))

    assert not any(call[1:3] == ("service", "create") for call in runner.calls)
    assert service.ledger.count("agent") == 0

    service.gpu_leases.release("concurrent-gpu-job")
    response = service.run("agent", _run_request(limits={"gpu_count": 1}))

    assert response.returncode == 0
    assert service.gpu_leases.in_use == 0


def test_run_gpu_lease_released_on_failed_create(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(create_rc=1)
    service = _broker(tmp_path, runner)

    with pytest.raises(DockerExecutorError, match="create failed"):
        service.run("agent", _run_request(limits={"gpu_count": 1}))

    assert service.gpu_leases.in_use == 0
    assert service.ledger.count("agent") == 0


def test_gpu_lease_ledger_enforces_capacity_and_keys() -> None:
    leases = GpuLeaseLedger(capacity=1)

    leases.acquire("job-a", 1)
    with pytest.raises(GpuLeaseError, match="already held"):
        leases.acquire("job-a", 1)
    with pytest.raises(GpuCapacityError, match="gpu_capacity_insufficient"):
        leases.acquire("job-b", 1)

    assert leases.release("job-a") is True
    assert leases.release("job-a") is False  # idempotent
    leases.acquire("job-b", 1)
    assert leases.in_use == 1
    assert leases.available == 0
    with pytest.raises(GpuLeaseError, match="positive integer"):
        leases.acquire("job-c", 0)


def test_orchestrator_service_spec_becomes_replicated_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeSwarmRunner(network_exists=False)
    ledger = WorkloadLedger()
    orchestrator = SwarmChallengeOrchestrator(runner=runner, ledger=ledger)
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: ({"status": "ok"}, {"api_version": "1.0"}),
    )
    spec = ChallengeSpec(
        slug="agent",
        image="ghcr.io/platformnetwork/agent:1.0.0",
        challenge_token="tok-secret",
        workload_class="service",
        resources=ChallengeResources(docker_timeout_seconds=600),
    )

    runtime = orchestrator.start_challenge(spec)

    argv = runner.create_argv()
    pairs = _pairs(argv)
    assert ("--mode", "replicated") in pairs
    assert ("--replicas", "1") in pairs
    assert ("--restart-condition", "any") in pairs
    assert ("--constraint", "node.role==worker") in pairs
    assert ("--network", "platform_challenges") in pairs
    assert (
        "--secret",
        "source=platform_agent_challenge_token,target=platform/challenge_token",
    ) in pairs
    assert "--privileged" not in argv
    assert "--generic-resource" not in argv
    network_create = next(
        call for call in runner.calls if call[1:3] == ("network", "create")
    )
    assert network_create == tuple(
        build_overlay_network_argv("docker", "platform_challenges", internal=True)
    )
    secret_index = runner.calls.index(
        ("docker", "secret", "create", "platform_agent_challenge_token", "-")
    )
    assert runner.inputs[secret_index] == "tok-secret"
    entry = ledger.get(runner.service_id)
    assert entry is not None
    assert entry.workload_class == "service"
    assert entry.timeout_seconds == 600
    assert ledger.count("agent") == 1
    assert runtime.container_id == runner.service_id
    assert runtime.container_name == "challenge-agent"


def test_orchestrator_job_spec_becomes_replicated_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeSwarmRunner()
    ledger = WorkloadLedger()
    orchestrator = SwarmChallengeOrchestrator(runner=runner, ledger=ledger)
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: ({"status": "ok"}, {"api_version": "1.0"}),
    )
    spec = ChallengeSpec(
        slug="agent",
        image="ghcr.io/platformnetwork/agent:1.0.0",
        workload_class="job",
    )

    orchestrator.start_challenge(spec)

    pairs = _pairs(runner.create_argv())
    assert ("--mode", "replicated-job") in pairs
    assert ("--restart-condition", "none") in pairs
    entry = ledger.get(runner.service_id)
    assert entry is not None
    assert entry.workload_class == "job"


def test_orchestrator_failed_create_releases_ledger() -> None:
    runner = FakeSwarmRunner(create_rc=1)
    ledger = WorkloadLedger()
    orchestrator = SwarmChallengeOrchestrator(runner=runner, ledger=ledger)
    spec = ChallengeSpec(
        slug="agent",
        image="ghcr.io/platformnetwork/agent:1.0.0",
        workload_class="service",
    )

    with pytest.raises(DockerOrchestrationError, match="create failed"):
        orchestrator.start_challenge(spec)

    assert ledger.count("agent") == 0


def test_orchestrator_stop_challenge_removes_service_and_releases() -> None:
    runner = FakeSwarmRunner(service_exists=True)
    ledger = WorkloadLedger()
    orchestrator = SwarmChallengeOrchestrator(runner=runner, ledger=ledger)
    ledger.register(
        WorkloadEntry(
            key=runner.service_id,
            kind="swarm_service",
            challenge_slug="agent",
            workload_class="service",
        )
    )

    orchestrator.stop_challenge("agent")

    assert ("docker", "service", "rm", "challenge-agent") in runner.calls
    assert ledger.count("agent") == 0


def test_build_service_create_argv_orders_image_and_command_last() -> None:
    plan = SwarmServicePlan(
        name="x",
        image="ghcr.io/platformnetwork/x:1",
        command=("run", "--flag"),
        mode="replicated-job",
    )

    argv = build_service_create_argv("docker", plan)

    assert argv[:6] == ["docker", "service", "create", "--detach", "--name", "x"]
    assert argv[-3:] == ["ghcr.io/platformnetwork/x:1", "run", "--flag"]


def test_build_service_create_argv_emits_generic_resources_before_image() -> None:
    plan = SwarmServicePlan(
        name="x",
        image="ghcr.io/platformnetwork/x:1",
        command=("run",),
        generic_resources=("NVIDIA-GPU=2",),
    )

    argv = build_service_create_argv("docker", plan)

    pairs = _pairs(tuple(argv))
    assert ("--generic-resource", "NVIDIA-GPU=2") in pairs
    assert "--gpus" not in argv
    assert argv[-2:] == ["ghcr.io/platformnetwork/x:1", "run"]


def test_orchestrator_gpu_service_emits_generic_resource_and_holds_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeSwarmRunner()
    orchestrator = SwarmChallengeOrchestrator(runner=runner, ledger=WorkloadLedger())
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: ({"status": "ok"}, {"api_version": "1.0"}),
    )
    spec = ChallengeSpec(
        slug="agent",
        image="ghcr.io/platformnetwork/agent:1.0.0",
        workload_class="service",
        resources=ChallengeResources(gpu_count=1),
    )

    orchestrator.start_challenge(spec)

    argv = runner.create_argv()
    pairs = _pairs(argv)
    assert ("--generic-resource", "NVIDIA-GPU=1") in pairs
    assert "--gpus" not in argv
    # Long-lived GPU challenge services hold the lease until stopped.
    assert orchestrator.gpu_leases.in_use == 1

    runner.service_exists = True
    orchestrator.stop_challenge("agent")

    assert orchestrator.gpu_leases.in_use == 0


def test_orchestrator_gpu_capacity_refusal_and_failed_create_release_lease() -> None:
    runner = FakeSwarmRunner(create_rc=1)
    orchestrator = SwarmChallengeOrchestrator(runner=runner, ledger=WorkloadLedger())
    spec = ChallengeSpec(
        slug="agent",
        image="ghcr.io/platformnetwork/agent:1.0.0",
        workload_class="service",
        resources=ChallengeResources(gpu_count=1),
    )

    with pytest.raises(DockerOrchestrationError, match="create failed"):
        orchestrator.start_challenge(spec)

    assert orchestrator.gpu_leases.in_use == 0

    orchestrator.gpu_leases.acquire("held-elsewhere", 1)
    with pytest.raises(DockerOrchestrationError, match="gpu_capacity_insufficient"):
        orchestrator.start_challenge(spec)


def test_orchestrator_external_secret_emits_reference_without_create(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeSwarmRunner()
    orchestrator = SwarmChallengeOrchestrator(runner=runner, ledger=WorkloadLedger())
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: ({"status": "ok"}, {"api_version": "1.0"}),
    )
    spec = ChallengeSpec(
        slug="agent-challenge",
        image="ghcr.io/platformnetwork/agent:1.0.0",
        challenge_token="fake-token-for-test",
        external_secrets=("submission_env_encryption_key",),
        workload_class="service",
    )

    orchestrator.start_challenge(spec)

    pairs = _pairs(runner.create_argv())
    assert (
        "--secret",
        "source=platform_agent_challenge_challenge_token,target=platform/"
        "challenge_token",
    ) in pairs
    assert (
        "--secret",
        "source=platform_agent_challenge_submission_env_encryption_key,"
        "target=platform/submission_env_encryption_key",
    ) in pairs
    assert (
        "--env",
        "SUBMISSION_ENV_ENCRYPTION_KEY_FILE=/run/secrets/platform/"
        "submission_env_encryption_key",
    ) in pairs
    secret_creates = [
        call for call in runner.calls if call[1:3] == ("secret", "create")
    ]
    assert [call[3] for call in secret_creates] == [
        "platform_agent_challenge_challenge_token"
    ]


def test_orchestrator_secret_value_never_appears_in_argv_or_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeSwarmRunner()
    orchestrator = SwarmChallengeOrchestrator(runner=runner, ledger=WorkloadLedger())
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: ({"status": "ok"}, {"api_version": "1.0"}),
    )
    challenge_value = "fake-challenge-token-value"
    broker_value = "fake-broker-token-value"
    spec = ChallengeSpec(
        slug="agent",
        image="ghcr.io/platformnetwork/agent:1.0.0",
        challenge_token=challenge_value,
        docker_broker_token=broker_value,
        workload_class="service",
    )

    orchestrator.start_challenge(spec)

    for call in runner.calls:
        for token in call:
            assert challenge_value not in token
            assert broker_value not in token
    create_indexes = [
        index
        for index, call in enumerate(runner.calls)
        if call[1:3] == ("secret", "create")
    ]
    assert {runner.inputs[index] for index in create_indexes} == {
        challenge_value,
        broker_value,
    }
    for index, payload in enumerate(runner.inputs):
        if index not in create_indexes:
            assert payload is None
