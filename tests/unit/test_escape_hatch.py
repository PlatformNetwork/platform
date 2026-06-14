"""Unit tests for the privileged DinD escape hatch (Task 13).

The escape hatch replaces the unconditional privileged-403 with a
capability-gated direct ``docker run --privileged`` on the worker node. The
docker CLI layer is replaced by an argv-capturing fake runner (mirroring
``FakeSwarmRunner``), so no dockerd is required.
"""

from __future__ import annotations

import base64
import io
import tarfile
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from platform_network.challenge_sdk.executors.docker import DockerExecutorError
from platform_network.master.docker_broker import (
    DockerBrokerConfig,
    DockerBrokerService,
    EscapeHatchCommandResult,
    create_docker_broker_app,
)
from platform_network.master.swarm_backend import (
    SwarmBrokerConfig,
    SwarmBrokerService,
)
from platform_network.master.workload_ledger import WorkloadEntry, WorkloadLedger
from platform_network.schemas.docker_broker import (
    BrokerCleanupRequest,
    BrokerRunRequest,
)

FROZEN_PRIVILEGED_DETAIL = (
    "privileged broker jobs require an isolated Kubernetes runtime"
)
FULL_CONTAINER_ID = "c0ffee" + "0" * 58

AUTH_HEADERS = {
    "authorization": "Bearer tok",
    "x-platform-challenge-slug": "agent",
}


class Registry:
    def get_broker_token(self, slug: str) -> str:
        return "tok" if slug == "agent" else ""


def _result(
    argv: tuple[str, ...],
    rc: int = 0,
    out: str = "",
    err: str = "",
    timed_out: bool = False,
) -> EscapeHatchCommandResult:
    return EscapeHatchCommandResult(
        argv=argv, returncode=rc, stdout=out, stderr=err, timed_out=timed_out
    )


class FakeEscapeRunner:
    """Scripted docker CLI fake capturing every escape-hatch argv."""

    def __init__(
        self,
        *,
        container_id: str = FULL_CONTAINER_ID,
        run_rc: int = 0,
        exit_code: int = 0,
        wait_timed_out: bool = False,
        log_stdout: str = "",
        log_stderr: str = "",
        ps_ids: list[str] | None = None,
    ) -> None:
        self.container_id = container_id
        self.run_rc = run_rc
        self.exit_code = exit_code
        self.wait_timed_out = wait_timed_out
        self.log_stdout = log_stdout
        self.log_stderr = log_stderr
        self.ps_ids = ps_ids or []
        self.calls: list[tuple[str, ...]] = []
        self.ledger: WorkloadLedger | None = None
        self.ledger_entry_at_wait: WorkloadEntry | None = None

    def run(
        self,
        argv: Any,
        *,
        timeout_seconds: float | None = None,
    ) -> EscapeHatchCommandResult:
        argv = tuple(argv)
        self.calls.append(argv)
        verb = argv[1]
        if verb == "run":
            if self.run_rc:
                return _result(argv, rc=self.run_rc, err="boom: run failed")
            return _result(argv, out=f"{self.container_id}\n")
        if verb == "wait":
            if self.ledger is not None:
                self.ledger_entry_at_wait = self.ledger.get(self.container_id)
            if self.wait_timed_out:
                return _result(argv, rc=124, timed_out=True)
            return _result(argv, out=f"{self.exit_code}\n")
        if verb == "logs":
            return _result(argv, out=self.log_stdout, err=self.log_stderr)
        if verb == "ps":
            return _result(argv, out="".join(f"{cid}\n" for cid in self.ps_ids))
        return _result(argv)


def _pairs(argv: tuple[str, ...]) -> list[tuple[str, str]]:
    return list(zip(argv, argv[1:], strict=False))


def _archive_member(name: str = "input.txt", data: bytes = b"ok") -> str:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return base64.b64encode(stream.getvalue()).decode("ascii")


def _run_request(**overrides: Any) -> BrokerRunRequest:
    payload: dict[str, Any] = {
        "job_id": "job-priv",
        "task_id": "task-1",
        "image": "ghcr.io/platformnetwork/dind-challenge:1.0.0",
        "command": ["dockerd-entrypoint.sh"],
        "workdir": "/workspace",
        "env": {"PLATFORM_ENV": "unit"},
        "labels": {"platform.challenge": "agent"},
        "limits": {"privileged": True},
        "mounts": [
            {
                "target": "/workspace/forge",
                "read_only": True,
                "source_type": "directory",
                "source_name": ".",
                "archive_b64": _archive_member(),
            }
        ],
        "timeout_seconds": 600,
    }
    limits_overrides = overrides.pop("limits", None)
    payload.update(overrides)
    if limits_overrides:
        payload["limits"] = {**payload["limits"], **limits_overrides}
    return BrokerRunRequest.model_validate(payload)


def _service(
    tmp_path: Path, runner: FakeEscapeRunner, **config_overrides: Any
) -> DockerBrokerService:
    config = DockerBrokerConfig(
        workspace_dir=tmp_path / "work",
        allowed_images=("ghcr.io/platformnetwork/",),
        **config_overrides,
    )
    ledger = WorkloadLedger()
    runner.ledger = ledger
    return DockerBrokerService(config, escape_runner=runner, ledger=ledger)


_GATED = {
    "privileged_escape_slugs": frozenset({"agent"}),
    "node_role": "worker",
}


def _escape_run_argv(runner: FakeEscapeRunner) -> tuple[str, ...]:
    for call in runner.calls:
        if call[1] == "run":
            return call
    raise AssertionError("no docker run call captured")


def test_privileged_without_capability_keeps_exact_403(tmp_path: Path) -> None:
    runner = FakeEscapeRunner()
    client = TestClient(
        create_docker_broker_app(
            registry=Registry(), service=_service(tmp_path, runner)
        )
    )

    response = client.post(
        "/v1/docker/run",
        headers=AUTH_HEADERS,
        json=_run_request().model_dump(mode="json"),
    )

    assert response.status_code == 403
    assert response.json() == {"detail": FROZEN_PRIVILEGED_DETAIL}
    assert runner.calls == []


def test_manager_node_context_refuses_with_frozen_403(tmp_path: Path) -> None:
    runner = FakeEscapeRunner()
    client = TestClient(
        create_docker_broker_app(
            registry=Registry(),
            service=_service(
                tmp_path,
                runner,
                privileged_escape_slugs=frozenset({"agent"}),
                node_role="manager",
            ),
        )
    )

    response = client.post(
        "/v1/docker/run",
        headers=AUTH_HEADERS,
        json=_run_request().model_dump(mode="json"),
    )

    assert response.status_code == 403
    assert response.json() == {"detail": FROZEN_PRIVILEGED_DETAIL}
    assert runner.calls == []


def test_gated_run_launches_privileged_docker_run_and_tracks_ledger(
    tmp_path: Path,
) -> None:
    runner = FakeEscapeRunner(log_stdout="inner daemon up\n")
    service = _service(tmp_path, runner, **_GATED)

    response = service.run("agent", _run_request(limits={"gpu_count": 2}))

    argv = _escape_run_argv(runner)
    pairs = _pairs(argv)
    assert argv[1:3] == ("run", "--detach")
    assert "--privileged" in argv
    assert ("--gpus", "2") in pairs
    # Task-11 insertion order: --gpus before --privileged.
    assert argv.index("--gpus") < argv.index("--privileged")
    assert "--init" in argv
    # DinD-mandated omissions (documented in build_escape_hatch_run_argv).
    assert "--cap-drop" not in argv
    assert "--security-opt" not in argv
    assert "--read-only" not in argv
    assert "--rm" not in argv
    volumes = [value for flag, value in pairs if flag == "-v"]
    assert any(v.endswith(":/var/lib/docker") for v in volumes)
    assert any("destination" not in v and "/workspace/forge" in v for v in volumes)
    assert ("--label", "platform.job=job-priv") in pairs
    assert argv[-2:] == (
        "ghcr.io/platformnetwork/dind-challenge:1.0.0",
        "dockerd-entrypoint.sh",
    )

    # Ledger entry was held (FULL container ID) while the job ran.
    entry = runner.ledger_entry_at_wait
    assert entry is not None
    assert entry.key == FULL_CONTAINER_ID
    assert entry.kind == "escape_hatch_container"
    assert entry.workload_class == "job"
    assert entry.timeout_seconds == 600
    # Released on exit; container removed.
    assert service.ledger.count("agent") == 0
    assert ("docker", "rm", "-f", FULL_CONTAINER_ID) in runner.calls
    assert any(call[1:3] == ("volume", "rm") for call in runner.calls)

    assert response.returncode == 0
    assert response.stdout == "inner daemon up\n"
    assert response.timed_out is False


def test_gated_run_without_gpu_omits_gpus_flag(tmp_path: Path) -> None:
    runner = FakeEscapeRunner()
    service = _service(tmp_path, runner, **_GATED)

    service.run("agent", _run_request())

    argv = _escape_run_argv(runner)
    assert "--gpus" not in argv
    assert "--privileged" in argv


def test_gated_run_timeout_returns_124_and_releases(tmp_path: Path) -> None:
    runner = FakeEscapeRunner(wait_timed_out=True)
    service = _service(tmp_path, runner, **_GATED)

    response = service.run("agent", _run_request(timeout_seconds=5))

    assert response.returncode == 124
    assert response.timed_out is True
    assert ("docker", "rm", "-f", FULL_CONTAINER_ID) in runner.calls
    assert service.ledger.count("agent") == 0


def test_gated_run_failed_create_raises_executor_error(tmp_path: Path) -> None:
    runner = FakeEscapeRunner(run_rc=1)
    service = _service(tmp_path, runner, **_GATED)

    with pytest.raises(DockerExecutorError, match="run failed"):
        service.run("agent", _run_request())

    assert service.ledger.count("agent") == 0
    assert not any(call[1] == "wait" for call in runner.calls)


def test_gated_run_rejects_disallowed_image(tmp_path: Path) -> None:
    runner = FakeEscapeRunner()
    service = _service(tmp_path, runner, **_GATED)

    with pytest.raises(DockerExecutorError, match="not allowed"):
        service.run("agent", _run_request(image="docker.io/evil:latest"))

    assert runner.calls == []


def test_cleanup_removes_escape_hatch_container_and_releases(tmp_path: Path) -> None:
    runner = FakeEscapeRunner(ps_ids=[FULL_CONTAINER_ID])
    service = _service(tmp_path, runner)
    service.ledger.register(
        WorkloadEntry(
            key=FULL_CONTAINER_ID,
            kind="escape_hatch_container",
            challenge_slug="agent",
            timeout_seconds=600,
        )
    )

    result = service.cleanup("agent", BrokerCleanupRequest(job_id="job-priv"))

    assert result.status == "ok"
    ps_call = next(call for call in runner.calls if call[1] == "ps")
    assert "--no-trunc" in ps_call
    assert "label=platform.challenge=agent" in ps_call
    assert "label=platform.job=job-priv" in ps_call
    assert ("docker", "rm", "-f", FULL_CONTAINER_ID) in runner.calls
    assert service.ledger.count("agent") == 0


def test_cleanup_without_escape_entries_spawns_no_escape_commands(
    tmp_path: Path,
) -> None:
    runner = FakeEscapeRunner()
    service = _service(tmp_path, runner)

    service.cleanup("agent", BrokerCleanupRequest(job_id="job-1"))

    assert runner.calls == []


def test_swarm_backend_gated_run_uses_docker_run_not_service_create(
    tmp_path: Path,
) -> None:
    escape_runner = FakeEscapeRunner(log_stdout="ok\n")

    class _NoSwarmRunner:
        def run(self, argv: Any, **kwargs: Any) -> Any:
            raise AssertionError(f"unexpected Swarm command: {tuple(argv)}")

    service = SwarmBrokerService(
        SwarmBrokerConfig(
            workspace_dir=tmp_path / "work",
            allowed_images=("ghcr.io/platformnetwork/",),
            privileged_escape_slugs=frozenset({"agent"}),
            node_role="worker",
        ),
        runner=_NoSwarmRunner(),
        escape_runner=escape_runner,
    )

    response = service.run("agent", _run_request())

    argv = _escape_run_argv(escape_runner)
    assert "--privileged" in argv
    assert "service" not in argv
    assert response.returncode == 0
    assert service.ledger.count("agent") == 0


def test_swarm_backend_default_config_keeps_privileged_403(tmp_path: Path) -> None:
    escape_runner = FakeEscapeRunner()

    class _IdleRunner:
        def run(self, argv: Any, **kwargs: Any) -> Any:
            raise AssertionError("no docker command expected")

    service = SwarmBrokerService(
        SwarmBrokerConfig(workspace_dir=tmp_path / "work"),
        runner=_IdleRunner(),
        escape_runner=escape_runner,
    )
    client = TestClient(create_docker_broker_app(registry=Registry(), service=service))

    response = client.post(
        "/v1/docker/run",
        headers=AUTH_HEADERS,
        json=_run_request().model_dump(mode="json"),
    )

    assert response.status_code == 403
    assert response.json() == {"detail": FROZEN_PRIVILEGED_DETAIL}
    assert escape_runner.calls == []
