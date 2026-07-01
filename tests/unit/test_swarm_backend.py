"""Unit tests for the Swarm-backed broker/orchestrator (Task 9).

The docker CLI layer is replaced by an argv-capturing fake runner, mirroring
how the broker is tested without dockerd. The golden parity tests replay the
contract-suite payloads against the Swarm service and compare the normalized
bytes against the FROZEN fixtures in ``tests/contract/golden/``.
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import os
import tarfile
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from base.challenge_sdk.executors.docker import DockerExecutorError
from base.challenge_sdk.mount_transport import (
    encode_dir_archive,
    extract_archive_to_dir,
    parse_drained_archives,
    strip_drain_sections,
)
from base.gpu.leases import (
    GpuCapacityError,
    GpuLeaseError,
    GpuLeaseLedger,
)
from base.master.docker_broker import create_docker_broker_app
from base.master.docker_orchestrator import (
    ChallengeResources,
    ChallengeSpec,
    DockerOrchestrationError,
    challenge_spec_from_registry,
)
from base.master.orchestration import MasterChallengeReconciler
from base.master.swarm_backend import (
    SwarmBrokerConfig,
    SwarmBrokerService,
    SwarmChallengeOrchestrator,
    SwarmCommandResult,
    SwarmServicePlan,
    build_overlay_network_argv,
    build_service_create_argv,
)
from base.master.workload_ledger import WorkloadEntry, WorkloadLedger
from base.schemas.challenge import ChallengeRecord, ChallengeStatus
from base.schemas.docker_broker import (
    BrokerCleanupRequest,
    BrokerListRequest,
    BrokerRunRequest,
)

GOLDEN_DIR = Path(__file__).resolve().parents[1] / "contract" / "golden"

AUTH_HEADERS = {
    "authorization": "Bearer tok",
    "x-base-challenge-slug": "agent",
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
        allowed_images=("ghcr.io/baseintelligence/",),
        **config_overrides,
    )
    ledger = WorkloadLedger()
    runner.ledger = ledger
    return SwarmBrokerService(config, runner=runner, ledger=ledger)


def _run_request(**overrides: Any) -> BrokerRunRequest:
    payload: dict[str, Any] = {
        "job_id": "job-1",
        "task_id": "task-1",
        "image": "ghcr.io/baseintelligence/challenge:1.2.3",
        "command": ["python", "-V"],
        "workdir": "/workspace",
        "env": {"BASE_ENV": "unit"},
        "labels": {"base.challenge": "agent"},
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
    assert ("--constraint", "node.labels.base.workload==cpu") in pairs
    assert ("--network", "base_jobs_internal") in pairs
    assert ("--limit-cpu", "2.0") in pairs
    assert ("--limit-memory", "4g") in pairs
    assert ("--limit-pids", "512") in pairs
    assert ("--cap-drop", "ALL") in pairs
    assert ("--ulimit", "nofile=1024:1024") in pairs
    assert ("--workdir", "/workspace") in pairs
    assert ("--env", "BASE_ENV=unit") in pairs
    assert ("--label", "base.job=job-1") in pairs
    assert ("--container-label", "base.task=task-1") in pairs
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
    assert argv[-3:] == ("ghcr.io/baseintelligence/challenge:1.2.3", "python", "-V")
    assert response.returncode == 0
    assert response.stdout == "Python 3.12.4\n"
    assert response.timed_out is False
    assert runner.ledger_count_at_create == 1
    assert service.ledger.count("agent") == 0


def test_run_job_emits_with_registry_auth(tmp_path: Path) -> None:
    # Without this flag a private-GHCR eval job creates fine but hangs pending
    # on an unauthorized pull on the worker node (Defect E2).
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(tmp_path, runner)

    service.run("agent", _run_request())

    assert "--with-registry-auth" in runner.create_argv()


def test_run_job_emits_tmpfs_mounts(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="Python 3.12.4\n")
    service = _broker(tmp_path, runner)

    service.run("agent", _run_request())

    pairs = _pairs(runner.create_argv())
    mounts = [value for flag, value in pairs if flag == "--mount"]
    assert "type=tmpfs,destination=/tmp,tmpfs-size=512m" in mounts


def test_run_job_mounts_docker_socket_for_allowlisted_slug(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(tmp_path, runner, docker_socket_slugs=frozenset({"agent"}))

    service.run("agent", _run_request())

    pairs = _pairs(runner.create_argv())
    mounts = [value for flag, value in pairs if flag == "--mount"]
    assert (
        "type=bind,source=/var/run/docker.sock,destination=/var/run/docker.sock"
        in mounts
    )
    # Socket must be read-write (Docker CLI issues write calls) and never
    # emitted as --privileged on the Swarm service.
    assert not any("docker.sock" in m and m.endswith(",readonly") for m in mounts)
    assert "--privileged" not in runner.create_argv()


def test_run_job_honors_custom_docker_socket_path(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(
        tmp_path,
        runner,
        docker_socket_slugs=frozenset({"agent"}),
        docker_socket_path="/run/docker.sock",
    )

    service.run("agent", _run_request())

    mounts = [
        value for flag, value in _pairs(runner.create_argv()) if flag == "--mount"
    ]
    assert "type=bind,source=/run/docker.sock,destination=/run/docker.sock" in mounts


def test_run_job_omits_docker_socket_for_non_allowlisted_slug(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(tmp_path, runner, docker_socket_slugs=frozenset({"other"}))

    service.run("agent", _run_request())

    mounts = [
        value for flag, value in _pairs(runner.create_argv()) if flag == "--mount"
    ]
    assert not any("docker.sock" in m for m in mounts)


def test_run_job_omits_docker_socket_by_default(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(tmp_path, runner)

    service.run("agent", _run_request())

    mounts = [
        value for flag, value in _pairs(runner.create_argv()) if flag == "--mount"
    ]
    assert not any("docker.sock" in m for m in mounts)


def test_run_job_mounts_eval_readonly_for_allowlisted_slug(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(
        tmp_path,
        runner,
        docker_socket_slugs=frozenset({"agent"}),
        eval_readonly_mounts=(
            ("agent_challenge_task_cache", "/opt/agent-challenge/task-cache"),
            ("/var/lib/agent-challenge/golden", "/opt/agent-challenge/golden"),
        ),
    )

    service.run("agent", _run_request())

    mounts = [
        value for flag, value in _pairs(runner.create_argv()) if flag == "--mount"
    ]
    # Named volume source -> type=volume; absolute host source -> type=bind. Both
    # read-only so the job can never mutate the shared cache.
    assert (
        "type=volume,source=agent_challenge_task_cache,"
        "destination=/opt/agent-challenge/task-cache,readonly" in mounts
    )
    assert (
        "type=bind,source=/var/lib/agent-challenge/golden,"
        "destination=/opt/agent-challenge/golden,readonly" in mounts
    )


def test_run_job_omits_eval_readonly_for_non_allowlisted_slug(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(
        tmp_path,
        runner,
        docker_socket_slugs=frozenset({"other"}),
        eval_readonly_mounts=(
            ("agent_challenge_task_cache", "/opt/agent-challenge/task-cache"),
        ),
    )

    service.run("agent", _run_request())

    mounts = [
        value for flag, value in _pairs(runner.create_argv()) if flag == "--mount"
    ]
    assert not any("agent-challenge" in m for m in mounts)


def test_run_job_omits_eval_readonly_by_default(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(tmp_path, runner)

    service.run("agent", _run_request())

    mounts = [
        value for flag, value in _pairs(runner.create_argv()) if flag == "--mount"
    ]
    assert not any("/opt/agent-challenge" in m for m in mounts)


_PRISM_EVAL_READONLY_BY_SLUG = {
    "prism": (
        ("prism_fineweb_edu_train", "/data/fineweb-edu/train"),
        ("prism_reference_tokenizers", "/opt/prism/reference-tokenizers"),
    )
}


def _prism_gpu_request(**overrides: Any) -> BrokerRunRequest:
    payload: dict[str, Any] = {
        "command": ["torchrun", "/workspace/runner.py"],
        "workdir": "/workspace",
        "labels": {"base.challenge": "prism"},
        "limits": {"gpu_count": 1, "network": "none"},
        "mounts": _gpu_mounts(),
    }
    payload.update(overrides)
    return _run_request(**payload)


def test_run_job_prism_mounts_eval_readonly_by_slug_without_socket(
    tmp_path: Path,
) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    # prism is NOT in docker_socket_slugs: it must receive the locked-data RO
    # mounts WITHOUT the (root-equivalent) host Docker socket.
    service = _broker(
        tmp_path,
        runner,
        eval_readonly_mounts_by_slug=_PRISM_EVAL_READONLY_BY_SLUG,
    )

    service.run("prism", _prism_gpu_request())

    argv = runner.create_argv()
    mounts = [value for flag, value in _pairs(argv) if flag == "--mount"]
    # The train split + reference tokenizers bind-mount READ-ONLY (a named
    # volume source -> type=volume; every entry ends with ,readonly).
    assert (
        "type=volume,source=prism_fineweb_edu_train,"
        "destination=/data/fineweb-edu/train,readonly" in mounts
    )
    assert (
        "type=volume,source=prism_reference_tokenizers,"
        "destination=/opt/prism/reference-tokenizers,readonly" in mounts
    )
    # No Docker-out-of-Docker socket for prism.
    assert not any("docker.sock" in m for m in mounts)


def test_run_job_prism_eval_readonly_exposes_only_train_split(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(
        tmp_path,
        runner,
        eval_readonly_mounts_by_slug=_PRISM_EVAL_READONLY_BY_SLUG,
    )

    service.run("prism", _prism_gpu_request())

    mounts = [
        value for flag, value in _pairs(runner.create_argv()) if flag == "--mount"
    ]
    data_mounts = [m for m in mounts if "/data/fineweb-edu" in m]
    assert data_mounts == [
        "type=volume,source=prism_fineweb_edu_train,"
        "destination=/data/fineweb-edu/train,readonly"
    ]
    # The secret held-out splits are NEVER mounted into the miner container.
    assert not any("destination=/data/fineweb-edu/val" in m for m in mounts)
    assert not any("destination=/data/fineweb-edu/test" in m for m in mounts)


def test_run_job_eval_readonly_by_slug_scoped_to_matching_slug(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(
        tmp_path,
        runner,
        eval_readonly_mounts_by_slug=_PRISM_EVAL_READONLY_BY_SLUG,
    )

    # A different slug must not inherit prism's locked-data mounts.
    service.run("agent", _run_request())

    mounts = [
        value for flag, value in _pairs(runner.create_argv()) if flag == "--mount"
    ]
    assert not any("prism_fineweb_edu_train" in m for m in mounts)
    assert not any("/data/fineweb-edu" in m for m in mounts)


def test_run_job_prism_eval_has_no_review_secret(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(
        tmp_path,
        runner,
        eval_readonly_mounts_by_slug=_PRISM_EVAL_READONLY_BY_SLUG,
    )

    service.run("prism", _prism_gpu_request())

    argv = runner.create_argv()
    # The scored eval job carries NO Swarm secret: the OpenRouter review key
    # (and every other secret) is absent from the eval container.
    assert "--secret" not in argv
    assert not any("openrouter" in token.lower() for token in argv)


# --- Task 14: untrusted eval job is egress-locked to the internal overlay --------

_PRISM_EGRESS_LOCKED = frozenset({"prism"})


def test_job_network_forces_internal_for_egress_locked_slug(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(tmp_path, runner, egress_locked_slugs=_PRISM_EGRESS_LOCKED)
    # An egress-locked slug (untrusted miner code) can NEVER reach an external
    # route: even an explicit request for the egress-capable "default" network
    # is overridden to the dedicated *internal* (no external route) overlay.
    assert service._job_network("default", "prism") == "base_jobs_internal"
    assert service._job_network("none", "prism") == "base_jobs_internal"
    assert service._job_network("base_other", "prism") == "base_jobs_internal"


def test_job_network_leaves_unlocked_slug_unaffected(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(tmp_path, runner, egress_locked_slugs=_PRISM_EGRESS_LOCKED)
    # A slug NOT on the egress-lock allowlist keeps the legacy behavior:
    # "default" -> host egress (None), "none" -> internal overlay.
    assert service._job_network("default", "agent") is None
    assert service._job_network("none", "agent") == "base_jobs_internal"


def test_run_job_egress_locked_prism_pins_internal_network(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(
        tmp_path,
        runner,
        egress_locked_slugs=_PRISM_EGRESS_LOCKED,
        eval_readonly_mounts_by_slug=_PRISM_EVAL_READONLY_BY_SLUG,
    )

    # A prism eval job that REQUESTS the egress-capable default network is still
    # pinned to the internal overlay (a compromised miner has no external route).
    service.run(
        "prism",
        _prism_gpu_request(limits={"gpu_count": 1, "network": "default"}),
    )

    pairs = _pairs(runner.create_argv())
    assert ("--network", "base_jobs_internal") in pairs
    assert ("--network", "default") not in pairs


def test_run_job_prism_eval_never_mounts_heldout_volumes(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(
        tmp_path,
        runner,
        egress_locked_slugs=_PRISM_EGRESS_LOCKED,
        eval_readonly_mounts_by_slug=_PRISM_EVAL_READONLY_BY_SLUG,
    )

    service.run("prism", _prism_gpu_request())

    mounts = [
        value for flag, value in _pairs(runner.create_argv()) if flag == "--mount"
    ]
    # The SECRET held-out volumes are NEVER bind-mounted into the untrusted
    # eval/miner container (only the trusted scorer service mounts them).
    assert not any("prism_fineweb_edu_val" in m for m in mounts)
    assert not any("prism_fineweb_edu_test" in m for m in mounts)


def test_run_job_prism_eval_network_none_is_isolated(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(
        tmp_path,
        runner,
        eval_readonly_mounts_by_slug=_PRISM_EVAL_READONLY_BY_SLUG,
    )

    service.run("prism", _prism_gpu_request())

    pairs = _pairs(runner.create_argv())
    # network=none maps to the dedicated *internal* (no external route) overlay;
    # it must never fall back to the default (egress-capable) network.
    assert ("--network", "base_jobs_internal") in pairs
    assert ("--network", "default") not in pairs


def test_run_job_eval_readonly_by_slug_merges_with_socket_allowlist(
    tmp_path: Path,
) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(
        tmp_path,
        runner,
        docker_socket_slugs=frozenset({"prism"}),
        eval_readonly_mounts=(("legacy_cache", "/opt/legacy/cache"),),
        eval_readonly_mounts_by_slug={
            "prism": (("prism_fineweb_edu_train", "/data/fineweb-edu/train"),)
        },
    )

    service.run("prism", _prism_gpu_request())

    mounts = [
        value for flag, value in _pairs(runner.create_argv()) if flag == "--mount"
    ]
    # A slug present in BOTH the legacy global allowlist and the per-slug map
    # receives the union of both read-only mount sets.
    assert (
        "type=volume,source=legacy_cache,destination=/opt/legacy/cache,readonly"
        in mounts
    )
    assert (
        "type=volume,source=prism_fineweb_edu_train,"
        "destination=/data/fineweb-edu/train,readonly" in mounts
    )


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
            allowed_images=("ghcr.io/baseintelligence/",),
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
    assert "label=base.challenge=agent" in ls_call
    assert "label=base.job=job-1" in ls_call
    assert service.ledger.count("agent") == 0


def test_list_maps_services_to_frozen_container_shape(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(
        ls_rows=[
            {
                "ID": "svc-a",
                "Name": "agent-job-1-x",
                "Image": "ghcr.io/baseintelligence/challenge:1.2.3",
                "Replicas": "0/1 (1/1 completed)",
            }
        ],
        inspect_details=[
            {
                "CreatedAt": "2026-06-12T10:00:00.000000000Z",
                "Spec": {
                    "Name": "agent-job-1-x",
                    "Labels": {
                        "base.challenge": "agent",
                        "base.job": "job-1",
                        "base.task": "task-1",
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
    assert container.image == "ghcr.io/baseintelligence/challenge:1.2.3"
    assert container.status == "0/1 (1/1 completed)"
    assert container.job_id == "job-1"
    assert container.task_id == "task-1"
    assert container.created == "2026-06-12T10:00:00.000000000Z"
    assert container.labels == {
        "base.challenge": "agent",
        "base.job": "job-1",
        "base.task": "task-1",
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
                        "Image": "ghcr.io/baseintelligence/challenge:1.2.3",
                        "Replicas": "Exited (0) 2 minutes ago",
                    }
                ],
                "inspect_details": [
                    {
                        "CreatedAt": "2026-06-12T10:00:00.000000000Z",
                        "Spec": {
                            "Name": "agent-job-1-x",
                            "Labels": {
                                "base.job": "job-1",
                                "base.task": "task-1",
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
    # The job carries a mount, so its command is wrapped for cross-node mount
    # transport; the original argv is preserved as the trailing positionals.
    assert argv[-2:] == ("python", "-V")
    assert "sh" in argv
    assert response.returncode == 0
    # The GPU lease is held only for the duration of the job.
    assert service.gpu_leases.in_use == 0


def _gpu_mounts() -> list[dict[str, Any]]:
    return [
        {
            "target": "/workspace",
            "read_only": True,
            "source_type": "directory",
            "source_name": ".",
            "archive_b64": _archive_member("payload.json", b"{}"),
        },
        {
            "target": "/artifacts",
            "read_only": False,
            "source_type": "directory",
            "source_name": ".",
            "archive_b64": _archive_member("seed", b""),
        },
    ]


def test_run_job_gpu_materializes_mounts_cross_node(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(tmp_path, runner)

    service.run(
        "agent",
        _run_request(
            command=["torchrun", "/workspace/runner.py"],
            workdir="/workspace",
            limits={"gpu_count": 1},
            mounts=_gpu_mounts(),
        ),
    )

    argv = runner.create_argv()
    mounts = [value for flag, value in _pairs(argv) if flag == "--mount"]
    # Transported mounts become node-local tmpfs (writable for the eval uid),
    # NOT bind mounts of a broker-node path the GPU worker cannot see.
    assert "type=tmpfs,destination=/workspace,tmpfs-mode=1777" in mounts
    assert "type=tmpfs,destination=/artifacts,tmpfs-mode=1777" in mounts
    assert not any(
        m.startswith("type=bind,") and "destination=/workspace" in m for m in mounts
    )
    # Each mount's content rides in env-carried (chunked) archive vars.
    envs = [value for flag, value in _pairs(argv) if flag == "--env"]
    assert any(e.startswith("BASE_BROKER_MOUNT_IN_0_0=") for e in envs)
    assert any(e.startswith("BASE_BROKER_MOUNT_IN_1_0=") for e in envs)
    # Command is wrapped; only the writable mount (index 1) is drained out.
    image_index = argv.index("ghcr.io/baseintelligence/challenge:1.2.3")
    assert argv[image_index + 1 : image_index + 3] == ("sh", "-c")
    script = argv[image_index + 3]
    assert "@@BASE_BROKER_MOUNT_OUT[1]:BEGIN@@" in script
    assert "@@BASE_BROKER_MOUNT_OUT[0]:BEGIN@@" not in script
    assert argv[-2:] == ("torchrun", "/workspace/runner.py")


def test_run_job_gpu_drains_writable_mount_to_manager_disk(tmp_path: Path) -> None:
    produced = tmp_path / "produced"
    produced.mkdir()
    (produced / "prism_run_manifest.v1.json").write_text(
        "artifact-here", encoding="utf-8"
    )
    drain = (
        "@@BASE_BROKER_MOUNT_OUT[1]:BEGIN@@\n"
        f"{encode_dir_archive(produced)}\n"
        "@@BASE_BROKER_MOUNT_OUT[1]:END@@\n"
    )
    runner = FakeSwarmRunner(log_stdout="job-log\n" + drain)
    service = _broker(tmp_path, runner)

    service.run("agent", _run_request(limits={"gpu_count": 1}, mounts=_gpu_mounts()))

    retrieved = list(
        (tmp_path / "work" / "retrieved").glob("*/mount-1/prism_run_manifest.v1.json")
    )
    assert retrieved, "writable mount artifact was not round-tripped to the broker node"
    assert retrieved[0].read_text(encoding="utf-8") == "artifact-here"


def test_run_job_gpu_drain_survives_log_cap_for_large_archive(tmp_path: Path) -> None:
    # A drained checkpoint whose base64 archive far exceeds the 64_000-byte log
    # cap. It rides back in BrokerRunResponse.stdout through the REAL _cap_log
    # seam and the executor must restore it byte-for-byte: the cap may only
    # touch the human-readable remainder, never the drain sections.
    produced = tmp_path / "produced"
    produced.mkdir()
    checkpoint = os.urandom(128 * 1024)  # incompressible -> base64 well over cap
    (produced / "checkpoint.bin").write_bytes(checkpoint)
    drain = (
        "@@BASE_BROKER_MOUNT_OUT[1]:BEGIN@@\n"
        f"{encode_dir_archive(produced)}\n"
        "@@BASE_BROKER_MOUNT_OUT[1]:END@@\n"
    )
    noisy = "training-log-line\n" * 8000  # human log also exceeds the cap
    runner = FakeSwarmRunner(log_stdout=noisy + drain)
    service = _broker(tmp_path, runner)

    response = service.run(
        "agent", _run_request(limits={"gpu_count": 1}, mounts=_gpu_mounts())
    )

    archives = parse_drained_archives(response.stdout)
    assert set(archives) == {1}
    restored = tmp_path / "restored"
    extract_archive_to_dir(archives[1], restored)
    assert (restored / "checkpoint.bin").read_bytes() == checkpoint
    # The human-readable remainder stays bounded by the configured cap.
    assert len(strip_drain_sections(response.stdout).encode()) <= 64_000


def test_run_job_cpu_keeps_bind_mounts(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(log_stdout="ok\n")
    service = _broker(tmp_path, runner)

    service.run("agent", _run_request(mounts=_gpu_mounts()))

    argv = runner.create_argv()
    mounts = [value for flag, value in _pairs(argv) if flag == "--mount"]
    # CPU jobs run on the broker node, so direct bind mounts are retained and
    # the command is not wrapped.
    assert any(
        m.startswith("type=bind,") and "destination=/artifacts" in m for m in mounts
    )
    assert "type=tmpfs,destination=/artifacts,tmpfs-mode=1777" not in mounts
    envs = [value for flag, value in _pairs(argv) if flag == "--env"]
    assert not any(e.startswith("BASE_BROKER_MOUNT_IN_") for e in envs)
    assert "sh" not in argv


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
        image="ghcr.io/baseintelligence/agent:1.0.0",
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
    assert ("--constraint", "node.role==manager") in pairs
    assert ("--network", "base_challenges") in pairs
    assert (
        "--secret",
        "source=base_agent_challenge_token,target=base/challenge_token",
    ) in pairs
    assert "--privileged" not in argv
    assert "--generic-resource" not in argv
    network_create = next(
        call for call in runner.calls if call[1:3] == ("network", "create")
    )
    assert network_create == tuple(
        build_overlay_network_argv("docker", "base_challenges", internal=True)
    )
    secret_index = runner.calls.index(
        ("docker", "secret", "create", "base_agent_challenge_token", "-")
    )
    assert runner.inputs[secret_index] == "tok-secret"
    entry = ledger.get(runner.service_id)
    assert entry is not None
    assert entry.workload_class == "service"
    assert entry.timeout_seconds == 600
    assert ledger.count("agent") == 1
    assert runtime.container_id == runner.service_id
    assert runtime.container_name == "challenge-agent"


def test_combined_mode_service_renders_env_and_no_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reconciler-built combined-mode spec renders as ONE replicated service
    with the combined-mode env var set and NO trailing command (image default
    CMD runs the API + in-process worker) - no separate ``-worker`` service."""

    runner = FakeSwarmRunner(network_exists=False)
    orchestrator = SwarmChallengeOrchestrator(runner=runner, ledger=WorkloadLedger())
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: ({"status": "ok"}, {"api_version": "1.0"}),
    )
    record = ChallengeRecord(
        slug="prism",
        name="PRISM",
        image="ghcr.io/baseintelligence/prism:latest",
        version="0.1.0",
        emission_percent=Decimal("30"),
        status=ChallengeStatus.ACTIVE,
        token_hash="hash",
        token_hint="hint",
        internal_base_url="http://challenge-prism:8080",
        public_proxy_base_path="/challenges/prism",
        required_capabilities=["get_weights", "proxy_routes"],
        resources={"cpu": "2", "memory": "8g"},
        env={
            "PRISM_DOCKER_BROKER_URL": "http://base-docker-broker:8082",
            "PRISM_DOCKER_BROKER_TOKEN_FILE": "/run/secrets/base/docker_broker_token",
        },
        metadata={"combined_mode_env": "PRISM_COMBINED_MODE"},
    )

    spec = challenge_spec_from_registry(record)
    orchestrator.start_challenge(spec)

    argv = runner.create_argv()
    pairs = _pairs(argv)
    envs = [value for flag, value in pairs if flag == "--env"]
    assert ("--mode", "replicated") in pairs
    assert "PRISM_COMBINED_MODE=true" in envs
    assert "PRISM_DOCKER_BROKER_URL=http://base-docker-broker:8082" in envs
    assert (
        "PRISM_DOCKER_BROKER_TOKEN_FILE=/run/secrets/base/docker_broker_token" in envs
    )
    # Image is the LAST token: no command override, so the image default CMD runs.
    assert argv[-1] == "ghcr.io/baseintelligence/prism:latest"
    # Exactly one ``service create`` and its name is ``challenge-prism`` (no -worker).
    service_creates = [
        call for call in runner.calls if call[1:3] == ("service", "create")
    ]
    assert len(service_creates) == 1
    assert ("--name", "challenge-prism") in pairs
    assert not any(value.endswith("-worker") for _, value in pairs if _ == "--name")


def test_orchestrator_spec_placement_constraint_overrides_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeSwarmRunner(network_exists=False)
    orchestrator = SwarmChallengeOrchestrator(
        runner=runner,
        ledger=WorkloadLedger(),
        challenge_placement_constraint="node.role==worker",
    )
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: ({"status": "ok"}, {"api_version": "1.0"}),
    )
    spec = ChallengeSpec(
        slug="agent",
        image="ghcr.io/baseintelligence/agent:1.0.0",
        workload_class="service",
        placement_constraint="node.role==manager",
    )

    orchestrator.start_challenge(spec)

    pairs = _pairs(runner.create_argv())
    assert ("--constraint", "node.role==manager") in pairs
    assert ("--constraint", "node.role==worker") not in pairs


def test_orchestrator_spec_without_placement_uses_orchestrator_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeSwarmRunner(network_exists=False)
    orchestrator = SwarmChallengeOrchestrator(
        runner=runner,
        ledger=WorkloadLedger(),
        challenge_placement_constraint="node.role==worker",
    )
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: ({"status": "ok"}, {"api_version": "1.0"}),
    )
    spec = ChallengeSpec(
        slug="agent",
        image="ghcr.io/baseintelligence/agent:1.0.0",
        workload_class="service",
    )

    orchestrator.start_challenge(spec)

    pairs = _pairs(runner.create_argv())
    assert ("--constraint", "node.role==worker") in pairs


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
        image="ghcr.io/baseintelligence/agent:1.0.0",
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
        image="ghcr.io/baseintelligence/agent:1.0.0",
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


def test_orchestrator_adopts_existing_challenge_service_without_duplicate_create(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # VAL-CODE-REG-003 (m9 rollout-prep): when a `challenge-<slug>` service
    # ALREADY exists (the live-prod state the operator migrates onto),
    # start_challenge ADOPTS it — it looks the service up by its
    # `challenge-<slug>` name and never issues a second `docker service create`,
    # so the default-on m7 reconciler cannot create a duplicate.
    runner = FakeSwarmRunner(service_exists=True)
    ledger = WorkloadLedger()
    orchestrator = SwarmChallengeOrchestrator(runner=runner, ledger=ledger)
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: ({"status": "ok"}, {"api_version": "1.0"}),
    )
    spec = ChallengeSpec(
        slug="agent",
        image="ghcr.io/baseintelligence/agent:1.0.0",
        challenge_token="tok-secret",
        workload_class="service",
    )

    runtime = orchestrator.start_challenge(spec)

    # Looked the service up by its `challenge-<slug>` name and reused it.
    assert (
        "docker",
        "service",
        "inspect",
        "--format",
        "{{.ID}}",
        "challenge-agent",
    ) in runner.calls
    # No create (no duplicate) and no secret churn on the adopt path.
    assert [c for c in runner.calls if c[1:3] == ("service", "create")] == []
    assert [c for c in runner.calls if c[1:3] == ("secret", "create")] == []
    assert runtime.container_id == runner.service_id
    assert runtime.container_name == "challenge-agent"
    assert runtime.internal_base_url == "http://challenge-agent:8000"
    # Adopting an existing service does not register a new ledger workload.
    assert ledger.count("agent") == 0


def test_reconciler_adopts_existing_challenge_service_no_duplicate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # VAL-CODE-REG-003 (m9 rollout-prep): the m7 MasterChallengeReconciler driven
    # by the REAL SwarmChallengeOrchestrator adopts a pre-existing
    # `challenge-<slug>` service (idempotent) rather than creating a
    # `base-challenge-<slug>` duplicate — the end-to-end guard that going live
    # with the default-on reconciler is safe against the migrated services.
    runner = FakeSwarmRunner(service_exists=True)
    orchestrator = SwarmChallengeOrchestrator(runner=runner, ledger=WorkloadLedger())
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: ({"status": "ok"}, {"api_version": "1.0"}),
    )

    record = ChallengeRecord(
        slug="prism",
        name="Prism",
        image="ghcr.io/baseintelligence/prism:1",
        version="1",
        emission_percent=Decimal("0"),
        status=ChallengeStatus.ACTIVE,
        token_hash="h",
        token_hint="hint",
        internal_base_url="http://challenge-prism:8000",
        public_proxy_base_path="/challenges/prism",
        required_capabilities=["get_weights", "proxy_routes"],
        resources={},
        env={},
        metadata={},
    )

    class _Registry:
        def list(self, *, active_only: bool = False) -> list[ChallengeRecord]:
            return [record]

    reconciler = MasterChallengeReconciler(
        registry=_Registry(), orchestrator=orchestrator
    )

    result = asyncio.run(reconciler.reconcile_once())

    # The ACTIVE challenge is reconciled (adopted) but its existing service is
    # reused — no `docker service create` (duplicate) is issued.
    assert result.started == ["prism"]
    assert result.stopped == []
    assert [c for c in runner.calls if c[1:3] == ("service", "create")] == []
    assert (
        "docker",
        "service",
        "inspect",
        "--format",
        "{{.ID}}",
        "challenge-prism",
    ) in runner.calls


def test_service_image_reads_running_container_image() -> None:
    # The accessor the challenge-image-updater uses to converge a service on the
    # SERVICE's actually-running digest: it reads
    # {{.Spec.TaskTemplate.ContainerSpec.Image}} for the challenge-<slug> service.
    ref = "ghcr.io/baseintelligence/agent:latest@sha256:" + "a" * 64

    class _ImageRunner:
        def __init__(self) -> None:
            self.calls: list[tuple[str, ...]] = []

        def run(
            self,
            argv: Any,
            *,
            input_text: str | None = None,
            timeout_seconds: float | None = None,
        ) -> SwarmCommandResult:
            argv = tuple(argv)
            self.calls.append(argv)
            return _result(argv, out=ref + "\n")

    runner = _ImageRunner()
    orchestrator = SwarmChallengeOrchestrator(runner=runner, ledger=WorkloadLedger())

    assert orchestrator.service_image("agent") == ref
    call = runner.calls[-1]
    assert call[:4] == ("docker", "service", "inspect", "--format")
    assert "{{.Spec.TaskTemplate.ContainerSpec.Image}}" in call
    assert call[-1] == "challenge-agent"


def test_service_image_returns_none_when_service_absent() -> None:
    class _MissingRunner:
        def run(
            self,
            argv: Any,
            *,
            input_text: str | None = None,
            timeout_seconds: float | None = None,
        ) -> SwarmCommandResult:
            return _result(tuple(argv), rc=1, err="no such service")

    orchestrator = SwarmChallengeOrchestrator(
        runner=_MissingRunner(), ledger=WorkloadLedger()
    )
    assert orchestrator.service_image("agent") is None


def test_list_running_challenge_slugs_discovers_by_label() -> None:
    # VAL-CODE-REG-006: the reconciler's cross-restart self-heal reads the
    # ACTUALLY-running challenge services from the backend. The orchestrator
    # lists ``challenge-<slug>`` services by their ``base.component=challenge``
    # label and derives the slug from the service name.
    class _LsRunner:
        def __init__(self) -> None:
            self.calls: list[tuple[str, ...]] = []

        def run(
            self,
            argv: Any,
            *,
            input_text: str | None = None,
            timeout_seconds: float | None = None,
        ) -> SwarmCommandResult:
            argv = tuple(argv)
            self.calls.append(argv)
            if argv[1:3] == ("service", "ls"):
                # Includes a non-challenge service to prove the prefix guard.
                return _result(
                    argv,
                    out="challenge-prism\nchallenge-agent-challenge\n"
                    "base-master-proxy\n\n",
                )
            return _result(argv)

    runner = _LsRunner()
    orchestrator = SwarmChallengeOrchestrator(runner=runner, ledger=WorkloadLedger())

    slugs = orchestrator.list_running_challenge_slugs()

    assert slugs == frozenset({"prism", "agent-challenge"})
    ls_call = next(c for c in runner.calls if c[1:3] == ("service", "ls"))
    assert ("--filter", "label=base.component=challenge") == (ls_call[3], ls_call[4])
    assert ls_call[-2:] == ("--format", "{{.Name}}")


def test_list_running_challenge_slugs_raises_on_error() -> None:
    class _FailRunner:
        def run(
            self,
            argv: Any,
            *,
            input_text: str | None = None,
            timeout_seconds: float | None = None,
        ) -> SwarmCommandResult:
            return _result(tuple(argv), rc=1, err="daemon down")

    orchestrator = SwarmChallengeOrchestrator(
        runner=_FailRunner(), ledger=WorkloadLedger()
    )
    with pytest.raises(DockerOrchestrationError):
        orchestrator.list_running_challenge_slugs()


def test_restart_challenge_applies_record_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # restart_challenge force-rolls WITH --image <record.image> so the service
    # actually converges onto the digest-pinned record image (not merely
    # redeploying the currently-running digest).
    runner = FakeSwarmRunner(service_exists=True)
    orchestrator = SwarmChallengeOrchestrator(runner=runner, ledger=WorkloadLedger())
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: ({"status": "ok"}, {"api_version": "1.0"}),
    )
    ref = "ghcr.io/baseintelligence/agent:latest@sha256:" + "a" * 64
    spec = ChallengeSpec(
        slug="agent",
        image=ref,
        challenge_token="tok-secret",
        workload_class="service",
    )

    orchestrator.restart_challenge(spec)

    update = next(c for c in runner.calls if c[1:3] == ("service", "update"))
    assert "--force" in update
    assert "--image" in update
    assert ref in update
    assert update[-1] == "challenge-agent"


def test_build_service_create_argv_orders_image_and_command_last() -> None:
    plan = SwarmServicePlan(
        name="x",
        image="ghcr.io/baseintelligence/x:1",
        command=("run", "--flag"),
        mode="replicated-job",
    )

    argv = build_service_create_argv("docker", plan)

    assert argv[:6] == ["docker", "service", "create", "--detach", "--name", "x"]
    assert argv[-3:] == ["ghcr.io/baseintelligence/x:1", "run", "--flag"]


def test_build_service_create_argv_emits_with_registry_auth_when_set() -> None:
    plan = SwarmServicePlan(
        name="x",
        image="ghcr.io/baseintelligence/x:1",
        command=("run",),
        with_registry_auth=True,
    )

    argv = build_service_create_argv("docker", plan)

    assert "--with-registry-auth" in argv
    # Image/command MUST stay last regardless of the flag.
    assert argv[-2:] == ["ghcr.io/baseintelligence/x:1", "run"]


def test_build_service_create_argv_omits_with_registry_auth_by_default() -> None:
    # Default plans (long-lived challenge services created on the manager,
    # which is already logged in) stay byte-identical to the pre-flag builder.
    plan = SwarmServicePlan(
        name="x",
        image="ghcr.io/baseintelligence/x:1",
        command=("run",),
    )

    argv = build_service_create_argv("docker", plan)

    assert "--with-registry-auth" not in argv


def test_build_service_create_argv_emits_generic_resources_before_image() -> None:
    plan = SwarmServicePlan(
        name="x",
        image="ghcr.io/baseintelligence/x:1",
        command=("run",),
        generic_resources=("NVIDIA-GPU=2",),
    )

    argv = build_service_create_argv("docker", plan)

    pairs = _pairs(tuple(argv))
    assert ("--generic-resource", "NVIDIA-GPU=2") in pairs
    assert "--gpus" not in argv
    assert argv[-2:] == ["ghcr.io/baseintelligence/x:1", "run"]


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
        image="ghcr.io/baseintelligence/agent:1.0.0",
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
        image="ghcr.io/baseintelligence/agent:1.0.0",
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
        image="ghcr.io/baseintelligence/agent:1.0.0",
        challenge_token="fake-token-for-test",
        external_secrets=("submission_env_encryption_key",),
        workload_class="service",
    )

    orchestrator.start_challenge(spec)

    pairs = _pairs(runner.create_argv())
    assert (
        "--secret",
        "source=base_agent_challenge_challenge_token,target=base/challenge_token",
    ) in pairs
    assert (
        "--secret",
        "source=base_agent_challenge_submission_env_encryption_key,"
        "target=base/submission_env_encryption_key",
    ) in pairs
    assert (
        "--env",
        "SUBMISSION_ENV_ENCRYPTION_KEY_FILE=/run/secrets/base/"
        "submission_env_encryption_key",
    ) in pairs
    secret_creates = [
        call for call in runner.calls if call[1:3] == ("secret", "create")
    ]
    assert [call[3] for call in secret_creates] == [
        "base_agent_challenge_challenge_token"
    ]


def test_challenge_plan_mounts_shared_gateway_token_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Every reconciler-managed challenge service mounts the shared
    # base_gateway_token at /run/secrets/base_gateway_token, matching the live
    # BASE_GATEWAY_TOKEN_FILE the challenges read.
    runner = FakeSwarmRunner()
    orchestrator = SwarmChallengeOrchestrator(runner=runner, ledger=WorkloadLedger())
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: ({"status": "ok"}, {"api_version": "1.0"}),
    )
    spec = ChallengeSpec(
        slug="prism",
        image="ghcr.io/baseintelligence/prism:1.0.0",
        workload_class="service",
    )

    orchestrator.start_challenge(spec)

    pairs = _pairs(runner.create_argv())
    assert (
        "--secret",
        "source=base_gateway_token,target=base_gateway_token",
    ) in pairs
    # The shared token is a pre-created external secret: never created here.
    assert [c for c in runner.calls if c[1:3] == ("secret", "create")] == []


def test_challenge_plan_shared_secret_refs_constructor_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeSwarmRunner()
    orchestrator = SwarmChallengeOrchestrator(
        runner=runner,
        ledger=WorkloadLedger(),
        shared_secret_refs=(),
    )
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: ({"status": "ok"}, {"api_version": "1.0"}),
    )
    spec = ChallengeSpec(
        slug="prism",
        image="ghcr.io/baseintelligence/prism:1.0.0",
        workload_class="service",
    )

    orchestrator.start_challenge(spec)

    secrets = [
        value for flag, value in _pairs(runner.create_argv()) if flag == "--secret"
    ]
    assert secrets == []


def test_reconciled_record_plan_references_declared_secrets_and_gateway_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # VAL-CODE-REG-004: a spec built by challenge_spec_from_registry from a
    # prism-like record renders a Swarm plan that references base_<slug>_<name>
    # for each declared secret AND the shared base_gateway_token target, is
    # probed on the record's port, and creates NO secret (all reference-only).
    runner = FakeSwarmRunner(network_exists=False)
    orchestrator = SwarmChallengeOrchestrator(runner=runner, ledger=WorkloadLedger())
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: ({"status": "ok"}, {"api_version": "1.0"}),
    )
    record = ChallengeRecord(
        slug="prism",
        name="PRISM",
        image="ghcr.io/baseintelligence/prism:latest",
        version="0.1.0",
        emission_percent=Decimal("30"),
        status=ChallengeStatus.ACTIVE,
        token_hash="hash",
        token_hint="hint",
        internal_base_url="http://challenge-prism:8080",
        public_proxy_base_path="/challenges/prism",
        required_capabilities=["get_weights", "proxy_routes"],
        resources={"cpu": "2", "memory": "8g"},
        env={},
        secrets=[
            "challenge_token",
            "docker_broker_token",
            "submission_env_encryption_key",
        ],
        metadata={"combined_mode_env": "PRISM_COMBINED_MODE"},
    )

    spec = challenge_spec_from_registry(record)
    assert spec.port == 8080
    orchestrator.start_challenge(spec)

    pairs = _pairs(runner.create_argv())
    for name in (
        "challenge_token",
        "docker_broker_token",
        "submission_env_encryption_key",
    ):
        assert (
            "--secret",
            f"source=base_prism_{name},target=base/{name}",
        ) in pairs
    assert (
        "--secret",
        "source=base_gateway_token,target=base_gateway_token",
    ) in pairs
    # The reconciler never has the token VALUES: every per-slug secret is
    # reference-only, so NO ``docker secret create`` is issued.
    assert [c for c in runner.calls if c[1:3] == ("secret", "create")] == []


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
        image="ghcr.io/baseintelligence/agent:1.0.0",
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


def test_build_service_create_argv_emits_extra_networks_after_network() -> None:
    plan = SwarmServicePlan(
        name="svc",
        image="ghcr.io/baseintelligence/x:1",
        network="base_challenges",
        extra_networks=("base_jobs_internal",),
    )

    argv = build_service_create_argv("docker", plan)

    pairs = _pairs(tuple(argv))
    networks = [value for flag, value in pairs if flag == "--network"]
    # base network first, each extra network as its own --network after it.
    assert networks == ["base_challenges", "base_jobs_internal"]


def test_build_service_create_argv_single_network_by_default() -> None:
    plan = SwarmServicePlan(name="svc", image="img", network="base_challenges")

    argv = build_service_create_argv("docker", plan)

    networks = [value for flag, value in _pairs(tuple(argv)) if flag == "--network"]
    assert networks == ["base_challenges"]


def test_orchestrator_multihomes_job_network_slug_onto_internal_overlay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """agent-challenge's long-lived service is attached to BOTH the control
    overlay and the isolated internal eval overlay so its eval JOB (which runs on
    base_jobs_internal) can resolve it by name for log streaming."""
    runner = FakeSwarmRunner(network_exists=False)
    orchestrator = SwarmChallengeOrchestrator(
        runner=runner,
        ledger=WorkloadLedger(),
        job_network_slugs=frozenset({"agent-challenge"}),
    )
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: ({"status": "ok"}, {"api_version": "1.0"}),
    )
    spec = ChallengeSpec(
        slug="agent-challenge",
        image="ghcr.io/baseintelligence/agent:1.0.0",
        challenge_token="fake-token-for-test",
        workload_class="service",
    )

    orchestrator.start_challenge(spec)

    networks = [
        value for flag, value in _pairs(runner.create_argv()) if flag == "--network"
    ]
    assert networks == ["base_challenges", "base_jobs_internal"]
    # The internal (no-egress) eval overlay is ensured/created too.
    network_creates = [
        tuple(call) for call in runner.calls if call[1:3] == ("network", "create")
    ]
    assert (
        tuple(build_overlay_network_argv("docker", "base_jobs_internal", internal=True))
        in network_creates
    )


def test_orchestrator_single_network_for_non_job_network_slug(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A challenge NOT in job_network_slugs (e.g. prism) stays on the single
    control overlay; its eval isolation is handled by the broker pinning the JOB,
    not by multi-homing the long-lived service."""
    runner = FakeSwarmRunner(network_exists=False)
    orchestrator = SwarmChallengeOrchestrator(
        runner=runner,
        ledger=WorkloadLedger(),
        job_network_slugs=frozenset({"agent-challenge"}),
    )
    monkeypatch.setattr(
        orchestrator,
        "wait_until_ready",
        lambda spec: ({"status": "ok"}, {"api_version": "1.0"}),
    )
    spec = ChallengeSpec(
        slug="prism",
        image="ghcr.io/baseintelligence/prism:1.0.0",
        challenge_token="fake-token-for-test",
        workload_class="service",
    )

    orchestrator.start_challenge(spec)

    networks = [
        value for flag, value in _pairs(runner.create_argv()) if flag == "--network"
    ]
    assert networks == ["base_challenges"]
