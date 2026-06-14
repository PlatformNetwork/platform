"""Task 26 offline backend parity harness (Kubernetes vs Docker Swarm).

Equivalence definition: the backends are equivalent iff (1) the broker HTTP
responses for a FIXED request sequence are byte-identical after masking the
volatile workload name, and (2) a backend-neutral workload-semantics
projection (image, command, env, identity labels, cpu/memory/gpu limits,
mounts, tmpfs, isolation, timeout) extracted from the Kubernetes manifests
and from the Swarm ``docker service create`` argv is byte-identical as
canonical JSON. Only volatile identifiers are normalized; semantic fields
(image refs, env names/values, resource limits, mount paths, secret names,
command/argv) are never masked. Run ``uv run python
tests/parity/parity_harness.py`` to regenerate ``.omo/evidence/parity/``.
"""

from __future__ import annotations

import base64
import difflib
import io
import json
import socket
import sqlite3
import subprocess
import sys
import tarfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest import mock

import httpx
from fastapi.testclient import TestClient

from platform_network.kubernetes.resources import (
    build_challenge_secret,
    build_challenge_service,
    build_challenge_workload,
)
from platform_network.master.docker_broker import create_docker_broker_app
from platform_network.master.docker_orchestrator import (
    DEFAULT_SECRET_MOUNT_DIR,
    ChallengeResources,
    ChallengeSpec,
)
from platform_network.master.kubernetes_broker import (
    KubernetesBrokerService,
    create_kubernetes_broker_app,
)
from platform_network.master.swarm_backend import (
    SwarmBrokerConfig,
    SwarmBrokerService,
    SwarmChallengeOrchestrator,
)
from platform_network.master.workload_ledger import WorkloadEntry, WorkloadLedger
from platform_network.schemas.docker_broker import BrokerRunRequest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EVIDENCE_DIR = _REPO_ROOT / ".omo" / "evidence" / "parity"
_BROKER_URL = "http://platform-broker:8082"
_AUTH_HEADERS = {
    "authorization": "Bearer tok",
    "x-platform-challenge-slug": "agent",
}
_GPU_RESOURCE_NAME = "nvidia.com/gpu"
_JOB_NETWORK = "platform_jobs_internal"

_VALUE_FLAGS = {
    "--name",
    "--mode",
    "--replicas",
    "--restart-condition",
    "--constraint",
    "--network",
    "--hostname",
    "--limit-cpu",
    "--limit-memory",
    "--limit-pids",
    "--cap-drop",
    "--ulimit",
    "--user",
    "--workdir",
    "--mount",
    "--secret",
    "--env",
    "--label",
    "--container-label",
    "--generic-resource",
}
_BOOL_FLAGS = {"--detach", "--read-only", "--init"}
_MEMORY_UNITS = {
    "gi": 1024**3,
    "mi": 1024**2,
    "ki": 1024,
    "g": 1024**3,
    "m": 1024**2,
    "k": 1024,
}

MutateArgv = Callable[[tuple[str, ...]], tuple[str, ...]]


class ParityGuardViolation(RuntimeError):
    """A forbidden side effect (network, subprocess, DB) was attempted."""


@dataclass
class GuardReport:
    installed: list[str] = field(default_factory=list)
    attempts: list[str] = field(default_factory=list)
    bittensor_importable: bool = False
    sqlalchemy_guarded: bool = False


@contextmanager
def forbidden_side_effects() -> Iterator[GuardReport]:
    """Deny every network connect, subprocess spawn, and DB engine/connect.

    Any attempt raises :class:`ParityGuardViolation` and is recorded in the
    report, so a completed scenario run PROVES zero DB writes and zero chain
    calls (chain clients cannot reach the network without a socket connect).
    """

    report = GuardReport()

    def deny(name: str) -> Callable[..., Any]:
        def _denied(*_args: Any, **_kwargs: Any) -> Any:
            report.attempts.append(name)
            raise ParityGuardViolation(f"forbidden side effect: {name}")

        return _denied

    targets: list[tuple[Any, str]] = [
        (socket.socket, "connect"),
        (socket, "create_connection"),
        (subprocess, "run"),
        (subprocess, "Popen"),
        (sqlite3, "connect"),
    ]
    try:
        import sqlalchemy
        from sqlalchemy.ext import asyncio as sqlalchemy_asyncio

        targets.append((sqlalchemy, "create_engine"))
        targets.append((sqlalchemy_asyncio, "create_async_engine"))
        report.sqlalchemy_guarded = True
    except ImportError:
        report.sqlalchemy_guarded = False
    try:
        import bittensor  # noqa: F401

        report.bittensor_importable = True
    except ImportError:
        report.bittensor_importable = False
    with ExitStack() as stack:
        for owner, attribute in targets:
            label = f"{getattr(owner, '__name__', owner)}.{attribute}"
            stack.enter_context(mock.patch.object(owner, attribute, deny(label)))
            report.installed.append(label)
        yield report


def prove_guards_active(report: GuardReport) -> list[str]:
    """Trip every guard on purpose and record that each one blocked."""

    def _connect_via_socket() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("203.0.113.1", 9))

    probes: list[tuple[str, Callable[[], Any]]] = [
        ("socket.socket.connect", _connect_via_socket),
        (
            "socket.create_connection",
            lambda: socket.create_connection(("203.0.113.1", 9)),
        ),
        ("subprocess.run", lambda: subprocess.run(["/bin/true"], check=False)),
        ("subprocess.Popen", lambda: subprocess.Popen(["/bin/true"])),
        ("sqlite3.connect", lambda: sqlite3.connect(":memory:")),
    ]
    if report.sqlalchemy_guarded:
        import sqlalchemy
        from sqlalchemy.ext import asyncio as sqlalchemy_asyncio

        probes.append(
            ("sqlalchemy.create_engine", lambda: sqlalchemy.create_engine("sqlite://"))
        )
        probes.append(
            (
                "sqlalchemy.ext.asyncio.create_async_engine",
                lambda: sqlalchemy_asyncio.create_async_engine("sqlite+aiosqlite://"),
            )
        )
    proofs: list[str] = []
    for label, probe in probes:
        try:
            probe()
        except ParityGuardViolation:
            proofs.append(f"{label}: BLOCKED")
        else:
            raise AssertionError(f"guard failed to block {label}")
    return proofs


class ParityTokenRegistry:
    def get_broker_token(self, slug: str) -> str:
        return "tok" if slug == "agent" else ""


class ParityKubernetesClient:
    """Recording fake satisfying the broker's Kubernetes client protocol."""

    def __init__(self, *, logs: str = "Python 3.12.4\n", exit_code: int = 0) -> None:
        self.logs = logs
        self.exit_code = exit_code
        self.applied: list[dict[str, Any]] = []
        self.deleted: list[tuple[Any, str | None]] = []
        self.deleted_by_label: list[tuple[str, str]] = []
        self.wait_calls: list[tuple[str, int]] = []

    def apply(self, resource: dict[str, Any]) -> dict[str, Any]:
        self.applied.append(resource)
        return resource

    def delete(self, resource: dict[str, Any] | str, name: str | None = None) -> None:
        self.deleted.append((resource, name))

    def wait_job_complete(self, name: str, *, timeout_seconds: int) -> int:
        self.wait_calls.append((name, timeout_seconds))
        return self.exit_code

    def pod_logs_for_job(self, job_name: str, *, tail_lines: int = 1000) -> str:
        return self.logs

    def delete_jobs_by_label(self, label_selector: str) -> None:
        self.deleted_by_label.append(("Job", label_selector))

    def delete_by_label(self, kind: str, label_selector: str) -> None:
        self.deleted_by_label.append((kind, label_selector))

    def list_jobs_by_label(self, label_selector: str) -> list[dict[str, Any]]:
        return []


class RecordingLedger(WorkloadLedger):
    def __init__(self) -> None:
        super().__init__()
        self.recorded: list[WorkloadEntry] = []

    def register(
        self, entry: WorkloadEntry, *, max_concurrent: int | None = None
    ) -> WorkloadEntry:
        self.recorded.append(entry)
        return super().register(entry, max_concurrent=max_concurrent)


class _MutatingRunner:
    """Self-test seam: rewrite ``service create`` argv before the fake runner.

    Injected via the harness's own wiring (never by editing shipped source);
    used to prove the diff machinery detects real semantic differences.
    """

    def __init__(self, inner: Any, mutate: MutateArgv) -> None:
        self.inner = inner
        self.mutate = mutate

    def run(
        self,
        argv: Sequence[str],
        *,
        input_text: str | None = None,
        timeout_seconds: float | None = None,
    ) -> Any:
        arguments = tuple(argv)
        if arguments[1:3] == ("service", "create"):
            arguments = self.mutate(arguments)
        return self.inner.run(
            arguments, input_text=input_text, timeout_seconds=timeout_seconds
        )


def mutate_limit_memory(argv: tuple[str, ...]) -> tuple[str, ...]:
    out = list(argv)
    index = out.index("--limit-memory")
    out[index + 1] = "8g"
    return tuple(out)


def mutate_env_value(argv: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        "PLATFORM_ENV=tampered" if token == "PLATFORM_ENV=unit" else token
        for token in argv
    )


def _fake_swarm_runner(**kwargs: Any) -> Any:
    unit_dir = str(_REPO_ROOT / "tests" / "unit")
    if unit_dir not in sys.path:
        sys.path.insert(0, unit_dir)
    from test_swarm_backend import FakeSwarmRunner

    return FakeSwarmRunner(**kwargs)


def _archive_b64(name: str = "input.txt", data: bytes = b"ok") -> str:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return base64.b64encode(stream.getvalue()).decode("ascii")


def run_normal_payload() -> dict[str, Any]:
    return {
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
                "archive_b64": _archive_b64(),
            }
        ],
        "timeout_seconds": 900,
    }


def run_gpu_payload() -> dict[str, Any]:
    payload = run_normal_payload()
    payload["job_id"] = "job-2"
    payload["limits"] = {"gpu_count": 1}
    return payload


def challenge_spec() -> ChallengeSpec:
    return ChallengeSpec(
        slug="prism",
        image="ghcr.io/platformnetwork/prism:1.2.3",
        version="1.2.3",
        challenge_token="parity-challenge-token",
        docker_broker_token="parity-broker-token",
        env={"PRISM_MODE": "eval"},
        resources=ChallengeResources(
            cpu=1.5,
            memory="2g",
            docker_max_concurrent=4,
            docker_timeout_seconds=3600,
        ),
        required_capabilities=("get_weights", "proxy_routes", "docker_executor"),
        port=8080,
        worker_command=("challenge-worker",),
        workload_class="service",
    )


def memory_bytes(value: str) -> int:
    text = value.strip().lower()
    for suffix in ("gi", "mi", "ki", "g", "m", "k"):
        if text.endswith(suffix) and text[: -len(suffix)]:
            return int(float(text[: -len(suffix)]) * _MEMORY_UNITS[suffix])
    return int(text)


def _parse_service_create(
    argv: tuple[str, ...],
) -> tuple[dict[str, list[str]], set[str], list[str]]:
    if argv[1:3] != ("service", "create"):
        raise AssertionError(f"not a service create argv: {argv[:3]}")
    flags: dict[str, list[str]] = {}
    bools: set[str] = set()
    positional: list[str] = []
    index = 3
    while index < len(argv):
        token = argv[index]
        if token in _BOOL_FLAGS:
            bools.add(token)
            index += 1
        elif token in _VALUE_FLAGS:
            flags.setdefault(token, []).append(argv[index + 1])
            index += 2
        elif token.startswith("--"):
            raise AssertionError(f"unknown service create flag: {token}")
        else:
            positional = list(argv[index:])
            break
    return flags, bools, positional


def _kv(values: Sequence[str]) -> dict[str, str]:
    pairs = {}
    for value in values:
        key, _, rest = value.partition("=")
        pairs[key] = rest
    return pairs


def _parse_csv_options(value: str) -> dict[str, Any]:
    options: dict[str, Any] = {}
    for piece in value.split(","):
        if "=" in piece:
            key, _, rest = piece.partition("=")
            options[key] = rest
        else:
            options[piece] = True
    return options


def k8s_broker_projection(client: ParityKubernetesClient) -> dict[str, Any]:
    job = next(item for item in client.applied if item["kind"] == "Job")
    policy = next(
        (item for item in client.applied if item["kind"] == "NetworkPolicy"), None
    )
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]
    security = container["securityContext"]
    volumes = {volume["name"]: volume for volume in pod["volumes"]}
    mounts: list[dict[str, Any]] = []
    tmpfs: list[dict[str, Any]] = []
    for volume_mount in container["volumeMounts"]:
        if volume_mount["name"].startswith("tmpfs-"):
            size = volumes[volume_mount["name"]]["emptyDir"].get("sizeLimit")
            tmpfs.append(
                {
                    "path": volume_mount["mountPath"],
                    "size_bytes": memory_bytes(size) if size else None,
                }
            )
        elif volume_mount["name"].startswith("mount-"):
            mounts.append(
                {
                    "target": volume_mount["mountPath"],
                    "read_only": bool(volume_mount.get("readOnly")),
                }
            )
    resources = container["resources"]
    labels = job["metadata"]["labels"]
    gpu_raw = resources["limits"].get(_GPU_RESOURCE_NAME)
    full_deny = (
        policy is not None
        and policy["spec"]["policyTypes"] == ["Ingress", "Egress"]
        and "ingress" not in policy["spec"]
        and "egress" not in policy["spec"]
    )
    return {
        "image": container["image"],
        "command": list(container["command"]),
        "workdir": container["workingDir"],
        "env": {item["name"]: item["value"] for item in container["env"]},
        "identity": {
            "challenge_slug": labels["platform.challenge.slug"],
            "job_id": labels["platform.job"],
            "task_id": labels.get("platform.task"),
        },
        "cpus": float(resources["limits"]["cpu"]),
        "memory_bytes": memory_bytes(resources["limits"]["memory"]),
        "gpu_count": int(gpu_raw) if gpu_raw is not None else None,
        "read_only_rootfs": bool(security["readOnlyRootFilesystem"]),
        "no_new_privileges": security["allowPrivilegeEscalation"] is False,
        "cap_drop": sorted(security["capabilities"]["drop"]),
        "mounts": sorted(mounts, key=lambda item: str(item["target"])),
        "tmpfs": sorted(tmpfs, key=lambda item: str(item["path"])),
        "external_network_blocked": full_deny,
        "timeout_seconds": job["spec"]["activeDeadlineSeconds"],
    }


def swarm_broker_projection(
    runner: Any, ledger: RecordingLedger, payload: dict[str, Any]
) -> dict[str, Any]:
    flags, bools, positional = _parse_service_create(runner.create_argv())
    labels = _kv(flags.get("--label", []))
    mounts: list[dict[str, Any]] = []
    tmpfs: list[dict[str, Any]] = []
    for raw in flags.get("--mount", []):
        mount = _parse_csv_options(raw)
        if mount.get("type") == "tmpfs":
            size = mount.get("tmpfs-size")
            tmpfs.append(
                {
                    "path": mount["destination"],
                    "size_bytes": memory_bytes(str(size)) if size else None,
                }
            )
        else:
            mounts.append(
                {
                    "target": mount["destination"],
                    "read_only": bool(mount.get("readonly")),
                }
            )
    gpu_count: int | None = None
    for resource in flags.get("--generic-resource", []):
        name, _, count = resource.partition("=")
        if name == "NVIDIA-GPU":
            gpu_count = int(count)
    network = flags.get("--network", [""])[0]
    internal_created = any(
        call[1:3] == ("network", "create")
        and "--internal" in call
        and call[-1] == network
        for call in runner.calls
    )
    request = BrokerRunRequest.model_validate(payload)
    job_entries = [entry for entry in ledger.recorded if entry.workload_class == "job"]
    return {
        "image": positional[0],
        "command": positional[1:],
        "workdir": flags["--workdir"][0],
        "env": _kv(flags.get("--env", [])),
        "identity": {
            "challenge_slug": labels["platform.challenge"],
            "job_id": labels["platform.job"],
            "task_id": labels.get("platform.task"),
        },
        "cpus": float(flags["--limit-cpu"][0]),
        "memory_bytes": memory_bytes(flags["--limit-memory"][0]),
        "gpu_count": gpu_count,
        "read_only_rootfs": "--read-only" in bools,
        "no_new_privileges": any(
            option.startswith("no-new-privileges")
            for option in request.limits.security_opt
        ),
        "cap_drop": sorted(flags.get("--cap-drop", [])),
        "mounts": sorted(mounts, key=lambda item: str(item["target"])),
        "tmpfs": sorted(tmpfs, key=lambda item: str(item["path"])),
        "external_network_blocked": network == _JOB_NETWORK and internal_created,
        "timeout_seconds": job_entries[0].timeout_seconds,
    }


def k8s_challenge_projection(
    secret: dict[str, Any] | None,
    service: dict[str, Any],
    workload: dict[str, Any],
) -> dict[str, Any]:
    template = workload["spec"]["template"]
    containers = {item["name"]: item for item in template["spec"]["containers"]}
    challenge = containers["challenge"]
    worker = containers.get("worker")
    labels = template["metadata"]["labels"]
    string_data = (secret or {}).get("stringData", {})
    resources = challenge["resources"]
    gpu_raw = resources["limits"].get(_GPU_RESOURCE_NAME)
    return {
        "image": challenge["image"],
        "challenge_slug": labels["platform.challenge.slug"],
        "version": labels["platform.challenge.version"],
        "worker_command": list(worker["command"]) if worker else [],
        "env": {item["name"]: item["value"] for item in challenge["env"]},
        "secret_files": {
            f"{DEFAULT_SECRET_MOUNT_DIR}/{name}": value
            for name, value in string_data.items()
        },
        "data_mounted_at_data": any(
            mount["mountPath"] == "/data" for mount in challenge["volumeMounts"]
        ),
        "data_persistent": "volumeClaimTemplates" in workload["spec"],
        "replicas": workload["spec"]["replicas"],
        "restart": "always",
        "dns_name": service["metadata"]["name"],
        "long_lived": True,
        "cpus": float(resources["limits"]["cpu"]),
        "memory_bytes": memory_bytes(resources["limits"]["memory"]),
        "gpu_count": int(gpu_raw) if gpu_raw is not None else None,
    }


def swarm_challenge_projection(runner: Any) -> dict[str, Any]:
    flags, _bools, positional = _parse_service_create(runner.create_argv())
    labels = _kv(flags.get("--label", []))
    secret_values = {
        call[3]: text
        for call, text in zip(runner.calls, runner.inputs, strict=True)
        if tuple(call[1:3]) == ("secret", "create") and text is not None
    }
    secret_files: dict[str, str] = {}
    for raw in flags.get("--secret", []):
        reference = _parse_csv_options(raw)
        secret_files[f"/run/secrets/{reference['target']}"] = secret_values[
            str(reference["source"])
        ]
    data_mounted = False
    data_persistent = False
    for raw in flags.get("--mount", []):
        mount = _parse_csv_options(raw)
        if mount["destination"] == "/data":
            data_mounted = True
            data_persistent = mount.get("type") == "volume"
    gpu_count = next(
        (
            int(resource.partition("=")[2])
            for resource in flags.get("--generic-resource", [])
        ),
        None,
    )
    return {
        "image": positional[0],
        "challenge_slug": labels["platform.challenge.slug"],
        "version": labels["platform.challenge.version"],
        "worker_command": positional[1:],
        "env": _kv(flags.get("--env", [])),
        "secret_files": secret_files,
        "data_mounted_at_data": data_mounted,
        "data_persistent": data_persistent,
        "replicas": int(flags["--replicas"][0]),
        "restart": {"any": "always", "none": "never"}[flags["--restart-condition"][0]],
        "dns_name": flags["--hostname"][0],
        "long_lived": flags["--mode"][0] == "replicated",
        "cpus": float(flags["--limit-cpu"][0]),
        "memory_bytes": memory_bytes(flags["--limit-memory"][0]),
        "gpu_count": gpu_count,
    }


def _normalize_http(response: httpx.Response) -> dict[str, Any]:
    body = response.json()
    if isinstance(body, dict) and "container_name" in body:
        body["container_name"] = "<ID>"
    return {"status": response.status_code, "body": body}


def _expect_ok(response: httpx.Response) -> httpx.Response:
    if response.status_code != 200:
        raise AssertionError(
            f"parity scenario failed: {response.status_code} {response.text}"
        )
    return response


def _k8s_broker_run(
    payload: dict[str, Any],
) -> tuple[httpx.Response, dict[str, Any]]:
    kubernetes_client = ParityKubernetesClient()
    service = KubernetesBrokerService(client=kubernetes_client)
    app = create_kubernetes_broker_app(registry=ParityTokenRegistry(), service=service)
    with TestClient(app) as client:
        response = _expect_ok(
            client.post("/v1/docker/run", json=payload, headers=_AUTH_HEADERS)
        )
    return response, k8s_broker_projection(kubernetes_client)


def _k8s_broker_cleanup() -> httpx.Response:
    service = KubernetesBrokerService(client=ParityKubernetesClient())
    app = create_kubernetes_broker_app(registry=ParityTokenRegistry(), service=service)
    with TestClient(app) as client:
        return _expect_ok(
            client.post(
                "/v1/docker/cleanup", json={"job_id": "job-1"}, headers=_AUTH_HEADERS
            )
        )


def _swarm_service(
    runner: Any, workspace: Path, mutate: MutateArgv | None
) -> tuple[SwarmBrokerService, RecordingLedger]:
    ledger = RecordingLedger()
    config = SwarmBrokerConfig(
        docker_bin="docker",
        workspace_dir=workspace,
        allowed_images=("ghcr.io/platformnetwork/",),
    )
    effective = _MutatingRunner(runner, mutate) if mutate else runner
    return SwarmBrokerService(config, runner=effective, ledger=ledger), ledger


def _swarm_broker_run(
    payload: dict[str, Any], mutate: MutateArgv | None = None
) -> tuple[httpx.Response, dict[str, Any]]:
    runner = _fake_swarm_runner(log_stdout="Python 3.12.4\n", network_exists=False)
    with TemporaryDirectory() as workspace:
        service, ledger = _swarm_service(runner, Path(workspace) / "work", mutate)
        app = create_docker_broker_app(registry=ParityTokenRegistry(), service=service)
        with TestClient(app) as client:
            response = _expect_ok(
                client.post("/v1/docker/run", json=payload, headers=_AUTH_HEADERS)
            )
    return response, swarm_broker_projection(runner, ledger, payload)


def _swarm_broker_cleanup() -> httpx.Response:
    runner = _fake_swarm_runner()
    with TemporaryDirectory() as workspace:
        service, _ledger = _swarm_service(runner, Path(workspace) / "work", None)
        app = create_docker_broker_app(registry=ParityTokenRegistry(), service=service)
        with TestClient(app) as client:
            return _expect_ok(
                client.post(
                    "/v1/docker/cleanup",
                    json={"job_id": "job-1"},
                    headers=_AUTH_HEADERS,
                )
            )


def _k8s_challenge() -> dict[str, Any]:
    spec = challenge_spec()
    secret = build_challenge_secret(spec, namespace="platform")
    service = build_challenge_service(spec, namespace="platform")
    workload = build_challenge_workload(
        spec,
        namespace="platform",
        mode="statefulset",
        docker_broker_url=_BROKER_URL,
        managed_postgres=False,
    )
    return k8s_challenge_projection(secret, service, workload)


def _swarm_challenge(mutate: MutateArgv | None = None) -> dict[str, Any]:
    runner = _fake_swarm_runner(network_exists=True, service_exists=False)
    effective = _MutatingRunner(runner, mutate) if mutate else runner
    orchestrator = SwarmChallengeOrchestrator(
        runner=effective,
        docker_broker_url=_BROKER_URL,
        ledger=WorkloadLedger(),
    )
    ready = ({"status": "ok"}, {"api_version": "1.0"})
    with mock.patch.object(
        SwarmChallengeOrchestrator, "wait_until_ready", return_value=ready
    ):
        orchestrator.start_challenge(challenge_spec())
    return swarm_challenge_projection(runner)


def build_documents(
    mutate_create_argv: MutateArgv | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    normal_payload = run_normal_payload()
    gpu_payload = run_gpu_payload()
    k8s_normal = _k8s_broker_run(normal_payload)
    k8s_gpu = _k8s_broker_run(gpu_payload)
    k8s_document = {
        "broker_http": {
            "run_normal": _normalize_http(k8s_normal[0]),
            "run_gpu": _normalize_http(k8s_gpu[0]),
            "cleanup": _normalize_http(_k8s_broker_cleanup()),
        },
        "broker_workload": {
            "run_normal": k8s_normal[1],
            "run_gpu": k8s_gpu[1],
        },
        "challenge_workload": _k8s_challenge(),
    }
    swarm_normal = _swarm_broker_run(normal_payload, mutate_create_argv)
    swarm_gpu = _swarm_broker_run(gpu_payload, mutate_create_argv)
    swarm_document = {
        "broker_http": {
            "run_normal": _normalize_http(swarm_normal[0]),
            "run_gpu": _normalize_http(swarm_gpu[0]),
            "cleanup": _normalize_http(_swarm_broker_cleanup()),
        },
        "broker_workload": {
            "run_normal": swarm_normal[1],
            "run_gpu": swarm_gpu[1],
        },
        "challenge_workload": _swarm_challenge(mutate_create_argv),
    }
    return k8s_document, swarm_document


def canonical_json(document: dict[str, Any]) -> str:
    return json.dumps(document, sort_keys=True, indent=2) + "\n"


def diff_documents(
    k8s_document: dict[str, Any], swarm_document: dict[str, Any]
) -> list[str]:
    return list(
        difflib.unified_diff(
            canonical_json(k8s_document).splitlines(),
            canonical_json(swarm_document).splitlines(),
            fromfile="k8s_normalized.json",
            tofile="docker_normalized.json",
            lineterm="",
        )
    )


@dataclass
class ParityResult:
    k8s_document: dict[str, Any]
    swarm_document: dict[str, Any]
    diff_lines: list[str]
    guard_proofs: list[str]
    scenario_attempts: int
    bittensor_importable: bool
    sqlalchemy_guarded: bool


def run_parity() -> ParityResult:
    with forbidden_side_effects() as report:
        proofs = prove_guards_active(report)
        baseline = len(report.attempts)
        k8s_document, swarm_document = build_documents()
        scenario_attempts = len(report.attempts) - baseline
    return ParityResult(
        k8s_document=k8s_document,
        swarm_document=swarm_document,
        diff_lines=diff_documents(k8s_document, swarm_document),
        guard_proofs=proofs,
        scenario_attempts=scenario_attempts,
        bittensor_importable=report.bittensor_importable,
        sqlalchemy_guarded=report.sqlalchemy_guarded,
    )


def run_selftest() -> tuple[str, bool]:
    sections = ["# Parity harness self-test (mutation sensitivity)", ""]
    passed = True
    base_k8s, _base_swarm = build_documents()
    mutations: list[tuple[str, MutateArgv]] = [
        ("--limit-memory 4g -> 8g", mutate_limit_memory),
        ("env PLATFORM_ENV=unit -> tampered", mutate_env_value),
    ]
    for label, mutate in mutations:
        _, mutated_swarm = build_documents(mutate_create_argv=mutate)
        diff = diff_documents(base_k8s, mutated_swarm)
        ok = bool(diff)
        passed = passed and ok
        sections.append(f"## Mutation: {label}")
        sections.append(
            f"diff lines: {len(diff)} (expected: non-empty) -> "
            f"{'DETECTED' if ok else 'MISSED'}"
        )
        sections.extend(diff[:24])
        sections.append("")
    _, clean_swarm = build_documents()
    clean_diff = diff_documents(base_k8s, clean_swarm)
    clean_ok = not clean_diff
    passed = passed and clean_ok
    sections.append("## Unmutated rerun")
    sections.append(
        f"diff lines: {len(clean_diff)} (expected: 0) -> "
        f"{'CLEAN' if clean_ok else 'UNEXPECTED DIFF'}"
    )
    sections.append("")
    sections.append(f"SELF-TEST VERDICT: {'PASS' if passed else 'FAIL'}")
    return "\n".join(sections) + "\n", passed


_EQUIVALENCE_TEXT = """\
## Equivalence definition
Backends are equivalent iff (1) broker HTTP responses for the fixed request
sequence (run normal, run gpu, cleanup) are byte-identical after masking the
volatile workload name, and (2) the backend-neutral workload-semantics
projection extracted from Kubernetes manifests vs Swarm `docker service
create` argv is byte-identical as canonical sorted-keys JSON.

## Normalized (volatile-only) fields
- HTTP `container_name` -> `<ID>` (k8s job name embeds a random run id;
  Swarm service name embeds a uuid suffix).
- Workload object names are excluded from projections; identity is compared
  via the platform.job / platform.task / challenge-slug labels instead
  (backend-native label keys: k8s `platform.challenge.slug`, Swarm
  `platform.challenge` for broker jobs).
- Memory quantities compared as canonical bytes (docker `4g` == k8s `4Gi`,
  per the platform's own `_memory_quantity` binary-suffix mapping).
- Nothing else is normalized: image refs, env names/values, command/argv,
  resource limits, mount paths, tmpfs sizes, secret names/paths/values,
  timeouts, capability drops are compared verbatim.

## Excluded fields (documented, NOT silently normalized)
- pids_limit / memory_swap / ulimits / init: no Kubernetes PodSpec
  equivalent (k8s validates/annotates them); docker enforces the stricter
  limit, which is the safe direction.
- Custom request.labels propagation: k8s emits only platform.* labels.
- /v1/docker/list status vocabulary: backend-native strings (k8s job phase
  vs Swarm replicas text), already non-portable vs legacy docker.
- docker_max_concurrent quota: docker-side WorkloadLedger (Task 14); k8s
  delegates to cluster quota/admission.
- Challenge-workload hardening block (read_only/init/tmpfs/security_opt/
  pids_limit): the k8s challenge template ignores ChallengeResources
  hardening by design; docker keeps the stricter legacy hardening.
  Matching k8s would LOOSEN security, so the difference is kept.
- Service port materialization: k8s Service port vs Swarm overlay DNS
  (no published port); connectivity is equivalent via the shared
  `challenge-<slug>` DNS name, which IS compared.
- Probe/secret/mount mechanisms (readiness probes, init-container archive
  extraction vs broker-side extraction, Secret volume vs docker secret):
  mechanism-specific; their semantic outcomes (paths, values, read-only)
  ARE compared.
- no_new_privileges on docker side is a documented derivation: the request
  is rejected by `_hardened_limits` unless security_opt contains
  no-new-privileges, and the flag is enforced daemon-wide (Task 8); k8s
  side reads allowPrivilegeEscalation=false directly.
- external_network_blocked: k8s full deny-all NetworkPolicy vs Swarm
  internal overlay. Intra-overlay job-to-job reachability remains a Task 9
  accepted approximation (see divergences).

## Documented real divergences (NOT hidden by the diff)
1. k8s broker jobs force runAsUser/runAsGroup 1000; docker honors the
   image/request user (legacy docker behavior). Security-relevant; revisit
   userns-remap at Task 28.
2. image_pull_policy is honored by the k8s broker and the legacy docker-run
   executor, but ignored by the Swarm path (`docker service create` has no
   per-job pull-policy flag; Swarm pulls on create). With digest-pinned
   production images the behaviors converge.
3. Default broker URL host differs (`platform-broker` vs
   `platform-docker-broker`) — Task 23 confirmed-known; the harness passes
   one explicit URL to both backends.
4. Worker topology: k8s runs the API container plus a `worker` sidecar;
   Swarm replaces the single container entrypoint with worker_command
   (Task 12 confirmed-known). An agent-challenge service-class workload
   with worker_command would lose its API endpoint on docker — flagged for
   Task 27/28 cutover review. worker_command VALUES are compared.
5. Secret names containing dashes mount at different paths (k8s uses the
   raw name as the file name; Swarm underscores it). The fixed spec uses
   underscore-only names, matching every shipped secret name.
6. FIXED in Task 26: Swarm broker jobs previously dropped limits.tmpfs
   (k8s emits Memory emptyDirs, legacy docker-run emits --tmpfs); the Swarm
   run path now emits equivalent tmpfs mounts.
7. Intra-overlay job-to-job traffic is possible on the Swarm internal
   overlay, while the k8s NetworkPolicy denies ALL traffic (Task 9
   accepted approximation; external egress is blocked on both).
"""


def write_evidence() -> int:
    _EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    result = run_parity()
    selftest_text, selftest_passed = run_selftest()
    (_EVIDENCE_DIR / "k8s_normalized.json").write_text(
        canonical_json(result.k8s_document)
    )
    (_EVIDENCE_DIR / "docker_normalized.json").write_text(
        canonical_json(result.swarm_document)
    )
    parity_ok = not result.diff_lines and result.scenario_attempts == 0
    verdict = "PASS" if parity_ok and selftest_passed else "FAIL"
    guard_lines = "\n".join(f"- {proof}" for proof in result.guard_proofs)
    diff_body = (
        "\n".join(result.diff_lines) if result.diff_lines else "(no differences)"
    )
    diff_text = (
        f"# Backend parity evidence (Task 26)\n\nVERDICT: {verdict}\n\n"
        f"{_EQUIVALENCE_TEXT}\n"
        "## Guard evidence (offline proof)\n"
        "Guards active for the entire scenario run; each was tripped on\n"
        "purpose first to prove it blocks:\n"
        f"{guard_lines}\n"
        f"- forbidden side-effect attempts during scenarios: "
        f"{result.scenario_attempts} (any attempt raises and aborts the run)\n"
        f"- sqlalchemy engine creation guarded: {result.sqlalchemy_guarded}\n"
        f"- bittensor importable in this environment: "
        f"{result.bittensor_importable} (all socket connects denied either "
        "way, so chain calls are impossible)\n\n"
        "## Unified diff (k8s_normalized.json vs docker_normalized.json)\n"
        f"{diff_body}\n"
    )
    (_EVIDENCE_DIR / "diff.txt").write_text(diff_text)
    (_EVIDENCE_DIR / "selftest.txt").write_text(selftest_text)
    print(f"parity verdict: {verdict}")
    print(f"diff lines: {len(result.diff_lines)}")
    print(f"evidence written to {_EVIDENCE_DIR}")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(write_evidence())
