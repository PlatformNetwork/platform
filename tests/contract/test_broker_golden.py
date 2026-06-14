"""Contract-freeze golden tests for the Docker broker HTTP API.

These tests pin the CURRENT request/response contract of the broker endpoints
(`/v1/docker/run`, `/v1/docker/cleanup`, `/v1/docker/list`) as byte-normalized
golden fixtures under ``tests/contract/golden/``. They are the compatibility
boundary for the k8s -> Docker Swarm migration: they must stay green,
unchanged, through every later migration task.

Normalization rules:
- JSON keys are sorted and the document is serialized with a fixed format,
  so comparisons are byte-stable.
- Values of volatile fields (container ids/names, timestamps, mount archive
  payloads) are replaced with stable placeholders such as ``"<ID>"``.
- Field NAMES, nesting, and value types are never normalized away: any added,
  removed, renamed, or retyped field changes the canonical bytes and fails.

To regenerate fixtures after an INTENTIONAL contract change (this should not
happen during the migration), run:

    PLATFORM_UPDATE_GOLDEN=1 uv run pytest tests/contract/test_broker_golden.py
"""

from __future__ import annotations

import base64
import io
import json
import os
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

import platform_network.master.docker_broker as broker_module
from platform_network.master.docker_broker import (
    DockerBrokerConfig,
    DockerBrokerService,
    create_docker_broker_app,
)
from platform_network.schemas.docker_broker import (
    BrokerCleanupRequest,
    BrokerCleanupResponse,
    BrokerContainerInfo,
    BrokerLimits,
    BrokerListRequest,
    BrokerListResponse,
    BrokerMount,
    BrokerRunRequest,
    BrokerRunResponse,
)

GOLDEN_DIR = Path(__file__).parent / "golden"

AUTH_HEADERS = {
    "authorization": "Bearer contract-token",
    "x-platform-challenge-slug": "agent",
}

# Volatile value placeholders. Only the VALUES of these keys are replaced;
# the keys themselves remain part of the frozen shape.
_VOLATILE_KEYS: dict[str, str] = {
    "container_id": "<ID>",
    "container_name": "<ID>",
    "created": "<TS>",
    "archive_b64": "<B64>",
}


class _Registry:
    """Minimal broker token registry matching the BrokerTokenRegistry protocol."""

    def get_broker_token(self, slug: str) -> str:
        return "contract-token" if slug == "agent" else ""


class _FakeExecutor:
    """Deterministic stand-in for DockerExecutor (no dockerd required).

    Returns values shaped like real Docker output, including randomized-looking
    suffixes, so the normalization layer is exercised the same way it would be
    against a live backend.
    """

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs

    def container_name(self, job_id: str, task_id: str | None = None) -> str:
        return f"platform-agent-{job_id}-{task_id or 'job'}-a1b2c3d4"

    def run(self, spec: Any, timeout_seconds: int) -> SimpleNamespace:
        return SimpleNamespace(
            container_name=spec.name,
            stdout="Python 3.12.4\n",
            stderr="",
            returncode=0,
            timed_out=False,
        )

    def cleanup_job(self, job_id: str) -> None:
        return None

    def list_containers(self, job_id: str | None = None) -> list[SimpleNamespace]:
        return [
            SimpleNamespace(
                container_id="f1e2d3c4b5a697887766554433221100",
                container_name="platform-agent-job-1-task-1-a1b2c3d4",
                image="ghcr.io/platformnetwork/challenge:1.2.3",
                status="Exited (0) 2 minutes ago",
                job_id=job_id or "job-1",
                task_id="task-1",
                created="2026-06-12 10:00:00 +0000 UTC",
                labels={
                    "platform.job": job_id or "job-1",
                    "platform.task": "task-1",
                    "com.docker.internal": "must-be-filtered-out",
                },
            )
        ]


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> TestClient:
    monkeypatch.setattr(broker_module, "DockerExecutor", _FakeExecutor)
    app = create_docker_broker_app(
        registry=_Registry(),
        service=DockerBrokerService(
            DockerBrokerConfig(
                docker_bin="docker-contract-test",
                workspace_dir=tmp_path / "work",
                allowed_images=("ghcr.io/platformnetwork/",),
            )
        ),
    )
    return TestClient(app)


def _archive_dir_b64() -> str:
    """Deterministic-content (but volatile-bytes) gzip tar of one small file."""
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        info = tarfile.TarInfo("input.txt")
        payload = b"contract"
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return base64.b64encode(stream.getvalue()).decode("ascii")


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
    text = json.dumps(_normalize(record), sort_keys=True, indent=2)
    return (text + "\n").encode("utf-8")


def _assert_matches_golden(name: str, record: dict[str, Any]) -> None:
    actual = _canonical_bytes(record)
    golden_path = GOLDEN_DIR / f"{name}.json"
    if os.environ.get("PLATFORM_UPDATE_GOLDEN") == "1":
        GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        golden_path.write_bytes(actual)
    if not golden_path.exists():
        pytest.fail(
            f"missing golden fixture {golden_path}; regenerate with "
            "PLATFORM_UPDATE_GOLDEN=1 only for intentional contract changes"
        )
    expected = golden_path.read_bytes()
    assert actual == expected, (
        f"broker contract drift detected for {name!r}: normalized bytes differ "
        f"from {golden_path}. The broker HTTP contract is FROZEN for the "
        "k8s->Swarm migration; shapes must not change."
    )


def _exchange(
    client: TestClient, endpoint: str, payload: dict[str, Any]
) -> dict[str, Any]:
    response = client.post(endpoint, headers=AUTH_HEADERS, json=payload)
    return {
        "endpoint": endpoint,
        "request": payload,
        "status_code": response.status_code,
        "response": response.json(),
    }


def _run_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "job_id": "job-1",
        "task_id": "task-1",
        "image": "ghcr.io/platformnetwork/challenge:1.2.3",
        "image_pull_policy": "IfNotPresent",
        "command": ["python", "-V"],
        "workdir": "/workspace",
        "env": {"PLATFORM_ENV": "contract"},
        "labels": {"platform.challenge": "agent"},
        "limits": {
            "cpus": 2.0,
            "memory": "4g",
            "memory_swap": "4g",
            "pids_limit": 512,
            "gpu_count": None,
            "network": "none",
            "read_only": True,
            "user": None,
            "tmpfs": ["/tmp:rw,noexec,nosuid,size=512m"],
            "ulimits": ["nofile=1024:1024"],
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges"],
            "init": True,
            "privileged": False,
        },
        "mounts": [
            {
                "target": "/workspace/forge",
                "read_only": True,
                "source_type": "directory",
                "source_name": ".",
                "archive_b64": _archive_dir_b64(),
            }
        ],
        "timeout_seconds": 900,
    }
    limits_overrides = overrides.pop("limits", None)
    payload.update(overrides)
    if limits_overrides:
        payload["limits"] = {**payload["limits"], **limits_overrides}
    return payload


def test_golden_run_normal(client: TestClient) -> None:
    record = _exchange(client, "/v1/docker/run", _run_payload())
    assert record["status_code"] == 200
    _assert_matches_golden("run_normal", record)


def test_golden_run_gpu(client: TestClient) -> None:
    record = _exchange(
        client,
        "/v1/docker/run",
        _run_payload(job_id="job-gpu", limits={"gpu_count": 1}),
    )
    assert record["status_code"] == 200
    _assert_matches_golden("run_gpu", record)


def test_golden_run_privileged_refusal(client: TestClient) -> None:
    # Current behavior: privileged broker jobs are refused with 403.
    # Task 13 may change the BEHAVIOR later, but the request/response SHAPE
    # captured here must remain identical.
    record = _exchange(
        client,
        "/v1/docker/run",
        _run_payload(job_id="job-priv", limits={"privileged": True}),
    )
    assert record["status_code"] == 403
    _assert_matches_golden("run_privileged", record)


def test_golden_cleanup(client: TestClient) -> None:
    record = _exchange(client, "/v1/docker/cleanup", {"job_id": "job-1"})
    assert record["status_code"] == 200
    _assert_matches_golden("cleanup", record)


def test_golden_list(client: TestClient) -> None:
    record = _exchange(client, "/v1/docker/list", {"job_id": "job-1"})
    assert record["status_code"] == 200
    _assert_matches_golden("list", record)


def test_golden_model_schemas() -> None:
    """Freeze the pydantic JSON Schemas of every broker request/response model.

    This pins the exact field set, types, defaults, and required lists for
    both directions of the contract: added, removed, renamed, or retyped
    fields all change the schema bytes and fail this test.
    """
    models = (
        BrokerMount,
        BrokerLimits,
        BrokerRunRequest,
        BrokerRunResponse,
        BrokerContainerInfo,
        BrokerListRequest,
        BrokerListResponse,
        BrokerCleanupRequest,
        BrokerCleanupResponse,
    )
    record: dict[str, Any] = {
        model.__name__: model.model_json_schema() for model in models
    }
    _assert_matches_golden("model_schemas", record)


def test_request_schemas_accept_minimal_payloads() -> None:
    """Request-side acceptance: minimal valid payloads must keep validating."""
    run = BrokerRunRequest.model_validate(
        {"job_id": "j", "image": "ghcr.io/platformnetwork/x", "command": ["true"]}
    )
    assert run.timeout_seconds == 900
    assert run.limits == BrokerLimits()
    assert BrokerCleanupRequest.model_validate({"job_id": "j"}).job_id == "j"
    assert BrokerListRequest.model_validate({}).job_id is None
