from __future__ import annotations

import base64
import io
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from fastapi.testclient import TestClient

from platform_network.master.docker_broker import (
    DockerBrokerConfig,
    DockerBrokerService,
    create_docker_broker_app,
)
from platform_network.schemas.docker_broker import (
    BrokerCleanupResponse,
    BrokerLimits,
    BrokerListResponse,
)


class Registry:
    def get_broker_token(self, slug: str) -> str:
        return "tok" if slug == "agent" else ""


def _archive_dir(path: Path) -> str:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        tar.add(path, arcname=".")
    return base64.b64encode(stream.getvalue()).decode("ascii")


def _archive_member(name: str, data: bytes = b"ok") -> str:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return base64.b64encode(stream.getvalue()).decode("ascii")


def test_broker_auth_and_run_materializes_mount(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "input.txt").write_text("ok", encoding="utf-8")
    app = create_docker_broker_app(
        registry=Registry(),
        service=DockerBrokerService(
            DockerBrokerConfig(
                docker_bin="true",
                workspace_dir=tmp_path / "work",
                allowed_images=("python:",),
            )
        ),
    )
    client = TestClient(app)

    unauthorized = client.post(
        "/v1/docker/run",
        json={
            "job_id": "job-1",
            "image": "python:3.12-slim",
            "command": ["python", "-V"],
            "timeout_seconds": 10,
        },
    )
    assert unauthorized.status_code == 400

    wrong_token = client.post(
        "/v1/docker/run",
        headers={
            "authorization": "Bearer wrong",
            "x-platform-challenge-slug": "agent",
        },
        json={
            "job_id": "job-1",
            "image": "python:3.12-slim",
            "command": ["python", "-V"],
            "timeout_seconds": 10,
        },
    )
    assert wrong_token.status_code == 401

    response = client.post(
        "/v1/docker/run",
        headers={
            "authorization": "Bearer tok",
            "x-platform-challenge-slug": "agent",
        },
        json={
            "job_id": "job-1",
            "task_id": "task-1",
            "image": "python:3.12-slim",
            "command": ["python", "-V"],
            "mounts": [
                {
                    "target": "/workspace/forge",
                    "read_only": True,
                    "source_type": "directory",
                    "source_name": ".",
                    "archive_b64": _archive_dir(src),
                }
            ],
            "timeout_seconds": 10,
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["returncode"] == 0


def test_broker_rejects_disallowed_image(tmp_path: Path) -> None:
    app = create_docker_broker_app(
        registry=Registry(),
        service=DockerBrokerService(
            DockerBrokerConfig(
                docker_bin="true",
                workspace_dir=tmp_path / "work",
                allowed_images=("platformnetwork/",),
            )
        ),
    )
    response = TestClient(app).post(
        "/v1/docker/run",
        headers={
            "authorization": "Bearer tok",
            "x-platform-challenge-slug": "agent",
        },
        json={
            "job_id": "job-1",
            "image": "python:3.12-slim",
            "command": ["true"],
            "timeout_seconds": 10,
        },
    )

    assert response.status_code == 400
    assert "Docker image is not allowed" in response.text


def test_broker_rejects_unsafe_network(tmp_path: Path) -> None:
    app = create_docker_broker_app(
        registry=Registry(),
        service=DockerBrokerService(
            DockerBrokerConfig(
                docker_bin="true",
                workspace_dir=tmp_path / "work",
                allowed_images=("python:",),
            )
        ),
    )
    response = TestClient(app).post(
        "/v1/docker/run",
        headers={
            "authorization": "Bearer tok",
            "x-platform-challenge-slug": "agent",
        },
        json={
            "job_id": "job-1",
            "image": "python:3.12-slim",
            "command": ["true"],
            "limits": {"network": "host"},
            "timeout_seconds": 10,
        },
    )

    assert response.status_code == 400
    assert "Docker network" in response.text


def test_broker_forwards_hardened_limits(monkeypatch, tmp_path: Path) -> None:
    import platform_network.master.docker_broker as broker_module

    captured: dict[str, Any] = {}

    class FakeExecutor:
        def __init__(self, **kwargs: object) -> None:
            captured["executor_kwargs"] = kwargs

        def container_name(self, job_id: str, task_id: str | None = None) -> str:
            return f"agent-{job_id}-{task_id or 'job'}"

        def run(self, spec, timeout_seconds: int):
            captured["limits"] = spec.limits
            captured["timeout_seconds"] = timeout_seconds
            return SimpleNamespace(
                container_name="agent-job",
                stdout="ok",
                stderr="",
                returncode=0,
                timed_out=False,
            )

    monkeypatch.setattr(broker_module, "DockerExecutor", FakeExecutor)
    app = create_docker_broker_app(
        registry=Registry(),
        service=DockerBrokerService(
            DockerBrokerConfig(
                docker_bin="docker-test",
                workspace_dir=tmp_path / "work",
                allowed_images=("python:",),
            )
        ),
    )

    response = TestClient(app).post(
        "/v1/docker/run",
        headers={
            "authorization": "Bearer tok",
            "x-platform-challenge-slug": "agent",
        },
        json={
            "job_id": "job-1",
            "image": "python:3.12-slim",
            "command": ["python", "-V"],
            "limits": {
                "cpus": 1.25,
                "memory": "768m",
                "memory_swap": "768m",
                "pids_limit": 96,
                "read_only": True,
                "init": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges"],
            },
            "timeout_seconds": 11,
        },
    )

    assert response.status_code == 200, response.text
    limits = cast(BrokerLimits, captured["limits"])
    assert limits.cpus == 1.25
    assert limits.memory == "768m"
    assert limits.pids_limit == 96
    assert limits.read_only is True
    assert limits.init is True
    assert limits.cap_drop == ("ALL",)
    assert limits.security_opt == ("no-new-privileges",)
    assert captured["timeout_seconds"] == 11


def test_broker_rejects_weakened_hardening(tmp_path: Path) -> None:
    app = create_docker_broker_app(
        registry=Registry(),
        service=DockerBrokerService(
            DockerBrokerConfig(
                docker_bin="true",
                workspace_dir=tmp_path / "work",
                allowed_images=("python:",),
            )
        ),
    )
    response = TestClient(app).post(
        "/v1/docker/run",
        headers={
            "authorization": "Bearer tok",
            "x-platform-challenge-slug": "agent",
        },
        json={
            "job_id": "job-1",
            "image": "python:3.12-slim",
            "command": ["true"],
            "limits": {"read_only": False},
            "timeout_seconds": 10,
        },
    )

    assert response.status_code == 400
    assert "read-only root filesystem" in response.text


def test_broker_rejects_privileged_jobs(tmp_path: Path) -> None:
    app = create_docker_broker_app(
        registry=Registry(),
        service=DockerBrokerService(
            DockerBrokerConfig(
                docker_bin="true",
                workspace_dir=tmp_path / "work",
                allowed_images=("python:",),
            )
        ),
    )
    response = TestClient(app).post(
        "/v1/docker/run",
        headers={
            "authorization": "Bearer tok",
            "x-platform-challenge-slug": "agent",
        },
        json={
            "job_id": "job-1",
            "image": "python:3.12-slim",
            "command": ["true"],
            "limits": {"privileged": True},
            "timeout_seconds": 10,
        },
    )

    assert response.status_code == 403
    assert "isolated Kubernetes runtime" in response.text


def test_broker_rejects_unsafe_file_mount_source(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "input.txt").write_text("ok", encoding="utf-8")
    app = create_docker_broker_app(
        registry=Registry(),
        service=DockerBrokerService(
            DockerBrokerConfig(
                docker_bin="true",
                workspace_dir=tmp_path / "work",
                allowed_images=("python:",),
            )
        ),
    )
    response = TestClient(app).post(
        "/v1/docker/run",
        headers={
            "authorization": "Bearer tok",
            "x-platform-challenge-slug": "agent",
        },
        json={
            "job_id": "job-1",
            "image": "python:3.12-slim",
            "command": ["python", "-V"],
            "mounts": [
                {
                    "target": "/workspace/forge",
                    "source_type": "file",
                    "source_name": "/var/run/docker.sock",
                    "archive_b64": _archive_dir(src),
                }
            ],
            "timeout_seconds": 10,
        },
    )

    assert response.status_code == 400
    assert "unsafe mount source" in response.text


def test_broker_rejects_unsafe_archive_member(tmp_path: Path) -> None:
    app = create_docker_broker_app(
        registry=Registry(),
        service=DockerBrokerService(
            DockerBrokerConfig(
                docker_bin="true",
                workspace_dir=tmp_path / "work",
                allowed_images=("python:",),
            )
        ),
    )
    response = TestClient(app).post(
        "/v1/docker/run",
        headers={
            "authorization": "Bearer tok",
            "x-platform-challenge-slug": "agent",
        },
        json={
            "job_id": "job-1",
            "image": "python:3.12-slim",
            "command": ["python", "-V"],
            "mounts": [
                {
                    "target": "/workspace/forge",
                    "source_type": "directory",
                    "source_name": ".",
                    "archive_b64": _archive_member("../escape.txt"),
                }
            ],
            "timeout_seconds": 10,
        },
    )

    assert response.status_code == 400
    assert "unsafe mount archive" in response.text


def test_broker_rejects_invalid_archive_payload(tmp_path: Path) -> None:
    app = create_docker_broker_app(
        registry=Registry(),
        service=DockerBrokerService(
            DockerBrokerConfig(
                docker_bin="true",
                workspace_dir=tmp_path / "work",
                allowed_images=("python:",),
            )
        ),
    )
    response = TestClient(app).post(
        "/v1/docker/run",
        headers={
            "authorization": "Bearer tok",
            "x-platform-challenge-slug": "agent",
        },
        json={
            "job_id": "job-1",
            "image": "python:3.12-slim",
            "command": ["python", "-V"],
            "mounts": [
                {
                    "target": "/workspace/forge",
                    "source_type": "directory",
                    "source_name": ".",
                    "archive_b64": "not base64",
                }
            ],
            "timeout_seconds": 10,
        },
    )

    assert response.status_code == 400
    assert "invalid mount archive" in response.text


def test_broker_cleanup_requires_auth_and_delegates(tmp_path: Path) -> None:
    class Service(DockerBrokerService):
        def __init__(self) -> None:
            self.config = DockerBrokerConfig(workspace_dir=tmp_path / "unused")
            self.cleaned: tuple[str, str] | None = None

        def cleanup(self, challenge_slug, request):
            self.cleaned = (challenge_slug, request.job_id)
            return BrokerCleanupResponse()

    service = Service()
    app = create_docker_broker_app(registry=Registry(), service=service)
    client = TestClient(app)

    unauthorized = client.post(
        "/v1/docker/cleanup",
        headers={
            "authorization": "Bearer wrong",
            "x-platform-challenge-slug": "agent",
        },
        json={"job_id": "job-1"},
    )
    assert unauthorized.status_code == 401

    response = client.post(
        "/v1/docker/cleanup",
        headers={
            "authorization": "Bearer tok",
            "x-platform-challenge-slug": "agent",
        },
        json={"job_id": "job-1"},
    )

    assert response.status_code == 200
    assert service.cleaned == ("agent", "job-1")


def test_broker_list_is_scoped_to_authenticated_challenge(tmp_path: Path) -> None:
    class Service(DockerBrokerService):
        def __init__(self) -> None:
            self.config = DockerBrokerConfig(workspace_dir=tmp_path / "unused")

        def list_containers(self, challenge_slug, request):
            assert challenge_slug == "agent"
            assert request.job_id == "job-1"
            return BrokerListResponse(
                containers=[
                    {
                        "container_id": "abc",
                        "container_name": "agent-job",
                        "image": "python",
                        "status": "running",
                        "job_id": "job-1",
                        "labels": {"platform.challenge": "agent"},
                    }
                ]
            )

    app = create_docker_broker_app(registry=Registry(), service=Service())
    client = TestClient(app)

    unauthorized = client.post(
        "/v1/docker/list",
        headers={
            "authorization": "Bearer tok",
            "x-platform-challenge-slug": "other",
        },
        json={"job_id": "job-1"},
    )
    assert unauthorized.status_code == 401

    response = client.post(
        "/v1/docker/list",
        headers={
            "authorization": "Bearer tok",
            "x-platform-challenge-slug": "agent",
        },
        json={"job_id": "job-1"},
    )

    assert response.status_code == 200
    assert response.json()["containers"][0]["container_name"] == "agent-job"
