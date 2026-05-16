from __future__ import annotations

import base64
import io
import tarfile
from pathlib import Path

from fastapi.testclient import TestClient

from platform_network.master.docker_broker import (
    DockerBrokerConfig,
    DockerBrokerService,
    create_docker_broker_app,
)
from platform_network.schemas.docker_broker import BrokerListResponse


class Registry:
    def get_broker_token(self, slug: str) -> str:
        return "tok" if slug == "agent" else ""


def _archive_dir(path: Path) -> str:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        tar.add(path, arcname=".")
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


def test_broker_list_is_scoped_to_authenticated_challenge(tmp_path: Path) -> None:
    class Service(DockerBrokerService):
        def __init__(self) -> None:
            pass

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
