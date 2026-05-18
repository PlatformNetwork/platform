from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from fastapi.testclient import TestClient

from platform_network.master.kubernetes_broker import (
    KubernetesBrokerRouterService,
    KubernetesBrokerService,
    create_kubernetes_broker_app,
)
from platform_network.schemas.docker_broker import (
    BrokerCleanupRequest,
    BrokerRunRequest,
)


class Registry:
    def get_broker_token(self, slug: str) -> str:
        return "tok" if slug == "agent" else ""


class FakeBrokerClient:
    def __init__(self, *, exit_code: int = 0, logs: str = "ok") -> None:
        self.exit_code = exit_code
        self.logs = logs
        self.applied: list[dict[str, Any]] = []
        self.deleted: list[tuple[str, str | None]] = []
        self.deleted_labels: list[str] = []

    def apply(self, resource: dict[str, Any]) -> dict[str, Any]:
        self.applied.append(resource)
        return resource

    def delete(self, resource: dict[str, Any] | str, name: str | None = None) -> None:
        kind = resource if isinstance(resource, str) else resource["kind"]
        self.deleted.append((kind, name))

    def wait_job_complete(self, name: str, *, timeout_seconds: int) -> int:
        assert name == self._job()["metadata"]["name"]
        assert timeout_seconds == 10
        return self.exit_code

    def pod_logs_for_job(self, job_name: str, *, tail_lines: int = 1000) -> str:
        assert job_name == self._job()["metadata"]["name"]
        return self.logs

    def delete_jobs_by_label(self, label_selector: str) -> None:
        self.deleted_labels.append(label_selector)

    def delete_by_label(self, kind: str, label_selector: str) -> None:
        self.deleted_labels.append(f"{kind}:{label_selector}")

    def list_jobs_by_label(self, label_selector: str) -> list[dict[str, Any]]:
        return []

    def _job(self) -> dict[str, Any]:
        return next(resource for resource in self.applied if resource["kind"] == "Job")


def test_kubernetes_broker_run_success_and_failure_logs() -> None:
    client = FakeBrokerClient(logs="stdout")
    service = KubernetesBrokerService(client=client, service_account_name="platform")

    response = service.run(
        "agent",
        _run_payload(),
    )

    assert response.returncode == 0
    assert response.stdout == "stdout"
    assert response.stderr == ""
    assert client.applied[0]["kind"] == "NetworkPolicy"
    assert client.applied[1]["kind"] == "Job"
    assert (
        client.applied[1]["spec"]["template"]["spec"]["serviceAccountName"]
        == "platform"
    )

    failed = KubernetesBrokerService(
        client=FakeBrokerClient(exit_code=1, logs="stderr")
    ).run("agent", _run_payload())
    assert failed.stdout == ""
    assert failed.stderr == "stderr"
    assert failed.returncode == 1


def test_kubernetes_broker_app_auth_and_mount_rejection() -> None:
    app = create_kubernetes_broker_app(
        registry=Registry(),
        service=KubernetesBrokerService(client=FakeBrokerClient()),
    )
    http = TestClient(app)

    missing_slug = http.post("/v1/docker/run", json=_run_json())
    assert missing_slug.status_code == 400

    unauthorized = http.post(
        "/v1/docker/run",
        headers={"authorization": "Bearer tok", "x-platform-challenge-slug": "other"},
        json=_run_json(),
    )
    assert unauthorized.status_code == 401

    rejected_mount = http.post(
        "/v1/docker/run",
        headers={"authorization": "Bearer tok", "x-platform-challenge-slug": "agent"},
        json=_run_json()
        | {"mounts": [{"target": "/x", "archive_b64": "YXJjaGl2ZQ=="}]},
    )
    assert rejected_mount.status_code == 400
    assert "invalid mount archive" in rejected_mount.text

    rejected_image = http.post(
        "/v1/docker/run",
        headers={"authorization": "Bearer tok", "x-platform-challenge-slug": "agent"},
        json=_run_json() | {"image": "docker.io/library/python:3.12"},
    )
    assert rejected_image.status_code == 400
    assert "Docker image is not allowed" in rejected_image.text


def test_kubernetes_broker_cleanup_deletes_job() -> None:
    fake = FakeBrokerClient()
    service = KubernetesBrokerService(client=fake)

    response = service.cleanup("agent", BrokerCleanupRequest(job_id="job-1"))

    assert response.status == "ok"
    assert fake.deleted == [("Job", "broker-agent-job-1")]
    assert fake.deleted_labels == [
        "platform.challenge.slug=agent,platform.job=job-1",
        "NetworkPolicy:platform.challenge.slug=agent,platform.job=job-1",
        "Secret:platform.challenge.slug=agent,platform.job=job-1",
    ]


def test_kubernetes_broker_router_uses_explicit_and_gpu_targets() -> None:
    default = StubBrokerService("default")
    gpu = StubBrokerService("gpu-a")
    registry = SimpleNamespace(
        get=lambda slug: SimpleNamespace(
            resources={
                "explicit": {"gpu_server": "gpu-a", "gpu_count": "1"},
                "automatic": {"gpu_count": "1"},
                "local": {},
            }[slug]
        )
    )
    router = KubernetesBrokerRouterService(
        default_service=default,
        target_services={"gpu-a": gpu},
        target_capacities={"gpu-a": 2},
        challenge_registry=registry,
    )

    assert router.run("explicit", _run_payload()).container_name == "gpu-a"
    assert router.run("automatic", _run_payload()).container_name == "gpu-a"
    assert router.run("local", _run_payload()).container_name == "default"


class StubBrokerService:
    def __init__(self, name: str) -> None:
        self.name = name

    def run(self, challenge_slug: str, request: BrokerRunRequest):
        return type(
            "Response",
            (),
            {
                "container_name": self.name,
                "stdout": "",
                "stderr": "",
                "returncode": 0,
                "timed_out": False,
            },
        )()

    def cleanup(self, challenge_slug: str, request: BrokerCleanupRequest):
        return type("Response", (), {"status": "ok"})()

    def list_containers(self, challenge_slug: str, request):
        return type("Response", (), {"containers": []})()


def _run_payload() -> BrokerRunRequest:
    return BrokerRunRequest.model_validate(_run_json())


def _run_json() -> dict[str, object]:
    return {
        "job_id": "job-1",
        "image": "ghcr.io/platformnetwork/worker:1",
        "command": ["python", "-V"],
        "timeout_seconds": 10,
    }
