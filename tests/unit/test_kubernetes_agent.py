from __future__ import annotations

from typing import cast

from fastapi.testclient import TestClient

from platform_network.kubernetes.agent import create_kubernetes_agent_app
from platform_network.master.docker_orchestrator import ChallengeRuntime
from platform_network.master.kubernetes_orchestrator import KubernetesOrchestrator
from platform_network.schemas.docker_broker import (
    BrokerCleanupResponse,
    BrokerListResponse,
    BrokerRunResponse,
)


def test_kubernetes_agent_auth_runtime_and_broker_routes() -> None:
    orchestrator = FakeOrchestrator()
    broker = FakeBrokerService()
    client = TestClient(
        create_kubernetes_agent_app(
            token_provider=lambda: "agent-token",
            orchestrator=cast(KubernetesOrchestrator, orchestrator),
            broker_service=broker,  # type: ignore[arg-type]
        )
    )

    headers = {"Authorization": "Bearer agent-token"}
    assert client.get("/health", headers=headers).json() == {"status": "ok"}

    start = client.post(
        "/v1/challenges/start",
        headers=headers,
        json={"slug": "demo", "image": "ghcr.io/org/demo:1", "recreate": True},
    )
    assert start.status_code == 200
    assert start.json()["container_name"] == "challenge-demo"
    assert orchestrator.recreate is True
    status = client.get("/v1/challenges/demo/status", headers=headers)
    assert status.status_code == 200
    assert status.json()["slug"] == "demo"

    broker_run = client.post(
        "/v1/broker/demo/run",
        headers=headers,
        json={
            "job_id": "job-1",
            "image": "ghcr.io/platformnetwork/worker:1",
            "command": ["true"],
        },
    )
    assert broker_run.status_code == 200
    assert broker_run.json()["container_name"] == "job-demo"
    assert broker.calls[-1] == ("run", "demo", "job-1")

    missing_auth = client.post(
        "/v1/broker/demo/cleanup",
        json={"job_id": "job-1"},
    )
    assert missing_auth.status_code == 401

    cleanup = client.post(
        "/v1/broker/demo/cleanup",
        headers=headers,
        json={"job_id": "job-1"},
    )
    assert cleanup.status_code == 200
    assert broker.calls[-1] == ("cleanup", "demo", "job-1")

    listed = client.post(
        "/v1/broker/demo/list",
        headers=headers,
        json={"job_id": "job-1"},
    )
    assert listed.status_code == 200
    assert listed.json() == {"containers": []}
    assert broker.calls[-1] == ("list", "demo", "job-1")


class FakeOrchestrator:
    def __init__(self) -> None:
        self.recreate = False
        self._runtime: dict[str, ChallengeRuntime] = {}
        self.request_timeout_seconds = 5.0

    @property
    def runtime(self):
        return dict(self._runtime)

    def pull_image(self, image: str):
        return {"image": image}

    def start_challenge(self, spec, *, recreate: bool = False):
        self.recreate = recreate
        runtime = _runtime(spec.slug, spec.image)
        self._runtime[spec.slug] = runtime
        return runtime

    def restart_challenge(self, spec):
        return self.start_challenge(spec, recreate=True)

    def stop_challenge(self, slug: str, *, remove: bool = False) -> None:
        self._runtime.pop(slug, None)


class FakeBrokerService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str | None]] = []

    def run(self, challenge_slug, request):
        self.calls.append(("run", challenge_slug, request.job_id))
        return BrokerRunResponse(container_name=f"job-{challenge_slug}", returncode=0)

    def cleanup(self, challenge_slug, request):
        self.calls.append(("cleanup", challenge_slug, request.job_id))
        return BrokerCleanupResponse()

    def list_containers(self, challenge_slug, request):
        self.calls.append(("list", challenge_slug, request.job_id))
        return BrokerListResponse(containers=[])


def _runtime(slug: str, image: str) -> ChallengeRuntime:
    return ChallengeRuntime(
        slug=slug,
        image=image,
        container_id=f"cid-{slug}",
        container_name=f"challenge-{slug}",
        internal_base_url=f"http://challenge-{slug}:8000",
        sqlite_volume_name=f"platform_{slug}_sqlite",
        health={"status": "ok"},
        version={"api_version": "1.0"},
    )
