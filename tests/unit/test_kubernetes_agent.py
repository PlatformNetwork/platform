from __future__ import annotations

from fastapi.testclient import TestClient

from platform_network.kubernetes.agent import create_kubernetes_agent_app
from platform_network.master.docker_orchestrator import ChallengeRuntime
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
            orchestrator=orchestrator,
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
    assert broker.challenge_slug == "demo"


class FakeOrchestrator:
    def __init__(self) -> None:
        self.recreate = False

    def pull_image(self, image: str):
        return {"image": image}

    def start_challenge(self, spec, *, recreate: bool = False):
        self.recreate = recreate
        return _runtime(spec.slug, spec.image)

    def restart_challenge(self, spec):
        return _runtime(spec.slug, spec.image)

    def stop_challenge(self, slug: str, *, remove: bool = False) -> None:
        return None


class FakeBrokerService:
    def __init__(self) -> None:
        self.challenge_slug = ""

    def run(self, challenge_slug, request):
        self.challenge_slug = challenge_slug
        return BrokerRunResponse(container_name=f"job-{challenge_slug}", returncode=0)

    def cleanup(self, challenge_slug, request):
        return BrokerCleanupResponse()

    def list_containers(self, challenge_slug, request):
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
