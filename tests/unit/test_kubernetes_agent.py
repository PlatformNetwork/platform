from __future__ import annotations

from typing import Any, cast

import httpx
import pytest
from fastapi.testclient import TestClient

from platform_network.kubernetes.agent import (
    KubernetesAgentClient,
    create_kubernetes_agent_app,
)
from platform_network.master.docker_orchestrator import ChallengeRuntime
from platform_network.master.kubernetes_orchestrator import KubernetesOrchestrator
from platform_network.schemas.docker_broker import (
    BrokerCleanupResponse,
    BrokerLimits,
    BrokerListResponse,
    BrokerRunRequest,
    BrokerRunResponse,
)


def test_kubernetes_agent_challenge_proxy_preserves_origin_404(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeAsyncClient:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback) -> None:
            return None

        async def request(self, method, url, *, content, headers):
            assert method == "GET"
            assert url == "http://challenge-demo:8000/missing?x=1"
            assert headers["Authorization"] == "Bearer forwarded-user-token"
            return httpx.Response(
                404,
                json={"detail": "not found"},
                headers={"content-type": "application/json"},
            )

    import platform_network.kubernetes.agent as agent_module

    monkeypatch.setattr(agent_module.httpx, "AsyncClient", FakeAsyncClient)
    client = TestClient(
        create_kubernetes_agent_app(
            token_provider=lambda: "agent-token",
            orchestrator=cast(KubernetesOrchestrator, FakeOrchestrator()),
            broker_service=FakeBrokerService(),  # type: ignore[arg-type]
        )
    )

    response = client.get(
        "/v1/challenges/demo/proxy/missing?x=1",
        headers={
            "Authorization": "Bearer agent-token",
            "X-Platform-Forward-Authorization": "Bearer forwarded-user-token",
        },
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "not found"}
    assert response.text != '{"detail":"challenge unavailable"}'


def test_kubernetes_agent_challenge_proxy_transport_failure_is_safe_502(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingAsyncClient:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback) -> None:
            return None

        async def request(self, method, url, *, content, headers):
            request = httpx.Request(method, url, headers=headers, content=content)
            raise httpx.ConnectError(
                "failed http://challenge-demo:8000/private?token=secret-token",
                request=request,
            )

    import platform_network.kubernetes.agent as agent_module

    monkeypatch.setattr(agent_module.httpx, "AsyncClient", FailingAsyncClient)
    client = TestClient(
        create_kubernetes_agent_app(
            token_provider=lambda: "agent-token",
            orchestrator=cast(KubernetesOrchestrator, FakeOrchestrator()),
            broker_service=FakeBrokerService(),  # type: ignore[arg-type]
        )
    )

    response = client.post(
        "/v1/challenges/demo/proxy/private?signature=secret-signature",
        content=b"safe-test-body",
        headers={
            "Authorization": "Bearer agent-token",
            "X-Platform-Forward-Authorization": "Bearer secret-token",
            "X-Signature": "secret-signature",
            "X-Nonce": "secret-nonce",
        },
    )

    assert response.status_code == 502
    assert response.json() == {"detail": "challenge unavailable"}
    body = response.text.lower()
    assert "challenge-demo" not in body
    assert "secret-token" not in body
    assert "secret-signature" not in body
    assert "secret-nonce" not in body
    assert "traceback" not in body


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


def test_platform_sdk_kubernetes_agent_client_run_broker_preserves_generic_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            captured["client_kwargs"] = kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback) -> None:
            return None

        def post(self, path: str, *, json, headers):
            captured["path"] = path
            captured["json"] = json
            captured["headers"] = headers
            return httpx.Response(
                200,
                request=httpx.Request("POST", f"http://agent{path}"),
                json={
                    "container_name": "job-demo",
                    "stdout": "",
                    "stderr": "",
                    "returncode": 0,
                    "timed_out": False,
                },
            )

    import platform_network.kubernetes.agent as agent_module

    monkeypatch.setattr(agent_module.httpx, "Client", FakeClient)
    response = KubernetesAgentClient(
        target_id="target-1",
        base_url="http://agent",
        token="agent-token",
    ).run_broker(
        "demo",
        BrokerRunRequest(
            job_id="job-1",
            task_id="terminal-bench-1",
            image="ghcr.io/platformnetwork/worker:1",
            image_pull_policy="Always",
            command=["python", "-m", "runner"],
            workdir="/workspace",
            env={"PLATFORM_TOKEN_FILE": "/var/run/secrets/platform/token"},
            labels={"platform.job": "job-1", "custom.label": "survives"},
            limits=BrokerLimits(cpus=1.5, memory="768Mi", gpu_count=1),
            timeout_seconds=44,
        ),
    )

    assert response.container_name == "job-demo"
    assert captured["path"] == "/v1/broker/demo/run"
    assert captured["headers"] == {"Authorization": "Bearer agent-token"}
    payload = cast(dict[str, Any], captured["json"])
    assert payload["image"] == "ghcr.io/platformnetwork/worker:1"
    assert payload["image_pull_policy"] == "Always"
    assert payload["command"] == ["python", "-m", "runner"]
    assert payload["workdir"] == "/workspace"
    assert payload["env"] == {"PLATFORM_TOKEN_FILE": "/var/run/secrets/platform/token"}
    assert payload["labels"] == {"platform.job": "job-1", "custom.label": "survives"}
    assert payload["limits"]["cpus"] == 1.5
    assert payload["limits"]["memory"] == "768Mi"
    assert payload["limits"]["gpu_count"] == 1
    assert payload["timeout_seconds"] == 44
    assert "agent_challenge" not in payload
    assert "provider_ref" not in payload
    assert "miner_env" not in payload


def test_kubernetes_agent_client_run_broker_uses_job_aware_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_timeouts: list[float] = []

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            captured_timeouts.append(cast(float, kwargs["timeout"]))

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback) -> None:
            return None

        def post(self, path: str, *, json, headers):
            return httpx.Response(
                200,
                request=httpx.Request("POST", f"http://agent{path}"),
                json={
                    "container_name": "job-demo",
                    "stdout": "",
                    "stderr": "",
                    "returncode": 0,
                    "timed_out": False,
                },
            )

    import platform_network.kubernetes.agent as agent_module

    monkeypatch.setattr(agent_module.httpx, "Client", FakeClient)
    client = KubernetesAgentClient(
        target_id="target-1",
        base_url="http://agent",
        token="agent-token",
        timeout_seconds=30,
    )
    client.run_broker(
        "demo",
        BrokerRunRequest(
            job_id="job-1",
            image="ghcr.io/platformnetwork/worker:1",
            command=["true"],
            timeout_seconds=900,
        ),
    )

    KubernetesAgentClient(
        target_id="target-1",
        base_url="http://agent",
        token="agent-token",
        timeout_seconds=1000,
    ).run_broker(
        "demo",
        BrokerRunRequest(
            job_id="job-2",
            image="ghcr.io/platformnetwork/worker:1",
            command=["true"],
            timeout_seconds=10,
        ),
    )

    assert captured_timeouts[0] >= 915
    assert captured_timeouts[1] >= 1000


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
