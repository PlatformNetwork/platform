from __future__ import annotations

from contextlib import asynccontextmanager
from decimal import Decimal
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from platform_network.master.app_admin import create_admin_app
from platform_network.master.app_proxy import create_proxy_app, is_blocked_proxy_path
from platform_network.master.challenge_dashboard import ChallengeMetrics
from platform_network.master.registry import ChallengeRegistry
from platform_network.schemas.challenge import (
    ChallengeCreate,
    ChallengeRecord,
    ChallengeStatus,
    RuntimeOperationResponse,
)
from platform_network.schemas.gpu_server import (
    GpuServerCreate,
    GpuServerRecord,
    GpuServerUpdate,
)
from platform_network.schemas.kubernetes_target import (
    KubernetesTargetCreate,
    KubernetesTargetHealth,
    KubernetesTargetRecord,
    KubernetesTargetUpdate,
)
from platform_network.security.miner_auth import (
    MinerUploadVerifier,
    NonceReplayError,
)


def _payload(slug: str = "demo") -> dict[str, Any]:
    return {
        "slug": slug,
        "name": "Demo",
        "image": "ghcr.io/platformnetwork/demo:1.0.0",
        "version": "1.0.0",
        "emission_percent": "40.0",
    }


class FakeRuntimeController:
    async def pull(self, slug: str) -> RuntimeOperationResponse:
        return RuntimeOperationResponse(slug=slug, operation="pull", status="ok")

    async def restart(self, slug: str) -> RuntimeOperationResponse:
        return RuntimeOperationResponse(slug=slug, operation="restart", status="ok")

    async def status(self, slug: str) -> RuntimeOperationResponse:
        return RuntimeOperationResponse(slug=slug, operation="status", status="ok")


class FakeGpuServerRegistry:
    def __init__(self) -> None:
        self.records: dict[str, GpuServerRecord] = {}
        self.tokens: dict[str, str] = {}

    def list(self) -> list[GpuServerRecord]:
        return list(self.records.values())

    def get(self, server_id: str) -> GpuServerRecord:
        return self.records[server_id]

    def create(self, payload: GpuServerCreate) -> GpuServerRecord:
        record = GpuServerRecord(
            id=payload.id,
            base_url=payload.base_url,
            enabled=payload.enabled,
            verify_tls=payload.verify_tls,
            timeout_seconds=payload.timeout_seconds,
            description=payload.description,
            labels=payload.labels,
            min_gpu_count=payload.min_gpu_count,
            token_hint="****" if payload.token else None,
        )
        self.records[payload.id] = record
        if payload.token:
            self.tokens[payload.id] = payload.token
        return record

    def update(self, server_id: str, payload: GpuServerUpdate) -> GpuServerRecord:
        data = self.get(server_id).model_dump()
        updates = payload.model_dump(exclude_unset=True)
        token = updates.pop("token", None)
        updates.pop("token_file", None)
        data.update(updates)
        if token:
            self.tokens[server_id] = token
            data["token_hint"] = "****"
        self.records[server_id] = GpuServerRecord(**data)
        return self.records[server_id]

    def delete(self, server_id: str) -> None:
        self.records.pop(server_id)
        self.tokens.pop(server_id, None)

    def set_enabled(self, server_id: str, enabled: bool) -> GpuServerRecord:
        return self.update(server_id, GpuServerUpdate(enabled=enabled))

    def get_token(self, server_id: str) -> str:
        return self.tokens[server_id]


class FakeKubernetesTargetRegistry:
    def __init__(self) -> None:
        self.records: dict[str, KubernetesTargetRecord] = {}
        self.tokens: dict[str, str] = {}
        self.assignments: dict[str, str] = {}

    def list(self) -> list[KubernetesTargetRecord]:
        return list(self.records.values())

    def get(self, target_id: str) -> KubernetesTargetRecord:
        return self.records[target_id]

    def create(self, payload: KubernetesTargetCreate) -> KubernetesTargetRecord:
        record = KubernetesTargetRecord(
            id=payload.id,
            mode=payload.mode,
            api_url=payload.api_url,
            agent_url=payload.agent_url,
            namespace=payload.namespace,
            service_account=payload.service_account,
            kubeconfig_file="/var/lib/platform/secrets/test-kubeconfig",
            enabled=payload.enabled,
            verify_tls=payload.verify_tls,
            timeout_seconds=payload.timeout_seconds,
            description=payload.description,
            labels=payload.labels,
            gpu_count=payload.gpu_count,
            storage_class=payload.storage_class,
            node_selector=payload.node_selector,
            tolerations=payload.tolerations,
            runtime_class_name=payload.runtime_class_name,
        )
        self.records[payload.id] = record
        if payload.agent_token:
            self.tokens[payload.id] = payload.agent_token
        return record

    def update(
        self, target_id: str, payload: KubernetesTargetUpdate
    ) -> KubernetesTargetRecord:
        data = self.get(target_id).model_dump()
        updates = payload.model_dump(exclude_unset=True)
        updates.pop("kubeconfig", None)
        updates.pop("agent_token", None)
        data.update(updates)
        self.records[target_id] = KubernetesTargetRecord(**data)
        return self.records[target_id]

    def delete(self, target_id: str) -> None:
        self.records.pop(target_id)

    def set_enabled(self, target_id: str, enabled: bool) -> KubernetesTargetRecord:
        return self.update(target_id, KubernetesTargetUpdate(enabled=enabled))

    def health(self, target_id: str) -> KubernetesTargetHealth:
        self.get(target_id)
        return KubernetesTargetHealth(id=target_id, status="ok", detail="direct")

    def get_agent_token(self, target_id: str) -> str:
        return self.tokens.get(target_id, "agent-token")

    def get_assignment(self, slug: str) -> str | None:
        return self.assignments.get(slug)


class FakeNonceStore:
    def __init__(self) -> None:
        self.keys: set[tuple[int, str, str, str]] = set()

    async def reserve(self, **kwargs: Any) -> None:
        key = (
            int(kwargs["netuid"]),
            str(kwargs["challenge_slug"]),
            str(kwargs["hotkey"]),
            str(kwargs["nonce"]),
        )
        if key in self.keys:
            raise NonceReplayError("nonce already used")
        self.keys.add(key)


def _admin_app(registry: ChallengeRegistry, **kwargs: Any) -> FastAPI:
    return create_admin_app(
        registry=registry,
        runtime_controller=FakeRuntimeController(),
        gpu_registry=FakeGpuServerRegistry(),
        **kwargs,
    )


class FakeCache:
    def get(self) -> dict[str, int]:
        return {}


def _proxy_app(registry: ChallengeRegistry, **kwargs: Any) -> FastAPI:
    return create_proxy_app(
        registry=registry,
        nonce_store=FakeNonceStore(),
        metagraph_cache=FakeCache(),  # type: ignore[arg-type]
        **kwargs,
    )


def test_admin_challenge_crud_and_registry_active_only() -> None:
    registry = ChallengeRegistry()
    app = _admin_app(registry, admin_token_provider=lambda: "admin-secret")
    client = TestClient(app)

    assert client.post("/v1/admin/challenges", json=_payload()).status_code == 401

    create_response = client.post(
        "/v1/admin/challenges",
        json=_payload(),
        headers={"X-Admin-Token": "admin-secret"},
    )
    assert create_response.status_code == 201
    body = create_response.json()
    assert body["challenge"]["slug"] == "demo"
    assert body["challenge"]["token_hint"]
    assert body["challenge_token"]
    assert "token_hash" not in body["challenge"]

    registry_response = client.get("/v1/registry")
    assert registry_response.status_code == 200
    assert registry_response.json()["challenges"] == []

    activate_response = client.post(
        "/v1/admin/challenges/demo/activate",
        headers={"X-Admin-Token": "admin-secret"},
    )
    assert activate_response.status_code == 200
    assert activate_response.json()["status"] == "active"

    registry_response = client.get("/v1/registry")
    assert registry_response.status_code == 200
    challenges = registry_response.json()["challenges"]
    assert len(challenges) == 1
    assert challenges[0]["slug"] == "demo"
    assert "token_hash" not in challenges[0]
    assert "challenge_token" not in challenges[0]


def test_registry_sets_defaults_without_exposing_clear_token() -> None:
    registry = ChallengeRegistry(master_uid=0)
    record, token = registry.create(ChallengeCreate(**_payload("code-arena")))

    assert token
    assert record.token_hash != token
    assert record.internal_base_url == "http://challenge-code-arena:8000"
    assert record.public_proxy_base_path == "/challenges/code-arena"
    assert record.volumes["sqlite"] == "platform_code_arena_sqlite"

    registry.set_status("code-arena", ChallengeStatus.ACTIVE)
    response = registry.registry_response()
    assert response.network == "platform"
    assert response.master_uid == 0
    assert response.challenges[0].emission_percent == Decimal("40.0")


def test_challenges_dashboard_svg_includes_all_statuses_without_secrets() -> None:
    registry = ChallengeRegistry()
    registry.create(ChallengeCreate(**_payload("active-one")))
    registry.set_status("active-one", ChallengeStatus.ACTIVE)
    registry.create(
        ChallengeCreate(
            **{
                **_payload("draft-one"),
                "name": "Draft <unsafe> & name",
                "emission_percent": "5.5",
            }
        )
    )
    client = TestClient(_admin_app(registry))

    response = client.get("/v1/challenges/dashboard.svg")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    svg = response.text
    assert "active-one" in svg
    assert "draft-one" in svg
    assert "online" in svg
    assert "offline" in svg
    assert "N/A" in svg
    assert "Draft &lt;unsafe&gt; &amp; name" in svg
    assert "token_hash" not in svg
    assert "challenge_token" not in svg


def test_challenges_dashboard_svg_uses_empty_state_when_empty() -> None:
    client = TestClient(_admin_app(ChallengeRegistry()))

    response = client.get("/v1/challenges/dashboard.svg")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    svg = response.text
    assert "No registered challenges" in svg
    assert "Create a challenge to populate this dashboard." in svg
    assert "Prism" not in svg
    assert "Agent Challenge" not in svg


def test_challenges_dashboard_svg_live_data_uses_real_records() -> None:
    registry = ChallengeRegistry()
    registry.create(
        ChallengeCreate(
            **{
                **_payload("live-one"),
                "name": "Live <unsafe>",
                "description": "Live & useful challenge",
            }
        )
    )
    client = TestClient(_admin_app(registry))

    response = client.get("/v1/challenges/dashboard.svg")

    assert response.status_code == 200
    svg = response.text
    assert "Live &lt;unsafe&gt;" in svg
    assert "Live &amp; useful challenge" in svg
    assert "Prism" not in svg


def test_challenges_dashboard_svg_accepts_future_metrics_provider() -> None:
    class StaticMetricsProvider:
        def metrics_for(self, challenge: ChallengeRecord) -> ChallengeMetrics:
            return ChallengeMetrics(miner_count=7)

    registry = ChallengeRegistry()
    registry.create(ChallengeCreate(**_payload()))
    client = TestClient(_admin_app(registry, metrics_provider=StaticMetricsProvider()))

    response = client.get("/v1/challenges/dashboard.svg")

    assert response.status_code == 200
    assert ">7</text>" in response.text


def test_admin_gpu_servers_pages_and_api_without_secret_leak() -> None:
    client = TestClient(
        _admin_app(
            registry=ChallengeRegistry(),
            admin_token_provider=lambda: "admin-secret",
        )
    )
    headers = {"X-Admin-Token": "admin-secret"}

    create_response = client.post(
        "/v1/admin/gpu-servers",
        headers=headers,
        json={
            "id": "gpu-a",
            "base_url": "https://gpu-a",
            "token": "secret-token",
            "min_gpu_count": 1,
        },
    )

    assert create_response.status_code == 201
    body = create_response.json()
    assert body["id"] == "gpu-a"
    assert "secret-token" not in create_response.text

    list_response = client.get("/v1/admin/gpu-servers", headers=headers)
    assert list_response.status_code == 200
    assert list_response.json()[0]["id"] == "gpu-a"

    page_response = client.get("/admin/gpu-servers", headers=headers)
    assert page_response.status_code == 200
    assert "gpu-a" in page_response.text

    disable_response = client.post(
        "/v1/admin/gpu-servers/gpu-a/disable", headers=headers
    )
    assert disable_response.json()["enabled"] is False

    delete_response = client.delete("/v1/admin/gpu-servers/gpu-a", headers=headers)
    assert delete_response.status_code == 204


def test_admin_kubernetes_targets_pages_api_and_health_without_secret_leak() -> None:
    client = TestClient(
        _admin_app(
            registry=ChallengeRegistry(),
            admin_token_provider=lambda: "admin-secret",
            kubernetes_target_registry=FakeKubernetesTargetRegistry(),
        )
    )
    headers = {"X-Admin-Token": "admin-secret"}

    create_response = client.post(
        "/v1/admin/kubernetes-targets",
        headers=headers,
        json={
            "id": "k8s-a",
            "mode": "direct",
            "api_url": "https://k8s-a",
            "kubeconfig": "apiVersion: v1\nsecret-data",
            "namespace": "platform-gpu",
            "gpu_count": 2,
            "labels": {"region": "eu"},
        },
    )

    assert create_response.status_code == 201
    body = create_response.json()
    assert body["id"] == "k8s-a"
    assert body["mode"] == "direct"
    assert body["gpu_count"] == 2
    assert "secret-data" not in create_response.text

    list_response = client.get("/v1/admin/kubernetes-targets", headers=headers)
    assert list_response.status_code == 200
    assert list_response.json()[0]["id"] == "k8s-a"

    page_response = client.get("/admin/kubernetes-targets", headers=headers)
    assert page_response.status_code == 200
    assert "k8s-a" in page_response.text

    health_response = client.post(
        "/v1/admin/kubernetes-targets/k8s-a/health", headers=headers
    )
    assert health_response.status_code == 200
    assert health_response.json()["status"] == "ok"

    delete_response = client.delete(
        "/v1/admin/kubernetes-targets/k8s-a", headers=headers
    )
    assert delete_response.status_code == 204


def test_proxy_blocks_internal_health_and_version_paths() -> None:
    for path in (
        "internal/v1/get_weights",
        "/internal",
        "health",
        "/version",
        "nested/../internal/x",
    ):
        assert is_blocked_proxy_path(path)

    registry = ChallengeRegistry()
    registry.create(ChallengeCreate(**_payload()))
    registry.set_status("demo", ChallengeStatus.ACTIVE)
    client = TestClient(_proxy_app(registry))

    for path in ("internal/v1/get_weights", "health", "version"):
        response = client.get(f"/challenges/demo/{path}")
        assert response.status_code == 403


def test_proxy_forwards_public_request_without_sensitive_headers() -> None:
    registry = ChallengeRegistry()
    registry.create(
        ChallengeCreate(
            **{
                **_payload(),
                "internal_base_url": "http://challenge-demo:8000",
            }
        )
    )
    registry.set_status("demo", ChallengeStatus.ACTIVE)

    challenge_app = FastAPI()
    captured: dict[str, str] = {}

    @challenge_app.post("/submissions")
    async def submissions(request: Request) -> dict[str, object]:
        captured.update(dict(request.headers))
        return {"ok": True, "body": await request.json()}

    @asynccontextmanager
    async def client_factory():
        transport = httpx.ASGITransport(app=challenge_app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://challenge-demo:8000"
        ) as client:
            yield client

    proxy_client = TestClient(_proxy_app(registry, client_factory=client_factory))
    response = proxy_client.post(
        "/challenges/demo/submissions",
        json={"answer": 42},
        headers={
            "Authorization": "Bearer should-not-forward",
            "X-Admin-Token": "should-not-forward",
            "X-Public-Header": "forward-me",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True, "body": {"answer": 42}}
    assert captured["x-platform-proxy"] == "true"
    assert captured["x-platform-challenge-slug"] == "demo"
    assert captured["x-public-header"] == "forward-me"
    assert "authorization" not in captured
    assert "x-admin-token" not in captured
    assert "x-platform-verified-hotkey" not in captured
    assert "x-signature" not in captured


def test_proxy_routes_assigned_kubernetes_agent_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = ChallengeRegistry()
    registry.create(ChallengeCreate(**_payload()))
    registry.set_status("demo", ChallengeStatus.ACTIVE)
    target_registry = FakeKubernetesTargetRegistry()
    target_registry.records["agent-a"] = KubernetesTargetRecord(
        id="agent-a",
        mode="agent",
        agent_url="https://agent-a",
        enabled=True,
        verify_tls=False,
        timeout_seconds=9,
    )
    target_registry.assignments["demo"] = "agent-a"
    calls: list[dict[str, object]] = []

    class AgentClient:
        def __init__(self, **kwargs: object) -> None:
            calls.append(kwargs)

        async def forward_challenge_request(self, **kwargs: object) -> httpx.Response:
            calls.append(kwargs)
            return httpx.Response(200, json={"ok": True})

    import platform_network.master.app_proxy as proxy_module

    monkeypatch.setattr(proxy_module, "KubernetesAgentClient", AgentClient)
    proxy_client = TestClient(
        _proxy_app(registry, kubernetes_target_registry=target_registry)
    )

    response = proxy_client.get("/challenges/demo/public")

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert calls[0]["base_url"] == "https://agent-a"
    assert calls[1]["slug"] == "demo"
    assert calls[1]["path"] == "public"


def test_signed_upload_bridge_verifies_and_forwards_internal_request() -> None:
    registry = ChallengeRegistry()
    registry.create(ChallengeCreate(**_payload()))
    registry.set_status("demo", ChallengeStatus.ACTIVE)
    captured: dict[str, Any] = {}

    class Cache:
        def get(self) -> dict[str, int]:
            return {"hk": 7}

    challenge_app = FastAPI()

    @challenge_app.post("/internal/v1/bridge/submissions")
    async def bridge(request: Request) -> dict[str, object]:
        captured["headers"] = dict(request.headers)
        captured["body"] = await request.body()
        return {"id": "sub-1", "status": "pending"}

    @asynccontextmanager
    async def client_factory():
        transport = httpx.ASGITransport(app=challenge_app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://challenge-demo:8000"
        ) as client:
            yield client

    verifier = MinerUploadVerifier(
        netuid=42,
        nonce_store=FakeNonceStore(),
        metagraph_cache=Cache(),  # type: ignore[arg-type]
        now_fn=lambda: 1_000,
        signature_verifier=lambda _hotkey, _message, signature: signature == "valid",
    )
    proxy_client = TestClient(
        create_proxy_app(
            registry=registry,
            client_factory=client_factory,
            miner_verifier=verifier,
            challenge_token_provider=lambda slug: (
                "challenge-token" if slug == "demo" else ""
            ),
        )
    )

    response = proxy_client.post(
        "/v1/challenges/demo/submissions",
        content=b"zip-bytes",
        headers={
            "Content-Type": "application/zip",
            "X-Hotkey": "hk",
            "X-Signature": "valid",
            "X-Nonce": "nonce-1",
            "X-Timestamp": "1000",
            "X-Submission-Filename": "project.zip",
            "X-Platform-Verified-Hotkey": "spoof",
        },
    )

    assert response.status_code == 200
    assert response.json()["id"] == "sub-1"
    headers = captured["headers"]
    assert headers["authorization"] == "Bearer challenge-token"  # type: ignore[index]
    assert headers["x-platform-verified-hotkey"] == "hk"  # type: ignore[index]
    assert headers["x-platform-verified-uid"] == "7"  # type: ignore[index]
    assert headers["x-platform-verified-nonce"] == "nonce-1"  # type: ignore[index]
    assert headers["x-submission-filename"] == "project.zip"  # type: ignore[index]
    assert captured["body"] == b"zip-bytes"


def test_signed_upload_bridge_rejects_replay_and_bad_time() -> None:
    registry = ChallengeRegistry()
    registry.create(ChallengeCreate(**_payload()))
    registry.set_status("demo", ChallengeStatus.ACTIVE)

    class Cache:
        def get(self) -> dict[str, int]:
            return {"hk": 7}

    verifier = MinerUploadVerifier(
        netuid=42,
        nonce_store=FakeNonceStore(),
        metagraph_cache=Cache(),  # type: ignore[arg-type]
        now_fn=lambda: 1_000,
        signature_verifier=lambda _hotkey, _message, signature: signature == "valid",
    )

    @asynccontextmanager
    async def failing_client_factory():
        async def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom", request=request)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            yield client

    client = TestClient(
        create_proxy_app(
            registry=registry,
            client_factory=failing_client_factory,
            miner_verifier=verifier,
            challenge_token_provider=lambda _slug: "challenge-token",
        )
    )
    headers = {
        "X-Hotkey": "hk",
        "X-Signature": "valid",
        "X-Nonce": "nonce-1",
        "X-Timestamp": "1000",
    }

    first = client.post(
        "/v1/challenges/demo/submissions", content=b"x", headers=headers
    )
    assert first.status_code == 502
    second = client.post(
        "/v1/challenges/demo/submissions", content=b"x", headers=headers
    )
    assert second.status_code == 409
    stale = {**headers, "X-Nonce": "nonce-2", "X-Timestamp": "1"}
    stale_response = client.post(
        "/v1/challenges/demo/submissions", content=b"x", headers=stale
    )
    assert stale_response.status_code == 401


def test_production_admin_rejects_unsafe_challenge_image() -> None:
    registry = ChallengeRegistry()
    client = TestClient(
        _admin_app(
            registry,
            admin_token_provider=lambda: "admin-secret",
            enforce_production_policy=True,
        )
    )

    response = client.post(
        "/v1/admin/challenges",
        json=_payload(),
        headers={"X-Admin-Token": "admin-secret"},
    )

    assert response.status_code == 400
    assert "digest" in response.text


def test_production_admin_accepts_pinned_image_and_rejects_update() -> None:
    registry = ChallengeRegistry()
    client = TestClient(
        _admin_app(
            registry,
            admin_token_provider=lambda: "admin-secret",
            enforce_production_policy=True,
        )
    )
    digest = "sha256:" + "b" * 64

    response = client.post(
        "/v1/admin/challenges",
        json={**_payload(), "image": f"ghcr.io/platformnetwork/demo:1.2.3@{digest}"},
        headers={"X-Admin-Token": "admin-secret"},
    )
    assert response.status_code == 201

    patch = client.patch(
        "/v1/admin/challenges/demo",
        json={"image": "ghcr.io/platformnetwork/demo:latest"},
        headers={"X-Admin-Token": "admin-secret"},
    )
    assert patch.status_code == 400
    assert "latest" in patch.text


def test_production_admin_rejects_verify_tls_false_targets() -> None:
    client = TestClient(
        _admin_app(
            registry=ChallengeRegistry(),
            admin_token_provider=lambda: "admin-secret",
            kubernetes_target_registry=FakeKubernetesTargetRegistry(),
            enforce_production_policy=True,
        )
    )
    headers = {"X-Admin-Token": "admin-secret"}

    gpu = client.post(
        "/v1/admin/gpu-servers",
        headers=headers,
        json={"id": "gpu-a", "base_url": "https://gpu-a", "verify_tls": False},
    )
    assert gpu.status_code == 400
    assert "verify_tls=true" in gpu.text

    target = client.post(
        "/v1/admin/kubernetes-targets",
        headers=headers,
        json={
            "id": "k8s-a",
            "mode": "agent",
            "agent_url": "https://agent-a",
            "verify_tls": False,
        },
    )
    assert target.status_code == 400
    assert "verify_tls=true" in target.text
