from __future__ import annotations

import asyncio
import secrets
from collections.abc import Mapping, MutableMapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from platform_network.master.app_admin import create_admin_app
from platform_network.master.app_proxy import (
    create_proxy_app,
    is_blocked_proxy_path,
    prism_upstream_proxy_path,
)
from platform_network.master.challenge_dashboard import ChallengeMetrics
from platform_network.master.registry import ChallengeRegistry
from platform_network.schemas.challenge import (
    ChallengeCreate,
    ChallengeRecord,
    ChallengeStatus,
    ChallengeUpdate,
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
from platform_network.schemas.weights import ChallengeWeightsResult
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


def _prism_payload() -> dict[str, Any]:
    return {
        "slug": "prism",
        "name": "PRISM",
        "image": "ghcr.io/platformnetwork/prism:latest",
        "version": "0.1.0",
        "status": "active",
        "emission_percent": "30",
        "internal_base_url": "http://challenge-prism:8000",
        "required_capabilities": ["get_weights", "proxy_routes"],
        "metadata": {
            "repository_url": "https://github.com/PlatformNetwork/prism",
            "category": "Agentic (Multi-step)",
            "benchmark_label": "PRISM architecture and training reward boards",
            "token": "fixture-token",
            "secret": "fixture-secret",
            "database_url": "postgres://fixture-secret",
            "internal_base_url": "http://challenge-prism:8000",
            "operator_notes": "private rollout notes",
            "nested": {"unsafe": "value"},
        },
    }


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("leaderboard", "/v1/leaderboard"),
        ("architectures", "/v1/architectures"),
        ("training-variants", "/v1/training-variants"),
        ("epochs/current", "/v1/epochs/current"),
        ("submissions/sub-1", "/v1/submissions/sub-1"),
        ("/v1/leaderboard", "/v1/leaderboard"),
        ("leaderboard-extra", "leaderboard-extra"),
        ("architectures-extra", "architectures-extra"),
        ("training-variants-extra", "training-variants-extra"),
        ("epochs/current-extra", "epochs/current-extra"),
        ("submissions/sub-1/events", "submissions/sub-1/events"),
    ],
)
def test_prism_upstream_proxy_path_maps_only_public_routes(
    path: str, expected: str
) -> None:
    assert prism_upstream_proxy_path("prism", path) == expected
    assert prism_upstream_proxy_path("agent-challenge", path) == path


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


class FakeWeightService:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[list[str], dict[str, str]]] = []

    async def compute_latest_response(
        self,
        challenges: list[Any],
        tokens: dict[str, str],
        *,
        netuid: int,
        chain_endpoint: str,
        now_fn: Any,
    ) -> Any:
        from datetime import timedelta

        from platform_network.schemas.weights import MasterWeightsResponse

        self.calls.append(([challenge.slug for challenge in challenges], tokens))
        if self.fail:
            raise RuntimeError("challenge collection failed")
        computed_at = now_fn()
        return MasterWeightsResponse(
            netuid=netuid,
            chain_endpoint=chain_endpoint,
            uids=[9],
            weights=[1.0],
            hotkey_weights={"miner-hotkey": 1.0},
            computed_at=computed_at,
            expires_at=computed_at + timedelta(seconds=720),
            source_challenges=[
                ChallengeWeightsResult(
                    slug="weights-smoke",
                    emission_percent=100,
                    weights={"miner-hotkey": 1.0},
                )
            ],
            metagraph_updated_at=computed_at,
        )


def test_weights_latest_is_public_and_computes_without_submit() -> None:
    registry = ChallengeRegistry()
    registry.create(
        ChallengeCreate(
            **{
                **_payload("weights-smoke"),
                "emission_percent": "100",
                "status": ChallengeStatus.ACTIVE,
                "internal_base_url": "http://challenge-weights-smoke:8000",
            }
        )
    )
    service = FakeWeightService()
    client = TestClient(
        _admin_app(
            registry,
            admin_token_provider=lambda: "admin-secret",
            weight_service=service,
            netuid=42,
            chain_endpoint="wss://chain.example:9944",
            now_fn=lambda: datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
        )
    )

    response = client.get("/v1/weights/latest")

    assert response.status_code == 200
    assert service.calls == [
        (["weights-smoke"], {"weights-smoke": registry.get_token("weights-smoke")})
    ]
    assert response.json() == {
        "netuid": 42,
        "chain_endpoint": "wss://chain.example:9944",
        "uids": [9],
        "weights": [1.0],
        "hotkey_weights": {"miner-hotkey": 1.0},
        "computed_at": "2030-01-01T12:00:00Z",
        "expires_at": "2030-01-01T12:12:00Z",
        "source_challenges": [
            {
                "slug": "weights-smoke",
                "emission_percent": 100.0,
                "weights": {"miner-hotkey": 1.0},
                "ok": True,
                "error": None,
            }
        ],
        "metagraph_updated_at": "2030-01-01T12:00:00Z",
    }


def test_weights_latest_returns_bad_gateway_when_collection_fails() -> None:
    registry = ChallengeRegistry()
    registry.create(
        ChallengeCreate(
            **{
                **_payload("weights-smoke"),
                "emission_percent": "100",
                "status": ChallengeStatus.ACTIVE,
            }
        )
    )
    client = TestClient(
        _admin_app(
            registry,
            weight_service=FakeWeightService(fail=True),
            now_fn=lambda: datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
        )
    )

    response = client.get("/v1/weights/latest")

    assert response.status_code == 502
    assert response.json()["detail"] == "challenge collection failed"


def test_admin_challenge_crud_and_registry_active_only() -> None:
    registry = ChallengeRegistry()
    app = _admin_app(registry, admin_token_provider=lambda: "admin-secret")
    client = TestClient(app)
    payload = {
        **_payload("agent-challenge"),
        "name": "Agent Challenge",
        "description": "Build and evaluate coding agents.",
        "metadata": {
            "tagline": "Compete with production-grade agents",
            "summary": "Agent Challenge benchmark and leaderboard",
            "docs_url": "https://docs.example.com/agent-challenge",
            "miner_docs_url": "https://docs.example.com/agent-challenge/miners",
            "validator_docs_url": "https://docs.example.com/agent-challenge/validators",
            "repository_url": "https://github.com/example/agent-challenge",
            "website_url": "https://example.com/agent-challenge",
            "banner_url": "https://cdn.example.com/agent-challenge/banner.png",
            "icon_url": "https://cdn.example.com/agent-challenge/icon.png",
            "category": "agents",
            "difficulty": "hard",
            "benchmark_label": "Terminal-Bench",
            "submission_format": "zip",
            "evaluation_timeout_seconds": 1800,
            "rate_limit_label": "10 submissions/hour",
            "token": "challenge-token",
            "secret": "shared-secret",
            "password": "password",
            "private_key": "private-key",
            "database_url": "postgres://secret",
            "internal_base_url": "http://internal:8000",
            "operator_notes": "do not publish",
            "nested": {"arbitrary": "object"},
        },
    }

    assert client.post("/v1/admin/challenges", json=payload).status_code == 401

    create_response = client.post(
        "/v1/admin/challenges",
        json=payload,
        headers={"X-Admin-Token": "admin-secret"},
    )
    assert create_response.status_code == 201
    body = create_response.json()
    assert body["challenge"]["slug"] == "agent-challenge"
    assert body["challenge"]["token_hint"]
    assert body["challenge_token"]
    assert "token_hash" not in body["challenge"]

    registry_response = client.get("/v1/registry")
    assert registry_response.status_code == 200
    assert registry_response.json()["challenges"] == []

    activate_response = client.post(
        "/v1/admin/challenges/agent-challenge/activate",
        headers={"X-Admin-Token": "admin-secret"},
    )
    assert activate_response.status_code == 200
    assert activate_response.json()["status"] == "active"

    registry_response = client.get("/v1/registry")
    assert registry_response.status_code == 200
    challenges = registry_response.json()["challenges"]
    assert len(challenges) == 1
    challenge = challenges[0]
    assert challenge["slug"] == "agent-challenge"
    assert challenge["name"] == "Agent Challenge"
    assert challenge["description"] == "Build and evaluate coding agents."
    assert challenge["public_proxy_base_path"] == "/challenges/agent-challenge"
    assert challenge["internal_base_url"] == "http://challenge-agent-challenge:8000"
    assert challenge["image"] == "ghcr.io/platformnetwork/demo:1.0.0"
    assert challenge["version"] == "1.0.0"
    assert challenge["emission_percent"] == "40.0"
    assert challenge["status"] == "active"
    assert challenge["required_capabilities"] == ["get_weights", "proxy_routes"]
    assert challenge["resources"] == {}
    assert challenge["volumes"] == {"sqlite": "platform_agent_challenge_sqlite"}
    assert challenge["env"] == {}
    assert challenge["secrets"] == []
    assert challenge["metadata"] == {
        "tagline": "Compete with production-grade agents",
        "summary": "Agent Challenge benchmark and leaderboard",
        "docs_url": "https://docs.example.com/agent-challenge",
        "miner_docs_url": "https://docs.example.com/agent-challenge/miners",
        "validator_docs_url": "https://docs.example.com/agent-challenge/validators",
        "repository_url": "https://github.com/example/agent-challenge",
        "website_url": "https://example.com/agent-challenge",
        "banner_url": "https://cdn.example.com/agent-challenge/banner.png",
        "icon_url": "https://cdn.example.com/agent-challenge/icon.png",
        "category": "agents",
        "difficulty": "hard",
        "benchmark_label": "Terminal-Bench",
        "submission_format": "zip",
        "evaluation_timeout_seconds": 1800,
        "rate_limit_label": "10 submissions/hour",
    }
    assert "token_hash" not in challenge
    assert "token_hint" not in challenge
    assert "broker_token_hash" not in challenge
    assert "broker_token_hint" not in challenge
    assert "challenge_token" not in challenge
    assert "token" not in challenge["metadata"]
    assert "secret" not in challenge["metadata"]
    assert "password" not in challenge["metadata"]
    assert "private_key" not in challenge["metadata"]
    assert "database_url" not in challenge["metadata"]
    assert "internal_base_url" not in challenge["metadata"]
    assert "operator_notes" not in challenge["metadata"]
    assert "nested" not in challenge["metadata"]


def test_prism_registry_contract_and_agent_challenge_emission_update() -> None:
    registry = ChallengeRegistry()
    _, agent_token = registry.create(
        ChallengeCreate(
            **{
                **_payload("agent-challenge"),
                "name": "Agent Challenge",
                "status": ChallengeStatus.ACTIVE,
            }
        )
    )
    prism_record, prism_token = registry.create(ChallengeCreate(**_prism_payload()))

    updated_agent = registry.update(
        "agent-challenge", ChallengeUpdate(emission_percent=Decimal("15"))
    )

    assert updated_agent.emission_percent == Decimal("15")
    assert registry.get_token("agent-challenge") == agent_token
    assert prism_record.slug == "prism"
    assert prism_token

    response = TestClient(_admin_app(registry)).get("/v1/registry")

    assert response.status_code == 200
    challenges = {item["slug"]: item for item in response.json()["challenges"]}
    assert set(challenges) == {"agent-challenge", "prism"}
    assert challenges["agent-challenge"]["emission_percent"] == "15"

    prism = challenges["prism"]
    assert prism["name"] == "PRISM"
    assert prism["image"] == "ghcr.io/platformnetwork/prism:latest"
    assert prism["version"] == "0.1.0"
    assert prism["status"] == "active"
    assert prism["emission_percent"] == "30"
    assert prism["internal_base_url"] == "http://challenge-prism:8000"
    assert prism["public_proxy_base_path"] == "/challenges/prism"
    assert prism["required_capabilities"] == ["get_weights", "proxy_routes"]
    assert prism["metadata"] == {
        "repository_url": "https://github.com/PlatformNetwork/prism",
        "category": "Agentic (Multi-step)",
        "benchmark_label": "PRISM architecture and training reward boards",
    }
    for unsafe_key in (
        "token",
        "secret",
        "database_url",
        "internal_base_url",
        "operator_notes",
        "nested",
    ):
        assert unsafe_key not in prism["metadata"]
    assert "challenge_token" not in prism
    assert "token_hash" not in prism
    assert "token_hint" not in prism


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


def test_proxy_serves_agent_challenge_frontend_read_contract() -> None:
    registry = ChallengeRegistry()
    registry.create(
        ChallengeCreate(
            **{
                **_payload("agent-challenge"),
                "name": "Agent Challenge",
                "status": ChallengeStatus.ACTIVE,
                "internal_base_url": "http://challenge-agent-challenge:8000",
            }
        )
    )

    challenge_app = FastAPI()
    captured: dict[str, dict[str, Any]] = {}
    sensitive_headers = (
        "authorization",
        "x-admin-token",
        "x-hotkey",
        "x-signature",
        "x-nonce",
        "x-timestamp",
    )

    async def record_read_route(
        route_name: str, request: Request, payload: dict[str, Any]
    ) -> dict[str, Any]:
        headers = dict(request.headers)
        captured[route_name] = {
            "headers": headers,
            "path": request.url.path,
            "query": request.url.query,
        }
        return {"route": route_name, "query": request.url.query, **payload}

    @challenge_app.get("/benchmarks")
    async def benchmarks(request: Request) -> dict[str, Any]:
        return await record_read_route(
            "benchmarks",
            request,
            {"benchmarks": [{"id": "terminal-bench", "tasks": 2}]},
        )

    @challenge_app.get("/benchmarks/tasks")
    async def benchmark_tasks(request: Request) -> dict[str, Any]:
        return await record_read_route(
            "benchmark_tasks",
            request,
            {"tasks": [{"id": "task-1", "benchmark_id": "terminal-bench"}]},
        )

    @challenge_app.get("/submissions")
    async def submissions(request: Request) -> dict[str, Any]:
        return await record_read_route(
            "submissions",
            request,
            {"submissions": [{"id": "submission-1", "status": "queued"}]},
        )

    @challenge_app.get("/submissions/count")
    async def submissions_count(request: Request) -> dict[str, Any]:
        return await record_read_route("submissions_count", request, {"count": 1})

    @challenge_app.get("/submissions/{submission_id}")
    async def submission_detail(submission_id: str, request: Request) -> dict[str, Any]:
        return await record_read_route(
            "submission_detail",
            request,
            {"submission": {"id": submission_id, "score": 0.91}},
        )

    @challenge_app.get("/submissions/{submission_id}/status")
    async def submission_status(submission_id: str, request: Request) -> dict[str, Any]:
        return await record_read_route(
            "submission_status",
            request,
            {"id": submission_id, "status": "running"},
        )

    @challenge_app.get("/leaderboard")
    async def leaderboard(request: Request) -> dict[str, Any]:
        return await record_read_route(
            "leaderboard",
            request,
            {"leaderboard": [{"agent_hash": "agent-abc", "rank": 1}]},
        )

    @challenge_app.get("/agents/{agent_hash}/evaluation")
    async def agent_evaluation(agent_hash: str, request: Request) -> dict[str, Any]:
        return await record_read_route(
            "agent_evaluation",
            request,
            {"agent_hash": agent_hash, "evaluation": {"score": 0.98}},
        )

    @asynccontextmanager
    async def client_factory():
        transport = httpx.ASGITransport(app=challenge_app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://challenge-agent-challenge:8000"
        ) as client:
            yield client

    proxy_client = TestClient(_proxy_app(registry, client_factory=client_factory))
    headers = {
        "Authorization": "Bearer should-not-forward",
        "X-Admin-Token": "should-not-forward",
        "X-Hotkey": "should-not-forward",
        "X-Signature": "should-not-forward",
        "X-Nonce": "should-not-forward",
        "X-Timestamp": "should-not-forward",
        "X-Public-Header": "forward-me",
    }
    requests: list[tuple[str, str, Mapping[str, Any]]] = [
        (
            "/challenges/agent-challenge/benchmarks?suite=terminal-bench",
            "benchmarks",
            {"benchmarks": [{"id": "terminal-bench", "tasks": 2}]},
        ),
        (
            "/challenges/agent-challenge/benchmarks/tasks?benchmark_id=terminal-bench",
            "benchmark_tasks",
            {"tasks": [{"id": "task-1", "benchmark_id": "terminal-bench"}]},
        ),
        (
            "/challenges/agent-challenge/submissions?limit=25",
            "submissions",
            {"submissions": [{"id": "submission-1", "status": "queued"}]},
        ),
        (
            "/challenges/agent-challenge/submissions/count?status=queued",
            "submissions_count",
            {"count": 1},
        ),
        (
            "/challenges/agent-challenge/submissions/submission-1",
            "submission_detail",
            {"submission": {"id": "submission-1", "score": 0.91}},
        ),
        (
            "/challenges/agent-challenge/submissions/submission-1/status",
            "submission_status",
            {"id": "submission-1", "status": "running"},
        ),
        (
            "/challenges/agent-challenge/leaderboard?benchmark_id=terminal-bench",
            "leaderboard",
            {"leaderboard": [{"agent_hash": "agent-abc", "rank": 1}]},
        ),
        (
            "/challenges/agent-challenge/agents/agent-abc/evaluation?benchmark_id=terminal-bench",
            "agent_evaluation",
            {"agent_hash": "agent-abc", "evaluation": {"score": 0.98}},
        ),
    ]

    for path, route_name, expected_payload in requests:
        response = proxy_client.get(path, headers=headers)

        assert response.status_code == 200
        body = response.json()
        assert body["route"] == route_name
        for key, value in expected_payload.items():
            assert body[key] == value

    assert captured["benchmarks"]["query"] == "suite=terminal-bench"
    assert set(captured) == {route_name for _, route_name, _ in requests}
    expected_upstream_paths = {
        "benchmarks": "/benchmarks",
        "benchmark_tasks": "/benchmarks/tasks",
        "submissions": "/submissions",
        "submissions_count": "/submissions/count",
        "submission_detail": "/submissions/submission-1",
        "submission_status": "/submissions/submission-1/status",
        "leaderboard": "/leaderboard",
        "agent_evaluation": "/agents/agent-abc/evaluation",
    }
    for route_name, upstream_path in expected_upstream_paths.items():
        assert captured[route_name]["path"] == upstream_path
    for request_capture in captured.values():
        upstream_headers = request_capture["headers"]
        for header in sensitive_headers:
            assert header not in upstream_headers
        assert upstream_headers["x-platform-proxy"] == "true"
        assert upstream_headers["x-platform-challenge-slug"] == "agent-challenge"
        assert upstream_headers["x-public-header"] == "forward-me"


def test_prism_public_proxy_routes_forward_to_public_surface() -> None:
    registry = ChallengeRegistry()
    registry.create(ChallengeCreate(**_prism_payload()))
    captured: dict[str, dict[str, Any]] = {}
    challenge_app = FastAPI()

    async def record_prism_route(
        route_name: str, request: Request, payload: dict[str, Any]
    ) -> dict[str, Any]:
        captured[route_name] = {
            "headers": dict(request.headers),
            "path": request.url.path,
            "query": request.url.query,
        }
        return {"route": route_name, **payload}

    @challenge_app.get("/v1/leaderboard")
    async def leaderboard(request: Request) -> dict[str, Any]:
        return await record_prism_route(
            "leaderboard",
            request,
            {"epoch_id": 7, "entries": [{"rank": 1, "hotkey": "hk", "score": 0.9}]},
        )

    @challenge_app.get("/v1/architectures")
    async def architectures(request: Request) -> dict[str, Any]:
        return await record_prism_route(
            "architectures", request, {"items": [{"id": "arch-1"}]}
        )

    @challenge_app.get("/v1/training-variants")
    async def training_variants(request: Request) -> dict[str, Any]:
        return await record_prism_route(
            "training_variants", request, {"items": [{"id": "variant-1"}]}
        )

    @challenge_app.get("/v1/epochs/current")
    async def current_epoch(request: Request) -> dict[str, Any]:
        return await record_prism_route(
            "current_epoch", request, {"epoch_id": 7, "epoch_seconds": 3600}
        )

    @challenge_app.get("/v1/submissions/{submission_id}")
    async def submission_status(submission_id: str, request: Request) -> dict[str, Any]:
        return await record_prism_route(
            "submission_status", request, {"id": submission_id, "status": "completed"}
        )

    @asynccontextmanager
    async def client_factory():
        transport = httpx.ASGITransport(app=challenge_app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://challenge-prism:8000"
        ) as client:
            yield client

    proxy_client = TestClient(_proxy_app(registry, client_factory=client_factory))
    requests = [
        ("/challenges/prism/leaderboard", "leaderboard"),
        ("/challenges/prism/architectures", "architectures"),
        ("/challenges/prism/training-variants?limit=5", "training_variants"),
        ("/challenges/prism/epochs/current", "current_epoch"),
        ("/challenges/prism/submissions/sub-1", "submission_status"),
    ]

    for path, route_name in requests:
        response = proxy_client.get(
            path,
            headers={
                "Authorization": "Bearer should-not-forward",
                "X-Admin-Token": "should-not-forward",
                "X-Public-Header": "forward-me",
            },
        )

        assert response.status_code == 200
        assert response.json()["route"] == route_name

    assert [item["path"] for item in captured.values()] == [
        "/v1/leaderboard",
        "/v1/architectures",
        "/v1/training-variants",
        "/v1/epochs/current",
        "/v1/submissions/sub-1",
    ]
    assert captured["training_variants"]["query"] == "limit=5"
    for request_capture in captured.values():
        upstream_headers = request_capture["headers"]
        assert upstream_headers["x-platform-proxy"] == "true"
        assert upstream_headers["x-platform-challenge-slug"] == "prism"
        assert upstream_headers["x-public-header"] == "forward-me"
        assert "authorization" not in upstream_headers
        assert "x-admin-token" not in upstream_headers


def test_prism_proxy_does_not_remap_public_route_suffix_neighbors() -> None:
    registry = ChallengeRegistry()
    registry.create(ChallengeCreate(**_prism_payload()))
    challenge_app = FastAPI()
    captured_paths: list[str] = []

    @challenge_app.api_route("/{path:path}", methods=["GET"])
    async def catch_all(path: str, request: Request) -> dict[str, str]:
        captured_paths.append(request.url.path)
        return {"path": request.url.path}

    @asynccontextmanager
    async def client_factory():
        transport = httpx.ASGITransport(app=challenge_app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://challenge-prism:8000"
        ) as client:
            yield client

    proxy_client = TestClient(_proxy_app(registry, client_factory=client_factory))
    for path in (
        "/challenges/prism/leaderboard-extra",
        "/challenges/prism/architectures-extra",
        "/challenges/prism/training-variants-extra",
        "/challenges/prism/epochs/current-extra",
        "/challenges/prism/submissions/sub-1/events",
    ):
        response = proxy_client.get(path)

        assert response.status_code == 200

    assert captured_paths == [
        "/leaderboard-extra",
        "/architectures-extra",
        "/training-variants-extra",
        "/epochs/current-extra",
        "/submissions/sub-1/events",
    ]


def test_prism_proxy_blocks_internal_and_unavailable_routes() -> None:
    inactive_registry = ChallengeRegistry()
    inactive_registry.create(
        ChallengeCreate(**{**_prism_payload(), "status": ChallengeStatus.INACTIVE})
    )
    missing_registry = ChallengeRegistry()
    active_registry = ChallengeRegistry()
    active_registry.create(ChallengeCreate(**_prism_payload()))
    challenge_app = FastAPI()
    captured_paths: list[str] = []

    @challenge_app.api_route("/{path:path}", methods=["GET", "POST"])
    async def catch_all(path: str, request: Request) -> dict[str, str]:
        captured_paths.append(request.url.path)
        return {"path": path}

    @asynccontextmanager
    async def client_factory():
        transport = httpx.ASGITransport(app=challenge_app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://challenge-prism:8000"
        ) as client:
            yield client

    inactive_client = TestClient(
        _proxy_app(inactive_registry, client_factory=client_factory)
    )
    missing_client = TestClient(
        _proxy_app(missing_registry, client_factory=client_factory)
    )
    active_client = TestClient(
        _proxy_app(active_registry, client_factory=client_factory)
    )

    assert inactive_client.get("/challenges/prism/leaderboard").status_code == 404
    assert missing_client.get("/challenges/prism/leaderboard").status_code == 404
    for path in (
        "/challenges/prism/internal/v1/get_weights",
        "/challenges/prism/internal/worker/process-next",
        "/challenges/prism/health",
        "/challenges/prism/version",
    ):
        response = active_client.get(path)

        assert response.status_code == 403
        assert response.json()["detail"] == "Proxy path is not allowed"
    assert captured_paths == []


def test_proxy_serves_agent_challenge_task_event_replay_shape() -> None:
    registry = ChallengeRegistry()
    registry.create(
        ChallengeCreate(
            **{
                **_payload("agent-challenge"),
                "internal_base_url": "http://challenge-agent-challenge:8000",
            }
        )
    )
    registry.set_status("agent-challenge", ChallengeStatus.ACTIVE)
    captured: dict[str, Any] = {}
    safe_replay_payload = {
        "submission": {
            "id": "submission-1",
            "family_id": "fam_public_1",
            "version_number": 2,
            "version_label": "v2",
            "version_count": 3,
            "is_latest_version": False,
            "latest_submission_id": "submission-3",
            "display_name": "Agent Prime",
        },
        "events": [
            {
                "id": 101,
                "sequence": 1,
                "submission_id": "submission-1",
                "event_type": "task.progress",
                "task_id": "terminal-bench:hello-world",
                "benchmark_id": "terminal-bench",
                "public_state": "running",
                "message": "started task",
                "metadata": {"phase": "setup"},
                "created_at": "2030-01-01T00:00:00Z",
            },
            {
                "id": 102,
                "sequence": 2,
                "submission_id": "submission-1",
                "event_type": "task.completed",
                "task_id": "terminal-bench:hello-world",
                "benchmark_id": "terminal-bench",
                "public_state": "completed",
                "message": "completed task",
                "metadata": {"score": 1.0},
                "created_at": "2030-01-01T00:00:01Z",
            },
        ],
        "next_cursor": 2,
        "latest_sequence": 2,
    }

    challenge_app = FastAPI()

    @challenge_app.get("/submissions/{submission_id}/task-events")
    async def task_events(submission_id: str, request: Request) -> dict[str, Any]:
        captured["path"] = request.url.path
        captured["query"] = request.url.query
        captured["headers"] = dict(request.headers)
        assert submission_id == "submission-1"
        return safe_replay_payload

    @asynccontextmanager
    async def client_factory():
        transport = httpx.ASGITransport(app=challenge_app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://challenge-agent-challenge:8000"
        ) as client:
            yield client

    direct_response = TestClient(challenge_app).get(
        "/submissions/submission-1/task-events?cursor=0&limit=10"
    )
    proxy_client = TestClient(_proxy_app(registry, client_factory=client_factory))
    proxy_response = proxy_client.get(
        "/challenges/agent-challenge/submissions/submission-1/task-events?cursor=0&limit=10",
        headers={"Authorization": "Bearer should-not-forward"},
    )

    assert direct_response.status_code == 200
    assert proxy_response.status_code == 200
    assert proxy_response.json() == direct_response.json()
    assert captured["path"] == "/submissions/submission-1/task-events"
    assert captured["query"] == "cursor=0&limit=10"
    upstream_headers = captured["headers"]
    assert upstream_headers["x-platform-proxy"] == "true"
    assert upstream_headers["x-platform-challenge-slug"] == "agent-challenge"
    assert "authorization" not in upstream_headers
    forbidden_terms = (
        "private_ref",
        "signature",
        "nonce",
        "canonical_artifact_hash",
        "normalized_name",
        "artifact_path",
        "token",
        "kubeconfig",
        "database_url",
        "docker_auth",
    )
    serialized = proxy_response.text.lower()
    for term in forbidden_terms:
        assert term not in serialized


async def test_proxy_streams_agent_challenge_sse_status_events() -> None:
    registry = ChallengeRegistry()
    registry.create(
        ChallengeCreate(
            **{
                **_payload("agent-challenge"),
                "internal_base_url": "http://challenge-agent-challenge:8000",
            }
        )
    )
    registry.set_status("agent-challenge", ChallengeStatus.ACTIVE)
    first_event_sent = asyncio.Event()
    release_stream = asyncio.Event()
    captured: dict[str, Any] = {}

    class ControlledSseStream(httpx.AsyncByteStream):
        async def __aiter__(self):  # type: ignore[no-untyped-def]
            yield (
                b"id: 101\n"
                b"event: submission.status\n"
                b'data: {"id":101,"sequence":1,"submission_id":42,'
                b'"status":"queued","public_state":"queued",'
                b'"phase":"analysis","created_at":"2030-01-01T00:00:00Z"}\n\n'
            )
            first_event_sent.set()
            await release_stream.wait()
            yield (
                b"id: 102\n"
                b"event: submission.status\n"
                b'data: {"id":102,"sequence":2,"submission_id":42,'
                b'"status":"valid","public_state":"valid",'
                b'"phase":"complete","created_at":"2030-01-01T00:00:01Z"}\n\n'
            )

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["headers"] = dict(request.headers)
        captured["query"] = request.url.query.decode()
        return httpx.Response(
            200,
            headers={
                "content-type": "text/event-stream; charset=utf-8",
                "cache-control": "no-cache",
                "transfer-encoding": "chunked",
            },
            stream=ControlledSseStream(),
        )

    @asynccontextmanager
    async def client_factory():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://challenge-agent-challenge:8000"
        ) as client:
            yield client

    app = _proxy_app(registry, client_factory=client_factory)
    response_started = asyncio.Event()
    first_body_sent = asyncio.Event()
    messages: list[MutableMapping[str, Any]] = []
    request_delivered = False

    async def receive() -> MutableMapping[str, Any]:
        nonlocal request_delivered
        if not request_delivered:
            request_delivered = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.Event().wait()
        return {"type": "http.disconnect"}

    async def send(message: MutableMapping[str, Any]) -> None:
        messages.append(message)
        if message["type"] == "http.response.start":
            response_started.set()
        if message["type"] == "http.response.body" and message.get("body"):
            first_body_sent.set()

    scope: MutableMapping[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/challenges/agent-challenge/submissions/42/events",
        "raw_path": b"/challenges/agent-challenge/submissions/42/events",
        "query_string": b"tail=1",
        "headers": [
            (b"host", b"platform.test"),
            (b"last-event-id", b"100"),
            (b"authorization", b"Bearer should-not-forward"),
            (b"x-admin-token", b"should-not-forward"),
            (b"x-public-header", b"forward-me"),
        ],
        "client": ("testclient", 50000),
        "server": ("platform.test", 80),
    }
    task = asyncio.create_task(app(scope, receive, send))

    await asyncio.wait_for(response_started.wait(), timeout=1)
    await asyncio.wait_for(first_body_sent.wait(), timeout=1)
    assert await asyncio.wait_for(first_event_sent.wait(), timeout=1) is True
    assert not task.done()

    start = next(
        message for message in messages if message["type"] == "http.response.start"
    )
    response_headers = {
        key.decode().lower(): value.decode() for key, value in start["headers"]
    }
    assert start["status"] == 200
    assert response_headers["content-type"].startswith("text/event-stream")
    assert response_headers["cache-control"] == "no-cache"
    assert "transfer-encoding" not in response_headers

    first_body = next(
        message["body"]
        for message in messages
        if message["type"] == "http.response.body" and message.get("body")
    )
    assert first_body.startswith(b"id: 101\nevent: submission.status\n")
    assert b'"submission_id":42' in first_body
    assert captured["path"] == "/submissions/42/events"
    assert captured["query"] == "tail=1"
    upstream_headers = captured["headers"]
    assert upstream_headers["last-event-id"] == "100"
    assert upstream_headers["x-platform-proxy"] == "true"
    assert upstream_headers["x-platform-challenge-slug"] == "agent-challenge"
    assert upstream_headers["x-public-header"] == "forward-me"
    assert "authorization" not in upstream_headers
    assert "x-admin-token" not in upstream_headers

    release_stream.set()
    await asyncio.wait_for(task, timeout=1)
    body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    assert b"id: 102" in body


async def test_proxy_streams_agent_challenge_task_events_incrementally() -> None:
    registry = ChallengeRegistry()
    registry.create(
        ChallengeCreate(
            **{
                **_payload("agent-challenge"),
                "internal_base_url": "http://challenge-agent-challenge:8000",
            }
        )
    )
    registry.set_status("agent-challenge", ChallengeStatus.ACTIVE)
    first_event_sent = asyncio.Event()
    release_stream = asyncio.Event()
    captured: dict[str, Any] = {}

    class ControlledTaskEventStream(httpx.AsyncByteStream):
        async def __aiter__(self):  # type: ignore[no-untyped-def]
            yield (
                b"id: 1\n"
                b"event: task.progress\n"
                b'data: {"id":101,"sequence":1,"submission_id":"submission-1",'
                b'"event_type":"task.progress","task_id":"terminal-bench:hello-world",'
                b'"benchmark_id":"terminal-bench","public_state":"running",'
                b'"message":"started task","metadata":{"phase":"setup"},'
                b'"version_label":"v2","created_at":"2030-01-01T00:00:00Z"}\n\n'
            )
            first_event_sent.set()
            await release_stream.wait()
            yield (
                b"id: 2\n"
                b"event: task.completed\n"
                b'data: {"id":102,"sequence":2,"submission_id":"submission-1",'
                b'"event_type":"task.completed","task_id":"terminal-bench:hello-world",'
                b'"benchmark_id":"terminal-bench","public_state":"completed",'
                b'"message":"completed task","metadata":{"score":1.0},'
                b'"version_label":"v2","created_at":"2030-01-01T00:00:01Z"}\n\n'
            )

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["headers"] = dict(request.headers)
        captured["query"] = request.url.query.decode()
        return httpx.Response(
            200,
            headers={
                "content-type": "text/event-stream; charset=utf-8",
                "cache-control": "no-cache",
                "transfer-encoding": "chunked",
            },
            stream=ControlledTaskEventStream(),
        )

    @asynccontextmanager
    async def client_factory():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://challenge-agent-challenge:8000"
        ) as client:
            yield client

    app = _proxy_app(registry, client_factory=client_factory)
    response_started = asyncio.Event()
    first_body_sent = asyncio.Event()
    messages: list[MutableMapping[str, Any]] = []
    request_delivered = False

    async def receive() -> MutableMapping[str, Any]:
        nonlocal request_delivered
        if not request_delivered:
            request_delivered = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.Event().wait()
        return {"type": "http.disconnect"}

    async def send(message: MutableMapping[str, Any]) -> None:
        messages.append(message)
        if message["type"] == "http.response.start":
            response_started.set()
        if message["type"] == "http.response.body" and message.get("body"):
            first_body_sent.set()

    task_events_path = (
        "/challenges/agent-challenge/submissions/submission-1/task-events/stream"
    )
    scope: MutableMapping[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": task_events_path,
        "raw_path": task_events_path.encode(),
        "query_string": b"cursor=0",
        "headers": [
            (b"host", b"platform.test"),
            (b"last-event-id", b"1"),
            (b"authorization", b"Bearer should-not-forward"),
            (b"x-admin-token", b"should-not-forward"),
            (b"x-public-header", b"forward-me"),
        ],
        "client": ("testclient", 50000),
        "server": ("platform.test", 80),
    }
    task = asyncio.create_task(app(scope, receive, send))

    await asyncio.wait_for(response_started.wait(), timeout=1)
    await asyncio.wait_for(first_body_sent.wait(), timeout=1)
    assert await asyncio.wait_for(first_event_sent.wait(), timeout=1) is True
    assert not task.done()

    start = next(
        message for message in messages if message["type"] == "http.response.start"
    )
    response_headers = {
        key.decode().lower(): value.decode() for key, value in start["headers"]
    }
    assert start["status"] == 200
    assert response_headers["content-type"].startswith("text/event-stream")
    assert response_headers["cache-control"] == "no-cache"
    assert "transfer-encoding" not in response_headers

    first_body = next(
        message["body"]
        for message in messages
        if message["type"] == "http.response.body" and message.get("body")
    )
    assert first_body.startswith(b"id: 1\nevent: task.progress\n")
    assert b'"version_label":"v2"' in first_body
    assert b"private_ref" not in first_body
    assert b"signature" not in first_body
    assert captured["path"] == "/submissions/submission-1/task-events/stream"
    assert captured["query"] == "cursor=0"
    upstream_headers = captured["headers"]
    assert upstream_headers["last-event-id"] == "1"
    assert upstream_headers["x-platform-proxy"] == "true"
    assert upstream_headers["x-platform-challenge-slug"] == "agent-challenge"
    assert upstream_headers["x-public-header"] == "forward-me"
    assert "authorization" not in upstream_headers
    assert "x-admin-token" not in upstream_headers

    release_stream.set()
    await asyncio.wait_for(task, timeout=1)
    body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    assert b"id: 2" in body


def test_proxy_preserves_agent_challenge_sse_replay_conflict() -> None:
    registry = ChallengeRegistry()
    registry.create(
        ChallengeCreate(
            **{
                **_payload("agent-challenge"),
                "internal_base_url": "http://challenge-agent-challenge:8000",
            }
        )
    )
    registry.set_status("agent-challenge", ChallengeStatus.ACTIVE)
    captured: dict[str, Any] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(
            409,
            json={"detail": "unknown Last-Event-ID", "replay_from": 101},
            headers={"content-type": "application/json"},
        )

    @asynccontextmanager
    async def client_factory():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://challenge-agent-challenge:8000"
        ) as client:
            yield client

    proxy_client = TestClient(_proxy_app(registry, client_factory=client_factory))
    response = proxy_client.get(
        "/challenges/agent-challenge/submissions/42/events",
        headers={"Last-Event-ID": "99"},
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "unknown Last-Event-ID", "replay_from": 101}
    assert captured["headers"]["last-event-id"] == "99"


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


def test_proxy_blocks_agent_challenge_private_task_event_neighbors() -> None:
    registry = ChallengeRegistry()
    registry.create(
        ChallengeCreate(
            **{
                **_payload("agent-challenge"),
                "internal_base_url": "http://challenge-agent-challenge:8000",
            }
        )
    )
    registry.set_status("agent-challenge", ChallengeStatus.ACTIVE)
    upstream_calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request.url.path)
        return httpx.Response(200, json={"would_have_leaked": True})

    @asynccontextmanager
    async def client_factory():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://challenge-agent-challenge:8000"
        ) as client:
            yield client

    client = TestClient(_proxy_app(registry, client_factory=client_factory))

    for path in ("health", "version", "internal/v1/get_weights"):
        response = client.get(f"/challenges/agent-challenge/{path}")
        assert response.status_code == 403
        assert response.json() == {"detail": "Proxy path is not allowed"}

    assert upstream_calls == []


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
            "X-Hotkey": "should-not-forward",
            "X-Signature": "should-not-forward",
            "X-Nonce": "should-not-forward",
            "X-Timestamp": "should-not-forward",
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
    assert "x-hotkey" not in captured
    assert "x-signature" not in captured
    assert "x-nonce" not in captured
    assert "x-timestamp" not in captured


def test_proxy_preserves_signed_agent_challenge_env_headers_for_env_routes() -> None:
    registry = ChallengeRegistry()
    registry.create(
        ChallengeCreate(
            **{
                **_payload("agent-challenge"),
                "internal_base_url": "http://challenge-agent-challenge:8000",
            }
        )
    )
    registry.set_status("agent-challenge", ChallengeStatus.ACTIVE)
    sentinel_body = f"TOKEN_{secrets.token_urlsafe(24)}".encode()
    captured: list[dict[str, Any]] = []

    challenge_app = FastAPI()

    async def record_env_route(submission_id: str, request: Request) -> dict[str, str]:
        captured.append(
            {
                "submission_id": submission_id,
                "method": request.method,
                "path": request.url.path,
                "query": request.url.query,
                "headers": dict(request.headers),
                "body": await request.body(),
            }
        )
        return {"ok": "true", "method": request.method, "path": request.url.path}

    @challenge_app.get("/submissions/{submission_id}/env")
    async def get_env(submission_id: str, request: Request) -> dict[str, str]:
        return await record_env_route(submission_id, request)

    @challenge_app.put("/submissions/{submission_id}/env")
    async def put_env(submission_id: str, request: Request) -> dict[str, str]:
        return await record_env_route(submission_id, request)

    @challenge_app.post("/submissions/{submission_id}/env/confirm-empty")
    async def confirm_empty(submission_id: str, request: Request) -> dict[str, str]:
        return await record_env_route(submission_id, request)

    @challenge_app.post("/submissions/{submission_id}/launch")
    async def launch(submission_id: str, request: Request) -> dict[str, str]:
        return await record_env_route(submission_id, request)

    @asynccontextmanager
    async def client_factory():
        transport = httpx.ASGITransport(app=challenge_app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://challenge-agent-challenge:8000"
        ) as client:
            yield client

    proxy_client = TestClient(_proxy_app(registry, client_factory=client_factory))
    signed_headers = {
        "X-Hotkey": "miner-hotkey",
        "X-Signature": "miner-signature",
        "X-Nonce": "miner-nonce",
        "X-Timestamp": "1700000000",
        "X-Admin-Token": "admin-secret",
        "X-Platform-Internal-Token": "internal-secret",
        "X-Platform-Verified-Hotkey": "spoofed-hotkey",
        "X-Platform-Request-Hash": "spoofed-hash",
        "Authorization": "Bearer should-not-forward",
        "X-Public-Header": "forward-me",
    }
    requests = [
        (
            "GET",
            "/challenges/agent-challenge/submissions/sub-1/env?include_schema=1",
            b"",
        ),
        ("PUT", "/challenges/agent-challenge/submissions/sub-1/env", sentinel_body),
        (
            "POST",
            "/challenges/agent-challenge/submissions/sub-1/env/confirm-empty",
            b"",
        ),
        ("POST", "/challenges/agent-challenge/submissions/sub-1/launch", b""),
    ]

    for method, path, body in requests:
        response = proxy_client.request(
            method, path, content=body, headers=signed_headers
        )

        assert response.status_code == 200
        assert sentinel_body.decode() not in response.text

    assert [item["method"] for item in captured] == ["GET", "PUT", "POST", "POST"]
    assert [item["path"] for item in captured] == [
        "/submissions/sub-1/env",
        "/submissions/sub-1/env",
        "/submissions/sub-1/env/confirm-empty",
        "/submissions/sub-1/launch",
    ]
    assert captured[0]["query"] == "include_schema=1"
    assert captured[1]["body"] == sentinel_body
    assert captured[0]["body"] == b""
    for request_capture in captured:
        upstream_headers = request_capture["headers"]
        assert upstream_headers["x-hotkey"] == "miner-hotkey"
        assert upstream_headers["x-signature"] == "miner-signature"
        assert upstream_headers["x-nonce"] == "miner-nonce"
        assert upstream_headers["x-timestamp"] == "1700000000"
        assert upstream_headers["x-public-header"] == "forward-me"
        assert upstream_headers["x-platform-proxy"] == "true"
        assert upstream_headers["x-platform-challenge-slug"] == "agent-challenge"
        assert "authorization" not in upstream_headers
        assert "x-admin-token" not in upstream_headers
        assert "x-platform-internal-token" not in upstream_headers
        assert "x-platform-verified-hotkey" not in upstream_headers
        assert "x-platform-request-hash" not in upstream_headers

    registry_response = TestClient(_admin_app(registry)).get("/v1/registry")
    assert registry_response.status_code == 200
    registry_text = registry_response.text
    assert sentinel_body.decode() not in registry_text
    assert "miner-signature" not in registry_text
    assert "miner-nonce" not in registry_text


def test_agent_challenge_env_proxy_transport_failure_redacts_body_and_headers() -> None:
    registry = ChallengeRegistry()
    registry.create(
        ChallengeCreate(
            **{
                **_payload("agent-challenge"),
                "internal_base_url": "http://challenge-agent-challenge:8000",
            }
        )
    )
    registry.set_status("agent-challenge", ChallengeStatus.ACTIVE)
    sentinel_body = f"TOKEN_{secrets.token_urlsafe(24)}".encode()

    @asynccontextmanager
    async def failing_client_factory():
        async def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(
                "failed with miner-signature and upstream-token", request=request
            )

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://challenge-agent-challenge:8000"
        ) as client:
            yield client

    proxy_client = TestClient(
        _proxy_app(registry, client_factory=failing_client_factory)
    )
    response = proxy_client.put(
        "/challenges/agent-challenge/submissions/sub-1/env",
        content=sentinel_body,
        headers={
            "X-Hotkey": "miner-hotkey",
            "X-Signature": "miner-signature",
            "X-Nonce": "miner-nonce",
            "X-Timestamp": "1700000000",
            "Authorization": "Bearer upstream-token",
        },
    )

    assert response.status_code == 502
    assert response.json() == {"detail": "Challenge unavailable"}
    body = response.text
    assert sentinel_body.decode() not in body
    assert "miner-signature" not in body
    assert "miner-nonce" not in body
    assert "upstream-token" not in body
    assert "traceback" not in body.lower()


def test_proxy_transport_failure_returns_safe_502_without_sensitive_detail() -> None:
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

    @asynccontextmanager
    async def failing_client_factory():
        async def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(
                "failed http://challenge-demo:8000/submissions?token=secret-token",
                request=request,
            )

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://challenge-demo:8000"
        ) as client:
            yield client

    proxy_client = TestClient(
        _proxy_app(registry, client_factory=failing_client_factory)
    )

    response = proxy_client.post(
        "/challenges/demo/submissions?signature=secret-signature&nonce=secret-nonce",
        json={"answer": 42},
        headers={
            "Authorization": "Bearer secret-token",
            "X-Signature": "secret-signature",
            "X-Nonce": "secret-nonce",
        },
    )

    assert response.status_code == 502
    assert response.json() == {"detail": "Challenge unavailable"}
    body = response.text.lower()
    assert "challenge-demo" not in body
    assert "secret-token" not in body
    assert "secret-signature" not in body
    assert "secret-nonce" not in body
    assert "traceback" not in body


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
    captured: dict[str, Any] = {"paths": []}

    class Cache:
        def get(self) -> dict[str, int]:
            return {"hk": 7}

    challenge_app = FastAPI()

    @challenge_app.post("/internal/v1/bridge/submissions")
    async def bridge(request: Request) -> dict[str, object]:
        captured["paths"].append(request.url.path)
        captured["headers"] = dict(request.headers)
        captured["body"] = await request.body()
        return {"id": "sub-1", "status": "pending"}

    @challenge_app.get("/v1/submissions/{submission_id}")
    async def submission_detail(
        submission_id: str,
        request: Request,
    ) -> dict[str, object]:
        captured["paths"].append(request.url.path)
        return {"id": submission_id, "status": "received"}

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

    status_response = proxy_client.get("/v1/challenges/demo/submissions/sub-1")

    assert status_response.status_code == 200
    assert status_response.json() == {"id": "sub-1", "status": "received"}
    assert captured["paths"] == [
        "/internal/v1/bridge/submissions",
        "/v1/submissions/sub-1",
    ]


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


def test_signed_upload_bridge_strict_rejects_unknown_hotkey() -> None:
    registry = ChallengeRegistry()
    registry.create(ChallengeCreate(**_payload()))
    registry.set_status("demo", ChallengeStatus.ACTIVE)

    class Cache:
        def get(self) -> dict[str, int]:
            return {"known": 7}

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
            raise httpx.ConnectError("unexpected upstream call", request=request)

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

    response = client.post(
        "/v1/challenges/demo/submissions",
        content=b"zip-bytes",
        headers={
            "X-Hotkey": "unknown",
            "X-Signature": "valid",
            "X-Nonce": "nonce-strict-unknown",
            "X-Timestamp": "1000",
        },
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "unknown hotkey"}


def test_signed_upload_bridge_bypass_forwards_unknown_without_uid() -> None:
    registry = ChallengeRegistry()
    registry.create(ChallengeCreate(**_payload()))
    registry.set_status("demo", ChallengeStatus.ACTIVE)
    captured: dict[str, Any] = {}

    class Cache:
        def get(self) -> dict[str, int]:
            return {"known": 7}

    challenge_app = FastAPI()

    @challenge_app.post("/internal/v1/bridge/submissions")
    async def bridge(request: Request) -> dict[str, object]:
        captured["headers"] = dict(request.headers)
        captured["body"] = await request.body()
        return {"id": "sub-bypass", "status": "pending"}

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
        require_registered_hotkey=False,
        signature_verifier=lambda _hotkey, _message, signature: signature == "valid",
    )
    client = TestClient(
        create_proxy_app(
            registry=registry,
            client_factory=client_factory,
            miner_verifier=verifier,
            challenge_token_provider=lambda _slug: "challenge-token",
        )
    )

    response = client.post(
        "/v1/challenges/demo/submissions",
        content=b"zip-bytes",
        headers={
            "Content-Type": "application/zip",
            "X-Hotkey": "unknown",
            "X-Signature": "valid",
            "X-Nonce": "nonce-bypass-unknown",
            "X-Timestamp": "1000",
            "X-Platform-Verified-Uid": "spoof",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"id": "sub-bypass", "status": "pending"}
    headers = captured["headers"]
    assert headers["authorization"] == "Bearer challenge-token"
    assert headers["x-platform-verified-hotkey"] == "unknown"
    assert headers["x-platform-verified-nonce"] == "nonce-bypass-unknown"
    assert "x-platform-verified-uid" not in headers
    assert captured["body"] == b"zip-bytes"


def test_signed_upload_bridge_disabled_registration_rejects_blocked_uid() -> None:
    registry = ChallengeRegistry()
    registry.create(ChallengeCreate(**_payload()))
    registry.set_status("demo", ChallengeStatus.ACTIVE)

    class Cache:
        def get(self) -> dict[str, int]:
            return {"known": 0}

    verifier = MinerUploadVerifier(
        netuid=42,
        nonce_store=FakeNonceStore(),
        metagraph_cache=Cache(),  # type: ignore[arg-type]
        now_fn=lambda: 1_000,
        require_registered_hotkey=False,
        signature_verifier=lambda _hotkey, _message, signature: signature == "valid",
    )

    @asynccontextmanager
    async def failing_client_factory():
        async def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("unexpected upstream call", request=request)

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

    response = client.post(
        "/v1/challenges/demo/submissions",
        content=b"zip-bytes",
        headers={
            "X-Hotkey": "known",
            "X-Signature": "valid",
            "X-Nonce": "nonce-blocked",
            "X-Timestamp": "1000",
        },
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "blocked uid"}


def test_signed_upload_bridge_bypass_keeps_signature_time_replay_guards() -> None:
    registry = ChallengeRegistry()
    registry.create(ChallengeCreate(**_payload()))
    registry.set_status("demo", ChallengeStatus.ACTIVE)

    class Cache:
        def get(self) -> dict[str, int]:
            return {"known": 7}

    verifier = MinerUploadVerifier(
        netuid=42,
        nonce_store=FakeNonceStore(),
        metagraph_cache=Cache(),  # type: ignore[arg-type]
        now_fn=lambda: 1_000,
        require_registered_hotkey=False,
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
        "X-Hotkey": "unknown",
        "X-Signature": "valid",
        "X-Nonce": "nonce-bypass-replay",
        "X-Timestamp": "1000",
    }

    invalid_signature = client.post(
        "/v1/challenges/demo/submissions",
        content=b"zip-bytes",
        headers={**headers, "X-Signature": "invalid", "X-Nonce": "nonce-invalid"},
    )
    assert invalid_signature.status_code == 401
    assert invalid_signature.json() == {"detail": "invalid signature"}

    stale = client.post(
        "/v1/challenges/demo/submissions",
        content=b"zip-bytes",
        headers={**headers, "X-Nonce": "nonce-stale", "X-Timestamp": "1"},
    )
    assert stale.status_code == 401
    assert stale.json() == {"detail": "stale signature"}

    first = client.post(
        "/v1/challenges/demo/submissions",
        content=b"zip-bytes",
        headers=headers,
    )
    assert first.status_code == 502
    assert first.json() == {"detail": "Challenge unavailable"}

    replay = client.post(
        "/v1/challenges/demo/submissions",
        content=b"zip-bytes",
        headers=headers,
    )
    assert replay.status_code == 409
    assert replay.json() == {"detail": "nonce already used"}


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


def test_production_admin_accepts_pinned_image_and_latest_digest_update() -> None:
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
        json={"image": f"ghcr.io/platformnetwork/demo:latest@{digest}"},
        headers={"X-Admin-Token": "admin-secret"},
    )
    assert patch.status_code == 200
    assert patch.json()["image"] == f"ghcr.io/platformnetwork/demo:latest@{digest}"

    unsafe_patch = client.patch(
        "/v1/admin/challenges/demo",
        json={"image": "ghcr.io/platformnetwork/demo:latest"},
        headers={"X-Admin-Token": "admin-secret"},
    )
    assert unsafe_patch.status_code == 400
    assert "digest" in unsafe_patch.text


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
