from __future__ import annotations

from contextlib import asynccontextmanager
from decimal import Decimal

import httpx
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
)


def _payload(slug: str = "demo") -> dict[str, object]:
    return {
        "slug": slug,
        "name": "Demo",
        "image": "ghcr.io/platformnetwork/demo:1.0.0",
        "version": "1.0.0",
        "emission_percent": "40.0",
    }


def test_admin_challenge_crud_and_registry_active_only() -> None:
    registry = ChallengeRegistry()
    app = create_admin_app(
        registry=registry, admin_token_provider=lambda: "admin-secret"
    )
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
    client = TestClient(create_admin_app(registry=registry))

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


def test_challenges_dashboard_svg_accepts_future_metrics_provider() -> None:
    class StaticMetricsProvider:
        def metrics_for(self, challenge: ChallengeRecord) -> ChallengeMetrics:
            return ChallengeMetrics(miner_count=7)

    registry = ChallengeRegistry()
    registry.create(ChallengeCreate(**_payload()))
    client = TestClient(
        create_admin_app(registry=registry, metrics_provider=StaticMetricsProvider())
    )

    response = client.get("/v1/challenges/dashboard.svg")

    assert response.status_code == 200
    assert ">7</text>" in response.text


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
    client = TestClient(create_proxy_app(registry=registry))

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

    proxy_client = TestClient(
        create_proxy_app(registry=registry, client_factory=client_factory)
    )
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
