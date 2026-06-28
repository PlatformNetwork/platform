"""Tests for the open validator directory API ``GET /v1/validators/public``.

Covers VAL-VDIR-API-001 (safe fields only, no secrets), VAL-VDIR-API-002
(per-challenge filter + graceful unknown slug), and VAL-VDIR-API-003 (open
public route vs token-gated admin route).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from base.bittensor.identity_cache import (
    SOURCE_CHAIN,
    IdentityCache,
    ResolvedIdentity,
    ValidatorIdentityResolver,
)
from base.bittensor.metagraph_cache import MetagraphCache
from base.db import Base, ValidatorStatus
from base.db.models import Validator
from base.db.session import create_engine, create_session_factory, session_scope
from base.master.app_proxy import create_proxy_app
from base.master.validator_coordination import ValidatorCoordinationService
from base.security.validator_auth import (
    MetagraphValidatorEligibility,
    SqlAlchemyValidatorNonceStore,
    ValidatorSignedRequestVerifier,
)

ADMIN_TOKEN = "admin-secret-token"
SUBNET_NAME = "BASE Subnet"
SUBNET_LOGO = "https://example.test/subnet.png"


class FakeNonceStore:
    async def reserve(self, **kwargs: Any) -> None:
        return None


class FakeCache:
    def get(self) -> dict[str, int]:
        return {}


def _now() -> datetime:
    return datetime(2024, 1, 1, tzinfo=UTC)


class _Harness:
    def __init__(
        self,
        client: AsyncClient,
        service: ValidatorCoordinationService,
        session_factory: Any,
    ) -> None:
        self.client = client
        self.service = service
        self.session_factory = session_factory

    async def public(self, *, challenge: str | None = None):
        params = {"challenge": challenge} if challenge is not None else None
        return await self.client.get("/v1/validators/public", params=params)

    async def admin(self, *, token: str | None = None):
        headers = {"X-Admin-Token": token} if token is not None else {}
        return await self.client.get("/v1/validators", headers=headers)

    async def set_offline(self, hotkey: str) -> None:
        async with session_scope(self.session_factory) as session:
            row = (
                await session.execute(
                    select(Validator).where(Validator.hotkey == hotkey)
                )
            ).scalar_one()
            row.status = ValidatorStatus.OFFLINE


async def _build_harness() -> tuple[_Harness, Any]:
    engine = create_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_factory = create_session_factory(engine)

    service = ValidatorCoordinationService(session_factory, now_fn=_now)

    eligibility_cache = MetagraphCache(netuid=1, ttl_seconds=300)
    eligibility_cache.update_from_metagraph(
        ["val-gpu"], validator_permits=[True], stakes=[100.0]
    )
    verifier = ValidatorSignedRequestVerifier(
        nonce_store=SqlAlchemyValidatorNonceStore(session_factory),
        eligibility=MetagraphValidatorEligibility(eligibility_cache),
        ttl_seconds=300,
    )

    identity_cache = IdentityCache(netuid=1, static=True)
    identity_cache.seed_static(
        {
            "val-gpu": ResolvedIdentity(
                display_name="GPU One",
                logo_url="https://example.test/gpu.png",
                source=SOURCE_CHAIN,
            )
        },
        subnet_identity=ResolvedIdentity(
            display_name=SUBNET_NAME, logo_url=SUBNET_LOGO, source=SOURCE_CHAIN
        ),
    )
    resolver = ValidatorIdentityResolver(cache=identity_cache)

    app = create_proxy_app(
        registry=object(),
        nonce_store=FakeNonceStore(),
        metagraph_cache=FakeCache(),  # type: ignore[arg-type]
        runtime_controller=object(),  # type: ignore[arg-type]
        validator_service=service,
        validator_verifier=verifier,
        identity_resolver=resolver,
        admin_token_provider=lambda: ADMIN_TOKEN,
    )
    transport = ASGITransport(app=app)
    client = AsyncClient(transport=transport, base_url="http://testserver")
    return _Harness(client, service, session_factory), engine


@pytest.fixture
async def harness() -> AsyncIterator[_Harness]:
    h, engine = await _build_harness()
    try:
        yield h
    finally:
        await h.client.aclose()
        await engine.dispose()


async def _seed_directory(harness: _Harness) -> None:
    # Unrestricted (empty subscriptions) -> validates ALL challenges, with an
    # on-chain identity from the static cache.
    await harness.service.register(
        hotkey="val-gpu", uid=1, capabilities=["cpu", "gpu"], version="1.0.0"
    )
    # Restricted to prism, plus a self-declared identity smuggled into
    # last_seen_meta alongside a would-be secret.
    await harness.service.register(
        hotkey="val-prism",
        uid=2,
        capabilities=["cpu", "gpu"],
        version="1.0.0",
        last_seen_meta={
            "display_name": "Prism Validator",
            "logo_url": "https://example.test/prism.png",
            "broker_token": "SUPER-SECRET-TOKEN",
            "openrouter_api_key": "sk-leak-me",
        },
    )
    await harness.service.set_subscriptions(hotkey="val-prism", slugs=["prism"])
    # Restricted to agent-challenge only.
    await harness.service.register(
        hotkey="val-ac", uid=3, capabilities=["cpu"], version="1.0.0"
    )
    await harness.service.set_subscriptions(hotkey="val-ac", slugs=["agent-challenge"])


# VAL-VDIR-API-003
async def test_public_route_open_admin_route_gated(harness: _Harness) -> None:
    await _seed_directory(harness)

    public = await harness.public()
    assert public.status_code == 200

    missing = await harness.admin()
    assert missing.status_code in (401, 403)

    bad = await harness.admin(token="wrong")
    assert bad.status_code in (401, 403)

    ok = await harness.admin(token=ADMIN_TOKEN)
    assert ok.status_code == 200


# VAL-VDIR-API-001
async def test_public_returns_safe_fields_and_subnet(harness: _Harness) -> None:
    await _seed_directory(harness)

    response = await harness.public()
    assert response.status_code == 200
    body = response.json()

    assert body["subnet"] == {"display_name": SUBNET_NAME, "logo_url": SUBNET_LOGO}

    by_hotkey = {row["hotkey"]: row for row in body["validators"]}
    assert set(by_hotkey) == {"val-gpu", "val-prism", "val-ac"}

    gpu = by_hotkey["val-gpu"]
    assert gpu["uid"] == 1
    assert gpu["status"] == "online"
    assert gpu["online"] is True
    assert gpu["capabilities"] == ["cpu", "gpu"]
    assert gpu["subscriptions"] == []
    assert gpu["last_heartbeat_at"] is not None
    # On-chain identity resolved from the static cache.
    assert gpu["identity"] == {
        "display_name": "GPU One",
        "logo_url": "https://example.test/gpu.png",
    }
    # Only the safe fields are present (no version, no last_seen_meta).
    assert set(gpu) == {
        "hotkey",
        "uid",
        "status",
        "online",
        "capabilities",
        "subscriptions",
        "last_heartbeat_at",
        "identity",
    }

    prism = by_hotkey["val-prism"]
    # Self-declared identity resolved from last_seen_meta (UNTRUSTED fallback).
    assert prism["identity"] == {
        "display_name": "Prism Validator",
        "logo_url": "https://example.test/prism.png",
    }


# VAL-VDIR-API-001
async def test_public_never_leaks_raw_meta_or_secrets(harness: _Harness) -> None:
    await _seed_directory(harness)

    response = await harness.public()
    raw = response.text
    assert "last_seen_meta" not in raw
    assert "SUPER-SECRET-TOKEN" not in raw
    assert "broker_token" not in raw
    assert "openrouter_api_key" not in raw
    assert "sk-leak-me" not in raw


# VAL-VDIR-API-001
async def test_public_reports_offline_status(harness: _Harness) -> None:
    await _seed_directory(harness)
    await harness.set_offline("val-ac")

    response = await harness.public()
    by_hotkey = {row["hotkey"]: row for row in response.json()["validators"]}
    assert by_hotkey["val-ac"]["status"] == "offline"
    assert by_hotkey["val-ac"]["online"] is False


# VAL-VDIR-API-002
async def test_challenge_filter_includes_subscribed_and_unrestricted(
    harness: _Harness,
) -> None:
    await _seed_directory(harness)

    prism = await harness.public(challenge="prism")
    assert prism.status_code == 200
    prism_keys = {row["hotkey"] for row in prism.json()["validators"]}
    # subscribed (val-prism) + unrestricted (val-gpu); NOT the ac-only validator.
    assert prism_keys == {"val-gpu", "val-prism"}

    ac = await harness.public(challenge="agent-challenge")
    ac_keys = {row["hotkey"] for row in ac.json()["validators"]}
    assert ac_keys == {"val-gpu", "val-ac"}

    # Two different challenges yield different validator sets.
    assert prism_keys != ac_keys


# VAL-VDIR-API-002
async def test_unknown_challenge_returns_only_unrestricted(harness: _Harness) -> None:
    await _seed_directory(harness)

    response = await harness.public(challenge="does-not-exist")
    assert response.status_code == 200
    keys = {row["hotkey"] for row in response.json()["validators"]}
    # Unknown slug is graceful: only unrestricted validators match.
    assert keys == {"val-gpu"}


async def test_public_empty_directory(harness: _Harness) -> None:
    response = await harness.public()
    assert response.status_code == 200
    body = response.json()
    assert body["validators"] == []
    assert body["subnet"] == {"display_name": SUBNET_NAME, "logo_url": SUBNET_LOGO}


async def test_public_without_validator_service_returns_empty() -> None:
    app = create_proxy_app(
        registry=object(),
        nonce_store=FakeNonceStore(),
        metagraph_cache=FakeCache(),  # type: ignore[arg-type]
        runtime_controller=object(),  # type: ignore[arg-type]
        admin_token_provider=lambda: ADMIN_TOKEN,
    )
    transport = ASGITransport(app=app)
    client = AsyncClient(transport=transport, base_url="http://testserver")
    try:
        response = await client.get("/v1/validators/public")
        assert response.status_code == 200
        assert response.json() == {"validators": [], "subnet": None}
    finally:
        await client.aclose()


async def test_public_without_identity_resolver_omits_identity() -> None:
    engine = create_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_factory = create_session_factory(engine)
    service = ValidatorCoordinationService(session_factory, now_fn=_now)
    await service.register(
        hotkey="val-gpu", uid=1, capabilities=["gpu"], version="1.0.0"
    )
    app = create_proxy_app(
        registry=object(),
        nonce_store=FakeNonceStore(),
        metagraph_cache=FakeCache(),  # type: ignore[arg-type]
        runtime_controller=object(),  # type: ignore[arg-type]
        validator_service=service,
        admin_token_provider=lambda: ADMIN_TOKEN,
    )
    transport = ASGITransport(app=app)
    client = AsyncClient(transport=transport, base_url="http://testserver")
    try:
        response = await client.get("/v1/validators/public")
        assert response.status_code == 200
        body = response.json()
        assert body["subnet"] is None
        assert body["validators"][0]["identity"] is None
    finally:
        await client.aclose()
        await engine.dispose()
