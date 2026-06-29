"""Tests for the ``base validator subscribe`` CLI + client round-trip.

Covers VAL-VDIR-SUB-005: the CLI builds the subscription request, signs it with
the validator sr25519 keypair, and POSTs it through the coordination client; the
persisted set returned by the server matches the slugs requested on the command
line.
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from httpx import ASGITransport
from sqlalchemy import select
from typer.testing import CliRunner

import base.cli_app.main as cli_main
from base.bittensor.metagraph_cache import MetagraphCache
from base.cli_app.main import app
from base.db import Base, Validator
from base.db.session import create_engine, create_session_factory
from base.master.app_proxy import create_proxy_app
from base.master.validator_coordination import ValidatorCoordinationService
from base.schemas.validator import ValidatorSubscriptionResponse, ValidatorView
from base.security.validator_auth import (
    MetagraphValidatorEligibility,
    SqlAlchemyValidatorNonceStore,
    ValidatorSignedRequestVerifier,
)
from base.validator.agent import CoordinationClient

NOW_EPOCH = 1_750_000_000.0
ADMIN_TOKEN = "admin-secret-token"


class FakeClock:
    def __init__(self, epoch: float) -> None:
        self.epoch = float(epoch)

    def time(self) -> float:
        return self.epoch

    def now(self) -> datetime:
        return datetime.fromtimestamp(self.epoch, UTC)


class FakeNonceStore:
    async def reserve(self, **kwargs: Any) -> None:
        return None


class FakeCache:
    def get(self) -> dict[str, int]:
        return {}


class FakeRegistry:
    def __init__(self, active: tuple[str, ...] = ("agent-challenge", "prism")) -> None:
        self.active = list(active)

    async def list(self, *, active_only: bool = False) -> list[Any]:
        return [SimpleNamespace(slug=slug) for slug in self.active]


def _sign(hotkey: str, canonical: str) -> str:
    return hashlib.sha256(f"{hotkey}:{canonical}".encode()).hexdigest()


def _verifier(hotkey: str, message: bytes, signature: str) -> bool:
    return signature == _sign(hotkey, message.decode())


class FakeSigner:
    def __init__(self, hotkey: str) -> None:
        self._hotkey = hotkey

    @property
    def hotkey(self) -> str:
        return self._hotkey

    def sign(self, message: bytes) -> str:
        return _sign(self._hotkey, message.decode())


class _Harness:
    def __init__(self, app: Any, session_factory: Any, clock: FakeClock) -> None:
        self.transport = ASGITransport(app=app)
        self.session_factory = session_factory
        self.clock = clock

    def client(self, hotkey: str = "permitted") -> CoordinationClient:
        return CoordinationClient(
            "http://testserver",
            FakeSigner(hotkey),
            transport=self.transport,
            now_fn=self.clock.time,
        )

    async def stored_subscriptions(self, hotkey: str = "permitted") -> list[str] | None:
        async with self.session_factory() as session:
            row = (
                await session.execute(
                    select(Validator).where(Validator.hotkey == hotkey)
                )
            ).scalar_one_or_none()
            return None if row is None else list(row.subscriptions)


async def _build_harness() -> tuple[_Harness, Any]:
    engine = create_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_factory = create_session_factory(engine)

    cache = MetagraphCache(netuid=1, ttl_seconds=300)
    cache.update_from_metagraph(["permitted"], validator_permits=[True], stakes=[100.0])
    clock = FakeClock(NOW_EPOCH)
    verifier = ValidatorSignedRequestVerifier(
        nonce_store=SqlAlchemyValidatorNonceStore(session_factory),
        eligibility=MetagraphValidatorEligibility(cache),
        signature_verifier=_verifier,
        ttl_seconds=300,
        now_fn=clock.time,
    )
    service = ValidatorCoordinationService(session_factory, now_fn=clock.now)
    app_proxy = create_proxy_app(
        registry=FakeRegistry(),
        nonce_store=FakeNonceStore(),
        metagraph_cache=FakeCache(),  # type: ignore[arg-type]
        validator_service=service,
        validator_verifier=verifier,
        admin_token_provider=lambda: ADMIN_TOKEN,
    )
    harness = _Harness(app_proxy, session_factory, clock)
    # register the validator so it has a persisted row to subscribe against.
    await service.register(
        hotkey="permitted", uid=1, capabilities=["cpu", "gpu"], version="1.0.0"
    )
    return harness, engine


@pytest.fixture
async def harness() -> AsyncIterator[_Harness]:
    h, engine = await _build_harness()
    try:
        yield h
    finally:
        await engine.dispose()


# VAL-VDIR-SUB-005 (client signs the exact bytes; server persists + round-trips)
async def test_client_subscribe_signs_and_round_trips(harness: _Harness) -> None:
    client = harness.client()
    response = await client.subscribe(["prism", "agent-challenge"])

    assert isinstance(response, ValidatorSubscriptionResponse)
    assert response.subscriptions == ["prism", "agent-challenge"]
    assert await harness.stored_subscriptions() == ["prism", "agent-challenge"]


# VAL-VDIR-SUB-005 (clearing via an empty set round-trips)
async def test_client_subscribe_empty_clears(harness: _Harness) -> None:
    client = harness.client()
    await client.subscribe(["prism"])
    assert await harness.stored_subscriptions() == ["prism"]

    response = await client.subscribe([])
    assert response.subscriptions == []
    assert await harness.stored_subscriptions() == []


class RecordingClient:
    """Stand-in coordination client recording the slugs the CLI sends."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.hotkey = "validator-hotkey"

    async def subscribe(self, slugs: Sequence[str]) -> ValidatorSubscriptionResponse:
        deduped = list(dict.fromkeys(slugs))
        self.calls.append(list(slugs))
        return ValidatorSubscriptionResponse(
            validator=ValidatorView(
                hotkey=self.hotkey,
                status="online",
                subscriptions=deduped,
                registered_at=datetime.now(UTC),
            ),
            subscriptions=deduped,
        )


def _patch_cli(monkeypatch: pytest.MonkeyPatch) -> RecordingClient:
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda config: SimpleNamespace(
            environment="development",
            observability=SimpleNamespace(
                log_json=False,
                sentry_dsn=None,
                otel_service_name="base",
                otel_endpoint=None,
            ),
        ),
    )
    monkeypatch.setattr(cli_main, "configure_logging", lambda *a, **k: None)
    client = RecordingClient()
    monkeypatch.setattr(cli_main, "_build_coordination_client", lambda settings: client)
    return client


# VAL-VDIR-SUB-005 (CLI parses --challenges and posts via the coordination client)
def test_cli_subscribe_sends_parsed_challenges(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _patch_cli(monkeypatch)
    result = CliRunner().invoke(
        app, ["validator", "subscribe", "--challenges", "prism, agent-challenge"]
    )
    assert result.exit_code == 0, result.output
    assert client.calls == [["prism", "agent-challenge"]]
    assert "prism" in result.output and "agent-challenge" in result.output


# VAL-VDIR-SUB-005 (empty --challenges clears the subscription)
def test_cli_subscribe_empty_clears(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _patch_cli(monkeypatch)
    result = CliRunner().invoke(app, ["validator", "subscribe", "--challenges", ""])
    assert result.exit_code == 0, result.output
    assert client.calls == [[]]
    assert "Cleared" in result.output
