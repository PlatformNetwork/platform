"""Config-driven static/mock metagraph seam (architecture.md G1).

A no-chain LIVE deploy can make N specified validator hotkeys eligible WITHOUT a
real Subtensor by configuring ``network.mock_metagraph``. These tests encode the
VAL-CODE-MMG-001..005 assertions:

* MMG-001: a configured permitted hotkey is accepted (no live Subtensor built).
* MMG-002: default-off is behavior-preserving (live path unchanged when unset).
* MMG-003: a non-listed / permit=false hotkey is rejected (403) even when signed.
* MMG-004: the runtime factory seeds the cache without constructing a Subtensor.
* MMG-005: miners stay submit-eligible via the allowlist, independent of the set.
"""

from __future__ import annotations

import hashlib
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from base.bittensor.factory import create_bittensor_runtime
from base.bittensor.metagraph_cache import MetagraphCache
from base.config.loader import load_settings
from base.config.settings import NetworkSettings
from base.security.miner_auth import MinerUploadVerifier
from base.security.validator_auth import (
    MetagraphValidatorEligibility,
    SqlAlchemyValidatorNonceStore,
    ValidatorIdentity,
    ValidatorSignedRequestVerifier,
    build_validator_auth_dependency,
    canonical_validator_request,
)

VALIDATOR_HOTKEY = "validator-hotkey"
UNPERMITTED_HOTKEY = "no-permit-hotkey"
ABSENT_HOTKEY = "absent-hotkey"
MINER_HOTKEY = "miner-hotkey"
NOW_EPOCH = 1_750_000_000.0


def _explode_bittensor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Install a ``bittensor`` whose Subtensor/Wallet blow up if constructed."""

    class _Boom:
        def __init__(self, **kwargs: object) -> None:
            raise AssertionError("mock metagraph must not construct a live Subtensor")

    monkeypatch.setitem(
        sys.modules,
        "bittensor",
        SimpleNamespace(Subtensor=_Boom, Wallet=_Boom),
    )


def _mock_settings(tmp_path: Path):
    config = tmp_path / "config.yaml"
    config.write_text(
        "\n".join(
            [
                "network:",
                "  netuid: 7",
                "  chain_endpoint: ws://localhost:9944",
                "  mock_metagraph:",
                f"    - hotkey: {VALIDATOR_HOTKEY}",
                "      uid: 3",
                "      validator_permit: true",
                "      stake: 1000.0",
                f"    - hotkey: {UNPERMITTED_HOTKEY}",
                "      uid: 4",
                "      validator_permit: false",
                "      stake: 0.0",
                "master:",
                "  metagraph_cache_ttl_seconds: 300",
            ]
        ),
        encoding="utf-8",
    )
    return load_settings(config)


def _sign(hotkey: str, canonical: str) -> str:
    return hashlib.sha256(f"{hotkey}:{canonical}".encode()).hexdigest()


def _signature_verifier(hotkey: str, message: bytes, signature: str) -> bool:
    return signature == _sign(hotkey, message.decode())


def _signed_headers(*, hotkey: str, nonce: str, body: bytes = b"{}") -> dict[str, str]:
    ts = str(int(NOW_EPOCH))
    canonical = canonical_validator_request(
        method="POST",
        path="/protected",
        query_string="",
        timestamp=ts,
        nonce=nonce,
        body=body,
    )
    return {
        "X-Hotkey": hotkey,
        "X-Signature": _sign(hotkey, canonical),
        "X-Nonce": nonce,
        "X-Timestamp": ts,
    }


# ---------------------------------------------------------------------------
# Settings parsing
# ---------------------------------------------------------------------------


def test_network_settings_mock_metagraph_defaults_empty() -> None:
    # MMG-002: the seam is OFF by default.
    assert NetworkSettings().mock_metagraph == []


def test_load_settings_parses_mock_metagraph(tmp_path: Path) -> None:
    settings = _mock_settings(tmp_path)
    nodes = settings.network.mock_metagraph
    assert [node.hotkey for node in nodes] == [VALIDATOR_HOTKEY, UNPERMITTED_HOTKEY]
    assert nodes[0].uid == 3
    assert nodes[0].validator_permit is True
    assert nodes[0].stake == 1000.0
    assert nodes[1].validator_permit is False


# ---------------------------------------------------------------------------
# MMG-004 / MMG-002: factory seeding without a live Subtensor
# ---------------------------------------------------------------------------


def test_factory_seeds_cache_without_subtensor_when_mock_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # MMG-004: when configured, seed MetagraphCache from the static set and never
    # construct a live Subtensor (the patched Subtensor raises if instantiated).
    _explode_bittensor(monkeypatch)

    runtime = create_bittensor_runtime(_mock_settings(tmp_path))

    cache = runtime.metagraph_cache
    assert cache.subtensor is None
    assert cache.netuid == 7
    assert cache.hotkey_to_uid == {VALIDATOR_HOTKEY: 3, UNPERMITTED_HOTKEY: 4}
    assert cache.validator_permit(VALIDATOR_HOTKEY) is True
    assert cache.stake(VALIDATOR_HOTKEY) == 1000.0
    assert cache.is_validator(VALIDATOR_HOTKEY) is True
    assert cache.is_validator(UNPERMITTED_HOTKEY) is False
    assert runtime.weight_setter is None


def test_factory_static_cache_never_refreshes_from_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A static cache stays valid past its TTL without ever touching a subtensor.
    _explode_bittensor(monkeypatch)
    cache = create_bittensor_runtime(_mock_settings(tmp_path)).metagraph_cache

    assert cache.expired() is False
    cache._updated_at = 0.0  # force TTL to look long-expired
    # get() must NOT call refresh() (which would require a subtensor).
    assert cache.get() == {VALIDATOR_HOTKEY: 3, UNPERMITTED_HOTKEY: 4}
    assert cache.get(force=True) == {VALIDATOR_HOTKEY: 3, UNPERMITTED_HOTKEY: 4}


def test_factory_builds_live_subtensor_when_mock_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # MMG-002: with no mock configured the live-metagraph path is unchanged.
    calls: list[dict[str, object]] = []

    class _Subtensor:
        def __init__(self, **kwargs: object) -> None:
            calls.append(kwargs)

    monkeypatch.setitem(
        sys.modules, "bittensor", SimpleNamespace(Subtensor=_Subtensor, Wallet=object)
    )
    config = tmp_path / "config.yaml"
    config.write_text(
        "network:\n  netuid: 42\n  chain_endpoint: ws://localhost:9944\n",
        encoding="utf-8",
    )
    runtime = create_bittensor_runtime(load_settings(config))

    assert calls == [{"network": "ws://localhost:9944"}]
    assert runtime.metagraph_cache.subtensor is not None


# ---------------------------------------------------------------------------
# MetagraphCache.update_from_metagraph honours explicit uids
# ---------------------------------------------------------------------------


def test_update_from_metagraph_honours_explicit_uids() -> None:
    cache = MetagraphCache(netuid=1)
    cache.update_from_metagraph(
        ["a", "b"],
        uids=[5, 9],
        validator_permits=[True, False],
        stakes=[10.0, 2.0],
    )
    assert cache.hotkey_to_uid == {"a": 5, "b": 9}
    # permits/stakes stay positionally aligned with the hotkeys list.
    assert cache.validator_permit("a") is True
    assert cache.stake("b") == 2.0


# ---------------------------------------------------------------------------
# MMG-001 / MMG-003: eligibility dependency over the seeded cache
# ---------------------------------------------------------------------------


@pytest.fixture
async def mock_auth_client(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[AsyncClient]:
    from base.db import Base
    from base.db.session import create_engine, create_session_factory

    _explode_bittensor(monkeypatch)
    tmp_path = tmp_path_factory.mktemp("mock_auth")
    cache = create_bittensor_runtime(_mock_settings(tmp_path)).metagraph_cache

    engine = create_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_factory = create_session_factory(engine)

    verifier = ValidatorSignedRequestVerifier(
        nonce_store=SqlAlchemyValidatorNonceStore(session_factory),
        eligibility=MetagraphValidatorEligibility(cache),
        signature_verifier=_signature_verifier,
        ttl_seconds=300,
        now_fn=lambda: NOW_EPOCH,
    )
    dependency = build_validator_auth_dependency(verifier)

    app = FastAPI()

    @app.post("/protected")
    async def protected(
        identity: ValidatorIdentity = Depends(dependency),
    ) -> dict[str, object]:
        return {"hotkey": identity.hotkey, "uid": identity.uid}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
    await engine.dispose()


async def test_mmg001_permitted_hotkey_accepted(mock_auth_client: AsyncClient) -> None:
    response = await mock_auth_client.post(
        "/protected",
        content=b"{}",
        headers=_signed_headers(hotkey=VALIDATOR_HOTKEY, nonce="n-accept"),
    )
    assert response.status_code == 200
    assert response.json() == {"hotkey": VALIDATOR_HOTKEY, "uid": 3}


async def test_mmg003_absent_hotkey_rejected(mock_auth_client: AsyncClient) -> None:
    response = await mock_auth_client.post(
        "/protected",
        content=b"{}",
        headers=_signed_headers(hotkey=ABSENT_HOTKEY, nonce="n-absent"),
    )
    assert response.status_code == 403


async def test_mmg003_unpermitted_hotkey_rejected(
    mock_auth_client: AsyncClient,
) -> None:
    response = await mock_auth_client.post(
        "/protected",
        content=b"{}",
        headers=_signed_headers(hotkey=UNPERMITTED_HOTKEY, nonce="n-nopermit"),
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# MMG-005: miners stay submit-eligible via the allowlist, independent of the set
# ---------------------------------------------------------------------------


class _FakeNonceStore:
    async def reserve(self, **kwargs: object) -> None:
        return None


async def test_mmg005_miner_allowlisted_independent_of_mock_metagraph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _explode_bittensor(monkeypatch)
    cache = create_bittensor_runtime(_mock_settings(tmp_path)).metagraph_cache
    # The miner hotkey is NOT in the validator mock set.
    assert MINER_HOTKEY not in cache.hotkey_to_uid

    verifier = MinerUploadVerifier(
        netuid=7,
        nonce_store=_FakeNonceStore(),
        metagraph_cache=cache,
        require_registered_hotkey=True,
        extra_registered_hotkeys={MINER_HOTKEY},
        signature_verifier=lambda hotkey, message, signature: True,
        now_fn=lambda: NOW_EPOCH,
    )

    identity = await verifier.verify(
        method="POST",
        path="/v1/challenges/prism/submissions",
        headers={
            "x-hotkey": MINER_HOTKEY,
            "x-signature": "0x00",
            "x-nonce": "n1",
            "x-timestamp": str(int(NOW_EPOCH)),
        },
        body=b"zip",
        challenge_slug="prism",
    )
    assert identity.hotkey == MINER_HOTKEY
    assert identity.uid is None
