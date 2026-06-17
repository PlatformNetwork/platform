"""Task 6: prism re-seed RECOMPUTES + OVERWRITES the broker URL in record.env.

Wave 0 probe #1 found the live prism challenge record carrying
``CHALLENGE_DOCKER_BROKER_URL`` / ``PRISM_DOCKER_BROKER_URL`` pointing at the
non-resolving ``platform-master-broker`` host (NXDOMAIN). The correct broker
service is ``platform-docker-broker``.

Re-seeding takes the else-branch of ``seed_prism_challenges`` ->
``registry.update`` <- ``_prism_challenge_update`` (which recomputes the full
env from ``prism_challenge_create`` with the broker URL derived from
``_settings_docker_broker_url(settings)``). This locks the SOURCE-side contract
consumed by live tasks 14/15: the recompute must REPLACE the broker-URL keys
with the current correct value, never merge-keep the stale stored value.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

import platform_network.cli_app.main as cli_module
import platform_network.validator.image_updater as image_updater_module
from platform_network.master.registry import FileChallengeRegistry
from platform_network.schemas.challenge import ChallengeCreate, ChallengeStatus

PINNED_DIGEST = "sha256:" + "c" * 64
STALE_BROKER_URL = "http://platform-master-broker:8082"
CORRECT_BROKER_URL = "http://platform-docker-broker:8082"


@pytest.fixture(autouse=True)
def _offline_digest_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        image_updater_module,
        "resolve_remote_digest",
        lambda image_reference, **kwargs: PINNED_DIGEST,
    )


def _docker_settings() -> SimpleNamespace:
    return SimpleNamespace(
        runtime=SimpleNamespace(backend="docker"),
        docker=SimpleNamespace(broker_url=CORRECT_BROKER_URL),
    )


def _stale_prism_create() -> ChallengeCreate:
    """A prism record pre-seeded with the STALE broker host (live defect state)."""

    return ChallengeCreate(
        slug="prism",
        name="PRISM",
        image="ghcr.io/platformnetwork/prism:latest",
        version="0.1.0",
        status=ChallengeStatus.ACTIVE,
        required_capabilities=["get_weights", "proxy_routes"],
        env={
            "PRISM_DOCKER_BROKER_URL": STALE_BROKER_URL,
            "CHALLENGE_DOCKER_BROKER_URL": STALE_BROKER_URL,
            "PRISM_DOCKER_ENABLED": "true",
        },
    )


def test_reseed_overwrites_stale_broker_url(tmp_path: Path) -> None:
    registry = FileChallengeRegistry(tmp_path / "registry.json", tmp_path / "secrets")
    registry.create(_stale_prism_create())

    # Pre-condition: stored record carries the stale, non-resolving host.
    pre = registry.get("prism")
    assert pre.env["CHALLENGE_DOCKER_BROKER_URL"] == STALE_BROKER_URL
    assert pre.env["PRISM_DOCKER_BROKER_URL"] == STALE_BROKER_URL

    result = asyncio.run(cli_module.seed_prism_challenges(registry, _docker_settings()))
    assert result["prism"] == "updated"

    post = registry.get("prism")
    # The recompute OVERWRITES both broker-URL keys with the correct value.
    assert post.env["CHALLENGE_DOCKER_BROKER_URL"] == CORRECT_BROKER_URL
    assert post.env["PRISM_DOCKER_BROKER_URL"] == CORRECT_BROKER_URL
    # REPLACE (not merge): no trace of the stale host survives anywhere in env.
    assert all(STALE_BROKER_URL not in value for value in post.env.values())
    assert "platform-master-broker" not in repr(post.env)


def test_reseed_preserves_required_capabilities(tmp_path: Path) -> None:
    registry = FileChallengeRegistry(tmp_path / "registry.json", tmp_path / "secrets")
    registry.create(_stale_prism_create())

    asyncio.run(cli_module.seed_prism_challenges(registry, _docker_settings()))

    post = registry.get("prism")
    # Regression: prism keeps its declared capabilities after re-seed.
    assert {"get_weights", "proxy_routes"} <= set(post.required_capabilities)
    # MUST NOT: docker_executor is task 13 (gated/deferred) — never on prism here.
    assert "docker_executor" not in post.required_capabilities
