"""Task 25: seeding on the docker backend + per-slug secret plumbing.

`seed_prism_challenges` is registry-driven and must behave identically when
`runtime.backend == "docker"`: same records, same per-slug token registry
(tokens preserved on re-seed). The runtime controller must carry
record-declared secret names beyond the registry tokens as external Swarm
secret references without ever resolving their values.
"""

from __future__ import annotations

import asyncio
import stat
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest

import platform_network.cli_app.main as cli_module
import platform_network.validator.image_updater as image_updater_module
from platform_network.cli_app.main import DockerRuntimeController
from platform_network.master.registry import ChallengeRegistry, FileChallengeRegistry
from platform_network.schemas.challenge import ChallengeCreate, ChallengeStatus

PINNED_DIGEST = "sha256:" + "c" * 64


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
        docker=SimpleNamespace(broker_url="http://platform-docker-broker:8082"),
    )


def _agent_challenge_create() -> ChallengeCreate:
    return ChallengeCreate(
        slug="agent-challenge",
        name="Agent Challenge",
        image="ghcr.io/platformnetwork/agent-challenge:latest",
        version="0.1.0",
        status=ChallengeStatus.ACTIVE,
        emission_percent=Decimal("40"),
    )


def test_seed_on_docker_backend_preserves_per_slug_tokens(tmp_path: Path) -> None:
    secret_dir = tmp_path / "secrets"
    registry = FileChallengeRegistry(tmp_path / "registry.json", secret_dir)
    _, agent_token = registry.create(_agent_challenge_create())
    agent_broker_token = registry.get_broker_token("agent-challenge")
    settings = _docker_settings()

    first = asyncio.run(cli_module.seed_prism_challenges(registry, settings))
    prism_token = registry.get_token("prism")
    prism_broker_token = registry.get_broker_token("prism")
    second = asyncio.run(cli_module.seed_prism_challenges(registry, settings))

    assert first == {"prism": "created", "agent-challenge": "updated"}
    assert second == {"prism": "updated", "agent-challenge": "updated"}
    assert registry.get_token("agent-challenge") == agent_token
    assert registry.get_broker_token("agent-challenge") == agent_broker_token
    assert registry.get_token("prism") == prism_token
    assert registry.get_broker_token("prism") == prism_broker_token

    prism = registry.get("prism")
    assert prism.secrets == ["challenge_token", "docker_broker_token"]
    assert prism.env["CHALLENGE_DOCKER_BROKER_URL"] == (
        "http://platform-docker-broker:8082"
    )
    assert prism.metadata["runtime_database"] == "challenge-local-sqlite"
    assert prism.metadata["workload_class"] == "service"
    agent = registry.get("agent-challenge")
    assert agent.secrets == [
        "challenge_token",
        "docker_broker_token",
        "submission_env_encryption_key",
    ]

    for name in (
        "prism_challenge_token",
        "prism_docker_broker_token",
        "agent-challenge_challenge_token",
        "agent-challenge_docker_broker_token",
    ):
        mode = stat.S_IMODE((secret_dir / name).stat().st_mode)
        assert mode == 0o600, f"{name} must be owner-only, got {oct(mode)}"


def test_runtime_controller_spec_carries_external_secret_names() -> None:
    registry = ChallengeRegistry()
    registry.create(_agent_challenge_create())
    asyncio.run(cli_module.seed_prism_challenges(registry, _docker_settings()))
    controller = DockerRuntimeController(registry, orchestrator=object())

    agent_spec = asyncio.run(controller._spec("agent-challenge"))
    prism_spec = asyncio.run(controller._spec("prism"))

    assert agent_spec.external_secrets == ("submission_env_encryption_key",)
    assert agent_spec.challenge_token == registry.get_token("agent-challenge")
    assert agent_spec.docker_broker_token == (
        registry.get_broker_token("agent-challenge")
    )
    assert agent_spec.secret_names() == (
        "challenge_token",
        "docker_broker_token",
        "submission_env_encryption_key",
    )
    assert prism_spec.external_secrets == ()
    assert prism_spec.secret_names() == ("challenge_token", "docker_broker_token")
