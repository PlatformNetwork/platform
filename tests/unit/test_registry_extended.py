from __future__ import annotations

import asyncio
import json
from decimal import Decimal
from pathlib import Path

import pytest

from platform_network.db.migrations import upgrade
from platform_network.db.session import create_engine, create_session_factory
from platform_network.master.registry import (
    ChallengeAlreadyExistsError,
    ChallengeNotFoundError,
    ChallengeRegistry,
    DatabaseChallengeRegistry,
    FileChallengeRegistry,
    default_internal_base_url,
    default_public_proxy_base_path,
    default_sqlite_volume_name,
    record_to_admin_view,
    record_to_registry_view,
)
from platform_network.schemas.challenge import (
    ChallengeCreate,
    ChallengeStatus,
    ChallengeUpdate,
)


def payload(slug: str = "demo") -> ChallengeCreate:
    return ChallengeCreate(
        slug=slug,
        name="Demo",
        image="ghcr.io/platformnetwork/demo:1.0.0",
        version="1.0.0",
        emission_percent=Decimal("10"),
    )


def test_registry_update_views_and_errors() -> None:
    registry = ChallengeRegistry(network="net", api_version="2", master_uid=7)
    record, token = registry.create(payload("demo-case"))
    assert record.slug == "demo-case"
    assert token
    assert default_internal_base_url("x") == "http://challenge-x:8000"
    assert default_public_proxy_base_path("x") == "/challenges/x"
    assert default_sqlite_volume_name("a-b") == "platform_a_b_sqlite"

    with pytest.raises(ChallengeAlreadyExistsError):
        registry.create(payload("demo-case"))
    with pytest.raises(ChallengeNotFoundError):
        registry.get("missing")

    updated = registry.update(
        "demo-case",
        ChallengeUpdate(name="Updated", metadata={"k": "v"}, env={"A": "B"}),
    )
    assert updated.name == "Updated"
    assert updated.metadata == {"k": "v"}
    assert registry.list(active_only=True) == []

    registry.set_status("demo-case", ChallengeStatus.ACTIVE)
    response = registry.registry_response()
    assert response.network == "net"
    assert response.api_version == "2"
    assert response.master_uid == 7
    assert response.challenges[0].slug == "demo-case"

    admin = record_to_admin_view(registry.get("demo-case"))
    public = record_to_registry_view(registry.get("demo-case"))
    assert admin.token_hint
    assert public.public_proxy_base_path == "/challenges/demo-case"


def test_registry_view_filters_frontend_metadata() -> None:
    registry = ChallengeRegistry()
    record, _token = registry.create(
        ChallengeCreate(
            slug="agent-challenge",
            name="Agent Challenge",
            image="ghcr.io/platformnetwork/agent-challenge:1.0.0",
            version="1.0.0",
            emission_percent=Decimal("20"),
            status=ChallengeStatus.ACTIVE,
            description="Build and evaluate coding agents.",
            metadata={
                "tagline": "Compete with production-grade agents",
                "docs_url": "https://docs.example.com/agent-challenge",
                "miner_docs_url": "https://docs.example.com/agent-challenge/miners",
                "validator_docs_url": "https://docs.example.com/agent-challenge/validators",
                "category": "agents",
                "difficulty": "hard",
                "benchmark_label": "Terminal-Bench",
                "evaluation_timeout_seconds": 1800,
                "rate_limit_label": "10 submissions/hour",
                "token": "challenge-token",
                "secret": "shared-secret",
                "password": "password",
                "private_key": "private-key",
                "database_url": "postgres://secret",
                "internal_base_url": "http://internal:8000",
                "operator_notes": "internal only",
                "nested": {"hide": "me"},
                "summary": ["not", "a", "public", "scalar"],
            },
        )
    )

    public = record_to_registry_view(record)

    assert public.description == "Build and evaluate coding agents."
    assert public.metadata == {
        "tagline": "Compete with production-grade agents",
        "docs_url": "https://docs.example.com/agent-challenge",
        "miner_docs_url": "https://docs.example.com/agent-challenge/miners",
        "validator_docs_url": "https://docs.example.com/agent-challenge/validators",
        "category": "agents",
        "difficulty": "hard",
        "benchmark_label": "Terminal-Bench",
        "evaluation_timeout_seconds": 1800,
        "rate_limit_label": "10 submissions/hour",
    }
    assert public.internal_base_url == "http://challenge-agent-challenge:8000"
    assert public.public_proxy_base_path == "/challenges/agent-challenge"
    assert record.metadata["token"] == "challenge-token"
    assert record.metadata["nested"] == {"hide": "me"}


def test_image_digest_round_trip() -> None:
    registry = ChallengeRegistry()
    record, _token = registry.create(
        ChallengeCreate(
            slug="digest-demo",
            name="Digest",
            image="ghcr.io/platformnetwork/demo@sha256:abc123",
            version="1.0.0",
        )
    )

    assert record.image == "ghcr.io/platformnetwork/demo@sha256:abc123"


def test_file_registry_handles_missing_and_invalid_state(tmp_path: Path) -> None:
    state = tmp_path / "registry.json"
    registry = FileChallengeRegistry(state)
    assert registry.list() == []

    state.write_text(json.dumps({"records": []}), encoding="utf-8")
    assert FileChallengeRegistry(state).list() == []

    registry = FileChallengeRegistry(state)
    record, token = registry.create(payload())
    assert record.slug == "demo"
    assert registry.get_token("demo") == token
    assert (tmp_path / "demo_challenge_token").is_file()

    reloaded = FileChallengeRegistry(state)
    assert reloaded.get("demo").slug == "demo"
    with pytest.raises(RuntimeError, match="token file is missing"):
        reloaded.get_token("missing")

    broker_path = tmp_path / "demo_docker_broker_token"
    broker_path.unlink()
    with pytest.raises(RuntimeError, match="broker token file is missing"):
        reloaded.get_broker_token("demo")
    assert not broker_path.exists()


def test_database_registry_uses_sqlite_source_of_truth(tmp_path: Path) -> None:
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'master.sqlite3'}"
    upgrade(Path(__file__).resolve().parents[2] / "alembic.ini", db_url)

    async def run() -> None:
        engine = create_engine(db_url)
        registry = DatabaseChallengeRegistry(
            create_session_factory(engine),
            secret_dir=tmp_path / "secrets",
            master_uid=3,
        )

        draft, challenge_token = await registry.create(payload("draft-demo"))
        inactive_payload = payload("inactive-demo").model_dump()
        inactive_payload["status"] = ChallengeStatus.INACTIVE
        inactive_payload["internal_base_url"] = "http://custom:8000"
        inactive, _ = await registry.create(ChallengeCreate(**inactive_payload))

        assert draft.broker_token_hint
        assert challenge_token
        assert registry.get_token("draft-demo") != registry.get_broker_token(
            "draft-demo"
        )
        assert (tmp_path / "secrets" / "draft-demo_challenge_token").is_file()
        assert (tmp_path / "secrets" / "draft-demo_docker_broker_token").is_file()

        response = await registry.registry_response()
        assert response.master_uid == 3
        assert [challenge.slug for challenge in response.challenges] == [
            "inactive-demo"
        ]
        assert response.challenges[0].internal_base_url == "http://custom:8000"
        assert inactive.status == ChallengeStatus.INACTIVE

        digest_payload = payload("digest-demo").model_dump()
        digest_payload["image"] = "ghcr.io/platformnetwork/demo:1.0@sha256:abc123"
        digest, _ = await registry.create(ChallengeCreate(**digest_payload))
        assert digest.image == "ghcr.io/platformnetwork/demo:1.0@sha256:abc123"

        await engine.dispose()

    asyncio.run(run())


def test_production_registry_rejects_mutable_and_untagged_images() -> None:
    registry = ChallengeRegistry(production_policy=True)
    digest = "sha256:" + "a" * 64

    accepted, _ = registry.create(
        ChallengeCreate(
            slug="prod-demo",
            name="Prod",
            image=f"ghcr.io/platformnetwork/demo:1.2.3@{digest}",
            version="1.2.3",
        )
    )
    assert accepted.image.endswith(digest)

    latest, _ = registry.create(
        ChallengeCreate(
            slug="prod-latest-demo",
            name="Prod Latest",
            image=f"ghcr.io/platformnetwork/demo:latest@{digest}",
            version="1.2.3",
        )
    )
    assert latest.image == f"ghcr.io/platformnetwork/demo:latest@{digest}"

    for image, message in (
        ("ghcr.io/platformnetwork/demo:latest", "digest"),
        ("ghcr.io/platformnetwork/demo", "tag"),
        ("ghcr.io/platformnetwork/demo:1.2.3", "digest"),
    ):
        with pytest.raises(ValueError, match=message):
            registry.create(
                ChallengeCreate(
                    slug=f"bad-{message}",
                    name="Bad",
                    image=image,
                    version="1.2.3",
                )
            )


def test_dev_registry_still_accepts_local_mutable_images() -> None:
    registry = ChallengeRegistry()
    record, _ = registry.create(
        ChallengeCreate(
            slug="local-demo",
            name="Local",
            image="localhost:5000/platform/demo:latest",
            version="dev",
        )
    )

    assert record.image == "localhost:5000/platform/demo:latest"
