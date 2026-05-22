from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from platform_network.config.policy import validate_database_url
from platform_network.db import (
    Base,
    Challenge,
    ChallengeAuth,
    ChallengeCapability,
    ChallengeEnv,
    ChallengeHealthEvent,
    ChallengeImage,
    ChallengeRepository,
    ChallengeResource,
    ChallengeRoute,
    ChallengeSecret,
    ChallengeStatus,
    ChallengeVolume,
    create_engine,
    create_session_factory,
    migrations,
    session_scope,
)
from platform_network.schemas.health import HealthResponse, VersionResponse

ROOT_DIR = Path(__file__).resolve().parents[2]


def test_db_models_construct_and_metadata() -> None:
    challenge = Challenge(
        slug="demo",
        name="Demo",
        version="1.0.0",
        status=ChallengeStatus.ACTIVE,
        metadata_={"a": "b"},
    )
    challenge.image = ChallengeImage(
        registry_name="ghcr.io", repository="org/demo", tag="1"
    )
    challenge.auth = ChallengeAuth(token_hash="hash", token_hint="hint")
    challenge.resources.append(ChallengeResource(key="cpu", value="1"))
    challenge.volumes.append(
        ChallengeVolume(name="sqlite", mount_path="/data", type="volume")
    )
    challenge.secrets.append(
        ChallengeSecret(
            name="token", mount_path="/run/token", source_path="/host/token"
        )
    )
    challenge.env.append(ChallengeEnv(key="A", value_encrypted="B", is_secret=False))
    challenge.capabilities.append(ChallengeCapability(name="get_weights", version="1"))
    challenge.routes.append(ChallengeRoute(public_prefix="/x", proxy_enabled=True))
    challenge.health_events.append(
        ChallengeHealthEvent(status="ok", version="1", message="fine")
    )

    assert challenge.slug == "demo"
    assert challenge.image.repository == "org/demo"
    assert challenge.resources[0].key == "cpu"
    assert Base.metadata.tables["challenges"].name == "challenges"
    assert HealthResponse(slug="demo", version="1").status == "ok"
    assert "get_weights" in VersionResponse(challenge_version="1").capabilities


def test_challenge_status_orm_enum_matches_migration_metadata() -> None:
    status_column = Challenge.__table__.c.status

    assert status_column.type.name == "challenge_status"
    assert status_column.type.native_enum is False
    assert status_column.type.enums == [status.value for status in ChallengeStatus]


def test_challenge_status_migration_literals_match_model_enum() -> None:
    migration_path = ROOT_DIR / "alembic/versions/0001_create_challenge_registry.py"
    migration_ast = ast.parse(migration_path.read_text(encoding="utf-8"))

    enum_call = None
    for node in migration_ast.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "challenge_status"
            for target in node.targets
        ):
            continue
        enum_call = node.value
        break

    assert isinstance(enum_call, ast.Call)
    assert isinstance(enum_call.func, ast.Attribute)
    assert enum_call.func.attr == "Enum"
    assert [arg.value for arg in enum_call.args if isinstance(arg, ast.Constant)] == [
        status.value for status in ChallengeStatus
    ]


def test_session_helpers_and_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_engine("sqlite+aiosqlite:///:memory:")
    factory = create_session_factory(engine)
    assert factory is not None

    async def run_success() -> None:
        async with session_scope(factory) as session:
            assert session is not None

    async def run_failure() -> None:
        with pytest.raises(RuntimeError):
            async with session_scope(factory):
                raise RuntimeError("rollback")

    import asyncio

    asyncio.run(run_success())
    asyncio.run(run_failure())
    asyncio.run(engine.dispose())


def test_migration_helpers(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    calls: list[tuple[str, object, str]] = []

    monkeypatch.setattr(
        migrations.command, "upgrade", lambda cfg, rev: calls.append(("up", cfg, rev))
    )
    monkeypatch.setattr(
        migrations.command,
        "downgrade",
        lambda cfg, rev: calls.append(("down", cfg, rev)),
    )
    cfg_path = tmp_path / "alembic.ini"
    cfg_path.write_text("[alembic]\nscript_location = alembic\n", encoding="utf-8")
    cfg = migrations.alembic_config(cfg_path, "sqlite+aiosqlite:///:memory:")
    assert cfg.get_main_option("sqlalchemy.url") == "sqlite+aiosqlite:///:memory:"
    migrations.upgrade(cfg_path, revision="head")
    migrations.downgrade(cfg_path, revision="base")
    assert calls[0][0] == "up"
    assert calls[1][0] == "down"


def test_repository_methods_with_fake_session() -> None:
    class Result:
        def scalar_one_or_none(self):
            return "one"

        def scalars(self):
            return SimpleNamespace(all=lambda: ["a"])

    class Session:
        def __init__(self) -> None:
            self.added: list[object] = []
            self.deleted: list[object] = []

        def add(self, value):
            self.added.append(value)

        async def flush(self):
            return None

        async def execute(self, query):
            return Result()

        async def delete(self, value):
            self.deleted.append(value)

    async def run() -> None:
        session = Session()
        repo = ChallengeRepository(session)  # type: ignore[arg-type]
        challenge = Challenge(slug="demo", name="Demo", version="1")
        assert await repo.add(challenge) is challenge
        assert await repo.get(challenge.id) == "one"
        assert await repo.get_by_slug("demo") == "one"
        assert await repo.list() == ["a"]
        assert await repo.list_active() == ["a"]
        await repo.delete(challenge)
        event = ChallengeHealthEvent(status="ok")
        assert await repo.record_health_event(event) is event
        assert session.added
        assert session.deleted == [challenge]

    import asyncio

    asyncio.run(run())


def test_database_policy_rejects_sqlite_for_production() -> None:
    validate_database_url("sqlite+aiosqlite:///:memory:", production=False)
    validate_database_url("postgresql+asyncpg://user:pass@db/platform", production=True)
    with pytest.raises(ValueError, match="PostgreSQL"):
        validate_database_url("sqlite+aiosqlite:///:memory:", production=True)
