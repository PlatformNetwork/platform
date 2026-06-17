"""Regression tests for DatabaseChallengeRegistry collection-replace updates.

These reproduce the source-level durability defect where updating a child
collection (env / capabilities / ...) on the Postgres-backed registry emits the
INSERT of the new rows BEFORE the orphan DELETE in the same flush, transiently
violating ``UNIQUE(challenge_id, key)`` on ``challenge_env`` (and the equivalent
``UNIQUE(challenge_id, name)`` on ``challenge_capabilities``).

The bug is fully reproduced on sqlite (same SQLAlchemy 2.0.x as deployed); the
constraint-ordering behaviour is identical to Postgres for this scenario.
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
from pathlib import Path

from platform_network.db.migrations import upgrade
from platform_network.db.session import create_engine, create_session_factory
from platform_network.master.registry import DatabaseChallengeRegistry
from platform_network.schemas.challenge import ChallengeCreate, ChallengeUpdate


def _payload(slug: str) -> ChallengeCreate:
    return ChallengeCreate(
        slug=slug,
        name="Reseed Demo",
        image="ghcr.io/platformnetwork/demo:1.0.0",
        version="1.0.0",
        emission_percent=Decimal("10"),
        env={"A": "1", "B": "old"},
        required_capabilities=["cap-keep", "cap-drop"],
    )


def _make_registry(tmp_path: Path) -> tuple[object, DatabaseChallengeRegistry]:
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'master.sqlite3'}"
    upgrade(Path(__file__).resolve().parents[2] / "alembic.ini", db_url)
    engine = create_engine(db_url)
    registry = DatabaseChallengeRegistry(
        create_session_factory(engine),
        secret_dir=tmp_path / "secrets",
        master_uid=3,
    )
    return engine, registry


def test_env_collection_replace_overwrites_existing_keys(tmp_path: Path) -> None:
    """Re-seeding an existing env key's value must not raise IntegrityError.

    Reproduces: UNIQUE constraint failed: challenge_env.challenge_id,
    challenge_env.key — because INSERT of the new ``A``/``B`` rows ran before the
    orphan DELETE of the old ``A``/``B`` rows in the same flush.
    """

    engine, registry = _make_registry(tmp_path)

    async def run() -> None:
        created, _token = await registry.create(_payload("env-reseed"))
        assert created.env == {"A": "1", "B": "old"}

        # Collection replace: same keys, new values (the live re-seed shape).
        updated = await registry.update(
            "env-reseed",
            ChallengeUpdate(env={"A": "2", "B": "new", "C": "added"}),
        )

        assert updated.env == {"A": "2", "B": "new", "C": "added"}

        # Persisted (fresh read) and row count is exactly 3 — no stale orphans.
        reread = await registry.get("env-reseed")
        assert reread.env == {"A": "2", "B": "new", "C": "added"}
        assert len(reread.env) == 3

        await engine.dispose()

    asyncio.run(run())


def test_capabilities_collection_replace_overwrites_existing(tmp_path: Path) -> None:
    """Replacing required_capabilities must not raise IntegrityError.

    Reproduces the equivalent UNIQUE(challenge_id, name) violation on
    challenge_capabilities when a retained capability name is re-inserted before
    the orphan delete.
    """

    engine, registry = _make_registry(tmp_path)

    async def run() -> None:
        created, _token = await registry.create(_payload("cap-reseed"))
        assert sorted(created.required_capabilities) == ["cap-drop", "cap-keep"]

        # Replace: keep "cap-keep" (the UNIQUE hazard), drop "cap-drop", add new.
        updated = await registry.update(
            "cap-reseed",
            ChallengeUpdate(required_capabilities=["cap-keep", "cap-new"]),
        )

        assert sorted(updated.required_capabilities) == ["cap-keep", "cap-new"]

        reread = await registry.get("cap-reseed")
        assert sorted(reread.required_capabilities) == ["cap-keep", "cap-new"]
        assert len(reread.required_capabilities) == 2

        await engine.dispose()

    asyncio.run(run())


def test_combined_env_and_capabilities_replace(tmp_path: Path) -> None:
    """A single update() that replaces BOTH env and capabilities succeeds.

    This is the exact shape of the prism re-seed: env + capabilities re-written
    in one transaction.
    """

    engine, registry = _make_registry(tmp_path)

    async def run() -> None:
        await registry.create(_payload("combo-reseed"))

        updated = await registry.update(
            "combo-reseed",
            ChallengeUpdate(
                env={"A": "2", "B": "new"},
                required_capabilities=["cap-keep"],
            ),
        )

        assert updated.env == {"A": "2", "B": "new"}
        assert updated.required_capabilities == ["cap-keep"]

        reread = await registry.get("combo-reseed")
        assert reread.env == {"A": "2", "B": "new"}
        assert reread.required_capabilities == ["cap-keep"]

        await engine.dispose()

    asyncio.run(run())
