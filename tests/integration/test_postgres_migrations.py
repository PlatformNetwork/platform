from __future__ import annotations

import ast
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text

from platform_network.db import ChallengeStatus, create_engine

ROOT_DIR = Path(__file__).resolve().parents[2]
CHALLENGE_REGISTRY_MIGRATION = (
    ROOT_DIR / "alembic/versions/0001_create_challenge_registry.py"
)

pytestmark = pytest.mark.postgres


def _current_alembic_head() -> str:
    config = Config(str(ROOT_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT_DIR / "alembic"))
    return ScriptDirectory.from_config(config).get_current_head()


def _migration_challenge_status_literals() -> list[str]:
    migration_ast = ast.parse(
        CHALLENGE_REGISTRY_MIGRATION.read_text(encoding="utf-8")
    )

    for node in migration_ast.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "challenge_status"
            for target in node.targets
        ):
            continue
        enum_call = node.value
        assert isinstance(enum_call, ast.Call)
        return [
            arg.value
            for arg in enum_call.args
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
        ]

    raise AssertionError("challenge_status enum declaration not found")


async def test_postgres_migration_reaches_head_with_non_native_status_enum(
    migrated_postgres_database: str,
) -> None:
    assert _migration_challenge_status_literals() == [
        status.value for status in ChallengeStatus
    ]

    engine = create_engine(migrated_postgres_database)
    try:
        async with engine.connect() as connection:
            version_num = (
                await connection.execute(
                    text("SELECT version_num FROM alembic_version")
                )
            ).scalar_one()
            status_column = (
                await connection.execute(
                    text(
                        """
                        SELECT data_type, udt_name
                        FROM information_schema.columns
                        WHERE table_schema = current_schema()
                          AND table_name = 'challenges'
                          AND column_name = 'status'
                        """
                    )
                )
            ).mappings().one()
            challenge_status_type_count = (
                await connection.execute(
                    text(
                        """
                        SELECT count(*)
                        FROM pg_type
                        WHERE typname = 'challenge_status'
                        """
                    )
                )
            ).scalar_one()
            challenge_status_dependency_count = (
                await connection.execute(
                    text(
                        """
                        SELECT count(*)
                        FROM pg_depend dependency
                        JOIN pg_type type
                          ON type.oid = dependency.refobjid
                        JOIN pg_class relation
                          ON relation.oid = dependency.objid
                        JOIN pg_attribute attribute
                          ON attribute.attrelid = relation.oid
                         AND attribute.attnum = dependency.objsubid
                        WHERE type.typname = 'challenge_status'
                          AND relation.relname = 'challenges'
                          AND attribute.attname = 'status'
                        """
                    )
                )
            ).scalar_one()
    finally:
        await engine.dispose()

    assert version_num == _current_alembic_head()
    assert status_column["data_type"] == "character varying"
    assert status_column["udt_name"] != "challenge_status"
    assert challenge_status_type_count == 0
    assert challenge_status_dependency_count == 0
