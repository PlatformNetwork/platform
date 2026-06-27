"""Alembic migration tests for the control-plane tables on SQLite.

Covers VAL-ASSIGN-030/031 on SQLite: ``alembic upgrade head`` from an empty DB
creates ``validators``, ``validator_health_events``, and ``work_assignments``
with their key columns/indices/constraints; the history has a single head; the
migration matches the ORM models (empty ``compare_metadata`` diff); and a
downgrade/re-upgrade round-trips cleanly.
"""

from __future__ import annotations

from pathlib import Path

from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine as create_sync_engine
from sqlalchemy import inspect

from base.db import Base, migrations

ROOT_DIR = Path(__file__).resolve().parents[2]
ALEMBIC_INI = ROOT_DIR / "alembic.ini"


def _async_url(db_path: Path) -> str:
    return f"sqlite+aiosqlite:///{db_path}"


def _sync_url(db_path: Path) -> str:
    return f"sqlite:///{db_path}"


def _table_names(db_path: Path) -> set[str]:
    engine = create_sync_engine(_sync_url(db_path))
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def test_single_head() -> None:
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(ROOT_DIR / "alembic"))
    heads = ScriptDirectory.from_config(config).get_heads()
    assert len(heads) == 1


def test_upgrade_from_empty_creates_control_plane_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "fresh.sqlite3"
    migrations.upgrade(ALEMBIC_INI, database_url=_async_url(db_path), revision="head")

    tables = _table_names(db_path)
    assert {
        "validators",
        "validator_health_events",
        "work_assignments",
    } <= tables

    engine = create_sync_engine(_sync_url(db_path))
    try:
        inspector = inspect(engine)
        columns = {c["name"] for c in inspector.get_columns("work_assignments")}
        assert {
            "id",
            "challenge_slug",
            "work_unit_id",
            "submission_ref",
            "payload",
            "required_capability",
            "assigned_validator_hotkey",
            "status",
            "attempt_count",
            "max_attempts",
            "deadline_at",
            "last_progress_at",
            "checkpoint_ref",
            "result_ref",
            "created_at",
            "updated_at",
        } <= columns

        index_names = {idx["name"] for idx in inspector.get_indexes("work_assignments")}
        assert {
            "ix_work_assignments_challenge_slug",
            "ix_work_assignments_status",
            "ix_work_assignments_assigned_validator_hotkey",
            "ix_work_assignments_status_validator",
            "ix_work_assignments_status_deadline",
        } <= index_names

        unique_constraints = inspector.get_unique_constraints("work_assignments")
        unique_column_sets = {
            tuple(sorted(uc["column_names"])) for uc in unique_constraints
        }
        assert ("challenge_slug", "work_unit_id") in unique_column_sets

        # validators.hotkey unique constraint exists.
        validator_unique = {
            tuple(sorted(uc["column_names"]))
            for uc in inspector.get_unique_constraints("validators")
        }
        assert ("hotkey",) in validator_unique
    finally:
        engine.dispose()


def test_migration_matches_models_no_drift(tmp_path: Path) -> None:
    db_path = tmp_path / "compare.sqlite3"
    migrations.upgrade(ALEMBIC_INI, database_url=_async_url(db_path), revision="head")

    engine = create_sync_engine(_sync_url(db_path))
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection,
                opts={
                    "compare_type": True,
                    "compare_server_default": True,
                    "render_as_batch": True,
                    "target_metadata": Base.metadata,
                },
            )
            diff = compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()

    assert diff == []


def test_downgrade_removes_work_assignments_and_reupgrade_recreates(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "roundtrip.sqlite3"
    async_url = _async_url(db_path)

    migrations.upgrade(ALEMBIC_INI, database_url=async_url, revision="head")
    assert "work_assignments" in _table_names(db_path)

    # Downgrade only the head migration: work_assignments is dropped while the
    # earlier control-plane tables remain.
    migrations.downgrade(ALEMBIC_INI, database_url=async_url, revision="-1")
    tables_after_downgrade = _table_names(db_path)
    assert "work_assignments" not in tables_after_downgrade
    assert "validators" in tables_after_downgrade

    migrations.upgrade(ALEMBIC_INI, database_url=async_url, revision="head")
    assert "work_assignments" in _table_names(db_path)
