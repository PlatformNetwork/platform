"""Alembic environment for the base master database."""

from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from base.db import models as _models  # noqa: F401, E402
from base.db.base import Base  # noqa: E402

config = context.config

if config.config_file_name is not None:
    # disable_existing_loggers=False so running a migration never silently
    # disables loggers created before this call (fileConfig's default would set
    # ``disabled=True`` on every pre-existing logger not named in alembic.ini).
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _database_url() -> str:
    url = os.getenv("BASE_DATABASE_URL") or os.getenv("DATABASE_URL")
    if url:
        return url

    configured_url = config.get_main_option("sqlalchemy.url")
    if configured_url:
        return configured_url

    raise RuntimeError(
        "Database URL must be set via BASE_DATABASE_URL, DATABASE_URL, or alembic.ini"
    )


def run_migrations_offline() -> None:
    """Run migrations without creating an engine."""

    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Run migrations with an established sync connection."""

    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        render_as_batch=connection.dialect.name == "sqlite",
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Create an async engine and run migrations."""

    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _database_url()
    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_async_migrations())
