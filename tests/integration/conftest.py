from __future__ import annotations

import os
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

import pytest
from sqlalchemy import text

from base.db.migrations import upgrade
from base.db.session import create_engine

ROOT = Path(__file__).resolve().parents[2]
POSTGRES_SCHEMES = ("postgres://", "postgresql://", "postgresql+asyncpg://")
APPLICATION_TABLES = (
    "challenge_health_events",
    "challenge_routes",
    "challenge_capabilities",
    "challenge_env",
    "challenge_secrets",
    "challenge_volumes",
    "challenge_resources",
    "challenge_auth",
    "challenge_images",
    "miner_request_nonces",
    "validator_request_nonces",
    "validator_health_events",
    "validators",
    "work_assignments",
    "llm_usage_records",
    "challenges",
)
ENV_VAR_MESSAGE = "BASE_TEST_DATABASE_URL or BASE_DATABASE__URL"


def _async_postgres_url(database_url: str) -> str:
    if database_url.startswith("postgresql+asyncpg://"):
        return database_url
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql+asyncpg://", 1)
    return database_url


@pytest.fixture(scope="session")
def postgres_database_url() -> str:
    database_url = os.getenv("BASE_TEST_DATABASE_URL") or os.getenv(
        "BASE_DATABASE__URL"
    )
    if not database_url:
        pytest.skip(f"set {ENV_VAR_MESSAGE} to run tests marked postgres")
    if not database_url.startswith(POSTGRES_SCHEMES):
        schemes = ", ".join(POSTGRES_SCHEMES)
        pytest.skip(
            f"{ENV_VAR_MESSAGE} must use PostgreSQL; accepted schemes: {schemes}"
        )
    return _async_postgres_url(database_url)


@pytest.fixture(scope="session")
def migrated_postgres_database(postgres_database_url: str) -> str:
    upgrade(ROOT / "alembic.ini", database_url=postgres_database_url)
    return postgres_database_url


async def truncate_postgres_application_tables(database_url: str) -> None:
    engine = create_engine(database_url)
    try:
        async with engine.begin() as connection:
            tables = ", ".join(APPLICATION_TABLES)
            await connection.execute(
                text(f"TRUNCATE TABLE {tables} RESTART IDENTITY CASCADE")
            )
    finally:
        await engine.dispose()


@pytest.fixture
async def cleanup_postgres_database(
    migrated_postgres_database: str,
) -> AsyncIterator[Callable[[], Awaitable[None]]]:
    async def cleanup() -> None:
        await truncate_postgres_application_tables(migrated_postgres_database)

    await cleanup()
    try:
        yield cleanup
    finally:
        await cleanup()
