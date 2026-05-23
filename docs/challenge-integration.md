# Challenge Integration Guide

![Platform Banner](../assets/banner.jpg)

## Implement weights

In the generated challenge repository, implement:

```python
async def get_weights() -> dict[str, float]:
    return {"5F...hotkey": 1.0}
```

The master normalizes returned values, so raw scores are acceptable as long as they are finite and non-negative.

## Challenge database contract

Generated challenges use the async SQLAlchemy SDK and read their runtime database URL from `CHALLENGE_DATABASE_URL`.

In Kubernetes managed mode, Platform creates one isolated managed Postgres server per challenge slug. Each slug gets its own Postgres Secret, Service, StatefulSet, and data claim. Platform injects `CHALLENGE_DATABASE_URL` into the challenge workload automatically from that per-challenge Secret. Challenge authors must not set that environment variable in the Kubernetes challenge spec when managed Postgres is enabled.

The per-challenge credential is only for that challenge database. It is separate from the Platform control-plane database URL used by the master or validator process. Challenges must never receive `PLATFORM_DATABASE_URL`, master database URLs, or any central control-plane PostgreSQL credentials.

Generated local development and Docker fallback stay SQLite:

```text
sqlite+aiosqlite:////data/challenge.sqlite3
```

That fallback is for local generated challenge runs and the legacy Docker runtime. Legacy Docker challenge runtime does not create Postgres and continues to mount `/data` for the SQLite file and artifacts.

## Async SQLAlchemy usage

Generated challenge templates export a `Base` and `database` helper. Use normal SQLAlchemy 2.x async ORM patterns with `AsyncSession`, `select()`, model registration, and the FastAPI session dependency.

```python
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import Integer, String, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Submission(Base):
    __tablename__ = "submissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hotkey: Mapped[str] = mapped_column(String(128), index=True)
    score: Mapped[int] = mapped_column(Integer, default=0)


# In generated challenges, import Base and database instead:
# from .core.db import Base, database

router = APIRouter()
DatabaseSession = Annotated[AsyncSession, Depends(database.session_dependency)]


@router.get("/submissions/{hotkey}")
async def list_submissions(hotkey: str, session: DatabaseSession) -> list[int]:
    result = await session.execute(
        select(Submission).where(Submission.hotkey == hotkey)
    )
    return [submission.score for submission in result.scalars()]
```

Generated applications call `Base.metadata.create_all` through the async engine during startup after models are imported. That creates missing tables for the current model set. Challenge Alembic migration automation is not part of this implementation.

## Persistent storage

Kubernetes challenge workloads still get a separate `/data` PVC. Use `/data` for artifacts, analyzer output, uploaded files, temporary local state that should survive restarts, or the local SQLite fallback.

Do not treat the challenge `/data` PVC as Postgres storage. Managed Postgres uses its own StatefulSet volume claim mounted inside the Postgres container at `/var/lib/postgresql/data`.

By default, Platform retains the managed Postgres data claim and managed Postgres Secret when a challenge is removed. That retention protects challenge state and credentials from accidental deletion. Manual deletion of either object is destructive because it can remove the database contents or the credential needed to reconnect to retained data.

## Operator cleanup and purge

Normal challenge stop or remove flows delete the managed Postgres StatefulSet and Service but keep the per-challenge Postgres Secret and data claim by default. If an operator intentionally wants to purge a challenge database, inspect the objects first, then delete only the matching slug resources.

```bash
kubectl -n <namespace> get secret,pvc --selector app.kubernetes.io/managed-by=platform-network,platform.challenge.slug=<slug>

kubectl -n <namespace> delete secret --selector platform.component=challenge-postgres-secret,platform.challenge.slug=<slug>

kubectl -n <namespace> delete pvc --selector platform.component=challenge-postgres-data,platform.challenge.slug=<slug>
```

These commands are manual and destructive. Confirm the namespace and slug before running them. Platform does not provide automated destructive purge in this implementation.

## Out of scope

This implementation does not provide Docker Compose Postgres support, automatic backups, restore workflows, high availability, connection pooling, Postgres operator support, storage resize workflows, challenge Alembic migration automation, or automated destructive purge.

## Build and publish

The generated CI workflow tests the challenge and pushes its Docker image to GHCR on main/tags.
