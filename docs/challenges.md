# Challenges

![Platform Banner](../assets/banner.jpg)

## Model

A challenge is an independent repository and Docker image. It owns its logic, public routes, submissions, scoring data, database schema, and challenge-local files.

In Kubernetes managed mode, Platform creates isolated managed Postgres resources per challenge slug and injects `CHALLENGE_DATABASE_URL` automatically from the per-challenge Secret. Local generated challenge runs and legacy Docker runtime stay SQLite-backed with `sqlite+aiosqlite:////data/challenge.sqlite3`.

The challenge `/data` PVC is separate from managed Postgres. Use `/data` for artifacts, analyzer output, uploaded files, local files, and the SQLite fallback. Managed Postgres uses its own retained data claim.

## Required API

```text
GET /health
GET /version
GET /internal/v1/get_weights
```

The internal endpoint is authenticated with a per-challenge shared token mounted by the master.

## Create a challenge

```bash
uv run platform challenge create code-arena --out ../code-arena
cd ../code-arena
uv run --extra dev pytest
```

## Public routes

Public routes are exposed through:

```text
/challenges/{slug}/...
```

The master blocks `/internal/*`, `/health`, and `/version` from the public proxy.
