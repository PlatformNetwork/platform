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

## Proxy failure behavior

Platform proxy should preserve challenge-origin non-2xx responses when the challenge answered with a safe response. Transport failures, unreachable services, missing Kubernetes targets, DNS failures, and connection timeouts become safe 502 responses at Platform. Frontends should render unavailable copy and retry with backoff instead of showing raw text such as `Platform request failed with status 502`.

Operator checklist for challenge 502s:

1. Confirm ingress includes `/challenges` and routes it to Platform proxy.
2. Confirm the slug maps to a running challenge service.
3. Confirm challenge service health, service DNS, service port, and pod readiness.
4. In Kubernetes target mode, confirm target assignment, target health, and capacity state.
5. Check whether the response came from proxy transport handling or from the challenge origin. Only transport failures should be rewritten to 502.

Agent Challenge env and launch routes are public proxy routes, but Platform does not store their request bodies or per-submission env values. The allowed Platform paths are `GET/PUT /challenges/agent-challenge/submissions/{id}/env`, `POST /challenges/agent-challenge/submissions/{id}/env/confirm-empty`, and `POST /challenges/agent-challenge/submissions/{id}/launch`. The challenge-local paths are `GET/PUT /submissions/{id}/env`, `POST /submissions/{id}/env/confirm-empty`, and `POST /submissions/{id}/launch`. Only signed miner headers `X-Hotkey`, `X-Signature`, `X-Nonce`, and `X-Timestamp` are preserved for those routes.
