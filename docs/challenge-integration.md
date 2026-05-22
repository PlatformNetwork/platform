# Challenge Integration Guide

![Platform Banner](../assets/banner.jpg)

## Implement weights

In the generated challenge repository, implement:

```python
async def get_weights() -> dict[str, float]:
    return {"5F...hotkey": 1.0}
```

The master normalizes returned values, so raw scores are acceptable as long as they are finite and non-negative.

## SQLite

The template config uses:

```text
sqlite+aiosqlite:////data/challenge.sqlite3
```

`/data` is mounted as persistent storage for the Kubernetes challenge workload.

## Build and publish

The generated CI workflow tests the challenge and pushes its Docker image to GHCR on main/tags.
