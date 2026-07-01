from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import httpx

from base.schemas.weights import MasterWeightsResponse


def validate_master_weights_payload(
    payload: MasterWeightsResponse,
    *,
    netuid: int | None,
    weights_freshness_seconds: int,
    now: datetime | None = None,
) -> str | None:
    """Validate a fetched master weight vector before on-chain submission.

    Returns ``None`` when the payload is safe to submit, or a human-readable
    reason string when it must be skipped. Shared by every consumer of
    ``/v1/weights/latest`` so all on-chain relays validate the master vector
    identically (netuid match, not expired, not stale, non-empty, equal-length).
    """

    now = now or datetime.now(UTC)
    if payload.netuid != netuid:
        return f"netuid mismatch: expected {netuid}, got {payload.netuid}"
    if payload.expires_at <= now:
        return "payload expired"
    if (now - payload.computed_at).total_seconds() > weights_freshness_seconds:
        return "payload stale"
    if not payload.uids:
        return "uids vector is empty"
    if not payload.weights:
        return "weights vector is empty"
    if len(payload.uids) != len(payload.weights):
        return "uids and weights vector lengths differ"
    return None


class WeightsClient:
    def __init__(
        self, base_url: str, *, timeout_seconds: float = 15.0, retries: int = 3
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.retries = retries

    async def fetch_latest(self) -> MasterWeightsResponse:
        last_error: Exception | None = None
        for attempt in range(max(1, self.retries + 1)):
            try:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    response = await client.get(f"{self.base_url}/v1/weights/latest")
                    response.raise_for_status()
                    return MasterWeightsResponse.model_validate(response.json())
            except Exception as exc:
                last_error = exc
                if attempt < self.retries:
                    await asyncio.sleep(0)
        raise last_error or RuntimeError("weights fetch failed")
