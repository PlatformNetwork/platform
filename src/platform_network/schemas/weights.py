from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

MASTER_WEIGHTS_FRESHNESS_SECONDS = 720


class ChallengeWeightsResponse(BaseModel):
    challenge_slug: str
    epoch: int | None = None
    weights: dict[str, float] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    computed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ChallengeWeightsResult(BaseModel):
    slug: str
    emission_percent: float
    weights: dict[str, float] = Field(default_factory=dict)
    ok: bool = True
    error: str | None = None


class FinalWeights(BaseModel):
    uids: list[int]
    weights: list[float]
    hotkey_weights: dict[str, float] = Field(default_factory=dict)


class MasterWeightsResponse(BaseModel):
    netuid: int
    chain_endpoint: str
    uids: list[int]
    weights: list[float]
    hotkey_weights: dict[str, float] = Field(default_factory=dict)
    computed_at: datetime
    expires_at: datetime
    source_challenges: list[ChallengeWeightsResult]
    metagraph_updated_at: datetime

    @field_validator("expires_at")
    @classmethod
    def validate_not_expired(cls, value: datetime) -> datetime:
        if value <= datetime.now(UTC):
            raise ValueError("expires_at must be in the future")
        return value
