"""Challenge API schemas used by the master admin, registry, and proxy apps."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ChallengeStatus(StrEnum):
    """Lifecycle status for a registered challenge."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    DISABLED = "disabled"
    DRAFT = "draft"


class ChallengeCreate(BaseModel):
    """Payload for creating challenge metadata."""

    slug: str = Field(..., min_length=1, pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")
    name: str = Field(..., min_length=1)
    image: str = Field(..., min_length=1)
    version: str = Field(..., min_length=1)
    emission_percent: Decimal = Field(default=Decimal("0"), ge=0)
    status: ChallengeStatus = ChallengeStatus.DRAFT
    description: str | None = None
    api_version: str = Field(default="1.0", min_length=1)
    internal_base_url: str | None = None
    required_capabilities: list[str] = Field(
        default_factory=lambda: ["get_weights", "proxy_routes"]
    )
    resources: dict[str, str] = Field(default_factory=dict)
    volumes: dict[str, str] = Field(default_factory=dict)
    env: dict[str, str] = Field(default_factory=dict)
    secrets: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("slug")
    @classmethod
    def normalize_slug(cls, value: str) -> str:
        """Normalize challenge slugs for stable route and container names."""

        return value.lower()


class ChallengeUpdate(BaseModel):
    """Payload for patching mutable challenge metadata."""

    name: str | None = Field(default=None, min_length=1)
    image: str | None = Field(default=None, min_length=1)
    version: str | None = Field(default=None, min_length=1)
    emission_percent: Decimal | None = Field(default=None, ge=0)
    status: ChallengeStatus | None = None
    description: str | None = None
    api_version: str | None = Field(default=None, min_length=1)
    internal_base_url: str | None = None
    required_capabilities: list[str] | None = None
    resources: dict[str, str] | None = None
    volumes: dict[str, str] | None = None
    env: dict[str, str] | None = None
    secrets: list[str] | None = None
    metadata: dict[str, Any] | None = None


class ChallengeRecord(BaseModel):
    """Persistable challenge metadata.

    This model intentionally excludes clear-text challenge tokens. Runtime storage
    keeps only a token hash and hint so registry/admin responses cannot leak the
    internal challenge shared secret.
    """

    model_config = ConfigDict(use_enum_values=True)

    slug: str
    name: str
    image: str
    version: str
    emission_percent: Decimal
    status: ChallengeStatus
    token_hash: str
    token_hint: str
    broker_token_hash: str | None = None
    broker_token_hint: str | None = None
    description: str | None = None
    api_version: str = "1.0"
    internal_base_url: str
    public_proxy_base_path: str
    required_capabilities: list[str] = Field(
        default_factory=lambda: ["get_weights", "proxy_routes"]
    )
    resources: dict[str, str] = Field(default_factory=dict)
    volumes: dict[str, str] = Field(default_factory=dict)
    env: dict[str, str] = Field(default_factory=dict)
    secrets: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ChallengeAdminView(BaseModel):
    """Admin-safe challenge representation."""

    slug: str
    name: str
    image: str
    version: str
    emission_percent: Decimal
    status: ChallengeStatus
    token_hint: str
    broker_token_hint: str | None = None
    description: str | None = None
    api_version: str
    internal_base_url: str
    public_proxy_base_path: str
    required_capabilities: list[str]
    resources: dict[str, str]
    volumes: dict[str, str]
    env: dict[str, str]
    secrets: list[str]
    metadata: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class ChallengeCreateResponse(BaseModel):
    """Create response that returns the clear token exactly once."""

    challenge: ChallengeAdminView
    challenge_token: str = Field(..., min_length=1)
    docker_broker_token: str = Field(..., min_length=1)


class RegistryChallenge(BaseModel):
    """Challenge metadata exposed through the registry endpoint."""

    slug: str
    name: str
    image: str
    version: str
    emission_percent: Decimal
    status: ChallengeStatus
    internal_base_url: str
    public_proxy_base_path: str
    required_capabilities: list[str]
    resources: dict[str, str]
    volumes: dict[str, str]
    env: dict[str, str]
    secrets: list[str]


class RegistryResponse(BaseModel):
    """Validator-facing registry response."""

    network: str = "platform"
    api_version: str = "1.0"
    master_uid: int = 0
    challenges: list[RegistryChallenge]


class RuntimeOperationResponse(BaseModel):
    """Response for runtime operations such as pull and restart."""

    slug: str
    operation: str
    status: str
    detail: str | None = None
