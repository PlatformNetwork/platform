"""Normalized challenge models for the platform master database."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import Uuid

from platform_network.db.base import Base


class ChallengeStatus(StrEnum):
    """Lifecycle states supported by the master challenge registry."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    DISABLED = "disabled"
    DRAFT = "draft"


class TimestampMixin:
    """Created/updated timestamp columns shared by mutable tables."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class Challenge(Base, TimestampMixin):
    """A registered challenge managed by the platform master."""

    __tablename__ = "challenges"
    __table_args__ = (
        Index("ix_challenges_status", "status"),
        Index("ix_challenges_slug_status", "slug", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    slug: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[ChallengeStatus] = mapped_column(
        Enum(
            ChallengeStatus,
            name="challenge_status",
            values_callable=lambda obj: [e.value for e in obj],
            native_enum=False,
        ),
        nullable=False,
        default=ChallengeStatus.DRAFT,
        server_default=ChallengeStatus.DRAFT.value,
    )
    emission_percent: Mapped[Decimal] = mapped_column(
        Numeric(8, 4),
        nullable=False,
        default=Decimal("0"),
        server_default="0",
    )
    version: Mapped[str] = mapped_column(Text, nullable=False)
    api_version: Mapped[str] = mapped_column(
        Text, nullable=False, default="1.0", server_default="1.0"
    )
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSON,
        nullable=False,
        default=dict,
        server_default="{}",
    )

    image: Mapped[ChallengeImage | None] = relationship(
        back_populates="challenge",
        cascade="all, delete-orphan",
        single_parent=True,
        uselist=False,
    )
    auth: Mapped[ChallengeAuth | None] = relationship(
        back_populates="challenge",
        cascade="all, delete-orphan",
        single_parent=True,
        uselist=False,
    )
    resources: Mapped[list[ChallengeResource]] = relationship(
        back_populates="challenge",
        cascade="all, delete-orphan",
    )
    volumes: Mapped[list[ChallengeVolume]] = relationship(
        back_populates="challenge",
        cascade="all, delete-orphan",
    )
    secrets: Mapped[list[ChallengeSecret]] = relationship(
        back_populates="challenge",
        cascade="all, delete-orphan",
    )
    env: Mapped[list[ChallengeEnv]] = relationship(
        back_populates="challenge",
        cascade="all, delete-orphan",
    )
    capabilities: Mapped[list[ChallengeCapability]] = relationship(
        back_populates="challenge",
        cascade="all, delete-orphan",
    )
    routes: Mapped[list[ChallengeRoute]] = relationship(
        back_populates="challenge",
        cascade="all, delete-orphan",
    )
    health_events: Mapped[list[ChallengeHealthEvent]] = relationship(
        back_populates="challenge",
        cascade="all, delete-orphan",
        order_by="ChallengeHealthEvent.checked_at.desc()",
    )


class ChallengeImage(Base):
    """Container image coordinates for a challenge."""

    __tablename__ = "challenge_images"
    __table_args__ = (
        UniqueConstraint("challenge_id", name="uq_challenge_images_challenge_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False,
    )
    registry_name: Mapped[str] = mapped_column("registry", Text, nullable=False)
    repository: Mapped[str] = mapped_column(Text, nullable=False)
    tag: Mapped[str] = mapped_column(Text, nullable=False)
    digest: Mapped[str | None] = mapped_column(Text)
    pull_policy: Mapped[str] = mapped_column(
        Text, nullable=False, default="if_not_present", server_default="if_not_present"
    )

    challenge: Mapped[Challenge] = relationship(back_populates="image")


class ChallengeAuth(Base):
    """Hashed authentication material for challenge internal endpoints."""

    __tablename__ = "challenge_auth"
    __table_args__ = (
        UniqueConstraint("challenge_id", name="uq_challenge_auth_challenge_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    token_hint: Mapped[str | None] = mapped_column(Text)
    broker_token_hash: Mapped[str | None] = mapped_column(Text)
    broker_token_hint: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    challenge: Mapped[Challenge] = relationship(back_populates="auth")


class ChallengeResource(Base):
    """A named runtime resource value requested by a challenge."""

    __tablename__ = "challenge_resources"
    __table_args__ = (
        UniqueConstraint(
            "challenge_id", "key", name="uq_challenge_resources_challenge_key"
        ),
        Index("ix_challenge_resources_challenge_id", "challenge_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False,
    )
    key: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)

    challenge: Mapped[Challenge] = relationship(back_populates="resources")


class ChallengeVolume(Base):
    """A Docker volume mount requested by a challenge."""

    __tablename__ = "challenge_volumes"
    __table_args__ = (
        UniqueConstraint(
            "challenge_id", "name", name="uq_challenge_volumes_challenge_name"
        ),
        Index("ix_challenge_volumes_challenge_id", "challenge_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    mount_path: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[str] = mapped_column(Text, nullable=False)

    challenge: Mapped[Challenge] = relationship(back_populates="volumes")


class ChallengeSecret(Base):
    """A file secret mounted into a challenge container."""

    __tablename__ = "challenge_secrets"
    __table_args__ = (
        UniqueConstraint(
            "challenge_id", "name", name="uq_challenge_secrets_challenge_name"
        ),
        Index("ix_challenge_secrets_challenge_id", "challenge_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    mount_path: Mapped[str] = mapped_column(Text, nullable=False)
    source_path: Mapped[str] = mapped_column(Text, nullable=False)

    challenge: Mapped[Challenge] = relationship(back_populates="secrets")


class ChallengeEnv(Base):
    """An environment variable definition for a challenge container."""

    __tablename__ = "challenge_env"
    __table_args__ = (
        UniqueConstraint("challenge_id", "key", name="uq_challenge_env_challenge_key"),
        Index("ix_challenge_env_challenge_id", "challenge_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False,
    )
    key: Mapped[str] = mapped_column(Text, nullable=False)
    value_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    is_secret: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )

    challenge: Mapped[Challenge] = relationship(back_populates="env")


class ChallengeCapability(Base):
    """A named capability advertised by a challenge."""

    __tablename__ = "challenge_capabilities"
    __table_args__ = (
        UniqueConstraint(
            "challenge_id", "name", name="uq_challenge_capabilities_challenge_name"
        ),
        Index("ix_challenge_capabilities_challenge_id", "challenge_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str | None] = mapped_column(Text)

    challenge: Mapped[Challenge] = relationship(back_populates="capabilities")


class ChallengeRoute(Base):
    """A public route prefix exposed by a challenge through the proxy."""

    __tablename__ = "challenge_routes"
    __table_args__ = (
        UniqueConstraint(
            "challenge_id", "public_prefix", name="uq_challenge_routes_challenge_prefix"
        ),
        Index("ix_challenge_routes_challenge_id", "challenge_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False,
    )
    public_prefix: Mapped[str] = mapped_column(Text, nullable=False)
    proxy_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="1"
    )

    challenge: Mapped[Challenge] = relationship(back_populates="routes")


class ChallengeHealthEvent(Base):
    """Historical health/version observations for a challenge."""

    __tablename__ = "challenge_health_events"
    __table_args__ = (
        Index(
            "ix_challenge_health_events_challenge_checked", "challenge_id", "checked_at"
        ),
        Index("ix_challenge_health_events_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str | None] = mapped_column(Text)
    message: Mapped[str | None] = mapped_column(Text)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    challenge: Mapped[Challenge] = relationship(back_populates="health_events")


class MinerRequestNonce(Base):
    """Replay protection for signed miner uploads accepted by the proxy."""

    __tablename__ = "miner_request_nonces"
    __table_args__ = (
        UniqueConstraint(
            "netuid",
            "challenge_slug",
            "hotkey",
            "nonce",
            name="uq_miner_request_nonces_scope",
        ),
        Index("ix_miner_request_nonces_created_at", "created_at"),
        Index("ix_miner_request_nonces_hotkey", "hotkey"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    netuid: Mapped[int] = mapped_column(Integer, nullable=False)
    challenge_slug: Mapped[str] = mapped_column(Text, nullable=False)
    hotkey: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str] = mapped_column(Text, nullable=False)
    body_hash: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
