"""Create normalized challenge registry tables.

Revision ID: 0001_create_challenge_registry
Revises:
Create Date: 2026-05-05 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0001_create_challenge_registry"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

challenge_status = sa.Enum(
    "active",
    "inactive",
    "disabled",
    "draft",
    name="challenge_status",
    native_enum=False,
)


def upgrade() -> None:
    """Apply the migration."""

    op.create_table(
        "challenges",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("slug", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", challenge_status, server_default="draft", nullable=False),
        sa.Column(
            "emission_percent", sa.Numeric(8, 4), server_default="0", nullable=False
        ),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column("api_version", sa.Text(), server_default="1.0", nullable=False),
        sa.Column(
            "metadata",
            sa.JSON(),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_challenges")),
        sa.UniqueConstraint("slug", name=op.f("uq_challenges_slug")),
    )
    op.create_index(
        "ix_challenges_slug_status", "challenges", ["slug", "status"], unique=False
    )
    op.create_index("ix_challenges_status", "challenges", ["status"], unique=False)

    op.create_table(
        "challenge_images",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("challenge_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("registry", sa.Text(), nullable=False),
        sa.Column("repository", sa.Text(), nullable=False),
        sa.Column("tag", sa.Text(), nullable=False),
        sa.Column("digest", sa.Text(), nullable=True),
        sa.Column(
            "pull_policy", sa.Text(), server_default="if_not_present", nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["challenge_id"],
            ["challenges.id"],
            name=op.f("fk_challenge_images_challenge_id_challenges"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_challenge_images")),
        sa.UniqueConstraint("challenge_id", name="uq_challenge_images_challenge_id"),
    )

    op.create_table(
        "challenge_auth",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("challenge_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("token_hint", sa.Text(), nullable=True),
        sa.Column("broker_token_hash", sa.Text(), nullable=True),
        sa.Column("broker_token_hint", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["challenge_id"],
            ["challenges.id"],
            name=op.f("fk_challenge_auth_challenge_id_challenges"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_challenge_auth")),
        sa.UniqueConstraint("challenge_id", name="uq_challenge_auth_challenge_id"),
    )

    op.create_table(
        "challenge_resources",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("challenge_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["challenge_id"],
            ["challenges.id"],
            name=op.f("fk_challenge_resources_challenge_id_challenges"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_challenge_resources")),
        sa.UniqueConstraint(
            "challenge_id", "key", name="uq_challenge_resources_challenge_key"
        ),
    )
    op.create_index(
        "ix_challenge_resources_challenge_id",
        "challenge_resources",
        ["challenge_id"],
        unique=False,
    )

    op.create_table(
        "challenge_volumes",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("challenge_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("mount_path", sa.Text(), nullable=False),
        sa.Column("type", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["challenge_id"],
            ["challenges.id"],
            name=op.f("fk_challenge_volumes_challenge_id_challenges"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_challenge_volumes")),
        sa.UniqueConstraint(
            "challenge_id", "name", name="uq_challenge_volumes_challenge_name"
        ),
    )
    op.create_index(
        "ix_challenge_volumes_challenge_id",
        "challenge_volumes",
        ["challenge_id"],
        unique=False,
    )

    op.create_table(
        "challenge_secrets",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("challenge_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("mount_path", sa.Text(), nullable=False),
        sa.Column("source_path", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["challenge_id"],
            ["challenges.id"],
            name=op.f("fk_challenge_secrets_challenge_id_challenges"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_challenge_secrets")),
        sa.UniqueConstraint(
            "challenge_id", "name", name="uq_challenge_secrets_challenge_name"
        ),
    )
    op.create_index(
        "ix_challenge_secrets_challenge_id",
        "challenge_secrets",
        ["challenge_id"],
        unique=False,
    )

    op.create_table(
        "challenge_env",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("challenge_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("value_encrypted", sa.Text(), nullable=False),
        sa.Column("is_secret", sa.Boolean(), server_default="0", nullable=False),
        sa.ForeignKeyConstraint(
            ["challenge_id"],
            ["challenges.id"],
            name=op.f("fk_challenge_env_challenge_id_challenges"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_challenge_env")),
        sa.UniqueConstraint(
            "challenge_id", "key", name="uq_challenge_env_challenge_key"
        ),
    )
    op.create_index(
        "ix_challenge_env_challenge_id", "challenge_env", ["challenge_id"], unique=False
    )

    op.create_table(
        "challenge_capabilities",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("challenge_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("version", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["challenge_id"],
            ["challenges.id"],
            name=op.f("fk_challenge_capabilities_challenge_id_challenges"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_challenge_capabilities")),
        sa.UniqueConstraint(
            "challenge_id", "name", name="uq_challenge_capabilities_challenge_name"
        ),
    )
    op.create_index(
        "ix_challenge_capabilities_challenge_id",
        "challenge_capabilities",
        ["challenge_id"],
        unique=False,
    )

    op.create_table(
        "challenge_routes",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("challenge_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("public_prefix", sa.Text(), nullable=False),
        sa.Column("proxy_enabled", sa.Boolean(), server_default="1", nullable=False),
        sa.ForeignKeyConstraint(
            ["challenge_id"],
            ["challenges.id"],
            name=op.f("fk_challenge_routes_challenge_id_challenges"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_challenge_routes")),
        sa.UniqueConstraint(
            "challenge_id", "public_prefix", name="uq_challenge_routes_challenge_prefix"
        ),
    )
    op.create_index(
        "ix_challenge_routes_challenge_id",
        "challenge_routes",
        ["challenge_id"],
        unique=False,
    )

    op.create_table(
        "challenge_health_events",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("challenge_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("version", sa.Text(), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column(
            "checked_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["challenge_id"],
            ["challenges.id"],
            name=op.f("fk_challenge_health_events_challenge_id_challenges"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_challenge_health_events")),
    )
    op.create_index(
        "ix_challenge_health_events_challenge_checked",
        "challenge_health_events",
        ["challenge_id", "checked_at"],
        unique=False,
    )
    op.create_index(
        "ix_challenge_health_events_status",
        "challenge_health_events",
        ["status"],
        unique=False,
    )


def downgrade() -> None:
    """Revert the migration."""

    op.drop_index(
        "ix_challenge_health_events_status", table_name="challenge_health_events"
    )
    op.drop_index(
        "ix_challenge_health_events_challenge_checked",
        table_name="challenge_health_events",
    )
    op.drop_table("challenge_health_events")
    op.drop_index("ix_challenge_routes_challenge_id", table_name="challenge_routes")
    op.drop_table("challenge_routes")
    op.drop_index(
        "ix_challenge_capabilities_challenge_id", table_name="challenge_capabilities"
    )
    op.drop_table("challenge_capabilities")
    op.drop_index("ix_challenge_env_challenge_id", table_name="challenge_env")
    op.drop_table("challenge_env")
    op.drop_index("ix_challenge_secrets_challenge_id", table_name="challenge_secrets")
    op.drop_table("challenge_secrets")
    op.drop_index("ix_challenge_volumes_challenge_id", table_name="challenge_volumes")
    op.drop_table("challenge_volumes")
    op.drop_index(
        "ix_challenge_resources_challenge_id", table_name="challenge_resources"
    )
    op.drop_table("challenge_resources")
    op.drop_table("challenge_auth")
    op.drop_table("challenge_images")
    op.drop_index("ix_challenges_status", table_name="challenges")
    op.drop_index("ix_challenges_slug_status", table_name="challenges")
    op.drop_table("challenges")
