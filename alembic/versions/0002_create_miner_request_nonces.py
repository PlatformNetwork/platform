"""Create miner upload nonce table.

Revision ID: 0002_create_miner_request_nonces
Revises: 0001_create_challenge_registry
Create Date: 2026-05-11 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002_create_miner_request_nonces"
down_revision: str | None = "0001_create_challenge_registry"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply the migration."""

    op.create_table(
        "miner_request_nonces",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("netuid", sa.Integer(), nullable=False),
        sa.Column("challenge_slug", sa.Text(), nullable=False),
        sa.Column("hotkey", sa.Text(), nullable=False),
        sa.Column("nonce", sa.Text(), nullable=False),
        sa.Column("body_hash", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_miner_request_nonces")),
        sa.UniqueConstraint(
            "netuid",
            "challenge_slug",
            "hotkey",
            "nonce",
            name="uq_miner_request_nonces_scope",
        ),
    )
    op.create_index(
        "ix_miner_request_nonces_created_at",
        "miner_request_nonces",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_miner_request_nonces_hotkey",
        "miner_request_nonces",
        ["hotkey"],
        unique=False,
    )


def downgrade() -> None:
    """Revert the migration."""

    op.drop_index("ix_miner_request_nonces_hotkey", table_name="miner_request_nonces")
    op.drop_index(
        "ix_miner_request_nonces_created_at", table_name="miner_request_nonces"
    )
    op.drop_table("miner_request_nonces")
