"""Create LLM gateway usage metering table.

Revision ID: 0004_create_llm_usage_records
Revises: 0003_create_validator_registry
Create Date: 2026-06-27 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0004_create_llm_usage_records"
down_revision: str | None = "0003_create_validator_registry"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply the migration."""

    op.create_table(
        "llm_usage_records",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("validator_hotkey", sa.Text(), nullable=False),
        sa.Column("assignment_id", sa.Text(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("model", sa.Text(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "completion_tokens", sa.Integer(), server_default="0", nullable=False
        ),
        sa.Column("total_tokens", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_llm_usage_records")),
    )
    op.create_index(
        "ix_llm_usage_records_validator_assignment",
        "llm_usage_records",
        ["validator_hotkey", "assignment_id"],
        unique=False,
    )
    op.create_index(
        "ix_llm_usage_records_created_at",
        "llm_usage_records",
        ["created_at"],
        unique=False,
    )


def downgrade() -> None:
    """Revert the migration."""

    op.drop_index("ix_llm_usage_records_created_at", table_name="llm_usage_records")
    op.drop_index(
        "ix_llm_usage_records_validator_assignment",
        table_name="llm_usage_records",
    )
    op.drop_table("llm_usage_records")
