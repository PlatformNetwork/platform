"""Create the work_assignments coordination table.

Revision ID: 0005_create_work_assignments
Revises: 0004_create_llm_usage_records
Create Date: 2026-06-27 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0005_create_work_assignments"
down_revision: str | None = "0004_create_llm_usage_records"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

work_assignment_status = sa.Enum(
    "pending",
    "assigned",
    "running",
    "completed",
    "failed",
    name="work_assignment_status",
    native_enum=False,
)


def upgrade() -> None:
    """Apply the migration."""

    op.create_table(
        "work_assignments",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("challenge_slug", sa.Text(), nullable=False),
        sa.Column("work_unit_id", sa.Text(), nullable=False),
        sa.Column("submission_ref", sa.Text(), nullable=False),
        sa.Column("payload", sa.JSON(), server_default="{}", nullable=False),
        sa.Column(
            "required_capability", sa.Text(), server_default="cpu", nullable=False
        ),
        sa.Column("assigned_validator_hotkey", sa.Text(), nullable=True),
        sa.Column(
            "status", work_assignment_status, server_default="pending", nullable=False
        ),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("max_attempts", sa.Integer(), server_default="3", nullable=False),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_progress_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("checkpoint_ref", sa.Text(), nullable=True),
        sa.Column("result_ref", sa.Text(), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_work_assignments")),
        sa.UniqueConstraint(
            "challenge_slug",
            "work_unit_id",
            name="uq_work_assignments_challenge_work_unit",
        ),
    )
    op.create_index(
        "ix_work_assignments_challenge_slug",
        "work_assignments",
        ["challenge_slug"],
        unique=False,
    )
    op.create_index(
        "ix_work_assignments_status",
        "work_assignments",
        ["status"],
        unique=False,
    )
    op.create_index(
        "ix_work_assignments_assigned_validator_hotkey",
        "work_assignments",
        ["assigned_validator_hotkey"],
        unique=False,
    )
    op.create_index(
        "ix_work_assignments_status_validator",
        "work_assignments",
        ["status", "assigned_validator_hotkey"],
        unique=False,
    )
    op.create_index(
        "ix_work_assignments_status_deadline",
        "work_assignments",
        ["status", "deadline_at"],
        unique=False,
    )


def downgrade() -> None:
    """Revert the migration."""

    op.drop_index("ix_work_assignments_status_deadline", table_name="work_assignments")
    op.drop_index("ix_work_assignments_status_validator", table_name="work_assignments")
    op.drop_index(
        "ix_work_assignments_assigned_validator_hotkey",
        table_name="work_assignments",
    )
    op.drop_index("ix_work_assignments_status", table_name="work_assignments")
    op.drop_index("ix_work_assignments_challenge_slug", table_name="work_assignments")
    op.drop_table("work_assignments")
