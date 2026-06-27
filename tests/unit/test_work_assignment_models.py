"""Model + migration-parity tests for the ``work_assignments`` table.

Covers the model-side of VAL-ASSIGN-030/031: the ORM table exists with the
documented columns, a status enum (non-native varchar), the
``(challenge_slug, work_unit_id)`` unique constraint, and migration enum
literals that match the model.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import cast

from sqlalchemy import Enum as SQLAlchemyEnum
from sqlalchemy import UniqueConstraint

from base.db import Base, WorkAssignment, WorkAssignmentStatus

ROOT_DIR = Path(__file__).resolve().parents[2]
WORK_ASSIGNMENT_MIGRATION = (
    ROOT_DIR / "alembic/versions/0005_create_work_assignments.py"
)


def test_work_assignment_model_constructs_and_registers_metadata() -> None:
    assignment = WorkAssignment(
        challenge_slug="agent-challenge",
        work_unit_id="sub-1:task-0",
        submission_ref="hk-abc",
        payload={"task_id": "task-0"},
        required_capability="cpu",
        status=WorkAssignmentStatus.PENDING,
    )

    assert assignment.challenge_slug == "agent-challenge"
    assert assignment.work_unit_id == "sub-1:task-0"
    assert assignment.required_capability == "cpu"
    assert assignment.status == WorkAssignmentStatus.PENDING
    assert "work_assignments" in Base.metadata.tables


def test_work_assignment_has_documented_columns() -> None:
    columns = set(Base.metadata.tables["work_assignments"].c.keys())
    assert {
        "id",
        "challenge_slug",
        "work_unit_id",
        "submission_ref",
        "payload",
        "required_capability",
        "assigned_validator_hotkey",
        "status",
        "attempt_count",
        "max_attempts",
        "deadline_at",
        "last_progress_at",
        "checkpoint_ref",
        "result_ref",
        "created_at",
        "updated_at",
    } <= columns


def test_work_assignment_status_enum_is_non_native_varchar() -> None:
    status_column = WorkAssignment.__table__.c.status
    status_type = cast(SQLAlchemyEnum, status_column.type)
    assert status_type.name == "work_assignment_status"
    assert status_type.native_enum is False
    assert status_type.enums == [status.value for status in WorkAssignmentStatus]


def test_work_assignment_has_challenge_work_unit_unique_constraint() -> None:
    table = Base.metadata.tables["work_assignments"]
    unique_columns = {
        tuple(sorted(column.name for column in constraint.columns))
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("challenge_slug", "work_unit_id") in unique_columns


def test_work_assignment_indices_present() -> None:
    table = Base.metadata.tables["work_assignments"]
    index_names = {index.name for index in table.indexes}
    assert {
        "ix_work_assignments_challenge_slug",
        "ix_work_assignments_status",
        "ix_work_assignments_assigned_validator_hotkey",
        "ix_work_assignments_status_validator",
        "ix_work_assignments_status_deadline",
    } <= index_names


def _migration_enum_literals(name: str) -> list[str]:
    migration_ast = ast.parse(WORK_ASSIGNMENT_MIGRATION.read_text(encoding="utf-8"))
    for node in migration_ast.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            continue
        enum_call = node.value
        assert isinstance(enum_call, ast.Call)
        return [
            arg.value
            for arg in enum_call.args
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
        ]
    raise AssertionError(f"{name} enum declaration not found in migration")


def test_migration_enum_literals_match_model_enum() -> None:
    assert _migration_enum_literals("work_assignment_status") == [
        status.value for status in WorkAssignmentStatus
    ]
