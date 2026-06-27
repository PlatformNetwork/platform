"""Assignment lifecycle binding for scoped gateway tokens.

A scoped gateway token only authorizes calls while its assignment is active. Once
the assignment is completed, failed, reassigned away, or revoked, the token must
be rejected even though its signature and expiry still verify (architecture.md
sec 5; VAL-LLM-023). The gateway consults an :class:`AssignmentLifecycleResolver`
on every call; the concrete master resolver (backed by ``work_assignments``) is
wired by the assignment/coordination plane, while tests use the in-memory one.
"""

from __future__ import annotations

from typing import Protocol


class AssignmentLifecycleResolver(Protocol):
    """Reports whether an assignment is still active for a given validator."""

    async def is_active(self, *, validator_hotkey: str, assignment_id: str) -> bool: ...


class InMemoryAssignmentResolver:
    """An in-memory resolver tracking the set of active (validator, assignment)."""

    def __init__(self, active: set[tuple[str, str]] | None = None) -> None:
        self._active: set[tuple[str, str]] = set(active or set())

    def activate(self, validator_hotkey: str, assignment_id: str) -> None:
        self._active.add((validator_hotkey, assignment_id))

    def deactivate(self, validator_hotkey: str, assignment_id: str) -> None:
        self._active.discard((validator_hotkey, assignment_id))

    async def is_active(self, *, validator_hotkey: str, assignment_id: str) -> bool:
        return (validator_hotkey, assignment_id) in self._active
