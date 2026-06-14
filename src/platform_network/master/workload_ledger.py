"""Authoritative active-workload ledger for the Docker/Swarm backend.

This module is the SINGLE source of truth for active Docker/Swarm workloads
launched by the platform. Both the broker quota check (``docker_max_concurrent``
enforcement at ``/v1/docker/run``) and the supervisor timeout reaper import
THIS module — no duplicate state may exist anywhere else.

Design decisions (see ``.omo/plans/platform-docker-migration.md`` Task 7):

* Entries are keyed by Swarm **service ID** (``kind="swarm_service"``) or, for
  the privileged escape hatch, by **container ID**
  (``kind="escape_hatch_container"``).
* Quota counting uses ledger entries ONLY. Docker labels are forgeable and are
  never consulted for counting.
* Deadlines are computed from the daemon-reported ``StartedAt`` timestamp plus
  ``timeout_seconds`` — never from cross-host wall-clock at registration time.
  When ``StartedAt`` is unknown at registration (e.g. ``docker service
  create`` returns before the task starts), the deadline stays ``None`` and is
  computed lazily once :meth:`WorkloadLedger.observe_started_at` records the
  first daemon observation.
* ``workload_class="service"`` entries (long-lived workloads such as PRISM)
  NEVER have a deadline and are never eligible for reaping.
* :meth:`WorkloadLedger.reconstruct` rebuilds the full state from one daemon
  listing per node (validator + worker) via the injectable
  :class:`WorkloadSource` protocol, so a restarted supervisor can restore the
  ledger before making any reaping decision.

Thread-safety: the broker exposes synchronous ``def`` FastAPI handlers, which
FastAPI executes on a thread pool, so concurrent register/release calls arrive
on multiple OS threads. All mutating and reading ledger operations therefore
synchronize on a single :class:`threading.Lock`; capacity enforcement
(``max_concurrent``) is check-and-register atomic under that lock.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Literal, Protocol

WorkloadKind = Literal["swarm_service", "escape_hatch_container"]
WorkloadClass = Literal["job", "service"]


class WorkloadLedgerError(RuntimeError):
    """Raised when a ledger operation or entry is invalid."""


class WorkloadCapacityError(WorkloadLedgerError):
    """Raised when registering would exceed a challenge's concurrency cap."""

    def __init__(self, challenge_slug: str, *, active: int, max_concurrent: int):
        super().__init__(
            f"challenge {challenge_slug!r} is at its concurrency cap "
            f"({active}/{max_concurrent} active workloads)"
        )
        self.challenge_slug = challenge_slug
        self.active = active
        self.max_concurrent = max_concurrent


@dataclass(frozen=True)
class WorkloadEntry:
    """One active workload tracked by the ledger.

    Attributes:
        key: Swarm service ID, or container ID for escape-hatch workloads.
        kind: How the workload was launched (and therefore how it is removed:
            ``docker service rm`` vs ``docker rm -f``).
        challenge_slug: Owning challenge, the quota-counting dimension.
        workload_class: ``job`` workloads are deadline-bound and reapable;
            ``service`` workloads are long-lived and never reaped.
        started_at: Daemon-reported ``StartedAt`` (timezone-aware). ``None``
            until the daemon has been observed reporting it.
        timeout_seconds: Author/operator timeout for ``job`` workloads.
    """

    key: str
    kind: WorkloadKind
    challenge_slug: str
    workload_class: WorkloadClass = "job"
    started_at: datetime | None = None
    timeout_seconds: int | None = None

    def __post_init__(self) -> None:
        if not self.key:
            raise WorkloadLedgerError("workload key cannot be empty")
        if not self.challenge_slug:
            raise WorkloadLedgerError("challenge slug cannot be empty")
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise WorkloadLedgerError("timeout_seconds must be positive")
        _require_aware(self.started_at, "started_at")

    @property
    def deadline(self) -> datetime | None:
        """Deadline = daemon-reported ``started_at`` + ``timeout_seconds``.

        ``None`` for long-lived ``service`` workloads (never reaped), when no
        timeout is configured, or while ``started_at`` is still unknown.
        """

        if self.workload_class == "service":
            return None
        if self.started_at is None or self.timeout_seconds is None:
            return None
        return self.started_at + timedelta(seconds=self.timeout_seconds)


class WorkloadSource(Protocol):
    """One daemon's listing of active platform workloads.

    Implementations adapt ``docker service ls``/``docker ps`` output (or test
    fakes) into :class:`WorkloadEntry` values for :meth:`WorkloadLedger.reconstruct`.
    """

    def list_workloads(self) -> Sequence[WorkloadEntry]: ...


class WorkloadLedger:
    """Thread-safe authoritative ledger of active Docker/Swarm workloads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, WorkloadEntry] = {}

    def register(
        self, entry: WorkloadEntry, *, max_concurrent: int | None = None
    ) -> WorkloadEntry:
        """Register a workload, atomically enforcing the optional cap.

        Raises:
            WorkloadLedgerError: if ``entry.key`` is already registered.
            WorkloadCapacityError: if registering would exceed ``max_concurrent``
                active workloads for ``entry.challenge_slug``.
        """

        with self._lock:
            if entry.key in self._entries:
                raise WorkloadLedgerError(
                    f"workload {entry.key!r} is already registered"
                )
            if max_concurrent is not None:
                active = self._count_locked(entry.challenge_slug)
                if active >= max_concurrent:
                    raise WorkloadCapacityError(
                        entry.challenge_slug,
                        active=active,
                        max_concurrent=max_concurrent,
                    )
            self._entries[entry.key] = entry
            return entry

    def release(self, key: str) -> bool:
        """Remove a workload by key. Idempotent: returns False when absent."""

        with self._lock:
            return self._entries.pop(key, None) is not None

    def count(self, challenge_slug: str) -> int:
        """Count active ledger entries for a challenge (NEVER Docker labels)."""

        with self._lock:
            return self._count_locked(challenge_slug)

    def get(self, key: str) -> WorkloadEntry | None:
        """Return the entry registered under ``key``, if any."""

        with self._lock:
            return self._entries.get(key)

    def entries(self) -> tuple[WorkloadEntry, ...]:
        """Return a detached snapshot of all active entries."""

        with self._lock:
            return tuple(self._entries.values())

    def observe_started_at(
        self, key: str, started_at: datetime
    ) -> WorkloadEntry | None:
        """Record the daemon-reported ``StartedAt`` for a workload.

        The first daemon observation wins; later calls never overwrite an
        already-known ``started_at``. Returns the (possibly updated) entry, or
        ``None`` when the key is unknown.
        """

        _require_aware(started_at, "started_at")
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.started_at is not None:
                return entry
            updated = replace(entry, started_at=started_at)
            self._entries[key] = updated
            return updated

    def deadline(self, key: str) -> datetime | None:
        """Return the computed deadline for ``key`` (``None`` if not reapable)."""

        with self._lock:
            entry = self._entries.get(key)
            return entry.deadline if entry is not None else None

    def expired(self, now: datetime) -> tuple[WorkloadEntry, ...]:
        """Return workloads whose deadline has passed at ``now``.

        ``now`` must be timezone-aware and should itself derive from daemon
        observations, never a bare cross-host wall clock. ``service``-class
        and deadline-less entries are never returned.
        """

        _require_aware(now, "now")
        with self._lock:
            return tuple(
                entry
                for entry in self._entries.values()
                if entry.deadline is not None and entry.deadline <= now
            )

    def reconstruct(self, daemons: Iterable[WorkloadSource]) -> int:
        """Rebuild the ledger from daemon listings, replacing in-memory state.

        Enumerates EVERY provided daemon (both nodes) so a restarted process
        restores the complete picture before any reaping decision. On
        duplicate keys across daemons, the entry carrying a known
        ``started_at`` is preferred. Returns the number of restored entries.
        """

        listings = [tuple(daemon.list_workloads()) for daemon in daemons]
        rebuilt: dict[str, WorkloadEntry] = {}
        for listing in listings:
            for entry in listing:
                existing = rebuilt.get(entry.key)
                if existing is not None and entry.started_at is None:
                    continue
                rebuilt[entry.key] = entry
        with self._lock:
            self._entries = rebuilt
            return len(self._entries)

    def _count_locked(self, challenge_slug: str) -> int:
        return sum(
            1
            for entry in self._entries.values()
            if entry.challenge_slug == challenge_slug
        )


def _require_aware(value: datetime | None, name: str) -> None:
    if value is not None and value.tzinfo is None:
        raise WorkloadLedgerError(f"{name} must be a timezone-aware datetime")
