"""Scheduled-task abstraction for the supervisor.

Tasks 17-22 each contribute one :class:`ScheduledTask` (reaper,
image-updater, challenge-image-updater, config-sync, weights, self-update).
They register through ``supervisor/tasks.py`` — NOT by editing this module
or the loop.

Execution model (one dedicated thread per task, fixed-delay ticks):

- Each task runs in its own daemon thread, so a slow or blocked task can
  never starve the supervisor's watchdog heartbeat (which lives on the main
  thread) or any other task.
- The next tick is scheduled ``interval_seconds`` AFTER the previous run
  completes (fixed delay). Slow runs therefore shift subsequent ticks —
  missed ticks never stack into a catch-up burst.
- A task callable raising is logged and the schedule continues; one broken
  task cannot kill the loop or its siblings.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScheduledTask:
    """A named periodic job: run ``run()`` every ``interval_seconds``."""

    name: str
    interval_seconds: float
    run: Callable[[], None]

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise ValueError("ScheduledTask.name must be a non-empty string")
        if self.interval_seconds <= 0:
            raise ValueError(
                f"ScheduledTask {self.name!r} interval_seconds must be positive, "
                f"got {self.interval_seconds!r}"
            )


@dataclass
class TaskWorker:
    """Runs one :class:`ScheduledTask` on its own thread until shutdown."""

    task: ScheduledTask
    shutdown: threading.Event
    initial_delay_seconds: float = 0.0
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError(f"task worker {self.task.name!r} already started")
        self._thread = threading.Thread(
            target=self._loop,
            name=f"supervisor-task-{self.task.name}",
            daemon=True,
        )
        self._thread.start()

    def join(self, timeout: float | None = None) -> bool:
        """Join the worker thread. Returns True when it exited in time."""
        if self._thread is None:
            return True
        self._thread.join(timeout)
        return not self._thread.is_alive()

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _loop(self) -> None:
        if self.initial_delay_seconds > 0 and self.shutdown.wait(
            self.initial_delay_seconds
        ):
            return
        while not self.shutdown.is_set():
            try:
                self.task.run()
            except Exception:
                logger.exception(
                    "scheduled task %r raised; continuing schedule", self.task.name
                )
            # Fixed-delay scheduling: wait the full interval AFTER the run
            # finished, so slow runs shift ticks instead of stacking them.
            if self.shutdown.wait(self.task.interval_seconds):
                return
