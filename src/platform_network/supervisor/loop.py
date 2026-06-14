"""Supervisor core loop: lifecycle + watchdog heartbeat.

This module is deliberately FROZEN for Tasks 17-22: new periodic jobs plug in
via ``supervisor/tasks.py`` (one module per job + one registration line) and
never edit this file.

Responsibilities of the main thread:

- Install SIGTERM/SIGINT handlers (when running on the main thread).
- Emit ``READY=1`` once after all task workers start.
- Emit ``WATCHDOG=1`` every ``heartbeat_interval_seconds`` — nothing else
  runs on this thread, so no scheduled task (however slow or blocked) can
  starve the heartbeat.
- On shutdown: emit ``STOPPING=1``, signal all workers, join them within a
  grace period, exit 0.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
import types
from collections.abc import Iterable

from platform_network.supervisor.scheduler import ScheduledTask, TaskWorker
from platform_network.supervisor.sd_notify import SystemdNotifier

logger = logging.getLogger(__name__)

DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 5.0
DEFAULT_SHUTDOWN_GRACE_SECONDS = 10.0


class Supervisor:
    """Long-running control-plane supervisor for the Docker backend."""

    def __init__(
        self,
        *,
        notifier: SystemdNotifier | None = None,
        heartbeat_interval_seconds: float = DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
        shutdown_grace_seconds: float = DEFAULT_SHUTDOWN_GRACE_SECONDS,
    ) -> None:
        if heartbeat_interval_seconds <= 0:
            raise ValueError("heartbeat_interval_seconds must be positive")
        if shutdown_grace_seconds < 0:
            raise ValueError("shutdown_grace_seconds must be >= 0")
        self._notifier = notifier if notifier is not None else SystemdNotifier()
        self._heartbeat_interval_seconds = heartbeat_interval_seconds
        self._shutdown_grace_seconds = shutdown_grace_seconds
        self._shutdown = threading.Event()
        self._tasks: list[ScheduledTask] = []
        self._workers: list[TaskWorker] = []

    @property
    def tasks(self) -> tuple[ScheduledTask, ...]:
        return tuple(self._tasks)

    def register(self, task: ScheduledTask) -> None:
        """Register one periodic task. Must happen before :meth:`run`."""
        if any(existing.name == task.name for existing in self._tasks):
            raise ValueError(f"duplicate scheduled task name: {task.name!r}")
        self._tasks.append(task)

    def register_all(self, tasks: Iterable[ScheduledTask]) -> None:
        for task in tasks:
            self.register(task)

    def request_shutdown(self) -> None:
        self._shutdown.set()

    def run(self) -> int:
        """Run until SIGTERM/SIGINT (or :meth:`request_shutdown`). Returns 0."""
        self._install_signal_handlers()
        for task in self._tasks:
            logger.info(
                "registered scheduled task %r (interval %.1fs)",
                task.name,
                task.interval_seconds,
            )
            worker = TaskWorker(task=task, shutdown=self._shutdown)
            self._workers.append(worker)
            worker.start()
        self._notifier.ready()
        logger.info(
            "supervisor ready: %d scheduled task(s), heartbeat every %.1fs",
            len(self._workers),
            self._heartbeat_interval_seconds,
        )
        try:
            while not self._shutdown.wait(self._heartbeat_interval_seconds):
                self._notifier.watchdog()
                logger.debug("watchdog heartbeat sent")
        finally:
            self._notifier.stopping()
            self._shutdown.set()
            self._join_workers()
        logger.info("supervisor stopped cleanly")
        return 0

    def _install_signal_handlers(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            logger.debug("not on the main thread; skipping signal handler install")
            return

        def _handle(signum: int, _frame: types.FrameType | None) -> None:
            logger.info(
                "received signal %s; shutting down", signal.Signals(signum).name
            )
            self.request_shutdown()

        signal.signal(signal.SIGTERM, _handle)
        signal.signal(signal.SIGINT, _handle)

    def _join_workers(self) -> None:
        deadline = time.monotonic() + self._shutdown_grace_seconds
        for worker in self._workers:
            remaining = max(0.0, deadline - time.monotonic())
            if not worker.join(timeout=remaining):
                logger.warning(
                    "scheduled task %r did not stop within the %.1fs grace period; "
                    "abandoning daemon thread",
                    worker.task.name,
                    self._shutdown_grace_seconds,
                )
