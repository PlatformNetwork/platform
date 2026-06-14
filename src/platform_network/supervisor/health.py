"""Broker health gating for the supervisor.

The broker's ``/health`` endpoint is native ``async`` (Task 15) — its latency
is O(event-loop scheduling) even when every threadpool worker is busy with a
slow ``/v1/docker/*`` call. Per the Task 15 guidance:

- Probe with a SHORT timeout (2-5 s). A healthy broker answers in single-digit
  milliseconds; anything slower than the timeout means the process/loop is
  genuinely wedged, not merely loaded.
- Trip only after 2-3 CONSECUTIVE failures, so one dropped packet or probe
  hiccup does not flap the gate.
- NEVER treat slow ``/v1/docker/*`` operations (run/list/cleanup) as a health
  signal — broker load is not broker death.

The probe itself runs as an ordinary :class:`ScheduledTask` on its own worker
thread, so even a probe stuck up to its socket timeout can never stall the
supervisor loop or its watchdog heartbeats.
"""

from __future__ import annotations

import logging
import threading
import urllib.error
import urllib.request
from collections.abc import Callable

logger = logging.getLogger(__name__)

DEFAULT_PROBE_TIMEOUT_SECONDS = 3.0
DEFAULT_FAILURE_THRESHOLD = 3


def http_health_prober(url: str, timeout_seconds: float) -> Callable[[], bool]:
    """Build a prober hitting ``url`` with a hard socket timeout."""

    def probe() -> bool:
        try:
            with urllib.request.urlopen(url, timeout=timeout_seconds) as response:
                return bool(200 <= response.status < 300)
        except (urllib.error.URLError, OSError, TimeoutError):
            return False

    return probe


class BrokerHealthGate:
    """Tracks consecutive ``/health`` failures behind a threshold.

    ``healthy`` stays True until ``failure_threshold`` consecutive probe
    failures accumulate; any success resets the counter. Thread-safe: the
    probe task records from its worker thread while consumers (future
    Tasks 17-22 ticks deciding whether to touch the broker) read from theirs.
    """

    def __init__(
        self,
        prober: Callable[[], bool],
        *,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        self._prober = prober
        self._failure_threshold = failure_threshold
        self._consecutive_failures = 0
        self._lock = threading.Lock()

    @property
    def healthy(self) -> bool:
        with self._lock:
            return self._consecutive_failures < self._failure_threshold

    @property
    def consecutive_failures(self) -> int:
        with self._lock:
            return self._consecutive_failures

    def record(self, success: bool) -> None:
        with self._lock:
            previously_healthy = self._consecutive_failures < self._failure_threshold
            if success:
                self._consecutive_failures = 0
            else:
                self._consecutive_failures += 1
            now_healthy = self._consecutive_failures < self._failure_threshold
        if previously_healthy and not now_healthy:
            logger.warning(
                "broker health gate tripped after %d consecutive probe failures",
                self._failure_threshold,
            )
        elif not previously_healthy and now_healthy:
            logger.info("broker health gate recovered")

    def probe_once(self) -> None:
        """One probe tick: run the prober and record the outcome."""
        self.record(self._prober())
