"""Minimal sd_notify implementation (systemd ``Type=notify`` protocol).

Speaks the ``NOTIFY_SOCKET`` unix datagram protocol directly via the stdlib
``socket`` module — deliberately NO third-party dependency (no ``sdnotify``,
no ``systemd-python``). When ``NOTIFY_SOCKET`` is unset (dev/test runs outside
systemd) every call degrades to a logged no-op.

Protocol reference: sd_notify(3). Messages are newline-separated
``KEY=VALUE`` assignments sent as single datagrams. Abstract-namespace
sockets are advertised by systemd with a leading ``@`` which maps to a
leading NUL byte on the wire.
"""

from __future__ import annotations

import logging
import os
import socket

logger = logging.getLogger(__name__)

READY = "READY=1"
WATCHDOG = "WATCHDOG=1"
STOPPING = "STOPPING=1"


class SystemdNotifier:
    """Send sd_notify datagrams to ``NOTIFY_SOCKET``; no-op when unset."""

    def __init__(self, socket_path: str | None = None) -> None:
        if socket_path is None:
            socket_path = os.environ.get("NOTIFY_SOCKET")
        self._address: str | None = None
        if socket_path:
            if socket_path.startswith("@"):
                # Abstract socket namespace: '@' prefix maps to a NUL byte.
                self._address = "\0" + socket_path[1:]
            else:
                self._address = socket_path
        if self._address is None:
            logger.info(
                "NOTIFY_SOCKET unset; sd_notify disabled (running outside systemd)"
            )

    @property
    def enabled(self) -> bool:
        return self._address is not None

    def notify(self, state: str) -> bool:
        """Send one sd_notify state datagram. Returns True when sent.

        Errors are logged, never raised: a broken notify socket must not
        take the supervisor down (systemd's watchdog will handle a truly
        dead manager).
        """
        if self._address is None:
            logger.debug("sd_notify no-op (NOTIFY_SOCKET unset): %s", state)
            return False
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
                sock.sendto(state.encode("utf-8"), self._address)
            return True
        except OSError:
            logger.exception("sd_notify send failed for state %r", state)
            return False

    def ready(self) -> bool:
        return self.notify(READY)

    def watchdog(self) -> bool:
        return self.notify(WATCHDOG)

    def stopping(self) -> bool:
        return self.notify(STOPPING)


def watchdog_interval_seconds(default: float) -> float:
    """Derive the heartbeat interval from systemd's ``WATCHDOG_USEC``.

    systemd exports ``WATCHDOG_USEC`` to ``Type=notify`` services with
    ``WatchdogSec=`` configured. Heartbeating at half the watchdog window is
    the conventional safety margin. Falls back to ``default`` when the
    variable is unset or malformed.
    """
    raw = os.environ.get("WATCHDOG_USEC")
    if not raw:
        return default
    try:
        usec = int(raw)
    except ValueError:
        logger.warning("Ignoring malformed WATCHDOG_USEC=%r", raw)
        return default
    if usec <= 0:
        return default
    return usec / 2 / 1_000_000
