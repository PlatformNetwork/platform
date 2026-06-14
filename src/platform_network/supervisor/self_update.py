"""Supervisor self-update — staged, health-gated replacement for helm ``--atomic``.

The Kubernetes helm-upgrader CronJob re-ran ``helm upgrade --install
--atomic --wait --cleanup-on-fail`` from a GitHub tarball every five
minutes; ``--atomic`` gave it transactional rollback. On the Docker backend
the supervisor must upgrade ITSELF with the same guarantees. Design:

Release layout (all paths under one root, default
``/var/lib/platform/supervisor``)::

    <root>/releases/<version>/     # one immutable checkout per release
    <root>/current                 # symlink -> releases/<version>
    <root>/self_update_state.json  # update state machine (atomic writes)

The systemd unit (``deploy/swarm/platform-supervisor.service``) launches
through ``current`` with ``Restart=always``, so EVERY process exit — clean
or crash — re-execs whatever ``current`` points at. ``systemctl stop``
still stops the unit (systemd never auto-restarts after an explicit stop).

Update lifecycle (one ``self-update`` :class:`ScheduledTask` tick):

1. **Detect** — ``version_detector()`` returns the latest published
   release (default: fetch a tiny JSON manifest, see
   :func:`http_manifest_detector`; the production manifest URL is wired at
   deployment, Task 27 — an unwired detector is an inert no-op).
2. **Stage** — materialize ``releases/<version>/`` SIDE-BY-SIDE via the
   ``stager`` seam (default :func:`tarball_stager`: GitHub-style tarball +
   ``uv sync``). Staging writes into ``releases/<version>.staging`` and
   renames into place, so a half-staged dir is never mistaken for a
   release. Staging never touches the running or previous release.
3. **Pre-swap health gate** (BOTH must pass, or NO swap):
   (a) the shared :class:`BrokerHealthGate` must currently be healthy —
   never "upgrade" an already-broken node into ambiguity (a rollback
   decision needs a known-good baseline);
   (b) the STAGED release must pass ``release_prober`` (default: the
   staged checkout can at least import/execute — catches releases so
   broken they could never run the rollback agent below).
4. **Swap** — write ``state=pending`` (recording the previous version),
   then atomically flip ``current`` (temp symlink + ``os.replace``, a
   single ``rename(2)``), then request a restart (default: SIGTERM to our
   own pid → the supervisor's clean-shutdown path → exit → systemd
   re-execs ``current``).
5. **Post-swap health gate** — the NEW process must prove itself:
   - :func:`run_startup_rollback_check` (called once from the
     ``tasks.py`` build path at startup) increments a persisted
     ``boot_attempts`` counter while the update is pending. More than
     ``max_boot_attempts`` boots without a commit = restart storm → the
     hook flips ``current`` back to the previous release, marks the state
     ``rolled-back`` and exits (systemd re-execs the OLD version). This is
     the rollback agent.
   - The new process COMMITS the update on a later ``self-update`` tick
     once it has been up for ``min_uptime_seconds`` AND the broker health
     gate is healthy. Budget: commit normally lands on the first tick
     after ``min_uptime_seconds``; rollback triggers within
     ``max_boot_attempts`` systemd restart cycles.
6. **Retention invariant** — this module NEVER deletes a release
   directory. The previous release therefore always survives until (and
   beyond) the new one's commit; pruning anything older than the previous
   release is an explicit operator/runbook action (Task 27).

A version that was rolled back is remembered in the state file and never
re-attempted until the detector advertises a DIFFERENT version.

Crash consistency: every mutation is either an atomic state-file replace
or the single atomic symlink flip, and every intermediate state is
recoverable — ``current`` always points at a complete release dir, so the
system is launchable at any crash point (see the crash matrix in the
migration notepad, Task 22 section).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import tarfile
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from platform_network.config.settings import Settings
from platform_network.master.swarm_backend import SwarmCliRunner, SwarmCommandRunner
from platform_network.supervisor.health import BrokerHealthGate
from platform_network.supervisor.scheduler import ScheduledTask

logger = logging.getLogger(__name__)

DEFAULT_RELEASE_ROOT = Path("/var/lib/platform/supervisor")
SELF_UPDATE_INTERVAL_SECONDS = 300.0  # parity with autoUpgrade.schedule */5.
DEFAULT_MIN_UPTIME_SECONDS = 30.0  # one full WatchdogSec window.
DEFAULT_MAX_BOOT_ATTEMPTS = 3
DEFAULT_COMMAND_TIMEOUT_SECONDS = 600.0
ROLLBACK_EXIT_CODE = 86

STATE_IDLE = "idle"
STATE_PENDING = "pending"
STATE_COMMITTED = "committed"
STATE_ROLLED_BACK = "rolled-back"
STATE_ABORTED = "aborted"


class SelfUpdateRollback(SystemExit):
    """Deliberate process exit after the rollback agent flipped ``current``.

    Subclasses :class:`SystemExit` so no generic ``except Exception``
    handler between the startup hook and the interpreter can swallow it.
    """

    def __init__(self, message: str) -> None:
        super().__init__(ROLLBACK_EXIT_CODE)
        self.message = message


@dataclass(frozen=True)
class AvailableRelease:
    """A published release the detector found."""

    version: str
    source_url: str | None = None

    def __post_init__(self) -> None:
        if not self.version or not self.version.strip():
            raise ValueError("AvailableRelease.version must be non-empty")
        if "/" in self.version or self.version in {".", ".."}:
            raise ValueError(f"AvailableRelease.version unsafe: {self.version!r}")


@dataclass(frozen=True)
class UpdateState:
    """Persisted self-update state machine record."""

    status: str = STATE_IDLE
    previous: str | None = None
    new: str | None = None
    boot_attempts: int = 0


@dataclass(frozen=True)
class ReleasePaths:
    """Filesystem layout for staged releases."""

    root: Path = DEFAULT_RELEASE_ROOT

    @property
    def releases(self) -> Path:
        return self.root / "releases"

    @property
    def current(self) -> Path:
        return self.root / "current"

    @property
    def state_file(self) -> Path:
        return self.root / "self_update_state.json"

    def release_dir(self, version: str) -> Path:
        return self.releases / version

    def staging_dir(self, version: str) -> Path:
        return self.releases / f"{version}.staging"

    def current_version(self) -> str | None:
        """Version name ``current`` points at, or None when absent."""
        try:
            target = os.readlink(self.current)
        except OSError:
            return None
        return Path(target).name


VersionDetector = Callable[[], AvailableRelease | None]
ReleaseStager = Callable[[AvailableRelease, Path], None]
ReleaseProber = Callable[[Path], bool]


def load_state(paths: ReleasePaths) -> UpdateState:
    """Read the persisted state; any unreadable/absent file means idle."""
    try:
        raw = json.loads(paths.state_file.read_text())
    except (OSError, ValueError):
        return UpdateState()
    if not isinstance(raw, dict):
        return UpdateState()
    status = raw.get("status")
    previous = raw.get("previous")
    new = raw.get("new")
    attempts = raw.get("boot_attempts")
    return UpdateState(
        status=status if isinstance(status, str) else STATE_IDLE,
        previous=previous if isinstance(previous, str) else None,
        new=new if isinstance(new, str) else None,
        boot_attempts=attempts if isinstance(attempts, int) else 0,
    )


def save_state(paths: ReleasePaths, state: UpdateState) -> None:
    """Atomically persist ``state`` (temp file + fsync + ``os.replace``)."""
    paths.root.mkdir(parents=True, exist_ok=True)
    payload = {
        "status": state.status,
        "previous": state.previous,
        "new": state.new,
        "boot_attempts": state.boot_attempts,
    }
    tmp = paths.state_file.with_name(paths.state_file.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, paths.state_file)


def atomic_symlink_swap(link: Path, target: str) -> None:
    """Point ``link`` at ``target`` via ONE atomic ``rename(2)``.

    A temp symlink is created next to ``link`` and ``os.replace``d over
    it; a crash at any point leaves either the old or the new link intact,
    never a missing/half-written one.
    """
    tmp = link.with_name(link.name + ".swap-tmp")
    try:
        tmp.unlink()
    except FileNotFoundError:
        pass
    os.symlink(target, tmp)
    os.replace(tmp, link)


def detect_running_version(paths: ReleasePaths) -> str | None:
    """Infer which staged release THIS process is running from.

    Resolves this module's ``__file__`` against ``releases/``; a process
    launched from a plain dev checkout (not under ``releases/``) returns
    None and the update machinery treats itself as unmanaged (no commits,
    no rollbacks — log-only).
    """
    try:
        module_path = Path(__file__).resolve()
        relative = module_path.relative_to(paths.releases.resolve())
    except (OSError, ValueError):
        return None
    return relative.parts[0] if relative.parts else None


def http_manifest_detector(
    url: str, *, timeout_seconds: float = 30.0
) -> VersionDetector:
    """Detector fetching a JSON manifest ``{"version": ..., "source_url": ...}``.

    This is the "simple version manifest fetch" detection channel: the
    release pipeline publishes a tiny JSON document (e.g. a raw file on
    the release branch / GitHub release asset) naming the latest
    supervisor release and its source tarball. Errors return None (a
    failed detection is a skipped tick, never a crash).
    """

    def detect() -> AvailableRelease | None:
        try:
            with urllib.request.urlopen(url, timeout=timeout_seconds) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except (OSError, ValueError):
            logger.warning("self-update: manifest fetch failed for %s", url)
            return None
        version = raw.get("version") if isinstance(raw, dict) else None
        if not isinstance(version, str) or not version.strip():
            logger.warning("self-update: manifest at %s has no version", url)
            return None
        source = raw.get("source_url")
        return AvailableRelease(
            version=version.strip(),
            source_url=source if isinstance(source, str) else None,
        )

    return detect


def tarball_stager(
    *,
    runner: SwarmCommandRunner | None = None,
    uv_bin: str = "uv",
    uv_sync: bool = True,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> ReleaseStager:
    """Default stager: GitHub-style tarball download + ``uv sync``.

    Downloads ``release.source_url`` (a codeload-style ``.tar.gz`` whose
    single top-level directory is stripped — same shape the helm-upgrader
    consumed), extracts with the safe ``data`` tar filter, then pre-warms
    the per-release virtualenv with ``uv sync`` so the post-swap boot does
    not pay resolution latency. Raises on any failure; the caller treats a
    raising stager as "release not staged".
    """
    command_runner = runner if runner is not None else SwarmCliRunner()

    def stage(release: AvailableRelease, target_dir: Path) -> None:
        if not release.source_url:
            raise ValueError(
                f"release {release.version!r} has no source_url; cannot stage"
            )
        target_dir.mkdir(parents=True, exist_ok=False)
        archive = target_dir.with_name(target_dir.name + ".tar.gz")
        try:
            response = urllib.request.urlopen(
                release.source_url, timeout=timeout_seconds
            )
            with response, archive.open("wb") as handle:
                shutil.copyfileobj(response, handle)
            with tarfile.open(archive) as tar:
                members = tar.getmembers()
                for member in members:
                    parts = Path(member.name).parts
                    member.name = str(Path(*parts[1:])) if len(parts) > 1 else "."
                tar.extractall(target_dir, members=members, filter="data")
        finally:
            try:
                archive.unlink()
            except FileNotFoundError:
                pass
        if uv_sync:
            result = command_runner.run(
                [uv_bin, "sync", "--project", str(target_dir)],
                timeout_seconds=timeout_seconds,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"uv sync failed for staged release {release.version!r} "
                    f"(rc={result.returncode}): {result.stderr.strip()}"
                )

    return stage


def uv_release_prober(
    *,
    runner: SwarmCommandRunner | None = None,
    uv_bin: str = "uv",
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> ReleaseProber:
    """Default pre-swap smoke probe for a STAGED release.

    Proves the staged checkout's environment can at least import the
    supervisor package (and therefore run the startup rollback agent).
    A release that fails this is never swapped in.
    """
    command_runner = runner if runner is not None else SwarmCliRunner()

    def probe(release_dir: Path) -> bool:
        result = command_runner.run(
            [
                uv_bin,
                "run",
                "--project",
                str(release_dir),
                "python",
                "-c",
                "import platform_network.supervisor.self_update",
            ],
            timeout_seconds=timeout_seconds,
        )
        if result.returncode != 0:
            logger.error(
                "self-update: staged release at %s failed smoke probe (rc=%d): %s",
                release_dir,
                result.returncode,
                result.stderr.strip(),
            )
        return result.returncode == 0

    return probe


def _default_restart_requester() -> None:
    """Ask systemd for a restart by taking the clean-shutdown path.

    SIGTERM to our own pid drives the supervisor's signal handler →
    STOPPING=1, workers joined, exit 0 → with ``Restart=always`` systemd
    re-execs whatever ``current`` now points at.
    """
    logger.info("self-update: requesting supervisor restart (SIGTERM to self)")
    os.kill(os.getpid(), signal.SIGTERM)


class SelfUpdater:
    """Tick body for the ``self-update`` scheduled task."""

    def __init__(
        self,
        paths: ReleasePaths,
        *,
        version_detector: VersionDetector,
        stager: ReleaseStager,
        release_prober: ReleaseProber,
        health_gate: BrokerHealthGate | None = None,
        restart_requester: Callable[[], None] | None = None,
        running_version: Callable[[], str | None] | None = None,
        clock: Callable[[], float] = time.monotonic,
        min_uptime_seconds: float = DEFAULT_MIN_UPTIME_SECONDS,
        max_boot_attempts: int = DEFAULT_MAX_BOOT_ATTEMPTS,
    ) -> None:
        self._paths = paths
        self._detector = version_detector
        self._stager = stager
        self._prober = release_prober
        self._gate = health_gate
        self._restart = (
            restart_requester
            if restart_requester is not None
            else _default_restart_requester
        )
        self._running_version = (
            running_version
            if running_version is not None
            else lambda: detect_running_version(paths)
        )
        self._clock = clock
        self._min_uptime_seconds = min_uptime_seconds
        self._max_boot_attempts = max_boot_attempts
        self._started_at = clock()

    def tick(self) -> None:
        """One scheduled tick; never raises."""
        try:
            self._tick()
        except Exception:
            logger.exception("self-update: tick failed; will retry next interval")

    # ------------------------------------------------------------------

    def _tick(self) -> None:
        state = load_state(self._paths)
        if state.status == STATE_PENDING:
            self._handle_pending(state)
            return
        release = self._detector()
        if release is None:
            return
        current = self._paths.current_version()
        if release.version == current:
            logger.debug("self-update: already on %s; no-op", release.version)
            return
        if state.status == STATE_ROLLED_BACK and state.new == release.version:
            logger.warning(
                "self-update: release %s was previously rolled back; refusing to "
                "retry until a different version is published",
                release.version,
            )
            return
        release_dir = self._ensure_staged(release)
        if release_dir is None:
            return
        # Pre-swap gate (a): never upgrade an already-unhealthy node — a
        # rollback decision needs a known-good baseline to roll back TO.
        if self._gate is not None and not self._gate.healthy:
            logger.warning(
                "self-update: %s staged but broker health gate is unhealthy; "
                "NOT swapping",
                release.version,
            )
            return
        # Pre-swap gate (b): the staged release itself must prove basic
        # viability, otherwise it could never run the rollback agent.
        if not self._prober(release_dir):
            logger.error(
                "self-update: staged release %s failed its pre-swap probe; "
                "NOT swapping",
                release.version,
            )
            return
        self._swap(release.version, previous=current)

    def _ensure_staged(self, release: AvailableRelease) -> Path | None:
        release_dir = self._paths.release_dir(release.version)
        if release_dir.exists():
            return release_dir
        staging = self._paths.staging_dir(release.version)
        if staging.exists():
            # Leftover from a crashed stage attempt — never a live release.
            shutil.rmtree(staging)
        try:
            self._stager(release, staging)
        except Exception:
            logger.exception(
                "self-update: staging release %s failed; will retry", release.version
            )
            return None
        os.replace(staging, release_dir)
        logger.info(
            "self-update: staged release %s at %s", release.version, release_dir
        )
        return release_dir

    def _swap(self, version: str, *, previous: str | None) -> None:
        save_state(
            self._paths,
            UpdateState(
                status=STATE_PENDING,
                previous=previous,
                new=version,
                boot_attempts=0,
            ),
        )
        atomic_symlink_swap(self._paths.current, f"releases/{version}")
        logger.info(
            "self-update: swapped current %s -> %s (previous retained for rollback); "
            "requesting restart",
            previous,
            version,
        )
        self._restart()

    def _handle_pending(self, state: UpdateState) -> None:
        running = self._running_version()
        if running is None:
            logger.warning(
                "self-update: update to %s pending but running version is unknown "
                "(unmanaged checkout?); leaving state untouched",
                state.new,
            )
            return
        if running == state.new:
            uptime = self._clock() - self._started_at
            if uptime < self._min_uptime_seconds:
                return
            if self._gate is not None and not self._gate.healthy:
                logger.warning(
                    "self-update: %s pending commit but broker health gate is "
                    "unhealthy; deferring",
                    state.new,
                )
                return
            save_state(self._paths, replace(state, status=STATE_COMMITTED))
            logger.info(
                "self-update: committed release %s (uptime %.1fs); previous "
                "release %s retained on disk",
                state.new,
                uptime,
                state.previous,
            )
            return
        if running == state.previous:
            if self._paths.current_version() == state.new:
                # Swap flipped but the restart never landed (crash between
                # flip and exit) — re-request, idempotently.
                logger.warning(
                    "self-update: current points at pending release %s but the "
                    "previous version is still running; re-requesting restart",
                    state.new,
                )
                self._restart()
                return
            # current points elsewhere (flip never happened, or the rollback
            # agent flipped back without persisting): clear the pending state.
            save_state(self._paths, replace(state, status=STATE_ABORTED))
            logger.warning(
                "self-update: pending update to %s never took effect; marked "
                "aborted (will re-attempt on next detection)",
                state.new,
            )
            return
        logger.warning(
            "self-update: pending update to %s but running version %s matches "
            "neither new nor previous; leaving state untouched",
            state.new,
            running,
        )


def run_startup_rollback_check(
    paths: ReleasePaths | None = None,
    *,
    running_version: Callable[[], str | None] | None = None,
    max_boot_attempts: int = DEFAULT_MAX_BOOT_ATTEMPTS,
) -> None:
    """Post-swap rollback agent; call ONCE at supervisor startup.

    While an update is ``pending``, every boot of the NEW release
    increments a persisted ``boot_attempts`` counter. Exceeding
    ``max_boot_attempts`` means the new release keeps getting restarted by
    systemd without ever committing (watchdog kills, crashes after
    startup) — the agent then flips ``current`` back to the previous
    release, persists ``rolled-back`` and raises
    :class:`SelfUpdateRollback` so systemd re-execs the OLD version.

    Anything unexpected is swallowed (log-only): a broken state file must
    never stop the supervisor from serving. The deliberate
    :class:`SelfUpdateRollback` exit is the ONLY exception that escapes.
    """
    if paths is None:
        paths = ReleasePaths()
    rollback_message: str | None = None
    try:
        rollback_message = _startup_rollback_decision(
            paths,
            running_version=running_version,
            max_boot_attempts=max_boot_attempts,
        )
    except Exception:
        logger.exception("self-update: startup rollback check failed; continuing")
        return
    if rollback_message is not None:
        raise SelfUpdateRollback(rollback_message)


def _startup_rollback_decision(
    paths: ReleasePaths,
    *,
    running_version: Callable[[], str | None] | None,
    max_boot_attempts: int,
) -> str | None:
    """Apply the boot-attempt budget; return a message when rollback fired."""
    state = load_state(paths)
    if state.status != STATE_PENDING:
        return None
    resolve_running = (
        running_version
        if running_version is not None
        else lambda: detect_running_version(paths)
    )
    running = resolve_running()
    if running != state.new:
        logger.warning(
            "self-update: pending update to %s but this process runs %s; "
            "deferring to the scheduled task",
            state.new,
            running,
        )
        return None
    attempts = state.boot_attempts + 1
    if attempts <= max_boot_attempts:
        save_state(paths, replace(state, boot_attempts=attempts))
        logger.info(
            "self-update: boot %d/%d of pending release %s",
            attempts,
            max_boot_attempts,
            state.new,
        )
        return None
    if state.previous is None:
        save_state(paths, replace(state, status=STATE_ABORTED))
        logger.critical(
            "self-update: pending release %s exceeded %d boot attempts but "
            "there is NO previous release to roll back to; marked aborted",
            state.new,
            max_boot_attempts,
        )
        return None
    atomic_symlink_swap(paths.current, f"releases/{state.previous}")
    save_state(
        paths,
        replace(state, status=STATE_ROLLED_BACK, boot_attempts=attempts),
    )
    logger.critical(
        "self-update: release %s failed its post-swap health gate "
        "(%d boot attempts without commit); rolled current back to %s",
        state.new,
        attempts - 1,
        state.previous,
    )
    return f"rolled back to {state.previous}; exiting so systemd re-execs it"


def build_self_update_task(
    settings: Settings,
    *,
    health_gate: BrokerHealthGate | None = None,
    paths: ReleasePaths | None = None,
    version_detector: VersionDetector | None = None,
    stager: ReleaseStager | None = None,
    release_prober: ReleaseProber | None = None,
    restart_requester: Callable[[], None] | None = None,
    running_version: Callable[[], str | None] | None = None,
    clock: Callable[[], float] = time.monotonic,
    manifest_url: str | None = None,
    min_uptime_seconds: float = DEFAULT_MIN_UPTIME_SECONDS,
    max_boot_attempts: int = DEFAULT_MAX_BOOT_ATTEMPTS,
    interval_seconds: float = SELF_UPDATE_INTERVAL_SECONDS,
) -> ScheduledTask:
    """Build the ``self-update`` :class:`ScheduledTask` (Task-16 recipe).

    ``settings`` is accepted for recipe parity; the release-manifest URL is
    deployment configuration wired by the cutover runbook (Task 27) via
    ``manifest_url``/``version_detector`` — with neither provided the task
    is an inert no-op (the safest default for a self-replacing job).
    """
    del settings  # recipe parity; manifest wiring is deployment territory.
    if paths is None:
        paths = ReleasePaths()
    if version_detector is None:
        if manifest_url:
            version_detector = http_manifest_detector(manifest_url)
        else:
            logger.info(
                "self-update: no manifest_url/version_detector configured; "
                "task is inert until deployment wires one (Task 27)"
            )

            def version_detector() -> AvailableRelease | None:
                return None

    updater = SelfUpdater(
        paths,
        version_detector=version_detector,
        stager=stager if stager is not None else tarball_stager(),
        release_prober=(
            release_prober if release_prober is not None else uv_release_prober()
        ),
        health_gate=health_gate,
        restart_requester=restart_requester,
        running_version=running_version,
        clock=clock,
        min_uptime_seconds=min_uptime_seconds,
        max_boot_attempts=max_boot_attempts,
    )
    return ScheduledTask(
        name="self-update",
        interval_seconds=interval_seconds,
        run=updater.tick,
    )
