"""Tests for the supervisor self-update task (plan Task 22)."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from platform_network.config.settings import Settings
from platform_network.supervisor.health import BrokerHealthGate
from platform_network.supervisor.self_update import (
    STATE_ABORTED,
    STATE_COMMITTED,
    STATE_PENDING,
    STATE_ROLLED_BACK,
    AvailableRelease,
    ReleasePaths,
    SelfUpdater,
    SelfUpdateRollback,
    UpdateState,
    build_self_update_task,
    load_state,
    run_startup_rollback_check,
    save_state,
)

ROOT = Path(__file__).resolve().parents[2]

V1 = "v1.0.0"
V2 = "v2.0.0"


def _gate(healthy: bool) -> BrokerHealthGate:
    gate = BrokerHealthGate(lambda: healthy, failure_threshold=1)
    gate.record(healthy)
    return gate


def _make_paths(tmp_path: Path, *, current: str | None = V1) -> ReleasePaths:
    paths = ReleasePaths(root=tmp_path / "supervisor")
    paths.releases.mkdir(parents=True)
    for version in (V1,):
        (paths.release_dir(version)).mkdir()
        (paths.release_dir(version) / "VERSION").write_text(version)
    if current is not None:
        os.symlink(f"releases/{current}", paths.current)
    return paths


def _copy_stager(
    payload: str = "new release",
) -> Callable[[AvailableRelease, Path], None]:
    def stage(release: AvailableRelease, target_dir: Path) -> None:
        target_dir.mkdir(parents=True)
        (target_dir / "VERSION").write_text(release.version)
        (target_dir / "payload.txt").write_text(payload)

    return stage


def _updater(
    paths: ReleasePaths,
    *,
    detector_version: str | None = V2,
    healthy: bool = True,
    probe_ok: bool = True,
    running: str | None = V1,
    clock: Callable[[], float] | None = None,
    min_uptime_seconds: float = 0.0,
) -> tuple[SelfUpdater, list[str]]:
    restarts: list[str] = []

    def detector() -> AvailableRelease | None:
        if detector_version is None:
            return None
        return AvailableRelease(version=detector_version)

    updater = SelfUpdater(
        paths,
        version_detector=detector,
        stager=_copy_stager(),
        release_prober=lambda _release_dir: probe_ok,
        health_gate=_gate(healthy),
        restart_requester=lambda: restarts.append("restart"),
        running_version=lambda: running,
        clock=clock if clock is not None else (lambda: 0.0),
        min_uptime_seconds=min_uptime_seconds,
    )
    return updater, restarts


def test_no_new_version_is_a_noop(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    updater, restarts = _updater(paths, detector_version=None)
    updater.tick()
    assert paths.current_version() == V1
    assert restarts == []
    assert load_state(paths).status == "idle"

    same_version, restarts_same = _updater(paths, detector_version=V1)
    same_version.tick()
    assert paths.current_version() == V1
    assert restarts_same == []
    assert not paths.release_dir(V1 + ".staging").exists()


def test_staged_but_unhealthy_gate_never_swaps(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    updater, restarts = _updater(paths, healthy=False)
    updater.tick()
    assert paths.release_dir(V2).exists(), "staging side-by-side is allowed"
    assert paths.current_version() == V1, "swap must be blocked by the gate"
    assert restarts == []
    assert load_state(paths).status == "idle"


def test_staged_but_failing_probe_never_swaps(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    updater, restarts = _updater(paths, probe_ok=False)
    updater.tick()
    assert paths.release_dir(V2).exists()
    assert paths.current_version() == V1
    assert restarts == []


def test_healthy_swap_flips_current_and_requests_restart(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    updater, restarts = _updater(paths)
    updater.tick()
    assert paths.current_version() == V2
    assert restarts == ["restart"]
    state = load_state(paths)
    assert state.status == STATE_PENDING
    assert state.previous == V1
    assert state.new == V2
    assert paths.release_dir(V1).exists(), "previous release must be retained"
    assert (paths.release_dir(V1) / "VERSION").read_text() == V1


def test_previous_release_survives_through_commit(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    updater, _ = _updater(paths)
    updater.tick()
    assert paths.release_dir(V1).exists()

    new_process, _ = _updater(paths, running=V2)
    new_process.tick()
    assert load_state(paths).status == STATE_COMMITTED
    assert paths.release_dir(V1).exists(), "previous retained even after commit"
    assert paths.release_dir(V2).exists()


def test_commit_waits_for_min_uptime_and_healthy_gate(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    swapper, _ = _updater(paths)
    swapper.tick()

    early, _ = _updater(paths, running=V2, clock=lambda: 0.0, min_uptime_seconds=30.0)
    early.tick()
    assert load_state(paths).status == STATE_PENDING

    unhealthy, _ = _updater(paths, running=V2, healthy=False)
    unhealthy.tick()
    assert load_state(paths).status == STATE_PENDING

    ticks = iter([0.0, 31.0])
    healthy = SelfUpdater(
        paths,
        version_detector=lambda: None,
        stager=_copy_stager(),
        release_prober=lambda _d: True,
        health_gate=_gate(True),
        restart_requester=lambda: None,
        running_version=lambda: V2,
        clock=lambda: next(ticks),
        min_uptime_seconds=30.0,
    )
    healthy.tick()
    assert load_state(paths).status == STATE_COMMITTED


def test_pending_with_old_process_rerequests_restart(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    swapper, restarts = _updater(paths)
    swapper.tick()
    assert restarts == ["restart"]

    still_old, old_restarts = _updater(paths, running=V1)
    still_old.tick()
    assert old_restarts == ["restart"], "crash between flip and exit → re-request"
    assert paths.current_version() == V2


def test_startup_rollback_after_boot_storm(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    swapper, _ = _updater(paths)
    swapper.tick()
    assert paths.current_version() == V2

    for boot in (1, 2, 3):
        run_startup_rollback_check(
            paths, running_version=lambda: V2, max_boot_attempts=3
        )
        assert load_state(paths).boot_attempts == boot
        assert paths.current_version() == V2

    with pytest.raises(SelfUpdateRollback):
        run_startup_rollback_check(
            paths, running_version=lambda: V2, max_boot_attempts=3
        )
    state = load_state(paths)
    assert state.status == STATE_ROLLED_BACK
    assert paths.current_version() == V1, "rollback must flip current back"
    assert paths.release_dir(V2).exists(), "failed release kept for forensics"

    old_serving, restarts = _updater(paths, running=V1, detector_version=None)
    old_serving.tick()
    assert restarts == []
    assert paths.current_version() == V1


def test_rolled_back_version_is_never_retried(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    save_state(
        paths,
        UpdateState(status=STATE_ROLLED_BACK, previous=V1, new=V2, boot_attempts=4),
    )
    updater, restarts = _updater(paths)
    updater.tick()
    assert paths.current_version() == V1
    assert restarts == []

    retry_newer, newer_restarts = _updater(paths, detector_version="v3.0.0")
    retry_newer.tick()
    assert paths.current_version() == "v3.0.0"
    assert newer_restarts == ["restart"]


def test_startup_hook_noop_paths(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    run_startup_rollback_check(paths, running_version=lambda: V1)
    assert load_state(paths).status == "idle"

    save_state(paths, UpdateState(status=STATE_PENDING, previous=V1, new=V2))
    run_startup_rollback_check(paths, running_version=lambda: V1)
    assert load_state(paths).boot_attempts == 0, "old version booting must not count"

    missing_root = ReleasePaths(root=tmp_path / "absent")
    run_startup_rollback_check(missing_root, running_version=lambda: None)


def test_pending_without_flip_is_marked_aborted(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    save_state(paths, UpdateState(status=STATE_PENDING, previous=V1, new=V2))
    updater, restarts = _updater(paths, running=V1)
    updater.tick()
    assert load_state(paths).status == STATE_ABORTED
    assert restarts == []
    assert paths.current_version() == V1


def test_tick_never_raises(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)

    def exploding_detector() -> AvailableRelease | None:
        raise RuntimeError("registry down")

    def exploding_stager(release: AvailableRelease, target_dir: Path) -> None:
        raise RuntimeError("disk full")

    bad_detector = SelfUpdater(
        paths,
        version_detector=exploding_detector,
        stager=_copy_stager(),
        release_prober=lambda _d: True,
        restart_requester=lambda: None,
        running_version=lambda: V1,
    )
    bad_detector.tick()
    assert paths.current_version() == V1

    bad_stager = SelfUpdater(
        paths,
        version_detector=lambda: AvailableRelease(version=V2),
        stager=exploding_stager,
        release_prober=lambda _d: True,
        restart_requester=lambda: None,
        running_version=lambda: V1,
    )
    bad_stager.tick()
    assert paths.current_version() == V1
    assert not paths.release_dir(V2).exists()
    assert not paths.staging_dir(V2).exists()


def test_idempotent_retick_after_commit(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    swapper, _ = _updater(paths)
    swapper.tick()
    committer, _ = _updater(paths, running=V2)
    committer.tick()
    assert load_state(paths).status == STATE_COMMITTED

    again, restarts = _updater(paths, running=V2)
    again.tick()
    again.tick()
    assert restarts == [], "committed update must not re-swap or re-restart"
    assert paths.current_version() == V2
    assert load_state(paths).status == STATE_COMMITTED


def test_builder_returns_named_task_and_inert_default_detector(
    tmp_path: Path,
) -> None:
    paths = _make_paths(tmp_path)
    restarts: list[str] = []
    task = build_self_update_task(
        Settings(),
        paths=paths,
        stager=_copy_stager(),
        release_prober=lambda _d: True,
        restart_requester=lambda: restarts.append("restart"),
        running_version=lambda: V1,
    )
    assert task.name == "self-update"
    task.run()
    assert restarts == [], "no manifest configured → inert no-op"
    assert paths.current_version() == V1


def test_systemd_unit_launches_via_current_with_restart_always() -> None:
    unit = (ROOT / "deploy" / "swarm" / "platform-supervisor.service").read_text()
    assert "Restart=always" in unit
    assert "/var/lib/platform/supervisor/current" in unit
    assert "master supervisor" in unit
