"""Tests for the supervisor compute-only weights task (plan Task 21).

The weights schedule port must invoke the SAME compute path as
``platform master weights --once`` (one epoch per tick) with ZERO on-chain
effects: ``submit=False`` is hardcoded and no ``WeightSetter`` is ever
attached (a mock standing in for chain submission asserts zero invocations).
"""

from __future__ import annotations

import logging
import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

from platform_network.cli_app import main as cli_main
from platform_network.config.settings import Settings
from platform_network.schemas.weights import FinalWeights
from platform_network.supervisor import weights as weights_module
from platform_network.supervisor.scheduler import ScheduledTask, TaskWorker
from platform_network.supervisor.tasks import build_scheduled_tasks


def _wire_fake_cli_compute_path(
    monkeypatch: pytest.MonkeyPatch,
    *,
    weight_setter: Any = None,
) -> dict[str, Any]:
    """Replace every cli_app.main helper the weights tick calls with fakes.

    Returns a recorder dict: ``set_weights_calls`` counts invocations of the
    chain-submission function (must stay ZERO), ``epoch_calls`` records the
    compute invocations, ``migrations`` counts startup-migration calls.
    """
    recorder: dict[str, Any] = {
        "set_weights_calls": [],
        "epoch_calls": [],
        "migrations": 0,
        "registry": object(),
        "service": SimpleNamespace(weight_setter=weight_setter),
    }

    # Mock standing in for ANY chain submission: if anything on the
    # supervisor weights path reached WeightSetter.set_weights, it would
    # land here.
    monkeypatch.setattr(
        "platform_network.bittensor.weight_setter.WeightSetter.set_weights",
        lambda self, uids, weights: recorder["set_weights_calls"].append(
            (uids, weights)
        ),
    )

    def _migrate(settings: Any) -> None:
        recorder["migrations"] += 1

    async def _fake_epoch(
        service: Any, registry: Any, *, submit: bool = False
    ) -> FinalWeights:
        recorder["epoch_calls"].append(
            {"service": service, "registry": registry, "submit": submit}
        )
        if submit:  # mirror the real run_epoch's chain branch
            service.weight_setter.set_weights([1], [1.0])
        return FinalWeights(uids=[1, 2], weights=[0.5, 0.5])

    monkeypatch.setattr(cli_main, "_run_startup_migrations", _migrate)
    monkeypatch.setattr(
        cli_main, "_master_registry", lambda settings: recorder["registry"]
    )
    monkeypatch.setattr(
        cli_main,
        "create_bittensor_runtime",
        lambda settings: SimpleNamespace(metagraph_cache=object(), weight_setter=None),
    )
    monkeypatch.setattr(
        cli_main, "_kubernetes_target_registry", lambda settings: object()
    )
    monkeypatch.setattr(
        cli_main,
        "_master_weight_service",
        lambda settings, kubernetes_targets, *, metagraph_cache: recorder["service"],
    )
    monkeypatch.setattr(cli_main, "_run_master_weight_epoch", _fake_epoch)
    return recorder


def test_tick_invokes_compute_exactly_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Settings] = []

    def fake_compute(settings: Settings) -> FinalWeights:
        calls.append(settings)
        return FinalWeights(uids=[], weights=[])

    monkeypatch.setattr(weights_module, "compute_weights_once", fake_compute)
    settings = Settings()
    task = weights_module.build_weights_task(settings)
    task.run()
    assert calls == [settings]
    assert task.name == "weights-compute"
    assert task.interval_seconds == float(settings.master.epoch_interval_seconds)


def test_compute_uses_cli_path_with_zero_chain_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _wire_fake_cli_compute_path(monkeypatch)
    task = weights_module.build_weights_task(Settings())

    task.run()  # one scheduled tick

    assert recorder["migrations"] == 1  # same startup behavior as the CronJob
    assert len(recorder["epoch_calls"]) == 1
    epoch_call = recorder["epoch_calls"][0]
    assert epoch_call["submit"] is False  # compute-only, hardcoded
    assert epoch_call["registry"] is recorder["registry"]
    assert epoch_call["service"] is recorder["service"]
    # ZERO on-chain invocations — the hard Task 21 constraint.
    assert recorder["set_weights_calls"] == []


def test_compute_refuses_attached_weight_setter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even a wrongly-wired service with a WeightSetter cannot submit."""
    recorder = _wire_fake_cli_compute_path(monkeypatch, weight_setter=object())
    with pytest.raises(RuntimeError, match="never hold a WeightSetter"):
        weights_module.compute_weights_once(Settings())
    assert recorder["epoch_calls"] == []  # refused BEFORE any compute
    assert recorder["set_weights_calls"] == []


def test_compute_raise_is_logged_and_schedule_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counts = {"n": 0}
    lock = threading.Lock()

    def boom(settings: Settings) -> FinalWeights:
        with lock:
            counts["n"] += 1
        raise RuntimeError("weights compute boom")

    monkeypatch.setattr(weights_module, "compute_weights_once", boom)
    task = weights_module.build_weights_task(Settings())
    fast = ScheduledTask(name=task.name, interval_seconds=0.01, run=task.run)
    shutdown = threading.Event()
    worker = TaskWorker(task=fast, shutdown=shutdown)

    class _RecordingHandler(logging.Handler):
        def __init__(self) -> None:
            super().__init__(level=logging.ERROR)
            self.messages: list[str] = []
            self._lock = threading.Lock()

        def emit(self, record: logging.LogRecord) -> None:
            with self._lock:
                self.messages.append(record.getMessage())

    # Attach directly to the scheduler logger: immune to other tests
    # reconfiguring root logging (which breaks caplog in the full run).
    # Re-enable it too: alembic's env.py fileConfig (run by any migration
    # test) disables all previously-imported loggers suite-wide.
    scheduler_logger = logging.getLogger("platform_network.supervisor.scheduler")
    handler = _RecordingHandler()
    was_disabled = scheduler_logger.disabled
    scheduler_logger.disabled = False
    scheduler_logger.addHandler(handler)
    try:
        worker.start()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            with lock:
                if counts["n"] >= 3:
                    break
            time.sleep(0.005)
        shutdown.set()
        assert worker.join(timeout=5.0)
    finally:
        scheduler_logger.removeHandler(handler)
        scheduler_logger.disabled = was_disabled
    assert counts["n"] >= 3  # schedule kept ticking after each raise
    assert any("raised; continuing schedule" in message for message in handler.messages)


def test_build_scheduled_tasks_registers_weights_task() -> None:
    settings = Settings()
    tasks, _gate = build_scheduled_tasks(settings)
    weights_task = next(t for t in tasks if t.name == "weights-compute")
    assert weights_task.interval_seconds == float(
        settings.master.epoch_interval_seconds
    )
