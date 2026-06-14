"""Weights schedule port (plan Task 21) — compute-only `master weights --once`.

Each tick performs ONE master weight epoch exactly as the CLI command
``platform master weights --once`` does (the Kubernetes weights CronJob it
replaces), by calling the SAME ``cli_app.main`` helpers — no duplicated
logic. The cycle: startup migrations (idempotent alembic upgrade, identical
to every CronJob invocation), registry/challenge-token reads, metagraph
fetch (chain READ), per-challenge ``get_weights`` HTTP collection, then
aggregation into the final UID vector.

ZERO on-chain effects — proven by the call graph, double-gated here:

1. ``create_bittensor_runtime`` (bittensor/factory.py) never constructs a
   ``WeightSetter`` (only ``create_bittensor_submit_runtime`` does), and the
   CLI only attaches one under ``--submit-on-chain`` — which this port never
   passes. :func:`compute_weights_once` additionally REFUSES to run if a
   ``WeightSetter`` is somehow attached.
2. ``MasterWeightService.run_epoch(..., submit=False)`` returns the computed
   vector BEFORE the ``weight_setter.set_weights`` line (master/service.py)
   — this port hardcodes ``submit=False``.

On-chain submission stays exactly where it is today (validator runtime /
explicit ``--submit-on-chain``); wiring live runs is GO-gated plan Task 28.

The broker health gate is accepted per the Task-16 builder recipe but NOT
consulted: the weights compute path touches the control-plane DB, the chain
endpoint (read-only), and challenge HTTP APIs — never the Docker broker.
"""

from __future__ import annotations

import asyncio
import logging

from platform_network.config.settings import Settings
from platform_network.schemas.weights import FinalWeights
from platform_network.supervisor.health import BrokerHealthGate
from platform_network.supervisor.scheduler import ScheduledTask

logger = logging.getLogger(__name__)

WEIGHTS_TASK_NAME = "weights-compute"


def compute_weights_once(settings: Settings) -> FinalWeights:
    """Run one compute-only master weight epoch (no chain submission).

    Mirrors ``cli_app.main.master_weights(once=True)`` minus the CLI-only
    pieces (``configure_logging``, typer echo) and minus any possibility of
    submission (``submit=False`` hardcoded; no ``WeightSetter`` tolerated).
    """
    # Lazy import: keeps the supervisor package import light and immune to
    # any future cli_app <-> supervisor import cycle (cli_app.main already
    # imports the supervisor lazily inside `master supervisor`).
    from platform_network.cli_app import main as cli_main

    cli_main._run_startup_migrations(settings)
    registry = cli_main._master_registry(settings)
    runtime = cli_main.create_bittensor_runtime(settings)
    kubernetes_targets = cli_main._kubernetes_target_registry(settings)
    service = cli_main._master_weight_service(
        settings,
        kubernetes_targets,
        metagraph_cache=runtime.metagraph_cache,
    )
    if service.weight_setter is not None:
        # Structural guard: only the CLI's --submit-on-chain branch ever
        # attaches a WeightSetter; the supervisor path must never hold one.
        raise RuntimeError(
            "supervisor weights task must never hold a WeightSetter; "
            "on-chain submission is GO-gated (plan Task 28)"
        )
    final = asyncio.run(
        cli_main._run_master_weight_epoch(service, registry, submit=False)
    )
    logger.info(
        "supervisor weights tick: compute-only, %d uids",
        len(final.uids),
        extra={"uids": len(final.uids)},
    )
    return final


def build_weights_task(
    settings: Settings,
    *,
    health_gate: BrokerHealthGate | None = None,
) -> ScheduledTask:
    """Build the scheduled compute-only weights task (Task-16 recipe).

    Interval follows the CLI loop's cadence (`settings.master.
    epoch_interval_seconds`). ``health_gate`` is part of the shared builder
    signature but deliberately unused — see module docstring.
    """
    del health_gate  # weights compute never touches the broker

    def run() -> None:
        # Module-level lookup so tests can monkeypatch compute_weights_once.
        compute_weights_once(settings)

    return ScheduledTask(
        name=WEIGHTS_TASK_NAME,
        interval_seconds=float(settings.master.epoch_interval_seconds),
        run=run,
    )
