"""Trimmed, submit-only on-chain weight submitter for the Docker-Swarm cutover.

This process replaces the full ``base validator run`` deployment for the
Docker-Swarm cutover. It does ONE thing: every
``validator.weights_interval_seconds`` it fetches the master's final weight
vector over HTTP and submits it on-chain with the validator hotkey.

What it deliberately does NOT do (vs ``base validator run``):
  * No challenge orchestration / registry reconcile loop. The production CLI
    runs ``NormalValidatorRunner.run_forever()`` (the ``run_once`` registry
    sync that launches challenge containers) concurrently with the submit
    loop (see ``cli_app/main.py:_run_validator_runtime``). On the submitter
    host that ``run_once`` path is both unnecessary (challenge orchestration
    belongs to the manager, not the submitter) and dangerous (it could clobber
    live challenge services), so it is dropped entirely here. We keep ONLY the
    second coroutine: the submit loop.
  * No database connection. The submit path never opens the control-plane DB.

The submit wiring mirrors production exactly: same ``load_settings`` ->
``create_bittensor_submit_runtime`` -> ``NormalValidatorRunner`` ->
``run_epoch_loop(weights_interval_seconds, ...)`` chain, using the same
``WeightsClient`` / ``WeightSetter`` objects and the same interval source.

Host install (validator node only, holds the hotkey):
  * script:  /var/lib/base/submitter/run_submitter.py
  * config:  /etc/base/submitter.yaml
  * python:  /var/lib/base/supervisor/current/.venv/bin/python
  * wallet:  /var/lib/base/wallets/<wallet_name>/hotkeys/<wallet_hotkey>

Security: never logs the private key or any secret. The only key material it
touches is the PUBLIC hotkey SS58 address, logged once at startup so the
operator can confirm the submitting identity before go-live.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal

from base.bittensor.factory import create_bittensor_submit_runtime
from base.bittensor.validator_loop import run_epoch_loop
from base.bittensor.weight_setter import (
    is_rejected_set_weights_result,
    set_weights_rejection_message,
)
from base.config import Settings, load_settings
from base.observability.logging import configure_logging
from base.observability.otel import init_otel
from base.observability.sentry import init_sentry
from base.validator.normal_runner import NormalValidatorRunner
from base.validator.weights_client import WeightsClient

logger = logging.getLogger("base.submitter")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Submit-only on-chain weight submitter (Docker-Swarm cutover)."
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to the submitter YAML config (e.g. /etc/base/submitter.yaml).",
    )
    return parser.parse_args()


def _log_startup_identity(runner: NormalValidatorRunner, settings: Settings) -> None:
    """Log the submit target and the PUBLIC hotkey SS58 (never the private key)."""
    logger.info(
        "submitter configured: weights_url=%s netuid=%s interval=%ss freshness=%ss",
        settings.validator.resolved_weights_url,
        settings.network.netuid,
        settings.validator.weights_interval_seconds,
        settings.validator.weights_freshness_seconds,
    )
    # The hotkey SS58 is public address metadata; reading it loads the keyfile
    # but never exposes the secret seed. Best-effort so a wallet that is not yet
    # staged does not crash startup (systemd will retry the whole process).
    setter = runner.weight_setter
    wallet = getattr(setter, "wallet", None)
    try:
        ss58 = wallet.hotkey.ss58_address if wallet is not None else None
    except Exception:
        logger.warning(
            "could not read wallet hotkey SS58 at startup; verify the wallet is staged"
        )
        return
    logger.info("submitting with validator hotkey SS58: %s", ss58)


async def _submit_once(runner: NormalValidatorRunner) -> None:
    """Fetch the latest master vector and submit it on-chain, with full logging.

    This inlines the exact three operations of
    ``NormalValidatorRunner.submit_latest_weights`` -- ``WeightsClient.fetch_latest``
    -> ``runner._validate_weights_payload`` -> ``WeightSetter.set_weights`` (guarded
    by ``is_rejected_set_weights_result``) -- rather than calling that method
    directly. Reason (sole deviation from the oracle entrypoint sketch): the
    opaque ``bool`` return of ``submit_latest_weights`` cannot expose the
    per-iteration payload summary (netuid / n weights / computed_at) or the
    precise ``set_weights`` outcome that operators need during the cutover soak.
    Behaviour and validation are byte-identical to production because the same
    client, the same ``runner._validate_weights_payload``, the same setter and the
    same rejection guard are used.
    """
    if (
        runner.weights_client is None
        or runner.weight_setter is None
        or runner.netuid is None
    ):
        logger.error("submit path is not configured (missing weights client/setter)")
        return

    try:
        payload = await runner.weights_client.fetch_latest()
    except Exception:
        logger.exception("weights fetch failed")
        return
    logger.info(
        "weights fetched: netuid=%s n_uids=%s n_weights=%s computed_at=%s",
        payload.netuid,
        len(payload.uids),
        len(payload.weights),
        payload.computed_at.isoformat(),
    )

    failure = runner._validate_weights_payload(payload)
    if failure is not None:
        logger.warning("weights submission skipped: %s", failure)
        return

    try:
        # WeightSetter.set_weights raises RuntimeError on a subtensor rejection
        # (incl. a commit-reveal ExtrinsicResponse with success=False), so the
        # rejection reason is captured by this exception handler.
        result = runner.weight_setter.set_weights(payload.uids, payload.weights)
    except Exception:
        logger.exception("weights submission failed (incl. on-chain rejection)")
        return
    # Defence-in-depth: if a future setter ever returns a rejected result instead
    # of raising, surface it as a failure here rather than logging success.
    if is_rejected_set_weights_result(result):
        logger.warning(
            "weights submission rejected by subtensor: %s",
            set_weights_rejection_message(result),
        )
        return
    logger.info(
        "weights submitted on-chain: netuid=%s n_weights=%s",
        payload.netuid,
        len(payload.weights),
    )


def _build_runner(settings: Settings) -> NormalValidatorRunner:
    """Mirror the production submit wiring (cli_app/main.py:validator_run).

    ``registry_client`` and ``orchestrator`` are passed as ``None``: they are
    required keyword args but the submit path only stores them and never
    dereferences them (verified in ``normal_runner.py``), so this is safe and
    keeps the challenge-orchestration surface entirely out of this process.
    """
    runtime = create_bittensor_submit_runtime(settings)
    return NormalValidatorRunner(
        # Typed RegistryClient/Any but only stored, never used on the submit
        # path (verified above), so None is safe; ignore the non-Optional hint.
        registry_client=None,  # type: ignore[arg-type]
        orchestrator=None,
        weights_client=WeightsClient(
            settings.validator.resolved_weights_url,
            timeout_seconds=settings.validator.weights_timeout_seconds,
            retries=settings.validator.weights_retries,
        ),
        weight_setter=runtime.weight_setter,
        netuid=settings.network.netuid,
        weights_freshness_seconds=settings.validator.weights_freshness_seconds,
    )


async def _run(settings: Settings) -> None:
    runner = _build_runner(settings)
    # Re-assert logging AFTER the runtime is built. ``_build_runner`` calls
    # ``create_bittensor_submit_runtime``, which initializes bittensor and
    # resets root logging to WARNING ("Enabling default logging (Warning
    # level)"), silencing this module's INFO records for the rest of the
    # process. ``configure_logging`` uses ``basicConfig(..., force=True)``, so
    # this re-call clears bittensor's handler and restores our INFO handler
    # with no duplicates.
    configure_logging(settings.observability.log_json)
    _log_startup_identity(runner, settings)

    async def submit_weights() -> None:
        await _submit_once(runner)

    loop = asyncio.get_running_loop()
    task = asyncio.create_task(
        run_epoch_loop(settings.validator.weights_interval_seconds, submit_weights)
    )

    # SIGTERM (systemd stop) / SIGINT request cancellation. An in-flight
    # set_weights is a single synchronous extrinsic call, so cancellation can
    # only take effect at the next await point (the loop's sleep): a submission
    # already in progress completes fully -- the stop never leaves a
    # half-submitted state.
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, task.cancel)

    try:
        await task
    except asyncio.CancelledError:
        logger.info("shutdown signal received; exiting cleanly")


def main() -> None:
    args = _parse_args()
    settings = load_settings(args.config)
    configure_logging(settings.observability.log_json)
    init_sentry(settings.observability.sentry_dsn, environment=settings.environment)
    init_otel(
        settings.observability.otel_service_name,
        settings.observability.otel_endpoint,
    )
    asyncio.run(_run(settings))


if __name__ == "__main__":
    main()
