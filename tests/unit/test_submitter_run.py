from __future__ import annotations

import importlib.util
import logging
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_RUN_SUBMITTER = _ROOT / "deploy" / "swarm" / "submitter" / "run_submitter.py"


def _load_run_submitter() -> Any:
    spec = importlib.util.spec_from_file_location("run_submitter", _RUN_SUBMITTER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _payload() -> SimpleNamespace:
    return SimpleNamespace(
        netuid=100,
        uids=[0],
        weights=[1.0],
        computed_at=datetime.now(UTC),
    )


class _Client:
    def __init__(self, payload: SimpleNamespace) -> None:
        self._payload = payload

    async def fetch_latest(self) -> SimpleNamespace:
        return self._payload


def _runner(setter: Any, payload: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(
        weights_client=_Client(payload),
        weight_setter=setter,
        netuid=100,
        _validate_weights_payload=lambda _payload: None,
    )


async def test_submit_once_logs_failure_on_rejection_not_success(
    caplog: pytest.LogCaptureFixture,
) -> None:
    module = _load_run_submitter()

    class RejectingSetter:
        def set_weights(self, uids: list[int], weights: list[float]) -> object:
            raise RuntimeError("subtensor rejected weight submission: TooFast")

    payload = _payload()
    with caplog.at_level(logging.INFO, logger="base.submitter"):
        await module._submit_once(_runner(RejectingSetter(), payload))

    messages = [record.getMessage() for record in caplog.records]
    assert any("weights submission failed" in message for message in messages)
    assert not any("weights submitted on-chain" in message for message in messages)


async def test_submit_once_logs_success_on_accepted_response(
    caplog: pytest.LogCaptureFixture,
) -> None:
    module = _load_run_submitter()
    response = SimpleNamespace(success=True, message=None)

    class AcceptingSetter:
        def set_weights(self, uids: list[int], weights: list[float]) -> object:
            return response

    payload = _payload()
    with caplog.at_level(logging.INFO, logger="base.submitter"):
        await module._submit_once(_runner(AcceptingSetter(), payload))

    messages = [record.getMessage() for record in caplog.records]
    assert any("weights submitted on-chain" in message for message in messages)


def test_main_initializes_sentry_and_otel(monkeypatch: pytest.MonkeyPatch) -> None:
    from base.config.settings import Settings

    module = _load_run_submitter()
    settings = Settings()
    settings.observability.sentry_dsn = "https://public@sentry.example/3"
    settings.observability.otel_service_name = "base-submitter"
    settings.observability.otel_endpoint = "http://otel-collector:4317"

    sentry_calls: list[tuple[str | None, str | None]] = []
    otel_calls: list[tuple[str, str | None]] = []

    monkeypatch.setattr(
        module, "_parse_args", lambda: SimpleNamespace(config="submitter.yaml")
    )
    monkeypatch.setattr(module, "load_settings", lambda config: settings)
    monkeypatch.setattr(module, "configure_logging", lambda json_logs: None)
    monkeypatch.setattr(
        module,
        "init_sentry",
        lambda dsn, environment=None: sentry_calls.append((dsn, environment)),
    )
    monkeypatch.setattr(
        module,
        "init_otel",
        lambda service_name, endpoint=None: otel_calls.append((service_name, endpoint)),
    )
    monkeypatch.setattr(module, "_run", lambda settings: None)
    monkeypatch.setattr(module.asyncio, "run", lambda coro: None)

    module.main()

    assert sentry_calls == [("https://public@sentry.example/3", "development")]
    assert otel_calls == [("base-submitter", "http://otel-collector:4317")]
