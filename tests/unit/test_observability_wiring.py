"""Observability wiring (m4 H2): init_sentry/init_otel call-sites + OTLP exporter.

Covers VAL-HARD-OBS-001 (every logging-configuring entrypoint also initializes
Sentry + OTEL with settings-derived args, no-op safe when unconfigured) and
VAL-HARD-OBS-002 (a configured OTLP endpoint attaches a real span
processor/exporter rather than an inert TracerProvider).
"""

from __future__ import annotations

import sys
import types

import pytest
from typer.testing import CliRunner

from base.cli_app import main
from base.cli_app.main import app
from base.config.settings import Settings
from base.observability.otel import init_otel
from base.observability.sentry import init_sentry

# Every CLI entrypoint that configures logging (cli_app/main.py).
ENTRYPOINTS = [
    ["master", "proxy"],
    ["master", "broker"],
    ["master", "supervisor"],
    ["master", "weights"],
    ["validator", "run"],
    ["validator", "agent"],
    ["validator", "subscribe"],
]


def _configured_settings() -> Settings:
    settings = Settings()
    settings.observability.log_json = False
    settings.observability.sentry_dsn = "https://public@sentry.example/42"
    settings.observability.otel_service_name = "base-test"
    settings.observability.otel_endpoint = "http://otel-collector:4317"
    return settings


def test_configure_observability_wires_init_from_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    log_calls: list[bool] = []
    sentry_calls: list[tuple[str | None, str | None]] = []
    otel_calls: list[tuple[str, str | None]] = []

    monkeypatch.setattr(
        main, "configure_logging", lambda json_logs: log_calls.append(json_logs)
    )
    monkeypatch.setattr(
        main,
        "init_sentry",
        lambda dsn, environment=None: sentry_calls.append((dsn, environment)),
    )
    monkeypatch.setattr(
        main,
        "init_otel",
        lambda service_name, endpoint=None: otel_calls.append((service_name, endpoint)),
    )

    settings = _configured_settings()
    main._configure_observability(settings)

    assert log_calls == [False]
    assert sentry_calls == [("https://public@sentry.example/42", "development")]
    assert otel_calls == [("base-test", "http://otel-collector:4317")]


def test_configure_observability_noop_safe_when_unconfigured() -> None:
    # Default Settings: no sentry DSN, no OTLP endpoint. Must not raise.
    main._configure_observability(Settings())


@pytest.mark.parametrize("command", ENTRYPOINTS, ids=lambda c: "-".join(c))
def test_entrypoint_initializes_sentry_and_otel(
    monkeypatch: pytest.MonkeyPatch, command: list[str]
) -> None:
    class _Stop(Exception):
        pass

    settings = _configured_settings()
    sentry_calls: list[tuple[str | None, str | None]] = []
    otel_calls: list[tuple[str, str | None]] = []

    monkeypatch.setattr(main, "load_settings", lambda config: settings)
    monkeypatch.setattr(main, "configure_logging", lambda json_logs: None)
    monkeypatch.setattr(
        main,
        "init_sentry",
        lambda dsn, environment=None: sentry_calls.append((dsn, environment)),
    )

    def fake_otel(service_name: str, endpoint: str | None = None) -> None:
        otel_calls.append((service_name, endpoint))
        # Halt the entrypoint right after observability setup so no heavy
        # runtime (uvicorn / migrations / bittensor) is exercised.
        raise _Stop()

    monkeypatch.setattr(main, "init_otel", fake_otel)

    result = CliRunner().invoke(app, command)

    assert isinstance(result.exception, _Stop)
    assert sentry_calls == [("https://public@sentry.example/42", "development")]
    assert otel_calls == [("base-test", "http://otel-collector:4317")]


def test_init_sentry_noop_when_dsn_none() -> None:
    # No DSN -> returns without importing/initializing sentry_sdk (no raise).
    init_sentry(None)
    init_sentry(None, environment="production")


def test_init_sentry_initializes_when_dsn_set(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}
    fake_sdk = types.SimpleNamespace(init=lambda **kwargs: captured.update(kwargs))
    monkeypatch.setitem(sys.modules, "sentry_sdk", fake_sdk)

    init_sentry("https://public@sentry.example/1", environment="production")

    assert captured == {
        "dsn": "https://public@sentry.example/1",
        "environment": "production",
    }


def test_init_otel_attaches_otlp_exporter_when_endpoint_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import opentelemetry.trace as trace_api
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    captured: dict[str, object] = {}
    monkeypatch.setattr(
        trace_api,
        "set_tracer_provider",
        lambda provider: captured.__setitem__("provider", provider),
    )

    init_otel("base-svc", "http://otel-collector:4317")

    provider = captured["provider"]
    processors = provider._active_span_processor._span_processors  # type: ignore[attr-defined]
    assert len(processors) == 1
    assert isinstance(processors[0], BatchSpanProcessor)
    assert isinstance(processors[0].span_exporter, OTLPSpanExporter)
    provider.shutdown()  # type: ignore[attr-defined]


def test_init_otel_no_exporter_when_endpoint_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import opentelemetry.trace as trace_api

    captured: dict[str, object] = {}
    monkeypatch.setattr(
        trace_api,
        "set_tracer_provider",
        lambda provider: captured.__setitem__("provider", provider),
    )

    init_otel("base-svc")

    provider = captured["provider"]
    processors = provider._active_span_processor._span_processors  # type: ignore[attr-defined]
    assert len(processors) == 0
