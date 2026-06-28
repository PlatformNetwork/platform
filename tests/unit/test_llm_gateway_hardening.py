"""Hardening tests for the master LLM gateway (m-misc-gateway-hardening).

These lock in three optional hardening behaviors while preserving the existing
VAL-LLM-* contract:

* ``_surface_upstream_error`` distinguishes a controlled, caller-induced upstream
  4xx (-> 400) from an upstream 5xx/exception (-> 502), never relaying the
  upstream body/headers (VAL-LLM-019/020 stay green; key/token never leak).
* The two upstream-failure paths (upstream 5xx ``ProviderResponse`` and an
  upstream exception) return a single, consistent, non-leaking 502 detail.
* The per-request scoped gateway token is defensively registered for redaction
  for the duration of the forward path, so that if header logging is ever
  introduced the token cannot leak (VAL-LLM-014).

Providers are always the deterministic mock (no network egress).
"""

from __future__ import annotations

import json
import logging

import pytest
from httpx import ASGITransport, AsyncClient

from base.master.app_proxy import create_proxy_app
from base.master.llm_gateway import (
    DEEPSEEK_BASE_URL,
    OPENROUTER_BASE_URL,
    REDACTION_PLACEHOLDER,
    GatewayTokenAuthority,
    InMemoryAssignmentResolver,
    InMemoryUsageRecorder,
    LLMGatewayService,
    MockLLMProvider,
    ProviderResponse,
    install_secret_redaction,
    redact_in_context,
)
from base.master.llm_gateway import gateway as gateway_module

DEEPSEEK_KEY = "sk-deepseek-server-secret-key"
OPENROUTER_KEY = "sk-or-server-secret-key"
TOKEN_SECRET = "gateway-hmac-secret"


class FakeNonceStore:
    async def reserve(self, **_: object) -> None:
        return None


class FakeCache:
    def get(self) -> dict[str, int]:
        return {}


def _deepseek_body(model: str = "deepseek-v4-pro") -> dict[str, object]:
    return {"model": model, "messages": [{"role": "user", "content": "hi"}]}


def _build_service(
    *,
    response_factory=None,
) -> tuple[
    LLMGatewayService,
    MockLLMProvider,
    GatewayTokenAuthority,
    InMemoryUsageRecorder,
    InMemoryAssignmentResolver,
]:
    deepseek = MockLLMProvider(
        name="deepseek",
        base_url=DEEPSEEK_BASE_URL,
        response_factory=response_factory,
    )
    openrouter = MockLLMProvider(name="openrouter", base_url=OPENROUTER_BASE_URL)
    authority = GatewayTokenAuthority(TOKEN_SECRET)
    recorder = InMemoryUsageRecorder()
    resolver = InMemoryAssignmentResolver()
    service = LLMGatewayService(
        providers={"deepseek": deepseek, "openrouter": openrouter},
        api_keys={"deepseek": DEEPSEEK_KEY, "openrouter": OPENROUTER_KEY},
        token_authority=authority,
        usage_recorder=recorder,
        assignment_resolver=resolver,
    )
    return service, deepseek, authority, recorder, resolver


def _make_client(service: LLMGatewayService) -> AsyncClient:
    app = create_proxy_app(
        registry=object(),
        nonce_store=FakeNonceStore(),
        metagraph_cache=FakeCache(),  # type: ignore[arg-type]
        llm_gateway_service=service,
    )
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")


# Part 1: caller-induced upstream 4xx is surfaced as a controlled 400, distinct
# from a 5xx server failure, and never relays the upstream body/headers.
@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422])
async def test_upstream_4xx_surfaced_as_controlled_400_without_leaking(
    status: int,
) -> None:
    upstream = ProviderResponse(
        status_code=status,
        body=json.dumps({"error": f"bad request key={DEEPSEEK_KEY}"}).encode(),
        headers={
            "Authorization": f"Bearer {DEEPSEEK_KEY}",
            "X-Upstream-Leak": OPENROUTER_KEY,
        },
    )
    service, _ds, authority, recorder, resolver = _build_service(
        response_factory=lambda _req: upstream
    )
    resolver.activate("v1", "a1")
    token = authority.issue(validator_hotkey="v1", assignment_id="a1")
    async with _make_client(service) as client:
        response = await client.post(
            "/llm/deepseek/chat/completions",
            content=json.dumps(_deepseek_body()).encode(),
            headers={"X-Gateway-Token": token},
        )
    # Controlled 4xx (caller-induced), distinct from a 5xx server failure.
    assert response.status_code == 400
    assert response.status_code != 502
    # Upstream body/headers are never relayed back to the caller.
    assert DEEPSEEK_KEY not in response.text
    assert OPENROUTER_KEY not in response.text
    assert token not in response.text
    assert all(
        DEEPSEEK_KEY not in v and OPENROUTER_KEY not in v
        for v in response.headers.values()
    )
    # An upstream failure is not a successful call -> no metering row.
    assert recorder.records == []


# Part 1 preserved: rate limiting stays a distinct, controlled 429.
async def test_upstream_429_still_distinct_from_4xx_and_5xx() -> None:
    upstream = ProviderResponse(
        status_code=429,
        body=json.dumps({"error": f"slow down {DEEPSEEK_KEY}"}).encode(),
    )
    service, _ds, authority, _recorder, resolver = _build_service(
        response_factory=lambda _req: upstream
    )
    resolver.activate("v1", "a1")
    token = authority.issue(validator_hotkey="v1", assignment_id="a1")
    async with _make_client(service) as client:
        response = await client.post(
            "/llm/deepseek/chat/completions",
            content=json.dumps(_deepseek_body()).encode(),
            headers={"X-Gateway-Token": token},
        )
    assert response.status_code == 429
    assert DEEPSEEK_KEY not in response.text


# Part 3: the upstream-5xx path and the upstream-exception path return a single,
# consistent, non-leaking 502 detail.
async def test_upstream_5xx_and_exception_share_unified_detail() -> None:
    upstream_5xx = ProviderResponse(
        status_code=503,
        body=json.dumps({"error": f"down {DEEPSEEK_KEY}"}).encode(),
    )
    service_5xx, _ds, authority_5xx, _rec5, resolver_5xx = _build_service(
        response_factory=lambda _req: upstream_5xx
    )
    resolver_5xx.activate("v1", "a1")
    token_5xx = authority_5xx.issue(validator_hotkey="v1", assignment_id="a1")
    async with _make_client(service_5xx) as client:
        resp_5xx = await client.post(
            "/llm/deepseek/chat/completions",
            content=json.dumps(_deepseek_body()).encode(),
            headers={"X-Gateway-Token": token_5xx},
        )

    def _boom(_req: object) -> ProviderResponse:
        raise RuntimeError(f"upstream boom {DEEPSEEK_KEY}")

    service_exc, _ds2, authority_exc, _rec6, resolver_exc = _build_service(
        response_factory=_boom
    )
    resolver_exc.activate("v1", "a1")
    token_exc = authority_exc.issue(validator_hotkey="v1", assignment_id="a1")
    async with _make_client(service_exc) as client:
        resp_exc = await client.post(
            "/llm/deepseek/chat/completions",
            content=json.dumps(_deepseek_body()).encode(),
            headers={"X-Gateway-Token": token_exc},
        )

    assert resp_5xx.status_code == 502
    assert resp_exc.status_code == 502
    detail_5xx = resp_5xx.json()["detail"]
    detail_exc = resp_exc.json()["detail"]
    # A single consistent, non-leaking message across both failure paths.
    assert detail_5xx == detail_exc
    assert DEEPSEEK_KEY not in detail_5xx
    assert token_5xx not in detail_5xx
    assert token_exc not in detail_exc


# Part 2: the per-request gateway token is defensively redacted on the forward
# path, so a future header-logging line could not leak it (VAL-LLM-014).
async def test_per_request_token_redacted_on_forward_log_path(
    caplog: pytest.LogCaptureFixture,
) -> None:
    captured: dict[str, str] = {}

    def _factory(_req: object) -> ProviderResponse:
        # Simulate a future code path that logs request headers (which would
        # carry the bearer gateway token) on the gateway logger.
        gateway_module.logger.warning(
            "forward request headers: Authorization=Bearer %s", captured["token"]
        )
        return ProviderResponse(
            status_code=200,
            body=json.dumps({"ok": True}).encode(),
            media_type="application/json",
        )

    service, _ds, authority, _recorder, resolver = _build_service(
        response_factory=_factory
    )
    resolver.activate("v1", "a1")
    token = authority.issue(validator_hotkey="v1", assignment_id="a1")
    captured["token"] = token
    with caplog.at_level(logging.DEBUG, logger="base.master.llm_gateway.gateway"):
        async with _make_client(service) as client:
            response = await client.post(
                "/llm/deepseek/chat/completions",
                content=json.dumps(_deepseek_body()).encode(),
                headers={"X-Gateway-Token": token},
            )
    assert response.status_code == 200
    assert token not in caplog.text
    assert REDACTION_PLACEHOLDER in caplog.text
    assert DEEPSEEK_KEY not in caplog.text


# Part 2 unit: redact_in_context scopes a dynamic secret to the active context
# and removes it on exit (no permanent growth of the filter's secret set).
def test_redact_in_context_scopes_and_clears_dynamic_secret(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("base.master.llm_gateway.test_redact_in_context")
    logger.propagate = True
    install_secret_redaction(["static-only"], logger=logger)
    dynamic = "per-request-token-xyz"
    with caplog.at_level(logging.DEBUG, logger=logger.name):
        with redact_in_context(dynamic):
            logger.warning("inside %s", dynamic)
        logger.warning("outside %s", dynamic)

    messages = [record.getMessage() for record in caplog.records]
    inside = [m for m in messages if m.startswith("inside")]
    outside = [m for m in messages if m.startswith("outside")]
    assert inside and dynamic not in inside[0]
    assert REDACTION_PLACEHOLDER in inside[0]
    # Once the context exits the dynamic secret is no longer redacted.
    assert outside and dynamic in outside[0]


def test_redact_in_context_ignores_empty_secrets() -> None:
    # A None/empty token (missing gateway token) must not register anything.
    with redact_in_context(None, ""):
        pass
