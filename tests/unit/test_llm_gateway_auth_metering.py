"""Auth lifecycle, redaction, metering, and safe upstream passthrough.

Covers VAL-LLM-012..023 for the master LLM gateway: scoped-token lifecycle
binding, per-(validator, assignment) usage metering with no secret material,
key/token redaction across logs/responses/errors, and safe surfacing of
upstream 429/5xx. Providers are always the deterministic mock (no egress).
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient

from base.master.app_proxy import create_proxy_app
from base.master.llm_gateway import (
    DEEPSEEK_BASE_URL,
    DEEPSEEK_BASE_URL_ENV,
    OPENROUTER_BASE_URL,
    OPENROUTER_BASE_URL_ENV,
    GatewayTokenAuthority,
    InMemoryAssignmentResolver,
    InMemoryUsageRecorder,
    LLMGatewayService,
    MockLLMProvider,
    ProviderResponse,
)

DEEPSEEK_KEY = "sk-deepseek-server-secret-key"
OPENROUTER_KEY = "sk-or-server-secret-key"
TOKEN_SECRET = "gateway-hmac-secret"


class FakeNonceStore:
    async def reserve(self, **_: object) -> None:
        return None


class FakeCache:
    def get(self) -> dict[str, int]:
        return {}


class Clock:
    def __init__(self, epoch: float) -> None:
        self.epoch = float(epoch)

    def time(self) -> float:
        return self.epoch


class Harness:
    def __init__(
        self,
        client: AsyncClient,
        service: LLMGatewayService,
        deepseek: MockLLMProvider,
        openrouter: MockLLMProvider,
        authority: GatewayTokenAuthority,
        recorder: InMemoryUsageRecorder,
        resolver: InMemoryAssignmentResolver,
    ) -> None:
        self.client = client
        self.service = service
        self.deepseek = deepseek
        self.openrouter = openrouter
        self.authority = authority
        self.recorder = recorder
        self.resolver = resolver

    def token(
        self,
        *,
        validator_hotkey: str = "validator-1",
        assignment_id: str = "assignment-1",
        ttl_seconds: int = 3_600,
    ) -> str:
        self.resolver.activate(validator_hotkey, assignment_id)
        return self.authority.issue(
            validator_hotkey=validator_hotkey,
            assignment_id=assignment_id,
            ttl_seconds=ttl_seconds,
        )

    async def post(
        self,
        provider: str,
        *,
        body: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
        path: str = "chat/completions",
    ):
        content = json.dumps(body or {}).encode()
        return await self.client.post(
            f"/llm/{provider}/{path}",
            content=content,
            headers=headers or {},
        )


def _build(
    clock: Clock,
    *,
    deepseek_response: ProviderResponse | None = None,
) -> tuple[
    LLMGatewayService,
    MockLLMProvider,
    MockLLMProvider,
    GatewayTokenAuthority,
    InMemoryUsageRecorder,
    InMemoryAssignmentResolver,
]:
    deepseek = MockLLMProvider(
        name="deepseek",
        base_url=DEEPSEEK_BASE_URL,
        response_factory=(lambda _req: deepseek_response)
        if deepseek_response is not None
        else None,
    )
    openrouter = MockLLMProvider(name="openrouter", base_url=OPENROUTER_BASE_URL)
    authority = GatewayTokenAuthority(TOKEN_SECRET, now_fn=clock.time)
    recorder = InMemoryUsageRecorder()
    resolver = InMemoryAssignmentResolver()
    service = LLMGatewayService(
        providers={"deepseek": deepseek, "openrouter": openrouter},
        api_keys={"deepseek": DEEPSEEK_KEY, "openrouter": OPENROUTER_KEY},
        token_authority=authority,
        usage_recorder=recorder,
        assignment_resolver=resolver,
    )
    return service, deepseek, openrouter, authority, recorder, resolver


@pytest.fixture
async def harness() -> AsyncIterator[Harness]:
    clock = Clock(1_750_000_000.0)
    service, deepseek, openrouter, authority, recorder, resolver = _build(clock)
    app = create_proxy_app(
        registry=object(),
        nonce_store=FakeNonceStore(),
        metagraph_cache=FakeCache(),  # type: ignore[arg-type]
        llm_gateway_service=service,
    )
    transport = ASGITransport(app=app)
    client = AsyncClient(transport=transport, base_url="http://testserver")
    try:
        yield Harness(
            client, service, deepseek, openrouter, authority, recorder, resolver
        )
    finally:
        await client.aclose()


def _deepseek_body(model: str = "deepseek-v4-pro") -> dict[str, object]:
    return {"model": model, "messages": [{"role": "user", "content": "hi"}]}


# VAL-LLM-018
async def test_successful_call_records_metering_row_without_secret(
    harness: Harness,
) -> None:
    token = harness.token(validator_hotkey="val-A", assignment_id="assign-A")
    response = await harness.post(
        "deepseek", body=_deepseek_body(), headers={"X-Gateway-Token": token}
    )
    assert response.status_code == 200
    assert len(harness.recorder.records) == 1
    record = harness.recorder.records[0]
    assert record.validator_hotkey == "val-A"
    assert record.assignment_id == "assign-A"
    assert record.provider == "deepseek"
    assert record.model == "deepseek-v4-pro"
    assert record.total_tokens == 2
    # No secret material anywhere in the recorded row.
    serialized = json.dumps(record.__dict__)
    assert DEEPSEEK_KEY not in serialized
    assert token not in serialized


# VAL-LLM-012
async def test_provider_key_never_returned_to_caller(harness: Harness) -> None:
    response = await harness.post(
        "deepseek",
        body=_deepseek_body(),
        headers={"X-Gateway-Token": harness.token()},
    )
    assert response.status_code == 200
    assert DEEPSEEK_KEY not in response.text
    assert all(DEEPSEEK_KEY not in value for value in response.headers.values())


# VAL-LLM-013 / VAL-LLM-014
async def test_key_and_token_redacted_in_logs(
    harness: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    token = harness.token()
    with caplog.at_level(logging.DEBUG):
        ok = await harness.post(
            "deepseek", body=_deepseek_body(), headers={"X-Gateway-Token": token}
        )
        assert ok.status_code == 200
    assert DEEPSEEK_KEY not in caplog.text
    assert token not in caplog.text


# VAL-LLM-013 (error path traceback must not leak the key)
async def test_key_redacted_in_logs_on_upstream_exception(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = Clock(1_750_000_000.0)

    def _boom(_req: object) -> ProviderResponse:
        raise RuntimeError(f"upstream boom carrying {DEEPSEEK_KEY}")

    deepseek = MockLLMProvider(
        name="deepseek", base_url=DEEPSEEK_BASE_URL, response_factory=_boom
    )
    openrouter = MockLLMProvider(name="openrouter", base_url=OPENROUTER_BASE_URL)
    authority = GatewayTokenAuthority(TOKEN_SECRET, now_fn=clock.time)
    resolver = InMemoryAssignmentResolver()
    service = LLMGatewayService(
        providers={"deepseek": deepseek, "openrouter": openrouter},
        api_keys={"deepseek": DEEPSEEK_KEY, "openrouter": OPENROUTER_KEY},
        token_authority=authority,
        assignment_resolver=resolver,
    )
    app = create_proxy_app(
        registry=object(),
        nonce_store=FakeNonceStore(),
        metagraph_cache=FakeCache(),  # type: ignore[arg-type]
        llm_gateway_service=service,
    )
    resolver.activate("v1", "a1")
    token = authority.issue(validator_hotkey="v1", assignment_id="a1")
    transport = ASGITransport(app=app)
    with caplog.at_level(logging.DEBUG):
        async with AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await client.post(
                "/llm/deepseek/chat/completions",
                content=json.dumps(_deepseek_body()).encode(),
                headers={"X-Gateway-Token": token},
            )
    assert response.status_code == 502
    assert DEEPSEEK_KEY not in response.text
    assert DEEPSEEK_KEY not in caplog.text


# VAL-LLM-015
@pytest.mark.parametrize(
    "headers,body,expected",
    [
        ({}, {"model": "deepseek-v4-pro"}, (401, 403)),  # missing token
        ({"X-Gateway-Token": "garbage"}, {"model": "deepseek-v4-pro"}, (401, 403)),
        ({"X-Gateway-Token": "TOKEN"}, {"model": "deepseek-chat"}, (400, 422)),
    ],
)
async def test_error_bodies_never_leak_secrets(
    harness: Harness,
    headers: dict[str, str],
    body: dict[str, object],
    expected: tuple[int, ...],
) -> None:
    token = harness.token()
    resolved = {k: (token if v == "TOKEN" else v) for k, v in headers.items()}
    response = await harness.post("deepseek", body=body, headers=resolved)
    assert response.status_code in expected
    assert DEEPSEEK_KEY not in response.text
    assert OPENROUTER_KEY not in response.text
    assert token not in response.text


# VAL-LLM-019
async def test_upstream_429_surfaced_safely_without_metering() -> None:
    clock = Clock(1_750_000_000.0)
    upstream = ProviderResponse(
        status_code=429,
        body=json.dumps({"error": f"rate limited; key={DEEPSEEK_KEY}"}).encode(),
        headers={"Authorization": f"Bearer {DEEPSEEK_KEY}"},
    )
    service, deepseek, _or, authority, recorder, resolver = _build(
        clock, deepseek_response=upstream
    )
    app = create_proxy_app(
        registry=object(),
        nonce_store=FakeNonceStore(),
        metagraph_cache=FakeCache(),  # type: ignore[arg-type]
        llm_gateway_service=service,
    )
    resolver.activate("v1", "a1")
    token = authority.issue(validator_hotkey="v1", assignment_id="a1")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/llm/deepseek/chat/completions",
            content=json.dumps(_deepseek_body()).encode(),
            headers={"X-Gateway-Token": token},
        )
    assert response.status_code == 429
    assert DEEPSEEK_KEY not in response.text
    assert all(DEEPSEEK_KEY not in v for v in response.headers.values())
    # An upstream failure is not a successful call -> no metering row.
    assert recorder.records == []


# VAL-LLM-020
async def test_upstream_5xx_surfaced_safely_without_metering() -> None:
    clock = Clock(1_750_000_000.0)
    upstream = ProviderResponse(
        status_code=503,
        body=json.dumps({"error": f"backend down key={DEEPSEEK_KEY}"}).encode(),
    )
    service, _ds, _or, authority, recorder, resolver = _build(
        clock, deepseek_response=upstream
    )
    app = create_proxy_app(
        registry=object(),
        nonce_store=FakeNonceStore(),
        metagraph_cache=FakeCache(),  # type: ignore[arg-type]
        llm_gateway_service=service,
    )
    resolver.activate("v1", "a1")
    token = authority.issue(validator_hotkey="v1", assignment_id="a1")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/llm/deepseek/chat/completions",
            content=json.dumps(_deepseek_body()).encode(),
            headers={"X-Gateway-Token": token},
        )
    assert response.status_code == 502
    assert DEEPSEEK_KEY not in response.text
    assert recorder.records == []


# VAL-LLM-021
async def test_unknown_provider_path_rejected(harness: Harness) -> None:
    response = await harness.post(
        "anthropic",
        body=_deepseek_body(),
        headers={"X-Gateway-Token": harness.token()},
    )
    assert response.status_code in (400, 404)
    assert harness.deepseek.call_count == 0
    assert harness.openrouter.call_count == 0
    assert harness.recorder.records == []


# VAL-LLM-022
async def test_consumption_contract_base_url_and_token_only(harness: Harness) -> None:
    assert DEEPSEEK_BASE_URL_ENV == "DEEPSEEK_BASE_URL"
    assert OPENROUTER_BASE_URL_ENV == "OPENROUTER_BASE_URL"
    # A caller carrying ONLY a scoped gateway token (no provider key) succeeds.
    env = {"DEEPSEEK_BASE_URL": "http://gateway", "BASE_GATEWAY_TOKEN": harness.token()}
    assert "DEEPSEEK_API_KEY" not in env
    response = await harness.post(
        "deepseek",
        body=_deepseek_body(),
        headers={"X-Gateway-Token": env["BASE_GATEWAY_TOKEN"]},
    )
    assert response.status_code == 200
    assert harness.deepseek.requests[-1].header("Authorization") == (
        f"Bearer {DEEPSEEK_KEY}"
    )


# VAL-LLM-018 (metering is best-effort: a recorder failure never breaks the call)
async def test_metering_failure_does_not_break_call_or_leak(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = Clock(1_750_000_000.0)

    class BoomRecorder:
        async def record(self, record: object) -> None:
            raise RuntimeError(f"db down near {DEEPSEEK_KEY}")

    deepseek = MockLLMProvider(name="deepseek", base_url=DEEPSEEK_BASE_URL)
    openrouter = MockLLMProvider(name="openrouter", base_url=OPENROUTER_BASE_URL)
    authority = GatewayTokenAuthority(TOKEN_SECRET, now_fn=clock.time)
    resolver = InMemoryAssignmentResolver()
    service = LLMGatewayService(
        providers={"deepseek": deepseek, "openrouter": openrouter},
        api_keys={"deepseek": DEEPSEEK_KEY, "openrouter": OPENROUTER_KEY},
        token_authority=authority,
        usage_recorder=BoomRecorder(),
        assignment_resolver=resolver,
    )
    app = create_proxy_app(
        registry=object(),
        nonce_store=FakeNonceStore(),
        metagraph_cache=FakeCache(),  # type: ignore[arg-type]
        llm_gateway_service=service,
    )
    resolver.activate("v1", "a1")
    token = authority.issue(validator_hotkey="v1", assignment_id="a1")
    transport = ASGITransport(app=app)
    with caplog.at_level(logging.DEBUG):
        async with AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await client.post(
                "/llm/deepseek/chat/completions",
                content=json.dumps(_deepseek_body()).encode(),
                headers={"X-Gateway-Token": token},
            )
    assert response.status_code == 200
    assert DEEPSEEK_KEY not in response.text
    assert DEEPSEEK_KEY not in caplog.text


# VAL-LLM-023
async def test_token_rejected_after_assignment_terminates(harness: Harness) -> None:
    token = harness.token(validator_hotkey="val-X", assignment_id="assign-X")
    # While the assignment is active, the call succeeds.
    active = await harness.post(
        "deepseek", body=_deepseek_body(), headers={"X-Gateway-Token": token}
    )
    assert active.status_code == 200
    assert harness.deepseek.call_count == 1
    assert len(harness.recorder.records) == 1

    # Once the assignment terminates/reassigns, the same token is rejected and
    # the provider is NOT invoked.
    harness.resolver.deactivate("val-X", "assign-X")
    rejected = await harness.post(
        "deepseek", body=_deepseek_body(), headers={"X-Gateway-Token": token}
    )
    assert rejected.status_code in (401, 403)
    assert harness.deepseek.call_count == 1
    assert len(harness.recorder.records) == 1
    assert DEEPSEEK_KEY not in rejected.text
    assert token not in rejected.text
