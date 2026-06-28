"""Behavioral tests for the master LLM gateway core (VAL-LLM-001..011).

Providers are always the deterministic mock (no network egress); the gateway
injects the provider key server-side and the caller holds only a scoped token.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient

from base.master.app_proxy import create_proxy_app
from base.master.llm_gateway import (
    DEEPSEEK_BASE_URL,
    OPENROUTER_BASE_URL,
    GatewayTokenAuthority,
    HttpLLMProvider,
    LLMGatewayService,
    MockLLMProvider,
    ProviderConfig,
    ProviderResponse,
    build_providers,
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
        clock: Clock,
    ) -> None:
        self.client = client
        self.service = service
        self.deepseek = deepseek
        self.openrouter = openrouter
        self.authority = authority
        self.clock = clock

    def token(
        self,
        *,
        validator_hotkey: str = "validator-1",
        assignment_id: str = "assignment-1",
        ttl_seconds: int = 3_600,
    ) -> str:
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
        raw_body: bytes | None = None,
        headers: dict[str, str] | None = None,
        path: str = "chat/completions",
    ):
        content = raw_body if raw_body is not None else json.dumps(body or {}).encode()
        return await self.client.post(
            f"/llm/{provider}/{path}",
            content=content,
            headers=headers or {},
        )


def _build_service(
    clock: Clock,
    *,
    deepseek_response: ProviderResponse | None = None,
    openrouter_response: ProviderResponse | None = None,
) -> tuple[LLMGatewayService, MockLLMProvider, MockLLMProvider, GatewayTokenAuthority]:
    deepseek = MockLLMProvider(
        name="deepseek",
        base_url=DEEPSEEK_BASE_URL,
        response_factory=(lambda _req: deepseek_response)
        if deepseek_response is not None
        else None,
    )
    openrouter = MockLLMProvider(
        name="openrouter",
        base_url=OPENROUTER_BASE_URL,
        response_factory=(lambda _req: openrouter_response)
        if openrouter_response is not None
        else None,
    )
    authority = GatewayTokenAuthority(TOKEN_SECRET, now_fn=clock.time)
    service = LLMGatewayService(
        providers={"deepseek": deepseek, "openrouter": openrouter},
        api_keys={"deepseek": DEEPSEEK_KEY, "openrouter": OPENROUTER_KEY},
        token_authority=authority,
    )
    return service, deepseek, openrouter, authority


@pytest.fixture
async def harness() -> AsyncIterator[Harness]:
    clock = Clock(1_750_000_000.0)
    service, deepseek, openrouter, authority = _build_service(clock)
    app = create_proxy_app(
        registry=object(),
        nonce_store=FakeNonceStore(),
        metagraph_cache=FakeCache(),  # type: ignore[arg-type]
        llm_gateway_service=service,
    )
    transport = ASGITransport(app=app)
    client = AsyncClient(transport=transport, base_url="http://testserver")
    try:
        yield Harness(client, service, deepseek, openrouter, authority, clock)
    finally:
        await client.aclose()


def _deepseek_body(model: str = "deepseek-v4-pro") -> dict[str, object]:
    return {"model": model, "messages": [{"role": "user", "content": "hi"}]}


def _openrouter_body(model: str = "anthropic/claude-opus-4.8") -> dict[str, object]:
    return {"model": model, "messages": [{"role": "user", "content": "review"}]}


# VAL-LLM-001
async def test_deepseek_forwards_with_injected_key(harness: Harness) -> None:
    response = await harness.post(
        "deepseek",
        body=_deepseek_body(),
        headers={"X-Gateway-Token": harness.token()},
    )
    assert response.status_code == 200
    assert harness.deepseek.call_count == 1
    recorded = harness.deepseek.requests[0]
    # Server injected the configured DeepSeek key; the caller sent no key.
    assert recorded.header("Authorization") == f"Bearer {DEEPSEEK_KEY}"
    body = response.json()
    assert body["provider"] == "deepseek"


# VAL-LLM-002
async def test_deepseek_accepts_required_model_unchanged(harness: Harness) -> None:
    response = await harness.post(
        "deepseek",
        body=_deepseek_body("deepseek-v4-pro"),
        headers={"X-Gateway-Token": harness.token()},
    )
    assert response.status_code == 200
    assert harness.deepseek.call_count == 1
    # Model forwarded unchanged to the provider.
    assert harness.deepseek.requests[0].json_body()["model"] == "deepseek-v4-pro"


# VAL-LLM-003
@pytest.mark.parametrize(
    "body",
    [
        {"model": "deepseek-chat", "messages": []},
        {"model": "gpt-4o", "messages": []},
        {"model": "", "messages": []},
        {"messages": []},
    ],
)
async def test_deepseek_rejects_other_models_before_provider_call(
    harness: Harness, body: dict[str, object]
) -> None:
    response = await harness.post(
        "deepseek", body=body, headers={"X-Gateway-Token": harness.token()}
    )
    assert response.status_code in (400, 422)
    assert harness.deepseek.call_count == 0
    # Error body names the policy violation without leaking secrets.
    assert DEEPSEEK_KEY not in response.text
    assert "model" in response.text.lower()


# VAL-LLM-004
async def test_deepseek_real_provider_targets_api_deepseek_com() -> None:
    real = build_providers(ProviderConfig(mode="real"))
    deepseek = real["deepseek"]
    assert isinstance(deepseek, HttpLLMProvider)
    assert deepseek.base_url == "https://api.deepseek.com"
    assert (
        deepseek.compose_url("chat/completions")
        == "https://api.deepseek.com/chat/completions"
    )
    # The mock is selected under the default/test config (no egress).
    mock = build_providers(ProviderConfig(mode="mock"))
    assert isinstance(mock["deepseek"], MockLLMProvider)


# VAL-LLM-005
async def test_caller_never_supplies_provider_key(harness: Harness) -> None:
    # (a) Works with NO provider key at all.
    no_key = await harness.post(
        "deepseek",
        body=_deepseek_body(),
        headers={"X-Gateway-Token": harness.token()},
    )
    assert no_key.status_code == 200

    # (b) A bogus caller-supplied key is NOT forwarded; the server key is.
    bogus = await harness.post(
        "deepseek",
        body=_deepseek_body(),
        headers={
            "X-Gateway-Token": harness.token(),
            "Authorization": "Bearer bogus-caller-provider-key",
        },
    )
    assert bogus.status_code == 200
    forwarded_auth = harness.deepseek.requests[-1].header("Authorization")
    assert forwarded_auth == f"Bearer {DEEPSEEK_KEY}"
    assert "bogus-caller-provider-key" not in str(forwarded_auth)


# VAL-LLM-006
async def test_openrouter_forwards_with_injected_key(harness: Harness) -> None:
    response = await harness.post(
        "openrouter",
        body=_openrouter_body(),
        headers={"X-Gateway-Token": harness.token()},
    )
    assert response.status_code == 200
    assert harness.openrouter.call_count == 1
    recorded = harness.openrouter.requests[0]
    assert recorded.header("Authorization") == f"Bearer {OPENROUTER_KEY}"
    assert recorded.json_body()["model"] == "anthropic/claude-opus-4.8"


# VAL-LLM-007
@pytest.mark.parametrize(
    "review_body",
    [
        # agent-challenge analyzer review shape
        {
            "model": "anthropic/claude-opus-4.8",
            "messages": [
                {"role": "system", "content": "reviewer"},
                {"role": "user", "content": "manifest"},
            ],
            "tools": [{"type": "function", "function": {"name": "submit_verdict"}}],
            "tool_choice": "auto",
        },
        # prism llm_review shape
        {
            "model": "anthropic/claude-opus-4.8",
            "messages": [{"role": "user", "content": "prism review"}],
            "tools": [{"type": "function", "function": {"name": "SubmitVerdict"}}],
            "tool_choice": {"type": "function", "function": {"name": "SubmitVerdict"}},
            "temperature": 0,
        },
    ],
)
async def test_openrouter_serves_both_review_consumers(
    harness: Harness, review_body: dict[str, object]
) -> None:
    response = await harness.post(
        "openrouter",
        body=review_body,
        headers={"X-Gateway-Token": harness.token()},
    )
    assert response.status_code == 200
    recorded = harness.openrouter.requests[-1]
    assert recorded.header("Authorization") == f"Bearer {OPENROUTER_KEY}"
    assert recorded.json_body()["model"] == "anthropic/claude-opus-4.8"


# VAL-LLM-008
@pytest.mark.parametrize("provider", ["deepseek", "openrouter"])
async def test_missing_gateway_token_rejected(harness: Harness, provider: str) -> None:
    body = _deepseek_body() if provider == "deepseek" else _openrouter_body()
    response = await harness.post(provider, body=body, headers={})
    assert response.status_code in (401, 403)
    assert harness.deepseek.call_count == 0
    assert harness.openrouter.call_count == 0
    assert DEEPSEEK_KEY not in response.text
    assert OPENROUTER_KEY not in response.text


# VAL-LLM-009
@pytest.mark.parametrize("token", ["garbage", "not.a.real.token", "....", "a.b.c"])
async def test_invalid_gateway_token_rejected(harness: Harness, token: str) -> None:
    response = await harness.post(
        "deepseek", body=_deepseek_body(), headers={"X-Gateway-Token": token}
    )
    assert response.status_code in (401, 403)
    assert harness.deepseek.call_count == 0


# VAL-LLM-010
async def test_expired_gateway_token_rejected(harness: Harness) -> None:
    token = harness.token(ttl_seconds=10)
    # Advance the clock past the token's expiry.
    harness.clock.epoch += 20
    response = await harness.post(
        "deepseek", body=_deepseek_body(), headers={"X-Gateway-Token": token}
    )
    assert response.status_code in (401, 403)
    assert harness.deepseek.call_count == 0
    assert "expir" in response.text.lower() or "invalid" in response.text.lower()


# VAL-LLM-011
async def test_gateway_token_scoped_per_assignment_validator(harness: Harness) -> None:
    token = harness.token(validator_hotkey="validator-A", assignment_id="assignment-A")

    # In-scope call succeeds.
    in_scope = await harness.post(
        "deepseek",
        body=_deepseek_body(),
        headers={
            "X-Gateway-Token": token,
            "X-Gateway-Validator": "validator-A",
            "X-Gateway-Assignment": "assignment-A",
        },
    )
    assert in_scope.status_code == 200
    assert harness.deepseek.call_count == 1

    # Cross-use for a different assignment is rejected (provider not called).
    cross_assignment = await harness.post(
        "deepseek",
        body=_deepseek_body(),
        headers={
            "X-Gateway-Token": token,
            "X-Gateway-Validator": "validator-A",
            "X-Gateway-Assignment": "assignment-B",
        },
    )
    assert cross_assignment.status_code == 403
    assert harness.deepseek.call_count == 1

    # Cross-use for a different validator is rejected.
    cross_validator = await harness.post(
        "deepseek",
        body=_deepseek_body(),
        headers={
            "X-Gateway-Token": token,
            "X-Gateway-Validator": "validator-B",
            "X-Gateway-Assignment": "assignment-A",
        },
    )
    assert cross_validator.status_code == 403
    assert harness.deepseek.call_count == 1


async def test_upstream_failure_is_surfaced_without_leaking_secrets() -> None:
    clock = Clock(1_750_000_000.0)

    def _boom(_request: object) -> ProviderResponse:
        raise RuntimeError(f"upstream boom with {DEEPSEEK_KEY}")

    deepseek = MockLLMProvider(
        name="deepseek", base_url=DEEPSEEK_BASE_URL, response_factory=_boom
    )
    openrouter = MockLLMProvider(name="openrouter", base_url=OPENROUTER_BASE_URL)
    authority = GatewayTokenAuthority(TOKEN_SECRET, now_fn=clock.time)
    service = LLMGatewayService(
        providers={"deepseek": deepseek, "openrouter": openrouter},
        api_keys={"deepseek": DEEPSEEK_KEY, "openrouter": OPENROUTER_KEY},
        token_authority=authority,
    )
    app = create_proxy_app(
        registry=object(),
        nonce_store=FakeNonceStore(),
        metagraph_cache=FakeCache(),  # type: ignore[arg-type]
        llm_gateway_service=service,
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/llm/deepseek/chat/completions",
            content=json.dumps(_deepseek_body()).encode(),
            headers={
                "X-Gateway-Token": authority.issue(
                    validator_hotkey="v1", assignment_id="a1"
                )
            },
        )
    assert response.status_code == 502
    assert DEEPSEEK_KEY not in response.text
