"""Unit tests for gateway token issuance/verification and provider seams."""

from __future__ import annotations

import asyncio
import json

import pytest

from base.master.llm_gateway import (
    DEEPSEEK_BASE_URL,
    GatewayTokenAuthority,
    GatewayTokenExpired,
    GatewayTokenInvalid,
    GatewayTokenScopeError,
    HttpLLMProvider,
    LLMGatewayService,
    MockLLMProvider,
    ProviderConfig,
    ProviderRequest,
    UnknownProviderError,
    build_llm_gateway_service,
    compose_provider_url,
)

SECRET = "unit-secret"


class Clock:
    def __init__(self, epoch: float) -> None:
        self.epoch = float(epoch)

    def time(self) -> float:
        return self.epoch


def test_issue_then_verify_round_trips_claims() -> None:
    authority = GatewayTokenAuthority(SECRET, now_fn=lambda: 1000.0)
    token = authority.issue(validator_hotkey="v1", assignment_id="a1", ttl_seconds=60)
    claims = authority.verify(token)
    assert claims.validator_hotkey == "v1"
    assert claims.assignment_id == "a1"
    assert claims.expires_at == 1060


def test_empty_secret_rejected() -> None:
    with pytest.raises(ValueError):
        GatewayTokenAuthority("")


@pytest.mark.parametrize("token", ["", None, "one-part", "a.b.c", "x.", ".y"])
def test_malformed_token_is_invalid(token: str | None) -> None:
    authority = GatewayTokenAuthority(SECRET, now_fn=lambda: 1000.0)
    with pytest.raises(GatewayTokenInvalid):
        authority.verify(token)


def test_forged_signature_is_invalid() -> None:
    authority = GatewayTokenAuthority(SECRET, now_fn=lambda: 1000.0)
    token = authority.issue(validator_hotkey="v1", assignment_id="a1", ttl_seconds=60)
    payload_b64, _signature = token.split(".")
    forged = f"{payload_b64}.deadbeef"
    with pytest.raises(GatewayTokenInvalid):
        authority.verify(forged)


def test_token_signed_by_other_secret_is_invalid() -> None:
    issuer = GatewayTokenAuthority(SECRET, now_fn=lambda: 1000.0)
    token = issuer.issue(validator_hotkey="v1", assignment_id="a1", ttl_seconds=60)
    other = GatewayTokenAuthority("different-secret", now_fn=lambda: 1000.0)
    with pytest.raises(GatewayTokenInvalid):
        other.verify(token)


def test_expired_token_raises_expired() -> None:
    clock = Clock(1000.0)
    authority = GatewayTokenAuthority(SECRET, now_fn=clock.time)
    token = authority.issue(validator_hotkey="v1", assignment_id="a1", ttl_seconds=10)
    clock.epoch = 1011.0
    with pytest.raises(GatewayTokenExpired):
        authority.verify(token)


def test_scope_mismatch_raises_scope_error() -> None:
    authority = GatewayTokenAuthority(SECRET, now_fn=lambda: 1000.0)
    token = authority.issue(validator_hotkey="v1", assignment_id="a1", ttl_seconds=60)
    with pytest.raises(GatewayTokenScopeError):
        authority.verify(token, expected_validator="v2")
    with pytest.raises(GatewayTokenScopeError):
        authority.verify(token, expected_assignment="a2")
    # Matching scope passes.
    claims = authority.verify(token, expected_validator="v1", expected_assignment="a1")
    assert claims.assignment_id == "a1"


def test_compose_provider_url_strips_slashes() -> None:
    assert (
        compose_provider_url("https://api.deepseek.com/", "/chat/completions")
        == "https://api.deepseek.com/chat/completions"
    )


def test_mock_provider_is_deterministic_and_records_request() -> None:
    provider = MockLLMProvider(name="deepseek", base_url=DEEPSEEK_BASE_URL)
    request = ProviderRequest(
        method="POST",
        path="chat/completions",
        headers={"Authorization": "Bearer server-key"},
        body=json.dumps({"model": "deepseek-v4-pro"}).encode(),
    )

    first = asyncio.run(provider.forward(request))
    second = asyncio.run(provider.forward(request))

    assert first.body == second.body  # deterministic
    assert provider.call_count == 2
    recorded = provider.requests[0]
    assert recorded.header("authorization") == "Bearer server-key"
    assert recorded.url == "https://api.deepseek.com/chat/completions"
    assert recorded.json_body()["model"] == "deepseek-v4-pro"


def test_build_service_real_mode_requires_provider_keys() -> None:
    with pytest.raises(ValueError, match="deepseek, openrouter"):
        build_llm_gateway_service(
            deepseek_api_key="",
            openrouter_api_key="",
            token_secret=SECRET,
            provider_config=ProviderConfig(mode="real"),
        )
    with pytest.raises(ValueError, match="openrouter"):
        build_llm_gateway_service(
            deepseek_api_key="ds-key",
            openrouter_api_key="",
            token_secret=SECRET,
            provider_config=ProviderConfig(mode="real"),
        )


def test_build_service_real_mode_succeeds_with_keys() -> None:
    service = build_llm_gateway_service(
        deepseek_api_key="ds-key",
        openrouter_api_key="or-key",
        token_secret=SECRET,
        provider_config=ProviderConfig(mode="real"),
    )
    assert isinstance(service, LLMGatewayService)
    assert isinstance(service.provider("deepseek"), HttpLLMProvider)


def test_build_service_mock_mode_allows_empty_keys() -> None:
    service = build_llm_gateway_service(
        deepseek_api_key="",
        openrouter_api_key="",
        token_secret=SECRET,
        provider_config=ProviderConfig(mode="mock"),
    )
    token = service.issue_token(validator_hotkey="v1", assignment_id="a1")
    assert service.token_authority.verify(token).validator_hotkey == "v1"


def test_build_service_injects_key_and_enforces_model() -> None:
    service = build_llm_gateway_service(
        deepseek_api_key="ds-key",
        openrouter_api_key="or-key",
        token_secret=SECRET,
        provider_config=ProviderConfig(mode="mock"),
    )
    token = service.issue_token(validator_hotkey="v1", assignment_id="a1")
    assert service.token_authority.verify(token).validator_hotkey == "v1"

    response = asyncio.run(
        service.forward(
            provider="openrouter",
            path="chat/completions",
            body=json.dumps({"model": "gpt-4o"}).encode(),
            caller_headers={},
        )
    )
    assert response.status_code == 200
    provider = service.provider("openrouter")
    assert isinstance(provider, MockLLMProvider)
    assert provider.requests[-1].header("Authorization") == "Bearer or-key"


def test_service_unknown_provider_raises() -> None:
    service = build_llm_gateway_service(
        deepseek_api_key="ds-key",
        openrouter_api_key="or-key",
        token_secret=SECRET,
    )
    with pytest.raises(UnknownProviderError):
        service.provider("bogus")
    token = service.issue_token(validator_hotkey="v1", assignment_id="a1")
    with pytest.raises(UnknownProviderError):
        service.authenticate(
            provider="bogus",
            token=token,
            expected_validator=None,
            expected_assignment=None,
        )


def test_service_forward_rejects_disallowed_deepseek_model() -> None:
    from base.master.llm_gateway import ModelNotAllowedError

    service = build_llm_gateway_service(
        deepseek_api_key="ds-key",
        openrouter_api_key="or-key",
        token_secret=SECRET,
    )
    with pytest.raises(ModelNotAllowedError):
        asyncio.run(
            service.forward(
                provider="deepseek",
                path="chat/completions",
                body=json.dumps({"model": "deepseek-chat"}).encode(),
                caller_headers={},
            )
        )
