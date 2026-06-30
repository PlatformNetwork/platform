"""Central-gate (non-assignment-scoped) gateway token behavior (GW-001).

A ``central-gate`` token authorizes the central safety gates (agent-challenge
analyzer LLM review + prism ``llm_review`` gate) to call the master LLM gateway
WITHOUT a live work assignment. The gateway treats it as active by valid
signature + unexpired ``exp`` alone, bypassing the assignment-lifecycle resolver,
and records usage keyed by the token's principal/label. The standard
assignment-scoped path is left UNCHANGED (an inactive/unowned assignment still
yields 403).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient
from typer.testing import CliRunner

import base.cli_app.main as cli_main
from base.cli_app.main import app
from base.master.app_proxy import create_proxy_app
from base.master.llm_gateway import (
    CENTRAL_GATE_KIND,
    OPENROUTER_BASE_URL,
    GatewayAssignmentInactiveError,
    GatewayTokenAuthority,
    InMemoryUsageRecorder,
    LLMGatewayService,
    MockLLMProvider,
)
from base.master.llm_gateway.providers import DEEPSEEK_BASE_URL

TOKEN_SECRET = "central-gate-hmac-secret"
OPENROUTER_KEY = "sk-or-server-secret-key"
DEEPSEEK_KEY = "sk-deepseek-server-secret-key"


class FakeNonceStore:
    async def reserve(self, **_: object) -> None:
        return None


class FakeCache:
    def get(self) -> dict[str, int]:
        return {}


class ExplodingResolver:
    """A resolver that fails the test if it is ever consulted.

    Proves the central-gate path never reaches assignment resolution.
    """

    async def is_active(self, *, validator_hotkey: str, assignment_id: str) -> bool:
        raise AssertionError(
            "assignment resolver must NOT be consulted for a central-gate token"
        )


class InactiveResolver:
    async def is_active(self, *, validator_hotkey: str, assignment_id: str) -> bool:
        return False


def _service(resolver: object) -> tuple[LLMGatewayService, InMemoryUsageRecorder]:
    recorder = InMemoryUsageRecorder()
    service = LLMGatewayService(
        providers={
            "deepseek": MockLLMProvider(name="deepseek", base_url=DEEPSEEK_BASE_URL),
            "openrouter": MockLLMProvider(
                name="openrouter", base_url=OPENROUTER_BASE_URL
            ),
        },
        api_keys={"deepseek": DEEPSEEK_KEY, "openrouter": OPENROUTER_KEY},
        token_authority=GatewayTokenAuthority(TOKEN_SECRET, now_fn=lambda: 1_000.0),
        usage_recorder=recorder,
        assignment_resolver=resolver,  # type: ignore[arg-type]
    )
    return service, recorder


@pytest.fixture
async def client_and_recorder() -> AsyncIterator[
    tuple[AsyncClient, LLMGatewayService, InMemoryUsageRecorder]
]:
    service, recorder = _service(ExplodingResolver())
    app_proxy = create_proxy_app(
        registry=object(),
        nonce_store=FakeNonceStore(),
        metagraph_cache=FakeCache(),  # type: ignore[arg-type]
        llm_gateway_service=service,
    )
    transport = ASGITransport(app=app_proxy)
    client = AsyncClient(transport=transport, base_url="http://testserver")
    try:
        yield client, service, recorder
    finally:
        await client.aclose()


async def test_central_gate_token_bypasses_resolver_and_meters_principal_label(
    client_and_recorder: tuple[AsyncClient, LLMGatewayService, InMemoryUsageRecorder],
) -> None:
    client, service, recorder = client_and_recorder
    token = service.issue_central_gate_token(
        principal="central-gate", label="agent-challenge"
    )
    response = await client.post(
        "/llm/openrouter/chat/completions",
        content=json.dumps(
            {"model": "openai/gpt-4o", "messages": [{"role": "user", "content": "hi"}]}
        ).encode(),
        headers={"X-Gateway-Token": token},
    )
    # The ExplodingResolver would have raised (-> 500/403) had it been consulted;
    # a 200 proves the central-gate path bypassed assignment resolution.
    assert response.status_code == 200, response.text
    assert len(recorder.records) == 1
    record = recorder.records[0]
    assert record.validator_hotkey == "central-gate"
    assert record.assignment_id == "agent-challenge"
    assert record.provider == "openrouter"
    # No secret material is recorded.
    assert OPENROUTER_KEY not in json.dumps(record.__dict__)
    assert token not in json.dumps(record.__dict__)


async def test_central_gate_ensure_active_is_a_noop_without_consulting_resolver() -> (
    None
):
    service, _recorder = _service(ExplodingResolver())
    claims = service.token_authority.verify(
        service.issue_central_gate_token(principal="central-gate", label="prism")
    )
    assert claims.kind == CENTRAL_GATE_KIND
    # Must NOT raise (and must NOT consult the ExplodingResolver).
    await service.ensure_assignment_active(claims)


async def test_assignment_kind_still_rejects_inactive_assignment() -> None:
    service, _recorder = _service(InactiveResolver())
    claims = service.token_authority.verify(
        service.issue_token(validator_hotkey="v1", assignment_id="a1")
    )
    with pytest.raises(GatewayAssignmentInactiveError):
        await service.ensure_assignment_active(claims)


def test_cli_mint_central_gate_token_prints_verifiable_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "cli-gateway-secret"
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda config: SimpleNamespace(
            gateway=SimpleNamespace(token_secret=secret, token_secret_file=None)
        ),
    )
    result = CliRunner().invoke(
        app,
        [
            "master",
            "mint-central-gate-token",
            "--label",
            "agent-challenge",
            "--ttl-seconds",
            "31536000",
        ],
    )
    assert result.exit_code == 0, result.output
    token = result.output.strip()
    # ONLY the token is printed (a single non-empty line, two HMAC parts).
    assert token and len(token.splitlines()) == 1
    assert len(token.split(".")) == 2

    claims = GatewayTokenAuthority(secret).verify(token)
    assert claims.kind == CENTRAL_GATE_KIND
    assert claims.validator_hotkey == "central-gate"
    assert claims.assignment_id == "agent-challenge"
