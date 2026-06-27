"""The master LLM gateway: provider routing + server-side key injection.

The gateway exposes ``POST /llm/deepseek/{path}`` and
``POST /llm/openrouter/{path}`` (architecture.md sec 5). It authenticates the
caller with a scoped gateway token, injects the provider private key
server-side, enforces the DeepSeek model policy, and forwards to the
config-selected provider. Validators/eval runtimes hold NO provider key; they
point their client base URL at the gateway and pass a scoped token.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass

from fastapi import APIRouter, Request, Response

from base.master.llm_gateway.lifecycle import AssignmentLifecycleResolver
from base.master.llm_gateway.providers import (
    DEEPSEEK_BASE_URL,
    OPENROUTER_BASE_URL,
    LLMProvider,
    ProviderConfig,
    ProviderRequest,
    ProviderResponse,
    build_providers,
)
from base.master.llm_gateway.redaction import install_secret_redaction, redact_secrets
from base.master.llm_gateway.tokens import (
    GatewayTokenAuthority,
    GatewayTokenClaims,
    GatewayTokenError,
    GatewayTokenExpired,
    GatewayTokenInvalid,
    GatewayTokenScopeError,
)
from base.master.llm_gateway.usage import (
    NullUsageRecorder,
    UsageRecord,
    UsageRecorder,
    parse_usage,
)

logger = logging.getLogger(__name__)

#: DeepSeek agent execution is locked to this model (architecture.md sec 5).
DEEPSEEK_REQUIRED_MODEL = "deepseek-v4-pro"

DEEPSEEK_PROVIDER = "deepseek"
OPENROUTER_PROVIDER = "openrouter"

#: Header carrying the scoped gateway token (preferred over ``Authorization``).
GATEWAY_TOKEN_HEADER = "X-Gateway-Token"
#: Optional cross-check headers declaring the scope a call is attributed to.
GATEWAY_VALIDATOR_HEADER = "X-Gateway-Validator"
GATEWAY_ASSIGNMENT_HEADER = "X-Gateway-Assignment"

#: Consumption contract: eval runtimes point these env vars at the gateway and
#: pass a scoped token; the master injects the real provider credential. The raw
#: provider key is never delivered to the caller.
DEEPSEEK_BASE_URL_ENV = "DEEPSEEK_BASE_URL"
OPENROUTER_BASE_URL_ENV = "OPENROUTER_BASE_URL"
GATEWAY_TOKEN_ENV = "BASE_GATEWAY_TOKEN"

_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
#: Response headers never relayed back to the caller (secret / framing).
_STRIPPED_RESPONSE_HEADERS = _HOP_BY_HOP_HEADERS | {
    "authorization",
    "content-length",
    "content-encoding",
}


class GatewayError(Exception):
    """A controlled gateway failure that maps to a safe HTTP status."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class UnknownProviderError(GatewayError):
    def __init__(self, provider: str) -> None:
        super().__init__(404, "unknown gateway provider")
        self.provider = provider


class ModelNotAllowedError(GatewayError):
    def __init__(self) -> None:
        super().__init__(400, "model not allowed for this provider")


class GatewayAssignmentInactiveError(GatewayTokenError):
    """Token's assignment is completed/failed/reassigned (maps to HTTP 403)."""


@dataclass(frozen=True)
class AuthenticatedCall:
    """A token-verified gateway call ready to forward."""

    provider: str
    claims: GatewayTokenClaims


class LLMGatewayService:
    """Routes authenticated gateway calls to providers with key injection."""

    def __init__(
        self,
        *,
        providers: Mapping[str, LLMProvider],
        api_keys: Mapping[str, str],
        token_authority: GatewayTokenAuthority,
        enforced_models: Mapping[str, str] | None = None,
        usage_recorder: UsageRecorder | None = None,
        assignment_resolver: AssignmentLifecycleResolver | None = None,
    ) -> None:
        self._providers = dict(providers)
        self._api_keys = dict(api_keys)
        self._token_authority = token_authority
        self._enforced_models = dict(
            enforced_models or {DEEPSEEK_PROVIDER: DEEPSEEK_REQUIRED_MODEL}
        )
        self._usage_recorder: UsageRecorder = usage_recorder or NullUsageRecorder()
        self._assignment_resolver = assignment_resolver
        # Guarantee the injected provider keys are scrubbed from any gateway log.
        install_secret_redaction(self._api_keys.values(), logger=logger)

    @property
    def token_authority(self) -> GatewayTokenAuthority:
        return self._token_authority

    def _redact(self, text: str) -> str:
        return redact_secrets(text, self._api_keys.values())

    def provider(self, name: str) -> LLMProvider:
        try:
            return self._providers[name]
        except KeyError as exc:
            raise UnknownProviderError(name) from exc

    def enforced_model(self, name: str) -> str | None:
        return self._enforced_models.get(name)

    def authenticate(
        self,
        *,
        provider: str,
        token: str | None,
        expected_validator: str | None,
        expected_assignment: str | None,
    ) -> AuthenticatedCall:
        """Verify the gateway token and bind the call to its scope.

        Authentication happens BEFORE any provider call so a rejected token
        never reaches an upstream provider.
        """

        if provider not in self._providers:
            raise UnknownProviderError(provider)
        claims = self._token_authority.verify(
            token,
            expected_validator=expected_validator,
            expected_assignment=expected_assignment,
        )
        return AuthenticatedCall(provider=provider, claims=claims)

    async def ensure_assignment_active(self, claims: GatewayTokenClaims) -> None:
        """Reject a token whose assignment is no longer active (VAL-LLM-023).

        A no-op when no resolver is configured (the token is then bound only by
        signature, expiry, and scope). Raises before any provider call so a
        terminated/reassigned assignment never reaches an upstream provider.
        """

        if self._assignment_resolver is None:
            return
        active = await self._assignment_resolver.is_active(
            validator_hotkey=claims.validator_hotkey,
            assignment_id=claims.assignment_id,
        )
        if not active:
            raise GatewayAssignmentInactiveError("assignment is no longer active")

    async def record_usage(
        self,
        *,
        claims: GatewayTokenClaims,
        provider: str,
        request_body: bytes,
        response: ProviderResponse,
    ) -> None:
        """Meter a successful call, keyed by ``(validator, assignment)``.

        Best-effort: a metering failure is logged (redacted) and never breaks
        the proxied response. No secret material is recorded.
        """

        prompt_tokens, completion_tokens, total_tokens = parse_usage(response.body)
        record = UsageRecord(
            validator_hotkey=claims.validator_hotkey,
            assignment_id=claims.assignment_id,
            provider=provider,
            model=_extract_model(request_body),
            status_code=response.status_code,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
        )
        try:
            await self._usage_recorder.record(record)
        except Exception as exc:
            logger.error(
                "llm gateway usage metering failed: %s", self._redact(str(exc))
            )

    def _enforce_model(self, provider: str, body: bytes) -> None:
        required = self._enforced_models.get(provider)
        if required is None:
            return
        model = _extract_model(body)
        if model != required:
            raise ModelNotAllowedError()

    def _inject_headers(
        self, provider: str, caller_headers: Mapping[str, str]
    ) -> dict[str, str]:
        content_type = _header(caller_headers, "content-type") or "application/json"
        return {
            "Authorization": f"Bearer {self._api_keys.get(provider, '')}",
            "Content-Type": content_type,
            "Accept": "application/json",
        }

    async def forward(
        self,
        *,
        provider: str,
        path: str,
        body: bytes,
        caller_headers: Mapping[str, str],
    ) -> ProviderResponse:
        """Enforce policy, inject the key, and forward to the provider.

        The caller's ``Authorization``/api-key headers are NOT forwarded; only
        the server-injected provider key reaches the upstream.
        """

        impl = self.provider(provider)
        self._enforce_model(provider, body)
        upstream_headers = self._inject_headers(provider, caller_headers)
        return await impl.forward(
            ProviderRequest(
                method="POST",
                path=path,
                headers=upstream_headers,
                body=body,
            )
        )

    def issue_token(
        self,
        *,
        validator_hotkey: str,
        assignment_id: str,
        ttl_seconds: int | None = None,
    ) -> str:
        return self._token_authority.issue(
            validator_hotkey=validator_hotkey,
            assignment_id=assignment_id,
            ttl_seconds=ttl_seconds,
        )


def build_llm_gateway_service(
    *,
    deepseek_api_key: str,
    openrouter_api_key: str,
    token_secret: str,
    provider_config: ProviderConfig | None = None,
    token_ttl_seconds: int = 3_600,
    usage_recorder: UsageRecorder | None = None,
    assignment_resolver: AssignmentLifecycleResolver | None = None,
) -> LLMGatewayService:
    """Construct the gateway service from config (provider mode + secrets)."""

    config = provider_config or ProviderConfig()
    return LLMGatewayService(
        providers=build_providers(config),
        api_keys={
            DEEPSEEK_PROVIDER: deepseek_api_key,
            OPENROUTER_PROVIDER: openrouter_api_key,
        },
        token_authority=GatewayTokenAuthority(
            token_secret, default_ttl_seconds=token_ttl_seconds
        ),
        usage_recorder=usage_recorder,
        assignment_resolver=assignment_resolver,
    )


def _extract_model(body: bytes) -> str:
    if not body:
        return ""
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return ""
    if not isinstance(payload, dict):
        return ""
    model = payload.get("model")
    return model if isinstance(model, str) else ""


def _header(headers: Mapping[str, str], name: str) -> str | None:
    value = headers.get(name)
    if value is not None:
        return value
    lowered = name.lower()
    for key, val in headers.items():
        if key.lower() == lowered:
            return val
    return None


def _extract_token(headers: Mapping[str, str]) -> str | None:
    token = _header(headers, GATEWAY_TOKEN_HEADER)
    if token and token.strip():
        return token.strip()
    authorization = _header(headers, "authorization")
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[len("bearer ") :].strip() or None
    return None


def _response_headers(response: ProviderResponse) -> dict[str, str]:
    return {
        key: value
        for key, value in response.headers.items()
        if key.lower() not in _STRIPPED_RESPONSE_HEADERS
    }


def build_llm_gateway_router(*, service: LLMGatewayService) -> APIRouter:
    """Build the LLM gateway router (deepseek + openrouter forward routes)."""

    router = APIRouter()

    async def handle(provider: str, path: str, request: Request) -> Response:
        token = _extract_token(request.headers)
        try:
            call = service.authenticate(
                provider=provider,
                token=token,
                expected_validator=_header(request.headers, GATEWAY_VALIDATOR_HEADER),
                expected_assignment=_header(request.headers, GATEWAY_ASSIGNMENT_HEADER),
            )
            await service.ensure_assignment_active(call.claims)
        except GatewayAssignmentInactiveError:
            return _error_response(403, "gateway token assignment is not active")
        except GatewayTokenScopeError:
            return _error_response(403, "gateway token scope mismatch")
        except (GatewayTokenExpired, GatewayTokenInvalid):
            return _error_response(401, "invalid gateway token")
        except GatewayTokenError:
            return _error_response(401, "invalid gateway token")
        except UnknownProviderError:
            return _error_response(404, "unknown gateway provider")

        body = await request.body()
        try:
            upstream = await service.forward(
                provider=provider,
                path=path,
                body=body,
                caller_headers=request.headers,
            )
        except GatewayError as exc:
            return _error_response(exc.status_code, exc.detail)
        except Exception:
            logger.exception("llm gateway upstream forward failed")
            return _error_response(502, "gateway upstream error")

        # An upstream error is surfaced as a controlled, non-leaking status; the
        # raw upstream body/headers are never relayed back to the caller.
        if upstream.status_code >= 400:
            return _surface_upstream_error(upstream.status_code)

        await service.record_usage(
            claims=call.claims,
            provider=provider,
            request_body=body,
            response=upstream,
        )
        return Response(
            content=upstream.body,
            status_code=upstream.status_code,
            headers=_response_headers(upstream),
            media_type=upstream.media_type,
        )

    @router.post("/llm/deepseek/{path:path}")
    async def deepseek(path: str, request: Request) -> Response:
        return await handle(DEEPSEEK_PROVIDER, path, request)

    @router.post("/llm/openrouter/{path:path}")
    async def openrouter(path: str, request: Request) -> Response:
        return await handle(OPENROUTER_PROVIDER, path, request)

    return router


def _error_response(status_code: int, detail: str) -> Response:
    """A safe JSON error body that never carries key/token material."""

    return Response(
        content=json.dumps({"detail": detail}).encode("utf-8"),
        status_code=status_code,
        media_type="application/json",
    )


def _surface_upstream_error(status_code: int) -> Response:
    """Map an upstream error status to a controlled, non-leaking response.

    Rate limiting (429) is preserved so callers can back off; every other
    upstream failure collapses to ``502`` so internal upstream details (and any
    upstream auth header / body) are never relayed to the caller.
    """

    if status_code == 429:
        return _error_response(429, "upstream rate limited")
    return _error_response(502, "upstream provider error")


__all__ = [
    "DEEPSEEK_BASE_URL",
    "DEEPSEEK_BASE_URL_ENV",
    "DEEPSEEK_PROVIDER",
    "DEEPSEEK_REQUIRED_MODEL",
    "GATEWAY_ASSIGNMENT_HEADER",
    "GATEWAY_TOKEN_ENV",
    "GATEWAY_TOKEN_HEADER",
    "GATEWAY_VALIDATOR_HEADER",
    "OPENROUTER_BASE_URL",
    "OPENROUTER_BASE_URL_ENV",
    "OPENROUTER_PROVIDER",
    "AuthenticatedCall",
    "GatewayAssignmentInactiveError",
    "GatewayError",
    "LLMGatewayService",
    "ModelNotAllowedError",
    "UnknownProviderError",
    "build_llm_gateway_router",
    "build_llm_gateway_service",
]
