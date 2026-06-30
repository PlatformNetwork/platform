"""Scoped gateway tokens for the master LLM gateway.

Eval runtimes authenticate to the gateway with a short-lived token scoped to a
single ``(validator_hotkey, assignment_id)`` pair, NOT a raw provider key
(architecture.md sec 5). The token is a self-contained HMAC-signed value so the
gateway can verify it statelessly: ``base64url(payload).base64url(signature)``
where ``payload`` is the JSON claims and ``signature`` is
``HMAC-SHA256(secret, payload_b64)``.
"""

from __future__ import annotations

import base64
import hmac
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256

#: A standard token scoped to a single ``(validator_hotkey, assignment_id)``
#: work assignment. Its activity is bound to the live assignment lifecycle.
ASSIGNMENT_KIND = "assignment"
#: A non-assignment-scoped token for the central safety gates (agent-challenge +
#: prism LLM review). It carries a principal/label instead of a live assignment,
#: so the gateway treats it as active by valid signature + unexpired ``exp``
#: alone (no assignment-lifecycle resolution).
CENTRAL_GATE_KIND = "central-gate"

#: The token kinds the gateway recognizes; any other ``k`` claim is invalid.
_KNOWN_KINDS = frozenset({ASSIGNMENT_KIND, CENTRAL_GATE_KIND})


class GatewayTokenError(ValueError):
    """Base class for gateway-token verification failures."""


class GatewayTokenInvalid(GatewayTokenError):
    """Token is missing, malformed, or fails signature verification (HTTP 401)."""


class GatewayTokenExpired(GatewayTokenError):
    """Token signature is valid but the token has expired (HTTP 401)."""


class GatewayTokenScopeError(GatewayTokenError):
    """Token is used outside its ``(validator, assignment)`` scope (HTTP 403)."""


@dataclass(frozen=True)
class GatewayTokenClaims:
    """Verified scope of a gateway token."""

    validator_hotkey: str
    assignment_id: str
    expires_at: int
    kind: str = ASSIGNMENT_KIND


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


class GatewayTokenAuthority:
    """Issues and verifies scoped gateway tokens with a shared HMAC secret."""

    def __init__(
        self,
        secret: str,
        *,
        now_fn: Callable[[], float] = time.time,
        default_ttl_seconds: int = 3_600,
    ) -> None:
        if not secret:
            raise ValueError("gateway token secret must not be empty")
        self._secret = secret.encode("utf-8")
        self._now_fn = now_fn
        self.default_ttl_seconds = default_ttl_seconds

    def _sign(self, payload_b64: str) -> str:
        digest = hmac.new(self._secret, payload_b64.encode("ascii"), sha256).digest()
        return _b64encode(digest)

    def issue(
        self,
        *,
        validator_hotkey: str,
        assignment_id: str,
        ttl_seconds: int | None = None,
    ) -> str:
        """Mint a token scoped to ``(validator_hotkey, assignment_id)``."""

        ttl = self.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        expires_at = int(self._now_fn()) + int(ttl)
        payload = {
            "v": validator_hotkey,
            "a": assignment_id,
            "exp": expires_at,
        }
        payload_b64 = _b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        return f"{payload_b64}.{self._sign(payload_b64)}"

    def issue_central_gate(
        self,
        *,
        principal: str,
        label: str,
        ttl_seconds: int | None = None,
    ) -> str:
        """Mint a non-assignment-scoped ``central-gate`` token.

        The token carries a ``k`` claim marking it as :data:`CENTRAL_GATE_KIND`
        and reuses the ``v``/``a`` slots for the principal (e.g. ``central-gate``)
        and label (e.g. the challenge slug), so no new claim columns are needed.
        Unlike :meth:`issue`, it is NOT bound to a live work assignment: the
        gateway treats it as active by valid signature + unexpired ``exp`` alone.
        """

        ttl = self.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        expires_at = int(self._now_fn()) + int(ttl)
        payload = {
            "k": CENTRAL_GATE_KIND,
            "v": principal,
            "a": label,
            "exp": expires_at,
        }
        payload_b64 = _b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        return f"{payload_b64}.{self._sign(payload_b64)}"

    def verify(
        self,
        token: str | None,
        *,
        expected_validator: str | None = None,
        expected_assignment: str | None = None,
    ) -> GatewayTokenClaims:
        """Verify ``token`` and (optionally) bind it to an expected scope.

        Raises :class:`GatewayTokenInvalid` for a missing/malformed/forged
        token, :class:`GatewayTokenExpired` once past ``exp``, and
        :class:`GatewayTokenScopeError` when an expected validator/assignment
        does not match the token's claims.
        """

        if not token or not token.strip():
            raise GatewayTokenInvalid("missing gateway token")
        parts = token.strip().split(".")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise GatewayTokenInvalid("malformed gateway token")
        payload_b64, signature = parts
        if not hmac.compare_digest(self._sign(payload_b64), signature):
            raise GatewayTokenInvalid("gateway token signature mismatch")
        try:
            payload = json.loads(_b64decode(payload_b64))
        except (ValueError, json.JSONDecodeError) as exc:
            raise GatewayTokenInvalid("malformed gateway token payload") from exc
        if not isinstance(payload, dict):
            raise GatewayTokenInvalid("malformed gateway token payload")

        validator_hotkey = payload.get("v")
        assignment_id = payload.get("a")
        expires_at = payload.get("exp")
        if (
            not isinstance(validator_hotkey, str)
            or not isinstance(assignment_id, str)
            or not isinstance(expires_at, int)
        ):
            raise GatewayTokenInvalid("incomplete gateway token claims")

        kind = payload.get("k", ASSIGNMENT_KIND)
        if kind not in _KNOWN_KINDS:
            raise GatewayTokenInvalid("unknown gateway token kind")

        if int(self._now_fn()) >= expires_at:
            raise GatewayTokenExpired("gateway token expired")

        if expected_validator is not None and expected_validator != validator_hotkey:
            raise GatewayTokenScopeError("gateway token validator scope mismatch")
        if expected_assignment is not None and expected_assignment != assignment_id:
            raise GatewayTokenScopeError("gateway token assignment scope mismatch")

        return GatewayTokenClaims(
            validator_hotkey=validator_hotkey,
            assignment_id=assignment_id,
            expires_at=expires_at,
            kind=kind,
        )
