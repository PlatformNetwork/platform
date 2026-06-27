"""Secret redaction for the master LLM gateway.

Provider keys and gateway tokens must never appear in logs, responses, or error
bodies (architecture.md sec 5 and 11). This module provides a string-level
redactor and a logging filter that scrubs registered secrets from log records,
including the formatted exception traceback, so an accidental ``logger.exception``
on the forward path cannot leak an injected key.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar

#: Replacement written in place of any redacted secret substring.
REDACTION_PLACEHOLDER = "[REDACTED]"

#: Per-context (per-request) secrets, unioned with a filter's static secrets.
#: Used for short-lived material (e.g. a scoped gateway token) so it is redacted
#: while in scope without permanently growing any filter's secret set.
_context_secrets: ContextVar[frozenset[str]] = ContextVar(
    "llm_gateway_context_secrets", default=frozenset()
)


@contextmanager
def redact_in_context(*secrets: str | None) -> Iterator[None]:
    """Register ``secrets`` for redaction for the duration of the context.

    Unlike :func:`install_secret_redaction`, these secrets are scoped to the
    current execution context (and therefore the current request) and removed
    on exit, so short-lived per-request material (e.g. a scoped gateway token)
    is redacted from any log emitted by a :class:`SecretRedactingFilter` while
    it is in scope, without permanently growing the filter's secret set.
    """

    cleaned = frozenset(secret for secret in secrets if secret)
    if not cleaned:
        yield
        return
    reset_token = _context_secrets.set(_context_secrets.get() | cleaned)
    try:
        yield
    finally:
        _context_secrets.reset(reset_token)


def redact_secrets(text: str, secrets: Iterable[str]) -> str:
    """Replace every occurrence of each non-empty secret with the placeholder."""

    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, REDACTION_PLACEHOLDER)
    return redacted


class SecretRedactingFilter(logging.Filter):
    """A logging filter that scrubs registered secrets from emitted records.

    The record's rendered message, its arguments, and any attached exception
    traceback are redacted in place before the record reaches any handler.
    """

    def __init__(self, secrets: Iterable[str]) -> None:
        super().__init__()
        self._secrets: set[str] = {secret for secret in secrets if secret}

    @property
    def secrets(self) -> set[str]:
        return set(self._secrets)

    def add_secrets(self, secrets: Iterable[str]) -> None:
        self._secrets.update(secret for secret in secrets if secret)

    def filter(self, record: logging.LogRecord) -> bool:
        secrets = self._secrets | _context_secrets.get()
        if not secrets:
            return True
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive: malformed log args
            message = str(record.msg)
        record.msg = redact_secrets(message, secrets)
        record.args = None
        if record.exc_info and record.exc_info != (None, None, None):
            formatted = logging.Formatter().formatException(record.exc_info)
            record.exc_text = redact_secrets(formatted, secrets)
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = redact_secrets(record.exc_text, secrets)
        return True


def install_secret_redaction(secrets: Iterable[str], *, logger: logging.Logger) -> None:
    """Attach (or extend) a single redaction filter on ``logger``.

    Idempotent: repeated calls reuse the one :class:`SecretRedactingFilter`
    already on the logger and merely register additional secrets, so the gateway
    can call this whenever a service is constructed.
    """

    cleaned = {secret for secret in secrets if secret}
    if not cleaned:
        return
    for existing in logger.filters:
        if isinstance(existing, SecretRedactingFilter):
            existing.add_secrets(cleaned)
            return
    logger.addFilter(SecretRedactingFilter(cleaned))
