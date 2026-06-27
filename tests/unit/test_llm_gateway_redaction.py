"""Unit tests for gateway secret redaction across logs (VAL-LLM-013/014/015)."""

from __future__ import annotations

import logging

import pytest

from base.master.llm_gateway.redaction import (
    REDACTION_PLACEHOLDER,
    SecretRedactingFilter,
    install_secret_redaction,
    redact_secrets,
)

SECRET = "sk-redaction-unit-secret"


def test_redact_secrets_replaces_all_occurrences() -> None:
    text = f"key={SECRET} again {SECRET}"
    redacted = redact_secrets(text, [SECRET])
    assert SECRET not in redacted
    assert redacted.count(REDACTION_PLACEHOLDER) == 2


def test_redact_secrets_ignores_empty_secrets() -> None:
    text = "nothing to redact"
    assert redact_secrets(text, ["", None]) == text  # type: ignore[list-item]


def test_filter_scrubs_message_and_args(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("base.master.llm_gateway.test_filter_message")
    logger.propagate = True
    install_secret_redaction([SECRET], logger=logger)
    with caplog.at_level(logging.DEBUG):
        logger.warning("leaked %s here", SECRET)
    assert SECRET not in caplog.text
    assert REDACTION_PLACEHOLDER in caplog.text


def test_filter_scrubs_exception_traceback(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("base.master.llm_gateway.test_filter_exc")
    logger.propagate = True
    install_secret_redaction([SECRET], logger=logger)
    with caplog.at_level(logging.ERROR):
        try:
            raise RuntimeError(f"upstream boom with {SECRET}")
        except RuntimeError:
            logger.exception("forward failed")
    assert SECRET not in caplog.text


def test_install_is_idempotent_and_accumulates_secrets() -> None:
    logger = logging.getLogger("base.master.llm_gateway.test_idempotent")
    install_secret_redaction(["aaa"], logger=logger)
    install_secret_redaction(["bbb"], logger=logger)
    filters = [f for f in logger.filters if isinstance(f, SecretRedactingFilter)]
    assert len(filters) == 1
    assert redact_secrets("aaa bbb", filters[0].secrets) == (
        f"{REDACTION_PLACEHOLDER} {REDACTION_PLACEHOLDER}"
    )
