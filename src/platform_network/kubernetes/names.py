from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

POSTGRES_DATABASE_NAME = "challenge"
POSTGRES_DATABASE_USER = "challenge"
POSTGRES_SECRET_KEY_DB = "POSTGRES_DB"
POSTGRES_SECRET_KEY_USER = "POSTGRES_USER"
POSTGRES_SECRET_KEY_PASSWORD = "POSTGRES_PASSWORD"
POSTGRES_SECRET_KEY_DATABASE_URL = "CHALLENGE_DATABASE_URL"
POSTGRES_SECRET_KEYS = (
    POSTGRES_SECRET_KEY_DB,
    POSTGRES_SECRET_KEY_USER,
    POSTGRES_SECRET_KEY_PASSWORD,
    POSTGRES_SECRET_KEY_DATABASE_URL,
)

_DNS_LABEL_RE = re.compile(r"[^a-z0-9-]+")


@dataclass(frozen=True, slots=True)
class ChallengePostgresNames:
    base_name: str
    service_name: str
    statefulset_name: str
    secret_name: str
    data_claim_name: str
    database_name: str = POSTGRES_DATABASE_NAME
    database_user: str = POSTGRES_DATABASE_USER
    secret_keys: tuple[str, ...] = POSTGRES_SECRET_KEYS

    @property
    def stateful_set_name(self) -> str:
        return self.statefulset_name


def _dns_label(value: str) -> str:
    normalized = _DNS_LABEL_RE.sub("-", value.lower()).strip("-")
    if not normalized:
        raise ValueError("Kubernetes name cannot be empty")
    return normalized


def k8s_name(*parts: str, max_length: int = 63) -> str:
    raw = "-".join(part for part in parts if part)
    value = _dns_label(raw)
    if len(value) <= max_length:
        return value
    digest = hashlib.sha1(value.encode()).hexdigest()[:8]
    return f"{value[: max_length - 9].rstrip('-')}-{digest}"


def _postgres_slug_component(slug: str, *, max_length: int) -> str:
    normalized = _DNS_LABEL_RE.sub("-", slug.lower()).strip("-")
    digest = hashlib.sha1(slug.encode()).hexdigest()[:8]
    if not normalized:
        normalized = "slug"
    if normalized == slug and len(normalized) <= max_length:
        return normalized
    stem = normalized[: max_length - 9].rstrip("-") or "slug"
    return f"{stem}-{digest}"


def _challenge_postgres_name(slug: str, suffix: str) -> str:
    max_slug_length = 63 - len("challenge") - len(suffix) - 2
    slug_component = _postgres_slug_component(slug, max_length=max_slug_length)
    return k8s_name("challenge", slug_component, suffix)


def challenge_name(slug: str) -> str:
    return k8s_name("challenge", slug)


def challenge_secret_name(slug: str) -> str:
    return k8s_name("challenge", slug, "secrets")


def challenge_pvc_name(slug: str) -> str:
    return k8s_name("challenge", slug, "data")


def challenge_postgres_names(slug: str) -> ChallengePostgresNames:
    base_name = _challenge_postgres_name(slug, "postgres")
    return ChallengePostgresNames(
        base_name=base_name,
        service_name=base_name,
        statefulset_name=base_name,
        secret_name=_challenge_postgres_name(slug, "postgres-secret"),
        data_claim_name=_challenge_postgres_name(slug, "postgres-data"),
    )


def broker_job_name(
    challenge_slug: str,
    job_id: str,
    task_id: str | None = None,
    run_id: str | None = None,
) -> str:
    return k8s_name("broker", challenge_slug, job_id, task_id or "", run_id or "")
