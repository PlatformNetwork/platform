from __future__ import annotations

import hashlib
import re

_DNS_LABEL_RE = re.compile(r"[^a-z0-9-]+")


def k8s_name(*parts: str, max_length: int = 63) -> str:
    raw = "-".join(part for part in parts if part)
    value = _DNS_LABEL_RE.sub("-", raw.lower()).strip("-")
    if not value:
        raise ValueError("Kubernetes name cannot be empty")
    if len(value) <= max_length:
        return value
    digest = hashlib.sha1(value.encode()).hexdigest()[:8]
    return f"{value[: max_length - 9].rstrip('-')}-{digest}"


def challenge_name(slug: str) -> str:
    return k8s_name("challenge", slug)


def challenge_secret_name(slug: str) -> str:
    return k8s_name("challenge", slug, "secrets")


def challenge_pvc_name(slug: str) -> str:
    return k8s_name("challenge", slug, "data")


def broker_job_name(
    challenge_slug: str,
    job_id: str,
    task_id: str | None = None,
    run_id: str | None = None,
) -> str:
    return k8s_name("broker", challenge_slug, job_id, task_id or "", run_id or "")
