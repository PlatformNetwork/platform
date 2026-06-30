"""Guard: install-swarm.sh must make the master secret_dir volume
(``vol_base_secrets``) WRITABLE by the master runtime uid, so the non-root master
can create per-challenge token files at registration.

The master writes ``<slug>_challenge_token`` / ``<slug>_docker_broker_token`` into
its ``secret_dir`` (the ``vol_base_secrets`` volume, mounted at
``/var/lib/base/secrets`` on the proxy/broker) when a challenge is registered
(``POST /v1/admin/challenges`` -> ``registry._write_token`` /
``_write_broker_token``). A FRESH docker volume's root dir is owned ``root:root``
mode ``0755`` while the master runs NON-root (``Dockerfile.master`` pins
``USER 1000:1000``), so it CANNOT create new files there -> HTTP 500
``PermissionError`` (discovered live; operationally hot-fixed via
``chown 1000:1000`` of the volume dir). The installer must chown the volume ROOT
DIR to the runtime uid BEFORE the master starts.

These are BEHAVIORAL dry-run tests: they execute the real installer (mutating
nothing) with a stub ``docker`` on PATH and assert the *planned* argv, not the
source text. The volume-ROOT chown is exactly what the OLD code lacked -- it
chowned only the per-file token paths ``/secrets/<slug>_challenge_token``, leaving
the volume root ``root:root`` -- so these tests FAIL on that old behavior.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SWARM_INSTALLER = ROOT / "deploy" / "swarm" / "install-swarm.sh"

REQUIRED_SECRET_ENV = {
    "GHCR_USER": "ci-user",
    "GHCR_TOKEN": "ci-token",
    "BASE_ADMIN_TOKEN": "x",
    "MASTER_DATABASE_URL": "postgresql+asyncpg://base@base-master-postgres:5432/base",
    "MASTER_PG_PASSWORD": "x",
    "AGENT_CHALLENGE_CHALLENGE_TOKEN": "x",
    "AGENT_CHALLENGE_DOCKER_BROKER_TOKEN": "x",
    "AGENT_CHALLENGE_SUBMISSION_ENV_KEY": "x",
    "AGENT_CHALLENGE_DATABASE_URL": "postgresql+asyncpg://challenge@h:5432/challenge",
    "AGENT_CHALLENGE_PG_PASSWORD": "x",
    "PRISM_CHALLENGE_TOKEN": "x",
    "PRISM_DOCKER_BROKER_TOKEN": "x",
    "PRISM_DATABASE_URL": "postgresql+asyncpg://challenge@h:5432/challenge",
    "PRISM_PG_PASSWORD": "x",
    "OPENROUTER_API_KEY": "x",
    "GATEWAY_TOKEN": "x",
    "CENTRAL_GATEWAY_TOKEN": "x",
    "DEEPSEEK_API_KEY": "x",
}


def _docker_stub(bin_dir: Path, image_user: str | None = None) -> None:
    """`docker` stub: recent engine, INACTIVE swarm, every `inspect` MISSES.

    When ``image_user`` is given, ``docker image inspect`` echoes it (the image's
    ``Config.User``) so the installer derives the runtime uid FROM THE IMAGE; when
    ``None`` (the default) ``docker image`` falls through to a non-zero exit so the
    installer uses its 1000 fallback.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    stub = bin_dir / "docker"
    image_case = f"  image) echo '{image_user}' ;;\n" if image_user is not None else ""
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'case "$1" in\n'
        "  version) echo '29.1.3' ;;\n"
        "  info) echo 'inactive' ;;\n"
        f"{image_case}"
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _run(
    tmp_path: Path,
    *,
    image_user: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    _docker_stub(bin_dir, image_user=image_user)
    env = dict(os.environ)
    env.update(REQUIRED_SECRET_ENV)
    if extra_env:
        env.update(extra_env)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    env["BROKER_WORKSPACE_DIR"] = str(tmp_path / "broker-ws")
    env["MASTER_CONFIG_PATH"] = str(tmp_path / "master.yaml")
    return subprocess.run(
        [
            "bash",
            str(SWARM_INSTALLER),
            "--backup-dir",
            str(tmp_path / "missing"),
            "--greenfield",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _plan_text(out: str) -> str:
    """Plan lines, backslash-normalized.

    ``plan`` shell-quotes argv via ``printf '%q'`` which escapes the ``--mount``
    spec commas as ``\\,``; strip backslashes so the unescaped
    ``source=vol_base_secrets,destination=/secrets`` substring matches.
    """
    return out.replace("\\", "")


# A planned `docker run` that mounts vol_base_secrets at /secrets and chowns the
# volume ROOT dir (`/secrets` exactly, NOT a `/secrets/<file>` per-file path) to
# <uid>:<uid>. The per-file token-seed chowns target `/secrets/<name>`, so the
# negative lookahead excludes them -- this matches ONLY the volume-root chown.
_ROOT_CHOWN = re.compile(
    r"docker run\b[^\n]*source=vol_base_secrets,destination=/secrets"
    r"[^\n]*\bchown (\d+):(\d+) /secrets(?![\w/])"
)


def _root_chown_uids(plan_text: str) -> list[tuple[str, str]]:
    return [(m.group(1), m.group(2)) for m in _ROOT_CHOWN.finditer(plan_text)]


def test_secret_volume_root_made_writable_by_runtime_uid(tmp_path: Path) -> None:
    """The installer must plan a chown of the vol_base_secrets ROOT dir to the
    master runtime uid (1000 fallback). Absent on the old root:root-only behavior.
    """
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    plan = _plan_text(result.stdout)

    uids = _root_chown_uids(plan)
    assert uids, (
        "no planned chown of the vol_base_secrets ROOT dir to the runtime uid; a "
        "fresh docker volume root is root:root 0755 so the non-root master cannot "
        "create per-challenge token files -> POST /v1/admin/challenges 500. The "
        "installer must `docker run ... chown <uid>:<uid> /secrets` on the volume "
        "root (this is the old root:root-only regression)."
    )
    for owner_uid, owner_gid in uids:
        assert owner_uid == "1000" and owner_gid == "1000", (
            f"volume-root chown targets {owner_uid}:{owner_gid}, expected the "
            "master runtime uid 1000"
        )


def test_volume_root_chown_is_distinct_from_per_file_seed_chowns(
    tmp_path: Path,
) -> None:
    """The fix chowns the volume ROOT, not just the per-file token paths.

    The OLD code chowned only ``/secrets/<slug>_challenge_token`` (per-file), which
    left the volume root ``root:root`` and is why creating NEW token files 500'd.
    Both must be present now: the per-file seed chowns AND the new root-dir chown.
    """
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    plan = _plan_text(result.stdout)

    # Per-file seed chowns still happen (don't regress the bearer-token seeding).
    assert "chown 1000:1000 /secrets/agent-challenge_challenge_token" in plan
    assert "chown 1000:1000 /secrets/prism_challenge_token" in plan
    # And the volume ROOT is chowned too (the new, missing-before step).
    assert _root_chown_uids(plan), "volume-root chown step is missing"


def test_volume_writable_chown_runs_before_master_proxy_starts(
    tmp_path: Path,
) -> None:
    """The chown must be planned BEFORE the proxy service is created, else the
    master could start against a root:root volume and 500 on the first register."""
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    lines = _plan_text(result.stdout).splitlines()

    chown_idx = next((i for i, ln in enumerate(lines) if _ROOT_CHOWN.search(ln)), None)
    proxy_idx = next(
        (
            i
            for i, ln in enumerate(lines)
            if "docker service create" in ln and "--name base-master-proxy " in ln
        ),
        None,
    )
    assert chown_idx is not None, "no volume-root chown planned"
    assert proxy_idx is not None, "no base-master-proxy service create planned"
    assert chown_idx < proxy_idx, (
        "volume-root chown is planned AFTER the proxy service create; it must run "
        "first so the master never starts against a root:root secrets volume"
    )


def test_runtime_uid_is_derived_from_image_not_hardcoded(tmp_path: Path) -> None:
    """When the master image's ``Config.User`` reports a non-1000 uid, the chown
    must use THAT uid -- proving the uid is derived from the base image rather than
    a blind constant. The per-file seed chown must match for consistency too."""
    result = _run(tmp_path, image_user="4242:4242")
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    plan = _plan_text(result.stdout)

    uids = _root_chown_uids(plan)
    assert uids, "no volume-root chown planned"
    for owner_uid, owner_gid in uids:
        assert (owner_uid, owner_gid) == ("4242", "4242"), (
            f"volume-root chown used {owner_uid}:{owner_gid}, not the image's "
            "Config.User uid 4242 -> uid is hardcoded, not derived from the image"
        )
    # Consistency: the per-file token seed chown also tracks the derived uid.
    assert "chown 4242:4242 /secrets/agent-challenge_challenge_token" in plan


def test_runtime_uid_override_env_is_honored(tmp_path: Path) -> None:
    """An explicit MASTER_RUNTIME_UID override wins (operator escape hatch)."""
    result = _run(tmp_path, extra_env={"MASTER_RUNTIME_UID": "2002"})
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    plan = _plan_text(result.stdout)

    uids = _root_chown_uids(plan)
    assert uids, "no volume-root chown planned"
    for owner_uid, owner_gid in uids:
        assert (owner_uid, owner_gid) == ("2002", "2002")


def test_installer_is_bash_n_clean() -> None:
    proc = subprocess.run(
        ["bash", "-n", str(SWARM_INSTALLER)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"bash -n failed: {proc.stderr!r}"
