"""Defects D / E1 / E2: make prism miner-operable on Swarm via install-swarm.sh.

E1 (eval stuck pending): prism shipped with only the uvicorn API + postgres and
NO worker, so a claimed-nothing submission sits ``pending`` forever. A standing
``challenge-prism-worker`` service (command ``prism-worker --interval-seconds 5``)
must be deployed, manager-pinned to share the ``base_prism_pg`` /data volume with
the API (which must therefore also be manager-pinned).

E2 (eval can't pull the private evaluator): the broker shells out to ``docker
service create --with-registry-auth`` but the broker CONTAINER has no docker
config with ghcr.io creds, so the worker-node pull is unauthorized. The broker
must mount the manager's docker config dir and point ``DOCKER_CONFIG`` at it.

H1 (pre-mainnet hardening): the publicly-known //Alice dev seed MUST NOT be in the
DEFAULT ``UPLOAD_EXTRA_REGISTERED_HOTKEYS`` allowlist — anyone holding the public
//Alice key could otherwise submit as a registered hotkey. The default keeps only
the 4 operational hotkeys and any test key requires explicit operator opt-in via
the env override; the guard test FAILS if the //Alice ss58 reappears in the
rendered proxy allowlist env.

Behavioral dry-run tests: execute the real installer (mutating nothing) with a
stub ``docker`` on PATH and assert the planned argv, not the source text.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SWARM_INSTALLER = ROOT / "deploy" / "swarm" / "install-swarm.sh"

ALICE_HOTKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"

# The 4 operational hotkeys that MUST remain in the default allowlist
# (//AcE2EMiner, //Owner, //AcValidator1, //AcValidator2). //Alice is deliberately
# absent: it is a publicly-known dev seed and must never be miner-registrable by
# default.
OPERATIONAL_HOTKEYS = (
    "5EWKzomnbVvLKWjHeVqm2BMqMzmckKMiufR11qFXahaUfenR",
    "5FTyuyEQQZs8tCcPTUFqotkm2SYfDnpefn9FitRgmTHnFDBD",
    "5GGboHkKougeE8PqGRbNM32AEwRU7Dsv4MXATm2zukQJ8wrU",
    "5FJAjL6d31QDSfvcZPKkde9ftTLAPu7J5Mo86je5XbziRXSB",
)

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
    "DEEPSEEK_API_KEY": "x",
}


def _docker_stub(bin_dir: Path) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    stub = bin_dir / "docker"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'case "$1" in\n'
        "  version) echo '29.1.3' ;;\n"
        "  info) echo 'inactive' ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _run(
    tmp_path: Path, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    _docker_stub(bin_dir)
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
            "--static-challenges",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _service_block(plan_lines: list[str], name: str) -> str:
    """Return the single planned `docker service create` line for ``--name NAME``."""
    needle = f"--name {name} "
    for line in plan_lines:
        if "docker service create" in line and needle in line:
            return line
    raise AssertionError(f"no `docker service create --name {name}` line planned")


def _proxy_upload_allowlist_env(plan_lines: list[str]) -> str:
    """Return the rendered ``BASE_MASTER__UPLOAD_EXTRA_REGISTERED_HOTKEYS`` argv
    token from the planned ``base-master-proxy`` service create.

    The value is a compact JSON array (no spaces), so ``plan()``'s ``%q`` quoting
    keeps it a single whitespace-delimited token we can isolate.
    """
    proxy = _service_block(plan_lines, "base-master-proxy")
    marker = "BASE_MASTER__UPLOAD_EXTRA_REGISTERED_HOTKEYS="
    for token in proxy.split():
        if marker in token:
            return token
    raise AssertionError(
        "base-master-proxy plan missing"
        " BASE_MASTER__UPLOAD_EXTRA_REGISTERED_HOTKEYS env"
    )


def test_prism_worker_service_planned_with_constraint_and_command(
    tmp_path: Path,
) -> None:
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    lines = result.stdout.splitlines()

    worker = _service_block(lines, "challenge-prism-worker")
    assert "--constraint node.role==manager" in worker
    assert "prism-worker --interval-seconds 5" in worker
    assert "source=base_prism_pg" in worker and "destination=/data" in worker


def test_prism_api_pinned_to_manager_for_data_colocation(tmp_path: Path) -> None:
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    api = _service_block(result.stdout.splitlines(), "challenge-prism")
    assert "--constraint node.role==manager" in api


def test_broker_mounts_docker_config_for_registry_auth(tmp_path: Path) -> None:
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    broker = _service_block(result.stdout.splitlines(), "base-docker-broker")
    assert "target=/root/.docker" in broker
    assert "DOCKER_CONFIG=/root/.docker" in broker


def test_proxy_default_allowlist_excludes_alice_dev_seed(tmp_path: Path) -> None:
    """H1: the default rendered proxy allowlist is EXACTLY the 4 operational hotkeys
    and MUST NOT contain the publicly-known //Alice ss58. Fails if //Alice (or any
    other key) reappears in the rendered BASE_MASTER__UPLOAD_EXTRA_REGISTERED_HOTKEYS
    env of the planned base-master-proxy service argv."""
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"

    allowlist_env = _proxy_upload_allowlist_env(result.stdout.splitlines())
    # ss58 chars are base58 (no 0/O/I/l) and never %q-escaped, so they survive the
    # plan's shell-quoting verbatim and can be lifted out of the rendered token.
    rendered = re.findall(r"5[1-9A-HJ-NP-Za-km-z]{40,50}", allowlist_env)

    assert ALICE_HOTKEY not in rendered, (
        "//Alice dev seed must not be in the default UPLOAD_EXTRA_REGISTERED_HOTKEYS"
    )
    assert set(rendered) == set(OPERATIONAL_HOTKEYS), (
        f"default allowlist must be exactly the 4 operational hotkeys, got {rendered}"
    )


def test_proxy_allowlist_is_env_overridable(tmp_path: Path) -> None:
    """The allowlist stays env-overridable so a test key is only ever allowlisted by
    explicit operator opt-in (never by default)."""
    result = _run(
        tmp_path,
        extra_env={
            "UPLOAD_EXTRA_REGISTERED_HOTKEYS": f'["{ALICE_HOTKEY}"]',
        },
    )
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    allowlist_env = _proxy_upload_allowlist_env(result.stdout.splitlines())
    assert ALICE_HOTKEY in allowlist_env, "operator override must flow into the plan"
