"""H6 (VAL-HARD-SECRETS-001): mainnet deploy secret + placement guards.

Encodes the pre-mainnet hardening contract for ``install-swarm.sh``:

1. Every one of the 14 REQUIRED secret env vars HARD-FAILS the installer
   (``_ensure_secret`` → ``die``) when unset, so a missing secret is caught at
   ``create_secrets`` (STEP 6) and never silently tolerated.
2. The 1 CONDITIONAL secret (``DEEPSEEK_API_KEY``) hard-fails only when
   ``GATEWAY_PROVIDER_MODE=real`` (the default) and is tolerated/skipped under
   ``mock``.
3. The 2 OPTIONAL secrets (``CENTRAL_GATEWAY_TOKEN``, ``HF_TOKEN``) never
   hard-fail — an unset value is logged-and-skipped (``_ensure_optional_secret``).
4. The GHCR credentials hard-fail in ``preflight`` when unset.
5. Single-node placement behavior: the DEFAULT (no flags) master-orchestrated
   path EMITS the stranding ``node.role==worker`` default constraint (challenges
   stay Pending on a single-node swarm) and plans NO challenge service, while
   ``--static-challenges`` creates the challenge services directly WITHOUT the
   ``node.role==worker`` constraint (manager-pinned so they schedule on the sole
   manager).
6. The deploy/swarm runbook documents the required/conditional/optional secrets,
   the GHCR creds path, and the ``--static-challenges`` / ``--single-node-placement``
   placement requirement.

Behavioral dry-run tests: execute the real installer (mutating nothing) with a
stub ``docker`` on PATH and assert the planned argv / die message, not the source
text. They respect the ``test_docker_compose_deploy.py`` contract (imperative
``docker service create`` only, never compose YAML).
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SWARM_INSTALLER = ROOT / "deploy" / "swarm" / "install-swarm.sh"
SWARM_README = ROOT / "deploy" / "swarm" / "README.md"

# The 14 REQUIRED secrets: env var -> the docker secret name _ensure_secret makes.
# A missing/empty env var is a HARD error (die) — we never invent secret material.
REQUIRED_SECRETS: dict[str, str] = {
    "BASE_ADMIN_TOKEN": "base_admin_token",
    "MASTER_DATABASE_URL": "base_master_database_url",
    "MASTER_PG_PASSWORD": "base_master_pg_password",
    "AGENT_CHALLENGE_CHALLENGE_TOKEN": "base_agent_challenge_challenge_token",
    "AGENT_CHALLENGE_DOCKER_BROKER_TOKEN": "base_agent_challenge_docker_broker_token",
    "AGENT_CHALLENGE_SUBMISSION_ENV_KEY": (
        "base_agent_challenge_submission_env_encryption_key"
    ),
    "AGENT_CHALLENGE_DATABASE_URL": "base_agent_challenge_database_url",
    "AGENT_CHALLENGE_PG_PASSWORD": "base_agent_challenge_pg_password",
    "PRISM_CHALLENGE_TOKEN": "base_prism_challenge_token",
    "PRISM_DOCKER_BROKER_TOKEN": "base_prism_docker_broker_token",
    "PRISM_DATABASE_URL": "base_prism_database_url",
    "PRISM_PG_PASSWORD": "base_prism_pg_password",
    "OPENROUTER_API_KEY": "base_openrouter_api_key",
    "GATEWAY_TOKEN": "base_gateway_token_secret",
}

# The 1 CONDITIONAL secret (required only when GATEWAY_PROVIDER_MODE=real).
CONDITIONAL_SECRET = ("DEEPSEEK_API_KEY", "base_gateway_deepseek_api_key")

# The 2 OPTIONAL secrets (never hard-fail; logged-and-skipped when unset).
OPTIONAL_SECRETS: dict[str, str] = {
    "CENTRAL_GATEWAY_TOKEN": "base_gateway_token",
    "HF_TOKEN": "base_hf_token",
}

# Full env that satisfies every hard requirement so a dry-run runs to completion;
# individual tests DELETE one key to isolate its hard-fail. Values are throwaway
# (dry-run never uses them — plan_secret_stdin only prints in dry-run).
REQUIRED_SECRET_ENV: dict[str, str] = {
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
    """`docker` stub: recent engine, INACTIVE swarm, every `inspect` MISSES."""
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
    tmp_path: Path,
    *extra_args: str,
    drop_env: tuple[str, ...] = (),
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    _docker_stub(bin_dir)
    env = dict(os.environ)
    env.update(REQUIRED_SECRET_ENV)
    if extra_env:
        env.update(extra_env)
    # Genuinely UNSET the dropped vars (subprocess env is a full replacement, so a
    # value inherited from os.environ would otherwise leak through).
    for key in drop_env:
        env.pop(key, None)
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
            *extra_args,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _service_block(plan_lines: list[str], name: str) -> str:
    """Return the single planned `docker service create --name NAME ` line."""
    needle = f"--name {name} "
    for line in plan_lines:
        if "docker service create" in line and needle in line:
            return line.replace("\\", "")
    raise AssertionError(f"no `docker service create --name {name}` line planned")


def _challenge_create_lines(plan_lines: list[str]) -> list[str]:
    """All planned challenge APP service-create lines (api + worker, both slugs).

    Excludes the postgres services (``challenge-*-postgres``), which deploy in the
    DEFAULT path too — these are the challenge workloads gated by the placement flag.
    """
    app_names = (
        "challenge-agent-challenge ",
        "challenge-agent-challenge-worker ",
        "challenge-prism ",
        "challenge-prism-worker ",
    )
    out: list[str] = []
    for line in plan_lines:
        if "docker service create" not in line:
            continue
        if any(f"--name {name}" in line for name in app_names):
            out.append(line.replace("\\", ""))
    return out


# ---------------------------------------------------------------------------
# Required secrets: each hard-fails the installer when unset (_ensure_secret)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("envvar", sorted(REQUIRED_SECRETS))
def test_required_secret_hard_fails_when_unset(envvar: str, tmp_path: Path) -> None:
    result = _run(tmp_path, "--static-challenges", drop_env=(envvar,))

    assert result.returncode != 0, (
        f"installer must hard-fail when ${envvar} is unset; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    # _ensure_secret's die message names the missing env var (value never printed).
    assert f"required secret env var ${envvar} is empty" in result.stderr
    # No docker secret was created for it (the die precedes the plan_secret_stdin).
    secret_name = REQUIRED_SECRETS[envvar]
    assert f"docker secret create {secret_name}" not in result.stdout


def test_all_required_secrets_present_reaches_full_plan(tmp_path: Path) -> None:
    # Sanity: with every required secret present the dry-run completes and plans
    # all 14 secret creates (proves the per-var drop above is what triggers death).
    result = _run(tmp_path, "--static-challenges")
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    for secret_name in REQUIRED_SECRETS.values():
        assert f"docker secret create {secret_name}" in result.stdout


# ---------------------------------------------------------------------------
# Conditional secret: DEEPSEEK_API_KEY required only under provider_mode=real
# ---------------------------------------------------------------------------


def test_deepseek_hard_fails_when_provider_mode_real_and_unset(tmp_path: Path) -> None:
    envvar, secret_name = CONDITIONAL_SECRET
    # real is the default; assert explicitly to document the coupling.
    result = _run(
        tmp_path,
        "--static-challenges",
        drop_env=(envvar,),
        extra_env={"GATEWAY_PROVIDER_MODE": "real"},
    )
    assert result.returncode != 0, f"stdout={result.stdout!r}"
    assert f"required secret env var ${envvar} is empty" in result.stderr
    assert f"docker secret create {secret_name}" not in result.stdout


def test_deepseek_not_required_when_provider_mode_mock(tmp_path: Path) -> None:
    envvar, secret_name = CONDITIONAL_SECRET
    result = _run(
        tmp_path,
        "--static-challenges",
        drop_env=(envvar,),
        extra_env={"GATEWAY_PROVIDER_MODE": "mock"},
    )
    assert result.returncode == 0, (
        "mock provider mode must not require DEEPSEEK_API_KEY; "
        f"stderr={result.stderr!r}"
    )
    assert f"${envvar} is empty" not in result.stderr
    # The conditional secret is not even created under mock mode.
    assert f"docker secret create {secret_name}" not in result.stdout


# ---------------------------------------------------------------------------
# Optional secrets: never hard-fail (logged-and-skipped when unset)
# ---------------------------------------------------------------------------


def test_optional_secrets_skip_silently_when_unset(tmp_path: Path) -> None:
    # CENTRAL_GATEWAY_TOKEN / HF_TOKEN are absent from REQUIRED_SECRET_ENV, so a
    # plain run already exercises the optional-skip path.
    result = _run(tmp_path, "--static-challenges")
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    for envvar, secret_name in OPTIONAL_SECRETS.items():
        assert f"optional secret {secret_name} skipped" in result.stdout
        assert f"${envvar} is empty" not in result.stderr
        # No hard die for an optional secret.
        assert f"required secret env var ${envvar}" not in result.stderr


def test_optional_secrets_render_when_set(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        "--static-challenges",
        extra_env={"CENTRAL_GATEWAY_TOKEN": "scoped", "HF_TOKEN": "hf"},
    )
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    for secret_name in OPTIONAL_SECRETS.values():
        assert f"docker secret create {secret_name}" in result.stdout


# ---------------------------------------------------------------------------
# GHCR credentials: hard-fail in preflight when unset
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("envvar", ["GHCR_USER", "GHCR_TOKEN"])
def test_ghcr_credentials_hard_fail_when_unset(envvar: str, tmp_path: Path) -> None:
    result = _run(tmp_path, "--static-challenges", drop_env=(envvar,))
    assert result.returncode != 0, f"stdout={result.stdout!r}"
    assert f"{envvar} not set" in result.stderr


# ---------------------------------------------------------------------------
# Single-node placement: default emits node.role==worker (Pending) and plans NO
# challenge service; --static-challenges omits the worker constraint (manager-pin).
# ---------------------------------------------------------------------------


def test_default_path_emits_worker_constraint_and_plans_no_challenge_service(
    tmp_path: Path,
) -> None:
    # No --static-challenges (and no --single-node-placement): the master
    # orchestrates challenges, which inherit the default node.role==worker
    # constraint -> they sit Pending forever on a single-node swarm. The installer
    # documents this in STEP 4 and creates NO challenge app service itself.
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout

    assert "node.role==worker" in out
    assert "Pending" in out
    # The default deploy_challenges path is a no-op (master-orchestrated).
    assert "--static-challenges NOT set" in out
    assert _challenge_create_lines(out.splitlines()) == [], (
        "default path must NOT statically create challenge app services"
    )


def test_static_challenges_omits_worker_constraint_and_pins_manager(
    tmp_path: Path,
) -> None:
    result = _run(tmp_path, "--static-challenges")
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    lines = result.stdout.splitlines()

    challenge_lines = _challenge_create_lines(lines)
    # All four challenge app services (agent-challenge api+worker, prism api+worker)
    # are statically created.
    assert len(challenge_lines) == 4, challenge_lines
    for line in challenge_lines:
        # The stranding worker pin is omitted; the manager pin schedules them on
        # the sole manager node of a single-node swarm.
        assert "node.role==worker" not in line
        assert "--constraint node.role==manager" in line


# ---------------------------------------------------------------------------
# Runbook documents the required/conditional/optional secrets + GHCR + placement
# ---------------------------------------------------------------------------


def test_runbook_documents_secrets_ghcr_and_placement() -> None:
    readme = SWARM_README.read_text(encoding="utf-8")

    # All 14 required secrets (docker secret name + env var) are documented.
    for envvar, secret_name in REQUIRED_SECRETS.items():
        assert secret_name in readme, f"required secret {secret_name} undocumented"
        assert envvar in readme, f"required env var {envvar} undocumented"

    # Conditional secret + its GATEWAY_PROVIDER_MODE=real trigger.
    cond_env, cond_secret = CONDITIONAL_SECRET
    assert cond_env in readme
    assert cond_secret in readme
    assert "GATEWAY_PROVIDER_MODE=real" in readme

    # Optional secrets.
    for envvar, secret_name in OPTIONAL_SECRETS.items():
        assert envvar in readme
        assert secret_name in readme

    # GHCR credentials path.
    assert "GHCR_USER" in readme
    assert "GHCR_TOKEN" in readme

    # Single-node placement requirement: both flags + the stranding default + the
    # Pending consequence are documented.
    assert "--static-challenges" in readme
    assert "--single-node-placement" in readme
    assert "node.role==worker" in readme
    assert "Pending" in readme
