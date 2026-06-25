"""Task 11: greenfield (no-restore) bring-up path for install-swarm.sh.

The operator moved off k3s to Swarm, so the k3s cutover dumps
(`/root/cutover-backups/LATEST/{base,agent-challenge,prism}.sql`) will NOT exist
at deploy time. `--greenfield` must let a fresh install proceed by SKIPPING both
the backup-dump preflight requirement AND `restore_data`, while the DEFAULT
(non-greenfield) path stays byte-identical: dumps required, restore performed.

These are behavioral tests — they execute the real installer in its DEFAULT
dry-run mode (it mutates nothing) with a stub `docker` on PATH, so they assert
the actual control flow rather than re-reading the source. They respect the
`test_docker_compose_deploy.py` contract: the installer stays imperative
`docker service create`, never compose YAML.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SWARM_INSTALLER = ROOT / "deploy" / "swarm" / "install-swarm.sh"

RESTORE_MARKER = "psql restore"
PREFLIGHT_SKIP_MARKER = "SKIPPING backup-dump preflight"
RESTORE_SKIP_MARKER = "SKIPPING restore"

# Every secret env var the installer hard-requires (create_secrets / proxy seed)
# so a full dry-run reaches restore_data (STEP 8) instead of dying earlier on a
# missing secret. Values are throwaway non-empty strings — dry-run never uses
# them (plan_secret_stdin only prints in dry-run).
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
}


def _docker_stub(bin_dir: Path) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    stub = bin_dir / "docker"
    # Satisfy the read-only preflight/idempotency probes the installer runs
    # OUTSIDE the `plan` gate: report a recent engine + an inactive (not-yet)
    # swarm, and make every `inspect` miss so resources are "planned" (printed).
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
    with_backups: bool,
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    _docker_stub(bin_dir)

    backup_dir = tmp_path / "cutover-backups" / "LATEST"
    if with_backups:
        backup_dir.mkdir(parents=True, exist_ok=True)
        for dump in ("base.sql", "agent-challenge.sql", "prism.sql"):
            (backup_dir / dump).write_text("-- dump\n", encoding="utf-8")

    env = dict(os.environ)
    env.update(REQUIRED_SECRET_ENV)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    env["BROKER_WORKSPACE_DIR"] = str(tmp_path / "broker-ws")
    env["MASTER_CONFIG_PATH"] = str(tmp_path / "master.yaml")

    args = [
        "bash",
        str(SWARM_INSTALLER),
        "--backup-dir",
        str(backup_dir),
        *extra_args,
    ]
    return subprocess.run(
        args,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_greenfield_skips_preflight_dump_check_and_restore(tmp_path: Path) -> None:
    result = _run(tmp_path, "--greenfield", with_backups=False)

    assert result.returncode == 0, (
        "greenfield must NOT die on missing dumps; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert PREFLIGHT_SKIP_MARKER in result.stdout
    assert RESTORE_SKIP_MARKER in result.stdout
    # restore_data was bypassed: its dry-run plan ("psql restore") never printed.
    assert RESTORE_MARKER not in result.stdout
    assert "backup dir not found" not in result.stderr
    assert "missing dump file" not in result.stderr


def test_default_dies_when_dumps_missing(tmp_path: Path) -> None:
    result = _run(tmp_path, with_backups=False)

    assert result.returncode != 0
    assert "backup dir not found" in result.stderr
    assert PREFLIGHT_SKIP_MARKER not in result.stdout


def test_default_restores_when_dumps_present(tmp_path: Path) -> None:
    result = _run(tmp_path, with_backups=True)

    assert result.returncode == 0, (
        f"default with dumps present must succeed; stderr={result.stderr!r}"
    )
    # The DEFAULT path still invokes restore_data (its dry-run plan prints).
    assert RESTORE_MARKER in result.stdout
    assert PREFLIGHT_SKIP_MARKER not in result.stdout
    assert RESTORE_SKIP_MARKER not in result.stdout


def test_greenfield_stays_imperative_service_create_no_compose(
    tmp_path: Path,
) -> None:
    result = _run(tmp_path, "--greenfield", with_backups=False)

    # Respect the test_docker_compose_deploy.py contract: imperative Swarm only.
    assert "docker service create" in result.stdout
    assert "docker compose" not in result.stdout.lower()
    assert "compose.yml" not in result.stdout.lower()
