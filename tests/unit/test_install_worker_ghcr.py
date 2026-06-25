"""Task 19: worker-side GHCR auth (GAP-WORKER-AUTH) for scripts/install-worker.sh.

A freshly enrolled Swarm worker must be able to pull private
`ghcr.io/baseintelligence/*` images at deploy time. `install-worker.sh`
previously joined the swarm + staged the GPU daemon.json but NEVER logged into
ghcr.io, so a `docker pull` (and any non-`--with-registry-auth` task) on the
worker would fail with `denied`/`unauthorized`.

This adds a `ghcr_login` step that authenticates to ghcr.io using credentials
supplied at RUNTIME (env `GHCR_USER` / `GHCR_TOKEN`) — never hardcoded — with the
token fed on stdin (never argv, never logged), mirroring
`deploy/swarm/install-swarm.sh::ghcr_login`. When the credentials are absent the
step is a non-fatal skip (a worker can still receive creds via the manager's
`--with-registry-auth` at service-create time), so existing CPU/GPU enrollment
flows that don't set the vars keep working.

These are behavioral tests: they execute the real installer in its DEFAULT
dry-run mode (it mutates nothing) with a stub `docker` on PATH, asserting the
actual control flow rather than re-reading the source.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKER_INSTALLER = ROOT / "scripts" / "install-worker.sh"

# Markers emitted by the new ghcr_login step.
LOGIN_STEP_MARKER = "ghcr_login"
LOGIN_CMD_MARKER = "docker login ghcr.io"
PASSWORD_STDIN_MARKER = "--password-stdin"
SKIP_MARKER = "skipping ghcr.io login"

# A throwaway token value that must NEVER appear in plan/log output (dry-run does
# not even read it; under --apply it would only ever go to stdin).
SECRET_SENTINEL = "tok-SENTINEL-must-not-leak-123"


def _docker_stub(bin_dir: Path) -> None:
    """Minimal `docker`/`dockerd` stub satisfying the read-only preflight probes.

    The installer calls (outside the `plan` gate): `command -v docker`,
    `docker version --format ...` (preflight) and `docker info --format
    {{.Swarm.LocalNodeState}}` (swarm_join idempotency). Report a recent engine
    and an INACTIVE swarm so the join is planned (printed), not skipped.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    stub = bin_dir / "docker"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'case "$1" in\n'
        '  version) echo "29.2.1" ;;\n'
        '  info) echo "inactive" ;;\n'
        "  *) exit 0 ;;\n"
        "esac\n"
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    # `dockerd` is probed via `command -v dockerd`; absence is handled with a
    # warn (no --validate), keeping the cpu dry-run path clean. Do NOT provide it.


def _run(env_extra: dict[str, str], tmp_path: Path) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    _docker_stub(bin_dir)
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    # Required inputs so preflight passes and the run reaches the later steps.
    env.setdefault("JOIN_TOKEN", "join-xyz")
    env.update(env_extra)
    return subprocess.run(
        [
            "bash",
            str(WORKER_INSTALLER),
            "--manager-addr",
            "1.2.3.4:2377",
            "--workload",
            "cpu",
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(ROOT),
        timeout=60,
    )


def test_ghcr_login_planned_when_credentials_present(tmp_path: Path) -> None:
    """With GHCR_USER + GHCR_TOKEN set, the login command is planned (printed)."""
    res = _run(
        {"GHCR_USER": "echobt", "GHCR_TOKEN": SECRET_SENTINEL},
        tmp_path,
    )
    combined = res.stdout + res.stderr
    assert res.returncode == 0, combined
    assert LOGIN_STEP_MARKER in combined
    assert LOGIN_CMD_MARKER in combined
    assert PASSWORD_STDIN_MARKER in combined
    # The token value must never be echoed (stdin-only secret).
    assert SECRET_SENTINEL not in combined


def test_ghcr_login_skipped_when_credentials_absent(tmp_path: Path) -> None:
    """Without GHCR creds the step is a non-fatal skip — flow still succeeds."""
    res = _run({"GHCR_USER": "", "GHCR_TOKEN": ""}, tmp_path)
    combined = res.stdout + res.stderr
    assert res.returncode == 0, combined
    assert SKIP_MARKER in combined
    # No login command should be planned when creds are absent.
    assert LOGIN_CMD_MARKER not in combined
