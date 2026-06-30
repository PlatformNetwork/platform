"""G4 base-supervisor install/enable + auto-update config in ``install-swarm.sh``.

Encodes VAL-CODE-UPD-002: the installer must (1) render the ``supervisor:`` block
(registry + docker-config digest-auth + self-update state) into the master config,
(2) provide the base-supervisor.service install/enable path behind
``--install-supervisor`` (rendered, not hand-waved), and (3) document the
mandatory Watchtower decommission ordering.

BEHAVIORAL tests: run the real installer in DEFAULT dry-run (mutates nothing) with
a stub ``docker`` whose every ``inspect`` misses, so resources are PLANNED. No
compose YAML.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SWARM_INSTALLER = ROOT / "deploy" / "swarm" / "install-swarm.sh"
SUPERVISOR_UNIT = ROOT / "deploy" / "swarm" / "base-supervisor.service"
SWARM_README = ROOT / "deploy" / "swarm" / "README.md"

MANIFEST_URL = "https://raw.example/base/release/supervisor-manifest.json"

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
    tmp_path: Path,
    *,
    install_supervisor: bool = False,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    _docker_stub(bin_dir)
    env = dict(os.environ)
    env.update(REQUIRED_SECRET_ENV)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    env["BROKER_WORKSPACE_DIR"] = str(tmp_path / "broker-ws")
    env["MASTER_CONFIG_PATH"] = str(tmp_path / "master.yaml")
    if extra_env:
        env.update(extra_env)
    argv = [
        "bash",
        str(SWARM_INSTALLER),
        "--backup-dir",
        str(tmp_path / "missing"),
        "--greenfield",
        "--static-challenges",
    ]
    if install_supervisor:
        argv.append("--install-supervisor")
    return subprocess.run(
        argv, env=env, capture_output=True, text=True, timeout=120, check=False
    )


# ---------------------------------------------------------------------------
# Rendered supervisor config block (registry digest-auth + self-update state)
# ---------------------------------------------------------------------------


def test_supervisor_config_block_rendered_into_master_config(tmp_path: Path) -> None:
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout

    assert "supervisor:" in out
    assert "registry: ghcr.io" in out
    # Private-digest auth points at the manager's docker config.json.
    assert "registry_docker_config_path: /root/.docker/config.json" in out


def test_self_update_disabled_by_default_in_rendered_config(tmp_path: Path) -> None:
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout
    # No manifest URL => explicitly DISABLED in the config (not inert-enabled).
    assert "self_update_enabled: false" in out


def test_self_update_enabled_when_manifest_url_set(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        extra_env={"SUPERVISOR_SELF_UPDATE_MANIFEST_URL": MANIFEST_URL},
    )
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout
    assert "self_update_enabled: true" in out
    assert f"self_update_manifest_url: {MANIFEST_URL}" in out


# ---------------------------------------------------------------------------
# base-supervisor.service install/enable path (rendered, not hand-waved)
# ---------------------------------------------------------------------------


def test_supervisor_unit_template_exists_and_runs_supervisor() -> None:
    text = SUPERVISOR_UNIT.read_text(encoding="utf-8")
    assert "master supervisor" in text
    assert "Restart=always" in text


def test_install_supervisor_plans_unit_install_and_enable(tmp_path: Path) -> None:
    result = _run(tmp_path, install_supervisor=True)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout

    # The unit is installed to /etc/systemd/system and the service enabled+started.
    assert (
        "+ install -m 0644 " in out
        and "base-supervisor.service /etc/systemd/system/base-supervisor.service" in out
    )
    assert "+ systemctl daemon-reload" in out
    assert "+ systemctl enable --now base-supervisor.service" in out


def test_default_prints_install_instructions_without_executing(tmp_path: Path) -> None:
    result = _run(tmp_path, install_supervisor=False)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout
    # Without the flag, the enable command is an INSTRUCTION (no `  + ` plan line).
    assert "--install-supervisor NOT set" in out
    assert "+ systemctl enable --now base-supervisor.service" not in out
    assert "systemctl enable --now base-supervisor.service" in out


# ---------------------------------------------------------------------------
# Watchtower decommission ordering documented
# ---------------------------------------------------------------------------


def test_watchtower_decommission_ordering_printed(tmp_path: Path) -> None:
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout

    assert "Watchtower decommission ordering" in out
    # Stop Watchtower FIRST, then enable the supervisor (no racing updaters).
    assert "docker service rm platform-watchtower" in out
    assert "REPLACES Watchtower" in out


def test_readme_documents_watchtower_decommission_ordering() -> None:
    readme = SWARM_README.read_text(encoding="utf-8")
    assert "Watchtower decommission ordering" in readme
    assert "REPLACES Watchtower" in readme
    # Reverse (rollback) ordering is documented too.
    assert "Rollback ordering" in readme


def test_installer_is_bash_n_clean() -> None:
    proc = subprocess.run(
        ["bash", "-n", str(SWARM_INSTALLER)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"bash -n failed: {proc.stderr!r}"
