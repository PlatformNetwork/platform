"""Guard: every ``*_file`` path the installer renders into the master config must
resolve to a Swarm secret the SAME service actually mounts.

A Swarm ``--secret source=X,target=Y`` mounts the secret at ``/run/secrets/Y``
(no nested directory). The rendered ``security.admin_token_file`` previously read
``/run/secrets/base/admin_token`` (the ``SECRET_MOUNT_DIR`` "base/" subdir) while
the proxy AND broker mount the admin secret at ``target=admin_token`` ->
``/run/secrets/admin_token``. That mismatch made the master admin auth fail
closed (``GET /v1/validators`` -> 401 even with the correct ``X-Admin-Token``),
discovered during the live coexistence deploy.

These are BEHAVIORAL tests: they execute the real installer in DEFAULT dry-run
(mutates nothing) with a stub ``docker`` on PATH whose every ``inspect`` misses,
so every resource is *planned* (printed). They then parse BOTH the rendered
master config block and the planned ``docker service create`` secret specs and
assert each ``security``/``gateway``/``database`` ``*_file`` path equals
``/run/secrets/<target>`` for a target mounted on the service that reads it
(security/database -> the shared config object both proxy AND broker load;
gateway -> the proxy, which alone builds the LLM gateway).
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import yaml

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


def _run(tmp_path: Path) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    _docker_stub(bin_dir)
    env = dict(os.environ)
    env.update(REQUIRED_SECRET_ENV)
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


def _rendered_master_config(out: str) -> dict:
    """Parse the master config block the installer prints in dry-run.

    The dry-run renders the config via ``sed 's/^/      /'`` (a fixed 6-space
    prefix), so every config line begins with 6 spaces; strip it and YAML-parse.
    """
    lines = out.splitlines()
    start = None
    for i, line in enumerate(lines):
        if "master config that WOULD be written to" in line:
            start = i + 1
            break
    assert start is not None, "no rendered master config marker in plan output"
    body: list[str] = []
    for line in lines[start:]:
        if line.startswith("      "):
            body.append(line[6:])
        else:
            break
    assert body, "rendered master config block was empty"
    return yaml.safe_load("\n".join(body))


def _service_block(plan_lines: list[str], name: str) -> str:
    """Return the single planned `docker service create --name NAME ` line.

    Plan lines are shell-quoted via ``printf '%q'`` (commas escaped as ``\\,``),
    so backslashes are stripped to compare against the unescaped ``source=...,
    target=...`` secret specs.
    """
    needle = f"--name {name} "
    for line in plan_lines:
        if "docker service create" in line and needle in line:
            return line.replace("\\", "")
    raise AssertionError(f"no `docker service create --name {name}` line planned")


def _secret_targets(service_block: str) -> set[str]:
    """Targets from the ``--secret source=...,target=...`` specs of one service.

    Anchored on ``--secret`` so ``--mount``/``--config``/``--publish`` specs that
    also carry ``target=`` are ignored.
    """
    return {
        m.group(1)
        for m in re.finditer(r"--secret\s+source=[^,\s]+,target=(\S+)", service_block)
    }


def _file_paths_by_section(cfg: dict) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for section in ("security", "gateway", "database"):
        sec = cfg.get(section) or {}
        out[section] = {
            k: v for k, v in sec.items() if isinstance(k, str) and k.endswith("_file")
        }
    return out


def test_every_rendered_file_path_resolves_to_a_mounted_secret_target(
    tmp_path: Path,
) -> None:
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout

    cfg = _rendered_master_config(out)
    lines = out.splitlines()
    proxy_targets = _secret_targets(_service_block(lines, "base-master-proxy"))
    broker_targets = _secret_targets(_service_block(lines, "base-docker-broker"))
    both_targets = proxy_targets & broker_targets

    by_section = _file_paths_by_section(cfg)
    # Regression anchor: the security admin token file must be present + checked.
    assert "admin_token_file" in by_section["security"]

    for section, files in by_section.items():
        for key, path in files.items():
            match = re.fullmatch(r"/run/secrets/([^/]+)", path)
            assert match is not None, (
                f"{section}.{key}={path!r} is not a flat /run/secrets/<target> "
                "path; a Swarm --secret target=Y mounts at /run/secrets/Y with NO "
                "nested directory (this is exactly the /run/secrets/base/... bug)"
            )
            target = match.group(1)
            if section == "gateway":
                # The LLM gateway is built by the PROXY only; the broker never
                # reads these files, so they are mounted on the proxy alone.
                assert target in proxy_targets, (
                    f"{section}.{key} target {target!r} is not a --secret mounted "
                    f"on base-master-proxy (mounted: {sorted(proxy_targets)})"
                )
            else:
                # security/database files live in the shared master config object
                # BOTH master services load, so the secret must be on BOTH.
                assert target in both_targets, (
                    f"{section}.{key} target {target!r} is not a --secret mounted "
                    f"on BOTH proxy and broker (both: {sorted(both_targets)})"
                )


def test_admin_token_file_matches_swarm_secret_mount(tmp_path: Path) -> None:
    """``security.admin_token_file`` must equal the admin secret's mount target.

    The proxy AND broker mount ``--secret source=base_admin_token,target=admin_token``
    -> ``/run/secrets/admin_token``. The rendered config MUST read that exact path,
    never the old ``/run/secrets/base/admin_token`` (which fails the master admin
    auth closed -> 401).
    """
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout

    cfg = _rendered_master_config(out)
    admin_path = cfg["security"]["admin_token_file"]
    assert admin_path == "/run/secrets/admin_token"
    assert admin_path != "/run/secrets/base/admin_token"

    lines = out.splitlines()
    proxy_targets = _secret_targets(_service_block(lines, "base-master-proxy"))
    broker_targets = _secret_targets(_service_block(lines, "base-docker-broker"))
    assert "admin_token" in proxy_targets
    assert "admin_token" in broker_targets
