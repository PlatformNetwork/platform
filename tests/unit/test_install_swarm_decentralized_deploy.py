"""G3 decentralized no-chain deploy support for ``install-swarm.sh``.

Encodes VAL-CODE-DEPLOY-001..005: the installer must (1) honor ``IMAGE_*``
overrides so a dry-run renders the provided ``:sha-*`` images, (2) render the
mock-metagraph validator set + coordination/driver intervals + LLM gateway
provider config into the master config, (3) manager-pin the proxy (no hard
``node.role==worker`` pin) with configurable published ports for the 2-node
no-chain deploy, (4) ship a ``validator.yaml`` template + a documented N-validator
run path, and (5) keep dry-run the DEFAULT, deterministic/idempotent, and
``bash -n`` clean.

These are BEHAVIORAL tests: they run the real installer in DEFAULT dry-run
(mutates nothing) with a stub ``docker`` whose every ``inspect`` misses, so every
resource is *planned* (printed) regardless of host state. No compose YAML.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from base.config.loader import load_settings

ROOT = Path(__file__).resolve().parents[2]
SWARM_INSTALLER = ROOT / "deploy" / "swarm" / "install-swarm.sh"
VALIDATOR_TEMPLATE = ROOT / "deploy" / "swarm" / "validator.yaml"
SWARM_README = ROOT / "deploy" / "swarm" / "README.md"

# Sentinel image tags proving IMAGE_* overrides flow into the dry-run plan.
IMAGE_MASTER_SHA = "ghcr.io/baseintelligence/base-master:sha-DEPLOY01M"
IMAGE_AGENT_CHALLENGE_SHA = "ghcr.io/baseintelligence/agent-challenge:sha-DEPLOY01A"
IMAGE_PRISM_SHA = "ghcr.io/baseintelligence/prism:sha-DEPLOY01P"
IMAGE_PRISM_EVALUATOR_SHA = "ghcr.io/baseintelligence/prism-evaluator:sha-DEPLOY01E"

# Distinctive mock-metagraph validator hotkeys (not in the upload allowlist).
MMG_VAL_HOTKEY_1 = "5ValMMGdeploy0000000000000000000000000000000001"
MMG_VAL_HOTKEY_2 = "5ValMMGdeploy0000000000000000000000000000000002"
MOCK_METAGRAPH_JSON = (
    f'[{{"hotkey":"{MMG_VAL_HOTKEY_1}","validator_permit":true,"stake":1000}},'
    f'{{"hotkey":"{MMG_VAL_HOTKEY_2}","validator_permit":true,"stake":1000}}]'
)

GATEWAY_PUBLIC_BASE_URL = "http://master.example:18080"

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


def _run(
    tmp_path: Path,
    *,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    _docker_stub(bin_dir)
    env = dict(os.environ)
    env.update(REQUIRED_SECRET_ENV)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    env["BROKER_WORKSPACE_DIR"] = str(tmp_path / "broker-ws")
    env["MASTER_CONFIG_PATH"] = str(tmp_path / "master.yaml")
    env["GATEWAY_PUBLIC_BASE_URL"] = GATEWAY_PUBLIC_BASE_URL
    if extra_env:
        env.update(extra_env)
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
    """Return the single planned `docker service create --name NAME ` line.

    Plan lines are shell-quoted via ``printf '%q'`` (commas escaped as ``\\,``),
    so backslashes are stripped to compare against unescaped specs.
    """
    needle = f"--name {name} "
    for line in plan_lines:
        if "docker service create" in line and needle in line:
            return line.replace("\\", "")
    raise AssertionError(f"no `docker service create --name {name}` line planned")


# ---------------------------------------------------------------------------
# VAL-CODE-DEPLOY-001: IMAGE_* overrides flow into the dry-run plan
# ---------------------------------------------------------------------------


def test_image_overrides_flow_into_dry_run_plan(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        extra_env={
            "IMAGE_MASTER": IMAGE_MASTER_SHA,
            "IMAGE_AGENT_CHALLENGE": IMAGE_AGENT_CHALLENGE_SHA,
            "IMAGE_PRISM": IMAGE_PRISM_SHA,
            "IMAGE_PRISM_EVALUATOR": IMAGE_PRISM_EVALUATOR_SHA,
        },
    )
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    lines = result.stdout.splitlines()

    # base-master image used by BOTH the broker + proxy services.
    for service in ("base-docker-broker", "base-master-proxy"):
        block = _service_block(lines, service)
        assert IMAGE_MASTER_SHA in block

    # agent-challenge image on api + worker.
    for service in ("challenge-agent-challenge", "challenge-agent-challenge-worker"):
        assert IMAGE_AGENT_CHALLENGE_SHA in _service_block(lines, service)

    # prism image on api + worker; the evaluator image is the eval job image.
    for service in ("challenge-prism", "challenge-prism-worker"):
        block = _service_block(lines, service)
        assert IMAGE_PRISM_SHA in block
        assert f"PRISM_BASE_EVAL_IMAGE={IMAGE_PRISM_EVALUATOR_SHA}" in block


# ---------------------------------------------------------------------------
# VAL-CODE-DEPLOY-002: mock-metagraph + coordination + gateway rendered
# ---------------------------------------------------------------------------


def test_mock_metagraph_validator_set_rendered_into_master_config(
    tmp_path: Path,
) -> None:
    result = _run(tmp_path, extra_env={"MOCK_METAGRAPH": MOCK_METAGRAPH_JSON})
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout

    # network.mock_metagraph carries both permitted validator hotkeys.
    assert "mock_metagraph:" in out
    assert MMG_VAL_HOTKEY_1 in out
    assert MMG_VAL_HOTKEY_2 in out
    assert "validator_permit" in out


def test_default_mock_metagraph_is_empty_and_off(tmp_path: Path) -> None:
    # Unset MOCK_METAGRAPH => the seam is rendered OFF (empty list), so the
    # live-metagraph path is unchanged (production-safe default).
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    assert "mock_metagraph: []" in result.stdout


def test_coordination_intervals_and_gateway_config_rendered(tmp_path: Path) -> None:
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout

    # Coordination / driver intervals (architecture sec 4).
    assert "validator_heartbeat_interval_seconds:" in out
    assert "validator_heartbeat_timeout_seconds:" in out
    assert "validator_health_interval_seconds:" in out
    assert "assignment_lease_seconds:" in out
    assert "orchestration_interval_seconds:" in out

    # LLM gateway provider config (architecture sec 5).
    assert "provider_mode: real" in out
    assert "public_base_url:" in out
    assert "token_secret_file: /run/secrets/gateway_token_secret" in out
    assert "deepseek_api_key_file: /run/secrets/deepseek_api_key" in out
    assert "openrouter_api_key_file: /run/secrets/openrouter_api_key" in out


# ---------------------------------------------------------------------------
# VAL-CODE-DEPLOY-003: manager-pinned proxy + configurable ports
# ---------------------------------------------------------------------------


def test_proxy_is_manager_pinned_with_no_worker_pin(tmp_path: Path) -> None:
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    lines = result.stdout.splitlines()

    proxy = _service_block(lines, "base-master-proxy")
    assert "--constraint node.role==manager" in proxy
    # The old hard worker pin must be gone (no-chain deploy: no chain to reach).
    assert "node.role==worker" not in proxy

    # The broker stays manager-pinned too (control plane co-located on manager).
    broker = _service_block(lines, "base-docker-broker")
    assert "--constraint node.role==manager" in broker


def test_proxy_constraint_is_configurable_and_droppable(tmp_path: Path) -> None:
    # Empty MASTER_PROXY_CONSTRAINT drops the pin entirely.
    dropped = _run(tmp_path, extra_env={"MASTER_PROXY_CONSTRAINT": ""})
    assert dropped.returncode == 0, f"stderr={dropped.stderr!r}"
    proxy = _service_block(dropped.stdout.splitlines(), "base-master-proxy")
    assert "node.role==" not in proxy

    # A custom constraint is honored verbatim.
    custom = _run(
        tmp_path,
        extra_env={"MASTER_PROXY_CONSTRAINT": "node.labels.base.control==true"},
    )
    assert custom.returncode == 0, f"stderr={custom.stderr!r}"
    proxy = _service_block(custom.stdout.splitlines(), "base-master-proxy")
    assert "--constraint node.labels.base.control==true" in proxy


def test_published_ports_are_configurable(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        extra_env={"MASTER_PROXY_PORT": "28080", "MASTER_BROKER_PORT": "28082"},
    )
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout
    lines = out.splitlines()

    proxy = _service_block(lines, "base-master-proxy")
    assert "published=28080,target=28080,mode=host" in proxy

    broker = _service_block(lines, "base-docker-broker")
    assert "published=28082,target=28082,mode=host" in broker

    # Ports also flow into the rendered master config (proxy_port + broker_url).
    assert "proxy_port: 28080" in out
    assert "broker_port: 28082" in out
    assert "broker_url: http://base-docker-broker:28082" in out


# ---------------------------------------------------------------------------
# VAL-CODE-DEPLOY-004: validator.yaml template + N-validator run path
# ---------------------------------------------------------------------------


def test_validator_template_exists_and_loads_with_agent_block() -> None:
    assert VALIDATOR_TEMPLATE.is_file()
    settings = load_settings(VALIDATOR_TEMPLATE)

    agent = settings.validator.agent
    assert agent.master_url
    assert agent.gateway_url
    assert agent.broker_url
    assert agent.capabilities  # cpu (and gpu for the GPU validator)
    # A distinct hotkey wallet identity the agent signs coordination calls with.
    assert settings.network.wallet_name
    assert settings.network.wallet_path


def test_validator_template_documents_capabilities_and_own_broker() -> None:
    text = VALIDATOR_TEMPLATE.read_text(encoding="utf-8")
    assert "base validator agent --config" in text
    # capabilities cpu|gpu guidance present.
    assert 'capabilities: ["cpu"]' in text
    assert "gpu" in text
    # the validator's OWN broker (not the master's).
    assert "broker_url" in text


def test_readme_documents_n_validator_run_path() -> None:
    readme = SWARM_README.read_text(encoding="utf-8")
    assert "base validator agent --config" in readme
    assert "validator.yaml" in readme
    # Ties the validator hotkeys to the master's no-chain mock metagraph.
    assert "mock_metagraph" in readme
    assert "MOCK_METAGRAPH" in readme
    assert "capabilities" in readme


# ---------------------------------------------------------------------------
# VAL-VDIR-DEPLOY-001: self-declared validator identity (display_name/logo_url)
# rendered per MOCK_METAGRAPH entry + carried by the validator.yaml template, so
# the live test validators show a real subnet identity + logo on the no-chain
# deploy. Dry-run only; existing guard tests stay green; bash -n clean.
# ---------------------------------------------------------------------------

# Distinctive per-validator self-declared identities (not collidable with any
# other token in the plan output).
MMG_DISPLAY_NAME_1 = "Acme Subnet Validator"
MMG_LOGO_URL_1 = "https://logos.example/acme-validator.png"
MMG_DISPLAY_NAME_2 = "Beta Subnet Validator"
MMG_LOGO_URL_2 = "https://logos.example/beta-validator.png"
MOCK_METAGRAPH_IDENTITY_JSON = (
    f'[{{"hotkey":"{MMG_VAL_HOTKEY_1}","validator_permit":true,"stake":1000,'
    f'"display_name":"{MMG_DISPLAY_NAME_1}","logo_url":"{MMG_LOGO_URL_1}"}},'
    f'{{"hotkey":"{MMG_VAL_HOTKEY_2}","validator_permit":true,"stake":1000,'
    f'"display_name":"{MMG_DISPLAY_NAME_2}","logo_url":"{MMG_LOGO_URL_2}"}}]'
)


def test_mock_metagraph_identity_fields_rendered_into_master_config(
    tmp_path: Path,
) -> None:
    # Each MOCK_METAGRAPH entry's optional self-declared identity rides through
    # the verbatim render into network.mock_metagraph, so the dry-run plan carries
    # per-validator display_name + logo_url (the no-chain identity fallback).
    result = _run(tmp_path, extra_env={"MOCK_METAGRAPH": MOCK_METAGRAPH_IDENTITY_JSON})
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout

    assert "mock_metagraph:" in out
    assert "display_name" in out
    assert "logo_url" in out
    # Both per-validator identities are present, tied to their hotkeys.
    assert MMG_VAL_HOTKEY_1 in out
    assert MMG_DISPLAY_NAME_1 in out
    assert MMG_LOGO_URL_1 in out
    assert MMG_VAL_HOTKEY_2 in out
    assert MMG_DISPLAY_NAME_2 in out
    assert MMG_LOGO_URL_2 in out


def test_mock_metagraph_without_identity_omits_fields(tmp_path: Path) -> None:
    # Identity is OPTIONAL: a MOCK_METAGRAPH with no display_name/logo_url renders
    # neither key (identicon fallback), so the seam stays minimal when unset.
    result = _run(tmp_path, extra_env={"MOCK_METAGRAPH": MOCK_METAGRAPH_JSON})
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    config_lines = [
        line for line in result.stdout.splitlines() if "mock_metagraph:" in line
    ]
    assert config_lines, "mock_metagraph not rendered"
    rendered = config_lines[0]
    assert "display_name" not in rendered
    assert "logo_url" not in rendered


def test_validator_template_carries_self_declared_identity() -> None:
    # The validator.yaml template documents + sets the validator.agent
    # self-declared identity so a copied-per-validator config surfaces a real
    # name + logo on the no-chain deploy.
    text = VALIDATOR_TEMPLATE.read_text(encoding="utf-8")
    assert "display_name:" in text
    assert "logo_url:" in text

    settings = load_settings(VALIDATOR_TEMPLATE)
    agent = settings.validator.agent
    assert agent.display_name
    assert agent.logo_url


# ---------------------------------------------------------------------------
# VAL-CODE-DEPLOY-005: dry-run default, deterministic/idempotent, bash -n clean
# ---------------------------------------------------------------------------


def test_installer_is_bash_n_clean() -> None:
    proc = subprocess.run(
        ["bash", "-n", str(SWARM_INSTALLER)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"bash -n failed: {proc.stderr!r}"


def test_dry_run_is_the_default_and_mutates_nothing(tmp_path: Path) -> None:
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    # Default mode announces dry-run and only PRINTS planned commands (prefixed
    # by `  + `); the docker stub would exit 1 on any mutating subcommand, so a
    # clean exit proves nothing mutating was executed.
    assert "DRY-RUN (default)" in result.stdout
    assert "  + docker service create" in result.stdout


def test_dry_run_plan_is_deterministic(tmp_path: Path) -> None:
    # Idempotency proxy: with fixed inputs the planned output is byte-identical
    # across runs (no nondeterministic ordering / churn in the plan).
    env = {"MOCK_METAGRAPH": MOCK_METAGRAPH_JSON}
    first = _run(tmp_path, extra_env=env)
    second = _run(tmp_path, extra_env=env)
    assert first.returncode == 0 and second.returncode == 0
    assert first.stdout == second.stdout
