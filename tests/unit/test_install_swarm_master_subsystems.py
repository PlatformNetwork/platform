"""M7 deploy wiring: install-swarm.sh must provision the NEW master subsystems
(validator coordination plane, LLM gateway, HF checkpoint publisher) introduced
by the decentralization mission. Covers VAL-CICD-021 and supports VAL-CICD-022.

`base master proxy` now ALWAYS builds the LLM gateway and fails fast at startup
if the gateway token secret is missing, so the installer MUST provision a
MANDATORY ``gateway_token_secret`` docker secret (mounted at
``/run/secrets/gateway_token_secret``). In ``provider_mode=real`` it must also
provision the DeepSeek + OpenRouter provider keys the gateway injects
server-side. It must render ``gateway.public_base_url`` (the external master
gateway root advertised to validators) so eval runtimes target the gateway and
NOT the ``master.registry_url`` (chain registry) fallback, and carry the
coordination-plane config into the base-master config.

These are BEHAVIORAL tests: they execute the real installer in DEFAULT dry-run
(mutates nothing) with a stub ``docker`` on PATH whose every ``inspect`` misses,
so every resource is *planned* (printed) regardless of what the live host
already has. They respect the imperative-Swarm contract (no compose YAML).
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SWARM_INSTALLER = ROOT / "deploy" / "swarm" / "install-swarm.sh"

# Sentinel secret VALUES that must NEVER appear in plan/log output (dry-run only
# prints the env var NAME via plan_secret_stdin; values would reach stdin only).
GATEWAY_TOKEN_SENTINEL = "gtok-SENTINEL-must-not-leak"
DEEPSEEK_SENTINEL = "dsk-SENTINEL-must-not-leak"
HF_SENTINEL = "hf-SENTINEL-must-not-leak"
CENTRAL_GATEWAY_TOKEN_SENTINEL = "central-gtok-SENTINEL-must-not-leak"

# Deterministic gateway root for the consumer-URL assertions (avoids depending on
# the live default advertise address).
GATEWAY_PUBLIC_BASE_URL = "http://master.example:18080"
GATEWAY_OPENROUTER_ROUTE = f"{GATEWAY_PUBLIC_BASE_URL}/llm/openrouter"

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
    "GATEWAY_TOKEN": GATEWAY_TOKEN_SENTINEL,
    "CENTRAL_GATEWAY_TOKEN": CENTRAL_GATEWAY_TOKEN_SENTINEL,
    "DEEPSEEK_API_KEY": DEEPSEEK_SENTINEL,
}


def _docker_stub(bin_dir: Path) -> None:
    """`docker` stub: recent engine, INACTIVE swarm, every `inspect` MISSES.

    A missed inspect makes the installer *plan* (print) the create, so the
    full plan is exercised even though the live host already has the services.
    """
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
    provider_mode: str | None = None,
    hf_token: str | None = HF_SENTINEL,
    drop_central_gateway_token: bool = False,
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    _docker_stub(bin_dir)
    env = dict(os.environ)
    env.update(REQUIRED_SECRET_ENV)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    env["BROKER_WORKSPACE_DIR"] = str(tmp_path / "broker-ws")
    env["MASTER_CONFIG_PATH"] = str(tmp_path / "master.yaml")
    env["GATEWAY_PUBLIC_BASE_URL"] = GATEWAY_PUBLIC_BASE_URL
    if provider_mode is not None:
        env["GATEWAY_PROVIDER_MODE"] = provider_mode
    if hf_token is not None:
        env["HF_TOKEN"] = hf_token
    else:
        env.pop("HF_TOKEN", None)
    if drop_central_gateway_token:
        env.pop("CENTRAL_GATEWAY_TOKEN", None)
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
    so backslashes are stripped to compare against the unescaped ``source=...,
    target=...`` secret specs.
    """
    needle = f"--name {name} "
    for line in plan_lines:
        if "docker service create" in line and needle in line:
            return line.replace("\\", "")
    raise AssertionError(f"no `docker service create --name {name}` line planned")


def test_mandatory_gateway_token_secret_created_and_mounted_on_proxy(
    tmp_path: Path,
) -> None:
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout

    # The token-signing secret is provisioned (value via stdin, never argv).
    assert "docker secret create base_gateway_token_secret" in out

    # ...and mounted into the proxy at the exact path the gateway reads.
    proxy = _service_block(out.splitlines(), "base-master-proxy")
    assert "source=base_gateway_token_secret,target=gateway_token_secret" in proxy


def test_real_mode_provisions_provider_keys_on_the_gateway(tmp_path: Path) -> None:
    result = _run(tmp_path, provider_mode="real")
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout

    # DeepSeek key created; OpenRouter reuses base_openrouter_api_key.
    assert "docker secret create base_gateway_deepseek_api_key" in out

    proxy = _service_block(out.splitlines(), "base-master-proxy")
    assert "source=base_gateway_deepseek_api_key,target=deepseek_api_key" in proxy
    assert "source=base_openrouter_api_key,target=openrouter_api_key" in proxy


def test_mock_mode_keeps_token_secret_but_omits_provider_keys(tmp_path: Path) -> None:
    result = _run(tmp_path, provider_mode="mock")
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout

    # Token secret is mandatory in every mode.
    assert "docker secret create base_gateway_token_secret" in out
    proxy = _service_block(out.splitlines(), "base-master-proxy")
    assert "source=base_gateway_token_secret,target=gateway_token_secret" in proxy

    # Mock provider needs no provider key: none created/mounted.
    assert "docker secret create base_gateway_deepseek_api_key" not in out
    assert "target=deepseek_api_key" not in proxy
    assert "provider_mode: mock" in out


def test_rendered_master_config_wires_gateway_and_coordination(
    tmp_path: Path,
) -> None:
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout

    # LLM gateway block (architecture sec 5).
    assert "provider_mode: real" in out
    assert "public_base_url:" in out
    assert "token_secret_file: /run/secrets/gateway_token_secret" in out
    assert "deepseek_api_key_file: /run/secrets/deepseek_api_key" in out
    assert "openrouter_api_key_file: /run/secrets/openrouter_api_key" in out

    # public_base_url must NOT be the chain registry fallback.
    assert "public_base_url: https://chain.joinbase.ai" not in out

    # Validator coordination plane (architecture sec 4).
    assert "validator_heartbeat_interval_seconds:" in out
    assert "validator_heartbeat_timeout_seconds:" in out
    assert "validator_health_interval_seconds:" in out
    assert "assignment_lease_seconds:" in out
    assert "orchestration_interval_seconds:" in out


def test_hf_publisher_token_mounted_on_prism_when_present(tmp_path: Path) -> None:
    result = _run(tmp_path, hf_token=HF_SENTINEL)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout

    assert "docker secret create base_hf_token" in out
    prism = _service_block(out.splitlines(), "challenge-prism")
    assert "source=base_hf_token,target=hf_token" in prism


def test_hf_publisher_token_skipped_when_absent(tmp_path: Path) -> None:
    result = _run(tmp_path, hf_token=None)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    out = result.stdout

    # Optional secret: skipped (not created) and not mounted onto prism.
    assert "optional secret base_hf_token skipped" in out
    prism = _service_block(out.splitlines(), "challenge-prism")
    assert "base_hf_token" not in prism


def test_central_gate_token_secret_created(tmp_path: Path) -> None:
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    # Scoped central-gate token secret provisioned (value via stdin, never argv).
    # The trailing ``-`` disambiguates from the ``base_gateway_token_secret`` HMAC
    # secret.
    assert "docker secret create base_gateway_token -" in result.stdout


def test_central_gate_token_required_hard_fails_when_unset(tmp_path: Path) -> None:
    """The central-gate token is REQUIRED: an unset value hard-fails the installer.

    The master gateway is the sole LLM path for the central gates (no direct-key
    fallback), so ``_ensure_secret`` dies when ``CENTRAL_GATEWAY_TOKEN`` is unset.
    """
    result = _run(tmp_path, drop_central_gateway_token=True)
    assert result.returncode != 0, f"stdout={result.stdout!r}"
    assert "required secret env var $CENTRAL_GATEWAY_TOKEN is empty" in result.stderr
    assert "docker secret create base_gateway_token -" not in result.stdout


def test_central_gateway_routes_agent_challenge_consumer(tmp_path: Path) -> None:
    """agent-challenge api+worker get the gateway ROOT URL + scoped token mount.

    The analyzer appends ``/llm/openrouter`` to the base URL itself, so the
    installer renders the gateway ROOT. The scoped token mounts at
    ``/run/secrets/base_gateway_token`` and NO direct OpenRouter key is rendered.
    """
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    lines = result.stdout.splitlines()

    for service in ("challenge-agent-challenge", "challenge-agent-challenge-worker"):
        block = _service_block(lines, service)
        assert f"CHALLENGE_LLM_GATEWAY_BASE_URL={GATEWAY_PUBLIC_BASE_URL}" in block
        token_file = "CHALLENGE_LLM_GATEWAY_TOKEN_FILE=/run/secrets/base_gateway_token"
        assert token_file in block
        assert "source=base_gateway_token,target=base_gateway_token" in block
        # No direct provider key on the challenge service: the gateway is the sole
        # LLM path.
        assert "target=openrouter_api_key" not in block
        assert "CHALLENGE_OPENROUTER_API_KEY_FILE" not in block


def test_central_gateway_routes_prism_consumer(tmp_path: Path) -> None:
    """prism api+worker get the full ``/llm/openrouter`` route + scoped token mount.

    prism uses ``PRISM_LLM_GATEWAY_URL`` directly as the chat base_url, so the
    installer renders the FULL gateway route + ``BASE_GATEWAY_TOKEN_FILE``. The
    scoped token mounts at ``/run/secrets/base_gateway_token``, the LLM-review max
    tokens are raised to 4096, and NO direct OpenRouter key is rendered.
    """
    result = _run(tmp_path)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    lines = result.stdout.splitlines()

    for service in ("challenge-prism", "challenge-prism-worker"):
        block = _service_block(lines, service)
        assert f"PRISM_LLM_GATEWAY_URL={GATEWAY_OPENROUTER_ROUTE}" in block
        assert "BASE_GATEWAY_TOKEN_FILE=/run/secrets/base_gateway_token" in block
        assert "PRISM_LLM_REVIEW_ENABLED=true" in block
        assert "PRISM_LLM_REVIEW_MAX_TOKENS=4096" in block
        assert "source=base_gateway_token,target=base_gateway_token" in block
        # No direct provider key on the challenge service: the gateway is the sole
        # LLM path.
        assert "target=openrouter_api_key" not in block


def test_secret_values_never_leak_in_plan_output(tmp_path: Path) -> None:
    result = _run(tmp_path)
    combined = result.stdout + result.stderr
    assert GATEWAY_TOKEN_SENTINEL not in combined
    assert DEEPSEEK_SENTINEL not in combined
    assert HF_SENTINEL not in combined
    assert CENTRAL_GATEWAY_TOKEN_SENTINEL not in combined
