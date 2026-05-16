from __future__ import annotations

from pathlib import Path

from platform_network.config.loader import load_settings
from platform_network.security.tokens import generate_token, hash_token, verify_token
from platform_network.template_engine import (
    ChallengeTemplateContext,
    render_challenge_template,
)


def test_token_hash_verify() -> None:
    token = generate_token()
    assert verify_token(token, hash_token(token))
    assert not verify_token("wrong", hash_token(token))


def test_load_settings_yaml(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("network:\n  netuid: 42\n", encoding="utf-8")
    assert load_settings(config).network.netuid == 42


def test_load_settings_gpu_servers(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        "\n".join(
            [
                "gpu_servers:",
                "  - id: gpu-a",
                "    base_url: https://gpu-a.internal",
                "    token: secret",
                "    enabled: true",
                "    verify_tls: false",
                "    timeout_seconds: 12",
            ]
        ),
        encoding="utf-8",
    )
    server = load_settings(config).gpu_servers[0]
    assert server.id == "gpu-a"
    assert server.base_url == "https://gpu-a.internal"
    assert server.token == "secret"
    assert server.verify_tls is False
    assert server.timeout_seconds == 12


def test_load_settings_parses_complex_env(monkeypatch) -> None:
    monkeypatch.setenv(
        "PLATFORM_DOCKER__BROKER_ALLOWED_IMAGES",
        '["platformnetwork/","ghcr.io/platformnetwork/"]',
    )

    assert load_settings().docker.broker_allowed_images == [
        "platformnetwork/",
        "ghcr.io/platformnetwork/",
    ]


def test_render_challenge_template(tmp_path: Path) -> None:
    out = tmp_path / "challenge"
    files = render_challenge_template(
        out, ChallengeTemplateContext.from_slug("demo-challenge")
    )
    assert Path("pyproject.toml") in files
    assert Path("Dockerfile") in files
    assert Path("src/demo_challenge/sdk/executors/docker.py") in files
    assert (out / "src" / "demo_challenge" / "app.py").exists()
    assert (out / "src" / "demo_challenge" / "sdk" / "executors" / "docker.py").exists()
    assert "docker-cli" in (out / "Dockerfile").read_text(encoding="utf-8")
