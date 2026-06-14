from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from platform_network.config.loader import load_settings
from platform_network.config.settings import MasterSettings, ValidatorSettings
from platform_network.security.tokens import generate_token, hash_token, verify_token
from platform_network.template_engine import (
    ChallengeTemplateContext,
    render_challenge_template,
)


def test_registry_url_defaults_and_examples_use_chain_endpoint() -> None:
    root = Path(__file__).resolve().parents[2]
    expected = "https://chain.platform.network"

    assert MasterSettings().registry_url == expected
    assert ValidatorSettings().registry_url == expected

    master_example = yaml.safe_load(
        (root / "config" / "master.example.yaml").read_text(encoding="utf-8")
    )
    validator_example = yaml.safe_load(
        (root / "config" / "validator.example.yaml").read_text(encoding="utf-8")
    )

    assert master_example["master"]["registry_url"] == expected
    assert validator_example["validator"]["registry_url"] == expected
    assert ValidatorSettings().weights_url is None
    assert ValidatorSettings().resolved_weights_url == expected
    assert (
        ValidatorSettings(registry_url="https://master.example").resolved_weights_url
        == "https://master.example"
    )
    assert (
        ValidatorSettings(
            registry_url="https://registry.example",
            weights_url="https://weights.example",
        ).resolved_weights_url
        == "https://weights.example"
    )
    assert ValidatorSettings().weights_interval_seconds == 360
    assert ValidatorSettings().weights_timeout_seconds == 15.0
    assert ValidatorSettings().weights_retries == 3
    assert ValidatorSettings().weights_freshness_seconds == 720
    assert validator_example["validator"]["weights_url"] is None
    assert validator_example["validator"]["weights_interval_seconds"] == 360
    assert validator_example["validator"]["weights_timeout_seconds"] == 15.0
    assert validator_example["validator"]["weights_retries"] == 3
    assert validator_example["validator"]["weights_freshness_seconds"] == 720


def test_registry_facing_defaults_docs_and_examples_do_not_use_rpc_endpoint() -> None:
    root = Path(__file__).resolve().parents[2]
    registry_facing_files = [
        root / "src" / "platform_network" / "config" / "settings.py",
        root / "config" / "master.example.yaml",
        root / "config" / "validator.example.yaml",
        root / "docs" / "validator.md",
        root / "docs" / "validator" / "README.md",
        root / "deploy" / "helm" / "platform" / "values.yaml",
        root / "deploy" / "helm" / "platform" / "values.production.example.yaml",
    ]

    retired_rpc_host = ".".join(["rpc", "platform", "network"])
    retired_rpc_base_url = "https://" + retired_rpc_host
    retired_registry_url_path = retired_rpc_host + "/v1/registry"

    for registry_facing_file in registry_facing_files:
        content = registry_facing_file.read_text(encoding="utf-8")
        assert retired_rpc_base_url not in content
        assert retired_registry_url_path not in content


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
                "    verify_tls: true",
                "    timeout_seconds: 12",
            ]
        ),
        encoding="utf-8",
    )
    server = load_settings(config).gpu_servers[0]
    assert server.id == "gpu-a"
    assert server.base_url == "https://gpu-a.internal"
    assert server.token == "secret"
    assert server.verify_tls is True
    assert server.timeout_seconds == 12


def test_load_settings_kubernetes_targets(tmp_path: Path) -> None:
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text("apiVersion: v1\n", encoding="utf-8")
    config = tmp_path / "config.yaml"
    config.write_text(
        "\n".join(
            [
                "kubernetes:",
                f"  target_state_file: {tmp_path / 'targets.json'}",
                "kubernetes_targets:",
                "  - id: gpu-a",
                "    mode: direct",
                "    api_url: https://k8s-gpu-a",
                f"    kubeconfig_file: {kubeconfig}",
                "    namespace: platform-gpu",
                "    verify_tls: true",
                "    gpu_count: 4",
                "    labels:",
                "      region: eu",
            ]
        ),
        encoding="utf-8",
    )

    settings = load_settings(config)
    target = settings.kubernetes_targets[0]
    assert settings.kubernetes.target_state_file == str(tmp_path / "targets.json")
    assert target.id == "gpu-a"
    assert target.kubeconfig_file == str(kubeconfig)
    assert target.namespace == "platform-gpu"
    assert target.verify_tls is True
    assert target.gpu_count == 4
    assert target.labels == {"region": "eu"}


def test_load_settings_parses_complex_env(monkeypatch) -> None:
    monkeypatch.setenv(
        "PLATFORM_DOCKER__BROKER_ALLOWED_IMAGES",
        '["ghcr.io/platformnetwork/"]',
    )

    assert load_settings().docker.broker_allowed_images == ["ghcr.io/platformnetwork/"]


def test_load_settings_accepts_docker_runtime_backends(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        "\n".join(
            [
                "runtime:",
                "  backend: docker",
                "kubernetes:",
                "  broker_backend: docker",
            ]
        ),
        encoding="utf-8",
    )

    settings = load_settings(config)
    assert settings.runtime.backend == "docker"
    assert settings.kubernetes.broker_backend == "docker"


def test_load_settings_rejects_unknown_runtime_backends(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        "\n".join(
            [
                "runtime:",
                "  backend: podman",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="kubernetes"):
        load_settings(config)


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


def test_production_settings_require_postgres_safe_prefixes_and_tls(
    tmp_path: Path,
) -> None:
    config = tmp_path / "prod.yaml"
    config.write_text(
        "\n".join(
            [
                "environment: production",
                "database:",
                "  url: postgresql+asyncpg://user:pass@postgres.platform/platform",
                "docker:",
                "  broker_allowed_images:",
                "    - ghcr.io/platformnetwork/",
                "gpu_servers:",
                "  - id: gpu-a",
                "    base_url: https://gpu-a.internal",
                "    verify_tls: true",
            ]
        ),
        encoding="utf-8",
    )

    settings = load_settings(config)

    assert settings.environment == "production"
    assert settings.database.url.startswith("postgresql+asyncpg://")


def test_production_settings_reject_sqlite_broad_prefixes_and_insecure_tls(
    tmp_path: Path,
) -> None:
    config = tmp_path / "bad-prod.yaml"
    config.write_text(
        "\n".join(
            [
                "environment: production",
                "database:",
                "  url: sqlite+aiosqlite:////tmp/platform.sqlite3",
                "docker:",
                "  broker_allowed_images:",
                "    - platformnetwork/",
                "kubernetes_targets:",
                "  - id: k8s-a",
                "    mode: agent",
                "    agent_url: https://agent-a",
                "    verify_tls: false",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="PostgreSQL|external PostgreSQL"):
        load_settings(config)

    config.write_text(
        "\n".join(
            [
                "environment: production",
                "database:",
                "  url: postgresql+asyncpg://user:pass@postgres.platform/platform",
                "docker:",
                "  broker_allowed_images:",
                "    - platformnetwork/",
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="too broad"):
        load_settings(config)

    config.write_text(
        "\n".join(
            [
                "environment: production",
                "database:",
                "  url: postgresql+asyncpg://user:pass@postgres.platform/platform",
                "docker:",
                "  broker_allowed_images:",
                "    - ghcr.io/platformnetwork/",
                "gpu_servers:",
                "  - id: gpu-a",
                "    base_url: https://gpu-a.internal",
                "    verify_tls: false",
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="verify_tls=true"):
        load_settings(config)


def test_platform_docs_define_kubernetes_broker_gpu_contract() -> None:
    root = Path(__file__).resolve().parents[2]
    architecture_doc = (root / "docs" / "architecture.md").read_text(encoding="utf-8")
    security_doc = (root / "docs" / "security.md").read_text(encoding="utf-8")
    master_example = (root / "config" / "master.example.yaml").read_text(
        encoding="utf-8"
    )
    combined = f"{architecture_doc}\n{security_doc}\n{master_example}"

    for expected in (
        "Broker clients request GPUs with `limits.gpu_count`",
        "`gpu_count=None` or an omitted field means CPU-only",
        "Platform owns `gpu_resource_name`",
        "resources.limits['nvidia.com/gpu']",
        "Device IDs are metadata for observability",
        "not Kubernetes placement semantics",
        "Network isolation depends on CNI support",
        "clients such as PRISM do not set this name",
    ):
        assert expected in combined

    assert "gpu_resource_name: nvidia.com/gpu" in master_example
