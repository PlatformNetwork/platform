from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from platform_network.config.settings import (
    KubernetesSettings,
    RuntimeSettings,
    Settings,
)

ROOT = Path(__file__).resolve().parents[2]


def test_compose_deployment_files_are_removed_but_image_build_assets_remain() -> None:
    docker_dir = ROOT / "docker"

    assert not list(docker_dir.glob("compose*.yml"))
    assert not (docker_dir / "compose.yml").exists()
    assert not (docker_dir / "compose.dev.yml").exists()
    assert not (docker_dir / "compose.watchtower.yml").exists()

    assert (docker_dir / "Dockerfile.master").is_file()
    assert (docker_dir / "Dockerfile.validator").is_file()
    assert (ROOT / "deploy" / "helm" / "platform" / "Chart.yaml").is_file()


def test_platform_dockerfiles_run_as_non_root_user() -> None:
    for dockerfile in (
        ROOT / "docker" / "Dockerfile.master",
        ROOT / "docker" / "Dockerfile.validator",
    ):
        content = dockerfile.read_text(encoding="utf-8")

        assert "--uid 1000" in content
        assert "--gid 1000" in content
        assert "chown -R 1000:1000" in content
        assert "USER 1000:1000" in content


def test_first_party_defaults_are_docker_swarm() -> None:
    settings = Settings()
    master_example = yaml.safe_load(
        (ROOT / "config" / "master.example.yaml").read_text(encoding="utf-8")
    )
    validator_example = yaml.safe_load(
        (ROOT / "config" / "validator.example.yaml").read_text(encoding="utf-8")
    )

    assert settings.runtime.backend == "docker"
    assert settings.kubernetes.broker_backend == "docker"
    assert settings.database.url.startswith("postgresql+asyncpg://")
    assert settings.docker.broker_allowed_images == ["ghcr.io/platformnetwork/"]

    for example in (master_example, validator_example):
        assert example["runtime"]["backend"] == "docker"
        assert example["kubernetes"]["broker_backend"] == "docker"
        assert example["database"]["url"].startswith("postgresql+asyncpg://")
        assert example["docker"]["broker_allowed_images"] == [
            "ghcr.io/platformnetwork/"
        ]


def test_backend_accepts_only_kubernetes_or_docker() -> None:
    assert RuntimeSettings().backend == "docker"
    assert RuntimeSettings(backend="kubernetes").backend == "kubernetes"
    assert RuntimeSettings(backend="docker").backend == "docker"

    assert KubernetesSettings().broker_backend == "docker"
    assert KubernetesSettings(broker_backend="kubernetes").broker_backend == (
        "kubernetes"
    )
    assert KubernetesSettings(broker_backend="docker").broker_backend == "docker"

    with pytest.raises(ValidationError):
        RuntimeSettings.model_validate({"backend": "foo"})
    with pytest.raises(ValidationError):
        KubernetesSettings.model_validate({"broker_backend": "foo"})


def test_first_party_docs_and_ci_do_not_advertise_compose_or_watchtower() -> None:
    checked_paths = [
        ROOT / "README.md",
        ROOT / "docs" / "architecture.md",
        ROOT / "docs" / "security.md",
        ROOT / ".github" / "workflows" / "ci.yml",
    ]
    forbidden = [
        "docker compose",
        "compose.yml",
        "compose.dev.yml",
        "compose.watchtower.yml",
        "compose-validation",
        "watchtower",
        "com.centurylinklabs.watchtower.enable",
    ]

    for path in checked_paths:
        content = path.read_text(encoding="utf-8").lower()
        for token in forbidden:
            assert token not in content, f"{token!r} found in {path}"
