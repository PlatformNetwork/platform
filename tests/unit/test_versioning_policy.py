from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
VERSION = "3.0.0"
GIT_RELEASE_TAG = "v3.0.0"
PRODUCTION_DIGEST = "sha256:" + "1" * 64


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_platform_release_version_sources_are_3_0_0() -> None:
    pyproject = _pyproject()
    chart = yaml.safe_load(
        (ROOT / "deploy" / "helm" / "platform" / "Chart.yaml").read_text(
            encoding="utf-8"
        )
    )
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")

    assert pyproject["project"]["version"] == VERSION
    assert chart["version"] == VERSION
    assert chart["appVersion"] == VERSION
    assert 'name = "platform-network"\nversion = "3.0.0"' in lock


def test_production_values_start_at_platform_3_0_0() -> None:
    values = yaml.safe_load(
        (
            ROOT / "deploy" / "helm" / "platform" / "values.production.example.yaml"
        ).read_text(encoding="utf-8")
    )

    assert values["image"]["repository"] == "ghcr.io/platformnetwork/platform"
    assert values["image"]["tag"] == VERSION
    assert values["image"]["digest"] == PRODUCTION_DIGEST
    assert values["image"]["production"] is True


def test_versioning_policy_documents_release_contract() -> None:
    policy = (ROOT / "docs" / "versioning.md").read_text(encoding="utf-8")

    required = [
        "3.0.0",
        GIT_RELEASE_TAG,
        "Semantic Versioning",
        "pyproject.toml",
        "Chart.yaml",
        "appVersion",
        "GHCR",
        "type=semver,pattern={{version}}",
        "sha256",
        "latest",
        "Production",
    ]
    for token in required:
        assert token in policy


def test_github_workflow_publishes_canonical_semver_tags() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "v*.*.*" in workflow
    assert "type=semver,pattern={{version}}" in workflow
    assert "type=semver,pattern={{raw}}" in workflow
    assert "type=ref,event=tag" not in workflow
