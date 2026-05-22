from __future__ import annotations

from pathlib import Path

import yaml

from platform_network.config import load_settings

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_DOCS = [
    ROOT / "docs" / "validator.md",
    ROOT / "docs" / "validator" / "README.md",
    ROOT / "docs" / "operations" / "validator.md",
]
SCRIPT = ROOT / "scripts" / "install-validator.sh"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _render_installer_manifests(*args: str) -> list[dict]:
    import subprocess

    result = subprocess.run(
        [
            str(SCRIPT),
            "--render-manifests",
            "--skip-hotkey-import",
            *args,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [doc for doc in yaml.safe_load_all(result.stdout) if isinstance(doc, dict)]


def test_validator_install_docs_are_kubernetes_only() -> None:
    forbidden = [
        "platform master",
        "master validator",
        "master-admin",
        "master-proxy",
        "config/master",
        "Master Deployment",
        "docker compose",
        "compose.validator",
        "Docker Compose",
    ]
    for path in VALIDATOR_DOCS:
        content = _read(path)
        lowered = content.lower()
        for token in forbidden:
            assert token.lower() not in lowered, f"{token!r} found in {path}"
        assert "scripts/install-validator.sh" in content
        assert "kubectl" in content
        assert "Kubernetes" in content
        assert "https://chain.platform.network" in content
        assert "platform-validator.invalid" not in content


def test_validator_docs_document_kubernetes_policy_and_secret_behavior() -> None:
    docs = "\n".join(_read(path) for path in VALIDATOR_DOCS)

    assert (
        "postgresql+asyncpg://platform:<password>@postgres.platform.svc.cluster.local/platform"
        in docs
    )
    assert "PLATFORM_DATABASE_URL" in docs
    assert "PLATFORM_BROKER_ALLOWED_IMAGES" in docs
    assert "SQLite URLs" in docs
    assert "platformnetwork/" in docs
    assert "Secret read RBAC" in docs
    assert "encryption at rest" in docs


def test_installer_is_kubernetes_only() -> None:
    script = _read(SCRIPT)

    assert "kubectl" in script
    assert "docker compose" not in script
    assert "COMPOSE_FILE" not in script
    assert "docker system prune" not in script
    assert "docker container prune" not in script
    assert "docker volume prune" not in script
    assert "docker rm $(docker ps" not in script


def test_installer_prompts_only_for_hotkey_mnemonic() -> None:
    script = _read(SCRIPT)

    assert "Validator hotkey mnemonic" in script
    assert "read -r -s HOTKEY_MNEMONIC" in script
    assert "regenerate_hotkey" in script
    assert "regen_coldkey" not in script.lower()
    assert "new_coldkey" not in script.lower()
    assert "coldkey mnemonic" not in script.lower()


def test_installer_cleanup_is_scoped_to_kubernetes_validator_objects() -> None:
    script = _read(SCRIPT)

    assert 'APP="platform-validator"' in script
    assert 'delete deployment "$APP"' in script
    assert 'delete configmap "$APP-config"' in script
    assert 'delete secret "$APP-wallet"' in script
    assert 'delete role "$APP-runtime"' in script
    assert 'delete rolebinding "$APP-runtime"' in script
    assert 'delete serviceaccount "$APP"' in script
    assert "delete namespace" not in script
    assert "delete all" not in script


def test_installer_renders_validator_kubernetes_runtime() -> None:
    script = _read(SCRIPT)

    assert 'backend: "kubernetes"' in script
    assert 'registry_url: "${REGISTRY_URL}"' in script
    assert 'broker_backend: "kubernetes"' in script
    assert "kind: Deployment" in script
    assert "kind: Role" in script
    assert "kind: RoleBinding" in script
    assert "kind: PersistentVolumeClaim" in script
    assert "- platform" in script
    assert "- validator" in script
    assert "- run" in script
    assert "secretName: ${APP}-wallet" in script


def test_validator_extra_includes_kubernetes_runtime_dependencies() -> None:
    import tomllib

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    validator_extra = pyproject["project"]["optional-dependencies"]["validator"]

    assert any(item.startswith("bittensor") for item in validator_extra)
    assert any(item.startswith("kubernetes") for item in validator_extra)


def test_generated_validator_config_passes_settings_policy(tmp_path: Path) -> None:
    configmap = next(
        doc for doc in _render_installer_manifests() if doc.get("kind") == "ConfigMap"
    )
    config = tmp_path / "validator.yaml"
    config.write_text(configmap["data"]["validator.yaml"], encoding="utf-8")

    settings = load_settings(config)

    assert settings.runtime.backend == "kubernetes"
    assert settings.validator.registry_url == "https://chain.platform.network"
    assert settings.database.url.startswith("postgresql+asyncpg://")
    assert settings.docker.broker_allowed_images == ["ghcr.io/platformnetwork/"]


def test_generated_validator_config_supports_custom_policy_values(
    tmp_path: Path,
) -> None:
    configmap = next(
        doc
        for doc in _render_installer_manifests(
            "--database-url",
            "postgresql://platform:secret@postgres.platform/platform",
            "--broker-allowed-images",
            "ghcr.io/platformnetwork/,registry.example.com/platform/",
        )
        if doc.get("kind") == "ConfigMap"
    )
    config = tmp_path / "validator-custom.yaml"
    config.write_text(configmap["data"]["validator.yaml"], encoding="utf-8")

    settings = load_settings(config)

    assert (
        settings.database.url
        == "postgresql://platform:secret@postgres.platform/platform"
    )
    assert settings.docker.broker_allowed_images == [
        "ghcr.io/platformnetwork/",
        "registry.example.com/platform/",
    ]


def test_manual_validator_kubernetes_config_must_satisfy_policy(tmp_path: Path) -> None:
    config = tmp_path / "manual-validator.yaml"
    config.write_text(
        "\n".join(
            [
                "runtime:",
                "  backend: kubernetes",
                "database:",
                "  url: postgresql+asyncpg://platform:secret@postgres.platform/platform",
                "docker:",
                "  broker_allowed_images:",
                "    - ghcr.io/platformnetwork/",
                "kubernetes:",
                "  in_cluster: true",
                "  broker_backend: kubernetes",
            ]
        ),
        encoding="utf-8",
    )

    settings = load_settings(config)

    assert settings.runtime.backend == "kubernetes"
    assert settings.database.url.startswith("postgresql+asyncpg://")
    assert settings.docker.broker_allowed_images == ["ghcr.io/platformnetwork/"]

    config.write_text(
        "\n".join(
            [
                "runtime:",
                "  backend: kubernetes",
                "database:",
                "  url: sqlite+aiosqlite:////var/lib/platform/platform.sqlite3",
                "docker:",
                "  broker_allowed_images:",
                "    - ghcr.io/platformnetwork/",
            ]
        ),
        encoding="utf-8",
    )
    try:
        load_settings(config)
    except ValueError as exc:
        assert "PostgreSQL" in str(exc) or "external PostgreSQL" in str(exc)
    else:
        raise AssertionError("manual Kubernetes config accepted sqlite database")

    config.write_text(
        "\n".join(
            [
                "runtime:",
                "  backend: kubernetes",
                "database:",
                "  url: postgresql+asyncpg://platform:secret@postgres.platform/platform",
                "docker:",
                "  broker_allowed_images:",
                "    - platformnetwork/",
            ]
        ),
        encoding="utf-8",
    )
    try:
        load_settings(config)
    except ValueError as exc:
        assert "too broad" in str(exc)
    else:
        raise AssertionError("manual Kubernetes config accepted broad image allowlist")


def test_generated_manifest_uses_non_root_accessible_wallet_path() -> None:
    deployment = next(
        doc for doc in _render_installer_manifests() if doc.get("kind") == "Deployment"
    )
    pod_spec = deployment["spec"]["template"]["spec"]
    container = pod_spec["containers"][0]
    mounts = {mount["name"]: mount for mount in container["volumeMounts"]}

    assert pod_spec["securityContext"]["runAsNonRoot"] is True
    assert mounts["wallet"]["mountPath"] == (
        "/var/lib/platform/wallets/platform-validator/hotkeys"
    )
    assert (
        deployment["spec"]["template"]["spec"]["volumes"][2]["secret"]["optional"]
        is True
    )
