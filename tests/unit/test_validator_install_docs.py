from __future__ import annotations

import subprocess
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


def _validator_config(
    *,
    database_url: str = "postgresql+asyncpg://platform-validator.invalid/platform",
    broker_allowed_images: list[str] | None = None,
) -> str:
    allowed = broker_allowed_images or ["ghcr.io/platformnetwork/"]
    allowed_yaml = "\n".join(f"    - {item}" for item in allowed)
    return f"""runtime:
  backend: kubernetes
database:
  url: {database_url}
network:
  netuid: 0
  chain_endpoint: ""
  wallet_name: platform-validator
  wallet_hotkey: validator
  wallet_path: /var/lib/platform/wallets
  master_uid: 0
validator:
  registry_url: https://chain.platform.network
  registry_retry_seconds: 15
docker:
  broker_url: http://platform-validator-broker:8082
  secret_dir: /var/lib/platform/secrets
  broker_allowed_images:
{allowed_yaml}
kubernetes:
  namespace: platform-validator
  in_cluster: true
  target_state_file: /var/lib/platform/kubernetes_targets.json
  service_account: platform-validator
  challenge_mode: statefulset
  broker_backend: kubernetes
  storage_size: 10Gi
observability:
  log_json: true
  otel_service_name: platform-validator
"""


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
        assert "--dry-run" not in content
        assert "--skip-hotkey-import" not in content
        assert "--render-manifests" not in content


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
    assert "platform-validator-image-updater" in docs
    assert "cronjob/platform-validator-image-updater" in docs
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


def test_installer_has_no_smoke_modes() -> None:
    script = _read(SCRIPT)

    forbidden = [
        "--dry-run",
        "--skip-hotkey-import",
        "--render-manifests",
        "DRY_RUN",
        "SKIP_HOTKEY_IMPORT",
        "RENDER_ONLY",
        "WALLET_SECRET_OPTIONAL",
        "[dry-run]",
        "dry-run=client",
    ]
    for token in forbidden:
        assert token not in script


def test_removed_installer_smoke_options_are_rejected() -> None:
    for option in ["--dry-run", "--skip-hotkey-import", "--render-manifests"]:
        result = subprocess.run(
            [str(SCRIPT), option],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 2
        assert f"Unknown option: {option}" in result.stderr
        assert "Validator hotkey mnemonic" not in result.stdout
        assert "kubectl is required" not in result.stderr


def _write_fake_kubectl(tmp_path: Path) -> Path:
    kubectl = tmp_path / "kubectl"
    kubectl.write_text(
        "#!/usr/bin/env bash\n"
        'printf \'%s\\n\' "$*" >> "$KUBECTL_LOG"\n'
        'if [ "$1" = apply ]; then cat > "$KUBECTL_APPLY_MANIFEST"; fi\n',
        encoding="utf-8",
    )
    kubectl.chmod(0o700)
    return kubectl


def _write_unusable_hotkey_python(tmp_path: Path) -> None:
    for name in ["python3", "uv"]:
        executable = tmp_path / name
        executable.write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")
        executable.chmod(0o700)


def _write_fake_hotkey_python(tmp_path: Path) -> None:
    python = tmp_path / "python3"
    python.write_text(
        "#!/usr/bin/env bash\n"
        'if [ -n "${TMP_DIR:-}" ]; then\n'
        '  mkdir -p "$TMP_DIR/wallets/$WALLET_NAME/hotkeys"\n'
        "  printf 'hotkey' > \"$TMP_DIR/wallets/$WALLET_NAME/hotkeys/$WALLET_HOTKEY\"\n"
        "  printf 'hotkeypub' > "
        '"$TMP_DIR/wallets/$WALLET_NAME/hotkeys/${WALLET_HOTKEY}pub.txt"\n'
        "  cat >/dev/null\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    python.chmod(0o700)


def _run_installer_with_fakes(tmp_path: Path, image: str) -> list[dict]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    _write_fake_kubectl(tmp_path)
    _write_fake_hotkey_python(tmp_path)
    log = tmp_path / "kubectl.log"
    manifest = tmp_path / "manifest.yaml"
    env = {
        "PATH": f"{tmp_path}:/usr/bin:/bin",
        "KUBECTL_LOG": str(log),
        "KUBECTL_APPLY_MANIFEST": str(manifest),
    }

    result = subprocess.run(
        ["bash", str(SCRIPT), "--namespace", "validator-test", "--image", image],
        cwd=ROOT,
        env=env,
        input="disposable test mnemonic\n",
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = log.read_text(encoding="utf-8").splitlines()
    assert "apply -f -" in calls
    assert any(
        "create secret generic platform-validator-wallet" in call for call in calls
    )
    return [
        doc for doc in yaml.safe_load_all(manifest.read_text(encoding="utf-8")) if doc
    ]


def test_cleanup_requires_only_kubectl(tmp_path: Path) -> None:
    _write_fake_kubectl(tmp_path)
    _write_unusable_hotkey_python(tmp_path)
    log = tmp_path / "kubectl.log"
    env = {
        "PATH": f"{tmp_path}:/usr/bin:/bin",
        "KUBECTL_LOG": str(log),
    }

    result = subprocess.run(
        ["bash", str(SCRIPT), "--cleanup", "--namespace", "validator-test"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "python with bittensor" not in result.stderr
    calls = log.read_text(encoding="utf-8").splitlines()
    assert calls == [
        "-n validator-test delete cronjob platform-validator-image-updater",
        "-n validator-test delete role platform-validator-image-updater",
        "-n validator-test delete rolebinding platform-validator-image-updater",
        "-n validator-test delete serviceaccount platform-validator-image-updater",
        "-n validator-test delete deployment platform-validator",
        "-n validator-test delete configmap platform-validator-config",
        "-n validator-test delete secret platform-validator-wallet",
        "-n validator-test delete role platform-validator-runtime",
        "-n validator-test delete rolebinding platform-validator-runtime",
        "-n validator-test delete serviceaccount platform-validator",
    ]


def test_install_requires_hotkey_python_before_cleanup(tmp_path: Path) -> None:
    _write_fake_kubectl(tmp_path)
    _write_unusable_hotkey_python(tmp_path)
    log = tmp_path / "kubectl.log"
    env = {
        "PATH": f"{tmp_path}:/usr/bin:/bin",
        "KUBECTL_LOG": str(log),
    }

    result = subprocess.run(
        ["bash", str(SCRIPT), "--namespace", "validator-test"],
        cwd=ROOT,
        env=env,
        input="unused mnemonic\n",
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "python with bittensor is required" in result.stderr
    assert not log.exists()


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


def test_installer_default_config_values_pass_settings_policy(tmp_path: Path) -> None:
    script = _read(SCRIPT)
    config = tmp_path / "validator.yaml"
    config.write_text(_validator_config(), encoding="utf-8")

    settings = load_settings(config)

    assert 'DATABASE_URL="${PLATFORM_DATABASE_URL:-postgresql+asyncpg://' in script
    assert (
        'REGISTRY_URL="${PLATFORM_VALIDATOR_REGISTRY_URL:-https://chain.platform.network}"'
        in script
    )
    assert (
        'BROKER_ALLOWED_IMAGES="${PLATFORM_BROKER_ALLOWED_IMAGES:-ghcr.io/platformnetwork/}"'
        in script
    )
    assert settings.runtime.backend == "kubernetes"
    assert settings.validator.registry_url == "https://chain.platform.network"
    assert settings.database.url.startswith("postgresql+asyncpg://")
    assert settings.docker.broker_allowed_images == ["ghcr.io/platformnetwork/"]


def test_validator_config_supports_custom_policy_values(tmp_path: Path) -> None:
    config = tmp_path / "validator-custom.yaml"
    config.write_text(
        _validator_config(
            database_url="postgresql://platform:secret@postgres.platform/platform",
            broker_allowed_images=[
                "ghcr.io/platformnetwork/",
                "registry.example.com/platform/",
            ],
        ),
        encoding="utf-8",
    )

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


def test_generated_manifest_uses_non_root_accessible_required_wallet_path() -> None:
    script = _read(SCRIPT)

    assert "runAsNonRoot: true" in script
    assert "mountPath: ${WALLET_PATH}/${WALLET_NAME}/hotkeys" in script
    assert "secretName: ${APP}-wallet" in script
    assert "optional:" not in script


def test_validator_installer_renders_auto_update_cronjob() -> None:
    script = _read(SCRIPT)

    assert (
        'AUTO_UPDATE_SCHEDULE="${PLATFORM_VALIDATOR_AUTO_UPDATE_SCHEDULE:-*/5 * * * *}"'
        in script
    )
    assert (
        'AUTO_UPDATE_IMAGE="${PLATFORM_VALIDATOR_AUTO_UPDATE_IMAGE:-registry.k8s.io/kubectl@sha256:99b37df34bc4f99ee322521d4c85cb98c1ceb8f70ff0618bef84eec9fe1ebc20}"'
        in script
    )
    assert "kind: CronJob" in script
    assert "name: ${APP}-image-updater" in script
    assert "rollout" in script
    assert "restart" in script
    assert "deployment/${APP}" in script
    assert 'resources: ["jobs"]' in script
    assert 'resources: ["deployments"]' in script
    assert 'resourceNames: ["${APP}"]' in script
    assert 'delete cronjob "$APP-image-updater"' in script
    assert 'delete serviceaccount "$APP-image-updater"' in script


def test_validator_installer_image_update_changes_deployment_template(
    tmp_path: Path,
) -> None:
    first = _run_installer_with_fakes(
        tmp_path / "first",
        "ghcr.io/platformnetwork/platform:sha-one",
    )
    second = _run_installer_with_fakes(
        tmp_path / "second",
        "ghcr.io/platformnetwork/platform:sha-two",
    )

    first_deployment = next(doc for doc in first if doc.get("kind") == "Deployment")
    second_deployment = next(doc for doc in second if doc.get("kind") == "Deployment")
    first_container = first_deployment["spec"]["template"]["spec"]["containers"][0]
    second_container = second_deployment["spec"]["template"]["spec"]["containers"][0]

    assert first_container["image"] == "ghcr.io/platformnetwork/platform:sha-one"
    assert second_container["image"] == "ghcr.io/platformnetwork/platform:sha-two"
    assert first_container["imagePullPolicy"] == "Always"
    assert second_container["imagePullPolicy"] == "Always"


def test_validator_installer_auto_updater_uses_scoped_service_account(
    tmp_path: Path,
) -> None:
    manifests = _run_installer_with_fakes(
        tmp_path,
        "ghcr.io/platformnetwork/platform:latest",
    )
    cronjob = next(doc for doc in manifests if doc.get("kind") == "CronJob")
    pod_spec = cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    container = pod_spec["containers"][0]

    assert cronjob["spec"]["schedule"] == "*/5 * * * *"
    assert pod_spec["serviceAccountName"] == "platform-validator-image-updater"
    assert pod_spec["restartPolicy"] == "OnFailure"
    assert container["image"] == (
        "registry.k8s.io/kubectl@"
        "sha256:99b37df34bc4f99ee322521d4c85cb98c1ceb8f70ff0618bef84eec9fe1ebc20"
    )
    assert container["imagePullPolicy"] == "Always"
    assert container["command"] == [
        "kubectl",
        "-n",
        "validator-test",
        "rollout",
        "restart",
        "deployment/platform-validator",
    ]
