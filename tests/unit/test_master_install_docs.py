from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "install-master.sh"
MASTER_DOCS = [
    ROOT / "README.md",
    ROOT / "docs" / "master" / "README.md",
]
VALIDATOR_DOCS = [
    ROOT / "docs" / "validator.md",
    ROOT / "docs" / "validator" / "README.md",
    ROOT / "docs" / "operations" / "validator.md",
]

FOUNDATION_WARNING = (
    "Foundation-only installer for Cortex Foundation master infrastructure. "
    "Do not run this for validators or third-party operators."
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write_fake_kubectl(tmp_path: Path) -> None:
    kubectl = tmp_path / "kubectl"
    kubectl.write_text(
        "#!/usr/bin/env bash\n"
        'printf \'%s\\n\' "$*" >> "$KUBECTL_LOG"\n'
        'if [ "$1" = apply ]; then cat > "$KUBECTL_APPLY_MANIFEST"; fi\n',
        encoding="utf-8",
    )
    kubectl.chmod(0o700)


def _run_master_installer(
    tmp_path: Path,
    *,
    extra_args: list[str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[dict]]:
    _write_fake_kubectl(tmp_path)
    log = tmp_path / "kubectl.log"
    manifest = tmp_path / "manifest.yaml"
    env = {
        "PATH": f"{tmp_path}:/usr/bin:/bin",
        "KUBECTL_LOG": str(log),
        "KUBECTL_APPLY_MANIFEST": str(manifest),
    }

    command = [
        "bash",
        str(SCRIPT),
        "--namespace",
        "master-test",
        "--image",
        "ghcr.io/platformnetwork/platform-master:sha-one",
        "--database-url",
        "postgresql+asyncpg://user:pass@postgres.example/platform",
        *(extra_args or []),
    ]

    result = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    manifests: list[dict] = []
    if manifest.exists():
        manifests = [
            doc
            for doc in yaml.safe_load_all(manifest.read_text(encoding="utf-8"))
            if doc
        ]
    return result, manifests


def test_master_installer_script_is_committed_with_foundation_warning() -> None:
    script = _read(SCRIPT)

    assert FOUNDATION_WARNING in script
    assert 'NAMESPACE="${PLATFORM_NAMESPACE:-platform-master}"' in script
    assert "paste.rs" not in script
    assert "curl" not in script
    assert "mnemonic" not in script.lower()
    assert "coldkey" not in script.lower()
    assert "hotkey" not in script.lower()
    assert 'AUTO_UPGRADE_SUSPEND="${PLATFORM_AUTO_UPGRADE_SUSPEND:-true}"' in script
    assert 'DATABASE_URL="${PLATFORM_DATABASE_URL:-}"' in script
    assert "database-url is required" in script
    assert "cleanup_master\n  render_manifests" not in script


def test_master_installer_usage_states_foundation_only_boundary() -> None:
    result = subprocess.run(
        ["bash", str(SCRIPT), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert FOUNDATION_WARNING in result.stdout
    assert "Default: platform-master" in result.stdout
    assert "--auto-upgrade-suspend BOOL" in result.stdout
    assert "Default: true" in result.stdout
    assert "validators" in result.stdout
    assert "third-party operators" in result.stdout


def test_master_installer_rejects_validator_namespace() -> None:
    result = subprocess.run(
        ["bash", str(SCRIPT), "--namespace", "platform-validator"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "platform-validator is reserved for the validator installer" in result.stderr
    assert "kubectl is required" not in result.stderr


def test_master_installer_renders_master_only_resources(tmp_path: Path) -> None:
    result, manifests = _run_master_installer(tmp_path)

    assert result.returncode == 0, result.stderr
    assert FOUNDATION_WARNING in result.stdout
    kinds_by_name = {
        (doc.get("kind"), doc.get("metadata", {}).get("name")) for doc in manifests
    }
    assert ("Namespace", "master-test") in kinds_by_name
    assert ("Deployment", "platform-master-admin") in kinds_by_name
    assert ("Deployment", "platform-master-proxy") in kinds_by_name
    assert ("Deployment", "platform-master-broker") in kinds_by_name
    assert ("CronJob", "platform-master-helm-upgrader") in kinds_by_name
    assert ("CronJob", "platform-master-challenge-image-updater") in kinds_by_name
    assert ("ConfigMap", "platform-master-config") in kinds_by_name
    assert ("Secret", "platform-master-database-url") in kinds_by_name
    assert ("Secret", "platform-master-wallet") not in kinds_by_name
    assert ("Deployment", "platform-validator") not in kinds_by_name
    assert ("CronJob", "platform-master-weights") not in kinds_by_name


def test_master_installer_manifest_has_no_validator_or_submit_path(
    tmp_path: Path,
) -> None:
    result, manifests = _run_master_installer(tmp_path)

    assert result.returncode == 0, result.stderr
    rendered = yaml.safe_dump_all(manifests)
    deployment_commands = [
        doc["spec"]["template"]["spec"]["containers"][0]["command"]
        for doc in manifests
        if doc.get("kind") == "Deployment"
    ]
    cronjob_commands = [
        doc["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0][
            "command"
        ]
        for doc in manifests
        if doc.get("kind") == "CronJob"
    ]

    assert "platform-validator" not in rendered
    assert "validator run" not in rendered
    assert "validator.yaml" not in rendered
    assert "wallet" not in rendered.lower()
    assert "platform master weights" not in rendered
    assert "set_weights" not in rendered
    assert "--once" not in rendered
    assert [
        "platform",
        "master",
        "run",
        "--config",
        "config/master.kubernetes.yaml",
    ] in deployment_commands
    assert not any(
        command[:3] == ["platform", "kubernetes", "sync-config"]
        for command in cronjob_commands
    )
    helm_upgrade_command = " ".join(
        next(
            command
            for command in cronjob_commands
            if "set -- upgrade --install" in " ".join(command)
        )
    )
    assert "HELM_DRIVER" in rendered
    assert "suspend: true" in rendered
    assert "set -- upgrade --install platform-master" in helm_upgrade_command
    assert 'helm "$@"' in helm_upgrade_command
    assert "--namespace master-test" in helm_upgrade_command
    assert "--atomic" in helm_upgrade_command
    assert "--wait" in helm_upgrade_command
    assert "--cleanup-on-fail" in helm_upgrade_command
    assert "--take-ownership" in helm_upgrade_command
    assert (
        "codeload.github.com/PlatformNetwork/platform/tar.gz/main"
        in helm_upgrade_command
    )
    assert (
        '--set-string database.urlSecret.name="platform-master-database-url"'
        in helm_upgrade_command
    )
    assert '--set-string database.urlSecret.key="url"' in helm_upgrade_command
    assert (
        '--set-string security.existingSecret="platform-secrets"'
        in helm_upgrade_command
    )
    assert '--set-string kubernetes.namespace="master-test"' in helm_upgrade_command
    assert (
        '--set-string kubernetes.serviceAccount="platform-master"'
        in helm_upgrade_command
    )
    assert "postgresql+asyncpg://" not in helm_upgrade_command
    assert "mnemonic" not in helm_upgrade_command.lower()
    assert "token" not in helm_upgrade_command.lower()
    updater_role = next(
        doc
        for doc in manifests
        if doc.get("kind") == "Role"
        and doc.get("metadata", {}).get("name") == "platform-master-helm-upgrader"
    )
    runtime_role = next(
        doc
        for doc in manifests
        if doc.get("kind") == "Role"
        and doc.get("metadata", {}).get("name") == "platform-master-runtime"
    )
    assert any("secrets" in rule.get("resources", []) for rule in runtime_role["rules"])
    assert not any(
        "secrets" in rule.get("resources", []) for rule in updater_role["rules"]
    )
    assert any(
        rule["apiGroups"] == ["rbac.authorization.k8s.io"]
        and rule["resources"] == ["roles", "rolebindings"]
        for rule in updater_role["rules"]
    )


def test_master_installer_database_url_only_appears_in_secret(
    tmp_path: Path,
) -> None:
    database_url = "postgresql+asyncpg://user:pass@postgres.example/platform"
    result, manifests = _run_master_installer(
        tmp_path,
        extra_args=["--database-url", database_url],
    )

    assert result.returncode == 0, result.stderr
    database_secret = next(
        doc
        for doc in manifests
        if doc.get("kind") == "Secret"
        and doc.get("metadata", {}).get("name") == "platform-master-database-url"
    )
    non_secret_rendered = yaml.safe_dump_all(
        doc for doc in manifests if doc is not database_secret
    )
    config = next(doc for doc in manifests if doc.get("kind") == "ConfigMap")
    deployments = [doc for doc in manifests if doc.get("kind") == "Deployment"]

    assert database_secret["stringData"] == {"url": database_url}
    assert database_url not in non_secret_rendered
    assert "postgresql+asyncpg://" not in non_secret_rendered
    assert 'url: "${PLATFORM_DATABASE__URL}"' in config["data"]["master.yaml"]
    for deployment in deployments:
        container = deployment["spec"]["template"]["spec"]["containers"][0]
        assert {
            "name": "PLATFORM_DATABASE__URL",
            "valueFrom": {
                "secretKeyRef": {
                    "name": "platform-master-database-url",
                    "key": "url",
                }
            },
        } in container["env"]


def test_master_installer_rejects_unsafe_namespace() -> None:
    result = subprocess.run(
        [str(SCRIPT), "--namespace", "bad;name"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "namespace must contain only" in result.stderr
    assert "kubectl is required" not in result.stderr


def test_master_installer_rejects_unsafe_auto_upgrade_ref() -> None:
    result = subprocess.run(
        [str(SCRIPT), "--auto-upgrade-ref", 'main";touch'],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "auto-upgrade ref must" in result.stderr
    assert "kubectl is required" not in result.stderr


def test_master_installer_can_suspend_helm_upgrader(tmp_path: Path) -> None:
    result, manifests = _run_master_installer(
        tmp_path,
        extra_args=["--auto-upgrade-suspend", "true"],
    )

    assert result.returncode == 0, result.stderr
    cronjob = next(
        doc
        for doc in manifests
        if doc.get("kind") == "CronJob"
        and doc.get("metadata", {}).get("name") == "platform-master-helm-upgrader"
    )
    assert cronjob["spec"]["suspend"] is True


def test_master_cleanup_removes_installer_managed_database_secret(
    tmp_path: Path,
) -> None:
    _write_fake_kubectl(tmp_path)
    log = tmp_path / "kubectl.log"
    env = {
        "PATH": f"{tmp_path}:/usr/bin:/bin",
        "KUBECTL_LOG": str(log),
        "KUBECTL_APPLY_MANIFEST": str(tmp_path / "manifest.yaml"),
    }

    result = subprocess.run(
        ["bash", str(SCRIPT), "--cleanup", "--namespace", "master-test"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    calls = log.read_text(encoding="utf-8").splitlines()
    assert "-n master-test delete secret platform-master-database-url" in calls


def test_master_docs_are_foundation_only_and_do_not_reference_paste() -> None:
    docs = "\n".join(_read(path) for path in MASTER_DOCS)
    master_guide = _read(ROOT / "docs" / "master" / "README.md")

    assert FOUNDATION_WARNING in docs
    assert "./scripts/install-master.sh --database-url" in docs
    assert "export PLATFORM_DATABASE_URL=" in docs
    assert "PLATFORM_NAMESPACE=platform-master" in docs
    assert "platform-master-helm-upgrader" in docs
    assert "autoUpgrade.suspend=true" in docs
    assert "jsonpath='{.data.url}'" in docs
    assert "database.urlSecret.name=platform-master-database-url" in docs
    assert "removes `secret/platform-master-database-url`" in docs
    assert "without deleting healthy existing workloads" in docs
    assert "Deletes only prior installer-managed master objects" not in docs
    assert "paste.rs" not in docs
    assert "curl" not in docs
    assert "platform validator run" not in master_guide
    assert "platform-validator" not in master_guide
    assert "mnemonic" not in master_guide.lower()
    assert "coldkey" not in master_guide.lower()
    assert "hotkey" not in master_guide.lower()


def test_validator_docs_keep_operators_on_validator_installer() -> None:
    for path in VALIDATOR_DOCS:
        content = _read(path)
        assert "./scripts/install-validator.sh" in content
        assert "./scripts/install-master.sh" not in content
        assert "Foundation-only installer" not in content
        assert "Cortex Foundation master infrastructure" not in content
