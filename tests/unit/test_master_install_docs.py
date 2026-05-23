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
) -> tuple[subprocess.CompletedProcess[str], list[dict]]:
    _write_fake_kubectl(tmp_path)
    log = tmp_path / "kubectl.log"
    manifest = tmp_path / "manifest.yaml"
    env = {
        "PATH": f"{tmp_path}:/usr/bin:/bin",
        "KUBECTL_LOG": str(log),
        "KUBECTL_APPLY_MANIFEST": str(manifest),
    }

    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--namespace",
            "master-test",
            "--image",
            "ghcr.io/platformnetwork/platform-master:sha-one",
        ],
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
    assert ("CronJob", "platform-master-config-sync") in kinds_by_name
    assert ("ConfigMap", "platform-master-config") in kinds_by_name
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
    assert any(
        command[:3] == ["platform", "kubernetes", "sync-config"]
        for command in cronjob_commands
    )
    config_sync_command = next(
        command
        for command in cronjob_commands
        if command[:3] == ["platform", "kubernetes", "sync-config"]
    )
    assert config_sync_command == [
        "platform",
        "kubernetes",
        "sync-config",
        "--namespace",
        "master-test",
        "--config-map",
        "platform-master-config",
        "--repo",
        "PlatformNetwork/platform",
        "--ref",
        "main",
        "--rollout-target",
        "Deployment/platform-master-admin",
        "--rollout-target",
        "Deployment/platform-master-proxy",
        "--rollout-target",
        "Deployment/platform-master-broker",
    ]


def test_master_docs_are_foundation_only_and_do_not_reference_paste() -> None:
    docs = "\n".join(_read(path) for path in MASTER_DOCS)
    master_guide = _read(ROOT / "docs" / "master" / "README.md")

    assert FOUNDATION_WARNING in docs
    assert "./scripts/install-master.sh" in docs
    assert "PLATFORM_NAMESPACE=platform-master" in docs
    assert "platform-master-config-sync" in docs
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
