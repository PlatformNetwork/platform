from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from platform_network.config.loader import load_settings
from platform_network.config.settings import Settings
from platform_network.kubernetes.config_updater import (
    CONFIG_DIGEST_ANNOTATION,
    ConfigSyncSource,
    ConfigSyncUpdater,
    RolloutTarget,
    _digest,
    _runtime_config_payload,
)
from platform_network.master.swarm_backend import SwarmCommandResult
from platform_network.supervisor.config_sync import (
    CONFIG_SYNC_INTERVAL_SECONDS,
    DEFAULT_CONFIG_TARGET_PATH,
    DEFAULT_ROLLOUT_SERVICES,
    SwarmConfigSync,
    build_config_sync_task,
)

ROOT = Path(__file__).resolve().parents[2]


def test_config_defaults_to_platform_subnet_netuid() -> None:
    assert load_settings(None).network.netuid == 100


def test_example_configs_default_to_platform_subnet_netuid() -> None:
    master_example = yaml.safe_load(
        (ROOT / "config" / "master.example.yaml").read_text(encoding="utf-8")
    )
    validator_example = yaml.safe_load(
        (ROOT / "config" / "validator.example.yaml").read_text(encoding="utf-8")
    )

    assert master_example["network"]["netuid"] == 100
    assert validator_example["network"]["netuid"] == 100


def test_config_file_netuid_overrides_default(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("network:\n  netuid: 42\n", encoding="utf-8")

    assert load_settings(config).network.netuid == 42


class CoreApi:
    def __init__(self, config_map: SimpleNamespace) -> None:
        self.config_map = config_map
        self.config_map_patches: list[dict[str, Any]] = []
        self.secret_patches: list[dict[str, Any]] = []

    def read_namespaced_config_map(self, name: str, namespace: str) -> SimpleNamespace:
        assert name == "platform-config"
        assert namespace == "platform-test"
        return self.config_map

    def patch_namespaced_config_map(
        self, name: str, namespace: str, body: dict[str, Any]
    ) -> None:
        assert name == "platform-config"
        assert namespace == "platform-test"
        self.config_map_patches.append(body)
        annotations = self.config_map.metadata.annotations
        annotations.update(body.get("metadata", {}).get("annotations", {}))
        self.config_map.data.update(body.get("data", {}))

    def patch_namespaced_secret(
        self, name: str, namespace: str, body: dict[str, Any]
    ) -> None:
        self.secret_patches.append({"name": name, "namespace": namespace, "body": body})


class AppsApi:
    def __init__(self) -> None:
        self.deployment_patches: list[tuple[str, str, dict[str, Any]]] = []
        self.deployments: dict[str, SimpleNamespace] = {}

    def patch_namespaced_deployment(
        self, name: str, namespace: str, body: dict[str, Any]
    ) -> None:
        self.deployment_patches.append((name, namespace, body))
        deployment = self.deployments.setdefault(
            name,
            SimpleNamespace(
                spec=SimpleNamespace(
                    template=SimpleNamespace(metadata=SimpleNamespace(annotations={}))
                )
            ),
        )
        deployment.spec.template.metadata.annotations.update(
            body["spec"]["template"]["metadata"]["annotations"]
        )

    def read_namespaced_deployment(self, name: str, namespace: str) -> SimpleNamespace:
        return self.deployments.get(
            name,
            SimpleNamespace(
                spec=SimpleNamespace(
                    template=SimpleNamespace(metadata=SimpleNamespace(annotations={}))
                )
            ),
        )


class FailingOnceAppsApi(AppsApi):
    def __init__(self) -> None:
        super().__init__()
        self.fail_next_patch = True

    def patch_namespaced_deployment(
        self, name: str, namespace: str, body: dict[str, Any]
    ) -> None:
        if self.fail_next_patch:
            self.fail_next_patch = False
            raise RuntimeError("rollout patch failed")
        super().patch_namespaced_deployment(name, namespace, body)


def config_map(*, digest: str = "sha256:old") -> SimpleNamespace:
    return SimpleNamespace(
        metadata=SimpleNamespace(annotations={CONFIG_DIGEST_ANNOTATION: digest}),
        data={"master.yaml": "environment: current\n"},
    )


def test_default_github_source_contract_uses_platform_main_without_secrets() -> None:
    source = ConfigSyncSource.default()

    assert source.repository == "PlatformNetwork/platform"
    assert source.branch == "main"
    assert source.sync_secrets is False
    assert "deploy/helm/platform/values.yaml" in source.paths
    assert "Secret" not in source.allowed_kinds


def test_invalid_github_yaml_preserves_current_state_and_skips_rollout() -> None:
    core = CoreApi(config_map(digest="sha256:current"))
    apps = AppsApi()
    updater = ConfigSyncUpdater(
        core_api=core,
        apps_api=apps,
        source=ConfigSyncSource.default(fetcher=lambda _: "master: [invalid"),
    )

    result = updater.sync_once(
        namespace="platform-test",
        config_map="platform-config",
        rollout_targets=[RolloutTarget(kind="Deployment", name="platform-validator")],
    )

    assert result.changed is False
    assert result.reason == "invalid_config"
    assert result.current_digest == "sha256:current"
    assert core.config_map_patches == []
    assert apps.deployment_patches == []


def test_secret_manifests_are_rejected_and_never_patched() -> None:
    source_text = """
    apiVersion: v1
    kind: Secret
    metadata:
      name: platform-secrets
    stringData:
      token: plaintext
    """
    core = CoreApi(config_map())
    apps = AppsApi()
    updater = ConfigSyncUpdater(
        core_api=core,
        apps_api=apps,
        source=ConfigSyncSource.default(fetcher=lambda _: source_text),
    )

    result = updater.sync_once(
        namespace="platform-test",
        config_map="platform-config",
        rollout_targets=[RolloutTarget(kind="Deployment", name="platform-validator")],
    )

    assert result.changed is False
    assert result.reason == "secret_sync_rejected"
    assert core.config_map_patches == []
    assert core.secret_patches == []
    assert apps.deployment_patches == []


def test_changed_config_patches_configmap_and_shared_rollout_annotation() -> None:
    source_text = """
    environment: production
    network:
      netuid: 42
    validator:
      registry_url: https://registry.example.test
    """
    core = CoreApi(config_map(digest="sha256:old"))
    apps = AppsApi()
    updater = ConfigSyncUpdater(
        core_api=core,
        apps_api=apps,
        source=ConfigSyncSource.default(fetcher=lambda _: source_text),
    )

    result = updater.sync_once(
        namespace="platform-test",
        config_map="platform-config",
        rollout_targets=[
            RolloutTarget(kind="Deployment", name="platform-admin"),
            RolloutTarget(kind="Deployment", name="platform-validator"),
        ],
    )

    assert result.changed is True
    assert result.current_digest == "sha256:old"
    assert result.new_digest is not None
    assert result.new_digest.startswith("sha256:")
    config_patch = core.config_map_patches[0]
    assert config_patch["data"]["master.yaml"] == source_text
    assert (
        config_patch["metadata"]["annotations"][CONFIG_DIGEST_ANNOTATION]
        == result.new_digest
    )
    assert [name for name, _, _ in apps.deployment_patches] == [
        "platform-admin",
        "platform-validator",
    ]
    for _, namespace, patch in apps.deployment_patches:
        assert namespace == "platform-test"
        assert (
            patch["spec"]["template"]["metadata"]["annotations"][
                CONFIG_DIGEST_ANNOTATION
            ]
            == result.new_digest
        )


def test_helm_values_runtime_config_defaults_netuid_to_platform_subnet() -> None:
    source_text = """
    environment: production
    masterAdmin:
      port: 8000
    validator:
      registryUrl: https://registry.example.test
    """
    core = CoreApi(config_map(digest="sha256:old"))
    apps = AppsApi()
    updater = ConfigSyncUpdater(
        core_api=core,
        apps_api=apps,
        source=ConfigSyncSource.default(fetcher=lambda _: source_text),
    )

    result = updater.sync_once(
        namespace="platform-test",
        config_map="platform-config",
        rollout_targets=[RolloutTarget(kind="Deployment", name="platform-validator")],
    )

    assert result.changed is True
    config = yaml.safe_load(core.config_map_patches[0]["data"]["master.yaml"])
    assert config["network"]["netuid"] == 100


def test_same_digest_retries_rollout_after_partial_failure() -> None:
    source_text = "environment: production\n"
    core = CoreApi(config_map(digest="sha256:old"))
    apps = FailingOnceAppsApi()
    updater = ConfigSyncUpdater(
        core_api=core,
        apps_api=apps,
        source=ConfigSyncSource.default(fetcher=lambda _: source_text),
    )

    with pytest.raises(RuntimeError, match="rollout patch failed"):
        updater.sync_once(
            namespace="platform-test",
            config_map="platform-config",
            rollout_targets=[RolloutTarget(kind="Deployment", name="platform-admin")],
        )

    assert len(core.config_map_patches) == 1
    digest = core.config_map.metadata.annotations[CONFIG_DIGEST_ANNOTATION]
    assert apps.deployment_patches == []

    result = updater.sync_once(
        namespace="platform-test",
        config_map="platform-config",
        rollout_targets=[RolloutTarget(kind="Deployment", name="platform-admin")],
    )

    assert result.changed is True
    assert result.reason == "rollout_retried"
    assert result.current_digest == digest
    assert result.new_digest == digest
    assert len(core.config_map_patches) == 1
    assert [name for name, _, _ in apps.deployment_patches] == ["platform-admin"]


def test_config_sync_extracts_runtime_config_from_rendered_configmap_manifest() -> None:
    source_text = """
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: platform-config
    data:
      master.yaml: |
        environment: production
        runtime:
          backend: kubernetes
    """
    core = CoreApi(config_map(digest="sha256:old"))
    updater = ConfigSyncUpdater(
        core_api=core,
        apps_api=AppsApi(),
        source=ConfigSyncSource.default(fetcher=lambda _: source_text),
    )

    updater.sync_once(
        namespace="platform-test",
        config_map="platform-config",
        rollout_targets=[],
    )

    assert core.config_map_patches[0]["data"]["master.yaml"] == (
        "environment: production\nruntime:\n  backend: kubernetes\n"
    )


def test_validator_helm_values_runtime_config_uses_validator_service_account() -> None:
    values = (ROOT / "deploy/helm/platform/values.yaml").read_text()

    payload = _runtime_config_payload(
        values,
        config_map="platform-validator-config",
        namespace="platform-validator",
    )

    config = yaml.safe_load(payload)
    assert config["kubernetes"]["namespace"] == "platform-validator"
    assert config["kubernetes"]["service_account"] == "platform-validator"


def test_unknown_rollout_kind_is_rejected_without_patching_configmap() -> None:
    core = CoreApi(config_map())
    updater = ConfigSyncUpdater(
        core_api=core,
        apps_api=AppsApi(),
        source=ConfigSyncSource.default(fetcher=lambda _: "environment: production\n"),
    )

    with pytest.raises(ValueError, match="unsupported rollout kind"):
        updater.sync_once(
            namespace="platform-test",
            config_map="platform-config",
            rollout_targets=[RolloutTarget(kind="StatefulSet", name="platform-db")],
        )

    assert core.config_map_patches == []


# ---------------------------------------------------------------------------
# Supervisor Swarm config-sync (Task 20) — fake fetcher + fake runner only.
# ---------------------------------------------------------------------------

CONFIG_TEXT = "environment: production\n"
CONFIG_DIGEST = _digest(CONFIG_TEXT)
SWARM_SERVICES = ("platform-admin", "platform-broker")


class FakeSwarmRunner:
    def __init__(
        self,
        *,
        failing_services: set[str] | None = None,
        missing_services: set[str] | None = None,
    ) -> None:
        self.failing_services = (
            failing_services if failing_services is not None else set()
        )
        self.missing_services = (
            missing_services if missing_services is not None else set()
        )
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        input_text: str | None = None,
        timeout_seconds: float | None = None,
    ) -> SwarmCommandResult:
        call = tuple(argv)
        self.calls.append(call)
        assert call[1:3] == ("service", "update"), f"unexpected docker command: {call}"
        service = call[-1]
        if service in self.missing_services:
            return SwarmCommandResult(call, 1, "", f"no such service: {service}")
        if service in self.failing_services:
            return SwarmCommandResult(call, 1, "", "update failed")
        return SwarmCommandResult(call, 0, "", "")

    @property
    def update_calls(self) -> list[tuple[str, ...]]:
        return list(self.calls)


def make_swarm_sync(
    tmp_path: Path,
    runner: FakeSwarmRunner,
    fetched: str | Exception = CONFIG_TEXT,
    services: tuple[str, ...] = SWARM_SERVICES,
) -> SwarmConfigSync:
    def fetcher(_: ConfigSyncSource) -> str:
        if isinstance(fetched, Exception):
            raise fetched
        return fetched

    return SwarmConfigSync(
        ConfigSyncSource.default(fetcher=fetcher),
        target_path=tmp_path / "master.yaml",
        rollout_services=services,
        runner=runner,
    )


def test_swarm_changed_config_writes_file_and_forces_rollout(tmp_path: Path) -> None:
    runner = FakeSwarmRunner()
    result = make_swarm_sync(tmp_path, runner).sync_once()

    assert result.changed is True
    assert result.reason == "updated"
    assert result.new_digest == CONFIG_DIGEST
    assert (tmp_path / "master.yaml").read_text(encoding="utf-8") == CONFIG_TEXT
    assert (tmp_path / "master.yaml.digest").read_text(
        encoding="utf-8"
    ).strip() == CONFIG_DIGEST
    assert runner.update_calls == [
        ("docker", "service", "update", "--detach", "--force", name)
        for name in SWARM_SERVICES
    ]


def test_swarm_rerun_unchanged_is_noop(tmp_path: Path) -> None:
    runner = FakeSwarmRunner()
    sync = make_swarm_sync(tmp_path, runner)
    sync.sync_once()
    calls_after_apply = len(runner.calls)

    result = sync.sync_once()

    assert result.changed is False
    assert result.reason == "already_current"
    assert result.current_digest == CONFIG_DIGEST
    assert len(runner.calls) == calls_after_apply


def test_swarm_fresh_instance_over_current_target_is_noop(tmp_path: Path) -> None:
    make_swarm_sync(tmp_path, FakeSwarmRunner()).sync_once()

    runner = FakeSwarmRunner()
    result = make_swarm_sync(tmp_path, runner).sync_once()

    assert result.changed is False
    assert result.reason == "already_current"
    assert runner.calls == []


def test_swarm_invalid_yaml_applies_nothing(tmp_path: Path) -> None:
    runner = FakeSwarmRunner()
    result = make_swarm_sync(tmp_path, runner, fetched="{{ not yaml").sync_once()

    assert result.changed is False
    assert result.reason == "invalid_config"
    assert not (tmp_path / "master.yaml").exists()
    assert runner.calls == []


def test_swarm_disallowed_kind_applies_nothing(tmp_path: Path) -> None:
    runner = FakeSwarmRunner()
    result = make_swarm_sync(
        tmp_path, runner, fetched="kind: Deployment\nmetadata:\n  name: x\n"
    ).sync_once()

    assert result.changed is False
    assert result.reason == "invalid_config"
    assert not (tmp_path / "master.yaml").exists()
    assert runner.calls == []


def test_swarm_secret_content_rejected_nothing_applied(tmp_path: Path) -> None:
    runner = FakeSwarmRunner()
    result = make_swarm_sync(
        tmp_path,
        runner,
        fetched="kind: Secret\nstringData:\n  token: hunter2\n",
    ).sync_once()

    assert result.changed is False
    assert result.reason == "secret_sync_rejected"
    assert not (tmp_path / "master.yaml").exists()
    assert runner.calls == []


def test_swarm_fetch_failure_logged_skip_tick_never_raises(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    runner = FakeSwarmRunner()
    sync = make_swarm_sync(tmp_path, runner, fetched=RuntimeError("github down"))
    sync_logger = logging.getLogger("platform_network.supervisor.config_sync")
    previously_disabled = sync_logger.disabled
    sync_logger.disabled = False
    try:
        with caplog.at_level(
            logging.WARNING, logger="platform_network.supervisor.config_sync"
        ):
            sync.run_once()
    finally:
        sync_logger.disabled = previously_disabled

    assert not (tmp_path / "master.yaml").exists()
    assert runner.calls == []
    assert any("fetch/validation failed" in record.message for record in caplog.records)


def test_swarm_rollout_failure_withholds_digest_and_retries(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(failing_services={"platform-broker"})
    sync = make_swarm_sync(tmp_path, runner)

    first = sync.sync_once()
    assert first.changed is True
    assert first.reason == "updated"
    assert (tmp_path / "master.yaml").read_text(encoding="utf-8") == CONFIG_TEXT
    assert not (tmp_path / "master.yaml.digest").exists()

    runner.failing_services.clear()
    second = sync.sync_once()
    assert second.changed is True
    assert second.reason == "rollout_retried"
    assert (tmp_path / "master.yaml.digest").read_text(
        encoding="utf-8"
    ).strip() == CONFIG_DIGEST

    third = sync.sync_once()
    assert third.reason == "already_current"


def test_swarm_missing_rollout_service_is_logged_skip_not_retry(
    tmp_path: Path,
) -> None:
    runner = FakeSwarmRunner(missing_services={"platform-broker"})
    sync = make_swarm_sync(tmp_path, runner)

    first = sync.sync_once()
    assert first.reason == "updated"
    assert (tmp_path / "master.yaml.digest").exists()

    second = sync.sync_once()
    assert second.reason == "already_current"


def test_swarm_builder_returns_wired_scheduled_task(tmp_path: Path) -> None:
    runner = FakeSwarmRunner()
    task = build_config_sync_task(
        Settings(),
        source=ConfigSyncSource.default(fetcher=lambda _: CONFIG_TEXT),
        target_path=tmp_path / "master.yaml",
        rollout_services=("platform-admin",),
        runner=runner,
    )

    assert task.name == "config-sync"
    assert task.interval_seconds == CONFIG_SYNC_INTERVAL_SECONDS
    task.run()
    assert (tmp_path / "master.yaml").read_text(encoding="utf-8") == CONFIG_TEXT
    assert runner.update_calls == [
        ("docker", "service", "update", "--detach", "--force", "platform-admin")
    ]


def test_swarm_defaults_preserve_contract_and_exclude_self() -> None:
    assert CONFIG_SYNC_INTERVAL_SECONDS == 60.0
    assert DEFAULT_CONFIG_TARGET_PATH == "/etc/platform/master.yaml"
    assert DEFAULT_ROLLOUT_SERVICES == (
        "platform-admin",
        "platform-proxy",
        "platform-broker",
    )
    assert "platform-config-sync" not in DEFAULT_ROLLOUT_SERVICES
    source = ConfigSyncSource.default()
    assert source.repository == "PlatformNetwork/platform"
    assert source.branch == "main"
    assert source.paths == ("deploy/helm/platform/values.yaml",)
    assert source.sync_secrets is False
    assert source.allowed_kinds == ("ConfigMap",)
