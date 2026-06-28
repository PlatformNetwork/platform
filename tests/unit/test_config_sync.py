from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path

import pytest
import yaml

from base.config.loader import load_settings
from base.config.settings import Settings
from base.master.swarm_backend import SwarmCommandResult
from base.supervisor.config_source import ConfigSyncSource, _digest
from base.supervisor.config_sync import (
    CONFIG_SYNC_INTERVAL_SECONDS,
    DEFAULT_CONFIG_TARGET_PATH,
    DEFAULT_ROLLOUT_SERVICES,
    SwarmConfigSync,
    build_config_sync_task,
)

ROOT = Path(__file__).resolve().parents[2]


def test_config_defaults_to_base_subnet_netuid() -> None:
    assert load_settings(None).network.netuid == 100


def test_example_configs_default_to_base_subnet_netuid() -> None:
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


def test_default_github_source_contract_uses_base_main_without_secrets() -> None:
    source = ConfigSyncSource.default()

    assert source.repository == "BaseIntelligence/base"
    assert source.branch == "main"
    assert source.sync_secrets is False
    assert "deploy/swarm/master.yaml" in source.paths
    assert "Secret" not in source.allowed_kinds


# ---------------------------------------------------------------------------
# Supervisor Swarm config-sync (Task 20) — fake fetcher + fake runner only.
# ---------------------------------------------------------------------------

CONFIG_TEXT = "environment: production\n"
CONFIG_DIGEST = _digest(CONFIG_TEXT)
SWARM_SERVICES = ("base-admin", "base-broker")


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
    sync_logger = logging.getLogger("base.supervisor.config_sync")
    previously_disabled = sync_logger.disabled
    sync_logger.disabled = False
    try:
        with caplog.at_level(logging.WARNING, logger="base.supervisor.config_sync"):
            sync.run_once()
    finally:
        sync_logger.disabled = previously_disabled

    assert not (tmp_path / "master.yaml").exists()
    assert runner.calls == []
    assert any("fetch/validation failed" in record.message for record in caplog.records)


def test_swarm_rollout_failure_withholds_digest_and_retries(tmp_path: Path) -> None:
    runner = FakeSwarmRunner(failing_services={"base-broker"})
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
    runner = FakeSwarmRunner(missing_services={"base-broker"})
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
        rollout_services=("base-admin",),
        runner=runner,
    )

    assert task.name == "config-sync"
    assert task.interval_seconds == CONFIG_SYNC_INTERVAL_SECONDS
    task.run()
    assert (tmp_path / "master.yaml").read_text(encoding="utf-8") == CONFIG_TEXT
    assert runner.update_calls == [
        ("docker", "service", "update", "--detach", "--force", "base-admin")
    ]


def test_swarm_defaults_preserve_contract_and_exclude_self() -> None:
    assert CONFIG_SYNC_INTERVAL_SECONDS == 60.0
    assert DEFAULT_CONFIG_TARGET_PATH == "/etc/base/master.yaml"
    assert DEFAULT_ROLLOUT_SERVICES == (
        "base-master-proxy",
        "base-broker",
    )
    assert "base-proxy" not in DEFAULT_ROLLOUT_SERVICES
    assert "base-admin" not in DEFAULT_ROLLOUT_SERVICES
    assert "base-config-sync" not in DEFAULT_ROLLOUT_SERVICES
    source = ConfigSyncSource.default()
    assert source.repository == "BaseIntelligence/base"
    assert source.branch == "main"
    assert source.paths == ("deploy/swarm/master.yaml",)
    assert source.sync_secrets is False
    assert source.allowed_kinds == ("ConfigMap",)
