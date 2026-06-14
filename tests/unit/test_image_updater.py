"""Unit tests for the supervisor image-updater (Task 18).

Fake resolver + fake runner only — no network, no dockerd.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

import pytest

from platform_network.config.settings import Settings
from platform_network.master.swarm_backend import SwarmCommandResult
from platform_network.supervisor.image_updater import (
    DEFAULT_FIRST_PARTY_TARGETS,
    IMAGE_UPDATER_INTERVAL_SECONDS,
    ImageUpdateTarget,
    SwarmImageUpdater,
    build_image_updater_task,
)
from platform_network.validator.image_updater import ImageReference

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
IMAGE = "ghcr.io/platformnetwork/platform-master:latest"


class FakeRunner:
    def __init__(
        self,
        current_images: dict[str, str] | None = None,
        *,
        update_returncode: int = 0,
    ) -> None:
        self.current_images = dict(current_images or {})
        self.update_returncode = update_returncode
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
        if call[1:3] == ("service", "inspect"):
            image = self.current_images.get(call[-1])
            if image is None:
                return SwarmCommandResult(call, 1, "", "no such service")
            return SwarmCommandResult(call, 0, f"{image}\n", "")
        if call[1:3] == ("service", "update"):
            return SwarmCommandResult(call, self.update_returncode, "", "boom")
        raise AssertionError(f"unexpected docker command: {call}")

    @property
    def update_calls(self) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[1:3] == ("service", "update")]


def make_resolver(digest: str):
    def resolver(reference: ImageReference) -> str:
        return digest

    return resolver


def make_updater(
    runner: FakeRunner,
    resolver,
    targets: tuple[ImageUpdateTarget, ...] = (
        ImageUpdateTarget(service="platform-admin", image=IMAGE),
    ),
) -> SwarmImageUpdater:
    return SwarmImageUpdater(targets, runner=runner, resolver=resolver)


def test_same_digest_is_a_noop() -> None:
    runner = FakeRunner({"platform-admin": f"{IMAGE}@{DIGEST_A}"})
    make_updater(runner, make_resolver(DIGEST_A)).run_once()
    assert runner.update_calls == []


def test_new_digest_issues_exactly_one_update_per_service() -> None:
    services = ("platform-admin", "platform-proxy")
    runner = FakeRunner({name: f"{IMAGE}@{DIGEST_A}" for name in services})
    targets = tuple(ImageUpdateTarget(service=name, image=IMAGE) for name in services)
    make_updater(runner, make_resolver(DIGEST_B), targets).run_once()
    assert len(runner.update_calls) == len(services)
    for call, name in zip(runner.update_calls, services, strict=True):
        assert call == (
            "docker",
            "service",
            "update",
            "--detach",
            "--image",
            f"{IMAGE}@{DIGEST_B}",
            name,
        )


def test_resolver_failure_logs_and_skips_update(
    caplog: pytest.LogCaptureFixture,
) -> None:
    runner = FakeRunner({"platform-admin": f"{IMAGE}@{DIGEST_A}"})

    def resolver(reference: ImageReference) -> str:
        raise RuntimeError("registry unreachable")

    updater = make_updater(runner, resolver)
    with caplog.at_level(logging.WARNING):
        updater.run_once()
    assert runner.update_calls == []
    assert any("digest resolution failed" in rec.message for rec in caplog.records)


def test_resolver_failure_does_not_block_other_targets() -> None:
    other_image = "ghcr.io/platformnetwork/other:latest"
    runner = FakeRunner(
        {
            "platform-admin": f"{IMAGE}@{DIGEST_A}",
            "platform-other": f"{other_image}@{DIGEST_A}",
        }
    )

    def resolver(reference: ImageReference) -> str:
        if reference.repository.endswith("platform-master"):
            raise RuntimeError("registry unreachable")
        return DIGEST_B

    targets = (
        ImageUpdateTarget(service="platform-admin", image=IMAGE),
        ImageUpdateTarget(service="platform-other", image=other_image),
    )
    make_updater(runner, resolver, targets).run_once()
    assert len(runner.update_calls) == 1
    assert runner.update_calls[0][-1] == "platform-other"


def test_untagged_image_rejected_without_any_docker_calls(
    caplog: pytest.LogCaptureFixture,
) -> None:
    runner = FakeRunner()
    targets = (
        ImageUpdateTarget(
            service="platform-admin",
            image="ghcr.io/platformnetwork/platform-master",
        ),
    )
    with caplog.at_level(logging.ERROR):
        make_updater(runner, make_resolver(DIGEST_B), targets).run_once()
    assert runner.calls == []
    assert any("untagged image" in rec.message for rec in caplog.records)


def test_non_sha256_resolver_result_rejected(
    caplog: pytest.LogCaptureFixture,
) -> None:
    runner = FakeRunner({"platform-admin": f"{IMAGE}@{DIGEST_A}"})
    with caplog.at_level(logging.ERROR):
        make_updater(runner, make_resolver("md5:deadbeef")).run_once()
    assert runner.update_calls == []
    assert any("refusing un-pinned update" in rec.message for rec in caplog.records)


def test_missing_service_skipped_without_update(
    caplog: pytest.LogCaptureFixture,
) -> None:
    runner = FakeRunner({})
    with caplog.at_level(logging.WARNING):
        make_updater(runner, make_resolver(DIGEST_B)).run_once()
    assert runner.update_calls == []
    assert any("cannot inspect service" in rec.message for rec in caplog.records)


def test_failed_service_update_logged_not_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    runner = FakeRunner({"platform-admin": f"{IMAGE}@{DIGEST_A}"}, update_returncode=1)
    with caplog.at_level(logging.ERROR):
        make_updater(runner, make_resolver(DIGEST_B)).run_once()
    assert len(runner.update_calls) == 1
    assert any("docker service update failed" in rec.message for rec in caplog.records)


def test_unpinned_current_image_is_updated() -> None:
    runner = FakeRunner({"platform-admin": IMAGE})
    make_updater(runner, make_resolver(DIGEST_B)).run_once()
    assert len(runner.update_calls) == 1
    assert runner.update_calls[0][-2] == f"{IMAGE}@{DIGEST_B}"


def test_builder_returns_wired_scheduled_task() -> None:
    runner = FakeRunner({"platform-admin": f"{IMAGE}@{DIGEST_A}"})
    targets = (ImageUpdateTarget(service="platform-admin", image=IMAGE),)
    task = build_image_updater_task(
        Settings(),
        targets=targets,
        resolver=make_resolver(DIGEST_B),
        runner=runner,
    )
    assert task.name == "image-updater"
    assert task.interval_seconds == IMAGE_UPDATER_INTERVAL_SECONDS
    task.run()
    assert len(runner.update_calls) == 1


def test_default_targets_cover_first_party_services() -> None:
    names = {target.service for target in DEFAULT_FIRST_PARTY_TARGETS}
    assert names == {
        "platform-admin",
        "platform-proxy",
        "platform-broker",
        "platform-config-sync",
    }
    assert all(
        target.image == IMAGE and "@" not in target.image
        for target in DEFAULT_FIRST_PARTY_TARGETS
    )
