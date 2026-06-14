"""Unit tests for the supervisor challenge-image-updater (Task 19).

Fake registry + fake resolver + fake controller only — no network, no
dockerd, no real database.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from platform_network.config.settings import Settings
from platform_network.schemas.challenge import ChallengeStatus, ChallengeUpdate
from platform_network.supervisor.challenge_image_updater import (
    CHALLENGE_IMAGE_UPDATER_INTERVAL_SECONDS,
    ChallengeImageUpdater,
    build_challenge_image_updater_task,
)
from platform_network.validator.image_updater import ImageReference

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
BASE = "ghcr.io/platformnetwork/demo:latest"


def record(
    slug: str,
    image: str,
    status: ChallengeStatus = ChallengeStatus.ACTIVE,
) -> SimpleNamespace:
    return SimpleNamespace(slug=slug, image=image, status=status)


class FakeRegistry:
    def __init__(self, records: list[SimpleNamespace]) -> None:
        self.records = records
        self.updates: list[tuple[str, ChallengeUpdate]] = []

    async def list(self) -> list[SimpleNamespace]:
        return list(self.records)

    async def update(self, slug: str, update: ChallengeUpdate) -> None:
        self.updates.append((slug, update))


class FakeController:
    def __init__(self) -> None:
        self.restarts: list[str] = []

    async def restart(self, slug: str) -> dict[str, str]:
        self.restarts.append(slug)
        return {"slug": slug, "operation": "restart", "status": "ok"}


def make_resolver(digest: str):
    def resolver(reference: ImageReference) -> str:
        return digest

    return resolver


def make_updater(
    registry: FakeRegistry,
    controller: FakeController,
    resolver: Any,
) -> ChallengeImageUpdater:
    return ChallengeImageUpdater(
        registry_factory=lambda: registry,
        controller_factory=lambda _registry: controller,
        resolver=resolver,
    )


def test_changed_digest_updates_record_and_restarts_active() -> None:
    registry = FakeRegistry([record("demo", f"{BASE}@{DIGEST_A}")])
    controller = FakeController()
    make_updater(registry, controller, make_resolver(DIGEST_B)).run_once()
    assert registry.updates == [("demo", ChallengeUpdate(image=f"{BASE}@{DIGEST_B}"))]
    assert controller.restarts == ["demo"]


def test_unchanged_digest_is_a_noop() -> None:
    registry = FakeRegistry([record("demo", f"{BASE}@{DIGEST_A}")])
    controller = FakeController()
    make_updater(registry, controller, make_resolver(DIGEST_A)).run_once()
    assert registry.updates == []
    assert controller.restarts == []


def test_unpinned_record_is_updated_to_pinned_reference() -> None:
    registry = FakeRegistry([record("demo", BASE)])
    controller = FakeController()
    make_updater(registry, controller, make_resolver(DIGEST_A)).run_once()
    assert registry.updates == [("demo", ChallengeUpdate(image=f"{BASE}@{DIGEST_A}"))]
    assert controller.restarts == ["demo"]


@pytest.mark.parametrize("status", [ChallengeStatus.DRAFT, ChallengeStatus.DISABLED])
def test_draft_and_disabled_are_skipped_entirely(status: ChallengeStatus) -> None:
    calls: list[ImageReference] = []

    def resolver(reference: ImageReference) -> str:
        calls.append(reference)
        return DIGEST_B

    registry = FakeRegistry([record("demo", f"{BASE}@{DIGEST_A}", status)])
    controller = FakeController()
    make_updater(registry, controller, resolver).run_once()
    assert calls == []
    assert registry.updates == []
    assert controller.restarts == []


def test_inactive_is_updated_but_never_restarted() -> None:
    registry = FakeRegistry(
        [record("demo", f"{BASE}@{DIGEST_A}", ChallengeStatus.INACTIVE)]
    )
    controller = FakeController()
    make_updater(registry, controller, make_resolver(DIGEST_B)).run_once()
    assert registry.updates == [("demo", ChallengeUpdate(image=f"{BASE}@{DIGEST_B}"))]
    assert controller.restarts == []


@pytest.mark.parametrize(
    "image",
    [
        "docker.io/library/redis:7",
        "ghcr.io/platformnetwork/demo:sha-abc1234",
    ],
)
def test_non_ghcr_or_sha_tagged_images_are_skipped(image: str) -> None:
    registry = FakeRegistry([record("demo", image)])
    controller = FakeController()
    make_updater(registry, controller, make_resolver(DIGEST_B)).run_once()
    assert registry.updates == []
    assert controller.restarts == []


def test_resolver_failure_skips_challenge_but_siblings_proceed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def resolver(reference: ImageReference) -> str:
        if "broken" in reference.repository:
            raise RuntimeError("registry unreachable")
        return DIGEST_B

    registry = FakeRegistry(
        [
            record("broken", f"ghcr.io/platformnetwork/broken:latest@{DIGEST_A}"),
            record("demo", f"{BASE}@{DIGEST_A}"),
        ]
    )
    controller = FakeController()
    logger_name = "platform_network.supervisor.challenge_image_updater"
    with caplog.at_level("WARNING", logger=logger_name):
        make_updater(registry, controller, resolver).run_once()
    assert [slug for slug, _ in registry.updates] == ["demo"]
    assert controller.restarts == ["demo"]
    assert any("digest resolution failed" in message for message in caplog.messages)


def test_non_sha256_digest_is_refused() -> None:
    registry = FakeRegistry([record("demo", f"{BASE}@{DIGEST_A}")])
    controller = FakeController()
    make_updater(registry, controller, make_resolver("md5:nope")).run_once()
    assert registry.updates == []
    assert controller.restarts == []


def test_restart_failure_does_not_block_sibling_challenges() -> None:
    class ExplodingController(FakeController):
        async def restart(self, slug: str) -> dict[str, str]:
            if slug == "broken":
                raise RuntimeError("dockerd unavailable")
            return await super().restart(slug)

    registry = FakeRegistry(
        [
            record("broken", f"ghcr.io/platformnetwork/broken:latest@{DIGEST_A}"),
            record("demo", f"{BASE}@{DIGEST_A}"),
        ]
    )
    controller = ExplodingController()
    make_updater(registry, controller, make_resolver(DIGEST_B)).run_once()
    assert [slug for slug, _ in registry.updates] == ["broken", "demo"]
    assert controller.restarts == ["demo"]


def test_tick_never_raises_even_when_registry_listing_fails() -> None:
    class ExplodingRegistry(FakeRegistry):
        async def list(self) -> list[SimpleNamespace]:
            raise RuntimeError("database down")

    registry = ExplodingRegistry([])
    controller = FakeController()
    make_updater(registry, controller, make_resolver(DIGEST_B)).run_once()
    assert registry.updates == []
    assert controller.restarts == []


def test_builder_wires_task_name_interval_and_seams() -> None:
    registry = FakeRegistry([record("demo", f"{BASE}@{DIGEST_A}")])
    controller = FakeController()
    task = build_challenge_image_updater_task(
        Settings(),
        registry_factory=lambda: registry,
        controller_factory=lambda _registry: controller,
        resolver=make_resolver(DIGEST_B),
    )
    assert task.name == "challenge-image-updater"
    assert task.interval_seconds == CHALLENGE_IMAGE_UPDATER_INTERVAL_SECONDS
    task.run()
    assert registry.updates == [("demo", ChallengeUpdate(image=f"{BASE}@{DIGEST_B}"))]
    assert controller.restarts == ["demo"]


def test_builder_tag_override_retargets_mutable_base() -> None:
    registry = FakeRegistry(
        [record("demo", f"ghcr.io/platformnetwork/demo:main@{DIGEST_A}")]
    )
    controller = FakeController()
    task = build_challenge_image_updater_task(
        Settings(),
        registry_factory=lambda: registry,
        controller_factory=lambda _registry: controller,
        resolver=make_resolver(DIGEST_B),
        tag="main",
    )
    task.run()
    expected = f"ghcr.io/platformnetwork/demo:main@{DIGEST_B}"
    assert registry.updates == [("demo", ChallengeUpdate(image=expected))]
