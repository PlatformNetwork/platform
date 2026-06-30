"""Settings-driven image-updater targets + validator-agent auto-roll (G-A5).

Covers VAL-CODE-AUTO-003: the image-updater targets are configurable (not
hardcoded to only the master services), the default preserves the two master
services (back-compat), and a configured validator-agent target tracking the
mutable validator runtime image is registered and rolled on a digest change.
"""

from __future__ import annotations

from collections.abc import Sequence

from base.config.settings import (
    DEFAULT_VALIDATOR_AGENT_SERVICE,
    DEFAULT_VALIDATOR_RUNTIME_IMAGE,
    ImageUpdateTargetSetting,
    Settings,
    SupervisorSettings,
)
from base.master.swarm_backend import SwarmCommandResult
from base.supervisor.image_ref import ImageReference
from base.supervisor.image_updater import (
    DEFAULT_FIRST_PARTY_TARGETS,
    ImageUpdateTarget,
    SwarmImageUpdater,
    resolve_image_update_targets,
)
from base.supervisor.tasks import build_scheduled_tasks

DIGEST_OLD = "sha256:" + "a" * 64
DIGEST_NEW = "sha256:" + "b" * 64
MASTER_SERVICES = {"base-master-proxy", "base-docker-broker"}


def _settings(**supervisor: object) -> Settings:
    return Settings(supervisor=SupervisorSettings(**supervisor))  # type: ignore[arg-type]


def _image_updater_targets(settings: Settings) -> tuple[ImageUpdateTarget, ...]:
    tasks, _gate = build_scheduled_tasks(settings)
    image_updater = next(t for t in tasks if t.name == "image-updater")
    return tuple(image_updater.run.__self__._targets)  # type: ignore[attr-defined]


class _FakeRunner:
    def __init__(self, current_images: dict[str, str]) -> None:
        self._current_images = dict(current_images)
        self.update_calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        input_text: str | None = None,
        timeout_seconds: float | None = None,
    ) -> SwarmCommandResult:
        call = tuple(argv)
        if call[1:3] == ("service", "inspect"):
            image = self._current_images.get(call[-1])
            if image is None:
                return SwarmCommandResult(call, 1, "", "no such service")
            return SwarmCommandResult(call, 0, f"{image}\n", "")
        if call[1:3] == ("service", "update"):
            self.update_calls.append(call)
            return SwarmCommandResult(call, 0, "", "")
        raise AssertionError(f"unexpected docker command: {call}")


# ---------------------------------------------------------------------------
# Default / back-compat: the two master services are preserved when unset.
# ---------------------------------------------------------------------------


def test_default_targets_preserve_the_two_master_services() -> None:
    targets = resolve_image_update_targets(Settings())
    assert targets == DEFAULT_FIRST_PARTY_TARGETS
    assert {t.service for t in targets} == MASTER_SERVICES


def test_build_scheduled_tasks_default_image_updater_targets_unchanged() -> None:
    assert {t.service for t in _image_updater_targets(_settings())} == MASTER_SERVICES


# ---------------------------------------------------------------------------
# Configurable: an explicit list drives the targets.
# ---------------------------------------------------------------------------


def test_targets_are_settings_driven() -> None:
    custom = [
        ImageUpdateTargetSetting(
            service="custom-svc",
            image="ghcr.io/baseintelligence/base-master:latest",
        ),
    ]
    targets = resolve_image_update_targets(_settings(image_updater_targets=custom))
    assert targets == (
        ImageUpdateTarget(
            service="custom-svc",
            image="ghcr.io/baseintelligence/base-master:latest",
        ),
    )


def test_build_scheduled_tasks_honours_configured_targets() -> None:
    custom = [ImageUpdateTargetSetting(service="custom-svc", image="ghcr.io/x:latest")]
    targets = _image_updater_targets(_settings(image_updater_targets=custom))
    assert [t.service for t in targets] == ["custom-svc"]


# ---------------------------------------------------------------------------
# Validator-agent target: present/derivable and tracks the runtime image.
# ---------------------------------------------------------------------------


def test_validator_runtime_image_default_is_the_mutable_runtime_tag() -> None:
    assert DEFAULT_VALIDATOR_RUNTIME_IMAGE == (
        "ghcr.io/baseintelligence/base-validator-runtime:latest"
    )


def test_validator_agent_target_appended_when_enabled() -> None:
    targets = resolve_image_update_targets(
        _settings(validator_agent_target_enabled=True)
    )
    services = {t.service for t in targets}
    # Back-compat master services stay present...
    assert MASTER_SERVICES <= services
    # ...plus the validator-agent target tracking the runtime image.
    validator = next(t for t in targets if t.service == DEFAULT_VALIDATOR_AGENT_SERVICE)
    assert validator.image == DEFAULT_VALIDATOR_RUNTIME_IMAGE


def test_validator_only_targets_on_a_validator_node() -> None:
    # A validator NODE watches ONLY its agent: empty master list + toggle on.
    targets = resolve_image_update_targets(
        _settings(image_updater_targets=[], validator_agent_target_enabled=True)
    )
    assert targets == (
        ImageUpdateTarget(
            service=DEFAULT_VALIDATOR_AGENT_SERVICE,
            image=DEFAULT_VALIDATOR_RUNTIME_IMAGE,
        ),
    )


def test_validator_target_not_duplicated_when_already_listed() -> None:
    explicit = [
        ImageUpdateTargetSetting(
            service=DEFAULT_VALIDATOR_AGENT_SERVICE,
            image=DEFAULT_VALIDATOR_RUNTIME_IMAGE,
        )
    ]
    targets = resolve_image_update_targets(
        _settings(image_updater_targets=explicit, validator_agent_target_enabled=True)
    )
    assert [t.service for t in targets] == [DEFAULT_VALIDATOR_AGENT_SERVICE]


def test_build_scheduled_tasks_registers_validator_agent_target() -> None:
    targets = _image_updater_targets(_settings(validator_agent_target_enabled=True))
    assert any(t.service == DEFAULT_VALIDATOR_AGENT_SERVICE for t in targets)


def test_custom_validator_service_name_and_image_respected() -> None:
    targets = resolve_image_update_targets(
        _settings(
            image_updater_targets=[],
            validator_agent_target_enabled=True,
            validator_agent_service="base-validator-prod",
            validator_agent_image="ghcr.io/baseintelligence/base:latest",
        )
    )
    assert targets == (
        ImageUpdateTarget(
            service="base-validator-prod",
            image="ghcr.io/baseintelligence/base:latest",
        ),
    )


# ---------------------------------------------------------------------------
# Roll: a configured validator-agent target is rolled on a digest change.
# ---------------------------------------------------------------------------


def test_validator_agent_service_rolled_on_digest_change() -> None:
    runner = _FakeRunner(
        {
            DEFAULT_VALIDATOR_AGENT_SERVICE: (
                f"{DEFAULT_VALIDATOR_RUNTIME_IMAGE}@{DIGEST_OLD}"
            )
        }
    )

    def resolver(reference: ImageReference) -> str:
        return DIGEST_NEW

    targets = resolve_image_update_targets(
        _settings(image_updater_targets=[], validator_agent_target_enabled=True)
    )
    SwarmImageUpdater(targets, runner=runner, resolver=resolver).run_once()

    assert len(runner.update_calls) == 1
    call = runner.update_calls[0]
    assert call[-1] == DEFAULT_VALIDATOR_AGENT_SERVICE
    image_arg = call[call.index("--image") + 1]
    assert image_arg == f"{DEFAULT_VALIDATOR_RUNTIME_IMAGE}@{DIGEST_NEW}"


def test_validator_agent_service_noop_when_digest_matches() -> None:
    runner = _FakeRunner(
        {
            DEFAULT_VALIDATOR_AGENT_SERVICE: (
                f"{DEFAULT_VALIDATOR_RUNTIME_IMAGE}@{DIGEST_NEW}"
            )
        }
    )

    def resolver(reference: ImageReference) -> str:
        return DIGEST_NEW

    targets = resolve_image_update_targets(
        _settings(image_updater_targets=[], validator_agent_target_enabled=True)
    )
    SwarmImageUpdater(targets, runner=runner, resolver=resolver).run_once()
    assert runner.update_calls == []
