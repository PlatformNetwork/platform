from __future__ import annotations

from types import SimpleNamespace

import pytest

from platform_network.validator import image_updater
from platform_network.validator.image_updater import (
    DIGEST_ANNOTATION,
    ValidatorImageUpdater,
    extract_digest,
    parse_image_reference,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


class AppsApi:
    def __init__(self, deployment: SimpleNamespace) -> None:
        self.deployment = deployment
        self.patches: list[dict] = []

    def read_namespaced_deployment(self, name: str, namespace: str) -> SimpleNamespace:
        assert name == "platform-validator"
        assert namespace == "validator-test"
        return self.deployment

    def patch_namespaced_deployment(
        self, name: str, namespace: str, body: dict
    ) -> None:
        assert name == "platform-validator"
        assert namespace == "validator-test"
        self.patches.append(body)


class CoreApi:
    def __init__(self, image_id: str | None = None) -> None:
        self.image_id = image_id

    def list_namespaced_pod(
        self, namespace: str, label_selector: str
    ) -> SimpleNamespace:
        assert namespace == "validator-test"
        assert label_selector == "app=validator"
        statuses = []
        if self.image_id:
            statuses.append(SimpleNamespace(name="validator", image_id=self.image_id))
        return SimpleNamespace(
            items=[SimpleNamespace(status=SimpleNamespace(container_statuses=statuses))]
        )


def deployment(
    *,
    image: str = "ghcr.io/platformnetwork/platform:latest",
    metadata_digest: str | None = None,
    template_digest: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        metadata=SimpleNamespace(
            annotations={DIGEST_ANNOTATION: metadata_digest} if metadata_digest else {}
        ),
        spec=SimpleNamespace(
            selector=SimpleNamespace(match_labels={"app": "validator"}),
            template=SimpleNamespace(
                metadata=SimpleNamespace(
                    annotations={DIGEST_ANNOTATION: template_digest}
                    if template_digest
                    else {}
                ),
                spec=SimpleNamespace(
                    containers=[SimpleNamespace(name="validator", image=image)]
                ),
            ),
        ),
    )


def test_parse_image_reference_defaults_registry_and_tag() -> None:
    parsed = parse_image_reference("busybox")

    assert parsed.registry == "docker.io"
    assert parsed.repository == "library/busybox"
    assert parsed.tag == "latest"


def test_extract_digest_from_container_image_id() -> None:
    assert extract_digest(f"docker-pullable://example@{DIGEST_A}") == DIGEST_A


def test_digest_pinned_images_do_not_patch(monkeypatch: pytest.MonkeyPatch) -> None:
    updater = ValidatorImageUpdater(AppsApi(deployment()), CoreApi())
    monkeypatch.setattr(
        image_updater, "resolve_remote_digest", lambda *args, **kwargs: DIGEST_A
    )

    changed = updater.refresh(
        namespace="validator-test",
        deployment="platform-validator",
        container="validator",
        image=f"ghcr.io/platformnetwork/platform:3.0.0@{DIGEST_A}",
    )

    assert changed is False


def test_matching_recorded_digest_does_not_patch_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apps = AppsApi(deployment(metadata_digest=DIGEST_A))
    updater = ValidatorImageUpdater(apps, CoreApi())
    monkeypatch.setattr(
        image_updater, "resolve_remote_digest", lambda *args, **kwargs: DIGEST_A
    )

    changed = updater.refresh(
        namespace="validator-test",
        deployment="platform-validator",
        container="validator",
        image="ghcr.io/platformnetwork/platform:latest",
    )

    assert changed is False
    assert apps.patches == []


def test_matching_running_pod_digest_records_metadata_without_rollout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apps = AppsApi(deployment())
    updater = ValidatorImageUpdater(
        apps, CoreApi(f"docker-pullable://image@{DIGEST_A}")
    )
    monkeypatch.setattr(
        image_updater, "resolve_remote_digest", lambda *args, **kwargs: DIGEST_A
    )

    changed = updater.refresh(
        namespace="validator-test",
        deployment="platform-validator",
        container="validator",
        image="ghcr.io/platformnetwork/platform:latest",
    )

    assert changed is False
    assert apps.patches == [
        {"metadata": {"annotations": {DIGEST_ANNOTATION: DIGEST_A}}}
    ]


def test_changed_digest_patches_template_image(monkeypatch: pytest.MonkeyPatch) -> None:
    apps = AppsApi(deployment(metadata_digest=DIGEST_A, template_digest=DIGEST_A))
    updater = ValidatorImageUpdater(
        apps, CoreApi(f"docker-pullable://image@{DIGEST_A}")
    )
    monkeypatch.setattr(
        image_updater, "resolve_remote_digest", lambda *args, **kwargs: DIGEST_B
    )

    changed = updater.refresh(
        namespace="validator-test",
        deployment="platform-validator",
        container="validator",
        image="ghcr.io/platformnetwork/platform:latest",
    )

    assert changed is True
    patch = apps.patches[0]
    assert patch["metadata"]["annotations"][DIGEST_ANNOTATION] == DIGEST_B
    assert (
        patch["spec"]["template"]["metadata"]["annotations"][DIGEST_ANNOTATION]
        == DIGEST_B
    )
    assert patch["spec"]["template"]["spec"]["containers"] == [
        {
            "name": "validator",
            "image": f"ghcr.io/platformnetwork/platform:latest@{DIGEST_B}",
        }
    ]
