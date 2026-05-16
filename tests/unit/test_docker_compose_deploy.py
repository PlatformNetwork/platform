from __future__ import annotations

from pathlib import Path

import yaml


def test_compose_deploy_has_expected_services_and_socket_scope() -> None:
    compose = yaml.safe_load(
        (Path(__file__).resolve().parents[2] / "docker/compose.yml").read_text(
            encoding="utf-8"
        )
    )
    services = compose["services"]

    for name in (
        "master-admin",
        "master-proxy",
        "platform-docker-broker",
        "validator",
        "gpu-agent",
    ):
        assert name in services
    assert "postgres" not in services

    socket_services = {
        name
        for name, service in services.items()
        if any(
            "/var/run/docker.sock" in volume for volume in service.get("volumes", [])
        )
    }
    assert socket_services == {
        "master-admin",
        "platform-docker-broker",
        "gpu-agent",
    }
    assert "platform_challenges" in services["platform-docker-broker"]["networks"]
    assert compose["networks"]["platform_challenges"]["attachable"] is True
    assert "platform_db" in compose["volumes"]
    assert "platform_state" in compose["volumes"]
    assert "platform_secrets" in compose["volumes"]
    assert any(
        "platform_db:/var/lib/platform-db" in volume
        for volume in services["master-admin"]["volumes"]
    )
    assert any(
        "platform_db:/var/lib/platform-db" in volume
        for volume in services["master-proxy"]["volumes"]
    )
    assert any(
        "platform_secrets:/var/lib/platform/secrets" in volume
        for volume in services["master-proxy"]["volumes"]
    )
    assert services["master-admin"]["environment"]["PLATFORM_DATABASE__URL"].startswith(
        "sqlite+aiosqlite:///"
    )
    assert "PLATFORM_DOCKER__BROKER_ALLOWED_IMAGES" not in services[
        "platform-docker-broker"
    ].get("environment", {})
    assert "healthcheck" in services["master-admin"]
    assert "healthcheck" in services["master-proxy"]
