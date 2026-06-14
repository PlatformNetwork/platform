"""Tests for docker_max_concurrent / docker_timeout_seconds resource keys."""

import pytest

from platform_network.master.docker_orchestrator import (
    ChallengeResources,
    DockerOrchestrationError,
)


def test_from_mapping_parses_both_quota_keys() -> None:
    resources = ChallengeResources.from_mapping(
        {"docker_max_concurrent": "5", "docker_timeout_seconds": "600"}
    )
    assert resources.docker_max_concurrent == 5
    assert resources.docker_timeout_seconds == 600


def test_missing_quota_keys_default_to_none() -> None:
    resources = ChallengeResources.from_mapping({})
    assert resources.docker_max_concurrent is None
    assert resources.docker_timeout_seconds is None


def test_empty_quota_values_default_to_none() -> None:
    resources = ChallengeResources.from_mapping(
        {"docker_max_concurrent": "", "docker_timeout_seconds": ""}
    )
    assert resources.docker_max_concurrent is None
    assert resources.docker_timeout_seconds is None


@pytest.mark.parametrize("value", ["0", "-1", "ten", "1.5", "  "])
def test_invalid_docker_max_concurrent_rejected(value: str) -> None:
    with pytest.raises(DockerOrchestrationError, match="docker_max_concurrent"):
        ChallengeResources.from_mapping({"docker_max_concurrent": value})


@pytest.mark.parametrize("value", ["0", "-30", "soon"])
def test_invalid_docker_timeout_seconds_rejected(value: str) -> None:
    with pytest.raises(DockerOrchestrationError, match="docker_timeout_seconds"):
        ChallengeResources.from_mapping({"docker_timeout_seconds": value})


def test_operator_clamp_caps_author_values() -> None:
    resources = ChallengeResources.from_mapping(
        {"docker_max_concurrent": "9999", "docker_timeout_seconds": "86400"},
        max_concurrent_cap=10,
        timeout_seconds_cap=3600,
    )
    assert resources.docker_max_concurrent == 10
    assert resources.docker_timeout_seconds == 3600


def test_operator_clamp_keeps_values_under_cap() -> None:
    resources = ChallengeResources.from_mapping(
        {"docker_max_concurrent": "3", "docker_timeout_seconds": "60"},
        max_concurrent_cap=10,
        timeout_seconds_cap=3600,
    )
    assert resources.docker_max_concurrent == 3
    assert resources.docker_timeout_seconds == 60


def test_operator_clamp_ignores_missing_author_values() -> None:
    resources = ChallengeResources.from_mapping(
        {}, max_concurrent_cap=10, timeout_seconds_cap=3600
    )
    assert resources.docker_max_concurrent is None
    assert resources.docker_timeout_seconds is None


def test_invalid_operator_cap_rejected() -> None:
    with pytest.raises(DockerOrchestrationError, match="operator cap"):
        ChallengeResources.from_mapping(
            {"docker_max_concurrent": "5"}, max_concurrent_cap=0
        )


def test_direct_construction_validates_quota_fields() -> None:
    with pytest.raises(DockerOrchestrationError, match="docker_max_concurrent"):
        ChallengeResources(docker_max_concurrent=0)
    with pytest.raises(DockerOrchestrationError, match="docker_timeout_seconds"):
        ChallengeResources(docker_timeout_seconds=-5)
    resources = ChallengeResources(docker_max_concurrent=4, docker_timeout_seconds=120)
    assert resources.docker_max_concurrent == 4
    assert resources.docker_timeout_seconds == 120
