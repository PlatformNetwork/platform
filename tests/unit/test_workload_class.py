"""Tests for ChallengeSpec.workload_class (job vs service scheduling class)."""

from __future__ import annotations

from typing import Any

import pytest

from platform_network.master.docker_orchestrator import (
    ChallengeSpec,
    DockerOrchestrationError,
)
from platform_network.master.workload_ledger import WorkloadEntry


def test_challenge_spec_defaults_to_job() -> None:
    spec = ChallengeSpec(slug="eval-run", image="ghcr.io/platformnetwork/eval:1")
    assert spec.workload_class == "job"


def test_challenge_spec_accepts_explicit_service() -> None:
    spec = ChallengeSpec(
        slug="prism",
        image="ghcr.io/platformnetwork/prism:1",
        workload_class="service",
    )
    assert spec.workload_class == "service"


def test_challenge_spec_rejects_invalid_workload_class() -> None:
    with pytest.raises(DockerOrchestrationError, match="workload_class"):
        ChallengeSpec(
            slug="prism",
            image="ghcr.io/platformnetwork/prism:1",
            workload_class="daemon",  # type: ignore[arg-type]
        )


def test_challenge_spec_default_matches_workload_ledger_default() -> None:
    entry = WorkloadEntry(key="svc-1", kind="swarm_service", challenge_slug="prism")
    spec = ChallengeSpec(slug="eval-run", image="ghcr.io/platformnetwork/eval:1")
    assert spec.workload_class == entry.workload_class == "job"


def test_long_lived_api_construction_sites_use_service() -> None:
    """Every challenge API container spec must be schedulable as a service."""

    from platform_network.gpu.agent import _to_challenge_spec
    from platform_network.schemas.gpu import GpuChallengeSpecRequest

    request = GpuChallengeSpecRequest(
        slug="prism",
        image="ghcr.io/platformnetwork/prism:1",
    )
    assert _to_challenge_spec(request).workload_class == "service"


@pytest.mark.asyncio
async def test_cli_runtime_controller_spec_is_service() -> None:
    from platform_network.cli_app.main import DockerRuntimeController

    class _Record:
        slug = "prism"
        image = "ghcr.io/platformnetwork/prism:1"
        version = "1.0.0"
        env: dict[str, str] = {}
        resources: dict[str, str] = {}
        required_capabilities: tuple[str, ...] = ()
        internal_base_url = "http://challenge-prism:8080"
        metadata: dict[str, Any] = {}

    class _Registry:
        async def get(self, slug: str) -> _Record:
            return _Record()

        def get_token(self, slug: str) -> str:
            return "token"

    controller = DockerRuntimeController(registry=_Registry(), orchestrator=None)
    spec = await controller._spec("prism")
    assert spec.workload_class == "service"
