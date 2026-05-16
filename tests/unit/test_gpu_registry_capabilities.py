from __future__ import annotations

from pathlib import Path

from platform_network.gpu.capabilities import ResourceCapabilityChecker
from platform_network.gpu.registry import FileGpuServerRegistry
from platform_network.master.docker_orchestrator import ChallengeResources
from platform_network.schemas.gpu_server import GpuServerCreate, GpuServerUpdate


def test_file_gpu_registry_crud_and_token_redaction(tmp_path: Path) -> None:
    registry = FileGpuServerRegistry(
        tmp_path / "gpu.json",
        secret_dir=tmp_path / "secrets",
    )

    created = registry.create(
        GpuServerCreate(
            id="gpu-a",
            base_url="https://gpu-a",
            token="super-secret-token",
            min_gpu_count=2,
        )
    )

    assert created.token_hint == "supe…oken"
    assert registry.get_token("gpu-a") == "super-secret-token"
    assert "super-secret-token" not in registry.state_file.read_text(encoding="utf-8")

    updated = registry.update("gpu-a", GpuServerUpdate(enabled=False))
    assert updated.enabled is False
    assert registry.set_enabled("gpu-a", True).enabled is True

    reloaded = FileGpuServerRegistry(
        tmp_path / "gpu.json",
        secret_dir=tmp_path / "secrets",
    )
    assert reloaded.get("gpu-a").base_url == "https://gpu-a"
    reloaded.delete("gpu-a")
    assert reloaded.list() == []


def test_resource_capability_checker_gpu_decisions(tmp_path: Path) -> None:
    registry = {
        "gpu-a": FileGpuServerRegistry(
            tmp_path / "unused.json", secret_dir=tmp_path
        ).create(GpuServerCreate(id="gpu-a", base_url="http://gpu", min_gpu_count=1))
    }
    checker = ResourceCapabilityChecker(registry)

    assert checker.check(ChallengeResources()).can_run is True
    assert checker.check(ChallengeResources(gpu_server="gpu-a", gpu_count=1)).can_run
    assert (
        checker.check(ChallengeResources(gpu_server="missing", gpu_count=1)).reason
        == "gpu_server_unknown"
    )
    assert (
        checker.check(ChallengeResources(gpu_server="gpu-a", gpu_count=2)).reason
        == "gpu_capacity_insufficient"
    )
