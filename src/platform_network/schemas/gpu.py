from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from platform_network.master.docker_orchestrator import ChallengeRuntime


class GpuChallengeResources(BaseModel):
    cpu: float | None = None
    memory: str | None = None
    gpu_count: int | None = None
    gpu_device_ids: list[str] = Field(default_factory=list)
    gpu_capabilities: list[str] = Field(default_factory=lambda: ["gpu"])


class GpuChallengeSpecRequest(BaseModel):
    slug: str
    image: str
    version: str | None = None
    challenge_token: str | None = None
    docker_broker_token: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)
    resources: GpuChallengeResources = Field(default_factory=GpuChallengeResources)
    required_capabilities: list[str] = Field(
        default_factory=lambda: ["get_weights", "proxy_routes"]
    )
    expected_api_version: str = "1.0"
    port: int = 8000
    recreate: bool = False


class GpuChallengeSlugRequest(BaseModel):
    slug: str
    remove: bool = False


class GpuChallengeRuntimeResponse(BaseModel):
    slug: str
    image: str
    container_id: str
    container_name: str
    internal_base_url: str
    sqlite_volume_name: str
    health: dict[str, Any]
    version: dict[str, Any]

    @classmethod
    def from_runtime(cls, runtime: ChallengeRuntime) -> GpuChallengeRuntimeResponse:
        return cls(
            slug=runtime.slug,
            image=runtime.image,
            container_id=runtime.container_id,
            container_name=runtime.container_name,
            internal_base_url=runtime.internal_base_url,
            sqlite_volume_name=runtime.sqlite_volume_name,
            health=runtime.health,
            version=runtime.version,
        )


class GpuChallengeStopResponse(BaseModel):
    status: str = "ok"
