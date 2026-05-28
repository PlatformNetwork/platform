"""Schemas for the internal Docker broker API."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field


class BrokerMount(BaseModel):
    target: str = Field(..., min_length=1)
    read_only: bool = True
    source_type: str = "directory"
    source_name: str = "."
    archive_b64: str = Field(..., min_length=1)


class BrokerLimits(BaseModel):
    cpus: float = Field(default=2.0, gt=0)
    memory: str = Field(default="4g", min_length=1)
    memory_swap: str | None = Field(default="4g", min_length=1)
    pids_limit: int = Field(default=512, ge=1)
    gpu_count: Annotated[int, Field(strict=True, ge=1)] | None = None
    network: str = "none"
    read_only: bool = True
    user: str | None = None
    tmpfs: tuple[str, ...] = ("/tmp:rw,noexec,nosuid,size=512m",)
    ulimits: tuple[str, ...] = ("nofile=1024:1024",)
    cap_drop: tuple[str, ...] = ("ALL",)
    security_opt: tuple[str, ...] = ("no-new-privileges",)
    init: bool = True


class BrokerRunRequest(BaseModel):
    job_id: str = Field(..., min_length=1, max_length=128)
    task_id: str | None = Field(default=None, max_length=256)
    image: str = Field(..., min_length=1, max_length=255)
    image_pull_policy: Literal["Always", "IfNotPresent", "Never"] | None = None
    command: list[str] = Field(..., min_length=1)
    workdir: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)
    limits: BrokerLimits = Field(default_factory=BrokerLimits)
    mounts: list[BrokerMount] = Field(default_factory=list)
    timeout_seconds: int = Field(default=900, ge=1, le=86_400)


class BrokerRunResponse(BaseModel):
    container_name: str
    stdout: str = ""
    stderr: str = ""
    returncode: int
    timed_out: bool = False


class BrokerContainerInfo(BaseModel):
    container_id: str
    container_name: str
    image: str = ""
    status: str = ""
    job_id: str | None = None
    task_id: str | None = None
    created: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)


class BrokerListRequest(BaseModel):
    job_id: str | None = Field(default=None, max_length=128)


class BrokerListResponse(BaseModel):
    containers: list[BrokerContainerInfo] = Field(default_factory=list)


class BrokerCleanupRequest(BaseModel):
    job_id: str = Field(..., min_length=1, max_length=128)


class BrokerCleanupResponse(BaseModel):
    status: str = "ok"
