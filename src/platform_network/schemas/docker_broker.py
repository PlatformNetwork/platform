"""Schemas for the internal Docker broker API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class BrokerMount(BaseModel):
    target: str = Field(..., min_length=1)
    read_only: bool = True
    source_type: str = "directory"
    source_name: str = "."
    archive_b64: str = Field(..., min_length=1)


class BrokerLimits(BaseModel):
    cpus: float = 2.0
    memory: str = "4g"
    memory_swap: str | None = "4g"
    pids_limit: int = 512
    network: str = "none"
    read_only: bool = True
    user: str | None = None
    tmpfs: tuple[str, ...] = ("/tmp:rw,noexec,nosuid,size=512m",)
    ulimits: tuple[str, ...] = ("nofile=1024:1024",)


class BrokerRunRequest(BaseModel):
    job_id: str = Field(..., min_length=1, max_length=128)
    task_id: str | None = Field(default=None, max_length=256)
    image: str = Field(..., min_length=1, max_length=255)
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


class BrokerCleanupRequest(BaseModel):
    job_id: str = Field(..., min_length=1, max_length=128)


class BrokerCleanupResponse(BaseModel):
    status: str = "ok"
