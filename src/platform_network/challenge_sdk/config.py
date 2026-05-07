"""Shared challenge-side SDK configuration helpers."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class DockerExecutorSettings(BaseSettings):
    """Environment-backed Docker executor settings for challenges."""

    model_config = SettingsConfigDict(env_prefix="CHALLENGE_", extra="ignore")

    docker_enabled: bool = False
    docker_bin: str = "docker"
    docker_network: str = "none"
    docker_cpus: float = 2.0
    docker_memory: str = "4g"
    docker_memory_swap: str | None = "4g"
    docker_pids_limit: int = 512
    docker_read_only: bool = True
    docker_user: str | None = None
    docker_allowed_images: tuple[str, ...] = ()
    docker_backend: str = "cli"
    docker_broker_url: str | None = None
    docker_broker_token: str | None = None
    docker_broker_token_file: str | None = None
