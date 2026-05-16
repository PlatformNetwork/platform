from __future__ import annotations

from pydantic import BaseModel, Field


class NetworkSettings(BaseModel):
    name: str = "platform"
    netuid: int = 0
    chain_endpoint: str | None = None
    wallet_name: str = "default"
    wallet_hotkey: str = "default"
    master_uid: int = 0


class MasterSettings(BaseModel):
    registry_url: str = "https://rpc.platform.network"
    admin_host: str = "0.0.0.0"
    admin_port: int = 8080
    proxy_host: str = "0.0.0.0"
    proxy_port: int = 8081
    epoch_interval_seconds: int = 360
    metagraph_cache_ttl_seconds: int = 300
    challenge_timeout_seconds: float = 10.0
    challenge_retries: int = 3
    registry_state_file: str = "/var/lib/platform/registry.json"
    upload_signature_ttl_seconds: int = 300
    upload_nonce_ttl_seconds: int = 86_400
    upload_max_body_bytes: int = 2_000_000
    upload_require_registered_hotkey: bool = True


class ValidatorSettings(BaseModel):
    registry_url: str = "https://rpc.platform.network"
    registry_retry_seconds: int = 15


class DatabaseSettings(BaseModel):
    url: str = "sqlite+aiosqlite:////var/lib/platform-db/platform.sqlite3"


class DockerSettings(BaseModel):
    network_name: str = "platform_challenges"
    secret_dir: str = "/var/lib/platform/secrets"
    internal_network: bool = True
    broker_host: str = "0.0.0.0"
    broker_port: int = 8082
    broker_url: str = "http://platform-docker-broker:8082"
    broker_workspace_dir: str = "/tmp/platform-docker-broker"
    gpu_server_state_file: str = "/var/lib/platform/gpu_servers.json"
    broker_allowed_images: list[str] = Field(
        default_factory=lambda: ["platformnetwork/", "ghcr.io/platformnetwork/"]
    )


class GpuServerSettings(BaseModel):
    id: str = Field(..., min_length=1, pattern=r"^[a-zA-Z0-9_.-]+$")
    base_url: str = Field(..., min_length=1)
    token: str | None = None
    token_file: str | None = None
    enabled: bool = True
    verify_tls: bool = True
    timeout_seconds: float = 30.0


class SecuritySettings(BaseModel):
    admin_token: str | None = None
    admin_token_file: str | None = None


class ObservabilitySettings(BaseModel):
    log_json: bool = True
    sentry_dsn: str | None = None
    otel_service_name: str = "platform"


class Settings(BaseModel):
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    master: MasterSettings = Field(default_factory=MasterSettings)
    validator: ValidatorSettings = Field(default_factory=ValidatorSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    docker: DockerSettings = Field(default_factory=DockerSettings)
    gpu_servers: list[GpuServerSettings] = Field(default_factory=list)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
