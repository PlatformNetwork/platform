from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

from platform_network.config.policy import validate_settings_policy


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


class RuntimeSettings(BaseModel):
    backend: str = Field(default="docker", pattern=r"^(docker|kubernetes)$")


class KubernetesAutoscalingSettings(BaseModel):
    enabled: bool = True
    keda_enabled: bool = False
    min_replicas: int = Field(default=1, ge=1)
    max_replicas: int = Field(default=3, ge=1)
    target_cpu_utilization: int = Field(default=70, ge=1, le=100)

    @model_validator(mode="after")
    def validate_bounds(self) -> KubernetesAutoscalingSettings:
        if self.max_replicas < self.min_replicas:
            raise ValueError(
                "max_replicas must be greater than or equal to min_replicas"
            )
        return self


class KubernetesTargetDefaultsSettings(BaseModel):
    image_pull_secrets: list[str] = Field(default_factory=list)
    gpu_resource_name: str = "nvidia.com/gpu"
    runtime_class_name: str | None = None
    node_selector: dict[str, str] = Field(default_factory=dict)
    tolerations: list[dict[str, object]] = Field(default_factory=list)


class KubernetesSettings(BaseModel):
    namespace: str = "platform"
    in_cluster: bool = True
    kubeconfig: str | None = None
    target_state_file: str = "/var/lib/platform/kubernetes_targets.json"
    service_account: str = "platform-master"
    image_pull_secrets: list[str] = Field(default_factory=list)
    storage_class: str | None = None
    storage_size: str = "10Gi"
    challenge_mode: str = Field(
        default="statefulset", pattern=r"^(statefulset|deployment)$"
    )
    broker_backend: str = Field(default="docker", pattern=r"^(docker|kubernetes)$")
    gpu_resource_name: str = "nvidia.com/gpu"
    node_selector: dict[str, str] = Field(default_factory=dict)
    tolerations: list[dict[str, object]] = Field(default_factory=list)
    runtime_class_name: str | None = None
    target_defaults: KubernetesTargetDefaultsSettings = Field(
        default_factory=KubernetesTargetDefaultsSettings
    )
    autoscaling: KubernetesAutoscalingSettings = Field(
        default_factory=KubernetesAutoscalingSettings
    )


class GpuServerSettings(BaseModel):
    id: str = Field(..., min_length=1, pattern=r"^[a-zA-Z0-9_.-]+$")
    base_url: str = Field(..., min_length=1)
    token: str | None = None
    token_file: str | None = None
    enabled: bool = True
    verify_tls: bool = True
    timeout_seconds: float = 30.0


class KubernetesTargetSettings(BaseModel):
    id: str = Field(..., min_length=1, pattern=r"^[a-zA-Z0-9_.-]+$")
    mode: Literal["direct", "agent"] = "direct"
    api_url: str | None = None
    agent_url: str | None = None
    namespace: str = Field(default="platform", min_length=1)
    service_account: str | None = "platform-master"
    kubeconfig: str | None = None
    kubeconfig_file: str | None = None
    agent_token: str | None = None
    agent_token_file: str | None = None
    enabled: bool = True
    draining: bool = False
    verify_tls: bool = True
    timeout_seconds: float = 30.0
    description: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)
    gpu_count: int = Field(default=0, ge=0)
    storage_class: str | None = None
    node_selector: dict[str, str] = Field(default_factory=dict)
    tolerations: list[dict[str, object]] = Field(default_factory=list)
    runtime_class_name: str | None = None


class SecuritySettings(BaseModel):
    admin_token: str | None = None
    admin_token_file: str | None = None


class ObservabilitySettings(BaseModel):
    log_json: bool = True
    sentry_dsn: str | None = None
    otel_service_name: str = "platform"


class Settings(BaseModel):
    environment: str = "development"
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    master: MasterSettings = Field(default_factory=MasterSettings)
    validator: ValidatorSettings = Field(default_factory=ValidatorSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    docker: DockerSettings = Field(default_factory=DockerSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    kubernetes: KubernetesSettings = Field(default_factory=KubernetesSettings)
    gpu_servers: list[GpuServerSettings] = Field(default_factory=list)
    kubernetes_targets: list[KubernetesTargetSettings] = Field(default_factory=list)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)

    @model_validator(mode="after")
    def validate_production_policy(self) -> Settings:
        validate_settings_policy(self)
        return self
