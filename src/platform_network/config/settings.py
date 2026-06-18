from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

from platform_network.config.policy import validate_settings_policy


class NetworkSettings(BaseModel):
    name: str = "platform"
    netuid: int = 100
    chain_endpoint: str | None = None
    wallet_name: str = "default"
    wallet_hotkey: str = "default"
    wallet_path: str | None = None
    master_uid: int = 0


class MasterSettings(BaseModel):
    registry_url: str = "https://chain.platform.network"
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
    upload_max_body_bytes: int = 7_500_000
    upload_require_registered_hotkey: bool = True
    # ss58 hotkeys accepted without on-chain registration (QA/allowlist; empty in prod)
    upload_extra_registered_hotkeys: list[str] = Field(default_factory=list)


class ValidatorSettings(BaseModel):
    registry_url: str = "https://chain.platform.network"
    registry_retry_seconds: int = 15
    weights_url: str | None = None
    weights_interval_seconds: int = 360
    weights_timeout_seconds: float = 15.0
    weights_retries: int = 3
    weights_freshness_seconds: int = 720

    @property
    def resolved_weights_url(self) -> str:
        return self.weights_url or self.registry_url


class DatabaseSettings(BaseModel):
    url: str = "postgresql+asyncpg://platform:platform@postgres.platform.svc.cluster.local/platform"


class DockerSettings(BaseModel):
    network_name: str = "platform_challenges"
    secret_dir: str = "/var/lib/platform/secrets"
    internal_network: bool = True
    broker_host: str = "0.0.0.0"
    broker_port: int = 8082
    broker_url: str = "http://platform-docker-broker:8082"
    broker_workspace_dir: str = "/tmp/platform-docker-broker"
    broker_allowed_images: list[str] = Field(
        default_factory=lambda: ["ghcr.io/platformnetwork/"]
    )
    allow_privileged: bool = False
    broker_privileged_slugs: list[str] = Field(default_factory=list)
    broker_node_role: Literal["manager", "worker"] = "manager"
    broker_allow_privileged_escape: bool = False
    #: Challenge slugs whose Swarm jobs are bind-mounted the host Docker
    #: socket (Docker-out-of-Docker) so the job can create sibling task
    #: containers on the worker daemon. Swarm services cannot run
    #: ``--privileged`` (``docker service create`` rejects it), so this is the
    #: supported way to let a broker-created Swarm job spawn containers.
    #: Socket access is root-equivalent on the worker, so the empty default
    #: grants it to no one; gate enforced in ``SwarmBrokerService``.
    broker_docker_socket_slugs: list[str] = Field(default_factory=list)
    broker_docker_socket_path: str = "/var/run/docker.sock"
    #: Read-only mounts injected into the Swarm eval job for the same slugs as
    #: ``broker_docker_socket_slugs`` (e.g. the terminal-bench task cache + the
    #: frozen digest manifest, provisioned out-of-band onto a host path or named
    #: volume). Each entry is ``source:target`` where ``source`` is an absolute
    #: host path or a Docker named volume and ``target`` is the absolute mount
    #: path inside the job. Empty default mounts nothing.
    broker_eval_readonly_mounts: list[str] = Field(default_factory=list)
    # Challenge API services run on the manager/host; broker jobs run on
    # workers, steered to CPU- vs GPU-labeled nodes (platform.workload).
    challenge_placement_constraint: str | None = "node.role==manager"
    cpu_job_constraint: str | None = "node.labels.platform.workload==cpu"
    gpu_job_constraint: str | None = "node.labels.platform.workload==gpu"


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
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)

    @model_validator(mode="after")
    def validate_production_policy(self) -> Settings:
        validate_settings_policy(self)
        return self
