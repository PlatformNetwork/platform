from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

from base.config.policy import validate_settings_policy


class NetworkSettings(BaseModel):
    name: str = "base"
    netuid: int = 100
    chain_endpoint: str | None = None
    wallet_name: str = "default"
    wallet_hotkey: str = "default"
    wallet_path: str | None = None
    master_uid: int = 0


class MasterSettings(BaseModel):
    registry_url: str = "https://chain.joinbase.ai"
    # Ignored back-compat: the admin/registry surface is served by the proxy on
    # proxy_port (single public API); there is no separate admin listener.
    admin_host: str = "0.0.0.0"
    admin_port: int = 8080
    proxy_host: str = "0.0.0.0"
    proxy_port: int = 8081
    epoch_interval_seconds: int = 360
    metagraph_cache_ttl_seconds: int = 300
    challenge_timeout_seconds: float = 10.0
    challenge_retries: int = 3
    registry_state_file: str = "/var/lib/base/registry.json"
    upload_signature_ttl_seconds: int = 300
    upload_nonce_ttl_seconds: int = 86_400
    upload_max_body_bytes: int = 7_500_000
    upload_require_registered_hotkey: bool = True
    # ss58 hotkeys accepted without on-chain registration (QA/allowlist; empty in prod)
    upload_extra_registered_hotkeys: list[str] = Field(default_factory=list)
    # Validator coordination plane (architecture.md sec 4). The proxy serves the
    # hotkey-signed register/heartbeat/pull/progress/result routes, returns
    # ``validator_heartbeat_interval_seconds`` to validators, marks a validator
    # offline once its last heartbeat exceeds ``validator_heartbeat_timeout_seconds``,
    # and runs the crash-detection loop every ``validator_health_interval_seconds``.
    validator_heartbeat_interval_seconds: int = 60
    validator_heartbeat_timeout_seconds: int = 180
    validator_health_interval_seconds: float = 60.0
    validator_signature_ttl_seconds: int = 300
    validator_nonce_ttl_seconds: int = 86_400
    assignment_lease_seconds: int = 900


class ValidatorSettings(BaseModel):
    registry_url: str = "https://chain.joinbase.ai"
    registry_retry_seconds: int = 15
    weights_url: str | None = None
    weights_interval_seconds: int = 360
    weights_timeout_seconds: float = 15.0
    weights_retries: int = 3
    weights_freshness_seconds: int = 720
    # RUNTIME-OFF gate for the supervisor on-chain weights task (plan Task 8).
    # Defaults False so a deploy NEVER auto-commits weights on-chain; the first
    # on-chain commit is human-gated (plan Task 27) by flipping this flag.
    submit_on_chain_enabled: bool = False

    @property
    def resolved_weights_url(self) -> str:
        return self.weights_url or self.registry_url


class DatabaseSettings(BaseModel):
    url: str = "postgresql+asyncpg://base:base@postgres.base.svc.cluster.local/base"


class DockerSettings(BaseModel):
    network_name: str = "base_challenges"
    secret_dir: str = "/var/lib/base/secrets"
    internal_network: bool = True
    broker_host: str = "0.0.0.0"
    broker_port: int = 8082
    broker_url: str = "http://base-docker-broker:8082"
    broker_workspace_dir: str = "/tmp/base-docker-broker"
    broker_allowed_images: list[str] = Field(
        default_factory=lambda: ["ghcr.io/baseintelligence/"]
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
    #: Per-slug read-only mounts injected into the Swarm eval job, decoupled
    #: from ``broker_docker_socket_slugs``. Maps a challenge slug to a list of
    #: ``source:target`` specs (same format as ``broker_eval_readonly_mounts``).
    #: Used to bind-mount the locked prism FineWeb-Edu train split + reference
    #: tokenizers READ-ONLY into the prism eval container (which must NOT get the
    #: host Docker socket). The prism slug receives a built-in default when
    #: unset; see ``cli_app.main._eval_readonly_mounts_by_slug``.
    broker_eval_readonly_mounts_by_slug: dict[str, list[str]] = Field(
        default_factory=dict
    )
    #: Challenge slugs whose untrusted Swarm eval job is pinned to the internal
    #: (no-egress) overlay regardless of the requested network. The prism slug
    #: is locked by default in ``cli_app.main._egress_locked_slugs``; entries
    #: here are added to that allowlist.
    broker_egress_locked_slugs: list[str] = Field(default_factory=list)
    # Challenge API services run on the manager/host; broker jobs run on
    # workers, steered to CPU- vs GPU-labeled nodes (base.workload).
    challenge_placement_constraint: str | None = "node.role==manager"
    cpu_job_constraint: str | None = "node.labels.base.workload==cpu"
    gpu_job_constraint: str | None = "node.labels.base.workload==gpu"


class SecuritySettings(BaseModel):
    admin_token: str | None = None
    admin_token_file: str | None = None


class GatewaySettings(BaseModel):
    """Master LLM gateway config (architecture.md sec 5).

    The provider is config-selected: ``mock`` (deterministic, no egress; used by
    tests) or ``real`` (HTTP clients pinned to the upstream bases). Provider keys
    are injected server-side; validators/eval runtimes hold only a scoped gateway
    token and point their client base URL at the master gateway.
    """

    provider_mode: Literal["mock", "real"] = "mock"
    deepseek_base_url: str = "https://api.deepseek.com"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    deepseek_api_key: str | None = None
    deepseek_api_key_file: str | None = "/run/secrets/deepseek_api_key"
    openrouter_api_key: str | None = None
    openrouter_api_key_file: str | None = "/run/secrets/openrouter_api_key"
    token_secret: str | None = None
    token_secret_file: str | None = "/run/secrets/gateway_token_secret"
    token_ttl_seconds: int = 3_600
    request_timeout_seconds: float = 30.0


class ObservabilitySettings(BaseModel):
    log_json: bool = True
    sentry_dsn: str | None = None
    otel_service_name: str = "base"
    # Task 16: lightweight, config-driven webhook alerting (NO Prometheus/
    # Grafana). All endpoints default to None so a default deploy makes ZERO
    # network calls — the alert hook is a structured-log-only no-op until a
    # webhook URL is set, and the drand/GPU reachability probes are skipped
    # until their health URLs are configured.
    alert_webhook_url: str | None = None
    alert_webhook_timeout_seconds: float = 5.0
    #: drand beacon reachability probe target (e.g. a drand HTTP API health
    #: URL). When set, a supervisor probe fires a ``drand_unreachable`` alert on
    #: failure; when None the probe is skipped.
    drand_health_url: str | None = None
    #: GPU liveness probe target (e.g. the GPU worker's health endpoint). When
    #: set, a supervisor probe fires a ``gpu_down`` alert on failure; when None
    #: the probe is skipped.
    gpu_health_url: str | None = None
    #: Cadence for the drand/GPU reachability probe task.
    health_probe_interval_seconds: float = 60.0


class Settings(BaseModel):
    environment: str = "development"
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    master: MasterSettings = Field(default_factory=MasterSettings)
    validator: ValidatorSettings = Field(default_factory=ValidatorSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    docker: DockerSettings = Field(default_factory=DockerSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    gateway: GatewaySettings = Field(default_factory=GatewaySettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)

    @model_validator(mode="after")
    def validate_production_policy(self) -> Settings:
        validate_settings_policy(self)
        return self
