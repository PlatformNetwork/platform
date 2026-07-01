"""Docker orchestration for BASE challenge containers.

This module is intentionally self-contained so the master and normal
validator runtimes can share it without depending on the database or CLI
layers. It uses the Docker Python SDK to pull GHCR images, create the private
challenge network, provision per-challenge SQLite volumes, mount secret files,
start/stop containers, and verify the required health/version endpoints.
"""

from __future__ import annotations

import json
import math
import re
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, get_args
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from base.master.workload_ledger import WorkloadClass

DEFAULT_API_VERSION = "1.0"
DEFAULT_CHALLENGE_PORT = 8000
DEFAULT_NETWORK_NAME = "base_challenges"
DEFAULT_SECRET_DIR = "/var/lib/base/secrets"
DEFAULT_SQLITE_PATH = "/data/challenge.sqlite3"
DEFAULT_SECRET_MOUNT_DIR = "/run/secrets/base"
DEFAULT_DOCKER_BROKER_URL = "http://base-docker-broker:8082"

_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_.-]+")


def port_from_internal_base_url(internal_base_url: str | None) -> int:
    """Derive the challenge container port from its internal base URL.

    Challenges advertise where they listen via ``internal_base_url`` (e.g.
    ``http://challenge-prism:8080``). The container port, health probes and
    the challenge Service must all use that port so traffic routes to the
    process; PRISM serves 8080 while the legacy default is 8000. Falls back to
    :data:`DEFAULT_CHALLENGE_PORT` when the URL is missing or has no port.
    """

    if not internal_base_url:
        return DEFAULT_CHALLENGE_PORT
    try:
        port = urlsplit(internal_base_url).port
    except ValueError:
        return DEFAULT_CHALLENGE_PORT
    return port if port is not None else DEFAULT_CHALLENGE_PORT


class DockerOrchestrationError(RuntimeError):
    """Raised when a challenge cannot be orchestrated safely."""


@dataclass(frozen=True)
class ChallengeResources:
    """Container resource limits for a challenge.

    Attributes:
        cpu: CPU count, translated to Docker nano CPUs.
        memory: Docker memory limit such as ``"4g"`` or ``"512m"``.
        docker_max_concurrent: Author-declared cap on concurrent Docker
            workloads for the challenge. ``None`` means "no quota
            configured" (unlimited) — Task 14 passes this verbatim as
            ``WorkloadLedger.register(..., max_concurrent=...)``.
        docker_timeout_seconds: Author-declared per-workload timeout.
            ``None`` means "no timeout configured" (never reaped) — feeds
            ``WorkloadEntry.timeout_seconds``.
    """

    cpu: float | None = 2.0
    memory: str | None = "4g"
    memory_swap: str | None = "4g"
    pids_limit: int = 512
    read_only: bool = True
    init: bool = True
    tmpfs: tuple[str, ...] = ("/tmp:rw,noexec,nosuid,size=512m",)
    cap_drop: tuple[str, ...] = ("ALL",)
    security_opt: tuple[str, ...] = ("no-new-privileges",)
    gpu_count: int | None = None
    gpu_device_ids: tuple[str, ...] = ()
    gpu_capabilities: tuple[str, ...] = ("gpu",)
    docker_max_concurrent: int | None = None
    docker_timeout_seconds: int | None = None

    def __post_init__(self) -> None:
        if self.docker_max_concurrent is not None:
            _parse_positive_int(self.docker_max_concurrent, "docker_max_concurrent")
        if self.docker_timeout_seconds is not None:
            _parse_positive_int(self.docker_timeout_seconds, "docker_timeout_seconds")

    @classmethod
    def from_mapping(
        cls,
        resources: dict[str, str],
        *,
        max_concurrent_cap: int | None = None,
        timeout_seconds_cap: int | None = None,
    ) -> ChallengeResources:
        """Parse author-declared resources, clamping quota keys to operator caps.

        ``max_concurrent_cap`` and ``timeout_seconds_cap`` are
        operator-configured maxima: author-declared
        ``docker_max_concurrent`` / ``docker_timeout_seconds`` values above
        a cap are clamped down to it (e.g. author asks 9999 concurrent with
        an operator cap of 10 → effective 10). ``None`` cap means no clamp.
        """

        cpu = resources.get("cpu") or resources.get("cpus")
        memory = resources.get("memory")
        memory_swap = resources.get("memory_swap") or resources.get("memswap_limit")
        pids_limit = resources.get("pids_limit") or resources.get("pids")
        gpu_count = resources.get("gpu_count") or resources.get("gpus")
        gpu_device_ids = _split_csv(resources.get("gpu_device_ids"))
        gpu_capabilities = _split_csv(resources.get("gpu_capabilities")) or ("gpu",)
        docker_max_concurrent = _parse_quota_key(
            resources, "docker_max_concurrent", cap=max_concurrent_cap
        )
        docker_timeout_seconds = _parse_quota_key(
            resources, "docker_timeout_seconds", cap=timeout_seconds_cap
        )
        return cls(
            cpu=_parse_cpu(cpu) if cpu else 2.0,
            memory=memory or "4g",
            memory_swap=memory_swap or "4g",
            pids_limit=int(pids_limit) if pids_limit else 512,
            gpu_count=int(gpu_count) if gpu_count else None,
            gpu_device_ids=gpu_device_ids,
            gpu_capabilities=gpu_capabilities,
            docker_max_concurrent=docker_max_concurrent,
            docker_timeout_seconds=docker_timeout_seconds,
        )

    def as_container_kwargs(self) -> dict[str, Any]:
        """Return docker-py container keyword arguments for limits."""

        kwargs: dict[str, Any] = {}
        if self.cpu is not None:
            if not math.isfinite(self.cpu) or self.cpu <= 0:
                raise DockerOrchestrationError(
                    "CPU limit must be a positive finite value"
                )
            kwargs["nano_cpus"] = int(self.cpu * 1_000_000_000)
        if self.memory:
            kwargs["mem_limit"] = self.memory
        if self.memory_swap:
            kwargs["memswap_limit"] = self.memory_swap
        if self.pids_limit < 1:
            raise DockerOrchestrationError("PID limit must be at least 1")
        kwargs["pids_limit"] = self.pids_limit
        kwargs["read_only"] = self.read_only
        kwargs["init"] = self.init
        kwargs["cap_drop"] = list(self.cap_drop)
        kwargs["security_opt"] = list(self.security_opt)
        if self.tmpfs:
            kwargs["tmpfs"] = _tmpfs_mapping(self.tmpfs)
        if self.gpu_count is not None:
            if self.gpu_count <= 0:
                raise DockerOrchestrationError("GPU count must be positive")
            try:
                from docker.types import DeviceRequest
            except ImportError as exc:  # pragma: no cover - environment-specific
                raise DockerOrchestrationError(
                    "docker-py SDK is required for GPU device requests"
                ) from exc
            request_kwargs: dict[str, Any] = {
                "capabilities": [list(self.gpu_capabilities)]
            }
            if self.gpu_device_ids:
                request_kwargs["device_ids"] = list(self.gpu_device_ids)
            else:
                request_kwargs["count"] = self.gpu_count
            kwargs["device_requests"] = [DeviceRequest(**request_kwargs)]
        return kwargs


@dataclass(frozen=True)
class ChallengeSpec:
    """Runtime specification for a challenge container.

    ``workload_class`` declares how the Swarm backend schedules the workload:
    ``"job"`` is an ephemeral evaluation run (Swarm replicated-job, eligible
    for timeout reaping) and ``"service"`` is a long-lived challenge API
    container such as PRISM (Swarm replicated service, NEVER reaped). The
    default is ``"job"`` to match :class:`WorkloadEntry`; the long-lived
    challenge API construction sites pass ``workload_class="service"``
    explicitly.
    """

    slug: str
    image: str
    version: str | None = None
    challenge_token: str | None = None
    docker_broker_token: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)
    external_secrets: tuple[str, ...] = ()
    resources: ChallengeResources = field(default_factory=ChallengeResources)
    required_capabilities: tuple[str, ...] = ("get_weights", "proxy_routes")
    expected_api_version: str = DEFAULT_API_VERSION
    port: int = DEFAULT_CHALLENGE_PORT
    worker_command: tuple[str, ...] = ()
    workload_class: WorkloadClass = "job"
    #: Explicit Swarm placement constraint (config seam). ``None`` defers to the
    #: backend default (byte-identical to prior behavior); a deploy can steer a
    #: workload from config without code edits (e.g. ``"node.role==manager"``).
    placement_constraint: str | None = None

    def __post_init__(self) -> None:
        if self.workload_class not in get_args(WorkloadClass):
            raise DockerOrchestrationError(
                f"workload_class must be one of {get_args(WorkloadClass)}, "
                f"got {self.workload_class!r}"
            )
        for name in self.external_secrets:
            if not isinstance(name, str) or not name.strip():
                raise DockerOrchestrationError(
                    "external_secrets entries must be non-empty strings"
                )

    @property
    def safe_slug(self) -> str:
        """Return a Docker-safe slug fragment."""

        value = _SAFE_NAME_RE.sub("-", self.slug.strip()).strip("-.")
        if not value:
            raise DockerOrchestrationError("Challenge slug cannot be empty")
        return value.lower()

    @property
    def container_name(self) -> str:
        """Return the standard container name used for Docker DNS routing."""

        return f"challenge-{self.safe_slug}"

    @property
    def sqlite_volume_name(self) -> str:
        """Return the standard named Docker volume for challenge SQLite data."""

        return f"base_{self.safe_slug.replace('-', '_')}_sqlite"

    @property
    def internal_base_url(self) -> str:
        """Return the Docker-network URL for this challenge."""

        return f"http://{self.container_name}:{self.port}"

    def all_secrets(self) -> dict[str, str]:
        """Return secrets that should be mounted into the container."""

        secrets = dict(self.secrets)
        if self.challenge_token is not None:
            secrets["challenge_token"] = self.challenge_token
        if self.docker_broker_token is not None:
            secrets["docker_broker_token"] = self.docker_broker_token
        return secrets

    def secret_names(self) -> tuple[str, ...]:
        """Return every secret name visible inside the container.

        Value-bearing secrets (:meth:`all_secrets`) come first, followed by
        ``external_secrets``: record-declared names whose values are
        provisioned out-of-band (for the Swarm backend these are pre-created
        ``docker secret`` objects the platform only references, never reads).
        """

        names = list(self.all_secrets())
        for name in self.external_secrets:
            if name not in names:
                names.append(name)
        return tuple(names)


def combined_mode_env_from_metadata(metadata: Mapping[str, Any]) -> str | None:
    """Return the env-var NAME that enables in-API worker (combined) mode.

    A registry challenge opts its single reconciler-deployed service into
    combined mode (the API process ALSO runs the eval-drain worker loop) by
    declaring the image's opt-in env var name here; the platform sets that var
    to ``"true"`` on the single service. ``None`` (absent) leaves the image at
    its default (worker OFF), preserving the legacy separate-service behavior.
    """

    raw = metadata.get("combined_mode_env")
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw.strip():
        raise DockerOrchestrationError(
            "combined_mode_env metadata must be a non-empty string"
        )
    return raw.strip()


def challenge_spec_from_registry(challenge: Any) -> ChallengeSpec:
    """Build a long-lived challenge service spec from a registry entry.

    Shared by the legacy :class:`NormalValidatorRunner` and the master registry
    reconciler so both deploy ACTIVE challenges with byte-identical specs. The
    ``challenge`` is duck-typed: any registry entry exposing ``slug``, ``image``,
    ``version``, ``env``, ``resources``, ``required_capabilities`` and
    ``metadata`` (a :class:`ChallengeRecord` or a registry ``RegistryChallenge``)
    works. Emits a ``"service"`` workload (a long-lived challenge API), never a
    reapable eval job.

    When the record declares a ``combined_mode_env`` metadata name, that env var
    is set to ``"true"`` on the single service so the image runs its worker loop
    in-process (combined mode): the ONE ``challenge-<slug>`` service both serves
    the API and drains the eval queue. The spec runs the image default CMD (no
    ``worker_command`` override), so no separate ``-worker`` service is needed.
    """

    metadata = getattr(challenge, "metadata", {}) or {}
    env = dict(challenge.env)
    combined_env = combined_mode_env_from_metadata(metadata)
    if combined_env is not None:
        env.setdefault(combined_env, "true")
    return ChallengeSpec(
        slug=challenge.slug,
        image=challenge.image,
        version=challenge.version,
        env=env,
        resources=ChallengeResources.from_mapping(dict(challenge.resources)),
        required_capabilities=tuple(challenge.required_capabilities),
        workload_class="service",
    )


@dataclass(frozen=True)
class ChallengeRuntime:
    """In-memory runtime state for a started challenge."""

    slug: str
    image: str
    container_id: str
    container_name: str
    internal_base_url: str
    sqlite_volume_name: str
    health: dict[str, Any]
    version: dict[str, Any]


class DockerOrchestrator:
    """Orchestrate challenge containers via docker-py.

    Args:
        client: Optional docker-py client. If omitted, ``docker.from_env()`` is used.
        network_name: Private Docker network used by master/proxy/challenges.
        secret_dir: Host directory visible to the Docker daemon for secret bind mounts.
        internal_network: Whether to create the network with Docker's ``internal`` flag.
        pull_ghcr_only: Require challenge images to be hosted on GHCR.
        request_timeout_seconds: Timeout for health/version HTTP checks.
        health_retries: Number of attempts for health/version readiness.
        health_retry_delay_seconds: Delay between readiness attempts.
    """

    def __init__(
        self,
        *,
        client: Any | None = None,
        network_name: str = DEFAULT_NETWORK_NAME,
        secret_dir: str | Path = DEFAULT_SECRET_DIR,
        internal_network: bool = True,
        pull_ghcr_only: bool = True,
        request_timeout_seconds: float = 5.0,
        health_retries: int = 12,
        health_retry_delay_seconds: float = 2.0,
        docker_broker_url: str = DEFAULT_DOCKER_BROKER_URL,
    ) -> None:
        self._client = client
        self.network_name = network_name
        self.secret_dir = Path(secret_dir)
        self.internal_network = internal_network
        self.pull_ghcr_only = pull_ghcr_only
        self.request_timeout_seconds = request_timeout_seconds
        self.health_retries = health_retries
        self.health_retry_delay_seconds = health_retry_delay_seconds
        self.docker_broker_url = docker_broker_url
        self._runtime: dict[str, ChallengeRuntime] = {}

    @property
    def runtime(self) -> dict[str, ChallengeRuntime]:
        """Return a copy of in-memory challenge runtime state."""

        return dict(self._runtime)

    @property
    def client(self) -> Any:
        """Return the docker-py client, creating it lazily."""

        if self._client is None:
            try:
                import docker
            except ImportError as exc:  # pragma: no cover - environment-specific
                raise DockerOrchestrationError(
                    "docker-py SDK is required; install the 'docker' package"
                ) from exc
            self._client = docker.from_env()  # type: ignore[attr-defined]
        return self._client

    def ensure_network(self) -> Any:
        """Create or return the private Docker network."""

        try:
            return self.client.networks.get(self.network_name)
        except Exception:
            return self.client.networks.create(
                self.network_name,
                driver="bridge",
                internal=self.internal_network,
                attachable=True,
                labels={"joinbase.ai": "challenges"},
            )

    def ensure_sqlite_volume(self, spec: ChallengeSpec) -> Any:
        """Create or return the named SQLite volume for a challenge."""

        try:
            return self.client.volumes.get(spec.sqlite_volume_name)
        except Exception:
            return self.client.volumes.create(
                name=spec.sqlite_volume_name,
                labels={
                    "base.volume.kind": "challenge-sqlite",
                    "base.challenge.slug": spec.slug,
                },
            )

    def pull_image(self, image: str) -> Any:
        """Pull a challenge image from GHCR."""

        if self.pull_ghcr_only and not image.startswith("ghcr.io/"):
            raise DockerOrchestrationError("Challenge images must be pulled from GHCR")
        return self.client.images.pull(image)

    def start_challenge(
        self, spec: ChallengeSpec, *, recreate: bool = False
    ) -> ChallengeRuntime:
        """Pull, create/start, and verify a challenge container."""

        self.pull_image(spec.image)
        self.ensure_network()
        self.ensure_sqlite_volume(spec)

        existing = self._get_container(spec.container_name)
        if existing is not None and recreate:
            existing.stop(timeout=10)
            existing.remove(v=True)
            existing = None

        if existing is None:
            container = self._create_container(spec)
        else:
            container = existing
            if container.status != "running":
                container.start()

        health, version = self.wait_until_ready(spec)
        runtime = ChallengeRuntime(
            slug=spec.slug,
            image=spec.image,
            container_id=container.id,
            container_name=spec.container_name,
            internal_base_url=spec.internal_base_url,
            sqlite_volume_name=spec.sqlite_volume_name,
            health=health,
            version=version,
        )
        self._runtime[spec.slug] = runtime
        return runtime

    def stop_challenge(self, slug: str, *, remove: bool = False) -> None:
        """Stop a challenge container by slug."""

        safe_slug = _safe_slug(slug)
        container_name = f"challenge-{safe_slug}"
        container = self._get_container(container_name)
        if container is not None:
            if container.status == "running":
                container.stop(timeout=10)
            if remove:
                container.remove(v=False)
        self._runtime.pop(slug, None)

    def restart_challenge(self, spec: ChallengeSpec) -> ChallengeRuntime:
        """Restart a challenge container and verify readiness."""

        container = self._get_container(spec.container_name)
        if container is None:
            return self.start_challenge(spec)
        container.restart(timeout=10)
        health, version = self.wait_until_ready(spec)
        runtime = ChallengeRuntime(
            slug=spec.slug,
            image=spec.image,
            container_id=container.id,
            container_name=spec.container_name,
            internal_base_url=spec.internal_base_url,
            sqlite_volume_name=spec.sqlite_volume_name,
            health=health,
            version=version,
        )
        self._runtime[spec.slug] = runtime
        return runtime

    def wait_until_ready(
        self, spec: ChallengeSpec
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Wait for ``/health`` and ``/version`` to pass validation."""

        last_error: Exception | None = None
        for _attempt in range(self.health_retries):
            try:
                health = self._get_json(f"{spec.internal_base_url}/health")
                self._validate_health(spec, health)
                version = self._get_json(f"{spec.internal_base_url}/version")
                self._validate_version(spec, version)
                return health, version
            except Exception as exc:  # readiness retry path
                last_error = exc
                time.sleep(self.health_retry_delay_seconds)
        raise DockerOrchestrationError(
            f"Challenge {spec.slug!r} failed health/version checks"
        ) from last_error

    def _create_container(self, spec: ChallengeSpec) -> Any:
        mounts = self._build_mounts(spec)
        environment = self._build_environment(spec)
        kwargs = spec.resources.as_container_kwargs()
        if spec.worker_command:
            kwargs["command"] = list(spec.worker_command)
        return self.client.containers.run(
            spec.image,
            detach=True,
            name=spec.container_name,
            hostname=spec.container_name,
            network=self.network_name,
            environment=environment,
            mounts=mounts,
            labels={
                "base.component": "challenge",
                "base.challenge.slug": spec.slug,
                "base.challenge.version": spec.version or "",
            },
            restart_policy={"Name": "unless-stopped"},
            **kwargs,
        )

    def _build_mounts(self, spec: ChallengeSpec) -> list[Any]:
        try:
            from docker.types import Mount
        except ImportError as exc:  # pragma: no cover - environment-specific
            raise DockerOrchestrationError(
                "docker-py SDK is required; install the 'docker' package"
            ) from exc

        mounts: list[Any] = [
            Mount(
                target="/data",
                source=spec.sqlite_volume_name,
                type="volume",
                read_only=False,
            )
        ]

        secret_paths = self._write_secret_files(spec)
        for secret_name, host_path in secret_paths.items():
            mounts.append(
                Mount(
                    target=f"{DEFAULT_SECRET_MOUNT_DIR}/{secret_name}",
                    source=str(host_path),
                    type="bind",
                    read_only=True,
                )
            )
        return mounts

    def _build_environment(self, spec: ChallengeSpec) -> dict[str, str]:
        environment = dict(spec.env)
        environment.setdefault("BASE_CHALLENGE_SLUG", spec.slug)
        environment.setdefault(
            "CHALLENGE_DATABASE_URL",
            f"sqlite+aiosqlite:///{DEFAULT_SQLITE_PATH}",
        )
        for secret_name in spec.all_secrets():
            env_name = f"{secret_name.upper()}_FILE"
            environment.setdefault(
                env_name, f"{DEFAULT_SECRET_MOUNT_DIR}/{secret_name}"
            )
            if secret_name == "challenge_token":
                environment.setdefault(
                    "CHALLENGE_SHARED_TOKEN_FILE",
                    f"{DEFAULT_SECRET_MOUNT_DIR}/{secret_name}",
                )
        if "docker_executor" in spec.required_capabilities:
            environment.setdefault("CHALLENGE_DOCKER_ENABLED", "true")
            environment.setdefault("CHALLENGE_DOCKER_BACKEND", "broker")
            environment.setdefault(
                "CHALLENGE_DOCKER_BROKER_URL", self.docker_broker_url
            )
            environment.setdefault(
                "CHALLENGE_DOCKER_BROKER_TOKEN_FILE",
                f"{DEFAULT_SECRET_MOUNT_DIR}/docker_broker_token",
            )
        return environment

    def _write_secret_files(self, spec: ChallengeSpec) -> dict[str, Path]:
        secrets = spec.all_secrets()
        if not secrets:
            return {}

        challenge_secret_dir = self.secret_dir / spec.safe_slug
        challenge_secret_dir.mkdir(parents=True, exist_ok=True)
        challenge_secret_dir.chmod(stat.S_IRWXU)

        paths: dict[str, Path] = {}
        for secret_name, secret_value in secrets.items():
            safe_secret_name = _safe_secret_name(secret_name)
            path = challenge_secret_dir / safe_secret_name
            path.write_text(secret_value, encoding="utf-8")
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            paths[safe_secret_name] = path
        return paths

    def _get_container(self, container_name: str) -> Any | None:
        try:
            return self.client.containers.get(container_name)
        except Exception:
            return None

    def _get_json(self, url: str) -> dict[str, Any]:
        request = Request(url, headers={"Accept": "application/json"})
        try:
            with urlopen(request, timeout=self.request_timeout_seconds) as response:
                payload = response.read()
        except (HTTPError, URLError, TimeoutError) as exc:
            raise DockerOrchestrationError(f"HTTP check failed for {url}") from exc

        try:
            decoded = json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise DockerOrchestrationError(f"Invalid JSON response from {url}") from exc
        if not isinstance(decoded, dict):
            raise DockerOrchestrationError(f"Expected JSON object from {url}")
        return decoded

    def _validate_health(self, spec: ChallengeSpec, health: dict[str, Any]) -> None:
        if health.get("status") != "ok":
            raise DockerOrchestrationError(f"Challenge {spec.slug!r} health is not ok")
        response_slug = health.get("slug")
        if response_slug is not None and response_slug != spec.slug:
            raise DockerOrchestrationError(
                f"Challenge {spec.slug!r} returned mismatched health slug"
            )

    def _validate_version(self, spec: ChallengeSpec, version: dict[str, Any]) -> None:
        api_version = version.get("api_version")
        if api_version != spec.expected_api_version:
            raise DockerOrchestrationError(
                f"Challenge {spec.slug!r} API version {api_version!r} is incompatible"
            )
        if (
            spec.version is not None
            and version.get("challenge_version") != spec.version
        ):
            raise DockerOrchestrationError(
                f"Challenge {spec.slug!r} returned mismatched challenge version"
            )
        capabilities = version.get("capabilities", [])
        if not isinstance(capabilities, list):
            raise DockerOrchestrationError(
                f"Challenge {spec.slug!r} returned invalid capabilities"
            )
        missing = sorted(set(spec.required_capabilities) - set(capabilities))
        if missing:
            raise DockerOrchestrationError(
                f"Challenge {spec.slug!r} is missing required capabilities: {missing}"
            )


def _safe_slug(slug: str) -> str:
    value = _SAFE_NAME_RE.sub("-", slug.strip()).strip("-.")
    if not value:
        raise DockerOrchestrationError("Challenge slug cannot be empty")
    return value.lower()


def _split_csv(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _parse_cpu(value: str) -> float:
    value = value.strip()
    if value.endswith("m"):
        return float(value[:-1]) / 1000
    return float(value)


def _parse_positive_int(value: object, key: str) -> int:
    """Validate ``value`` as a strictly positive integer for ``key``."""

    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise DockerOrchestrationError(
            f"{key} must be a positive integer, got {value!r}"
        )
    try:
        parsed = int(str(value).strip())
    except ValueError as exc:
        raise DockerOrchestrationError(
            f"{key} must be a positive integer, got {value!r}"
        ) from exc
    if parsed <= 0:
        raise DockerOrchestrationError(
            f"{key} must be a positive integer, got {value!r}"
        )
    return parsed


def _parse_quota_key(
    resources: Mapping[str, object], key: str, *, cap: int | None
) -> int | None:
    """Parse an optional quota key, clamping it to the operator ``cap``.

    Missing or empty values mean "not configured" and yield ``None``. A
    declared value must be a strictly positive integer; values above the
    operator cap are clamped down to the cap.
    """

    value = resources.get(key)
    if value is None or value == "":
        return None
    parsed = _parse_positive_int(value, key)
    if cap is not None:
        cap = _parse_positive_int(cap, f"{key} operator cap")
        return min(parsed, cap)
    return parsed


def _tmpfs_mapping(values: tuple[str, ...]) -> dict[str, str]:
    tmpfs: dict[str, str] = {}
    for value in values:
        path, separator, options = value.partition(":")
        if not path.startswith("/"):
            raise DockerOrchestrationError(f"tmpfs mount must be absolute: {path}")
        tmpfs[path] = options if separator else ""
    return tmpfs


def _safe_secret_name(secret_name: str) -> str:
    value = _SAFE_NAME_RE.sub("_", secret_name.strip()).strip("_.-")
    if not value:
        raise DockerOrchestrationError("Secret name cannot be empty")
    return value.lower()
