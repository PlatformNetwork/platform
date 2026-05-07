"""Docker orchestration for Platform challenge containers.

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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_API_VERSION = "1.0"
DEFAULT_CHALLENGE_PORT = 8000
DEFAULT_NETWORK_NAME = "platform_challenges"
DEFAULT_SECRET_DIR = "/var/lib/platform/secrets"
DEFAULT_SQLITE_PATH = "/data/challenge.sqlite3"
DEFAULT_SECRET_MOUNT_DIR = "/run/secrets/platform"
DEFAULT_DOCKER_BROKER_URL = "http://platform-docker-broker:8082"

_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_.-]+")


class DockerOrchestrationError(RuntimeError):
    """Raised when a challenge cannot be orchestrated safely."""


@dataclass(frozen=True)
class ChallengeResources:
    """Container resource limits for a challenge.

    Attributes:
        cpu: Optional CPU count, translated to Docker nano CPUs.
        memory: Optional Docker memory limit such as ``"4g"`` or ``"512m"``.
    """

    cpu: float | None = None
    memory: str | None = None

    @classmethod
    def from_mapping(cls, resources: dict[str, str]) -> ChallengeResources:
        cpu = resources.get("cpu") or resources.get("cpus")
        memory = resources.get("memory")
        return cls(cpu=float(cpu) if cpu else None, memory=memory)

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
        return kwargs


@dataclass(frozen=True)
class ChallengeSpec:
    """Runtime specification for a challenge container."""

    slug: str
    image: str
    version: str | None = None
    challenge_token: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)
    resources: ChallengeResources = field(default_factory=ChallengeResources)
    required_capabilities: tuple[str, ...] = ("get_weights", "proxy_routes")
    expected_api_version: str = DEFAULT_API_VERSION
    port: int = DEFAULT_CHALLENGE_PORT

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

        return f"platform_{self.safe_slug.replace('-', '_')}_sqlite"

    @property
    def internal_base_url(self) -> str:
        """Return the Docker-network URL for this challenge."""

        return f"http://{self.container_name}:{self.port}"

    def all_secrets(self) -> dict[str, str]:
        """Return secrets that should be mounted into the container."""

        secrets = dict(self.secrets)
        if self.challenge_token is not None:
            secrets["challenge_token"] = self.challenge_token
        return secrets


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
                labels={"platform.network": "challenges"},
            )

    def ensure_sqlite_volume(self, spec: ChallengeSpec) -> Any:
        """Create or return the named SQLite volume for a challenge."""

        try:
            return self.client.volumes.get(spec.sqlite_volume_name)
        except Exception:
            return self.client.volumes.create(
                name=spec.sqlite_volume_name,
                labels={
                    "platform.volume.kind": "challenge-sqlite",
                    "platform.challenge.slug": spec.slug,
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
        return self.client.containers.run(
            spec.image,
            detach=True,
            name=spec.container_name,
            hostname=spec.container_name,
            network=self.network_name,
            environment=environment,
            mounts=mounts,
            labels={
                "platform.component": "challenge",
                "platform.challenge.slug": spec.slug,
                "platform.challenge.version": spec.version or "",
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
        environment.setdefault("PLATFORM_CHALLENGE_SLUG", spec.slug)
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
                f"{DEFAULT_SECRET_MOUNT_DIR}/challenge_token",
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


def _safe_secret_name(secret_name: str) -> str:
    value = _SAFE_NAME_RE.sub("_", secret_name.strip()).strip("_.-")
    if not value:
        raise DockerOrchestrationError("Secret name cannot be empty")
    return value.lower()
