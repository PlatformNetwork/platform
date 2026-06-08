"""Internal Docker broker for challenge-side evaluation containers."""

from __future__ import annotations

import base64
import binascii
import secrets
import tarfile
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Protocol

from fastapi import FastAPI, Header, HTTPException, status

from platform_network.challenge_sdk.executors.docker import (
    DockerExecutor,
    DockerExecutorError,
    DockerLimits,
    DockerMount,
    DockerRunSpec,
)
from platform_network.schemas.docker_broker import (
    BrokerCleanupRequest,
    BrokerCleanupResponse,
    BrokerContainerInfo,
    BrokerListRequest,
    BrokerListResponse,
    BrokerMount,
    BrokerRunRequest,
    BrokerRunResponse,
)


class BrokerTokenRegistry(Protocol):
    def get_broker_token(self, slug: str) -> str: ...


@dataclass(frozen=True)
class DockerBrokerConfig:
    docker_bin: str = "docker"
    workspace_dir: Path = Path("/tmp/platform-docker-broker")
    allowed_images: tuple[str, ...] = ("ghcr.io/platformnetwork/",)
    log_limit_bytes: int = 64_000


class DockerBrokerService:
    def __init__(self, config: DockerBrokerConfig | None = None) -> None:
        self.config = config or DockerBrokerConfig()
        self.config.workspace_dir.mkdir(parents=True, exist_ok=True)

    def run(self, challenge_slug: str, request: BrokerRunRequest) -> BrokerRunResponse:
        with TemporaryDirectory(
            prefix=f"{_safe_fragment(challenge_slug)}-{_safe_fragment(request.job_id)}-",
            dir=self.config.workspace_dir,
        ) as workspace:
            workspace_path = Path(workspace)
            mounts = [
                self._materialize_mount(workspace_path, index, mount)
                for index, mount in enumerate(request.mounts)
            ]
            executor = DockerExecutor(
                challenge=challenge_slug,
                docker_bin=self.config.docker_bin,
                allowed_images=self.config.allowed_images,
                log_limit_bytes=self.config.log_limit_bytes,
            )
            labels = {**request.labels, "platform.job": request.job_id}
            if request.task_id:
                labels["platform.task"] = request.task_id
            limits = self._hardened_limits(request)
            result = executor.run(
                DockerRunSpec(
                    image=request.image,
                    command=tuple(request.command),
                    mounts=tuple(mounts),
                    workdir=request.workdir,
                    env=request.env,
                    labels=labels,
                    name=executor.container_name(request.job_id, request.task_id),
                    limits=limits,
                ),
                timeout_seconds=request.timeout_seconds,
            )
            return BrokerRunResponse(
                container_name=result.container_name,
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                timed_out=result.timed_out,
            )

    def cleanup(
        self, challenge_slug: str, request: BrokerCleanupRequest
    ) -> BrokerCleanupResponse:
        DockerExecutor(
            challenge=challenge_slug,
            docker_bin=self.config.docker_bin,
            allowed_images=self.config.allowed_images,
            log_limit_bytes=self.config.log_limit_bytes,
        ).cleanup_job(request.job_id)
        return BrokerCleanupResponse()

    def list_containers(
        self, challenge_slug: str, request: BrokerListRequest
    ) -> BrokerListResponse:
        containers = DockerExecutor(
            challenge=challenge_slug,
            docker_bin=self.config.docker_bin,
            allowed_images=self.config.allowed_images,
            log_limit_bytes=self.config.log_limit_bytes,
        ).list_containers(request.job_id)
        return BrokerListResponse(
            containers=[
                BrokerContainerInfo(
                    container_id=container.container_id,
                    container_name=container.container_name,
                    image=container.image,
                    status=container.status,
                    job_id=container.job_id,
                    task_id=container.task_id,
                    created=container.created,
                    labels={
                        key: value
                        for key, value in container.labels.items()
                        if key.startswith("platform.")
                    },
                )
                for container in containers
            ]
        )

    def _materialize_mount(
        self, root: Path, index: int, mount: BrokerMount
    ) -> DockerMount:
        mount_root = root / f"mount-{index}"
        mount_root.mkdir(parents=True)
        archive_path = mount_root / "payload.tar.gz"
        try:
            archive = base64.b64decode(mount.archive_b64, validate=True)
            archive_path.write_bytes(archive)
            with tarfile.open(archive_path, mode="r:gz") as tar:
                _validate_tar_members(tar)
                tar.extractall(mount_root, filter="data")
        except HTTPException:
            raise
        except (binascii.Error, tarfile.TarError, ValueError, OSError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid mount archive",
            ) from exc
        archive_path.unlink(missing_ok=True)
        if mount.source_type == "file":
            source_name = Path(mount.source_name)
            if source_name.is_absolute() or ".." in source_name.parts:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"unsafe mount source: {mount.target}",
                )
            source = (mount_root / source_name).resolve()
            resolved_root = mount_root.resolve()
            if resolved_root not in source.parents and source != resolved_root:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"unsafe mount source: {mount.target}",
                )
        elif mount.source_type == "directory":
            source = mount_root
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"unsupported mount source type: {mount.target}",
            )
        if not source.exists():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"materialized mount source is missing: {mount.target}",
            )
        return DockerMount(
            source=source, target=mount.target, read_only=mount.read_only
        )

    def _hardened_limits(self, request: BrokerRunRequest) -> DockerLimits:
        if request.limits.privileged:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="privileged broker jobs require an isolated Kubernetes runtime",
            )
        limits = DockerLimits(**request.limits.model_dump(exclude={"privileged"}))
        if not limits.read_only:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="broker Docker jobs require a read-only root filesystem",
            )
        if not limits.init:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="broker Docker jobs require Docker init for process cleanup",
            )
        if "ALL" not in limits.cap_drop:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="broker Docker jobs must drop all Linux capabilities",
            )
        if not any(opt.startswith("no-new-privileges") for opt in limits.security_opt):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="broker Docker jobs require no-new-privileges",
            )
        return limits


def create_docker_broker_app(
    *,
    registry: BrokerTokenRegistry,
    service: DockerBrokerService | None = None,
) -> FastAPI:
    broker = service or DockerBrokerService()
    app = FastAPI(title="Platform Docker Broker", version="1.0")

    @app.get("/health", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/docker/run", response_model=BrokerRunResponse)
    def run_container(
        request: BrokerRunRequest,
        authorization: str | None = Header(default=None),
        slug: str | None = Header(default=None, alias="X-Platform-Challenge-Slug"),
    ) -> BrokerRunResponse:
        try:
            return broker.run(
                _authenticate(registry, slug, authorization),
                request,
            )
        except DockerExecutorError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    @app.post("/v1/docker/cleanup", response_model=BrokerCleanupResponse)
    def cleanup(
        request: BrokerCleanupRequest,
        authorization: str | None = Header(default=None),
        slug: str | None = Header(default=None, alias="X-Platform-Challenge-Slug"),
    ) -> BrokerCleanupResponse:
        return broker.cleanup(
            _authenticate(registry, slug, authorization),
            request,
        )

    @app.post("/v1/docker/list", response_model=BrokerListResponse)
    def list_containers(
        request: BrokerListRequest,
        authorization: str | None = Header(default=None),
        slug: str | None = Header(default=None, alias="X-Platform-Challenge-Slug"),
    ) -> BrokerListResponse:
        return broker.list_containers(
            _authenticate(registry, slug, authorization),
            request,
        )

    return app


def _authenticate(
    registry: BrokerTokenRegistry, slug: str | None, authorization: str | None
) -> str:
    if not slug:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing challenge slug")
    expected = registry.get_broker_token(slug)
    if not expected:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown challenge")
    expected_header = f"Bearer {expected}"
    if authorization is None or not secrets.compare_digest(
        authorization, expected_header
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid broker token")
    return slug


def _validate_tar_members(tar: tarfile.TarFile) -> None:
    for member in tar.getmembers():
        path = Path(member.name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or member.issym()
            or member.islnk()
            or member.isdev()
        ):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "unsafe mount archive")


def _safe_fragment(value: str) -> str:
    safe = "".join(ch if ch.isalnum() else "-" for ch in value.lower()).strip("-")
    return (safe or "x")[:48]
