"""Internal Docker broker for challenge-side evaluation containers."""

from __future__ import annotations

import base64
import binascii
import re
import secrets
import subprocess
import tarfile
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal, Protocol

from fastapi import FastAPI, Header, HTTPException, status

from platform_network.challenge_sdk.executors.docker import (
    DockerExecutor,
    DockerExecutorError,
    DockerLimits,
    DockerMount,
    DockerRunSpec,
)
from platform_network.master.workload_ledger import (
    WorkloadCapacityError,
    WorkloadEntry,
    WorkloadLedger,
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

#: Mount target for the dedicated DinD storage volume: the inner Docker
#: daemon gets its own named volume so image layers/containers never land on
#: the outer daemon's storage or the container's writable layer.
ESCAPE_HATCH_DIND_MOUNT_TARGET = "/var/lib/docker"

_IMAGE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9./_:@+-]{0,254}$")


class BrokerTokenRegistry(Protocol):
    def get_broker_token(self, slug: str) -> str: ...


class BrokerService(Protocol):
    """Backend-agnostic broker operations behind the frozen HTTP contract.

    Implemented by :class:`DockerBrokerService` (plain ``docker run``) and
    ``platform_network.master.swarm_backend.SwarmBrokerService`` (Swarm
    replicated-jobs). The request/response shapes are frozen by the golden
    contract suite and must stay byte-identical across implementations.
    """

    def run(
        self, challenge_slug: str, request: BrokerRunRequest
    ) -> BrokerRunResponse: ...

    def cleanup(
        self, challenge_slug: str, request: BrokerCleanupRequest
    ) -> BrokerCleanupResponse: ...

    def list_containers(
        self, challenge_slug: str, request: BrokerListRequest
    ) -> BrokerListResponse: ...


@dataclass(frozen=True)
class EscapeHatchCommandResult:
    """Captured outcome of one escape-hatch docker CLI invocation."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class EscapeHatchCommandRunner(Protocol):
    """Executes a docker CLI argv for the privileged escape hatch.

    Tests inject argv-capturing fakes (mirroring ``FakeSwarmRunner``) so no
    real dockerd is required.
    """

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float | None = None,
    ) -> EscapeHatchCommandResult: ...


class EscapeHatchCliRunner:
    """Run docker CLI commands via subprocess (the only process-spawn site).

    Timeouts surface as ``timed_out=True`` results with returncode 124,
    mirroring ``DockerExecutor``'s timeout contract instead of raising.
    """

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float | None = None,
    ) -> EscapeHatchCommandResult:
        try:
            proc = subprocess.run(
                list(argv),
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return EscapeHatchCommandResult(
                argv=tuple(argv),
                returncode=124,
                stdout=_coerce_text(exc.stdout),
                stderr=_coerce_text(exc.stderr),
                timed_out=True,
            )
        except OSError as exc:
            return EscapeHatchCommandResult(
                argv=tuple(argv),
                returncode=127,
                stdout="",
                stderr=str(exc),
            )
        return EscapeHatchCommandResult(
            argv=tuple(argv),
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )


@dataclass(frozen=True)
class DockerBrokerConfig:
    docker_bin: str = "docker"
    workspace_dir: Path = Path("/tmp/platform-docker-broker")
    allowed_images: tuple[str, ...] = ("ghcr.io/platformnetwork/",)
    log_limit_bytes: int = 64_000
    #: Challenge slugs carrying the ``docker_executor`` capability whose
    #: privileged jobs may use the DinD escape hatch (Task 13). The slug is
    #: trustworthy as a gate key because every broker request is
    #: authenticated against the per-slug broker token. Empty (the default)
    #: keeps the frozen privileged-403 refusal for everyone.
    privileged_escape_slugs: frozenset[str] = frozenset()
    #: Role of the node this broker runs on. The privileged escape hatch is
    #: worker-only; on a manager/validator node even allowlisted slugs get
    #: the frozen 403 refusal.
    node_role: Literal["manager", "worker"] = "manager"
    #: Per-challenge concurrency caps enforced at ``/v1/docker/run`` (Task
    #: 14). Mirrors ``ChallengeResources.docker_max_concurrent`` intent: the
    #: frozen broker request schema carries no quota field, so (like the
    #: Task-13 ``privileged_escape_slugs`` allowlist) the broker learns each
    #: slug's cap via broker-side config. A missing slug means UNLIMITED —
    #: the empty default keeps behavior unchanged; wiring real challenge
    #: metadata in ``cli_app/main.py`` is deployment territory (Tasks 24/28).
    max_concurrent_by_slug: Mapping[str, int] = field(default_factory=dict)


class DockerBrokerService:
    def __init__(
        self,
        config: DockerBrokerConfig | None = None,
        *,
        escape_runner: EscapeHatchCommandRunner | None = None,
        ledger: WorkloadLedger | None = None,
    ) -> None:
        self.config = config or DockerBrokerConfig()
        self.config.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.escape_runner: EscapeHatchCommandRunner = (
            escape_runner or EscapeHatchCliRunner()
        )
        self.ledger = ledger or WorkloadLedger()

    def run(self, challenge_slug: str, request: BrokerRunRequest) -> BrokerRunResponse:
        if request.limits.privileged and self._escape_hatch_allowed(challenge_slug):
            return self._run_escape_hatch(challenge_slug, request)
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
            name = executor.container_name(request.job_id, request.task_id)
            # Quota enforcement (Task 14): registered before launch with the
            # atomic capacity check, released in the finally. These legacy
            # ``docker run`` containers are local-daemon workloads removed
            # with ``docker rm -f`` (the same removal verb the
            # ``escape_hatch_container`` kind encodes for the reaper);
            # ``started_at`` is never observed on this request-scoped path,
            # so the deadline stays ``None`` and the reaper can never act on
            # these entries.
            self.ledger.register(
                WorkloadEntry(
                    key=name,
                    kind="escape_hatch_container",
                    challenge_slug=challenge_slug,
                    workload_class="job",
                    timeout_seconds=request.timeout_seconds,
                ),
                max_concurrent=self._max_concurrent(challenge_slug),
            )
            try:
                result = executor.run(
                    DockerRunSpec(
                        image=request.image,
                        command=tuple(request.command),
                        mounts=tuple(mounts),
                        workdir=request.workdir,
                        env=request.env,
                        labels=labels,
                        name=name,
                        limits=limits,
                    ),
                    timeout_seconds=request.timeout_seconds,
                )
            finally:
                self.ledger.release(name)
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
        self._cleanup_escape_hatch_containers(challenge_slug, request.job_id)
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

    # ------------------------------------------------- privileged escape hatch
    def _max_concurrent(self, challenge_slug: str) -> int | None:
        return self.config.max_concurrent_by_slug.get(challenge_slug)

    def _escape_hatch_allowed(self, challenge_slug: str) -> bool:
        """Capability gate for the privileged DinD escape hatch (Task 13).

        Open ONLY when the authenticated challenge slug is allowlisted for
        the ``docker_executor`` capability AND this broker runs on a worker
        node. Any other privileged request (including allowlisted slugs on a
        manager/validator node) falls through to ``_hardened_limits`` and
        receives the byte-identical frozen 403 refusal.
        """

        return (
            self.config.node_role == "worker"
            and challenge_slug in self.config.privileged_escape_slugs
        )

    def _run_escape_hatch(
        self, challenge_slug: str, request: BrokerRunRequest
    ) -> BrokerRunResponse:
        """Run a privileged DinD job as a direct local ``docker run``.

        Swarm services cannot run privileged (``docker service create``
        rejects ``--privileged``), so gated jobs bypass Swarm entirely and
        execute on this worker node's daemon. The launched container is
        tracked in the shared workload ledger keyed by its FULL container ID
        (``kind="escape_hatch_container"``); inner containers spawned by the
        DinD daemon are deliberately NOT tracked (outer-only accounting —
        removing the outer container tears down everything inside it).
        """

        self._validate_escape_request(request)
        with TemporaryDirectory(
            prefix=f"{_safe_fragment(challenge_slug)}-{_safe_fragment(request.job_id)}-",
            dir=self.config.workspace_dir,
        ) as workspace:
            workspace_path = Path(workspace)
            mounts = [
                self._materialize_mount(workspace_path, index, mount)
                for index, mount in enumerate(request.mounts)
            ]
            name = _escape_container_name(
                challenge_slug, request.job_id, request.task_id
            )
            labels = {
                **request.labels,
                "platform.challenge": challenge_slug,
                "platform.job": request.job_id,
            }
            if request.task_id:
                labels["platform.task"] = request.task_id
            dind_volume = f"{name}-dind"
            argv = build_escape_hatch_run_argv(
                self.config.docker_bin,
                name=name,
                request=request,
                mounts=mounts,
                labels=labels,
                dind_volume=dind_volume,
            )
            created = self.escape_runner.run(argv)
            if created.returncode != 0:
                raise DockerExecutorError(
                    f"escape hatch docker run failed: {self._cap_log(created.stderr)}"
                )
            container_id = created.stdout.strip().splitlines()[0].strip()
            if not container_id:
                raise DockerExecutorError(
                    "escape hatch docker run returned no container ID"
                )
            docker_bin = self.config.docker_bin
            try:
                # Single quota/registration point (Task 14): the atomic
                # capacity check happens here; a refusal lands in the finally
                # below (container removed, release is an idempotent no-op).
                self.ledger.register(
                    WorkloadEntry(
                        key=container_id,
                        kind="escape_hatch_container",
                        challenge_slug=challenge_slug,
                        workload_class="job",
                        timeout_seconds=request.timeout_seconds,
                    ),
                    max_concurrent=self._max_concurrent(challenge_slug),
                )
                waited = self.escape_runner.run(
                    [docker_bin, "wait", container_id],
                    timeout_seconds=float(request.timeout_seconds),
                )
                timed_out = waited.timed_out
                returncode = 124 if timed_out else _parse_wait_exit_code(waited.stdout)
                logs = self.escape_runner.run([docker_bin, "logs", container_id])
                return BrokerRunResponse(
                    container_name=name,
                    stdout=self._cap_log(logs.stdout),
                    stderr=self._cap_log(logs.stderr),
                    returncode=returncode,
                    timed_out=timed_out,
                )
            finally:
                self.escape_runner.run([docker_bin, "rm", "-f", container_id])
                self.ledger.release(container_id)
                # Best-effort: the dedicated DinD storage volume is removed
                # with its container so inner-daemon state never accumulates.
                self.escape_runner.run([docker_bin, "volume", "rm", dind_volume])

    def _validate_escape_request(self, request: BrokerRunRequest) -> None:
        image = request.image
        if not _IMAGE_RE.match(image) or image.startswith("-"):
            raise DockerExecutorError(f"unsafe Docker image reference: {image!r}")
        allowed = self.config.allowed_images
        if allowed and not any(
            image == item or image.startswith(item.rstrip("*")) for item in allowed
        ):
            raise DockerExecutorError(f"Docker image is not allowed: {image}")
        network = request.limits.network
        if network not in {"none", "default"} and not network.startswith("platform_"):
            raise DockerExecutorError(
                "Docker network must be 'none', 'default', or a platform network"
            )

    def _cleanup_escape_hatch_containers(
        self, challenge_slug: str, job_id: str
    ) -> None:
        """Remove the job's escape-hatch containers and release ledger entries.

        Only consults the docker daemon when the ledger actually holds
        escape-hatch entries for this challenge, so backends without the
        escape hatch in play never spawn a subprocess here. ``--no-trunc``
        keeps the listed IDs FULL so they match the ledger keys.
        """

        if not any(
            entry.kind == "escape_hatch_container"
            and entry.challenge_slug == challenge_slug
            for entry in self.ledger.entries()
        ):
            return
        docker_bin = self.config.docker_bin
        listed = self.escape_runner.run(
            [
                docker_bin,
                "ps",
                "-aq",
                "--no-trunc",
                "--filter",
                f"label=platform.challenge={challenge_slug}",
                "--filter",
                f"label=platform.job={job_id}",
            ]
        )
        if listed.returncode != 0:
            return
        for line in listed.stdout.splitlines():
            container_id = line.strip()
            if not container_id:
                continue
            self.escape_runner.run([docker_bin, "rm", "-f", container_id])
            self.ledger.release(container_id)

    def _cap_log(self, value: str) -> str:
        encoded = value.encode(errors="replace")
        limit = self.config.log_limit_bytes
        if len(encoded) <= limit:
            return value
        return encoded[-limit:].decode(errors="replace")


def build_escape_hatch_run_argv(
    docker_bin: str,
    *,
    name: str,
    request: BrokerRunRequest,
    mounts: Sequence[DockerMount],
    labels: Mapping[str, str],
    dind_volume: str,
) -> list[str]:
    """Build the detached privileged ``docker run`` argv for a DinD job.

    Mirrors ``DockerExecutor.build_run_command`` (the cli/escape-hatch argv
    reference, incl. the Task-11 ``--read-only`` -> ``--gpus`` ->
    ``--privileged`` insertion order) with DinD-mandated deviations:

    * ``--cap-drop`` is omitted: dockerd rejects ``--privileged`` combined
      with dropped capabilities ("conflicting options").
    * ``--security-opt no-new-privileges`` is omitted: the inner daemon needs
      privilege escalation (runc setuid) to start containers.
    * ``--read-only`` is omitted: the inner daemon writes outside
      ``/var/lib/docker`` (``/run``, ``/etc/docker``), so a read-only rootfs
      breaks DinD; its image/container storage is confined to the dedicated
      named volume instead.
    * ``--detach`` (no ``--rm``) so the FULL container ID is captured for
      ledger keying; logs are collected and the container is removed
      explicitly afterwards.
    """

    limits = request.limits
    cmd = [
        docker_bin,
        "run",
        "--detach",
        "--name",
        name,
        "--network",
        limits.network,
        "--cpus",
        str(limits.cpus),
        "--memory",
        limits.memory,
        "--pids-limit",
        str(limits.pids_limit),
    ]
    if limits.init:
        cmd.append("--init")
    if limits.memory_swap:
        cmd.extend(["--memory-swap", limits.memory_swap])
    # Task-11 insertion order preserved: (--read-only slot, omitted for
    # DinD) -> --gpus -> --privileged.
    if limits.gpu_count:
        cmd.extend(["--gpus", str(limits.gpu_count)])
    cmd.append("--privileged")
    if limits.user:
        cmd.extend(["--user", limits.user])
    for tmpfs in limits.tmpfs:
        cmd.extend(["--tmpfs", tmpfs])
    for ulimit in limits.ulimits:
        cmd.extend(["--ulimit", ulimit])
    cmd.extend(["-v", f"{dind_volume}:{ESCAPE_HATCH_DIND_MOUNT_TARGET}"])
    for mount in mounts:
        cmd.extend(["-v", mount.as_volume_arg()])
    if request.workdir:
        cmd.extend(["-w", request.workdir])
    for key, value in request.env.items():
        cmd.extend(["-e", f"{key}={value}"])
    for key, value in labels.items():
        cmd.extend(["--label", f"{key}={value}"])
    cmd.extend([request.image, *request.command])
    return cmd


def create_docker_broker_app(
    *,
    registry: BrokerTokenRegistry,
    service: BrokerService | None = None,
) -> FastAPI:
    broker: BrokerService = service or DockerBrokerService()
    app = FastAPI(title="Platform Docker Broker", version="1.0")

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        # Must stay native ``async def`` with zero blocking work: sync handlers
        # share the anyio threadpool with long-running /v1/docker/* calls, and a
        # sync probe queueing behind them lets the supervisor watchdog restart a
        # healthy broker (death-spiral).
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
        except WorkloadCapacityError as exc:
            # Quota refusal (Task 14): 429 because the condition is transient
            # (a slot frees on release) and the client should retry later;
            # the frozen ``{"detail": str}`` envelope carries the stable
            # machine-readable ``docker_quota_exceeded`` code prefix.
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                f"docker_quota_exceeded: {exc}",
            ) from exc
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


def _escape_container_name(
    challenge_slug: str, job_id: str, task_id: str | None
) -> str:
    pieces = [_safe_fragment(challenge_slug), _safe_fragment(job_id[:12])]
    if task_id:
        pieces.append(_safe_fragment(task_id)[:40])
    pieces.append(uuid.uuid4().hex[:8])
    return "-".join(piece for piece in pieces if piece)


def _parse_wait_exit_code(stdout: str) -> int:
    lines = stdout.strip().splitlines()
    try:
        return int(lines[0])
    except (IndexError, ValueError):
        return 1


def _coerce_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value
