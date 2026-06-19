"""Secure Docker CLI executor for challenge-side evaluation containers."""

from __future__ import annotations

import base64
import io
import json
import logging
import math
import re
import subprocess
import tarfile
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from platform_network.challenge_sdk.mount_transport import (
    extract_archive_to_dir,
    parse_drained_archives,
    strip_drain_sections,
)

_logger = logging.getLogger(__name__)

_IMAGE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9./_:@+-]{0,254}$")
_IMAGE_PULL_POLICIES = {"Always", "IfNotPresent", "Never"}

#: Members the broker's ``_validate_tar_members`` rejects (symlinks, hardlinks,
#: devices, FIFOs); one present makes the broker refuse the whole mount archive.
#: We DROP them rather than use ``dereference=True``: dropping never reads a link
#: target, whereas dereference would resolve an attacker-controlled symlink (e.g.
#: ``evil -> /run/secrets/...``) on the worker node and bake the secret into a
#: regular-file member that passes broker validation.
_DISALLOWED_MEMBER_CHECKS = ("issym", "islnk", "isdev", "ischr", "isblk", "isfifo")


def _safe_mount_member(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
    if any(getattr(info, check)() for check in _DISALLOWED_MEMBER_CHECKS):
        _logger.warning("dropping non-regular mount member from archive: %s", info.name)
        return None
    return info


class DockerExecutorError(RuntimeError):
    """Raised when a Docker evaluation container cannot be executed safely."""


@dataclass(frozen=True)
class DockerMount:
    """Bind mount for a Docker run spec."""

    source: Path
    target: str
    read_only: bool = True

    def as_volume_arg(self) -> str:
        mode = "ro" if self.read_only else "rw"
        return f"{self.source.resolve()}:{self.target}:{mode}"


@dataclass(frozen=True)
class DockerLimits:
    """Resource and kernel-surface limits for an evaluation container."""

    cpus: float = 2.0
    memory: str = "4g"
    memory_swap: str | None = "4g"
    pids_limit: int = 512
    network: str = "none"
    read_only: bool = True
    user: str | None = None
    tmpfs: tuple[str, ...] = ("/tmp:rw,noexec,nosuid,size=512m",)
    ulimits: tuple[str, ...] = ("nofile=1024:1024",)
    cap_drop: tuple[str, ...] = ("ALL",)
    security_opt: tuple[str, ...] = ("no-new-privileges",)
    init: bool = True
    gpu_count: int | None = None
    privileged: bool = False

    def __post_init__(self) -> None:
        if not math.isfinite(self.cpus) or self.cpus <= 0:
            raise DockerExecutorError("Docker CPU limit must be positive and finite")
        if not self.memory.strip():
            raise DockerExecutorError("Docker memory limit cannot be empty")
        if self.memory_swap is not None and not self.memory_swap.strip():
            raise DockerExecutorError("Docker memory swap limit cannot be empty")
        if self.pids_limit < 1:
            raise DockerExecutorError("Docker PID limit must be at least 1")
        if self.gpu_count is not None and (
            isinstance(self.gpu_count, bool)
            or not isinstance(self.gpu_count, int)
            or self.gpu_count < 1
        ):
            raise DockerExecutorError(
                "Docker GPU count must be a positive integer when set"
            )
        if not self.cap_drop:
            raise DockerExecutorError(
                "Docker cap_drop must drop at least one capability"
            )
        if not self.security_opt:
            raise DockerExecutorError(
                "Docker security_opt must include at least one security option"
            )


@dataclass(frozen=True)
class DockerRunSpec:
    """Generic Docker container run request."""

    image: str
    command: tuple[str, ...]
    mounts: tuple[DockerMount, ...] = ()
    workdir: str | None = None
    env: Mapping[str, str] = field(default_factory=dict)
    labels: Mapping[str, str] = field(default_factory=dict)
    name: str | None = None
    limits: DockerLimits = field(default_factory=DockerLimits)
    image_pull_policy: str | None = None


@dataclass(frozen=True)
class DockerRunResult:
    """Completed Docker run result with bounded logs."""

    container_name: str
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False


@dataclass(frozen=True)
class DockerContainerInfo:
    """Docker container metadata scoped to a single challenge."""

    container_id: str
    container_name: str
    image: str = ""
    status: str = ""
    job_id: str | None = None
    task_id: str | None = None
    created: str | None = None
    labels: Mapping[str, str] = field(default_factory=dict)


@dataclass
class DockerExecutor:
    """Run labelled, resource-limited Docker containers via Docker CLI."""

    challenge: str
    docker_bin: str = "docker"
    allowed_images: tuple[str, ...] = ()
    log_limit_bytes: int = 64_000
    backend: str = "cli"
    broker_url: str | None = None
    broker_token: str | None = None
    broker_token_file: str | None = None

    def run(self, spec: DockerRunSpec, timeout_seconds: int) -> DockerRunResult:
        self._validate_spec(spec)
        if self.backend == "broker":
            return self._run_via_broker(spec, timeout_seconds)
        if self.backend not in {"cli", "docker"}:
            raise DockerExecutorError(
                f"unsupported Docker executor backend: {self.backend}"
            )
        name = spec.name or self.container_name(spec.labels.get("platform.job", "job"))
        cmd = self.build_run_command(spec, name)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            return DockerRunResult(
                container_name=name,
                stdout=self._cap(proc.stdout),
                stderr=self._cap(proc.stderr),
                returncode=proc.returncode,
            )
        except subprocess.TimeoutExpired as exc:
            self.remove_container(name)
            return DockerRunResult(
                container_name=name,
                stdout=self._cap(exc.stdout or ""),
                stderr=self._cap(exc.stderr or ""),
                returncode=124,
                timed_out=True,
            )
        finally:
            self.remove_container(name)

    def build_run_command(self, spec: DockerRunSpec, name: str) -> list[str]:
        self._validate_spec(spec)
        limits = spec.limits
        cmd = [
            self.docker_bin,
            "run",
            "--rm",
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
        for capability in limits.cap_drop:
            cmd.extend(["--cap-drop", capability])
        for security_opt in limits.security_opt:
            cmd.extend(["--security-opt", security_opt])
        if limits.init:
            cmd.append("--init")
        if limits.memory_swap:
            cmd.extend(["--memory-swap", limits.memory_swap])
        if limits.read_only:
            cmd.append("--read-only")
        if limits.gpu_count:
            cmd.extend(["--gpus", str(limits.gpu_count)])
        if limits.privileged:
            cmd.append("--privileged")
        if limits.user:
            cmd.extend(["--user", limits.user])
        for tmpfs in limits.tmpfs:
            cmd.extend(["--tmpfs", tmpfs])
        for ulimit in limits.ulimits:
            cmd.extend(["--ulimit", ulimit])
        for mount in spec.mounts:
            cmd.extend(["-v", mount.as_volume_arg()])
        if spec.workdir:
            cmd.extend(["-w", spec.workdir])
        for key, value in spec.env.items():
            cmd.extend(["-e", f"{key}={value}"])
        labels = {**dict(spec.labels), "platform.challenge": self.challenge}
        if "platform.job" in spec.labels:
            labels["platform.job"] = str(spec.labels["platform.job"])
        if "platform.task" in spec.labels:
            labels["platform.task"] = str(spec.labels["platform.task"])
        for key, value in labels.items():
            cmd.extend(["--label", f"{key}={value}"])
        cmd.extend([spec.image, *spec.command])
        return cmd

    def cleanup_job(self, job_id: str) -> None:
        if self.backend == "broker":
            self._post_broker(
                "/v1/docker/cleanup", {"job_id": job_id}, timeout_seconds=30
            )
            return
        filters = [
            "--filter",
            f"label=platform.challenge={self.challenge}",
            "--filter",
            f"label=platform.job={job_id}",
        ]
        proc = subprocess.run(
            [self.docker_bin, "ps", "-aq", *filters],
            capture_output=True,
            text=True,
            check=False,
        )
        ids = [line for line in proc.stdout.splitlines() if line.strip()]
        if ids:
            subprocess.run(
                [self.docker_bin, "rm", "-f", *ids],
                capture_output=True,
                text=True,
                check=False,
            )

    def list_containers(self, job_id: str | None = None) -> list[DockerContainerInfo]:
        if self.backend == "broker":
            payload: dict[str, object] = {}
            if job_id:
                payload["job_id"] = job_id
            data = self._post_broker("/v1/docker/list", payload, timeout_seconds=30)
            containers = data.get("containers", [])
            if not isinstance(containers, list):
                raise DockerExecutorError("Docker broker returned invalid list payload")
            return [
                DockerContainerInfo(
                    container_id=str(item.get("container_id") or ""),
                    container_name=str(item.get("container_name") or ""),
                    image=str(item.get("image") or ""),
                    status=str(item.get("status") or ""),
                    job_id=item.get("job_id"),
                    task_id=item.get("task_id"),
                    created=item.get("created"),
                    labels=dict(item.get("labels") or {}),
                )
                for item in containers
                if isinstance(item, dict)
            ]
        filters = ["--filter", f"label=platform.challenge={self.challenge}"]
        if job_id:
            filters.extend(["--filter", f"label=platform.job={job_id}"])
        proc = subprocess.run(
            [
                self.docker_bin,
                "ps",
                "-a",
                *filters,
                "--format",
                "{{json .}}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise DockerExecutorError(f"Docker list failed: {self._cap(proc.stderr)}")
        return [
            _container_from_ps_json(line)
            for line in proc.stdout.splitlines()
            if line.strip()
        ]

    def remove_container(self, name: str) -> None:
        subprocess.run(
            [self.docker_bin, "rm", "-f", name],
            capture_output=True,
            text=True,
            check=False,
        )

    def container_name(self, job_id: str, task_id: str | None = None) -> str:
        pieces = [self.challenge, job_id[:12]]
        if task_id:
            pieces.append(_safe_fragment(task_id, 40))
        pieces.append(uuid.uuid4().hex[:8])
        return "-".join(_safe_fragment(piece, 48) for piece in pieces if piece)

    def _validate_spec(self, spec: DockerRunSpec) -> None:
        if not _IMAGE_RE.match(spec.image) or spec.image.startswith("-"):
            raise DockerExecutorError(f"unsafe Docker image reference: {spec.image!r}")
        if self.allowed_images and not _matches_allowed(
            spec.image, self.allowed_images
        ):
            raise DockerExecutorError(f"Docker image is not allowed: {spec.image}")
        if not spec.command:
            raise DockerExecutorError("Docker command cannot be empty")
        if spec.image_pull_policy is not None and (
            spec.image_pull_policy not in _IMAGE_PULL_POLICIES
        ):
            raise DockerExecutorError(
                "Docker image pull policy must be Always, IfNotPresent, or Never"
            )
        if spec.limits.network not in {"none", "default"} and (
            not spec.limits.network.startswith("platform_")
        ):
            raise DockerExecutorError(
                "Docker network must be 'none', 'default', or a platform network"
            )
        for mount in spec.mounts:
            if not mount.source.exists():
                raise DockerExecutorError(
                    f"mount source does not exist: {mount.source}"
                )
            if not mount.target.startswith("/"):
                raise DockerExecutorError(
                    f"mount target must be absolute: {mount.target}"
                )

    def _run_via_broker(
        self, spec: DockerRunSpec, timeout_seconds: int
    ) -> DockerRunResult:
        payload = {
            "job_id": spec.labels.get("platform.job", "job"),
            "task_id": spec.labels.get("platform.task"),
            "image": spec.image,
            "image_pull_policy": spec.image_pull_policy,
            "command": list(spec.command),
            "workdir": spec.workdir,
            "env": dict(spec.env),
            "labels": dict(spec.labels),
            "limits": asdict(spec.limits),
            "mounts": [_encode_mount(mount) for mount in spec.mounts],
            "timeout_seconds": timeout_seconds,
        }
        data = self._post_broker(
            "/v1/docker/run", payload, timeout_seconds=timeout_seconds + 15
        )
        returncode = data.get("returncode", 0)
        stdout = str(data.get("stdout") or "")
        # A broker job may run on a remote node; writable mounts it wrote are
        # drained back through stdout sentinels. Repopulate each writable mount
        # source so callers read artifacts (e.g. the eval manifest) from the
        # path they staged, then drop the drain sections from the logs.
        archives = parse_drained_archives(stdout)
        if archives:
            self._restore_drained_mounts(spec, archives)
            stdout = strip_drain_sections(stdout)
        return DockerRunResult(
            container_name=str(data["container_name"]),
            stdout=stdout,
            stderr=str(data.get("stderr") or ""),
            returncode=returncode
            if isinstance(returncode, int)
            else int(str(returncode)),
            timed_out=bool(data.get("timed_out") or False),
        )

    def _restore_drained_mounts(
        self, spec: DockerRunSpec, archives: Mapping[int, bytes]
    ) -> None:
        for index, archive in archives.items():
            if index >= len(spec.mounts):
                continue
            mount = spec.mounts[index]
            if mount.read_only:
                continue
            extract_archive_to_dir(archive, mount.source)

    def _post_broker(
        self, path: str, payload: Mapping[str, object], timeout_seconds: int
    ) -> dict[str, object]:
        if not self.broker_url:
            raise DockerExecutorError("Docker broker URL is not configured")
        token = self._broker_token()
        if token is None:
            raise DockerExecutorError("Docker broker token is not configured")
        body = json.dumps(payload, separators=(",", ":")).encode()
        request = Request(
            f"{self.broker_url.rstrip('/')}{path}",
            data=body,
            method="POST",
            headers={
                "authorization": f"Bearer {token}",
                "content-type": "application/json",
                "x-platform-challenge-slug": self.challenge,
            },
        )
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise DockerExecutorError(
                f"Docker broker request failed: {detail}"
            ) from exc
        except (OSError, URLError) as exc:
            raise DockerExecutorError(f"Docker broker is unavailable: {exc}") from exc

    def _broker_token(self) -> str | None:
        if self.broker_token:
            return self.broker_token
        if self.broker_token_file:
            path = Path(self.broker_token_file)
            if path.is_file():
                token = path.read_text(encoding="utf-8").strip()
                return token or None
        return None

    def _cap(self, value: str | bytes) -> str:
        if isinstance(value, bytes):
            value = value.decode(errors="replace")
        encoded = value.encode(errors="replace")
        if len(encoded) <= self.log_limit_bytes:
            return value
        return encoded[-self.log_limit_bytes :].decode(errors="replace")


def _safe_fragment(value: str, limit: int) -> str:
    safe = "".join(ch if ch.isalnum() else "-" for ch in value.lower()).strip("-")
    return (safe or "x")[:limit]


def _matches_allowed(image: str, allowed: Sequence[str]) -> bool:
    return any(image == item or image.startswith(item.rstrip("*")) for item in allowed)


def _container_from_ps_json(line: str) -> DockerContainerInfo:
    data = json.loads(line)
    labels = _parse_label_string(str(data.get("Labels") or ""))
    return DockerContainerInfo(
        container_id=str(data.get("ID") or ""),
        container_name=str(data.get("Names") or ""),
        image=str(data.get("Image") or ""),
        status=str(data.get("Status") or ""),
        created=str(data.get("CreatedAt") or "") or None,
        job_id=labels.get("platform.job"),
        task_id=labels.get("platform.task"),
        labels=labels,
    )


def _parse_label_string(raw: str) -> dict[str, str]:
    labels: dict[str, str] = {}
    for item in raw.split(","):
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        labels[key] = value
    return labels


def _encode_mount(mount: DockerMount) -> dict[str, object]:
    source = mount.source.resolve()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        if source.is_dir():
            tar.add(source, arcname=".", filter=_safe_mount_member)
            source_type = "directory"
            source_name = "."
        else:
            tar.add(source, arcname=source.name, filter=_safe_mount_member)
            source_type = "file"
            source_name = source.name
    return {
        "target": mount.target,
        "read_only": mount.read_only,
        "source_type": source_type,
        "source_name": source_name,
        "archive_b64": base64.b64encode(stream.getvalue()).decode("ascii"),
    }
