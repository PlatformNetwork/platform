"""Secure Docker CLI executor for challenge-side evaluation containers."""

from __future__ import annotations

import re
import subprocess
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

_IMAGE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9./_:@+-]{0,254}$")


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


@dataclass(frozen=True)
class DockerRunResult:
    """Completed Docker run result with bounded logs."""

    container_name: str
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False


@dataclass
class DockerExecutor:
    """Run labelled, resource-limited Docker containers via Docker CLI."""

    challenge: str
    docker_bin: str = "docker"
    allowed_images: tuple[str, ...] = ()
    log_limit_bytes: int = 64_000

    def run(self, spec: DockerRunSpec, timeout_seconds: int) -> DockerRunResult:
        self._validate_spec(spec)
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
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--init",
        ]
        if limits.memory_swap:
            cmd.extend(["--memory-swap", limits.memory_swap])
        if limits.read_only:
            cmd.append("--read-only")
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
        labels = {
            "platform.challenge": self.challenge,
            **dict(spec.labels),
        }
        for key, value in labels.items():
            cmd.extend(["--label", f"{key}={value}"])
        cmd.extend([spec.image, *spec.command])
        return cmd

    def cleanup_job(self, job_id: str) -> None:
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
        if spec.limits.network != "none" and not spec.limits.network.startswith(
            "platform_"
        ):
            raise DockerExecutorError(
                "Docker network must be 'none' or a platform network"
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
