"""Docker Swarm backend behind the frozen Docker broker contract (Task 9).

This module implements the docker backend's workload operations as Docker
Swarm operations while keeping the broker HTTP contract
(``schemas/docker_broker.py`` + ``tests/contract/test_broker_golden.py``)
byte-identical:

* ``/v1/docker/run``      -> ``docker service create --mode replicated-job
  --restart-condition none`` (evaluation jobs MUST never auto-restart).
* ``/v1/docker/cleanup``  -> ``docker service rm`` + ledger release.
* ``/v1/docker/list``     -> ``docker service ls``/``inspect`` mapped back to
  the frozen ``BrokerListResponse`` shape.
* :class:`SwarmChallengeOrchestrator` schedules long-lived challenge APIs
  (``ChallengeSpec.workload_class == "service"``) as replicated services on
  the encrypted overlay network with Swarm secrets.

Swarm-specific decisions (see ``.omo/plans/platform-docker-migration.md``):

* Placement is per workload: challenge API services run on the manager/host
  (``node.role==manager``) while broker eval jobs run on workers, steered to
  CPU- vs GPU-labeled nodes via ``node.labels.base.workload`` (cpu/gpu).
* Swarm cannot attach services to the predefined ``none`` network, so
  ``limits.network == "none"`` maps to a dedicated *internal* encrypted
  overlay (no external routes) instead.
* Overlay networks are created encrypted with MTU 1450.
* ``--security-opt`` and ``--memory-swap`` are not supported by
  ``docker service create``; ``no-new-privileges`` is enforced daemon-wide
  via daemon.json (Task 8/28) and swap limits are not emitted.
* Every created service is registered in the shared
  :class:`~base.master.workload_ledger.WorkloadLedger`
  (register-then-create; released on failed create AND on cleanup).
* GPU workloads (Task 10) are expressed as Swarm generic resources:
  ``--generic-resource "NVIDIA-GPU=N"`` (name case-sensitive, matching the
  worker daemon.json advertisement from Task 8) with capacity bookkeeping in
  :class:`~base.gpu.leases.GpuLeaseLedger` (lease acquired before
  ``service create``, released on cleanup/failure). This module deliberately
  emits no ``--gpus``/``--privileged`` flags (Swarm rejects them; the
  escape hatch is Task 13).
"""

from __future__ import annotations

import json
import re
import subprocess
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Literal, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from base.challenge_sdk.executors.docker import (
    DockerExecutorError,
    DockerLimits,
    DockerMount,
)
from base.challenge_sdk.mount_transport import (
    TransportMount,
    build_bootstrap_command,
    encode_mount_in_env,
    extract_archive_to_dir,
    extract_drain_sections,
    parse_drained_archives,
    strip_drain_sections,
)
from base.gpu.leases import GpuCapacityError, GpuLeaseLedger
from base.master.docker_broker import (
    DockerBrokerConfig,
    DockerBrokerService,
    EscapeHatchCommandRunner,
)
from base.master.docker_orchestrator import (
    DEFAULT_DOCKER_BROKER_URL,
    DEFAULT_NETWORK_NAME,
    DEFAULT_SECRET_MOUNT_DIR,
    DEFAULT_SQLITE_PATH,
    ChallengeRuntime,
    ChallengeSpec,
    DockerOrchestrationError,
)
from base.master.workload_ledger import (
    WorkloadEntry,
    WorkloadLedger,
)
from base.schemas.docker_broker import (
    BrokerCleanupRequest,
    BrokerCleanupResponse,
    BrokerContainerInfo,
    BrokerListRequest,
    BrokerListResponse,
    BrokerRunRequest,
    BrokerRunResponse,
)

DEFAULT_CHALLENGE_CONSTRAINT = "node.role==manager"
DEFAULT_CPU_JOB_CONSTRAINT = "node.labels.base.workload==cpu"
DEFAULT_GPU_JOB_CONSTRAINT = "node.labels.base.workload==gpu"
DEFAULT_JOB_NETWORK = "base_jobs_internal"
OVERLAY_MTU = "1450"
#: Swarm generic-resource name advertised by the worker daemon.json
#: (``node-generic-resources: ["NVIDIA-GPU=GPU-<uuid>"]``); case-sensitive.
GPU_GENERIC_RESOURCE_NAME = "NVIDIA-GPU"

#: Swarm task states that mean a replicated-job task will never run again
#: (``--restart-condition none`` guarantees no new task is scheduled).
JOB_TERMINAL_STATES = frozenset(
    {"complete", "failed", "rejected", "orphaned", "shutdown"}
)

_IMAGE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9./_:@+-]{0,254}$")
_SAFE_RE = re.compile(r"[^a-z0-9]+")


class SwarmBackendError(RuntimeError):
    """Raised when a Swarm CLI operation fails outside the broker run path."""


@dataclass(frozen=True)
class SwarmCommandResult:
    """Captured outcome of one docker CLI invocation."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class SwarmCommandRunner(Protocol):
    """Executes a docker CLI argv. Tests inject argv-capturing fakes."""

    def run(
        self,
        argv: Sequence[str],
        *,
        input_text: str | None = None,
        timeout_seconds: float | None = None,
    ) -> SwarmCommandResult: ...


class SwarmCliRunner:
    """Run docker CLI commands via subprocess (the only process-spawn site)."""

    def run(
        self,
        argv: Sequence[str],
        *,
        input_text: str | None = None,
        timeout_seconds: float | None = None,
    ) -> SwarmCommandResult:
        try:
            proc = subprocess.run(
                list(argv),
                input=input_text,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SwarmBackendError(
                f"docker command timed out after {timeout_seconds}s: {argv[:4]}"
            ) from exc
        return SwarmCommandResult(
            argv=tuple(argv),
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )


@dataclass(frozen=True)
class SwarmServicePlan:
    """Declarative input for ``docker service create`` argv construction.

    GPU intent is carried as ``generic_resources`` entries (e.g.
    ``"NVIDIA-GPU=1"`` built by :func:`gpu_generic_resources`) and emitted as
    ``--generic-resource`` flags. Nothing in this module may ever emit
    ``--privileged`` (Swarm services cannot run privileged; the escape hatch
    is Task 13) or ``--gpus`` (cli/escape-hatch only, Task 11).
    """

    name: str
    image: str
    command: tuple[str, ...] = ()
    mode: Literal["replicated-job", "replicated"] = "replicated-job"
    replicas: int = 1
    constraint: str | None = None
    network: str | None = None
    #: Additional overlay networks the service is attached to, each emitted as
    #: its own ``--network`` flag AFTER ``network``. Used to multi-home a
    #: long-lived challenge service on the isolated ``base_jobs_internal`` eval
    #: overlay (so an eval JOB can resolve it by name) in addition to the
    #: ``base_challenges`` control overlay; empty keeps single-network argv.
    extra_networks: tuple[str, ...] = ()
    env: tuple[tuple[str, str], ...] = ()
    labels: tuple[tuple[str, str], ...] = ()
    container_labels: tuple[tuple[str, str], ...] = ()
    mounts: tuple[str, ...] = ()
    secrets: tuple[str, ...] = ()
    limit_cpus: float | None = None
    limit_memory: str | None = None
    limit_pids: int | None = None
    read_only: bool = False
    init: bool = False
    cap_drop: tuple[str, ...] = ()
    ulimits: tuple[str, ...] = ()
    user: str | None = None
    workdir: str | None = None
    hostname: str | None = None
    generic_resources: tuple[str, ...] = ()
    with_registry_auth: bool = False


def gpu_generic_resources(gpu_count: int | None) -> tuple[str, ...]:
    """Translate a GPU count into Swarm generic-resource plan entries.

    ``None``/``0`` means no GPU intent and yields no flags at all, keeping
    non-GPU argv byte-identical to the pre-GPU builder output.
    """

    if not gpu_count:
        return ()
    return (f"{GPU_GENERIC_RESOURCE_NAME}={gpu_count}",)


def build_service_create_argv(docker_bin: str, plan: SwarmServicePlan) -> list[str]:
    """Build the ``docker service create`` argv for a service plan.

    Jobs (``mode == "replicated-job"``) always get ``--restart-condition
    none`` so an evaluation can never auto-restart; long-lived services get
    ``--restart-condition any``.
    """

    argv = [docker_bin, "service", "create", "--detach", "--name", plan.name]
    if plan.mode == "replicated-job":
        argv += ["--mode", "replicated-job", "--restart-condition", "none"]
    else:
        argv += [
            "--mode",
            "replicated",
            "--replicas",
            str(plan.replicas),
            "--restart-condition",
            "any",
        ]
    if plan.with_registry_auth:
        argv.append("--with-registry-auth")
    if plan.constraint:
        argv += ["--constraint", plan.constraint]
    if plan.network:
        argv += ["--network", plan.network]
    for extra_network in plan.extra_networks:
        argv += ["--network", extra_network]
    if plan.hostname:
        argv += ["--hostname", plan.hostname]
    if plan.limit_cpus is not None:
        argv += ["--limit-cpu", str(plan.limit_cpus)]
    if plan.limit_memory:
        argv += ["--limit-memory", plan.limit_memory]
    if plan.limit_pids is not None:
        argv += ["--limit-pids", str(plan.limit_pids)]
    if plan.read_only:
        argv.append("--read-only")
    if plan.init:
        argv.append("--init")
    for capability in plan.cap_drop:
        argv += ["--cap-drop", capability]
    for ulimit in plan.ulimits:
        argv += ["--ulimit", ulimit]
    if plan.user:
        argv += ["--user", plan.user]
    if plan.workdir:
        argv += ["--workdir", plan.workdir]
    for mount in plan.mounts:
        argv += ["--mount", mount]
    for secret in plan.secrets:
        argv += ["--secret", secret]
    for key, value in plan.env:
        argv += ["--env", f"{key}={value}"]
    for key, value in plan.labels:
        argv += ["--label", f"{key}={value}"]
    for key, value in plan.container_labels:
        argv += ["--container-label", f"{key}={value}"]
    # GPU challenges request Swarm generic resources here (Task 10); the
    # resource name is case-sensitive and must match the worker daemon.json
    # advertisement (see Task 8 notes). Image/command MUST stay last.
    for resource in plan.generic_resources:
        argv += ["--generic-resource", resource]
    argv.append(plan.image)
    argv.extend(plan.command)
    return argv


def build_overlay_network_argv(
    docker_bin: str, name: str, *, internal: bool
) -> list[str]:
    """Encrypted, MTU-1450, attachable overlay network create argv."""

    argv = [
        docker_bin,
        "network",
        "create",
        "--driver",
        "overlay",
        "--attachable",
        "--opt",
        "encrypted",
        "--opt",
        f"com.docker.network.driver.mtu={OVERLAY_MTU}",
    ]
    if internal:
        argv.append("--internal")
    argv.append(name)
    return argv


@dataclass(frozen=True)
class SwarmBrokerConfig(DockerBrokerConfig):
    """Broker config plus Swarm scheduling knobs.

    Broker eval jobs run on workers steered by node labels: GPU jobs land on
    ``gpu_job_constraint`` nodes and CPU jobs on ``cpu_job_constraint`` nodes.
    Either set to ``None`` disables that constraint flag (single-node test/QA
    swarms only).
    """

    job_network: str = DEFAULT_JOB_NETWORK
    cpu_job_constraint: str | None = DEFAULT_CPU_JOB_CONSTRAINT
    gpu_job_constraint: str | None = DEFAULT_GPU_JOB_CONSTRAINT
    poll_interval_seconds: float = 1.0
    command_timeout_seconds: float = 60.0
    #: Challenge slugs whose Swarm jobs receive a read-write bind mount of the
    #: host Docker socket (Docker-out-of-Docker). This lets a broker-created
    #: Swarm job spawn sibling task containers on the worker daemon without
    #: ``--privileged`` (which ``docker service create`` rejects). The socket
    #: is root-equivalent on the worker, so the empty default grants it to no
    #: one; only allowlisted slugs (authenticated per-slug broker token) get
    #: it. Hardening (read-only rootfs, cap-drop ALL, no-new-privileges) still
    #: applies: the job is only a Docker *client* of the host daemon.
    docker_socket_slugs: frozenset[str] = frozenset()
    docker_socket_path: str = "/var/run/docker.sock"
    #: Read-only mounts injected for the same slugs as ``docker_socket_slugs``
    #: (the DooD eval slugs). Each entry is ``(source, target)`` where
    #: ``source`` is an absolute host path or a Docker named volume and
    #: ``target`` is the absolute container mount path. Used to hand the
    #: terminal-bench task cache + frozen digest manifest to own_runner jobs
    #: without baking them into the runner image. Empty default mounts nothing.
    eval_readonly_mounts: tuple[tuple[str, str], ...] = ()
    #: Per-slug read-only mounts injected into the Swarm eval job, decoupled
    #: from the Docker-out-of-Docker socket allowlist. Used to bind-mount the
    #: locked prism FineWeb-Edu train split (+ reference tokenizers) READ-ONLY
    #: into the prism eval container, which must NOT receive the host Docker
    #: socket (prism is not a DooD slug). Each value mirrors
    #: ``eval_readonly_mounts``: a tuple of ``(source, target)`` where
    #: ``source`` is an absolute host path or a Docker named volume. Empty
    #: default mounts nothing for any slug.
    eval_readonly_mounts_by_slug: Mapping[str, tuple[tuple[str, str], ...]] = field(
        default_factory=dict
    )
    #: Challenge slugs whose Swarm eval job runs UNTRUSTED miner code and must
    #: never reach an external route. For these slugs the job is force-attached
    #: to the dedicated *internal* (``--internal``, no egress) overlay
    #: regardless of the requested network, closing the host-egress drift where
    #: ``network="default"`` would otherwise return ``None`` (host bridge with
    #: egress). The trusted long-lived challenge scorer service is NOT a broker
    #: job and is unaffected. Empty default locks no one.
    egress_locked_slugs: frozenset[str] = frozenset()


@dataclass(frozen=True)
class _JobOutcome:
    returncode: int
    timed_out: bool = False
    error: str = ""


class SwarmBrokerService(DockerBrokerService):
    """Frozen-contract broker service backed by Swarm replicated-jobs.

    Reuses :class:`DockerBrokerService` request hardening
    (``_hardened_limits`` — privileged refusal and read-only/init/cap-drop/
    no-new-privileges enforcement, byte-identical error envelopes) and mount
    materialization (``_materialize_mount``), but executes via
    ``docker service`` commands instead of ``docker run``.
    """

    def __init__(
        self,
        config: SwarmBrokerConfig | None = None,
        *,
        runner: SwarmCommandRunner | None = None,
        ledger: WorkloadLedger | None = None,
        gpu_leases: GpuLeaseLedger | None = None,
        escape_runner: EscapeHatchCommandRunner | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        swarm_config = config or SwarmBrokerConfig()
        super().__init__(swarm_config, escape_runner=escape_runner, ledger=ledger)
        self.swarm_config = swarm_config
        self.runner: SwarmCommandRunner = runner or SwarmCliRunner()
        self.gpu_leases = gpu_leases or GpuLeaseLedger()
        self._clock = clock
        self._sleep = sleep

    # ------------------------------------------------------------------ run
    def run(self, challenge_slug: str, request: BrokerRunRequest) -> BrokerRunResponse:
        if request.limits.privileged and self._escape_hatch_allowed(challenge_slug):
            # Privileged DinD jobs (Task 13) cannot run as Swarm services
            # (``docker service create`` rejects ``--privileged``); the
            # capability-gated escape hatch runs them as a direct local
            # ``docker run`` on this worker node instead.
            return self._run_escape_hatch(challenge_slug, request)
        limits = self._hardened_limits(request)
        self._validate_request(request)
        with TemporaryDirectory(
            prefix=f"{_safe_fragment(challenge_slug, 48)}-"
            f"{_safe_fragment(request.job_id, 48)}-",
            dir=self.config.workspace_dir,
        ) as workspace:
            workspace_path = Path(workspace)
            mounts = [
                self._materialize_mount(workspace_path, index, mount)
                for index, mount in enumerate(request.mounts)
            ]
            # tmpfs limits must be honored on the Swarm job path: with the
            # hardening-mandated read-only rootfs a job would otherwise have
            # no writable /tmp.
            try:
                tmpfs_mounts = tuple(_tmpfs_mount_arg(value) for value in limits.tmpfs)
            except DockerOrchestrationError as exc:
                raise DockerExecutorError(str(exc)) from exc
            name = _service_name(challenge_slug, request.job_id, request.task_id)
            labels = {
                **request.labels,
                "base.challenge": challenge_slug,
                "base.job": request.job_id,
            }
            if request.task_id:
                labels["base.task"] = request.task_id
            # A GPU job is scheduled on the GPU worker, NOT on this (manager)
            # broker node, so a host bind-mount source materialized here does
            # not exist there. Ship the materialized mounts INTO the remote
            # container as env-carried archives extracted by a bootstrap, and
            # drain writable mounts back out via stdout (see ``mount_transport``
            # and ``_persist_drained_mounts``). CPU jobs run on the broker node
            # and keep the cheaper direct bind mounts.
            cross_node = self._is_cross_node(limits) and bool(mounts)
            if cross_node:
                env = dict(request.env)
                transport: list[TransportMount] = []
                for index, m in enumerate(mounts):
                    in_env = encode_mount_in_env(index, m.source)
                    env.update(in_env)
                    transport.append(
                        TransportMount(
                            index=index,
                            target=m.target,
                            writable=not m.read_only,
                            in_chunks=len(in_env),
                        )
                    )
                command = build_bootstrap_command(request.command, tuple(transport))
                request_mount_args: tuple[str, ...] = tuple(
                    _materialization_tmpfs_arg(m.target) for m in mounts
                )
            else:
                command = tuple(request.command)
                request_mount_args = tuple(
                    _bind_mount_arg(m.source, m.target, m.read_only) for m in mounts
                )
                env = dict(request.env)
            plan = SwarmServicePlan(
                name=name,
                image=request.image,
                command=command,
                mode="replicated-job",
                constraint=(
                    self.swarm_config.gpu_job_constraint
                    if (limits.gpu_count or 0)
                    else self.swarm_config.cpu_job_constraint
                ),
                network=self._job_network(limits.network, challenge_slug),
                env=tuple(env.items()),
                labels=tuple(labels.items()),
                container_labels=tuple(labels.items()),
                mounts=request_mount_args
                + tmpfs_mounts
                + self._docker_socket_mounts(challenge_slug)
                + self._eval_readonly_mounts(challenge_slug),
                limit_cpus=limits.cpus,
                limit_memory=limits.memory,
                limit_pids=limits.pids_limit,
                read_only=limits.read_only,
                init=limits.init,
                cap_drop=limits.cap_drop,
                ulimits=limits.ulimits,
                user=limits.user,
                workdir=request.workdir,
                generic_resources=gpu_generic_resources(limits.gpu_count),
                with_registry_auth=True,
            )
            # GPU lease (capacity bookkeeping) is acquired BEFORE any ledger
            # registration or service create and released on every exit path;
            # a capacity refusal surfaces as the broker's standard 400.
            gpu_count = limits.gpu_count or 0
            if gpu_count:
                try:
                    self.gpu_leases.acquire(name, gpu_count)
                except GpuCapacityError as exc:
                    raise DockerExecutorError(str(exc)) from exc
            # Register-then-create: the provisional entry (keyed by service
            # name) carries the atomic quota check (Task 14); it is re-keyed
            # to the Swarm service ID once create succeeds (that second
            # register MUST stay uncapped — the slot is already held, and the
            # brief name+id double-entry over-counts, the safe direction) and
            # released on every exit path.
            entry = WorkloadEntry(
                key=name,
                kind="swarm_service",
                challenge_slug=challenge_slug,
                workload_class="job",
                timeout_seconds=request.timeout_seconds,
            )
            service_id = ""
            try:
                self.ledger.register(
                    entry, max_concurrent=self._max_concurrent(challenge_slug)
                )
                service_id = self._create_job_service(plan)
                self.ledger.register(replace(entry, key=service_id))
                self.ledger.release(name)
                outcome = self._wait_for_job(service_id, request.timeout_seconds)
                raw_stdout, raw_stderr = self._service_logs_raw(service_id)
                if cross_node:
                    # Round-trip writable mounts the remote container wrote to a
                    # manager-visible location (the broker node), where the
                    # challenge worker reads the eval manifest. The cross-node
                    # mounts are materialized as mode-1777 tmpfs, intentionally
                    # loosening a mount's read-only intent; only writable mounts
                    # are drained back, so any in-container writes to a ro mount
                    # are simply discarded.
                    self._persist_drained_mounts(name, raw_stdout, mounts)
                    # The drain sections carry the writable-mount archives the
                    # executor reconstructs; a drained checkpoint can dwarf the
                    # log cap, so cap ONLY the human-readable remainder and
                    # re-append the drain sections uncapped (truncating their
                    # base64 would silently break restoration on the executor).
                    stdout = self._cap_log(
                        strip_drain_sections(raw_stdout)
                    ) + extract_drain_sections(raw_stdout)
                else:
                    stdout = self._cap_log(raw_stdout)
                stderr = self._cap_log(raw_stderr)
                if outcome.error and not stderr:
                    stderr = self._cap_log(outcome.error)
                return BrokerRunResponse(
                    container_name=name,
                    stdout=stdout,
                    stderr=stderr,
                    returncode=outcome.returncode,
                    timed_out=outcome.timed_out,
                )
            finally:
                self._remove_service(service_id or name)
                if service_id:
                    self.ledger.release(service_id)
                self.ledger.release(name)
                if gpu_count:
                    self.gpu_leases.release(name)

    # -------------------------------------------------------------- cleanup
    def cleanup(
        self, challenge_slug: str, request: BrokerCleanupRequest
    ) -> BrokerCleanupResponse:
        self._cleanup_escape_hatch_containers(challenge_slug, request.job_id)
        for service in self._list_services(challenge_slug, request.job_id):
            # ``docker service ls`` truncates IDs; the ledger is keyed by the
            # full ID returned at create time, so resolve it before removal.
            full_id = self._full_service_id(service["ID"])
            self._remove_service(service["ID"])
            self.ledger.release(full_id)
            self.ledger.release(service["ID"])
            self.ledger.release(service["Name"])
        return BrokerCleanupResponse()

    def _full_service_id(self, reference: str) -> str:
        inspected = self._command(
            [
                self.config.docker_bin,
                "service",
                "inspect",
                "--format",
                "{{.ID}}",
                reference,
            ]
        )
        if inspected.returncode != 0:
            return reference
        return inspected.stdout.strip() or reference

    # ----------------------------------------------------------------- list
    def list_containers(
        self, challenge_slug: str, request: BrokerListRequest
    ) -> BrokerListResponse:
        rows = self._list_services(challenge_slug, request.job_id)
        details = self._inspect_services([row["ID"] for row in rows])
        containers: list[BrokerContainerInfo] = []
        for row in rows:
            detail = details.get(row["Name"], {})
            spec = detail.get("Spec", {})
            labels = spec.get("Labels", {}) if isinstance(spec, dict) else {}
            containers.append(
                BrokerContainerInfo(
                    container_id=row["ID"],
                    container_name=row["Name"],
                    image=str(row.get("Image") or ""),
                    status=str(row.get("Replicas") or ""),
                    job_id=labels.get("base.job"),
                    task_id=labels.get("base.task"),
                    created=str(detail.get("CreatedAt") or "") or None,
                    labels={
                        key: value
                        for key, value in labels.items()
                        if key.startswith("base.")
                    },
                )
            )
        return BrokerListResponse(containers=containers)

    # -------------------------------------------------------------- helpers
    def _validate_request(self, request: BrokerRunRequest) -> None:
        image = request.image
        if not _IMAGE_RE.match(image) or image.startswith("-"):
            raise DockerExecutorError(f"unsafe Docker image reference: {image!r}")
        allowed = self.config.allowed_images
        if allowed and not any(
            image == item or image.startswith(item.rstrip("*")) for item in allowed
        ):
            raise DockerExecutorError(f"Docker image is not allowed: {image}")
        network = request.limits.network
        if network not in {"none", "default"} and not network.startswith("base_"):
            raise DockerExecutorError(
                "Docker network must be 'none', 'default', or a base network"
            )

    def _docker_socket_mounts(self, challenge_slug: str) -> tuple[str, ...]:
        """Return the host-Docker-socket bind mount for allowlisted slugs.

        Empty for every non-allowlisted slug so non-agent jobs never gain
        Docker-out-of-Docker access. The socket is mounted read-write because
        the Docker CLI/SDK issues write calls (build/create/exec) over it.
        """

        if challenge_slug in self.swarm_config.docker_socket_slugs:
            return (_socket_mount_arg(self.swarm_config.docker_socket_path),)
        return ()

    def _eval_readonly_mounts(self, challenge_slug: str) -> tuple[str, ...]:
        """Return the read-only out-of-band mounts injected for ``challenge_slug``.

        Two independent sources are merged (deduplicated, order-preserving):

        * the legacy GLOBAL ``eval_readonly_mounts``, gated on the
          ``docker_socket_slugs`` allowlist — only an own_runner DooD eval job
          (which already gets the host Docker socket) is handed the shared
          terminal-bench task cache + frozen digest manifest; and
        * the PER-SLUG ``eval_readonly_mounts_by_slug``, decoupled from the
          socket allowlist — this delivers the locked prism FineWeb-Edu train
          split (+ reference tokenizers) READ-ONLY into the prism eval
          container WITHOUT granting it the (root-equivalent) Docker socket.

        Every mount is read-only so the job can never mutate the shared
        cache/locked-data volume. Empty for a slug present in neither source.
        """

        specs: list[tuple[str, str]] = []
        if challenge_slug in self.swarm_config.docker_socket_slugs:
            specs.extend(self.swarm_config.eval_readonly_mounts)
        specs.extend(
            self.swarm_config.eval_readonly_mounts_by_slug.get(challenge_slug, ())
        )
        seen: set[tuple[str, str]] = set()
        mounts: list[str] = []
        for source, target in specs:
            if (source, target) in seen:
                continue
            seen.add((source, target))
            mounts.append(_readonly_mount_arg(source, target))
        return tuple(mounts)

    def _job_network(self, requested: str, challenge_slug: str) -> str | None:
        if challenge_slug in self.swarm_config.egress_locked_slugs:
            # Untrusted miner code: pin to the internal (no external route)
            # overlay regardless of the requested network, so a compromised
            # eval container can never exfiltrate over an egress-capable net.
            self._ensure_overlay_network(self.swarm_config.job_network, internal=True)
            return self.swarm_config.job_network
        if requested == "default":
            return None
        if requested == "none":
            # Swarm cannot attach services to the predefined ``none``
            # network; the closest isolation is a dedicated *internal*
            # encrypted overlay with no external routes.
            self._ensure_overlay_network(self.swarm_config.job_network, internal=True)
            return self.swarm_config.job_network
        return requested

    def _ensure_overlay_network(self, name: str, *, internal: bool) -> None:
        docker_bin = self.config.docker_bin
        inspect = self._command(
            [docker_bin, "network", "inspect", "--format", "{{.Id}}", name]
        )
        if inspect.returncode == 0:
            return
        created = self._command(
            build_overlay_network_argv(docker_bin, name, internal=internal)
        )
        if created.returncode != 0 and "already exists" not in created.stderr:
            raise DockerExecutorError(
                f"Swarm overlay network create failed: {self._cap_log(created.stderr)}"
            )

    def _create_job_service(self, plan: SwarmServicePlan) -> str:
        created = self._command(build_service_create_argv(self.config.docker_bin, plan))
        if created.returncode != 0:
            raise DockerExecutorError(
                f"Swarm service create failed: {self._cap_log(created.stderr)}"
            )
        service_id = created.stdout.strip().splitlines()[0].strip()
        if not service_id:
            raise DockerExecutorError("Swarm service create returned no service ID")
        return service_id

    def _wait_for_job(self, service_id: str, timeout_seconds: int) -> _JobOutcome:
        deadline = self._clock() + timeout_seconds
        while True:
            status = self._job_task_status(service_id)
            if status is not None:
                state = str(status.get("State") or "")
                started_at = _parse_docker_timestamp(status.get("Timestamp"))
                if started_at is not None and state in (
                    JOB_TERMINAL_STATES | {"running"}
                ):
                    self.ledger.observe_started_at(service_id, started_at)
                if state in JOB_TERMINAL_STATES:
                    return _job_outcome_from_status(state, status)
            if self._clock() >= deadline:
                return _JobOutcome(returncode=124, timed_out=True)
            self._sleep(self.swarm_config.poll_interval_seconds)

    def _job_task_status(self, service_id: str) -> dict[str, Any] | None:
        tasks = self._command(
            [self.config.docker_bin, "service", "ps", service_id, "-q", "--no-trunc"]
        )
        task_ids = [line for line in tasks.stdout.splitlines() if line.strip()]
        if tasks.returncode != 0 or not task_ids:
            return None
        inspected = self._command(
            [
                self.config.docker_bin,
                "inspect",
                "--format",
                "{{json .Status}}",
                task_ids[0],
            ]
        )
        if inspected.returncode != 0:
            return None
        return _load_json_object(inspected.stdout)

    def _service_logs_raw(self, service_id: str) -> tuple[str, str]:
        logs = self._command(
            [self.config.docker_bin, "service", "logs", "--raw", service_id]
        )
        if logs.returncode != 0:
            return "", ""
        return logs.stdout, logs.stderr

    def _collect_logs(self, service_id: str) -> tuple[str, str]:
        stdout, stderr = self._service_logs_raw(service_id)
        return self._cap_log(stdout), self._cap_log(stderr)

    def _is_cross_node(self, limits: DockerLimits) -> bool:
        """Whether a job runs on a node other than this broker node.

        GPU jobs are steered to the GPU worker by ``gpu_job_constraint`` while
        the broker (and CPU jobs) run on the manager, so a positive GPU count
        is the signal that bind-mount sources on this node are unreachable by
        the job and mounts must be transported across nodes.
        """

        return bool(limits.gpu_count)

    def _persist_drained_mounts(
        self, service_name: str, raw_stdout: str, mounts: Sequence[DockerMount]
    ) -> None:
        """Write writable-mount artifacts drained from the job back to disk.

        The bootstrap prints each writable mount's archive to stdout between
        sentinels; here they are extracted under ``workspace_dir/retrieved`` on
        the broker (manager) node so the challenge worker — and validators over
        ssh — can read the round-tripped artifacts.
        """

        archives = parse_drained_archives(raw_stdout)
        if not archives:
            return
        base = self.config.workspace_dir / "retrieved" / service_name
        for index, archive in archives.items():
            if index >= len(mounts) or mounts[index].read_only:
                continue
            extract_archive_to_dir(archive, base / f"mount-{index}")

    def _remove_service(self, service: str) -> None:
        self._command([self.config.docker_bin, "service", "rm", service])

    def _list_services(
        self, challenge_slug: str, job_id: str | None
    ) -> list[dict[str, str]]:
        argv = [
            self.config.docker_bin,
            "service",
            "ls",
            "--filter",
            f"label=base.challenge={challenge_slug}",
        ]
        if job_id:
            argv += ["--filter", f"label=base.job={job_id}"]
        argv += ["--format", "{{json .}}"]
        listed = self._command(argv)
        if listed.returncode != 0:
            raise DockerExecutorError(
                f"Swarm service list failed: {self._cap_log(listed.stderr)}"
            )
        rows: list[dict[str, str]] = []
        for line in listed.stdout.splitlines():
            if not line.strip():
                continue
            parsed = _load_json_object(line)
            if parsed is not None and parsed.get("ID") and parsed.get("Name"):
                rows.append({str(k): str(v) for k, v in parsed.items()})
        return rows

    def _inspect_services(self, service_ids: list[str]) -> dict[str, dict[str, Any]]:
        if not service_ids:
            return {}
        inspected = self._command(
            [
                self.config.docker_bin,
                "service",
                "inspect",
                "--format",
                "{{json .}}",
                *service_ids,
            ]
        )
        details: dict[str, dict[str, Any]] = {}
        for line in inspected.stdout.splitlines():
            parsed = _load_json_object(line) if line.strip() else None
            if parsed is None:
                continue
            spec = parsed.get("Spec")
            name = spec.get("Name") if isinstance(spec, dict) else None
            if isinstance(name, str):
                details[name] = parsed
        return details

    def _command(self, argv: Sequence[str]) -> SwarmCommandResult:
        return self.runner.run(
            argv, timeout_seconds=self.swarm_config.command_timeout_seconds
        )


class SwarmChallengeOrchestrator:
    """Schedule challenge containers as Swarm services (factory docker branch).

    Long-lived challenge APIs (``spec.workload_class == "service"``) become
    replicated services with ``--restart-condition any`` pinned to the
    manager/host; evaluation specs (``"job"``) become replicated-jobs with
    ``--restart-condition none``. Every created service is registered in the
    shared workload ledger with ``workload_class`` copied verbatim from the
    spec.

    The synchronous ``wait_until_ready`` HTTP probe mirrors
    ``DockerOrchestrator``; Task 15 replaces it with an async health probe.
    """

    def __init__(
        self,
        *,
        runner: SwarmCommandRunner | None = None,
        docker_bin: str = "docker",
        network_name: str = DEFAULT_NETWORK_NAME,
        internal_network: bool = True,
        pull_ghcr_only: bool = True,
        docker_broker_url: str = DEFAULT_DOCKER_BROKER_URL,
        challenge_placement_constraint: str | None = DEFAULT_CHALLENGE_CONSTRAINT,
        job_network: str = DEFAULT_JOB_NETWORK,
        job_network_slugs: frozenset[str] = frozenset(),
        ledger: WorkloadLedger | None = None,
        gpu_leases: GpuLeaseLedger | None = None,
        request_timeout_seconds: float = 5.0,
        health_retries: int = 12,
        health_retry_delay_seconds: float = 2.0,
        command_timeout_seconds: float = 120.0,
    ) -> None:
        self.runner: SwarmCommandRunner = runner or SwarmCliRunner()
        self.docker_bin = docker_bin
        self.network_name = network_name
        self.internal_network = internal_network
        self.pull_ghcr_only = pull_ghcr_only
        self.docker_broker_url = docker_broker_url
        self.challenge_placement_constraint = challenge_placement_constraint
        #: The isolated eval overlay (``--internal``, no egress) that the eval
        #: JOB runs on; long-lived services for ``job_network_slugs`` are ALSO
        #: attached to it so the job can resolve/reach ONLY them by name.
        self.job_network = job_network
        #: Challenge slugs whose long-lived service is multi-homed onto
        #: ``job_network`` in addition to ``network_name`` (e.g. agent-challenge,
        #: whose eval job must reach the challenge API for log streaming). Empty
        #: keeps every service on the single control overlay.
        self.job_network_slugs = job_network_slugs
        self.ledger = ledger or WorkloadLedger()
        self.gpu_leases = gpu_leases or GpuLeaseLedger()
        self.request_timeout_seconds = request_timeout_seconds
        self.health_retries = health_retries
        self.health_retry_delay_seconds = health_retry_delay_seconds
        self.command_timeout_seconds = command_timeout_seconds
        self._runtime: dict[str, ChallengeRuntime] = {}

    @property
    def runtime(self) -> dict[str, ChallengeRuntime]:
        """Return a copy of in-memory challenge runtime state."""

        return dict(self._runtime)

    def pull_image(self, image: str) -> object:
        """Pull a challenge image (manager-side warm; workers pull on create)."""

        if self.pull_ghcr_only and not image.startswith("ghcr.io/"):
            raise DockerOrchestrationError("Challenge images must be pulled from GHCR")
        pulled = self._command([self.docker_bin, "pull", image])
        if pulled.returncode != 0:
            raise DockerOrchestrationError(
                f"Image pull failed for {image}: {pulled.stderr.strip()}"
            )
        return pulled.stdout

    def pull_challenge(self, spec: ChallengeSpec) -> object:
        return self.pull_image(spec.image)

    def start_challenge(
        self, spec: ChallengeSpec, *, recreate: bool = False
    ) -> ChallengeRuntime:
        """Create (or reuse) the Swarm service for a challenge and verify it."""

        self.ensure_network()
        for name in self._extra_networks(spec):
            # The eval overlay is internal (no egress); ensure it exists so a
            # fresh deploy can multi-home the service even before install-swarm
            # create_networks ran on this node.
            self._ensure_overlay_network(name, internal=True)
        existing = self._service_id(spec.container_name)
        if existing and recreate:
            self._remove_named_service(spec.container_name, existing)
            existing = None
        if existing:
            service_id = existing
        else:
            service_id = self._create_challenge_service(spec)
        health, version = self.wait_until_ready(spec)
        runtime = ChallengeRuntime(
            slug=spec.slug,
            image=spec.image,
            container_id=service_id,
            container_name=spec.container_name,
            internal_base_url=spec.internal_base_url,
            sqlite_volume_name=spec.sqlite_volume_name,
            health=health,
            version=version,
        )
        self._runtime[spec.slug] = runtime
        return runtime

    def restart_challenge(self, spec: ChallengeSpec) -> ChallengeRuntime:
        """Force-update the service (rolling restart) and verify readiness."""

        service_id = self._service_id(spec.container_name)
        if service_id is None:
            return self.start_challenge(spec)
        updated = self._command(
            [
                self.docker_bin,
                "service",
                "update",
                "--detach",
                "--force",
                spec.container_name,
            ]
        )
        if updated.returncode != 0:
            raise DockerOrchestrationError(
                f"Swarm service update failed for {spec.slug!r}: "
                f"{updated.stderr.strip()}"
            )
        health, version = self.wait_until_ready(spec)
        runtime = ChallengeRuntime(
            slug=spec.slug,
            image=spec.image,
            container_id=service_id,
            container_name=spec.container_name,
            internal_base_url=spec.internal_base_url,
            sqlite_volume_name=spec.sqlite_volume_name,
            health=health,
            version=version,
        )
        self._runtime[spec.slug] = runtime
        return runtime

    def stop_challenge(self, slug: str, *, remove: bool = False) -> None:
        """Remove the challenge service (Swarm has no stopped-service state)."""

        container_name = f"challenge-{_safe_fragment(slug, 48)}"
        service_id = self._service_id(container_name)
        if service_id is not None:
            self._remove_named_service(container_name, service_id)
        self._runtime.pop(slug, None)

    def ensure_network(self) -> None:
        """Create the encrypted overlay challenge network if missing."""

        self._ensure_overlay_network(self.network_name, internal=self.internal_network)

    def _ensure_overlay_network(self, name: str, *, internal: bool) -> None:
        """Create an encrypted overlay network by name if it does not exist."""

        inspected = self._command(
            [self.docker_bin, "network", "inspect", "--format", "{{.Id}}", name]
        )
        if inspected.returncode == 0:
            return
        created = self._command(
            build_overlay_network_argv(self.docker_bin, name, internal=internal)
        )
        if created.returncode != 0 and "already exists" not in created.stderr:
            raise DockerOrchestrationError(
                f"Swarm overlay network create failed: {created.stderr.strip()}"
            )

    def _extra_networks(self, spec: ChallengeSpec) -> tuple[str, ...]:
        """Return the additional overlay(s) ``spec``'s service multi-homes onto.

        A challenge in ``job_network_slugs`` (e.g. agent-challenge) is attached
        to the isolated ``job_network`` in ADDITION to the control overlay so
        its eval job — which runs on ``job_network`` — can resolve the service
        by name (log streaming / gateway) without exposing the broader network.
        """

        if spec.slug in self.job_network_slugs:
            return (self.job_network,)
        return ()

    def wait_until_ready(
        self, spec: ChallengeSpec
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Wait for ``/health`` and ``/version`` to pass validation.

        Synchronous probe kept behaviorally identical to
        ``DockerOrchestrator.wait_until_ready``; Task 15 swaps in the async
        health probe here.
        """

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

    # -------------------------------------------------------------- helpers
    def _create_challenge_service(self, spec: ChallengeSpec) -> str:
        secrets = self._ensure_secrets(spec)
        plan = self._challenge_plan(spec, secrets)
        # The GPU lease is keyed by the stable service name so it can be
        # released by name on stop/cleanup; held for the service lifetime.
        gpu_count = spec.resources.gpu_count or 0
        if gpu_count:
            try:
                self.gpu_leases.acquire(plan.name, gpu_count)
            except GpuCapacityError as exc:
                raise DockerOrchestrationError(str(exc)) from exc
        entry = WorkloadEntry(
            key=plan.name,
            kind="swarm_service",
            challenge_slug=spec.slug,
            workload_class=spec.workload_class,
            timeout_seconds=spec.resources.docker_timeout_seconds,
        )
        try:
            self.ledger.register(entry)
            created = self._command(build_service_create_argv(self.docker_bin, plan))
            if created.returncode != 0:
                raise DockerOrchestrationError(
                    f"Swarm service create failed for {spec.slug!r}: "
                    f"{created.stderr.strip()}"
                )
            service_id = created.stdout.strip().splitlines()[0].strip()
            if not service_id:
                raise DockerOrchestrationError(
                    f"Swarm service create returned no ID for {spec.slug!r}"
                )
        except BaseException:
            self.ledger.release(plan.name)
            if gpu_count:
                self.gpu_leases.release(plan.name)
            raise
        self.ledger.register(replace(entry, key=service_id))
        self.ledger.release(plan.name)
        return service_id

    def _challenge_plan(
        self, spec: ChallengeSpec, secrets: tuple[str, ...]
    ) -> SwarmServicePlan:
        resources = spec.resources
        labels = {
            "base.component": "challenge",
            "base.challenge.slug": spec.slug,
            "base.challenge.version": spec.version or "",
        }
        mounts = [
            f"type=volume,source={spec.sqlite_volume_name},destination=/data",
            *(_tmpfs_mount_arg(value) for value in resources.tmpfs),
        ]
        mode: Literal["replicated-job", "replicated"] = (
            "replicated" if spec.workload_class == "service" else "replicated-job"
        )
        return SwarmServicePlan(
            name=spec.container_name,
            image=spec.image,
            command=tuple(spec.worker_command),
            mode=mode,
            replicas=1,
            constraint=(
                spec.placement_constraint
                if spec.placement_constraint is not None
                else self.challenge_placement_constraint
            ),
            network=self.network_name,
            extra_networks=self._extra_networks(spec),
            env=tuple(self._build_environment(spec).items()),
            labels=tuple(labels.items()),
            container_labels=tuple(labels.items()),
            mounts=tuple(mounts),
            secrets=secrets,
            limit_cpus=resources.cpu,
            limit_memory=resources.memory,
            limit_pids=resources.pids_limit,
            read_only=resources.read_only,
            init=resources.init,
            cap_drop=resources.cap_drop,
            hostname=spec.container_name,
            generic_resources=gpu_generic_resources(resources.gpu_count),
        )

    def _build_environment(self, spec: ChallengeSpec) -> dict[str, str]:
        """Mirror ``DockerOrchestrator._build_environment`` for Swarm secrets."""

        environment = dict(spec.env)
        environment.setdefault("BASE_CHALLENGE_SLUG", spec.slug)
        environment.setdefault(
            "CHALLENGE_DATABASE_URL",
            f"sqlite+aiosqlite:///{DEFAULT_SQLITE_PATH}",
        )
        for secret_name in spec.secret_names():
            safe_name = _safe_fragment(secret_name, 48).replace("-", "_")
            env_name = f"{secret_name.upper()}_FILE"
            target = f"{DEFAULT_SECRET_MOUNT_DIR}/{safe_name}"
            environment.setdefault(env_name, target)
            if secret_name == "challenge_token":
                environment.setdefault("CHALLENGE_SHARED_TOKEN_FILE", target)
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

    def _ensure_secrets(self, spec: ChallengeSpec) -> tuple[str, ...]:
        """Create/refresh Swarm secrets and return ``--secret`` references.

        Secrets surface inside the container at
        ``/run/secrets/base/<name>`` to match the bind-mount layout used
        by ``DockerOrchestrator`` (env vars point at the same paths).
        Value-bearing secrets (the per-slug registry tokens) are created or
        refreshed via stdin; ``spec.external_secrets`` are referenced only —
        their ``docker secret`` objects are pre-created out-of-band and this
        process never sees the values.
        """

        references: list[str] = []
        value_bearing = spec.all_secrets()
        for secret_name, secret_value in value_bearing.items():
            full_name = self._swarm_secret_name(spec, secret_name)
            self._ensure_secret(full_name, secret_value)
            references.append(self._secret_reference(spec, secret_name))
        for secret_name in spec.external_secrets:
            if secret_name in value_bearing:
                continue
            references.append(self._secret_reference(spec, secret_name))
        return tuple(references)

    def _swarm_secret_name(self, spec: ChallengeSpec, secret_name: str) -> str:
        safe_name = _safe_fragment(secret_name, 48).replace("-", "_")
        return f"base_{spec.safe_slug}_{safe_name}".replace("-", "_")

    def _secret_reference(self, spec: ChallengeSpec, secret_name: str) -> str:
        safe_name = _safe_fragment(secret_name, 48).replace("-", "_")
        return (
            f"source={self._swarm_secret_name(spec, secret_name)},"
            f"target={DEFAULT_SECRET_MOUNT_DIR.removeprefix('/run/secrets/')}"
            f"/{safe_name}"
        )

    def _ensure_secret(self, name: str, value: str) -> None:
        created = self._command(
            [self.docker_bin, "secret", "create", name, "-"], input_text=value
        )
        if created.returncode == 0:
            return
        if "already exists" not in created.stderr:
            raise DockerOrchestrationError(
                f"Swarm secret create failed for {name!r}: {created.stderr.strip()}"
            )
        removed = self._command([self.docker_bin, "secret", "rm", name])
        if removed.returncode != 0:
            # Secret is in use by a running service; keep the existing value.
            return
        recreated = self._command(
            [self.docker_bin, "secret", "create", name, "-"], input_text=value
        )
        if recreated.returncode != 0:
            raise DockerOrchestrationError(
                f"Swarm secret create failed for {name!r}: {recreated.stderr.strip()}"
            )

    def _service_id(self, name: str) -> str | None:
        inspected = self._command(
            [self.docker_bin, "service", "inspect", "--format", "{{.ID}}", name]
        )
        if inspected.returncode != 0:
            return None
        service_id = inspected.stdout.strip()
        return service_id or None

    def _remove_named_service(self, name: str, service_id: str) -> None:
        self._command([self.docker_bin, "service", "rm", name])
        self.ledger.release(service_id)
        self.ledger.release(name)
        self.gpu_leases.release(name)

    def _command(
        self, argv: Sequence[str], *, input_text: str | None = None
    ) -> SwarmCommandResult:
        return self.runner.run(
            argv, input_text=input_text, timeout_seconds=self.command_timeout_seconds
        )

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


def _job_outcome_from_status(state: str, status: Mapping[str, Any]) -> _JobOutcome:
    container_status = status.get("ContainerStatus")
    exit_code: int | None = None
    if isinstance(container_status, Mapping):
        raw = container_status.get("ExitCode")
        if isinstance(raw, int) and not isinstance(raw, bool):
            exit_code = raw
    if state == "complete":
        return _JobOutcome(returncode=exit_code if exit_code is not None else 0)
    error = str(status.get("Err") or status.get("Message") or state)
    failure_code = exit_code if exit_code is not None and exit_code != 0 else 1
    return _JobOutcome(returncode=failure_code, error=error)


def _bind_mount_arg(source: Path, target: str, read_only: bool) -> str:
    arg = f"type=bind,source={source.resolve()},destination={target}"
    if read_only:
        arg += ",readonly"
    return arg


def _socket_mount_arg(socket_path: str) -> str:
    """Read-write bind mount of the host Docker socket (Docker-out-of-Docker)."""

    return f"type=bind,source={socket_path},destination={socket_path}"


def _readonly_mount_arg(source: str, target: str) -> str:
    """Read-only mount of a host path (absolute ``source``) or named volume."""

    mount_type = "bind" if source.startswith("/") else "volume"
    return f"type={mount_type},source={source},destination={target},readonly"


def _tmpfs_mount_arg(value: str) -> str:
    path, separator, options = value.partition(":")
    if not path.startswith("/"):
        raise DockerOrchestrationError(f"tmpfs mount must be absolute: {path}")
    arg = f"type=tmpfs,destination={path}"
    if separator:
        for option in options.split(","):
            if option.startswith("size="):
                arg += f",tmpfs-size={option.removeprefix('size=')}"
    return arg


def _materialization_tmpfs_arg(target: str) -> str:
    """Node-local writable tmpfs for a cross-node-transported mount.

    Mode ``1777`` (world-writable + sticky) lets the non-root eval uid extract
    the inbound archive and write artifacts without EACCES while keeping
    per-file ownership safe; the container memory limit bounds its size.
    """

    return f"type=tmpfs,destination={target},tmpfs-mode=1777"


def _service_name(challenge: str, job_id: str, task_id: str | None) -> str:
    pieces = [_safe_fragment(challenge, 20), _safe_fragment(job_id[:12], 12)]
    if task_id:
        pieces.append(_safe_fragment(task_id, 12))
    pieces.append(uuid.uuid4().hex[:8])
    return "-".join(piece for piece in pieces if piece)


def _safe_fragment(value: str, limit: int) -> str:
    safe = _SAFE_RE.sub("-", value.lower()).strip("-")
    return (safe or "x")[:limit]


def _load_json_object(raw: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _parse_docker_timestamp(raw: object) -> datetime | None:
    """Parse an RFC3339 docker timestamp (nanosecond precision) safely."""

    if not isinstance(raw, str) or not raw:
        return None
    value = raw.strip().replace("Z", "+00:00")
    match = re.match(r"^(.*?)(\.\d+)?([+-]\d{2}:\d{2})$", value)
    if match:
        base, fraction, offset = match.groups()
        fraction = (fraction or ".0")[:7]
        value = f"{base}{fraction}{offset}"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None
