from __future__ import annotations

import asyncio
import base64
import binascii
import inspect
import io
import re
import secrets
import tarfile
from pathlib import Path
from typing import Any, Protocol

from fastapi import FastAPI, Header, HTTPException, status

from platform_network.kubernetes.client import KubernetesClient
from platform_network.kubernetes.names import broker_job_name
from platform_network.kubernetes.resources import (
    broker_mount_secret_name,
    build_broker_job,
    build_broker_mount_secret,
    build_broker_network_policy,
    validate_broker_kubernetes_limits,
)
from platform_network.master.docker_broker import BrokerTokenRegistry
from platform_network.master.docker_orchestrator import ChallengeResources
from platform_network.schemas.docker_broker import (
    BrokerCleanupRequest,
    BrokerCleanupResponse,
    BrokerContainerInfo,
    BrokerListRequest,
    BrokerListResponse,
    BrokerRunRequest,
    BrokerRunResponse,
)

_IMAGE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9./_:@+-]{0,254}$")


class BrokerKubernetesClient(Protocol):
    def apply(self, resource: dict[str, Any]) -> dict[str, Any]: ...
    def delete(
        self, resource: dict[str, Any] | str, name: str | None = None
    ) -> None: ...
    def wait_job_complete(self, name: str, *, timeout_seconds: int) -> int: ...
    def pod_logs_for_job(self, job_name: str, *, tail_lines: int = 1000) -> str: ...
    def delete_jobs_by_label(self, label_selector: str) -> None: ...
    def delete_by_label(self, kind: str, label_selector: str) -> None: ...
    def list_jobs_by_label(self, label_selector: str) -> list[dict[str, Any]]: ...


class KubernetesBrokerService:
    def __init__(
        self,
        *,
        client: BrokerKubernetesClient,
        namespace: str = "platform",
        service_account_name: str = "platform-broker",
        log_limit_bytes: int = 64_000,
        allowed_images: tuple[str, ...] = ("ghcr.io/platformnetwork/",),
    ) -> None:
        self.client = client
        self.namespace = namespace
        self.service_account_name = service_account_name
        self.log_limit_bytes = log_limit_bytes
        self.allowed_images = allowed_images

    @classmethod
    def from_settings(cls, settings: Any) -> KubernetesBrokerService:
        return cls(
            client=KubernetesClient(
                namespace=settings.kubernetes.namespace,
                kubeconfig=settings.kubernetes.kubeconfig,
                in_cluster=settings.kubernetes.in_cluster,
            ),
            namespace=settings.kubernetes.namespace,
            service_account_name=settings.kubernetes.service_account,
            allowed_images=tuple(settings.docker.broker_allowed_images),
        )

    def run(self, challenge_slug: str, request: BrokerRunRequest) -> BrokerRunResponse:
        self._validate_request(request)
        run_id = secrets.token_hex(4)
        try:
            job = build_broker_job(
                challenge_slug,
                request,
                namespace=self.namespace,
                service_account_name=self.service_account_name,
                run_id=run_id,
            )
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        name = job["metadata"]["name"]
        mount_secret = build_broker_mount_secret(
            challenge_slug, request, namespace=self.namespace, run_id=run_id
        )
        try:
            if mount_secret is not None:
                self.client.apply(mount_secret)
            if request.limits.network == "none":
                self.client.apply(
                    build_broker_network_policy(
                        challenge_slug,
                        request,
                        namespace=self.namespace,
                        run_id=run_id,
                    )
                )
            self.client.apply(job)
            code = self.client.wait_job_complete(
                name, timeout_seconds=request.timeout_seconds
            )
            logs = self.client.pod_logs_for_job(name)
            if len(logs.encode()) > self.log_limit_bytes:
                logs = logs.encode()[-self.log_limit_bytes :].decode(errors="replace")
        finally:
            self.client.delete("Job", name)
            self.client.delete("NetworkPolicy", name)
            self.client.delete("Secret", broker_mount_secret_name(name))
        return BrokerRunResponse(
            container_name=name,
            stdout=logs if code == 0 else "",
            stderr=logs if code != 0 else "",
            returncode=code,
            timed_out=code == 124,
        )

    def cleanup(
        self, challenge_slug: str, request: BrokerCleanupRequest
    ) -> BrokerCleanupResponse:
        self.client.delete("Job", broker_job_name(challenge_slug, request.job_id))
        self.client.delete_jobs_by_label(
            f"platform.challenge.slug={challenge_slug},platform.job={request.job_id}"
        )
        selector = (
            f"platform.challenge.slug={challenge_slug},platform.job={request.job_id}"
        )
        self.client.delete_by_label("NetworkPolicy", selector)
        self.client.delete_by_label("Secret", selector)
        return BrokerCleanupResponse()

    def list_containers(
        self, challenge_slug: str, request: BrokerListRequest
    ) -> BrokerListResponse:
        selector = f"platform.challenge.slug={challenge_slug}"
        if request.job_id:
            selector = f"{selector},platform.job={request.job_id}"
        containers: list[BrokerContainerInfo] = []
        for job in self.client.list_jobs_by_label(selector):
            metadata = job.get("metadata", {})
            labels = metadata.get("labels", {})
            status = job.get("status", {})
            containers.append(
                BrokerContainerInfo(
                    container_id=metadata.get("uid", ""),
                    container_name=metadata.get("name", ""),
                    image=_job_image(job),
                    status=_job_status(status),
                    job_id=labels.get("platform.job"),
                    task_id=labels.get("platform.task"),
                    created=metadata.get("creation_timestamp")
                    or metadata.get("creationTimestamp"),
                    labels={
                        key: value
                        for key, value in labels.items()
                        if str(key).startswith("platform.")
                    },
                )
            )
        return BrokerListResponse(containers=containers)

    def _validate_request(self, request: BrokerRunRequest) -> None:
        if not _IMAGE_RE.match(request.image) or request.image.startswith("-"):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"unsafe Docker image reference: {request.image!r}",
            )
        if not request.image.startswith(self.allowed_images):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "Docker image is not allowed"
            )
        try:
            validate_broker_kubernetes_limits(request.limits)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        for mount in request.mounts:
            _validate_mount_archive(mount.archive_b64)
            if mount.source_type == "file":
                source_name = Path(mount.source_name)
                if source_name.is_absolute() or ".." in source_name.parts:
                    raise HTTPException(
                        status.HTTP_400_BAD_REQUEST,
                        f"unsafe mount source: {mount.target}",
                    )
            elif mount.source_type != "directory":
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    f"unsupported mount source type: {mount.target}",
                )


class KubernetesBrokerRouterService:
    def __init__(
        self,
        *,
        default_service: Any,
        target_services: dict[str, Any] | None = None,
        target_capacities: dict[str, int] | None = None,
        challenge_registry: Any,
        settings: Any | None = None,
        target_registry: Any | None = None,
    ) -> None:
        self.default_service = default_service
        self.target_services = target_services or {}
        self.target_capacities = target_capacities or {}
        self.challenge_registry = challenge_registry
        self.settings = settings
        self.target_registry = target_registry

    def run(self, challenge_slug: str, request: BrokerRunRequest) -> BrokerRunResponse:
        return self._service_for(challenge_slug).run(challenge_slug, request)

    def cleanup(
        self, challenge_slug: str, request: BrokerCleanupRequest
    ) -> BrokerCleanupResponse:
        return self._service_for(challenge_slug).cleanup(challenge_slug, request)

    def list_containers(
        self, challenge_slug: str, request: BrokerListRequest
    ) -> BrokerListResponse:
        return self._service_for(challenge_slug).list_containers(
            challenge_slug, request
        )

    def _service_for(self, challenge_slug: str) -> Any:
        record = _resolve_sync(self.challenge_registry.get(challenge_slug))
        resources = ChallengeResources.from_mapping(record.resources)
        assigned = self._assignment_for(challenge_slug)
        if assigned and self._target_eligible(
            assigned, resources, exclude_slug=challenge_slug
        ):
            return self._service_for_target(assigned)
        if assigned:
            self._clear_assignment(challenge_slug)
        target_id = resources.gpu_server
        if target_id:
            if not self._target_eligible(
                target_id, resources, exclude_slug=challenge_slug
            ):
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "No valid Kubernetes target available for challenge "
                    f"{challenge_slug!r}",
                )
            service = self._service_for_target(target_id)
            self._assign(challenge_slug, target_id, resources.gpu_count)
            return service
        if resources.gpu_count:
            for candidate_id, service in self._target_services().items():
                if self._target_eligible(
                    candidate_id, resources, exclude_slug=challenge_slug
                ):
                    self._assign(challenge_slug, candidate_id, resources.gpu_count)
                    return service
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "No valid Kubernetes target available for challenge "
                f"{challenge_slug!r}",
            )
        return self.default_service

    def _target_services(self) -> dict[str, Any]:
        if self.target_registry is None or self.settings is None:
            return self.target_services
        return self._build_targets()[0]

    def _target_capacities(self) -> dict[str, int]:
        if self.target_registry is None or self.settings is None:
            return self.target_capacities
        return self._build_targets()[1]

    def _service_for_target(self, target_id: str) -> Any:
        service = self._target_services().get(target_id)
        if (
            service is None
            and self.target_registry is not None
            and self.settings is not None
        ):
            service = self._build_service(self.target_registry.get(target_id))
        if service is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"Unknown Kubernetes target: {target_id}",
            )
        return service

    def _assignment_for(self, slug: str) -> str | None:
        if self.target_registry is not None and hasattr(
            self.target_registry, "get_assignment"
        ):
            return self.target_registry.get_assignment(slug)
        return None

    def _clear_assignment(self, slug: str) -> None:
        if self.target_registry is not None and hasattr(
            self.target_registry, "clear_assignment"
        ):
            self.target_registry.clear_assignment(slug)

    def _assign(self, slug: str, target_id: str, gpu_count: int | None = None) -> None:
        if self.target_registry is not None and hasattr(
            self.target_registry, "assign_challenge"
        ):
            try:
                self.target_registry.assign_challenge(slug, target_id, gpu_count)
            except TypeError:
                self.target_registry.assign_challenge(slug, target_id)

    def _build_targets(self) -> tuple[dict[str, Any], dict[str, int]]:
        assert self.settings is not None
        assert self.target_registry is not None
        services: dict[str, Any] = {}
        capacities: dict[str, int] = {}
        for target in self.target_registry.list():
            if not target.enabled or getattr(target, "draining", False):
                continue
            services[target.id] = self._build_service(target)
            capacities[target.id] = target.gpu_count
        return services, capacities

    def _target_eligible(
        self,
        target_id: str,
        resources: ChallengeResources,
        *,
        exclude_slug: str | None = None,
    ) -> bool:
        try:
            target = self._target_record(target_id)
        except Exception:
            return False
        if target is not None:
            if not getattr(target, "enabled", True) or getattr(
                target, "draining", False
            ):
                return False
        if self.target_registry is not None and hasattr(self.target_registry, "health"):
            try:
                health = self.target_registry.health(target_id)
            except Exception:
                return False
            if getattr(health, "status", None) != "ok":
                return False
        requested_gpu = int(resources.gpu_count or 0)
        if requested_gpu <= 0:
            return True
        capacity = self._target_capacities().get(target_id, 0)
        return capacity >= requested_gpu + self._assigned_gpu_count(
            target_id, exclude_slug=exclude_slug
        )

    def _target_record(self, target_id: str) -> Any | None:
        if self.target_registry is not None and hasattr(self.target_registry, "get"):
            return self.target_registry.get(target_id)
        if target_id in self._target_services():
            return None
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"Unknown Kubernetes target: {target_id}"
        )

    def _assigned_gpu_count(
        self, target_id: str, *, exclude_slug: str | None = None
    ) -> int:
        if self.target_registry is None or not hasattr(
            self.target_registry, "assignments"
        ):
            return 0
        total = 0
        assignments = self.target_registry.assignments
        if callable(assignments):
            assignments = assignments()
        for slug, assigned in dict(assignments).items():
            if slug == exclude_slug or assigned != target_id:
                continue
            if hasattr(self.target_registry, "get_assignment_metadata"):
                metadata = self.target_registry.get_assignment_metadata(slug) or {}
                total += int(metadata.get("gpu_count") or 0)
        return total

    def _build_service(self, target: Any) -> Any:
        assert self.settings is not None
        assert self.target_registry is not None
        if target.mode == "agent":
            from platform_network.kubernetes.agent import (
                KubernetesAgentBrokerService,
                KubernetesAgentClient,
            )

            token = self.target_registry.get_agent_token(target.id)
            if not target.agent_url or not token:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    f"Kubernetes agent target {target.id!r} is missing URL or token",
                )
            client = KubernetesAgentClient(
                target_id=target.id,
                base_url=target.agent_url,
                token=token,
                timeout_seconds=target.timeout_seconds,
                verify_tls=target.verify_tls,
                docker_broker_url=self.settings.docker.broker_url,
            )
            return KubernetesAgentBrokerService(client)
        return KubernetesBrokerService(
            client=KubernetesClient(
                namespace=target.namespace,
                kubeconfig=target.kubeconfig_file,
                in_cluster=False,
            ),
            namespace=target.namespace,
            service_account_name=(
                target.service_account or self.settings.kubernetes.service_account
            ),
            allowed_images=tuple(self.settings.docker.broker_allowed_images),
        )

    @classmethod
    def from_settings(
        cls, *, settings: Any, challenge_registry: Any, target_registry: Any
    ) -> KubernetesBrokerRouterService:
        return cls(
            default_service=KubernetesBrokerService.from_settings(settings),
            challenge_registry=challenge_registry,
            settings=settings,
            target_registry=target_registry,
        )


def _resolve_sync(value: Any) -> Any:
    if inspect.isawaitable(value):
        return asyncio.run(value)  # type: ignore[arg-type]
    return value


def _validate_mount_archive(archive_b64: str) -> None:
    try:
        archive = base64.b64decode(archive_b64, validate=True)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for member in tar.getmembers():
                path = Path(member.name)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or member.issym()
                    or member.islnk()
                    or member.isdev()
                ):
                    raise HTTPException(
                        status.HTTP_400_BAD_REQUEST, "unsafe mount archive"
                    )
    except HTTPException:
        raise
    except (binascii.Error, tarfile.TarError, ValueError, OSError) as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "invalid mount archive"
        ) from exc


def _job_image(job: dict[str, Any]) -> str:
    try:
        return str(job["spec"]["template"]["spec"]["containers"][0]["image"])
    except Exception:
        return ""


def _job_status(status: dict[str, Any]) -> str:
    if status.get("succeeded", 0) >= 1:
        return "exited"
    if status.get("failed", 0) >= 1:
        return "failed"
    if status.get("active", 0) >= 1:
        return "running"
    return "created"


def create_kubernetes_broker_app(
    *,
    registry: BrokerTokenRegistry,
    service: Any,
) -> FastAPI:
    app = FastAPI(title="Platform Kubernetes Broker", version="1.0")

    @app.get("/health", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/docker/run", response_model=BrokerRunResponse)
    def run_container(
        request: BrokerRunRequest,
        authorization: str | None = Header(default=None),
        x_platform_challenge_slug: str | None = Header(
            default=None, alias="X-Platform-Challenge-Slug"
        ),
    ) -> BrokerRunResponse:
        slug = _authenticate(registry, x_platform_challenge_slug, authorization)
        return service.run(slug, request)

    @app.post("/v1/docker/cleanup", response_model=BrokerCleanupResponse)
    def cleanup(
        request: BrokerCleanupRequest,
        authorization: str | None = Header(default=None),
        x_platform_challenge_slug: str | None = Header(
            default=None, alias="X-Platform-Challenge-Slug"
        ),
    ) -> BrokerCleanupResponse:
        slug = _authenticate(registry, x_platform_challenge_slug, authorization)
        return service.cleanup(slug, request)

    @app.post("/v1/docker/list", response_model=BrokerListResponse)
    def list_containers(
        request: BrokerListRequest,
        authorization: str | None = Header(default=None),
        x_platform_challenge_slug: str | None = Header(
            default=None, alias="X-Platform-Challenge-Slug"
        ),
    ) -> BrokerListResponse:
        slug = _authenticate(registry, x_platform_challenge_slug, authorization)
        return service.list_containers(slug, request)

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
