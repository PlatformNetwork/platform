from __future__ import annotations

from typing import Any
from urllib.parse import quote

from platform_network.config.policy import (
    ProductionPolicyError,
    validate_image_reference,
)
from platform_network.kubernetes.names import (
    POSTGRES_SECRET_KEY_DATABASE_URL,
    POSTGRES_SECRET_KEY_DB,
    POSTGRES_SECRET_KEY_PASSWORD,
    POSTGRES_SECRET_KEY_USER,
    broker_job_name,
    challenge_name,
    challenge_postgres_names,
    challenge_secret_name,
)
from platform_network.master.docker_orchestrator import (
    DEFAULT_SECRET_MOUNT_DIR,
    DEFAULT_SQLITE_PATH,
    ChallengeResources,
    ChallengeSpec,
)
from platform_network.schemas.docker_broker import BrokerLimits, BrokerRunRequest


def common_labels(
    component: str, *, challenge_slug: str | None = None
) -> dict[str, str]:
    labels = {
        "app.kubernetes.io/name": "platform-network",
        "app.kubernetes.io/managed-by": "platform-network",
        "platform.component": component,
    }
    if challenge_slug:
        labels["platform.challenge.slug"] = challenge_slug
    return labels


def challenge_labels(spec: ChallengeSpec) -> dict[str, str]:
    return common_labels("challenge", challenge_slug=spec.slug) | {
        "app.kubernetes.io/instance": challenge_name(spec.slug),
        "platform.challenge.version": spec.version or "",
    }


def build_challenge_secret(
    spec: ChallengeSpec, *, namespace: str
) -> dict[str, Any] | None:
    secrets = spec.all_secrets()
    if not secrets:
        return None
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": challenge_secret_name(spec.slug),
            "namespace": namespace,
            "labels": common_labels("challenge-secret", challenge_slug=spec.slug),
        },
        "type": "Opaque",
        "stringData": dict(secrets),
    }


def build_challenge_service(spec: ChallengeSpec, *, namespace: str) -> dict[str, Any]:
    name = challenge_name(spec.slug)
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": challenge_labels(spec),
        },
        "spec": {
            "type": "ClusterIP",
            "selector": {"app.kubernetes.io/instance": name},
            "ports": [
                {
                    "name": "http",
                    "port": spec.port,
                    "targetPort": spec.port,
                }
            ],
        },
    }


def build_challenge_postgres_secret(
    slug: str,
    *,
    namespace: str,
    retain: bool = True,
    password: str | None = None,
    database_url: str | None = None,
) -> dict[str, Any]:
    names = challenge_postgres_names(slug)
    if not password:
        raise ValueError("managed Postgres password must be provided")
    password_value = password
    database_url_value = database_url or (
        f"postgresql+asyncpg://{names.database_user}:{quote(password_value, safe='')}"
        f"@{names.service_name}:5432/{names.database_name}"
    )
    metadata: dict[str, Any] = {
        "name": names.secret_name,
        "namespace": namespace,
        "labels": common_labels("challenge-postgres-secret", challenge_slug=slug),
    }
    if retain:
        metadata["annotations"] = {"helm.sh/resource-policy": "keep"}
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": metadata,
        "type": "Opaque",
        "stringData": {
            POSTGRES_SECRET_KEY_DB: names.database_name,
            POSTGRES_SECRET_KEY_USER: names.database_user,
            POSTGRES_SECRET_KEY_PASSWORD: password_value,
            POSTGRES_SECRET_KEY_DATABASE_URL: database_url_value,
        },
    }


def build_challenge_postgres_service(slug: str, *, namespace: str) -> dict[str, Any]:
    names = challenge_postgres_names(slug)
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": names.service_name,
            "namespace": namespace,
            "labels": _challenge_postgres_labels(slug),
        },
        "spec": {
            "type": "ClusterIP",
            "selector": {"app.kubernetes.io/instance": names.statefulset_name},
            "ports": [{"name": "postgres", "port": 5432, "targetPort": 5432}],
        },
    }


def build_challenge_postgres_statefulset(
    slug: str,
    *,
    namespace: str,
    image: str = "postgres:16-alpine",
    storage_class_name: str | None = None,
    storage_size: str = "10Gi",
    retain_pvc: bool = True,
    resources: dict[str, Any] | None = None,
) -> dict[str, Any]:
    names = challenge_postgres_names(slug)
    labels = _challenge_postgres_labels(slug) | {
        "app.kubernetes.io/instance": names.statefulset_name
    }
    claim_metadata: dict[str, Any] = {
        "name": names.data_claim_name,
        "labels": common_labels("challenge-postgres-data", challenge_slug=slug),
    }
    if retain_pvc:
        claim_metadata["annotations"] = {"helm.sh/resource-policy": "keep"}
    claim_spec: dict[str, Any] = {
        "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": storage_size}},
    }
    if storage_class_name:
        claim_spec["storageClassName"] = storage_class_name
    container: dict[str, Any] = {
        "name": "postgres",
        "image": image,
        "ports": [{"name": "postgres", "containerPort": 5432}],
        "env": [
            _secret_env_var(POSTGRES_SECRET_KEY_DB, names.secret_name),
            _secret_env_var(POSTGRES_SECRET_KEY_USER, names.secret_name),
            _secret_env_var(POSTGRES_SECRET_KEY_PASSWORD, names.secret_name),
            {"name": "PGDATA", "value": "/var/lib/postgresql/data/pgdata"},
        ],
        "volumeMounts": [
            {"name": names.data_claim_name, "mountPath": "/var/lib/postgresql/data"}
        ],
    }
    if resources is not None:
        container["resources"] = resources
    return {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": names.statefulset_name,
            "namespace": namespace,
            "labels": _challenge_postgres_labels(slug),
        },
        "spec": {
            "replicas": 1,
            "serviceName": names.service_name,
            "selector": {
                "matchLabels": {"app.kubernetes.io/instance": names.statefulset_name}
            },
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": _postgres_pod_security_context(),
                    "containers": [container],
                },
            },
            "volumeClaimTemplates": [{"metadata": claim_metadata, "spec": claim_spec}],
        },
    }


def validate_broker_kubernetes_limits(limits: BrokerLimits) -> None:
    defaults = BrokerLimits()
    if limits.pids_limit != defaults.pids_limit:
        raise ValueError(
            "Kubernetes PodSpec does not support Docker pids_limit; "
            "enforce PID ceilings with cluster or admission policy"
        )
    if limits.memory_swap != defaults.memory_swap:
        raise ValueError(
            "Kubernetes PodSpec does not support Docker memory_swap; "
            "enforce swap behavior with node or admission policy"
        )
    if limits.network not in {"none", "default"}:
        raise ValueError(
            "Kubernetes broker supports network=none or network=default; "
            "Docker-specific network modes are unsupported"
        )


def validate_challenge_kubernetes_resources(resources: ChallengeResources) -> None:
    defaults = ChallengeResources()
    if resources.pids_limit != defaults.pids_limit:
        raise ValueError(
            "Kubernetes PodSpec does not support Docker pids_limit; "
            "enforce PID ceilings with cluster or admission policy"
        )
    if resources.memory_swap != defaults.memory_swap:
        raise ValueError(
            "Kubernetes PodSpec does not support Docker memory_swap; "
            "enforce swap behavior with node or admission policy"
        )


def build_challenge_workload(
    spec: ChallengeSpec,
    *,
    namespace: str,
    mode: str = "statefulset",
    storage_class_name: str | None = None,
    storage_size: str = "10Gi",
    replicas: int = 1,
    gpu_resource_name: str = "nvidia.com/gpu",
    node_selector: dict[str, str] | None = None,
    tolerations: list[dict[str, Any]] | None = None,
    runtime_class_name: str | None = None,
    image_pull_secrets: list[str] | None = None,
    docker_broker_url: str = "http://platform-broker:8082",
    production: bool = False,
    managed_postgres: bool = False,
) -> dict[str, Any]:
    if mode not in {"statefulset", "deployment"}:
        raise ValueError("mode must be 'statefulset' or 'deployment'")
    validate_challenge_kubernetes_resources(spec.resources)
    if mode == "statefulset" and replicas != 1:
        raise ValueError("SQLite-backed StatefulSet challenges must use one replica")
    name = challenge_name(spec.slug)
    template = _pod_template(
        spec,
        namespace=namespace,
        gpu_resource_name=gpu_resource_name,
        node_selector=node_selector or {},
        tolerations=tolerations or [],
        runtime_class_name=runtime_class_name,
        image_pull_secrets=image_pull_secrets or [],
        docker_broker_url=docker_broker_url,
        with_pvc=mode == "statefulset",
        production=production,
        managed_postgres=managed_postgres,
    )
    base: dict[str, Any] = {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet" if mode == "statefulset" else "Deployment",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": challenge_labels(spec),
        },
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"app.kubernetes.io/instance": name}},
            "template": template,
        },
    }
    if mode == "statefulset":
        claim_spec: dict[str, Any] = {
            "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": storage_size}},
        }
        if storage_class_name:
            claim_spec["storageClassName"] = storage_class_name
        claim: dict[str, Any] = {
            "metadata": {"name": "challenge-data"},
            "spec": claim_spec,
        }
        base["spec"]["serviceName"] = name
        base["spec"]["volumeClaimTemplates"] = [claim]
    return base


def build_challenge_hpa(
    spec: ChallengeSpec,
    *,
    namespace: str,
    min_replicas: int = 1,
    max_replicas: int = 3,
    target_cpu_utilization: int = 70,
) -> dict[str, Any]:
    if max_replicas < min_replicas:
        raise ValueError("max_replicas must be >= min_replicas")
    name = challenge_name(spec.slug)
    return {
        "apiVersion": "autoscaling/v2",
        "kind": "HorizontalPodAutoscaler",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": common_labels("challenge-hpa", challenge_slug=spec.slug),
        },
        "spec": {
            "scaleTargetRef": {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "name": name,
            },
            "minReplicas": min_replicas,
            "maxReplicas": max_replicas,
            "metrics": [
                {
                    "type": "Resource",
                    "resource": {
                        "name": "cpu",
                        "target": {
                            "type": "Utilization",
                            "averageUtilization": target_cpu_utilization,
                        },
                    },
                }
            ],
        },
    }


def build_challenge_scaled_object(
    spec: ChallengeSpec,
    *,
    namespace: str,
    min_replicas: int = 1,
    max_replicas: int = 3,
    target_cpu_utilization: int = 70,
) -> dict[str, Any]:
    if max_replicas < min_replicas:
        raise ValueError("max_replicas must be >= min_replicas")
    name = challenge_name(spec.slug)
    return {
        "apiVersion": "keda.sh/v1alpha1",
        "kind": "ScaledObject",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": common_labels("challenge-scaledobject", challenge_slug=spec.slug),
        },
        "spec": {
            "scaleTargetRef": {"name": name},
            "minReplicaCount": min_replicas,
            "maxReplicaCount": max_replicas,
            "triggers": [
                {
                    "type": "cpu",
                    "metricType": "Utilization",
                    "metadata": {"value": str(target_cpu_utilization)},
                }
            ],
        },
    }


def build_broker_job(
    challenge_slug: str,
    request: BrokerRunRequest,
    *,
    namespace: str,
    service_account_name: str,
    run_id: str | None = None,
    archive_extractor_image: str = "python:3.12-alpine",
) -> dict[str, Any]:
    name = broker_job_name(challenge_slug, request.job_id, request.task_id, run_id)
    labels = common_labels("broker-job", challenge_slug=challenge_slug) | {
        "platform.job": request.job_id,
    }
    if request.task_id:
        labels["platform.task"] = request.task_id
    if run_id:
        labels["platform.run"] = run_id
    validate_broker_kubernetes_limits(request.limits)
    memory = _memory_quantity(request.limits.memory)
    resources = {
        "requests": {"cpu": str(request.limits.cpus), "memory": memory},
        "limits": {"cpu": str(request.limits.cpus), "memory": memory},
    }
    volumes = _broker_volumes(name, request)
    volume_mounts = _broker_volume_mounts(request)
    init_containers = _broker_init_containers(
        request, archive_extractor_image=archive_extractor_image
    )
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": labels,
            "annotations": _unsupported_docker_semantics_annotations(),
        },
        "spec": {
            "ttlSecondsAfterFinished": 300,
            "activeDeadlineSeconds": request.timeout_seconds,
            "backoffLimit": 0,
            "template": {
                "metadata": {
                    "labels": labels,
                    "annotations": _unsupported_docker_semantics_annotations(),
                },
                "spec": {
                    "serviceAccountName": service_account_name,
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": _pod_security_context(),
                    "initContainers": init_containers,
                    "containers": [
                        {
                            "name": "job",
                            "image": request.image,
                            "command": request.command,
                            "workingDir": request.workdir,
                            "env": [
                                {"name": key, "value": value}
                                for key, value in request.env.items()
                            ],
                            "resources": resources,
                            "volumeMounts": volume_mounts,
                            "securityContext": _container_security_context(
                                read_only=request.limits.read_only
                            ),
                        }
                    ],
                    "volumes": volumes,
                },
            },
        },
    }


def build_broker_mount_secret(
    challenge_slug: str,
    request: BrokerRunRequest,
    *,
    namespace: str,
    run_id: str | None = None,
) -> dict[str, Any] | None:
    if not request.mounts:
        return None
    name = broker_job_name(challenge_slug, request.job_id, request.task_id, run_id)
    string_data = {
        f"mount-{index}.tar.gz.b64": mount.archive_b64
        for index, mount in enumerate(request.mounts)
    }
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": broker_mount_secret_name(name),
            "namespace": namespace,
            "labels": common_labels("broker-job-mount", challenge_slug=challenge_slug)
            | {"platform.job": request.job_id},
        },
        "type": "Opaque",
        "stringData": string_data,
    }


def build_broker_network_policy(
    challenge_slug: str,
    request: BrokerRunRequest,
    *,
    namespace: str,
    run_id: str | None = None,
) -> dict[str, Any]:
    name = broker_job_name(challenge_slug, request.job_id, request.task_id, run_id)
    labels = common_labels("broker-job-network", challenge_slug=challenge_slug) | {
        "platform.job": request.job_id,
    }
    if request.task_id:
        labels["platform.task"] = request.task_id
    if run_id:
        labels["platform.run"] = run_id
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": labels,
            "annotations": _unsupported_docker_semantics_annotations(),
        },
        "spec": {
            "podSelector": {"matchLabels": {"job-name": name}},
            "policyTypes": ["Ingress", "Egress"],
        },
    }


def broker_mount_secret_name(job_name: str) -> str:
    return f"{job_name}-mounts"


def _broker_volumes(job_name: str, request: BrokerRunRequest) -> list[dict[str, Any]]:
    volumes = [
        _tmpfs_volume(index, tmpfs) for index, tmpfs in enumerate(request.limits.tmpfs)
    ]
    if request.mounts:
        volumes.append(
            {
                "name": "archives",
                "secret": {"secretName": broker_mount_secret_name(job_name)},
            }
        )
        volumes.extend(
            {"name": f"mount-{index}", "emptyDir": {}}
            for index, _mount in enumerate(request.mounts)
        )
    return volumes


def _broker_volume_mounts(request: BrokerRunRequest) -> list[dict[str, Any]]:
    volume_mounts = [
        {"name": f"tmpfs-{index}", "mountPath": _tmpfs_path(tmpfs)}
        for index, tmpfs in enumerate(request.limits.tmpfs)
    ]
    for index, mount in enumerate(request.mounts):
        volume_mount: dict[str, Any] = {
            "name": f"mount-{index}",
            "mountPath": mount.target,
            "readOnly": mount.read_only,
        }
        if mount.source_type == "file":
            volume_mount["subPath"] = mount.source_name
        volume_mounts.append(volume_mount)
    return volume_mounts


def _broker_init_containers(
    request: BrokerRunRequest, *, archive_extractor_image: str
) -> list[dict[str, Any]]:
    if not request.mounts:
        return []
    script = "\n".join(
        [
            "import base64, io, pathlib, sys, tarfile",
            "archive = pathlib.Path(sys.argv[1]).read_text().strip()",
            "root = pathlib.Path(sys.argv[2]).resolve()",
            "payload = io.BytesIO(base64.b64decode(archive))",
            "with tarfile.open(fileobj=payload, mode='r:gz') as tar:",
            "    for member in tar.getmembers():",
            "        path = pathlib.Path(member.name)",
            "        if (path.is_absolute() or '..' in path.parts or member.issym()",
            "                or member.islnk() or member.isdev()):",
            "            raise SystemExit('unsafe mount archive')",
            "        target = (root / path).resolve()",
            "        if target != root and root not in target.parents:",
            "            raise SystemExit('unsafe mount archive')",
            "    tar.extractall(root, filter='data')",
        ]
    )
    return [
        {
            "name": f"unpack-mount-{index}",
            "image": archive_extractor_image,
            "command": [
                "python",
                "-c",
                script,
                f"/archives/mount-{index}.tar.gz.b64",
                "/work",
            ],
            "volumeMounts": [
                {"name": "archives", "mountPath": "/archives", "readOnly": True},
                {"name": f"mount-{index}", "mountPath": "/work"},
            ],
            "securityContext": _container_security_context(read_only=True),
        }
        for index, _mount in enumerate(request.mounts)
    ]


def _tmpfs_volume(index: int, value: str) -> dict[str, Any]:
    empty_dir: dict[str, str] = {"medium": "Memory"}
    size = _tmpfs_size(value)
    if size:
        empty_dir["sizeLimit"] = size
    return {"name": f"tmpfs-{index}", "emptyDir": empty_dir}


def _tmpfs_path(value: str) -> str:
    return value.split(":", 1)[0]


def _tmpfs_size(value: str) -> str | None:
    for option in value.split(":")[1:]:
        for part in option.split(","):
            if part.startswith("size="):
                return _memory_quantity(part.removeprefix("size="))
    return None


def _pod_template(
    spec: ChallengeSpec,
    *,
    namespace: str,
    gpu_resource_name: str,
    node_selector: dict[str, str],
    tolerations: list[dict[str, Any]],
    runtime_class_name: str | None,
    image_pull_secrets: list[str],
    docker_broker_url: str,
    with_pvc: bool,
    production: bool,
    managed_postgres: bool,
) -> dict[str, Any]:
    if managed_postgres and "CHALLENGE_DATABASE_URL" in spec.env:
        raise ValueError(
            "CHALLENGE_DATABASE_URL is owned by Platform-managed Postgres when "
            "managed_postgres=True; remove it from challenge env"
        )
    if production:
        _validate_production_challenge_spec(spec, managed_postgres=managed_postgres)
    volumes: list[dict[str, Any]] = []
    volume_mounts: list[dict[str, Any]] = []
    if with_pvc:
        volume_mounts.append({"name": "challenge-data", "mountPath": "/data"})
    else:
        volumes.append({"name": "challenge-data", "emptyDir": {}})
        volume_mounts.append({"name": "challenge-data", "mountPath": "/data"})
    if spec.all_secrets():
        volumes.append(
            {
                "name": "platform-secrets",
                "secret": {"secretName": challenge_secret_name(spec.slug)},
            }
        )
        volume_mounts.append(
            {
                "name": "platform-secrets",
                "mountPath": DEFAULT_SECRET_MOUNT_DIR,
                "readOnly": True,
            }
        )
    pod_spec: dict[str, Any] = {
        "automountServiceAccountToken": False,
        "securityContext": _pod_security_context(),
        "containers": [
            {
                "name": "challenge",
                "image": spec.image,
                "ports": [{"name": "http", "containerPort": spec.port}],
                "env": _challenge_env(
                    spec,
                    docker_broker_url=docker_broker_url,
                    managed_postgres=managed_postgres,
                ),
                "volumeMounts": volume_mounts,
                "resources": _challenge_resources(spec, gpu_resource_name),
                "readinessProbe": _http_probe("/health", spec.port),
                "livenessProbe": _http_probe("/health", spec.port),
                "securityContext": _container_security_context(),
            }
        ],
        "volumes": volumes,
    }
    if node_selector:
        pod_spec["nodeSelector"] = node_selector
    if tolerations:
        pod_spec["tolerations"] = tolerations
    if runtime_class_name:
        pod_spec["runtimeClassName"] = runtime_class_name
    if image_pull_secrets:
        pod_spec["imagePullSecrets"] = [
            {"name": secret_name} for secret_name in image_pull_secrets
        ]
    return {
        "metadata": {
            "labels": challenge_labels(spec),
            "annotations": _unsupported_docker_semantics_annotations(),
        },
        "spec": pod_spec,
    }


def _challenge_env(
    spec: ChallengeSpec, *, docker_broker_url: str, managed_postgres: bool
) -> list[dict[str, Any]]:
    env = dict(spec.env)
    env.setdefault("PLATFORM_CHALLENGE_SLUG", spec.slug)
    if not managed_postgres:
        env.setdefault(
            "CHALLENGE_DATABASE_URL", f"sqlite+aiosqlite:///{DEFAULT_SQLITE_PATH}"
        )
    for secret_name in spec.all_secrets():
        env.setdefault(
            f"{secret_name.upper()}_FILE",
            f"{DEFAULT_SECRET_MOUNT_DIR}/{secret_name}",
        )
        if secret_name == "challenge_token":
            env.setdefault(
                "CHALLENGE_SHARED_TOKEN_FILE",
                f"{DEFAULT_SECRET_MOUNT_DIR}/{secret_name}",
            )
    if "docker_executor" in spec.required_capabilities:
        env.setdefault("CHALLENGE_DOCKER_ENABLED", "true")
        env.setdefault("CHALLENGE_DOCKER_BACKEND", "broker")
        env.setdefault("CHALLENGE_DOCKER_BROKER_URL", docker_broker_url)
        env.setdefault(
            "CHALLENGE_DOCKER_BROKER_TOKEN_FILE",
            f"{DEFAULT_SECRET_MOUNT_DIR}/docker_broker_token",
        )
    env_items: list[dict[str, Any]] = [
        {"name": key, "value": value} for key, value in sorted(env.items())
    ]
    if managed_postgres:
        env_items = [
            item for item in env_items if item["name"] != "CHALLENGE_DATABASE_URL"
        ]
        env_items.append(
            _secret_env_var(
                POSTGRES_SECRET_KEY_DATABASE_URL,
                challenge_postgres_names(spec.slug).secret_name,
            )
        )
        env_items.sort(key=lambda item: item["name"])
    return env_items


def _secret_env_var(name: str, secret_name: str) -> dict[str, Any]:
    return {
        "name": name,
        "valueFrom": {"secretKeyRef": {"name": secret_name, "key": name}},
    }


def _challenge_postgres_labels(slug: str) -> dict[str, str]:
    return common_labels("challenge-postgres", challenge_slug=slug)


def _validate_production_challenge_spec(
    spec: ChallengeSpec, *, managed_postgres: bool = False
) -> None:
    try:
        validate_image_reference(spec.image, production=True)
    except ProductionPolicyError as exc:
        raise ValueError(
            "production Kubernetes challenges require semver-tagged "
            "digest-pinned images"
        ) from exc
    database_url = spec.env.get("CHALLENGE_DATABASE_URL", "")
    if not managed_postgres and not database_url.startswith(
        ("postgres://", "postgresql://", "postgresql+asyncpg://")
    ):
        raise ValueError("production Kubernetes challenges require PostgreSQL")
    if spec.resources.cpu is None or spec.resources.memory is None:
        raise ValueError(
            "production Kubernetes challenges require CPU and memory requests/limits"
        )


def _unsupported_docker_semantics_annotations() -> dict[str, str]:
    return {
        "platform.network/kubernetes-pid-semantics": (
            "Docker pids_limit is not a Kubernetes PodSpec field; "
            "enforce PID ceilings with cluster or admission policy."
        ),
        "platform.network/kubernetes-swap-semantics": (
            "Docker memory_swap is not a Kubernetes PodSpec field; "
            "enforce swap behavior with node or admission policy."
        ),
    }


def _memory_quantity(value: str) -> str:
    stripped = value.strip()
    suffixes = {"g": "Gi", "m": "Mi", "k": "Ki"}
    suffix = stripped[-1:]
    if suffix in suffixes and stripped[:-1]:
        return f"{stripped[:-1]}{suffixes[suffix]}"
    return stripped


def _challenge_resources(spec: ChallengeSpec, gpu_resource_name: str) -> dict[str, Any]:
    requests: dict[str, str] = {}
    limits: dict[str, str] = {}
    if spec.resources.cpu is not None:
        requests["cpu"] = str(spec.resources.cpu)
        limits["cpu"] = str(spec.resources.cpu)
    if spec.resources.memory is not None:
        memory = _memory_quantity(spec.resources.memory)
        requests["memory"] = memory
        limits["memory"] = memory
    if spec.resources.gpu_count is not None and spec.resources.gpu_count > 0:
        limits[gpu_resource_name] = str(spec.resources.gpu_count)
    return {"requests": requests, "limits": limits}


def _pod_security_context() -> dict[str, Any]:
    return {
        "runAsNonRoot": True,
        "fsGroup": 1000,
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def _postgres_pod_security_context() -> dict[str, Any]:
    context = _pod_security_context()
    context.update({"runAsUser": 70, "runAsGroup": 70, "fsGroup": 70})
    return context


def _container_security_context(*, read_only: bool = False) -> dict[str, Any]:
    return {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": read_only,
        "capabilities": {"drop": ["ALL"]},
    }


def _http_probe(path: str, port: int) -> dict[str, Any]:
    return {
        "httpGet": {"path": path, "port": port},
        "periodSeconds": 10,
        "timeoutSeconds": 2,
        "failureThreshold": 6,
    }
