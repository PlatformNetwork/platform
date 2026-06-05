from __future__ import annotations

import base64
import io
import re
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

import platform_network.kubernetes.resources as kubernetes_resources
from platform_network.kubernetes.names import (
    POSTGRES_SECRET_KEYS,
    broker_job_name,
    challenge_name,
    challenge_postgres_names,
    k8s_name,
)
from platform_network.kubernetes.resources import (
    build_broker_job,
    build_broker_mount_secret,
    build_broker_network_policy,
    build_challenge_hpa,
    build_challenge_scaled_object,
    build_challenge_secret,
    build_challenge_service,
    build_challenge_workload,
    validate_broker_kubernetes_limits,
)
from platform_network.master.docker_orchestrator import (
    DEFAULT_SECRET_MOUNT_DIR,
    ChallengeResources,
    ChallengeSpec,
)
from platform_network.schemas.docker_broker import (
    BrokerLimits,
    BrokerMount,
    BrokerRunRequest,
)


def test_k8s_name_is_dns_safe_and_stable() -> None:
    assert k8s_name("Challenge", "Demo_One") == "challenge-demo-one"
    long = k8s_name("x" * 100)
    assert len(long) == 63
    assert re.fullmatch(r"x+-[a-f0-9]{8}", long)
    with pytest.raises(ValueError):
        k8s_name("!!!")


def test_challenge_postgres_names_contract_is_dns_safe_and_stable() -> None:
    names = challenge_postgres_names("agent-challenge")

    assert names.base_name == "challenge-agent-challenge-postgres"
    assert names.service_name == "challenge-agent-challenge-postgres"
    assert names.statefulset_name == "challenge-agent-challenge-postgres"
    assert names.stateful_set_name == "challenge-agent-challenge-postgres"
    assert names.secret_name == "challenge-agent-challenge-postgres-secret"
    assert names.data_claim_name == "challenge-agent-challenge-postgres-data"
    assert names.database_name == "challenge"
    assert names.database_user == "challenge"
    assert names.secret_keys == POSTGRES_SECRET_KEYS
    assert names.secret_keys == (
        "POSTGRES_DB",
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
        "CHALLENGE_DATABASE_URL",
    )

    normalized = challenge_postgres_names("Agent_Challenge")
    assert normalized.base_name.startswith("challenge-agent-challenge-")
    assert normalized.base_name.endswith("-postgres")
    assert normalized.base_name != names.base_name

    long = challenge_postgres_names("a" * 80)
    for value in (
        normalized.base_name,
        normalized.service_name,
        normalized.statefulset_name,
        normalized.secret_name,
        normalized.data_claim_name,
        long.base_name,
        long.service_name,
        long.statefulset_name,
        long.secret_name,
        long.data_claim_name,
    ):
        assert len(value) <= 63
        assert re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", value)


def test_challenge_postgres_name_collision_resistance_for_normalized_slugs() -> None:
    hyphen = challenge_postgres_names("agent-challenge")
    underscore = challenge_postgres_names("agent_challenge")

    assert k8s_name("agent-challenge") == k8s_name("agent_challenge")
    assert hyphen.base_name != underscore.base_name
    assert hyphen.secret_name != underscore.secret_name
    assert hyphen.data_claim_name != underscore.data_claim_name


def test_managed_postgres_secret_keys_avoid_password_snapshot() -> None:
    names = challenge_postgres_names("agent-challenge")
    builder = _required_managed_postgres_builder("build_challenge_postgres_secret")

    secret = builder(
        "agent-challenge",
        namespace="platform",
        retain=True,
        password="unit-test-generated-credential",
    )

    assert secret["apiVersion"] == "v1"
    assert secret["kind"] == "Secret"
    assert secret["metadata"]["name"] == names.secret_name
    assert secret["metadata"]["namespace"] == "platform"
    assert secret["metadata"]["labels"]["platform.challenge.slug"] == "agent-challenge"
    assert (
        secret["metadata"]["labels"]["platform.component"]
        == "challenge-postgres-secret"
    )
    assert secret["metadata"]["annotations"] == {"helm.sh/resource-policy": "keep"}
    assert secret["type"] == "Opaque"
    assert set(secret["stringData"]) == set(names.secret_keys)
    assert secret["stringData"]["POSTGRES_DB"] == names.database_name
    assert secret["stringData"]["POSTGRES_USER"] == names.database_user
    assert secret["stringData"]["POSTGRES_PASSWORD"]
    assert secret["stringData"]["CHALLENGE_DATABASE_URL"]
    assert secret["stringData"]["POSTGRES_PASSWORD"] != "replace-me"
    assert "replace-me" not in secret["stringData"]["CHALLENGE_DATABASE_URL"]


def test_managed_postgres_secret_requires_explicit_password() -> None:
    builder = _required_managed_postgres_builder("build_challenge_postgres_secret")

    with pytest.raises(ValueError, match="password must be provided"):
        builder("agent-challenge", namespace="platform", retain=True)


def test_managed_postgres_service_manifest_targets_postgres_statefulset() -> None:
    names = challenge_postgres_names("agent-challenge")
    builder = _required_managed_postgres_builder("build_challenge_postgres_service")

    service = builder("agent-challenge", namespace="platform")

    assert service["apiVersion"] == "v1"
    assert service["kind"] == "Service"
    assert service["metadata"]["name"] == names.service_name
    assert service["metadata"]["namespace"] == "platform"
    assert service["metadata"]["labels"]["platform.challenge.slug"] == "agent-challenge"
    assert service["metadata"]["labels"]["platform.component"] == "challenge-postgres"
    assert service["spec"]["type"] == "ClusterIP"
    assert service["spec"]["selector"] == {
        "app.kubernetes.io/instance": names.statefulset_name
    }
    assert service["spec"]["ports"] == [
        {"name": "postgres", "port": 5432, "targetPort": 5432}
    ]


def test_managed_postgres_statefulset_manifest_has_independent_data_claim() -> None:
    names = challenge_postgres_names("agent-challenge")
    builder = _required_managed_postgres_builder("build_challenge_postgres_statefulset")

    statefulset = builder(
        "agent-challenge",
        namespace="platform",
        image="postgres:16-alpine",
        storage_class_name="fast-retain",
        storage_size="10Gi",
        retain_pvc=True,
        resources={
            "requests": {"cpu": "100m", "memory": "256Mi"},
            "limits": {"cpu": "500m", "memory": "512Mi"},
        },
    )
    pod_spec = statefulset["spec"]["template"]["spec"]
    container = pod_spec["containers"][0]
    env = _env_by_name(container["env"])

    assert statefulset["apiVersion"] == "apps/v1"
    assert statefulset["kind"] == "StatefulSet"
    assert statefulset["metadata"]["name"] == names.statefulset_name
    assert statefulset["metadata"]["namespace"] == "platform"
    assert (
        statefulset["metadata"]["labels"]["platform.challenge.slug"]
        == "agent-challenge"
    )
    assert (
        statefulset["metadata"]["labels"]["platform.component"] == "challenge-postgres"
    )
    assert statefulset["spec"]["serviceName"] == names.service_name
    assert statefulset["spec"]["selector"] == {
        "matchLabels": {"app.kubernetes.io/instance": names.statefulset_name}
    }
    assert (
        statefulset["spec"]["template"]["metadata"]["labels"][
            "app.kubernetes.io/instance"
        ]
        == names.statefulset_name
    )
    assert container["name"] == "postgres"
    assert container["image"] == "postgres:16-alpine"
    assert pod_spec["securityContext"] == {
        "runAsNonRoot": True,
        "seccompProfile": {"type": "RuntimeDefault"},
        "runAsUser": 70,
        "runAsGroup": 70,
        "fsGroup": 70,
    }
    assert container["ports"] == [{"name": "postgres", "containerPort": 5432}]
    assert _secret_env_ref(env, "POSTGRES_DB") == {
        "name": names.secret_name,
        "key": "POSTGRES_DB",
    }
    assert _secret_env_ref(env, "POSTGRES_USER") == {
        "name": names.secret_name,
        "key": "POSTGRES_USER",
    }
    assert _secret_env_ref(env, "POSTGRES_PASSWORD") == {
        "name": names.secret_name,
        "key": "POSTGRES_PASSWORD",
    }
    assert env["PGDATA"] == {
        "name": "PGDATA",
        "value": "/var/lib/postgresql/data/pgdata",
    }
    assert {"name": names.data_claim_name, "mountPath": "/var/lib/postgresql/data"} in (
        container["volumeMounts"]
    )
    assert statefulset["spec"]["volumeClaimTemplates"] == [
        {
            "metadata": {
                "name": names.data_claim_name,
                "labels": {
                    "app.kubernetes.io/name": "platform-network",
                    "app.kubernetes.io/managed-by": "platform-network",
                    "platform.component": "challenge-postgres-data",
                    "platform.challenge.slug": "agent-challenge",
                },
                "annotations": {"helm.sh/resource-policy": "keep"},
            },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "resources": {"requests": {"storage": "10Gi"}},
                "storageClassName": "fast-retain",
            },
        }
    ]
    assert names.data_claim_name != "challenge-data"


def test_managed_postgres_challenge_runtime_env_uses_database_url_secret_ref() -> None:
    names = challenge_postgres_names("agent-challenge")

    workload = build_challenge_workload(
        ChallengeSpec(slug="agent-challenge", image="ghcr.io/org/agent-challenge:1"),
        namespace="platform",
        mode="statefulset",
        managed_postgres=True,
    )
    container = workload["spec"]["template"]["spec"]["containers"][0]
    env = _env_by_name(container["env"])

    assert _secret_env_ref(env, "CHALLENGE_DATABASE_URL") == {
        "name": names.secret_name,
        "key": "CHALLENGE_DATABASE_URL",
    }


def test_challenge_worker_sidecar_uses_same_image_env_and_storage() -> None:
    workload = build_challenge_workload(
        ChallengeSpec(
            slug="agent-challenge",
            image="ghcr.io/platformnetwork/agent-challenge:1",
            worker_command=("agent-challenge-worker",),
            required_capabilities=("get_weights", "proxy_routes", "docker_executor"),
        ),
        namespace="platform",
        mode="statefulset",
        managed_postgres=True,
        docker_broker_url="http://platform-master-broker:8082",
    )

    containers = workload["spec"]["template"]["spec"]["containers"]
    challenge, worker = containers

    assert challenge["name"] == "challenge"
    assert worker["name"] == "worker"
    assert worker["image"] == challenge["image"]
    assert worker["command"] == ["agent-challenge-worker"]
    assert worker["env"] == challenge["env"]
    assert worker["volumeMounts"] == challenge["volumeMounts"]
    assert "ports" not in worker
    assert "readinessProbe" not in worker
    assert _env_by_name(worker["env"])["CHALLENGE_DOCKER_BACKEND"]["value"] == "broker"


def test_challenge_containers_pin_numeric_run_as_user_for_nonroot_images() -> None:
    workload = build_challenge_workload(
        ChallengeSpec(
            slug="prism",
            image="ghcr.io/platformnetwork/prism:latest@sha256:dead",
            worker_command=("prism-worker",),
        ),
        namespace="platform",
        mode="statefulset",
        managed_postgres=True,
    )

    pod_spec = workload["spec"]["template"]["spec"]
    challenge, worker = pod_spec["containers"]

    for container in (challenge, worker):
        assert container["securityContext"]["runAsUser"] == 1000
        assert container["securityContext"]["runAsGroup"] == 1000
        assert container["securityContext"]["allowPrivilegeEscalation"] is False

    assert pod_spec["securityContext"]["runAsNonRoot"] is True
    assert pod_spec["securityContext"]["fsGroup"] == 1000


def test_managed_postgres_database_url_conflict_is_rejected() -> None:
    spec = ChallengeSpec(
        slug="agent-challenge",
        image="ghcr.io/org/agent-challenge:1",
        env={"CHALLENGE_DATABASE_URL": "postgresql+asyncpg://db.example/challenge"},
    )

    with pytest.raises(
        ValueError,
        match="CHALLENGE_DATABASE_URL.*Platform-managed Postgres",
    ):
        build_challenge_workload(
            spec,
            namespace="platform",
            mode="statefulset",
            managed_postgres=True,
        )


def test_production_managed_postgres_accepts_without_user_database_url() -> None:
    names = challenge_postgres_names("agent-challenge")
    spec = ChallengeSpec(
        slug="agent-challenge",
        image=(
            "ghcr.io/org/agent-challenge:1.2.3@"
            "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        ),
        resources=ChallengeResources(cpu=1, memory="1Gi"),
    )

    workload = build_challenge_workload(
        spec,
        namespace="platform",
        mode="deployment",
        replicas=2,
        production=True,
        managed_postgres=True,
    )
    container = workload["spec"]["template"]["spec"]["containers"][0]
    env = _env_by_name(container["env"])

    assert _secret_env_ref(env, "CHALLENGE_DATABASE_URL") == {
        "name": names.secret_name,
        "key": "CHALLENGE_DATABASE_URL",
    }


def test_data_pvc_independent_from_managed_postgres_statefulset_storage() -> None:
    names = challenge_postgres_names("agent-challenge")
    challenge_workload = build_challenge_workload(
        ChallengeSpec(slug="agent-challenge", image="ghcr.io/org/agent-challenge:1"),
        namespace="platform",
        mode="statefulset",
    )
    challenge_container = challenge_workload["spec"]["template"]["spec"]["containers"][
        0
    ]
    postgres_builder = _required_managed_postgres_builder(
        "build_challenge_postgres_statefulset"
    )

    assert {"name": "challenge-data", "mountPath": "/data"} in (
        challenge_container["volumeMounts"]
    )
    assert challenge_workload["spec"]["volumeClaimTemplates"][0]["metadata"][
        "name"
    ] == ("challenge-data")

    postgres_statefulset = postgres_builder(
        "agent-challenge",
        namespace="platform",
        image="postgres:16-alpine",
        storage_size="10Gi",
    )
    postgres_container = postgres_statefulset["spec"]["template"]["spec"]["containers"][
        0
    ]

    assert {"name": names.data_claim_name, "mountPath": "/var/lib/postgresql/data"} in (
        postgres_container["volumeMounts"]
    )
    assert names.data_claim_name != "challenge-data"
    assert all(
        volume_mount["name"] != names.data_claim_name
        for volume_mount in challenge_container["volumeMounts"]
    )


def test_multi_challenge_postgres_isolation_uses_distinct_resources() -> None:
    slugs = ("agent-challenge-a", "agent-challenge-b")
    names_by_slug = {slug: challenge_postgres_names(slug) for slug in slugs}
    secret_builder = _required_managed_postgres_builder(
        "build_challenge_postgres_secret"
    )
    service_builder = _required_managed_postgres_builder(
        "build_challenge_postgres_service"
    )
    statefulset_builder = _required_managed_postgres_builder(
        "build_challenge_postgres_statefulset"
    )

    secrets = {
        slug: secret_builder(
            slug,
            namespace="platform",
            retain=True,
            password=f"unit-test-generated-credential-{index}",
        )
        for index, slug in enumerate(slugs)
    }
    services = {slug: service_builder(slug, namespace="platform") for slug in slugs}
    statefulsets = {
        slug: statefulset_builder(slug, namespace="platform") for slug in slugs
    }
    workloads = {
        slug: build_challenge_workload(
            ChallengeSpec(slug=slug, image=f"ghcr.io/org/{slug}:1"),
            namespace="platform",
            mode="statefulset",
            managed_postgres=True,
        )
        for slug in slugs
    }

    first, second = slugs
    first_names = names_by_slug[first]
    second_names = names_by_slug[second]

    assert first_names.secret_name != second_names.secret_name
    assert first_names.service_name != second_names.service_name
    assert first_names.statefulset_name != second_names.statefulset_name
    assert first_names.data_claim_name != second_names.data_claim_name

    for slug in slugs:
        names = names_by_slug[slug]
        secret = secrets[slug]
        service = services[slug]
        statefulset = statefulsets[slug]
        workload = workloads[slug]

        assert secret["metadata"]["name"] == names.secret_name
        assert service["metadata"]["name"] == names.service_name
        assert service["spec"]["selector"] == {
            "app.kubernetes.io/instance": names.statefulset_name
        }
        assert statefulset["metadata"]["name"] == names.statefulset_name
        assert statefulset["spec"]["serviceName"] == names.service_name
        assert (
            statefulset["spec"]["volumeClaimTemplates"][0]["metadata"]["name"]
            == names.data_claim_name
        )

        postgres_env = _env_by_name(
            statefulset["spec"]["template"]["spec"]["containers"][0]["env"]
        )
        assert _secret_env_ref(postgres_env, "POSTGRES_DB") == {
            "name": names.secret_name,
            "key": "POSTGRES_DB",
        }
        assert _secret_env_ref(postgres_env, "POSTGRES_USER") == {
            "name": names.secret_name,
            "key": "POSTGRES_USER",
        }
        assert _secret_env_ref(postgres_env, "POSTGRES_PASSWORD") == {
            "name": names.secret_name,
            "key": "POSTGRES_PASSWORD",
        }

        challenge_env = _env_by_name(
            workload["spec"]["template"]["spec"]["containers"][0]["env"]
        )
        assert _secret_env_ref(challenge_env, "CHALLENGE_DATABASE_URL") == {
            "name": names.secret_name,
            "key": "CHALLENGE_DATABASE_URL",
        }

    first_url = _database_url_parts(
        secrets[first]["stringData"]["CHALLENGE_DATABASE_URL"]
    )
    second_url = _database_url_parts(
        secrets[second]["stringData"]["CHALLENGE_DATABASE_URL"]
    )

    assert first_url["scheme"] == "postgresql+asyncpg"
    assert second_url["scheme"] == "postgresql+asyncpg"
    assert first_url["username"] == first_names.database_user
    assert second_url["username"] == second_names.database_user
    assert first_url["hostname"] == first_names.service_name
    assert second_url["hostname"] == second_names.service_name
    assert first_url["hostname"] != second_url["hostname"]
    assert first_url["port"] == 5432
    assert second_url["port"] == 5432
    assert first_url["path"] == f"/{first_names.database_name}"
    assert second_url["path"] == f"/{second_names.database_name}"


def test_challenge_resources_include_secrets_gpu_and_pull_secrets() -> None:
    spec = ChallengeSpec(
        slug="demo",
        image="ghcr.io/org/demo:1",
        challenge_token="challenge-token",
        docker_broker_token="broker-token",
        resources=ChallengeResources(cpu=2, memory="4Gi", gpu_count=1),
        required_capabilities=("get_weights", "proxy_routes", "docker_executor"),
    )

    secret = build_challenge_secret(spec, namespace="platform")
    assert secret is not None
    assert secret["metadata"]["name"] == "challenge-demo-secrets"
    assert secret["stringData"]["challenge_token"] == "challenge-token"

    service = build_challenge_service(spec, namespace="platform")
    assert service["spec"]["selector"] == {
        "app.kubernetes.io/instance": challenge_name("demo")
    }

    workload = build_challenge_workload(
        spec,
        namespace="platform",
        mode="deployment",
        replicas=2,
        gpu_resource_name="nvidia.com/gpu",
        node_selector={"accelerator": "nvidia"},
        tolerations=[{"key": "nvidia.com/gpu", "operator": "Exists"}],
        runtime_class_name="nvidia",
        image_pull_secrets=["ghcr-auth"],
    )
    pod_spec = workload["spec"]["template"]["spec"]
    container = pod_spec["containers"][0]
    env = {item["name"]: item["value"] for item in container["env"]}

    assert workload["kind"] == "Deployment"
    assert workload["spec"]["replicas"] == 2
    assert pod_spec["nodeSelector"] == {"accelerator": "nvidia"}
    assert pod_spec["runtimeClassName"] == "nvidia"
    assert pod_spec["imagePullSecrets"] == [{"name": "ghcr-auth"}]
    assert container["resources"]["requests"] == {"cpu": "2", "memory": "4Gi"}
    assert container["resources"]["limits"]["cpu"] == "2"
    assert container["resources"]["limits"]["memory"] == "4Gi"
    assert container["resources"]["limits"]["nvidia.com/gpu"] == "1"
    assert (
        "pids_limit is not a Kubernetes PodSpec field"
        in (
            workload["spec"]["template"]["metadata"]["annotations"][
                "platform.network/kubernetes-pid-semantics"
            ]
        )
    )
    assert env["CHALLENGE_DOCKER_BACKEND"] == "broker"
    assert env["CHALLENGE_DOCKER_BROKER_TOKEN_FILE"] == (
        f"{DEFAULT_SECRET_MOUNT_DIR}/docker_broker_token"
    )


def test_kubernetes_resources_normalize_docker_memory_suffixes() -> None:
    challenge = build_challenge_workload(
        ChallengeSpec(
            slug="demo",
            image="ghcr.io/org/demo:1",
            resources=ChallengeResources(memory="4g"),
        ),
        namespace="platform",
    )
    challenge_container = challenge["spec"]["template"]["spec"]["containers"][0]
    assert challenge_container["resources"]["requests"]["memory"] == "4Gi"

    broker = build_broker_job(
        "demo",
        BrokerRunRequest(
            job_id="job-1",
            image="ghcr.io/platformnetwork/worker:1",
            command=["python", "-V"],
            limits=BrokerLimits(memory="512m"),
        ),
        namespace="platform",
        service_account_name="platform-master",
    )
    broker_container = broker["spec"]["template"]["spec"]["containers"][0]
    assert broker_container["resources"]["requests"]["memory"] == "512Mi"
    assert broker["spec"]["template"]["spec"]["volumes"][0]["emptyDir"] == {
        "medium": "Memory",
        "sizeLimit": "512Mi",
    }


def test_production_challenge_workload_requires_digest_image_and_postgres() -> None:
    spec = ChallengeSpec(
        slug="demo",
        image=(
            "ghcr.io/org/demo:1.2.3@"
            "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        ),
        env={"CHALLENGE_DATABASE_URL": "postgresql+asyncpg://db.example/demo"},
    )

    workload = build_challenge_workload(
        spec,
        namespace="platform",
        mode="deployment",
        replicas=2,
        production=True,
    )
    container = workload["spec"]["template"]["spec"]["containers"][0]
    env = {item["name"]: item["value"] for item in container["env"]}

    assert container["image"] == (
        "ghcr.io/org/demo:1.2.3@"
        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    )
    assert ":latest" not in container["image"]
    assert env["CHALLENGE_DATABASE_URL"].startswith("postgresql+asyncpg://")
    assert "sqlite" not in repr(workload).lower()


@pytest.mark.parametrize(
    "spec, expected",
    [
        (
            ChallengeSpec(slug="demo", image="ghcr.io/org/demo:latest"),
            "semver-tagged digest-pinned images",
        ),
        (
            ChallengeSpec(
                slug="demo",
                image=(
                    "ghcr.io/org/demo@"
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                ),
            ),
            "semver-tagged digest-pinned images",
        ),
        (
            ChallengeSpec(
                slug="demo",
                image=(
                    "ghcr.io/org/demo:1.2.3@"
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                ),
                env={
                    "CHALLENGE_DATABASE_URL": "sqlite+aiosqlite:////data/demo.sqlite3"
                },
            ),
            "PostgreSQL",
        ),
    ],
)
def test_production_challenge_workload_rejects_unsafe_image_or_database(
    spec: ChallengeSpec, expected: str
) -> None:
    with pytest.raises(ValueError, match=expected):
        build_challenge_workload(
            spec,
            namespace="platform",
            mode="deployment",
            production=True,
        )


def test_kubernetes_challenge_workload_rejects_unsupported_docker_only_limits() -> None:
    with pytest.raises(ValueError, match="pids_limit"):
        build_challenge_workload(
            ChallengeSpec(
                slug="demo",
                image="ghcr.io/org/demo:1",
                resources=ChallengeResources(pids_limit=64),
            ),
            namespace="platform",
        )


def test_production_challenge_workload_requires_cpu_and_memory_bounds() -> None:
    with pytest.raises(ValueError, match="CPU and memory requests/limits"):
        build_challenge_workload(
            ChallengeSpec(
                slug="demo",
                image=(
                    "ghcr.io/org/demo:1.2.3@"
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                ),
                env={"CHALLENGE_DATABASE_URL": "postgresql+asyncpg://db/demo"},
                resources=ChallengeResources(cpu=None, memory="4Gi"),
            ),
            namespace="platform",
            mode="deployment",
            production=True,
        )


def test_statefulset_guards_sqlite_replica_count_and_hpa_target() -> None:
    spec = ChallengeSpec(slug="demo", image="ghcr.io/org/demo:1")
    with pytest.raises(ValueError, match="one replica"):
        build_challenge_workload(
            spec,
            namespace="platform",
            mode="statefulset",
            replicas=2,
        )
    with pytest.raises(ValueError, match="mode"):
        build_challenge_workload(spec, namespace="platform", mode="daemonset")

    hpa = build_challenge_hpa(
        spec,
        namespace="platform",
        min_replicas=2,
        max_replicas=5,
        target_cpu_utilization=65,
    )
    assert hpa["spec"]["scaleTargetRef"] == {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "name": "challenge-demo",
    }
    assert hpa["spec"]["minReplicas"] == 2
    with pytest.raises(ValueError, match="max_replicas"):
        build_challenge_hpa(spec, namespace="platform", min_replicas=3, max_replicas=2)

    scaled_object = build_challenge_scaled_object(spec, namespace="platform")
    assert scaled_object["kind"] == "ScaledObject"
    assert scaled_object["spec"]["scaleTargetRef"] == {"name": "challenge-demo"}


def test_broker_job_is_non_privileged_and_supports_tmpfs_and_archive_mounts() -> None:
    request = BrokerRunRequest(
        job_id="job-1",
        task_id="task-1",
        image="ghcr.io/platformnetwork/worker:1",
        command=["python", "-m", "worker"],
        env={"A": "B"},
        limits=BrokerLimits(cpus=1, memory="512Mi", read_only=True),
    )
    job = build_broker_job(
        "demo",
        request,
        namespace="platform",
        service_account_name="platform-master",
    )
    container = job["spec"]["template"]["spec"]["containers"][0]

    assert job["metadata"]["name"] == broker_job_name("demo", "job-1", "task-1")
    assert job["spec"]["template"]["spec"]["automountServiceAccountToken"] is False
    assert container["resources"] == {
        "requests": {"cpu": "1.0", "memory": "512Mi"},
        "limits": {"cpu": "1.0", "memory": "512Mi"},
    }
    assert (
        "memory_swap is not a Kubernetes PodSpec field"
        in (
            job["spec"]["template"]["metadata"]["annotations"][
                "platform.network/kubernetes-swap-semantics"
            ]
        )
    )
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["runAsUser"] == 1000
    assert container["securityContext"]["runAsGroup"] == 1000
    assert job["spec"]["activeDeadlineSeconds"] == request.timeout_seconds
    assert {"name": "tmpfs-0", "mountPath": "/tmp"} in container["volumeMounts"]
    assert "/var/run/docker.sock" not in repr(job)

    network_policy = build_broker_network_policy(
        "demo",
        request,
        namespace="platform",
    )
    assert network_policy["kind"] == "NetworkPolicy"
    assert network_policy["spec"]["podSelector"] == {
        "matchLabels": {"job-name": job["metadata"]["name"]}
    }
    assert network_policy["spec"]["policyTypes"] == ["Ingress", "Egress"]
    assert "egress" not in network_policy["spec"]

    archive = _archive_b64()
    mounted = request.model_copy(
        update={
            "mounts": [BrokerMount(target="/work", archive_b64=archive)],
        }
    )
    mounted_job = build_broker_job(
        "demo",
        mounted,
        namespace="platform",
        service_account_name="platform-master",
        run_id="abcd1234",
    )
    mount_secret = build_broker_mount_secret(
        "demo", mounted, namespace="platform", run_id="abcd1234"
    )

    assert mounted_job["metadata"]["name"].endswith("abcd1234")
    assert mounted_job["spec"]["template"]["spec"]["initContainers"][0]["name"] == (
        "unpack-mount-0"
    )
    init_security = mounted_job["spec"]["template"]["spec"]["initContainers"][0][
        "securityContext"
    ]
    assert init_security["runAsUser"] == 1000
    assert init_security["runAsGroup"] == 1000
    assert {
        "name": "mount-0",
        "mountPath": "/work",
        "readOnly": True,
    } in mounted_job["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
    assert mount_secret is not None
    assert mount_secret["stringData"]["mount-0.tar.gz.b64"] == archive


def test_platform_sdk_broker_job_contract_keeps_secrets_out_of_job_spec() -> None:
    archive = _archive_b64()
    request = BrokerRunRequest(
        job_id="job-1",
        task_id="terminal-bench/hello-world",
        image="ghcr.io/platformnetwork/controlled-runner:1",
        image_pull_policy="Never",
        command=["python", "-m", "runner"],
        workdir="/workspace",
        env={"PLATFORM_TOKEN_FILE": "/var/run/secrets/platform/token"},
        labels={"custom.label": "survives"},
        limits=BrokerLimits(cpus=1.25, memory="640Mi", read_only=True),
        mounts=[BrokerMount(target="/workspace/input", archive_b64=archive)],
        timeout_seconds=123,
    )

    job = build_broker_job(
        "agent-challenge",
        request,
        namespace="platform",
        service_account_name="platform-master",
        run_id="runabcd1",
    )
    mount_secret = build_broker_mount_secret(
        "agent-challenge", request, namespace="platform", run_id="runabcd1"
    )
    assert mount_secret is not None
    network_policy = build_broker_network_policy(
        "agent-challenge", request, namespace="platform", run_id="runabcd1"
    )

    pod_template = job["spec"]["template"]
    pod_spec = pod_template["spec"]
    container = pod_spec["containers"][0]
    init_container = pod_spec["initContainers"][0]
    labels = {
        "app.kubernetes.io/name": "platform-network",
        "app.kubernetes.io/managed-by": "platform-network",
        "platform.component": "broker-job",
        "platform.challenge.slug": "agent-challenge",
        "platform.job": "job-1",
        "platform.task": "terminal-bench-hello-world",
        "platform.run": "runabcd1",
    }

    assert job["metadata"]["labels"] == labels
    assert pod_template["metadata"]["labels"] == labels
    assert job["spec"]["ttlSecondsAfterFinished"] == 300
    assert job["spec"]["backoffLimit"] == 0
    assert job["spec"]["activeDeadlineSeconds"] == 123
    assert pod_spec["serviceAccountName"] == "platform-master"
    assert pod_spec["automountServiceAccountToken"] is False
    assert pod_spec["securityContext"] == {
        "runAsNonRoot": True,
        "seccompProfile": {"type": "RuntimeDefault"},
        "fsGroup": 1000,
    }
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["runAsUser"] == 1000
    assert container["securityContext"]["runAsGroup"] == 1000
    assert init_container["securityContext"]["runAsUser"] == 1000
    assert container["resources"] == {
        "requests": {"cpu": "1.25", "memory": "640Mi"},
        "limits": {"cpu": "1.25", "memory": "640Mi"},
    }
    assert container["imagePullPolicy"] == "Never"
    archive_volume = {
        "name": "archives",
        "secret": {"secretName": mount_secret["metadata"]["name"]},
    }
    assert archive_volume in pod_spec["volumes"]
    assert archive not in repr(job)
    assert "TOKEN_SHOULD_NOT_APPEAR" not in repr(job)
    assert mount_secret["stringData"] == {"mount-0.tar.gz.b64": archive}
    assert network_policy["metadata"]["labels"]["platform.run"] == "runabcd1"
    assert network_policy["spec"]["policyTypes"] == ["Ingress", "Egress"]


def test_broker_job_maps_gpu_count_to_default_resource_limit() -> None:
    request = BrokerRunRequest(
        job_id="job-1",
        image="ghcr.io/platformnetwork/worker:1",
        command=["python", "-V"],
        limits=BrokerLimits(cpus=1, memory="512Mi", gpu_count=1),
    )

    job = build_broker_job(
        "demo",
        request,
        namespace="platform",
        service_account_name="platform-master",
    )

    resources = job["spec"]["template"]["spec"]["containers"][0]["resources"]
    assert resources["requests"] == {"cpu": "1.0", "memory": "512Mi"}
    assert resources["limits"]["cpu"] == "1.0"
    assert resources["limits"]["memory"] == "512Mi"
    assert resources["limits"]["nvidia.com/gpu"] == "1"
    assert "nvidia.com/gpu" not in resources["requests"]
    assert "gpu_device_ids" not in repr(job)


def test_broker_job_runtime_fields_include_gpu_target_pod_spec_fields() -> None:
    request = BrokerRunRequest(
        job_id="job-1",
        image="ghcr.io/platformnetwork/worker:1",
        command=["python", "-V"],
        limits=BrokerLimits(cpus=1, memory="512Mi", gpu_count=1),
    )

    job = build_broker_job(
        "demo",
        request,
        namespace="platform",
        service_account_name="platform-master",
        image_pull_secrets=("pull-secret",),
        node_selector={"accelerator": "nvidia"},
        tolerations=({"key": "gpu", "operator": "Exists"},),
        runtime_class_name="nvidia",
    )

    pod_spec = job["spec"]["template"]["spec"]
    resources = pod_spec["containers"][0]["resources"]
    assert pod_spec["imagePullSecrets"] == [{"name": "pull-secret"}]
    assert pod_spec["nodeSelector"] == {"accelerator": "nvidia"}
    assert pod_spec["tolerations"] == [{"key": "gpu", "operator": "Exists"}]
    assert pod_spec["runtimeClassName"] == "nvidia"
    assert resources["limits"]["nvidia.com/gpu"] == "1"
    assert "nvidia.com/gpu" not in resources["requests"]


def test_broker_job_maps_image_pull_policy_to_main_container_only() -> None:
    request = BrokerRunRequest(
        job_id="job-1",
        image="ghcr.io/platformnetwork/worker:1",
        image_pull_policy="IfNotPresent",
        command=["python", "-V"],
        mounts=[BrokerMount(target="/work", archive_b64=_archive_b64())],
    )

    job = build_broker_job(
        "demo",
        request,
        namespace="platform",
        service_account_name="platform-master",
    )

    pod_spec = job["spec"]["template"]["spec"]
    assert pod_spec["containers"][0]["imagePullPolicy"] == "IfNotPresent"
    assert "imagePullPolicy" not in pod_spec["initContainers"][0]


def test_broker_job_omits_gpu_resource_when_gpu_count_is_none() -> None:
    request = BrokerRunRequest(
        job_id="job-1",
        image="ghcr.io/platformnetwork/worker:1",
        command=["python", "-V"],
        limits=BrokerLimits(cpus=1, memory="512Mi"),
    )

    job = build_broker_job(
        "demo",
        request,
        namespace="platform",
        service_account_name="platform-master",
    )

    pod_spec = job["spec"]["template"]["spec"]
    resources = pod_spec["containers"][0]["resources"]
    assert resources == {
        "requests": {"cpu": "1.0", "memory": "512Mi"},
        "limits": {"cpu": "1.0", "memory": "512Mi"},
    }
    assert "imagePullSecrets" not in pod_spec
    assert "nodeSelector" not in pod_spec
    assert "tolerations" not in pod_spec
    assert "runtimeClassName" not in pod_spec
    assert "imagePullPolicy" not in pod_spec["containers"][0]


def test_broker_job_maps_gpu_count_to_custom_resource_limit() -> None:
    request = BrokerRunRequest(
        job_id="job-1",
        image="ghcr.io/platformnetwork/worker:1",
        command=["python", "-V"],
        limits=BrokerLimits(gpu_count=1),
    )

    job = build_broker_job(
        "demo",
        request,
        namespace="platform",
        service_account_name="platform-master",
        gpu_resource_name="example.com/gpu",
    )

    resources = job["spec"]["template"]["spec"]["containers"][0]["resources"]
    assert resources["limits"]["example.com/gpu"] == "1"
    assert "example.com/gpu" not in resources["requests"]
    assert "nvidia.com/gpu" not in resources["limits"]


@pytest.mark.parametrize(
    "gpu_resource_name, message",
    [
        ("", "non-empty"),
        (" kubernetes.io/gpu", "non-empty"),
        ("kubernetes.io/gpu", "kubernetes.io"),
        ("gpu", "qualified"),
        ("example.com/", "invalid Kubernetes GPU resource name"),
    ],
)
def test_broker_job_rejects_invalid_gpu_resource_names(
    gpu_resource_name: str, message: str
) -> None:
    request = BrokerRunRequest(
        job_id="job-1",
        image="ghcr.io/platformnetwork/worker:1",
        command=["python", "-V"],
        limits=BrokerLimits(gpu_count=1),
    )

    with pytest.raises(ValueError, match=message):
        build_broker_job(
            "demo",
            request,
            namespace="platform",
            service_account_name="platform-master",
            gpu_resource_name=gpu_resource_name,
        )


def test_broker_job_defensively_rejects_invalid_gpu_count() -> None:
    request = BrokerRunRequest(
        job_id="job-1",
        image="ghcr.io/platformnetwork/worker:1",
        command=["python", "-V"],
        limits=BrokerLimits().model_copy(update={"gpu_count": True}),
    )

    with pytest.raises(ValueError, match="gpu_count"):
        build_broker_job(
            "demo",
            request,
            namespace="platform",
            service_account_name="platform-master",
        )


def test_broker_mount_init_extractor_validates_archive_members(tmp_path: Path) -> None:
    mounted = BrokerRunRequest(
        job_id="job-1",
        image="ghcr.io/platformnetwork/worker:1",
        command=["python", "-V"],
        mounts=[BrokerMount(target="/work", archive_b64=_archive_b64())],
    )
    job = build_broker_job(
        "demo",
        mounted,
        namespace="platform",
        service_account_name="platform-master",
    )
    command = job["spec"]["template"]["spec"]["initContainers"][0]["command"]
    script = command[2]

    assert "getmembers()" in script
    assert "filter='data'" in script
    assert ".extractall(sys.argv[2])" not in script

    archive_path = tmp_path / "mount.tar.gz.b64"
    archive_path.write_text(_archive_b64(), encoding="ascii")
    workdir = tmp_path / "work"
    workdir.mkdir()
    good = subprocess.run(
        [sys.executable, "-c", script, str(archive_path), str(workdir)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert good.returncode == 0, good.stderr
    assert (workdir / "input.txt").read_text(encoding="utf-8") == "ok"

    archive_path.write_text(_archive_b64("../escape.txt"), encoding="ascii")
    bad = subprocess.run(
        [sys.executable, "-c", script, str(archive_path), str(workdir)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad.returncode != 0
    assert "unsafe mount archive" in bad.stderr


def test_broker_job_sanitizes_slash_containing_task_id_labels() -> None:
    request = BrokerRunRequest(
        job_id="job-1",
        task_id="terminal-bench/terminal-bench-2-1",
        image="ghcr.io/platformnetwork/worker:1",
        command=["python", "-V"],
    )

    job = build_broker_job(
        "demo",
        request,
        namespace="platform",
        service_account_name="platform-master",
    )

    labels = job["metadata"]["labels"]
    pod_labels = job["spec"]["template"]["metadata"]["labels"]
    assert labels["platform.task"] == "terminal-bench-terminal-bench-2-1"
    assert pod_labels["platform.task"] == "terminal-bench-terminal-bench-2-1"


def test_broker_job_rejects_unsupported_docker_only_limits() -> None:
    base: dict[str, Any] = {
        "job_id": "job-1",
        "image": "ghcr.io/platformnetwork/worker:1",
        "command": ["python", "-V"],
    }
    cases = [
        (BrokerLimits(pids_limit=64), "pids_limit"),
        (BrokerLimits(network="host"), "Docker-specific network modes"),
    ]
    for limits, message in cases:
        with pytest.raises(ValueError, match=message):
            build_broker_job(
                "demo",
                BrokerRunRequest(**base, limits=limits),
                namespace="platform",
                service_account_name="platform-master",
            )


def test_validate_broker_kubernetes_limits_tolerates_memory_swap() -> None:
    validate_broker_kubernetes_limits(BrokerLimits(memory_swap="8g"))

    job = build_broker_job(
        "demo",
        BrokerRunRequest(
            job_id="job-1",
            image="ghcr.io/platformnetwork/worker:1",
            command=["python", "-V"],
            limits=BrokerLimits(cpus=1, memory="512Mi", memory_swap="8g"),
        ),
        namespace="platform",
        service_account_name="platform-master",
    )

    pod_spec = job["spec"]["template"]["spec"]
    assert "8g" not in repr(pod_spec)
    assert "memory_swap" not in repr(pod_spec)
    assert pod_spec["containers"][0]["resources"]["limits"]["memory"] == "512Mi"
    swap_annotation = job["spec"]["template"]["metadata"]["annotations"][
        "platform.network/kubernetes-swap-semantics"
    ]
    assert "memory_swap is not a Kubernetes PodSpec field" in swap_annotation


def _required_managed_postgres_builder(name: str) -> Any:
    builder = getattr(kubernetes_resources, name, None)
    assert builder is not None, f"missing managed Postgres Kubernetes builder: {name}"
    return builder


def _env_by_name(env: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {item["name"]: item for item in env}


def _secret_env_ref(env: dict[str, dict[str, Any]], name: str) -> dict[str, str]:
    item = env[name]
    assert "value" not in item
    secret_key_ref = item.get("valueFrom", {}).get("secretKeyRef")
    assert secret_key_ref is not None
    return secret_key_ref


def _database_url_parts(database_url: str) -> dict[str, Any]:
    parsed = urlsplit(database_url)
    assert parsed.password
    return {
        "scheme": parsed.scheme,
        "username": parsed.username,
        "hostname": parsed.hostname,
        "port": parsed.port,
        "path": parsed.path,
    }


def _archive_b64(name: str = "input.txt") -> str:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        data = b"ok"
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return base64.b64encode(stream.getvalue()).decode("ascii")
