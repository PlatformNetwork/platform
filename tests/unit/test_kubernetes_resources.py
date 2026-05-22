from __future__ import annotations

import base64
import io
import re
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest

from platform_network.kubernetes.names import broker_job_name, challenge_name, k8s_name
from platform_network.kubernetes.resources import (
    build_broker_job,
    build_broker_mount_secret,
    build_broker_network_policy,
    build_challenge_hpa,
    build_challenge_scaled_object,
    build_challenge_secret,
    build_challenge_service,
    build_challenge_workload,
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
    with pytest.raises(ValueError, match="memory_swap"):
        build_challenge_workload(
            ChallengeSpec(
                slug="demo",
                image="ghcr.io/org/demo:1",
                resources=ChallengeResources(memory_swap=None),
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
    assert {
        "name": "mount-0",
        "mountPath": "/work",
        "readOnly": True,
    } in mounted_job["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
    assert mount_secret is not None
    assert mount_secret["stringData"]["mount-0.tar.gz.b64"] == archive


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


def test_broker_job_rejects_unsupported_docker_only_limits() -> None:
    base: dict[str, Any] = {
        "job_id": "job-1",
        "image": "ghcr.io/platformnetwork/worker:1",
        "command": ["python", "-V"],
    }
    cases = [
        (BrokerLimits(pids_limit=64), "pids_limit"),
        (BrokerLimits(memory_swap=None), "memory_swap"),
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


def _archive_b64(name: str = "input.txt") -> str:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        data = b"ok"
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return base64.b64encode(stream.getvalue()).decode("ascii")
