from __future__ import annotations

import base64
import io
import re
import tarfile

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
    assert container["resources"]["limits"]["nvidia.com/gpu"] == "1"
    assert env["CHALLENGE_DOCKER_BACKEND"] == "broker"
    assert env["CHALLENGE_DOCKER_BROKER_TOKEN_FILE"] == (
        f"{DEFAULT_SECRET_MOUNT_DIR}/docker_broker_token"
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


def _archive_b64() -> str:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        data = b"ok"
        info = tarfile.TarInfo("input.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return base64.b64encode(stream.getvalue()).decode("ascii")
