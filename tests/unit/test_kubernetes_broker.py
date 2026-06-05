from __future__ import annotations

import base64
import io
import tarfile
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient

from platform_network.master.kubernetes_broker import (
    KubernetesBrokerRouterService,
    KubernetesBrokerService,
    create_kubernetes_broker_app,
)
from platform_network.schemas.docker_broker import (
    BrokerCleanupRequest,
    BrokerLimits,
    BrokerListRequest,
    BrokerRunRequest,
)


class Registry:
    def get_broker_token(self, slug: str) -> str:
        return "tok" if slug == "agent" else ""


class FakeBrokerClient:
    def __init__(
        self,
        *,
        exit_code: int = 0,
        logs: str = "ok",
        wait_error: Exception | None = None,
        log_error: Exception | None = None,
        fail_apply_kind: str | None = None,
    ) -> None:
        self.exit_code = exit_code
        self.logs = logs
        self.wait_error = wait_error
        self.log_error = log_error
        self.fail_apply_kind = fail_apply_kind
        self.applied: list[dict[str, Any]] = []
        self.deleted: list[tuple[str, str | None]] = []
        self.deleted_labels: list[str] = []

    def apply(self, resource: dict[str, Any]) -> dict[str, Any]:
        self.applied.append(resource)
        if resource["kind"] == self.fail_apply_kind:
            raise RuntimeError(f"apply failed: {resource['kind']}")
        return resource

    def delete(self, resource: dict[str, Any] | str, name: str | None = None) -> None:
        kind = resource if isinstance(resource, str) else resource["kind"]
        self.deleted.append((kind, name))

    def wait_job_complete(self, name: str, *, timeout_seconds: int) -> int:
        assert name == self._job()["metadata"]["name"]
        assert timeout_seconds == 10
        if self.wait_error is not None:
            raise self.wait_error
        return self.exit_code

    def pod_logs_for_job(self, job_name: str, *, tail_lines: int = 1000) -> str:
        assert job_name == self._job()["metadata"]["name"]
        if self.log_error is not None:
            raise self.log_error
        return self.logs

    def delete_jobs_by_label(self, label_selector: str) -> None:
        self.deleted_labels.append(label_selector)

    def delete_by_label(self, kind: str, label_selector: str) -> None:
        self.deleted_labels.append(f"{kind}:{label_selector}")

    def list_jobs_by_label(self, label_selector: str) -> list[dict[str, Any]]:
        return []

    def _job(self) -> dict[str, Any]:
        return next(resource for resource in self.applied if resource["kind"] == "Job")


def test_kubernetes_broker_run_success_and_failure_logs() -> None:
    client = FakeBrokerClient(logs="stdout")
    service = KubernetesBrokerService(client=client, service_account_name="platform")

    response = service.run(
        "agent",
        _run_payload(),
    )

    assert response.returncode == 0
    assert response.stdout == "stdout"
    assert response.stderr == ""
    assert client.applied[0]["kind"] == "NetworkPolicy"
    assert client.applied[1]["kind"] == "Job"
    assert (
        client.applied[1]["spec"]["template"]["spec"]["serviceAccountName"]
        == "platform"
    )
    name = client.applied[1]["metadata"]["name"]
    assert client.deleted == [
        ("Job", name),
        ("NetworkPolicy", name),
        ("Secret", f"{name}-mounts"),
    ]

    failure_client = FakeBrokerClient(exit_code=1, logs="stderr")
    failed = KubernetesBrokerService(client=failure_client).run("agent", _run_payload())
    assert failed.stdout == ""
    assert failed.stderr == "stderr"
    assert failed.returncode == 1
    failure_name = failure_client.applied[1]["metadata"]["name"]
    assert failure_client.deleted == [
        ("Job", failure_name),
        ("NetworkPolicy", failure_name),
        ("Secret", f"{failure_name}-mounts"),
    ]


def test_kubernetes_broker_uses_configured_gpu_resource_name() -> None:
    default_client = FakeBrokerClient()
    KubernetesBrokerService(client=default_client).run(
        "agent", _run_payload(limits=BrokerLimits(gpu_count=1))
    )
    default_limits = _main_container_limits(default_client)
    assert default_limits["nvidia.com/gpu"] == "1"

    custom_client = FakeBrokerClient()
    KubernetesBrokerService(
        client=custom_client, gpu_resource_name="example.com/gpu"
    ).run("agent", _run_payload(limits=BrokerLimits(gpu_count=1)))
    custom_limits = _main_container_limits(custom_client)
    assert custom_limits["example.com/gpu"] == "1"
    assert "nvidia.com/gpu" not in custom_limits


def test_kubernetes_broker_run_applies_runtime_fields_to_job_pod_spec() -> None:
    client = FakeBrokerClient()
    service = KubernetesBrokerService(
        client=client,
        image_pull_secrets=("pull-secret",),
        node_selector={"accelerator": "nvidia"},
        tolerations=({"key": "gpu", "operator": "Exists"},),
        runtime_class_name="nvidia",
    )

    service.run("agent", _run_payload(limits=BrokerLimits(gpu_count=1)))

    pod_spec = client._job()["spec"]["template"]["spec"]
    assert pod_spec["imagePullSecrets"] == [{"name": "pull-secret"}]
    assert pod_spec["nodeSelector"] == {"accelerator": "nvidia"}
    assert pod_spec["tolerations"] == [{"key": "gpu", "operator": "Exists"}]
    assert pod_spec["runtimeClassName"] == "nvidia"
    assert pod_spec["containers"][0]["resources"]["limits"]["nvidia.com/gpu"] == "1"


def test_kubernetes_broker_run_timeout_and_wait_error_cleanup() -> None:
    timeout_client = FakeBrokerClient(exit_code=124, logs="timeout")
    timed_out = KubernetesBrokerService(client=timeout_client).run(
        "agent", _run_payload()
    )

    assert timed_out.returncode == 124
    assert timed_out.timed_out is True
    timeout_name = timeout_client.applied[1]["metadata"]["name"]
    assert timeout_client.deleted == [
        ("Job", timeout_name),
        ("NetworkPolicy", timeout_name),
        ("Secret", f"{timeout_name}-mounts"),
    ]

    error_client = FakeBrokerClient(wait_error=RuntimeError("boom"))
    with pytest.raises(RuntimeError, match="boom"):
        KubernetesBrokerService(client=error_client).run("agent", _run_payload())
    error_name = error_client.applied[1]["metadata"]["name"]
    assert error_client.deleted == [
        ("Job", error_name),
        ("NetworkPolicy", error_name),
        ("Secret", f"{error_name}-mounts"),
    ]


def test_kubernetes_broker_run_apply_and_log_error_cleanup() -> None:
    apply_client = FakeBrokerClient(fail_apply_kind="Job")
    with pytest.raises(RuntimeError, match="apply failed: Job"):
        KubernetesBrokerService(client=apply_client).run("agent", _run_payload())
    apply_name = apply_client.applied[1]["metadata"]["name"]
    assert apply_client.deleted == [
        ("Job", apply_name),
        ("NetworkPolicy", apply_name),
        ("Secret", f"{apply_name}-mounts"),
    ]

    log_client = FakeBrokerClient(log_error=RuntimeError("logs failed"))
    with pytest.raises(RuntimeError, match="logs failed"):
        KubernetesBrokerService(client=log_client).run("agent", _run_payload())
    log_name = log_client.applied[1]["metadata"]["name"]
    assert log_client.deleted == [
        ("Job", log_name),
        ("NetworkPolicy", log_name),
        ("Secret", f"{log_name}-mounts"),
    ]


def test_kubernetes_broker_from_settings_threads_gpu_resource_name_runtime_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_client: dict[str, Any] = {}

    class CapturingClient:
        def __init__(self, **kwargs: Any) -> None:
            captured_client.update(kwargs)

    monkeypatch.setattr(
        "platform_network.master.kubernetes_broker.KubernetesClient", CapturingClient
    )
    node_selector = {"accelerator": "nvidia"}
    toleration = {"key": "gpu", "operator": "Exists"}
    settings = SimpleNamespace(
        docker=SimpleNamespace(broker_allowed_images=["ghcr.io/platformnetwork/"]),
        kubernetes=SimpleNamespace(
            namespace="platform-gpu",
            kubeconfig="/tmp/kubeconfig",
            in_cluster=False,
            service_account="broker-sa",
            gpu_resource_name="example.com/gpu",
            image_pull_secrets=["pull-secret"],
            node_selector=node_selector,
            tolerations=[toleration],
            runtime_class_name="nvidia",
        ),
    )

    service = KubernetesBrokerService.from_settings(settings)
    node_selector["mutated"] = "ignored"
    toleration["value"] = "ignored"

    assert captured_client == {
        "namespace": "platform-gpu",
        "kubeconfig": "/tmp/kubeconfig",
        "in_cluster": False,
    }
    assert service.namespace == "platform-gpu"
    assert service.service_account_name == "broker-sa"
    assert service.allowed_images == ("ghcr.io/platformnetwork/",)
    assert service.gpu_resource_name == "example.com/gpu"
    assert service.image_pull_secrets == ("pull-secret",)
    assert service.node_selector == {"accelerator": "nvidia"}
    assert service.tolerations == ({"key": "gpu", "operator": "Exists"},)
    assert service.runtime_class_name == "nvidia"


def test_kubernetes_broker_app_auth_and_mount_rejection() -> None:
    app = create_kubernetes_broker_app(
        registry=Registry(),
        service=KubernetesBrokerService(client=FakeBrokerClient()),
    )
    http = TestClient(app)

    missing_slug = http.post("/v1/docker/run", json=_run_json())
    assert missing_slug.status_code == 400

    unauthorized = http.post(
        "/v1/docker/run",
        headers={"authorization": "Bearer tok", "x-platform-challenge-slug": "other"},
        json=_run_json(),
    )
    assert unauthorized.status_code == 401

    wrong_token = http.post(
        "/v1/docker/run",
        headers={"authorization": "Bearer wrong", "x-platform-challenge-slug": "agent"},
        json=_run_json(),
    )
    assert wrong_token.status_code == 401

    rejected_mount = http.post(
        "/v1/docker/run",
        headers={"authorization": "Bearer tok", "x-platform-challenge-slug": "agent"},
        json=_run_json()
        | {"mounts": [{"target": "/x", "archive_b64": "YXJjaGl2ZQ=="}]},
    )
    assert rejected_mount.status_code == 400
    assert "invalid mount archive" in rejected_mount.text

    rejected_unsafe_archive = http.post(
        "/v1/docker/run",
        headers={"authorization": "Bearer tok", "x-platform-challenge-slug": "agent"},
        json=_run_json()
        | {"mounts": [{"target": "/x", "archive_b64": _archive_member("/abs")}]},
    )
    assert rejected_unsafe_archive.status_code == 400
    assert "unsafe mount archive" in rejected_unsafe_archive.text

    rejected_image = http.post(
        "/v1/docker/run",
        headers={"authorization": "Bearer tok", "x-platform-challenge-slug": "agent"},
        json=_run_json() | {"image": "docker.io/library/python:3.12"},
    )
    assert rejected_image.status_code == 400
    assert "Docker image is not allowed" in rejected_image.text

    rejected_image_syntax = http.post(
        "/v1/docker/run",
        headers={"authorization": "Bearer tok", "x-platform-challenge-slug": "agent"},
        json=_run_json() | {"image": "ghcr.io/platformnetwork/bad image"},
    )
    assert rejected_image_syntax.status_code == 400
    assert "unsafe Docker image reference" in rejected_image_syntax.text

    rejected_pull_policy = http.post(
        "/v1/docker/run",
        headers={"authorization": "Bearer tok", "x-platform-challenge-slug": "agent"},
        json=_run_json() | {"image_pull_policy": "Missing"},
    )
    assert rejected_pull_policy.status_code == 422

    rejected_source = http.post(
        "/v1/docker/run",
        headers={"authorization": "Bearer tok", "x-platform-challenge-slug": "agent"},
        json=_run_json()
        | {
            "mounts": [
                {
                    "target": "/x",
                    "source_type": "file",
                    "source_name": "../escape.txt",
                    "archive_b64": _archive_member("input.txt"),
                }
            ]
        },
    )
    assert rejected_source.status_code == 400
    assert "unsafe mount source" in rejected_source.text


def test_kubernetes_broker_app_cleanup_and_list_require_auth() -> None:
    app = create_kubernetes_broker_app(
        registry=Registry(),
        service=KubernetesBrokerService(client=FakeBrokerClient()),
    )
    http = TestClient(app)

    cleanup_unauthorized = http.post(
        "/v1/docker/cleanup",
        headers={"authorization": "Bearer wrong", "x-platform-challenge-slug": "agent"},
        json={"job_id": "job-1"},
    )
    assert cleanup_unauthorized.status_code == 401

    cleanup = http.post(
        "/v1/docker/cleanup",
        headers={"authorization": "Bearer tok", "x-platform-challenge-slug": "agent"},
        json={"job_id": "job-1"},
    )
    assert cleanup.status_code == 200

    listed = http.post(
        "/v1/docker/list",
        headers={"authorization": "Bearer tok", "x-platform-challenge-slug": "agent"},
        json={"job_id": "job-1"},
    )
    assert listed.status_code == 200
    assert listed.json() == {"containers": []}

    list_unauthorized = http.post(
        "/v1/docker/list",
        headers={"authorization": "Bearer tok", "x-platform-challenge-slug": "other"},
        json={"job_id": "job-1"},
    )
    assert list_unauthorized.status_code == 401


def test_kubernetes_broker_app_router_awaits_async_challenge_registry() -> None:
    class AsyncRegistry(Registry):
        async def get(self, slug: str) -> SimpleNamespace:
            assert slug == "agent"
            return SimpleNamespace(resources={})

    broker_client = FakeBrokerClient(exit_code=1, logs="stderr")
    router = KubernetesBrokerRouterService(
        default_service=KubernetesBrokerService(client=broker_client),
        challenge_registry=AsyncRegistry(),
    )
    http = TestClient(
        create_kubernetes_broker_app(registry=AsyncRegistry(), service=router)
    )
    headers = {"authorization": "Bearer tok", "x-platform-challenge-slug": "agent"}

    run = http.post("/v1/docker/run", headers=headers, json=_run_json())

    assert run.status_code == 200
    assert run.json()["returncode"] == 1
    assert run.json()["stderr"] == "stderr"
    cleanup = http.post("/v1/docker/cleanup", headers=headers, json={"job_id": "job-1"})
    assert cleanup.status_code == 200
    listed = http.post("/v1/docker/list", headers=headers, json={"job_id": "job-1"})
    assert listed.status_code == 200
    assert listed.json() == {"containers": []}


def test_broker_limits_gpu_count_schema_contract() -> None:
    assert BrokerLimits().gpu_count is None
    assert BrokerLimits(gpu_count=1).model_dump(mode="json")["gpu_count"] == 1

    invalid_gpu_counts: list[Any] = [0, -1, True, "1", 1.5]
    for invalid_gpu_count in invalid_gpu_counts:
        with pytest.raises(Exception, match="gpu_count"):
            BrokerLimits(gpu_count=invalid_gpu_count)


def test_broker_run_request_without_gpu_fields_remains_valid() -> None:
    request = BrokerRunRequest.model_validate(_run_json())

    assert request.limits.gpu_count is None
    assert request.image_pull_policy is None


def test_broker_run_request_accepts_only_kubernetes_image_pull_policies() -> None:
    request = BrokerRunRequest.model_validate(
        _run_json() | {"image_pull_policy": "IfNotPresent"}
    )
    assert request.image_pull_policy == "IfNotPresent"

    with pytest.raises(Exception, match="image_pull_policy"):
        BrokerRunRequest.model_validate(_run_json() | {"image_pull_policy": "Missing"})


def test_kubernetes_broker_rejects_unsupported_docker_only_limits() -> None:
    service = KubernetesBrokerService(client=FakeBrokerClient())
    cases = [
        (BrokerLimits(pids_limit=96), "pids_limit"),
        (BrokerLimits(network="platform_challenges"), "Docker-specific network modes"),
    ]
    for limits, message in cases:
        with pytest.raises(Exception) as error:
            service.run(
                "agent",
                BrokerRunRequest(
                    job_id="job-1",
                    image="ghcr.io/platformnetwork/worker:1",
                    command=["python", "-V"],
                    limits=limits,
                    timeout_seconds=10,
                ),
            )
        assert message in str(error.value)


def test_kubernetes_broker_cleanup_deletes_job() -> None:
    fake = FakeBrokerClient()
    service = KubernetesBrokerService(client=fake)

    response = service.cleanup("agent", BrokerCleanupRequest(job_id="job-1"))

    assert response.status == "ok"
    assert fake.deleted == [("Job", "broker-agent-job-1")]
    assert fake.deleted_labels == [
        "platform.challenge.slug=agent,platform.job=job-1",
        "NetworkPolicy:platform.challenge.slug=agent,platform.job=job-1",
        "Secret:platform.challenge.slug=agent,platform.job=job-1",
    ]


def test_kubernetes_broker_list_containers_maps_jobs() -> None:
    class ListingClient(FakeBrokerClient):
        def list_jobs_by_label(self, label_selector: str) -> list[dict[str, Any]]:
            assert label_selector == "platform.challenge.slug=agent,platform.job=job-1"
            return [
                {
                    "metadata": {
                        "uid": "uid-1",
                        "name": "broker-agent-job-1",
                        "creationTimestamp": "now",
                        "labels": {
                            "platform.job": "job-1",
                            "platform.task": "task-1",
                            "other": "hidden",
                        },
                    },
                    "status": {"failed": 1},
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {"image": "ghcr.io/platformnetwork/worker:1"}
                                ]
                            }
                        }
                    },
                }
            ]

    response = KubernetesBrokerService(client=ListingClient()).list_containers(
        "agent", BrokerListRequest(job_id="job-1")
    )

    assert response.containers[0].container_name == "broker-agent-job-1"
    assert response.containers[0].image == "ghcr.io/platformnetwork/worker:1"
    assert response.containers[0].status == "failed"
    assert response.containers[0].labels == {
        "platform.job": "job-1",
        "platform.task": "task-1",
    }


def test_kubernetes_broker_router_uses_explicit_and_gpu_targets() -> None:
    default = StubBrokerService("default")
    gpu = StubBrokerService("gpu-a")
    registry = SimpleNamespace(
        get=lambda slug: SimpleNamespace(
            resources={
                "explicit": {"gpu_server": "gpu-a", "gpu_count": "1"},
                "automatic": {"gpu_count": "1"},
                "local": {},
            }[slug]
        )
    )
    router = KubernetesBrokerRouterService(
        default_service=default,
        target_services={"gpu-a": gpu},
        target_capacities={"gpu-a": 2},
        challenge_registry=registry,
    )

    assert router.run("explicit", _run_payload()).container_name == "gpu-a"
    assert router.run("automatic", _run_payload()).container_name == "gpu-a"
    assert router.run("local", _run_payload()).container_name == "default"


def test_platform_sdk_broker_router_preserves_generic_payload_for_targets() -> None:
    default = CapturingBrokerService("default")
    gpu = CapturingBrokerService("gpu-a")
    registry = SimpleNamespace(
        get=lambda slug: SimpleNamespace(
            resources={
                "explicit": {"gpu_server": "gpu-a", "gpu_count": "1"},
                "local": {},
            }[slug]
        )
    )
    router = KubernetesBrokerRouterService(
        default_service=default,
        target_services={"gpu-a": gpu},
        target_capacities={"gpu-a": 2},
        challenge_registry=registry,
    )
    request = BrokerRunRequest(
        job_id="job-1",
        task_id="terminal-bench-1",
        image="ghcr.io/platformnetwork/controlled-runner:1",
        image_pull_policy="IfNotPresent",
        command=["python", "-m", "runner"],
        workdir="/workspace",
        env={"PLATFORM_TOKEN_FILE": "/var/run/secrets/platform/token"},
        labels={"platform.job": "job-1", "custom.label": "survives"},
        limits=BrokerLimits(cpus=1.5, memory="768Mi", gpu_count=1),
        timeout_seconds=321,
    )

    explicit_response = router.run("explicit", request)
    local_response = router.run("local", request)

    assert explicit_response.container_name == "gpu-a"
    assert local_response.container_name == "default"
    assert gpu.calls == [("run", "explicit", request)]
    assert default.calls == [("run", "local", request)]
    forwarded = gpu.calls[0][2].model_dump(mode="json")
    assert forwarded["image"] == "ghcr.io/platformnetwork/controlled-runner:1"
    assert forwarded["image_pull_policy"] == "IfNotPresent"
    assert forwarded["command"] == ["python", "-m", "runner"]
    assert forwarded["env"] == {
        "PLATFORM_TOKEN_FILE": "/var/run/secrets/platform/token"
    }
    assert forwarded["labels"] == {
        "platform.job": "job-1",
        "custom.label": "survives",
    }
    assert forwarded["limits"]["gpu_count"] == 1
    assert "agent_challenge" not in forwarded
    assert "provider_ref" not in forwarded
    assert "miner_env" not in forwarded


def test_kubernetes_broker_router_uses_persisted_assignment() -> None:
    default = StubBrokerService("default")
    gpu = StubBrokerService("gpu-a")
    registry = SimpleNamespace(get=lambda slug: SimpleNamespace(resources={}))
    target_registry = DynamicTargetRegistry()
    target_registry.targets["gpu-a"] = SimpleNamespace(
        id="gpu-a", enabled=True, draining=False, gpu_count=2
    )
    target_registry.assign_challenge("assigned", "gpu-a", 1)
    router = DynamicBrokerRouter(
        default_service=default,
        challenge_registry=registry,
        settings=SimpleNamespace(),
        target_registry=target_registry,
    )
    router.services["gpu-a"] = gpu

    assert router.run("assigned", _run_payload()).container_name == "gpu-a"


def test_kubernetes_broker_router_reassigns_unavailable_targets() -> None:
    registry = SimpleNamespace(
        get=lambda slug: SimpleNamespace(resources={"gpu_count": "1"})
    )
    target_registry = DynamicTargetRegistry()
    target_registry.targets["gpu-a"] = SimpleNamespace(
        id="gpu-a", enabled=False, draining=False, gpu_count=2
    )
    target_registry.targets["gpu-b"] = SimpleNamespace(
        id="gpu-b", enabled=True, draining=False, gpu_count=2
    )
    target_registry.assign_challenge("demo", "gpu-a", 1)
    router = DynamicBrokerRouter(
        default_service=StubBrokerService("default"),
        challenge_registry=registry,
        settings=SimpleNamespace(),
        target_registry=target_registry,
    )
    router.services["gpu-a"] = StubBrokerService("gpu-a")
    router.services["gpu-b"] = StubBrokerService("gpu-b")

    assert router.run("demo", _run_payload()).container_name == "gpu-b"
    assert target_registry.assignments == {"demo": "gpu-b"}


def test_kubernetes_broker_router_rejects_no_valid_target() -> None:
    registry = SimpleNamespace(
        get=lambda slug: SimpleNamespace(resources={"gpu_count": "2"})
    )
    target_registry = DynamicTargetRegistry()
    target_registry.targets["gpu-a"] = SimpleNamespace(
        id="gpu-a", enabled=True, draining=False, gpu_count=1
    )
    router = DynamicBrokerRouter(
        default_service=StubBrokerService("default"),
        challenge_registry=registry,
        settings=SimpleNamespace(),
        target_registry=target_registry,
    )
    router.services["gpu-a"] = StubBrokerService("gpu-a")

    with pytest.raises(Exception) as error:
        router.run("demo", _run_payload())
    assert "No valid Kubernetes target" in str(error.value)


def test_kubernetes_broker_router_builds_direct_kubeconfig_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_client: dict[str, Any] = {}
    captured_service: dict[str, Any] = {}

    class CapturingClient:
        def __init__(self, **kwargs: Any) -> None:
            captured_client.update(kwargs)

    class CapturingBrokerService(StubBrokerService):
        def __init__(self, **kwargs: Any) -> None:
            captured_service.update(kwargs)
            super().__init__("direct-a")

    registry = SimpleNamespace(
        get=lambda slug: SimpleNamespace(
            resources={"gpu_server": "direct-a", "gpu_count": "1"}
        )
    )
    target_registry = DynamicTargetRegistry()
    target_registry.targets["direct-a"] = SimpleNamespace(
        id="direct-a",
        mode="direct",
        enabled=True,
        draining=False,
        gpu_count=1,
        namespace="platform-gpu",
        service_account="target-sa",
        kubeconfig_file="/tmp/direct-a.kubeconfig",
    )
    monkeypatch.setattr(
        "platform_network.master.kubernetes_broker.KubernetesClient", CapturingClient
    )
    monkeypatch.setattr(
        "platform_network.master.kubernetes_broker.KubernetesBrokerService",
        CapturingBrokerService,
    )
    router = KubernetesBrokerRouterService(
        default_service=StubBrokerService("default"),
        challenge_registry=registry,
        settings=_settings(),
        target_registry=target_registry,
    )

    assert router.run("demo", _run_payload()).container_name == "direct-a"
    assert captured_client == {
        "namespace": "platform-gpu",
        "kubeconfig": "/tmp/direct-a.kubeconfig",
        "in_cluster": False,
    }
    assert captured_service["namespace"] == "platform-gpu"
    assert captured_service["service_account_name"] == "target-sa"
    assert captured_service["allowed_images"] == ("ghcr.io/platformnetwork/",)
    assert captured_service["gpu_resource_name"] == "defaults.example.com/gpu"
    assert captured_service["image_pull_secrets"] == ("default-pull-secret",)
    assert captured_service["node_selector"] == {
        "global": "true",
        "default": "true",
    }
    assert captured_service["tolerations"] == (
        {"key": "default-gpu", "operator": "Exists"},
    )
    assert captured_service["runtime_class_name"] == "default-runtime"


def test_kubernetes_broker_router_direct_kubeconfig_service_runtime_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_service: dict[str, Any] = {}

    class CapturingClient:
        def __init__(self, **kwargs: Any) -> None:
            pass

    class CapturingBrokerService(StubBrokerService):
        def __init__(self, **kwargs: Any) -> None:
            captured_service.update(kwargs)
            super().__init__("direct-a")

    registry = SimpleNamespace(
        get=lambda slug: SimpleNamespace(
            resources={"gpu_server": "direct-a", "gpu_count": "1"}
        )
    )
    target_registry = DynamicTargetRegistry()
    target_registry.targets["direct-a"] = SimpleNamespace(
        id="direct-a",
        mode="direct",
        enabled=True,
        draining=False,
        gpu_count=1,
        namespace="platform-gpu",
        service_account=None,
        kubeconfig_file="/tmp/direct-a.kubeconfig",
        node_selector={"target": "true", "default": "target"},
        tolerations=[{"key": "target-gpu", "operator": "Exists"}],
        runtime_class_name="target-runtime",
    )
    monkeypatch.setattr(
        "platform_network.master.kubernetes_broker.KubernetesClient", CapturingClient
    )
    monkeypatch.setattr(
        "platform_network.master.kubernetes_broker.KubernetesBrokerService",
        CapturingBrokerService,
    )
    router = KubernetesBrokerRouterService(
        default_service=StubBrokerService("default"),
        challenge_registry=registry,
        settings=_settings(),
        target_registry=target_registry,
    )

    assert router.run("demo", _run_payload()).container_name == "direct-a"
    assert captured_service["service_account_name"] == "default-sa"
    assert captured_service["gpu_resource_name"] == "defaults.example.com/gpu"
    assert captured_service["image_pull_secrets"] == ("default-pull-secret",)
    assert captured_service["node_selector"] == {
        "global": "true",
        "default": "target",
        "target": "true",
    }
    assert captured_service["tolerations"] == (
        {"key": "target-gpu", "operator": "Exists"},
    )
    assert captured_service["runtime_class_name"] == "target-runtime"


def test_kubernetes_broker_router_builds_agent_broker_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class CapturingAgentClient:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

        def run_broker(self, challenge_slug: str, request: BrokerRunRequest):
            return type(
                "Response",
                (),
                {
                    "container_name": f"agent-{challenge_slug}",
                    "stdout": "",
                    "stderr": "",
                    "returncode": 0,
                    "timed_out": False,
                },
            )()

    registry = SimpleNamespace(
        get=lambda slug: SimpleNamespace(
            resources={"gpu_server": "agent-a", "gpu_count": "1"}
        )
    )
    target_registry = DynamicTargetRegistry()
    target_registry.targets["agent-a"] = SimpleNamespace(
        id="agent-a",
        mode="agent",
        enabled=True,
        draining=False,
        gpu_count=1,
        agent_url="https://agent-a",
        timeout_seconds=12.0,
        verify_tls=True,
    )
    target_registry.agent_tokens["agent-a"] = "test-agent-credential"
    monkeypatch.setattr(
        "platform_network.kubernetes.agent.KubernetesAgentClient", CapturingAgentClient
    )
    router = KubernetesBrokerRouterService(
        default_service=StubBrokerService("default"),
        challenge_registry=registry,
        settings=_settings(),
        target_registry=target_registry,
    )

    assert router.run("demo", _run_payload()).container_name == "agent-demo"
    assert captured == {
        "target_id": "agent-a",
        "base_url": "https://agent-a",
        "token": "test-agent-credential",
        "timeout_seconds": 12.0,
        "verify_tls": True,
        "docker_broker_url": "http://broker:8082",
    }


class DynamicTargetRegistry:
    def __init__(self) -> None:
        self.targets: dict[str, Any] = {}
        self.assignments: dict[str, str] = {}
        self.metadata: dict[str, dict[str, object]] = {}
        self.health_status: dict[str, str] = {}
        self.agent_tokens: dict[str, str] = {}

    def list(self) -> list[Any]:
        return list(self.targets.values())

    def get(self, target_id: str) -> Any:
        return self.targets[target_id]

    def get_assignment(self, slug: str) -> str | None:
        return self.assignments.get(slug)

    def assign_challenge(
        self, slug: str, target_id: str, gpu_count: int | None = None
    ) -> None:
        self.assignments[slug] = target_id
        self.metadata[slug] = {"target_id": target_id, "gpu_count": gpu_count or 0}

    def clear_assignment(self, slug: str) -> None:
        self.assignments.pop(slug, None)
        self.metadata.pop(slug, None)

    def get_assignment_metadata(self, slug: str) -> dict[str, object] | None:
        return self.metadata.get(slug)

    def health(self, target_id: str) -> SimpleNamespace:
        return SimpleNamespace(status=self.health_status.get(target_id, "ok"))

    def get_agent_token(self, target_id: str) -> str:
        return self.agent_tokens.get(target_id, "")


class DynamicBrokerRouter(KubernetesBrokerRouterService):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.services: dict[str, Any] = {}

    def _build_targets(self) -> tuple[dict[str, Any], dict[str, int]]:
        target_registry = cast(DynamicTargetRegistry, self.target_registry)
        return self.services, {
            target_id: target.gpu_count
            for target_id, target in target_registry.targets.items()
            if target.enabled and not target.draining
        }

    def _build_service(self, target: Any) -> Any:
        return self.services[target.id]


class StubBrokerService:
    def __init__(self, name: str) -> None:
        self.name = name

    def run(self, challenge_slug: str, request: BrokerRunRequest):
        return type(
            "Response",
            (),
            {
                "container_name": self.name,
                "stdout": "",
                "stderr": "",
                "returncode": 0,
                "timed_out": False,
            },
        )()

    def cleanup(self, challenge_slug: str, request: BrokerCleanupRequest):
        return type("Response", (), {"status": "ok"})()

    def list_containers(self, challenge_slug: str, request):
        return type("Response", (), {"containers": []})()


class CapturingBrokerService(StubBrokerService):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.calls: list[tuple[str, str, BrokerRunRequest]] = []

    def run(self, challenge_slug: str, request: BrokerRunRequest):
        self.calls.append(("run", challenge_slug, request))
        return super().run(challenge_slug, request)


def _main_container_limits(client: FakeBrokerClient) -> dict[str, Any]:
    return client._job()["spec"]["template"]["spec"]["containers"][0]["resources"][
        "limits"
    ]


def _run_payload(*, limits: BrokerLimits | None = None) -> BrokerRunRequest:
    payload = BrokerRunRequest.model_validate(_run_json())
    if limits is not None:
        payload = payload.model_copy(update={"limits": limits})
    return payload


def _run_json() -> dict[str, object]:
    return {
        "job_id": "job-1",
        "image": "ghcr.io/platformnetwork/worker:1",
        "command": ["python", "-V"],
        "timeout_seconds": 10,
    }


def _archive_member(name: str, data: bytes = b"ok") -> str:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return base64.b64encode(stream.getvalue()).decode("ascii")


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        docker=SimpleNamespace(
            broker_url="http://broker:8082",
            broker_allowed_images=["ghcr.io/platformnetwork/"],
        ),
        kubernetes=SimpleNamespace(
            service_account="default-sa",
            gpu_resource_name="global.example.com/gpu",
            image_pull_secrets=["global-pull-secret"],
            node_selector={"global": "true"},
            tolerations=[{"key": "global-gpu", "operator": "Exists"}],
            runtime_class_name="global-runtime",
            target_defaults=SimpleNamespace(
                gpu_resource_name="defaults.example.com/gpu",
                image_pull_secrets=["default-pull-secret"],
                node_selector={"default": "true"},
                tolerations=[{"key": "default-gpu", "operator": "Exists"}],
                runtime_class_name="default-runtime",
            ),
        ),
    )
