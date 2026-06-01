from __future__ import annotations

import sys
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast

import pytest

from platform_network.kubernetes.client import KubernetesClient


class FakeCore:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    def connect_get_namespaced_service_proxy_with_path(
        self, *, name: str, namespace: str, path: str
    ) -> object:
        self.calls.append({"name": name, "namespace": namespace, "path": path})
        return self.response


def _client(response: object) -> KubernetesClient:
    client = KubernetesClient.__new__(KubernetesClient)
    client.namespace = "platform"
    client._core = FakeCore(response)
    return client


def test_service_json_parses_json_proxy_response() -> None:
    client = _client('{"status":"ok"}')

    assert client.service_json("challenge-demo", "health", port=8000) == {
        "status": "ok"
    }
    assert client._core.calls == [
        {
            "name": "challenge-demo:8000",
            "namespace": "platform",
            "path": "health",
        }
    ]


def test_service_json_parses_python_literal_proxy_response() -> None:
    client = _client("{'status': 'ok', 'capabilities': ['get_weights']}")

    assert client.service_json("challenge-demo", "/version", port=8000) == {
        "status": "ok",
        "capabilities": ["get_weights"],
    }


def test_service_json_rejects_non_object_proxy_response() -> None:
    client = _client('["not", "an", "object"]')

    with pytest.raises(ValueError, match="returned non-object"):
        client.service_json("challenge-demo", "health", port=8000)


def test_incluster_client_sets_authorization_bearer_token(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_path = tmp_path / "token"
    token_path.write_text("token-value\n", encoding="utf-8")
    created: dict[str, object] = {}

    class FakeConfiguration:
        def __init__(self) -> None:
            self.api_key: dict[str, str] = {}
            self.api_key_prefix: dict[str, str] = {}

        @classmethod
        def get_default_copy(cls):
            return cls()

    class FakeApiClient:
        def __init__(self, configuration=None) -> None:
            created["configuration"] = configuration

    fake_client = SimpleNamespace(
        ApiClient=FakeApiClient,
        Configuration=FakeConfiguration,
        CoreV1Api=lambda api_client: None,
        BatchV1Api=lambda api_client: None,
    )
    fake_config = SimpleNamespace(load_incluster_config=lambda: None)
    fake_dynamic = SimpleNamespace(DynamicClient=lambda api_client: None)

    monkeypatch.setitem(
        sys.modules,
        "kubernetes",
        SimpleNamespace(
            client=fake_client,
            config=fake_config,
            dynamic=fake_dynamic,
        ),
    )
    monkeypatch.setattr(
        "platform_network.kubernetes.client.Path",
        lambda _path: token_path,
    )

    KubernetesClient(namespace="platform", in_cluster=True)

    configuration = cast(FakeConfiguration, created["configuration"])
    assert configuration.api_key["authorization"] == "token-value"
    assert configuration.api_key_prefix["authorization"] == "Bearer"


def test_patch_workload_image_uses_strategic_merge_patch() -> None:
    calls: list[dict[str, object]] = []
    image = "ghcr.io/platformnetwork/demo:latest@sha256:" + "a" * 64

    class FakeApi:
        def patch(self, **kwargs: object) -> None:
            calls.append(kwargs)

    client = KubernetesClient.__new__(KubernetesClient)
    client.namespace = "platform"
    client._api_by_kind = lambda kind: FakeApi()  # type: ignore[method-assign]

    client.patch_workload_image(
        kind="StatefulSet",
        name="challenge-demo",
        container="challenge",
        image=image,
    )

    assert calls == [
        {
            "body": {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "challenge",
                                    "image": image,
                                }
                            ]
                        }
                    }
                }
            },
            "namespace": "platform",
            "name": "challenge-demo",
            "content_type": "application/strategic-merge-patch+json",
        }
    ]


def test_patch_statefulset_image_deletes_only_pods_on_stale_image() -> None:
    calls: list[dict[str, object]] = []
    deleted: list[dict[str, object]] = []
    old_image = "ghcr.io/platformnetwork/demo:latest@sha256:" + "a" * 64
    new_image = "ghcr.io/platformnetwork/demo:latest@sha256:" + "b" * 64

    class FakeApi:
        def patch(self, **kwargs: object) -> None:
            calls.append(kwargs)

    class FakeCore:
        def list_namespaced_pod(self, **kwargs: object) -> object:
            calls.append({"list_pods": kwargs})
            return SimpleNamespace(
                items=[
                    SimpleNamespace(
                        metadata=SimpleNamespace(name="challenge-demo-0"),
                        spec=SimpleNamespace(
                            containers=[
                                SimpleNamespace(name="challenge", image=old_image)
                            ]
                        ),
                    ),
                    SimpleNamespace(
                        metadata=SimpleNamespace(name="challenge-demo-1"),
                        spec=SimpleNamespace(
                            containers=[
                                SimpleNamespace(name="challenge", image=new_image)
                            ]
                        ),
                    ),
                ]
            )

        def delete_namespaced_pod(self, **kwargs: object) -> None:
            deleted.append(kwargs)

    client = KubernetesClient.__new__(KubernetesClient)
    client.namespace = "platform"
    client._core = FakeCore()
    client._api_by_kind = lambda kind: FakeApi()  # type: ignore[method-assign]
    client.get = lambda kind, name: {  # type: ignore[method-assign]
        "spec": {
            "selector": {
                "matchLabels": {"app.kubernetes.io/instance": "challenge-demo"}
            }
        }
    }

    client.patch_workload_image(
        kind="StatefulSet",
        name="challenge-demo",
        container="challenge",
        image=new_image,
    )

    assert calls[0] == {
        "body": {
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "challenge",
                                "image": new_image,
                            }
                        ]
                    }
                }
            }
        },
        "namespace": "platform",
        "name": "challenge-demo",
        "content_type": "application/strategic-merge-patch+json",
    }
    assert calls[1] == {
        "list_pods": {
            "namespace": "platform",
            "label_selector": "app.kubernetes.io/instance=challenge-demo",
        }
    }
    assert deleted == [
        {
            "name": "challenge-demo-0",
            "namespace": "platform",
            "propagation_policy": "Background",
        }
    ]


def test_patch_deployment_image_does_not_delete_pods() -> None:
    calls: list[dict[str, object]] = []

    class FakeApi:
        def patch(self, **kwargs: object) -> None:
            calls.append(kwargs)

    class FakeCore:
        def delete_namespaced_pod(self, **kwargs: object) -> None:
            raise AssertionError("Deployment image patch must not delete pods")

    client = KubernetesClient.__new__(KubernetesClient)
    client.namespace = "platform"
    client._core = FakeCore()
    client._api_by_kind = lambda kind: FakeApi()  # type: ignore[method-assign]

    client.patch_workload_image(
        kind="Deployment",
        name="challenge-demo",
        container="challenge",
        image="ghcr.io/platformnetwork/demo:latest@sha256:" + "b" * 64,
    )

    assert len(calls) == 1


def _logs_client(core: object) -> KubernetesClient:
    client = KubernetesClient.__new__(KubernetesClient)
    client.namespace = "platform"
    client._core = core
    return client


class _LogResp:
    def __init__(self, text: str) -> None:
        self.data = text.encode("utf-8")


def test_pod_logs_for_job_selects_succeeded_pod_and_retries_empty_read() -> None:
    running = SimpleNamespace(
        metadata=SimpleNamespace(name="job-xyz-running"),
        status=SimpleNamespace(
            phase="Running", start_time=datetime(2020, 1, 3, tzinfo=UTC)
        ),
    )
    succeeded = SimpleNamespace(
        metadata=SimpleNamespace(name="job-xyz-done"),
        status=SimpleNamespace(
            phase="Succeeded", start_time=datetime(2020, 1, 2, tzinfo=UTC)
        ),
    )

    class FakeCore:
        def __init__(self) -> None:
            self.read_names: list[str] = []
            self._reads = iter(
                [_LogResp(""), _LogResp('PRISM_METRICS_JSON={"q_arch":1.0}')]
            )

        def list_namespaced_pod(self, *, namespace: str, label_selector: str) -> object:
            return SimpleNamespace(items=[running, succeeded])

        def read_namespaced_pod_log(
            self,
            *,
            name: str,
            namespace: str,
            tail_lines: int,
            _preload_content: bool = True,
        ) -> object:
            self.read_names.append(name)
            return next(self._reads)

    core = FakeCore()
    client = _logs_client(core)

    out = client.pod_logs_for_job("job-xyz", tries=5, sleep_s=0)

    assert out == 'PRISM_METRICS_JSON={"q_arch":1.0}'
    assert core.read_names == ["job-xyz-done", "job-xyz-done"]


def test_pod_logs_for_job_decodes_bytes_response() -> None:
    succeeded = SimpleNamespace(
        metadata=SimpleNamespace(name="agent-pod"),
        status=SimpleNamespace(phase="Succeeded", start_time=None),
    )

    class FakeCore:
        def __init__(self) -> None:
            self.list_count = 0
            self.read_count = 0
            self.preload_flags: list[bool] = []

        def list_namespaced_pod(self, *, namespace: str, label_selector: str) -> object:
            self.list_count += 1
            return SimpleNamespace(items=[succeeded])

        def read_namespaced_pod_log(
            self,
            *,
            name: str,
            namespace: str,
            tail_lines: int,
            _preload_content: bool = True,
        ) -> object:
            self.read_count += 1
            self.preload_flags.append(_preload_content)
            return _LogResp("agent-challenge eval line\nmore output\n")

    core = FakeCore()
    client = _logs_client(core)

    out = client.pod_logs_for_job("agent-job")

    assert out.startswith("agent-challenge eval line")
    assert "b'" not in out
    assert core.list_count == 1
    assert core.read_count == 1
    assert core.preload_flags == [False]

