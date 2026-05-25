from __future__ import annotations

import sys
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


def test_incluster_client_sets_bearer_token_alias(
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
    assert configuration.api_key["BearerToken"] == "token-value"
    assert configuration.api_key_prefix["BearerToken"] == "Bearer"


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
