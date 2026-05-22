from __future__ import annotations

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
