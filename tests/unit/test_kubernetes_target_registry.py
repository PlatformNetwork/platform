from __future__ import annotations

import stat
from pathlib import Path

import pytest

from platform_network.kubernetes.registry import FileKubernetesTargetRegistry
from platform_network.schemas.kubernetes_target import (
    KubernetesTargetCreate,
    KubernetesTargetUpdate,
)


def test_file_kubernetes_target_registry_crud_and_secret_redaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Client:
        def __init__(self, **kwargs: object) -> None:
            pass

    monkeypatch.setattr("platform_network.kubernetes.client.KubernetesClient", Client)
    registry = FileKubernetesTargetRegistry(
        tmp_path / "kubernetes_targets.json",
        secret_dir=tmp_path / "secrets",
    )
    kubeconfig = "apiVersion: v1\nclusters:\n- name: gpu-a\n"

    created = registry.create(
        KubernetesTargetCreate(
            id="gpu-a",
            api_url="https://k8s-gpu-a",
            kubeconfig=kubeconfig,
            namespace="platform-gpu",
            gpu_count=2,
            labels={"region": "eu"},
        )
    )

    assert created.kubeconfig_file
    kubeconfig_path = Path(created.kubeconfig_file)
    assert stat.S_IMODE(kubeconfig_path.stat().st_mode) == 0o600
    assert registry.get_kubeconfig("gpu-a") == kubeconfig.strip()
    state = registry.state_file.read_text(encoding="utf-8")
    assert kubeconfig not in state
    assert created.kubeconfig_file in state

    updated = registry.update(
        "gpu-a",
        KubernetesTargetUpdate(
            enabled=False,
            node_selector={"accelerator": "nvidia"},
            runtime_class_name="nvidia",
        ),
    )
    assert updated.enabled is False
    assert updated.node_selector == {"accelerator": "nvidia"}
    assert registry.set_enabled("gpu-a", True).enabled is True
    assert registry.health("gpu-a").status == "ok"

    reloaded = FileKubernetesTargetRegistry(
        tmp_path / "kubernetes_targets.json",
        secret_dir=tmp_path / "secrets",
    )
    assert reloaded.get("gpu-a").namespace == "platform-gpu"
    reloaded.delete("gpu-a")
    assert reloaded.list() == []
    assert not kubeconfig_path.exists()


def test_file_kubernetes_target_registry_agent_token_is_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class AgentClient:
        def __init__(self, **kwargs: object) -> None:
            pass

        def health(self) -> dict[str, str]:
            return {"status": "ok"}

    monkeypatch.setattr(
        "platform_network.kubernetes.agent.KubernetesAgentClient", AgentClient
    )
    registry = FileKubernetesTargetRegistry(
        tmp_path / "kubernetes_targets.json",
        secret_dir=tmp_path / "secrets",
    )

    created = registry.create(
        KubernetesTargetCreate(
            id="agent-a",
            mode="agent",
            agent_url="https://agent-a",
            agent_token="agent-secret-token",
            gpu_count=1,
        )
    )

    assert created.agent_token_hint == "agen…oken"
    assert registry.get_agent_token("agent-a") == "agent-secret-token"
    assert "agent-secret-token" not in registry.state_file.read_text(encoding="utf-8")
    assert registry.health("agent-a").status == "ok"
