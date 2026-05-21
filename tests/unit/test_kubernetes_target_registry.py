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
    registry.assign_challenge("demo", "gpu-a", gpu_count=1)
    assert registry.get_assignment("demo") == "gpu-a"
    metadata = registry.get_assignment_metadata("demo")
    assert metadata is not None
    assert metadata == {
        "target_id": "gpu-a",
        "gpu_count": 1,
        "assigned_at": metadata["assigned_at"],
    }

    reloaded = FileKubernetesTargetRegistry(
        tmp_path / "kubernetes_targets.json",
        secret_dir=tmp_path / "secrets",
    )
    assert reloaded.get("gpu-a").namespace == "platform-gpu"
    assert reloaded.get_assignment("demo") == "gpu-a"
    assert reloaded.assignments() == {"demo": "gpu-a"}
    reloaded.clear_assignment("demo")
    assert reloaded.get_assignment("demo") is None
    reloaded.assign_challenge("demo", "gpu-a")
    reloaded.delete("gpu-a")
    assert reloaded.list() == []
    assert reloaded.get_assignment("demo") is None
    assert {entry["action"] for entry in reloaded.assignment_audit()} == {
        "assigned",
        "cleared",
    }
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
            agent_token="test-agent-credential",
            gpu_count=1,
        )
    )

    assert created.agent_token_hint == "test…tial"
    assert registry.get_agent_token("agent-a") == "test-agent-credential"
    assert "test-agent-credential" not in registry.state_file.read_text(
        encoding="utf-8"
    )
    assert registry.health("agent-a").status == "ok"


def test_file_kubernetes_target_registry_local_agent_health_allows_insecure_tls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    class AgentClient:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        def health(self) -> dict[str, str]:
            return {"status": "ok"}

    monkeypatch.setattr(
        "platform_network.kubernetes.agent.KubernetesAgentClient", AgentClient
    )
    registry = FileKubernetesTargetRegistry(
        tmp_path / "kubernetes_targets.json",
        secret_dir=tmp_path / "secrets",
    )
    registry.create(
        KubernetesTargetCreate(
            id="agent-a",
            mode="agent",
            agent_url="https://agent-a",
            agent_token="test-agent-credential",
            verify_tls=False,
        )
    )

    assert registry.health("agent-a").status == "ok"
    assert captured["base_url"] == "https://agent-a"
    assert captured["verify_tls"] is False


def test_file_kubernetes_target_registry_production_rejects_untrusted_agent(
    tmp_path: Path,
) -> None:
    registry = FileKubernetesTargetRegistry(
        tmp_path / "kubernetes_targets.json",
        secret_dir=tmp_path / "secrets",
        production_policy=True,
    )

    with pytest.raises(ValueError, match="HTTPS"):
        registry.create(
            KubernetesTargetCreate(
                id="agent-a",
                mode="agent",
                agent_url="http://agent-a",
                agent_token="test-agent-credential",
            )
        )

    with pytest.raises(ValueError, match="verify_tls=true"):
        registry.create(
            KubernetesTargetCreate(
                id="agent-b",
                mode="agent",
                agent_url="https://agent-b",
                agent_token="test-agent-credential",
                verify_tls=False,
            )
        )

    dev_registry = FileKubernetesTargetRegistry(
        tmp_path / "dev-kubernetes-targets.json",
        secret_dir=tmp_path / "dev-secrets",
    )
    dev_registry.create(
        KubernetesTargetCreate(
            id="agent-c",
            mode="agent",
            agent_url="http://agent-c",
            agent_token="test-agent-credential",
        )
    )

    with pytest.raises(ValueError, match="HTTPS"):
        FileKubernetesTargetRegistry(
            tmp_path / "dev-kubernetes-targets.json",
            secret_dir=tmp_path / "dev-secrets",
            production_policy=True,
        )

    dev_tls_registry = FileKubernetesTargetRegistry(
        tmp_path / "dev-tls-kubernetes-targets.json",
        secret_dir=tmp_path / "dev-tls-secrets",
    )
    dev_tls_registry.create(
        KubernetesTargetCreate(
            id="agent-d",
            mode="agent",
            agent_url="https://agent-d",
            agent_token="test-agent-credential",
            verify_tls=False,
        )
    )

    with pytest.raises(ValueError, match="verify_tls=true"):
        FileKubernetesTargetRegistry(
            tmp_path / "dev-tls-kubernetes-targets.json",
            secret_dir=tmp_path / "dev-tls-secrets",
            production_policy=True,
        )


def test_file_kubernetes_target_registry_draining_blocks_health(
    tmp_path: Path,
) -> None:
    registry = FileKubernetesTargetRegistry(
        tmp_path / "kubernetes_targets.json",
        secret_dir=tmp_path / "secrets",
    )
    created = registry.create(
        KubernetesTargetCreate(
            id="agent-a",
            mode="agent",
            agent_url="http://agent-a",
            agent_token="test-agent-credential",
            draining=True,
        )
    )

    assert created.draining is True
    assert registry.health("agent-a").status == "draining"
