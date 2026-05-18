from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml

from platform_network.config.settings import Settings

CHART = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "platform"


def test_helm_template_renders_secure_kubernetes_control_plane() -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    rendered = subprocess.check_output(
        [helm, "template", "platform", str(CHART)],
        text=True,
    )
    documents = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]
    kinds = {doc["kind"] for doc in documents}

    assert {"Deployment", "Role", "RoleBinding", "HorizontalPodAutoscaler"}.issubset(
        kinds
    )
    assert "NetworkPolicy" in kinds
    assert "docker.sock" not in rendered
    assert "privileged: true" not in rendered
    assert _role_resources(documents, "autoscaling") == {"horizontalpodautoscalers"}
    assert _role_resources(documents, "networking.k8s.io") == {"networkpolicies"}
    assert _role_resources(documents, "keda.sh") == set()

    for container in _containers(documents):
        security = container.get("securityContext", {})
        assert security.get("allowPrivilegeEscalation") is False
        assert security.get("privileged") is False
        assert security.get("capabilities", {}).get("drop") == ["ALL"]


def test_helm_template_switches_from_hpa_to_keda_scaledobjects() -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    rendered = subprocess.check_output(
        [helm, "template", "platform", str(CHART), "--set", "keda.enabled=true"],
        text=True,
    )
    documents = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]
    kinds = [doc["kind"] for doc in documents]

    assert "ScaledObject" in kinds
    assert "HorizontalPodAutoscaler" not in kinds
    assert _role_resources(documents, "keda.sh") == {"scaledobjects"}


def test_helm_template_renders_target_gpu_and_remote_agent_security_values(
    tmp_path: Path,
) -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    values_file = tmp_path / "values.yaml"
    values_file.write_text(
        textwrap.dedent(
            """
            image:
              pullSecrets:
                - ghcr-auth
            kubernetes:
              runtimeClassName: nvidia
              nodeSelector:
                accelerator: nvidia
              tolerations:
                - key: nvidia.com/gpu
                  operator: Exists
                  effect: NoSchedule
              targetDefaults:
                imagePullSecrets:
                  - remote-ghcr-auth
                gpuResourceName: nvidia.com/gpu
                runtimeClassName: nvidia
                nodeSelector:
                  accelerator: nvidia
                tolerations:
                  - key: nvidia.com/gpu
                    operator: Exists
            kubernetesTargets:
              enabled: true
              targets:
                - id: gpu-a
                  mode: agent
                  agent_url: https://gpu-a.example.test
                  namespace: platform
                  service_account: platform-target
                  gpu_count: 4
                  agent_token_file: /var/lib/platform/secrets/gpu-a-agent-token
                  labels:
                    pool: gpu
                  enabled: true
                  verify_tls: true
            remoteAgents:
              enabled: true
              networkPolicy:
                egressCIDRs:
                  - 10.10.0.0/24
                ports:
                  - 8443
            networkPolicy:
              egress:
                allowAll: false
            """
        ),
        encoding="utf-8",
    )

    rendered = subprocess.check_output(
        [helm, "template", "platform", str(CHART), "-f", str(values_file)],
        text=True,
    )
    documents = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]
    config = yaml.safe_load(
        _document(documents, "ConfigMap", "platform-config")["data"]["master.yaml"]
    )
    Settings.model_validate(config)
    network_policy = _document(documents, "NetworkPolicy", "platform-control-plane")

    assert config["kubernetes"]["runtime_class_name"] == "nvidia"
    assert config["kubernetes"]["node_selector"] == {"accelerator": "nvidia"}
    assert config["kubernetes"]["target_defaults"]["image_pull_secrets"] == [
        "remote-ghcr-auth"
    ]
    assert config["kubernetes_targets"][0]["id"] == "gpu-a"
    assert config["kubernetes_targets"][0]["agent_url"] == "https://gpu-a.example.test"
    assert config["kubernetes_targets"][0]["gpu_count"] == 4

    ingress_peers = network_policy["spec"]["ingress"][0]["from"]
    assert {"namespaceSelector": {}} not in ingress_peers
    assert any("matchExpressions" in peer["podSelector"] for peer in ingress_peers)
    assert network_policy["spec"]["egress"] == [
        {
            "to": [{"ipBlock": {"cidr": "10.10.0.0/24"}}],
            "ports": [{"protocol": "TCP", "port": 8443}],
        }
    ]


def _containers(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    containers: list[dict[str, Any]] = []
    for doc in documents:
        pod_spec = _pod_spec(doc)
        if pod_spec:
            containers.extend(pod_spec.get("containers", []))
    return containers


def _pod_spec(doc: dict[str, Any]) -> dict[str, Any] | None:
    kind = doc.get("kind")
    if kind == "Deployment":
        return doc["spec"]["template"]["spec"]
    if kind == "CronJob":
        return doc["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    return None


def _document(documents: list[dict[str, Any]], kind: str, name: str) -> dict[str, Any]:
    for doc in documents:
        if doc.get("kind") == kind and doc.get("metadata", {}).get("name") == name:
            return doc
    raise AssertionError(f"{kind}/{name} not rendered")


def _role_resources(documents: list[dict[str, Any]], api_group: str) -> set[str]:
    for doc in documents:
        if doc.get("kind") != "Role":
            continue
        resources: set[str] = set()
        for rule in doc.get("rules", []):
            if api_group in rule.get("apiGroups", []):
                resources.update(rule.get("resources", []))
        return resources
    return set()
