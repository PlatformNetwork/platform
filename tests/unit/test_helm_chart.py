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
PRODUCTION_VALUES = CHART / "values.production.example.yaml"


def _helm_template(*args: str) -> list[dict[str, Any]]:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")
    rendered = subprocess.check_output(
        [helm, "template", *args],
        text=True,
    )
    return [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]


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
    for pod_spec in _pod_specs(documents):
        security = pod_spec.get("securityContext", {})
        assert security.get("runAsNonRoot") is True
        assert security.get("runAsUser") == 1000
        assert security.get("runAsGroup") == 1000
        assert security.get("fsGroup") == 1000


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


def test_helm_template_renders_validator_registry_url_default_and_override(
    tmp_path: Path,
) -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    override_file = tmp_path / "override.yaml"
    override_file.write_text(
        textwrap.dedent(
            """
            validator:
              registryUrl: https://registry.override.test
            network:
              walletPath: /var/lib/platform/wallets
            """
        ),
        encoding="utf-8",
    )

    cases = [
        ([], "https://chain.platform.network", "/var/lib/platform/wallets"),
        (
            ["-f", str(override_file)],
            "https://registry.override.test",
            "/var/lib/platform/wallets",
        ),
    ]
    for args, expected, expected_wallet_path in cases:
        rendered = subprocess.check_output(
            [helm, "template", "platform", str(CHART), *args],
            text=True,
        )
        documents = [
            doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)
        ]
        config = yaml.safe_load(
            _document(documents, "ConfigMap", "platform-config")["data"]["master.yaml"]
        )

        assert config["validator"]["registry_url"] == expected
        assert config["network"]["wallet_path"] == expected_wallet_path
        assert config["master"]["registry_url"] == "http://platform-admin:8000"


def test_helm_validator_deployment_uses_configured_image_pull_policy() -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    rendered = subprocess.check_output(
        [
            helm,
            "template",
            "platform",
            str(CHART),
            "--set",
            "validator.enabled=true",
            "--set",
            "image.pullPolicy=Always",
        ],
        text=True,
    )
    documents = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]
    validator = _document(documents, "Deployment", "platform-validator")
    container = validator["spec"]["template"]["spec"]["containers"][0]

    assert container["imagePullPolicy"] == "Always"


def test_helm_mutable_auto_update_renders_master_and_validator_latest_images() -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    rendered = subprocess.check_output(
        [helm, "template", "platform", str(CHART)],
        text=True,
    )
    documents = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]

    for name, container_name in (
        ("platform-admin", "admin"),
        ("platform-proxy", "proxy"),
        ("platform-broker", "broker"),
    ):
        deployment = _document(documents, "Deployment", name)
        container = _named_container(_pod_spec(deployment), container_name)
        assert container["image"] == "ghcr.io/platformnetwork/platform-master:latest"
        assert container["imagePullPolicy"] == "Always"

    assert not any(
        doc.get("kind") == "Deployment"
        and doc.get("metadata", {}).get("name") == "platform-validator"
        for doc in documents
    )

    assert not any(
        doc.get("kind") == "CronJob"
        and doc.get("metadata", {}).get("name") == "platform-weights"
        for doc in documents
    )


def test_helm_renders_one_minute_image_updaters_for_master_and_validator() -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    rendered = subprocess.check_output(
        [helm, "template", "platform", str(CHART)],
        text=True,
    )
    documents = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]
    expected = {
        "platform-admin-image-updater": (
            "deployment",
            "platform-admin",
            "admin",
            "ghcr.io/platformnetwork/platform-master:latest",
        ),
        "platform-proxy-image-updater": (
            "deployment",
            "platform-proxy",
            "proxy",
            "ghcr.io/platformnetwork/platform-master:latest",
        ),
        "platform-broker-image-updater": (
            "deployment",
            "platform-broker",
            "broker",
            "ghcr.io/platformnetwork/platform-master:latest",
        ),
    }

    for cronjob_name, (kind, resource, container_name, image) in expected.items():
        cronjob = _document(documents, "CronJob", cronjob_name)
        pod_spec = _pod_spec(cronjob)
        assert pod_spec is not None
        updater = _named_container(pod_spec, "image-updater")

        assert cronjob["spec"]["schedule"] == "*/1 * * * *"
        assert cronjob["spec"]["concurrencyPolicy"] == "Forbid"
        assert pod_spec["serviceAccountName"] == "platform-image-updater"
        assert pod_spec["restartPolicy"] == "OnFailure"
        assert updater["image"] == "ghcr.io/platformnetwork/platform:latest"
        assert updater["imagePullPolicy"] == "Always"
        assert updater["command"] == [
            "platform",
            "validator",
            "refresh-image",
            "--namespace",
            "default",
            "--resource-kind",
            kind,
            "--name",
            resource,
            "--container",
            container_name,
            "--image",
            image,
            "--registry-endpoint",
            "",
        ]


def test_helm_renders_one_minute_github_config_sync_resources() -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    rendered = subprocess.check_output(
        [helm, "template", "platform", str(CHART)],
        text=True,
    )
    documents = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]
    cronjob = _document(documents, "CronJob", "platform-config-sync")
    service_account = _document(documents, "ServiceAccount", "platform-config-sync")
    role = _document(documents, "Role", "platform-config-sync")
    role_binding = _document(documents, "RoleBinding", "platform-config-sync")
    pod_spec = _pod_spec(cronjob)
    assert pod_spec is not None
    updater = _named_container(pod_spec, "config-sync")

    assert cronjob["spec"]["schedule"] == "*/1 * * * *"
    assert cronjob["spec"]["concurrencyPolicy"] == "Forbid"
    assert service_account["automountServiceAccountToken"] is True
    assert pod_spec["serviceAccountName"] == "platform-config-sync"
    assert pod_spec["restartPolicy"] == "OnFailure"
    assert updater["command"] == [
        "platform",
        "kubernetes",
        "sync-config",
        "--namespace",
        "default",
        "--config-map",
        "platform-config",
        "--github-repository",
        "PlatformNetwork/platform",
        "--ref",
        "main",
        "--values-path",
        "deploy/helm/platform/values.yaml",
        "--rollout-target",
        "Deployment/platform-admin",
        "--rollout-target",
        "Deployment/platform-proxy",
        "--rollout-target",
        "Deployment/platform-broker",
    ]
    assert "refresh-image" not in updater["command"]
    assert role_binding["subjects"] == [
        {"kind": "ServiceAccount", "name": "platform-config-sync"}
    ]
    assert "ClusterRole" not in {doc["kind"] for doc in documents}
    assert "ClusterRoleBinding" not in {doc["kind"] for doc in documents}

    rules = role["rules"]
    configmap_rule = next(rule for rule in rules if rule["resources"] == ["configmaps"])
    deployment_rule = next(
        rule for rule in rules if rule["resources"] == ["deployments"]
    )
    assert configmap_rule["resourceNames"] == ["platform-config"]
    assert configmap_rule["verbs"] == ["get", "patch", "update"]
    assert set(deployment_rule["resourceNames"]) == {
        "platform-admin",
        "platform-proxy",
        "platform-broker",
    }
    assert deployment_rule["verbs"] == ["get", "patch", "update"]
    assert not any(rule["resources"] == ["cronjobs"] for rule in rules)
    assert all("secrets" not in rule.get("resources", []) for rule in rules)
    assert all("*" not in rule.get("resources", []) for rule in rules)
    assert all("*" not in rule.get("verbs", []) for rule in rules)


@pytest.mark.parametrize(
    "release, namespace, set_args, expected_release, expected_mode",
    [
        (
            "platform-master",
            "platform-master",
            ["--set", "validator.enabled=false"],
            "platform-master",
            "master",
        ),
        (
            "platform-validator",
            "platform-validator",
            ["--set", "master.enabled=false", "--set", "validator.enabled=true"],
            "platform-validator",
            "validator",
        ),
    ],
)
def test_helm_auto_upgrade_renders_full_helm_upgrade_cronjob(
    release: str,
    namespace: str,
    set_args: list[str],
    expected_release: str,
    expected_mode: str,
) -> None:
    documents = _helm_template(
        release,
        str(CHART),
        "--namespace",
        namespace,
        "--set",
        "autoUpgrade.enabled=true",
        *set_args,
    )
    cronjob = _document(documents, "CronJob", f"{release}-helm-upgrader")
    pod_spec = _pod_spec(cronjob)
    assert pod_spec is not None
    upgrader = _named_container(pod_spec, "helm-upgrader")
    command = " ".join(upgrader["command"])

    assert cronjob["spec"]["schedule"] == "*/5 * * * *"
    assert cronjob["spec"]["concurrencyPolicy"] == "Forbid"
    assert pod_spec["serviceAccountName"] == f"{release}-helm-upgrader"
    assert pod_spec["restartPolicy"] == "OnFailure"
    assert upgrader["env"] == [{"name": "HELM_DRIVER", "value": "configmap"}]
    assert "set -x" not in command
    assert "codeload.github.com/PlatformNetwork/platform/tar.gz/main" in command
    assert "helm upgrade" in command
    assert f"helm upgrade --install {expected_release}" in command
    assert f"--namespace {namespace}" in command
    assert "--atomic" in command
    assert "--wait" in command
    assert "--cleanup-on-fail" in command
    assert "--history-max 5" in command
    assert "--timeout 10m" in command
    assert "--take-ownership" in command
    assert "-f ${WORKDIR}/source/deploy/helm/platform/values.yaml" in command
    assert f"--set autoUpgrade.mode={expected_mode}" in command


def test_helm_auto_upgrade_rbac_is_namespace_scoped_without_secret_access() -> None:
    documents = _helm_template(
        "platform-master",
        str(CHART),
        "--namespace",
        "platform-master",
        "--set",
        "autoUpgrade.enabled=true",
        "--set",
        "validator.enabled=false",
    )
    service_account = _document(
        documents, "ServiceAccount", "platform-master-helm-upgrader"
    )
    role = _document(documents, "Role", "platform-master-helm-upgrader")
    role_binding = _document(documents, "RoleBinding", "platform-master-helm-upgrader")

    assert service_account["automountServiceAccountToken"] is True
    assert role_binding["subjects"] == [
        {"kind": "ServiceAccount", "name": "platform-master-helm-upgrader"}
    ]
    assert "ClusterRole" not in {doc["kind"] for doc in documents}
    assert "ClusterRoleBinding" not in {doc["kind"] for doc in documents}
    for rule in role["rules"]:
        assert "secrets" not in rule.get("resources", [])
        assert "*" not in rule.get("resources", [])
        assert "*" not in rule.get("verbs", [])


def test_helm_auto_upgrade_suppresses_patch_only_updaters() -> None:
    documents = _helm_template(
        "platform-master",
        str(CHART),
        "--namespace",
        "platform-master",
        "--set",
        "autoUpgrade.enabled=true",
        "--set",
        "validator.enabled=false",
    )
    names = {
        doc.get("metadata", {}).get("name")
        for doc in documents
        if doc.get("kind") == "CronJob"
    }

    assert "platform-master-helm-upgrader" in names
    assert "platform-master-config-sync" not in names
    assert "platform-master-admin-image-updater" not in names
    assert "platform-master-proxy-image-updater" not in names
    assert "platform-master-broker-image-updater" not in names


@pytest.mark.parametrize(
    "release, namespace, set_args, expected_targets, expected_deployments",
    [
        (
            "platform-master",
            "platform-master",
            ["--set", "validator.enabled=false"],
            {
                "Deployment/platform-master-admin",
                "Deployment/platform-master-proxy",
                "Deployment/platform-master-broker",
            },
            {
                "platform-master-admin",
                "platform-master-proxy",
                "platform-master-broker",
            },
        ),
        (
            "platform-validator",
            "platform-validator",
            ["--set", "master.enabled=false", "--set", "validator.enabled=true"],
            {"Deployment/platform-validator-validator"},
            {"platform-validator-validator"},
        ),
    ],
)
def test_helm_config_sync_rollout_targets_follow_master_validator_split(
    release: str,
    namespace: str,
    set_args: list[str],
    expected_targets: set[str],
    expected_deployments: set[str],
) -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    rendered = subprocess.check_output(
        [
            helm,
            "template",
            release,
            str(CHART),
            "--namespace",
            namespace,
            *set_args,
        ],
        text=True,
    )
    documents = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]
    cronjob = _document(documents, "CronJob", f"{release}-config-sync")
    role = _document(documents, "Role", f"{release}-config-sync")
    command = _named_container(_pod_spec(cronjob), "config-sync")["command"]
    deployment_rule = next(
        rule for rule in role["rules"] if rule["resources"] == ["deployments"]
    )

    assert set(_arg_values(command, "--rollout-target")) == expected_targets
    assert set(deployment_rule["resourceNames"]) == expected_deployments
    assert not any(rule["resources"] == ["cronjobs"] for rule in role["rules"])


def test_helm_image_updater_rbac_is_namespace_scoped() -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    rendered = subprocess.check_output(
        [helm, "template", "platform", str(CHART)],
        text=True,
    )
    documents = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]
    service_account = _document(documents, "ServiceAccount", "platform-image-updater")
    role = _document(documents, "Role", "platform-image-updater")
    role_binding = _document(documents, "RoleBinding", "platform-image-updater")

    assert service_account["automountServiceAccountToken"] is True
    assert role_binding["subjects"] == [
        {"kind": "ServiceAccount", "name": "platform-image-updater"}
    ]
    assert "ClusterRole" not in {doc["kind"] for doc in documents}
    assert "ClusterRoleBinding" not in {doc["kind"] for doc in documents}
    rules = role["rules"]
    deployment_rule = next(
        rule for rule in rules if rule["resources"] == ["deployments"]
    )
    pods_rule = next(rule for rule in rules if rule["resources"] == ["pods"])

    assert set(deployment_rule["resourceNames"]) == {
        "platform-admin",
        "platform-proxy",
        "platform-broker",
    }
    assert deployment_rule["verbs"] == ["get", "patch"]
    assert not any(rule["resources"] == ["cronjobs"] for rule in rules)
    assert pods_rule["verbs"] == ["get", "list"]


def test_helm_master_mode_renders_only_master_resources_in_master_namespace() -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    rendered = subprocess.check_output(
        [
            helm,
            "template",
            "platform-master",
            str(CHART),
            "--namespace",
            "platform-master",
            "--set",
            "validator.enabled=false",
        ],
        text=True,
    )
    documents = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]
    names = {doc["metadata"]["name"] for doc in documents if "metadata" in doc}

    assert _document(documents, "Deployment", "platform-master-admin")["metadata"].get(
        "namespace"
    ) in (None, "platform-master")
    assert _document(documents, "Deployment", "platform-master-proxy")["metadata"].get(
        "namespace"
    ) in (None, "platform-master")
    assert _document(documents, "Deployment", "platform-master-broker")["metadata"].get(
        "namespace"
    ) in (None, "platform-master")
    assert "platform-master-weights" not in names
    assert "platform-master-validator" not in names
    assert not any(name.endswith("validator-image-updater") for name in names)
    assert _document(documents, "ConfigMap", "platform-master-config")["data"][
        "master.yaml"
    ]
    config_sync = _document(documents, "CronJob", "platform-master-config-sync")
    config_sync_command = _named_container(_pod_spec(config_sync), "config-sync")[
        "command"
    ]
    assert set(_arg_values(config_sync_command, "--rollout-target")) == {
        "Deployment/platform-master-admin",
        "Deployment/platform-master-proxy",
        "Deployment/platform-master-broker",
    }
    assert "Deployment/platform-master-validator" not in config_sync_command


def test_helm_validator_mode_renders_only_validator_resources() -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    rendered = subprocess.check_output(
        [
            helm,
            "template",
            "platform-validator",
            str(CHART),
            "--namespace",
            "platform-validator",
            "--set",
            "master.enabled=false",
            "--set",
            "validator.enabled=true",
        ],
        text=True,
    )
    documents = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]
    names = {doc["metadata"]["name"] for doc in documents if "metadata" in doc}

    validator = _document(documents, "Deployment", "platform-validator-validator")
    validator_pod = _pod_spec(validator)
    assert validator_pod is not None
    validator_container = _named_container(validator_pod, "validator")
    assert validator["metadata"].get("namespace") in (None, "platform-validator")
    assert validator_pod["serviceAccountName"] == "platform-validator"
    assert {mount["name"] for mount in validator_container["volumeMounts"]} == {
        "config",
        "data",
        "wallet",
    }
    wallet_mount = next(
        mount
        for mount in validator_container["volumeMounts"]
        if mount["name"] == "wallet"
    )
    assert wallet_mount == {
        "name": "wallet",
        "mountPath": "/var/lib/platform/wallets/default/hotkeys",
        "readOnly": True,
    }
    wallet_volume = next(
        volume for volume in validator_pod["volumes"] if volume["name"] == "wallet"
    )
    assert wallet_volume == {
        "name": "wallet",
        "secret": {
            "secretName": "platform-validator-wallet",
            "items": [
                {"key": "hotkey", "path": "default"},
                {"key": "hotkeypub.txt", "path": "defaultpub.txt"},
            ],
        },
    }
    assert "platform-validator-admin" not in names
    assert "platform-validator-proxy" not in names
    assert "platform-validator-broker" not in names
    assert "platform-validator-weights" not in names
    assert not any(name.endswith("admin-image-updater") for name in names)
    assert not any(name.endswith("proxy-image-updater") for name in names)
    assert not any(name.endswith("broker-image-updater") for name in names)
    assert not any(name.endswith("weights-image-updater") for name in names)

    config = yaml.safe_load(
        _document(documents, "ConfigMap", "platform-validator-config")["data"][
            "master.yaml"
        ]
    )
    assert config["kubernetes"]["namespace"] == "platform-validator"
    assert config["validator"]["weights_url"] is None
    assert config["validator"]["weights_interval_seconds"] == 360
    assert config["validator"]["weights_timeout_seconds"] == 15.0
    assert config["validator"]["weights_retries"] == 3
    assert config["validator"]["weights_freshness_seconds"] == 720
    config_sync = _document(documents, "CronJob", "platform-validator-config-sync")
    config_sync_command = _named_container(_pod_spec(config_sync), "config-sync")[
        "command"
    ]
    assert _arg_values(config_sync_command, "--rollout-target") == [
        "Deployment/platform-validator-validator"
    ]
    assert "Deployment/platform-validator-admin" not in config_sync_command


def test_helm_rejects_equal_master_and_validator_namespaces() -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    result = subprocess.run(
        [
            helm,
            "template",
            "platform",
            str(CHART),
            "--set",
            "master.namespace=platform-shared",
            "--set",
            "validator.namespace=platform-shared",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "master.namespace and validator.namespace must differ" in result.stderr


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
    config["docker"]["broker_allowed_images"] = ["ghcr.io/platformnetwork/"]
    config["database"]["url"] = "postgresql+asyncpg://user:pass@postgres/platform"
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


def test_helm_managed_postgres_defaults_render_into_kubernetes_config() -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    rendered = subprocess.check_output(
        [helm, "template", "platform", str(CHART)],
        text=True,
    )
    documents = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]
    config = yaml.safe_load(
        _document(documents, "ConfigMap", "platform-config")["data"]["master.yaml"]
    )
    config["database"]["url"] = "postgresql+asyncpg://user:pass@postgres/platform"

    settings = Settings.model_validate(config)
    managed_postgres = settings.kubernetes.managed_postgres

    assert settings.runtime.backend == "kubernetes"
    assert managed_postgres.enabled is True
    assert managed_postgres.image == "postgres:16-alpine"
    assert managed_postgres.storage_class == ""
    assert managed_postgres.storage_size == "10Gi"
    assert managed_postgres.retain_pvc is True
    assert managed_postgres.retain_secret is True
    assert managed_postgres.resources.requests == {"cpu": "100m", "memory": "256Mi"}
    assert managed_postgres.resources.limits == {"cpu": "500m", "memory": "512Mi"}
    assert set(config["kubernetes"]["managed_postgres"]) == {
        "enabled",
        "image",
        "storage_class",
        "storage_size",
        "retain_pvc",
        "retain_secret",
        "resources",
    }


def test_helm_managed_postgres_rbac_uses_statefulset_volume_claim_templates() -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    rendered = subprocess.check_output(
        [helm, "template", "platform", str(CHART)],
        text=True,
    )
    documents = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]

    assert {"secrets", "services"}.issubset(_role_resources(documents, ""))
    assert "statefulsets" in _role_resources(documents, "apps")
    assert "persistentvolumeclaims" not in _role_resources(documents, "")


def test_helm_managed_postgres_schema_accepts_operator_overrides(
    tmp_path: Path,
) -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    values_file = tmp_path / "managed-postgres.yaml"
    values_file.write_text(
        textwrap.dedent(
            """
            kubernetes:
              managedPostgres:
                enabled: true
                image: postgres:16-alpine
                storageClass: fast-retain
                storageSize: 20Gi
                retainPvc: true
                retainSecret: true
                resources:
                  requests:
                    cpu: 250m
                    memory: 512Mi
                  limits:
                    cpu: "1"
                    memory: 1Gi
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

    assert config["kubernetes"]["managed_postgres"]["storage_class"] == "fast-retain"
    assert config["kubernetes"]["managed_postgres"]["storage_size"] == "20Gi"
    assert config["kubernetes"]["managed_postgres"]["resources"] == {
        "requests": {"cpu": "250m", "memory": "512Mi"},
        "limits": {"cpu": "1", "memory": "1Gi"},
    }


def test_helm_production_values_render_safe_control_plane() -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    rendered = subprocess.check_output(
        [helm, "template", "platform", str(CHART), "-f", str(PRODUCTION_VALUES)],
        text=True,
    )
    documents = [doc for doc in yaml.safe_load_all(rendered) if isinstance(doc, dict)]
    rendered_lower = rendered.lower()
    images = [container["image"] for container in _containers(documents)]
    network_policy = _document(documents, "NetworkPolicy", "platform-control-plane")
    service_account = _document(documents, "ServiceAccount", "platform-master")
    role_binding = _document(documents, "RoleBinding", "platform-runtime")
    role = _document(documents, "Role", "platform-runtime")
    pod_specs = _pod_specs(documents)

    assert "sqlite" not in rendered_lower
    assert ":latest" not in rendered_lower
    assert "image-updater" not in rendered
    assert "imagePullSecrets" not in rendered
    assert (
        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        in rendered
    )
    assert all("@sha256:" in image for image in images)
    assert _database_secret_refs(documents) == {("platform-production-postgres", "url")}
    assert service_account["automountServiceAccountToken"] is True
    assert role_binding["subjects"] == [
        {"kind": "ServiceAccount", "name": "platform-master"}
    ]
    assert "ClusterRole" not in {doc["kind"] for doc in documents}
    assert "ClusterRoleBinding" not in {doc["kind"] for doc in documents}
    assert all("*" not in rule.get("resources", []) for rule in role["rules"])
    assert all("*" not in rule.get("verbs", []) for rule in role["rules"])
    assert network_policy["spec"]["egress"] != [{}]
    assert network_policy["spec"]["egress"]
    assert any(
        {"protocol": "UDP", "port": 53} in rule.get("ports", [])
        for rule in network_policy["spec"]["egress"]
    )
    assert any(
        {"protocol": "TCP", "port": 5432} in rule.get("ports", [])
        for rule in network_policy["spec"]["egress"]
    )
    assert any(
        {"protocol": "TCP", "port": 443} in rule.get("ports", [])
        for rule in network_policy["spec"]["egress"]
    )
    assert {"namespaceSelector": {}} not in network_policy["spec"]["ingress"][0]["from"]
    for pod_spec in pod_specs:
        security = pod_spec.get("securityContext", {})
        assert security.get("runAsNonRoot") is True
        assert security.get("runAsUser") == 1000
        assert security.get("runAsGroup") == 1000
        assert security.get("fsGroup") == 1000
    for container in _containers(documents):
        resources = container.get("resources", {})
        assert resources.get("requests", {}).get("cpu")
        assert resources.get("requests", {}).get("memory")
        assert resources.get("limits", {}).get("cpu")
        assert resources.get("limits", {}).get("memory")


@pytest.mark.parametrize(
    "override, expected",
    [
        (
            """
            image:
              tag: latest
            """,
            "/image/tag",
        ),
        (
            """
            image:
              digest: ""
            """,
            "digest",
        ),
        (
            """
            networkPolicy:
              egress:
                allowAll: true
            """,
            "allowAll",
        ),
        (
            """
            image:
              tag: canary
            """,
            "/image/tag",
        ),
    ],
)
def test_helm_production_schema_rejects_unsafe_values(
    tmp_path: Path, override: str, expected: str
) -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    values_file = tmp_path / "unsafe.yaml"
    values_file.write_text(textwrap.dedent(override), encoding="utf-8")

    result = subprocess.run(
        [
            helm,
            "template",
            "platform",
            str(CHART),
            "-f",
            str(PRODUCTION_VALUES),
            "-f",
            str(values_file),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert expected in result.stderr


def _arg_values(command: list[str], flag: str) -> list[str]:
    return [
        command[index + 1] for index, value in enumerate(command[:-1]) if value == flag
    ]


def _containers(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    containers: list[dict[str, Any]] = []
    for doc in documents:
        pod_spec = _pod_spec(doc)
        if pod_spec:
            containers.extend(pod_spec.get("containers", []))
    return containers


def _pod_specs(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [pod_spec for doc in documents if (pod_spec := _pod_spec(doc))]


def _database_secret_refs(documents: list[dict[str, Any]]) -> set[tuple[str, str]]:
    refs: set[tuple[str, str]] = set()
    for container in _containers(documents):
        for env in container.get("env", []):
            secret_ref = env.get("valueFrom", {}).get("secretKeyRef")
            if secret_ref:
                refs.add((secret_ref["name"], secret_ref["key"]))
    return refs


def _pod_spec(doc: dict[str, Any]) -> dict[str, Any] | None:
    kind = doc.get("kind")
    if kind == "Deployment":
        return doc["spec"]["template"]["spec"]
    if kind == "CronJob":
        return doc["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    return None


def _named_container(pod_spec: dict[str, Any] | None, name: str) -> dict[str, Any]:
    assert pod_spec is not None
    for container in pod_spec.get("containers", []):
        if container.get("name") == name:
            return container
    raise AssertionError(f"container {name!r} not rendered")


def _document(documents: list[dict[str, Any]], kind: str, name: str) -> dict[str, Any]:
    for doc in documents:
        if doc.get("kind") == kind and doc.get("metadata", {}).get("name") == name:
            return doc
    raise AssertionError(f"{kind}/{name} not rendered")


def _role_resources(documents: list[dict[str, Any]], api_group: str) -> set[str]:
    resources: set[str] = set()
    for doc in documents:
        if doc.get("kind") != "Role":
            continue
        for rule in doc.get("rules", []):
            if api_group in rule.get("apiGroups", []):
                resources.update(rule.get("resources", []))
    return resources


def test_helm_production_policy_rejects_unsafe_values(tmp_path: Path) -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    cases = [
        ("latest.yaml", "image:\n  tag: latest\n", "/image/tag"),
        ("missing-digest.yaml", "image:\n  digest: ''\n", "/image/digest"),
        (
            "verify-tls.yaml",
            textwrap.dedent(
                """
                kubernetesTargets:
                  enabled: true
                  targets:
                    - id: gpu-a
                      mode: agent
                      agent_url: https://gpu-a.example.test
                      verify_tls: false
                """
            ),
            "verify_tls=true",
        ),
        (
            "mutable-autoupdate.yaml",
            "imageAutoUpdate:\n  enabled: true\n",
            "imageAutoUpdate.enabled=true",
        ),
        (
            "mutable-helm-autoupgrade.yaml",
            "autoUpgrade:\n  enabled: true\n  githubRef: main\n",
            "autoUpgrade.githubRef must be immutable in production",
        ),
        (
            "missing-db-secret.yaml",
            "database:\n  urlSecret:\n    name: ''\n    key: url\n",
            "/database/urlSecret/name",
        ),
    ]

    for filename, values, message in cases:
        values_file = tmp_path / filename
        values_file.write_text(values, encoding="utf-8")
        result = subprocess.run(
            [
                helm,
                "template",
                "platform",
                str(CHART),
                "-f",
                str(PRODUCTION_VALUES),
                "-f",
                str(values_file),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode != 0
        assert message in result.stderr


def test_helm_policy_can_be_disabled_for_local_dev_images(tmp_path: Path) -> None:
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not installed")

    values_file = tmp_path / "local.yaml"
    values_file.write_text(
        textwrap.dedent(
            """
            policy:
              enforceProduction: false
            image:
              repository: localhost:5000/platform
              tag: latest
              digest: ''
            images:
              master:
                repository: localhost:5000/platform-master
                tag: latest
                digest: ''
                pullPolicy: Always
              validator:
                repository: localhost:5000/platform
                tag: latest
                digest: ''
                pullPolicy: Always
              updater:
                repository: localhost:5000/platform
                tag: latest
                digest: ''
                pullPolicy: Always
            """
        ),
        encoding="utf-8",
    )

    rendered = subprocess.check_output(
        [helm, "template", "platform", str(CHART), "-f", str(values_file)],
        text=True,
    )

    assert "localhost:5000/platform:latest" in rendered
