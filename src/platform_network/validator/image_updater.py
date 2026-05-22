from __future__ import annotations

import os
import re
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qsl

import httpx

DIGEST_ANNOTATION = "platform.network/validator-image-digest"
MEDIA_TYPES = ", ".join(
    [
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
    ]
)
_DIGEST_RE = re.compile(r"sha256:[0-9a-fA-F]{64}")


@dataclass(frozen=True)
class ImageReference:
    registry: str
    repository: str
    tag: str
    digest: str | None = None

    @property
    def immutable(self) -> bool:
        return self.digest is not None

    @property
    def tagged(self) -> str:
        return f"{self.registry}/{self.repository}:{self.tag}"

    def pinned(self, digest: str) -> str:
        return f"{self.tagged}@{digest}"


def parse_image_reference(image: str) -> ImageReference:
    name, _, digest = image.partition("@")
    digest_value = digest or None
    if "/" not in name:
        registry = "docker.io"
        remainder = f"library/{name}"
    else:
        first, rest = name.split("/", 1)
        if "." in first or ":" in first or first == "localhost":
            registry = first
            remainder = rest
        else:
            registry = "docker.io"
            remainder = name
    repository, separator, tag = remainder.rpartition(":")
    if not separator or "/" in tag:
        repository = remainder
        tag = "latest"
    return ImageReference(
        registry=registry,
        repository=repository,
        tag=tag,
        digest=digest_value,
    )


def extract_digest(value: str | None) -> str | None:
    if not value:
        return None
    match = _DIGEST_RE.search(value)
    return match.group(0).lower() if match else None


def _parse_www_authenticate(header: str) -> dict[str, str]:
    scheme, _, params = header.partition(" ")
    if scheme.lower() != "bearer":
        return {}
    parsed: dict[str, str] = {}
    for key, value in parse_qsl(params.replace(",", "&")):
        parsed[key] = value
    return parsed


def resolve_remote_digest(
    image: ImageReference,
    *,
    registry_endpoint: str | None = None,
    timeout_seconds: float = 30.0,
) -> str:
    if image.digest:
        return image.digest.lower()
    base_url = (
        registry_endpoint.rstrip("/")
        if registry_endpoint
        else f"https://{image.registry}"
    )
    manifest_path = f"/v2/{image.repository}/manifests/{image.tag}"
    headers = {"Accept": MEDIA_TYPES}
    with httpx.Client(timeout=timeout_seconds) as client:
        response = client.head(f"{base_url}{manifest_path}", headers=headers)
        if response.status_code == 401:
            challenge = _parse_www_authenticate(
                response.headers.get("www-authenticate", "")
            )
            if challenge.get("realm"):
                token_response = client.get(
                    challenge["realm"],
                    params={
                        key: value
                        for key, value in {
                            "service": challenge.get("service"),
                            "scope": challenge.get("scope"),
                        }.items()
                        if value
                    },
                )
                token_response.raise_for_status()
                token = token_response.json().get("token") or token_response.json().get(
                    "access_token"
                )
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                    response = client.head(
                        f"{base_url}{manifest_path}", headers=headers
                    )
        response.raise_for_status()
    digest = response.headers.get("Docker-Content-Digest")
    parsed = extract_digest(digest)
    if not parsed:
        raise RuntimeError(
            f"registry did not return a sha256 digest for {image.tagged}"
        )
    return parsed


class ValidatorImageUpdater:
    def __init__(self, apps_api: Any, core_api: Any) -> None:
        self.apps_api = apps_api
        self.core_api = core_api

    def refresh(
        self,
        *,
        namespace: str,
        deployment: str,
        container: str,
        image: str,
        registry_endpoint: str | None = None,
    ) -> bool:
        reference = parse_image_reference(image)
        if reference.immutable:
            return False
        remote_digest = resolve_remote_digest(
            reference,
            registry_endpoint=registry_endpoint or None,
        )
        current = self.apps_api.read_namespaced_deployment(deployment, namespace)
        if _annotation(current.metadata, DIGEST_ANNOTATION) == remote_digest:
            return False
        if (
            _annotation(current.spec.template.metadata, DIGEST_ANNOTATION)
            == remote_digest
        ):
            self._patch_metadata_annotation(namespace, deployment, remote_digest)
            return False
        observed_digest = self._observed_pod_digest(
            namespace=namespace,
            deployment=current,
            container=container,
        )
        if observed_digest == remote_digest:
            self._patch_metadata_annotation(namespace, deployment, remote_digest)
            return False
        if observed_digest is None and _container_image(
            current, container
        ) == reference.pinned(remote_digest):
            self._patch_metadata_annotation(namespace, deployment, remote_digest)
            return False
        self._patch_template(
            namespace=namespace,
            deployment=deployment,
            container=container,
            image=reference.pinned(remote_digest),
            digest=remote_digest,
        )
        return True

    def _observed_pod_digest(
        self,
        *,
        namespace: str,
        deployment: Any,
        container: str,
    ) -> str | None:
        selector = _selector(deployment)
        if not selector:
            return None
        pods = self.core_api.list_namespaced_pod(namespace, label_selector=selector)
        for pod in getattr(pods, "items", []) or []:
            for status in (
                getattr(getattr(pod, "status", None), "container_statuses", []) or []
            ):
                if getattr(status, "name", None) != container:
                    continue
                digest = extract_digest(getattr(status, "image_id", None))
                if digest:
                    return digest
        return None

    def _patch_metadata_annotation(
        self,
        namespace: str,
        deployment: str,
        digest: str,
    ) -> None:
        self.apps_api.patch_namespaced_deployment(
            deployment,
            namespace,
            {"metadata": {"annotations": {DIGEST_ANNOTATION: digest}}},
        )

    def _patch_template(
        self,
        *,
        namespace: str,
        deployment: str,
        container: str,
        image: str,
        digest: str,
    ) -> None:
        self.apps_api.patch_namespaced_deployment(
            deployment,
            namespace,
            {
                "metadata": {"annotations": {DIGEST_ANNOTATION: digest}},
                "spec": {
                    "template": {
                        "metadata": {"annotations": {DIGEST_ANNOTATION: digest}},
                        "spec": {
                            "containers": [
                                {
                                    "name": container,
                                    "image": image,
                                }
                            ]
                        },
                    }
                },
            },
        )


def create_incluster_updater() -> ValidatorImageUpdater:
    return ValidatorImageUpdater(_InClusterAppsApi(), _InClusterCoreApi())


class _InClusterClient:
    def __init__(self) -> None:
        host = os.environ["KUBERNETES_SERVICE_HOST"]
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        self.base_url = f"https://{host}:{port}"
        token = open(token_path, encoding="utf-8").read().strip()
        self.headers = {"Authorization": f"Bearer {token}"}
        self.verify: str | bool = ca_path if os.path.exists(ca_path) else True

    def get(self, path: str, **params: str) -> Any:
        with httpx.Client(verify=self.verify, timeout=30.0) as client:
            response = client.get(
                f"{self.base_url}{path}",
                headers=self.headers,
                params={key: value for key, value in params.items() if value},
            )
            response.raise_for_status()
            return _objectify(response.json())

    def patch(self, path: str, body: dict) -> None:
        headers = {
            **self.headers,
            "Content-Type": "application/strategic-merge-patch+json",
        }
        with httpx.Client(verify=self.verify, timeout=30.0) as client:
            response = client.patch(
                f"{self.base_url}{path}", headers=headers, json=body
            )
            response.raise_for_status()


class _InClusterAppsApi:
    def __init__(self) -> None:
        self.client = _InClusterClient()

    def read_namespaced_deployment(self, name: str, namespace: str) -> Any:
        return self.client.get(
            f"/apis/apps/v1/namespaces/{namespace}/deployments/{name}"
        )

    def patch_namespaced_deployment(
        self, name: str, namespace: str, body: dict
    ) -> None:
        self.client.patch(
            f"/apis/apps/v1/namespaces/{namespace}/deployments/{name}",
            body,
        )


class _InClusterCoreApi:
    def __init__(self) -> None:
        self.client = _InClusterClient()

    def list_namespaced_pod(self, namespace: str, label_selector: str) -> Any:
        return self.client.get(
            f"/api/v1/namespaces/{namespace}/pods",
            labelSelector=label_selector,
        )


def _objectify(value: Any) -> Any:
    if isinstance(value, list):
        return [_objectify(item) for item in value]
    if not isinstance(value, dict):
        return value
    aliases = {
        "matchLabels": "match_labels",
        "containerStatuses": "container_statuses",
        "imageID": "image_id",
        "labelSelector": "label_selector",
    }
    mapping_keys = {"annotations", "labels", "matchLabels"}
    fields = {
        str(aliases.get(key, key)): item if key in mapping_keys else _objectify(item)
        for key, item in value.items()
    }
    return SimpleNamespace(**fields)


def _annotation(metadata: Any, key: str) -> str | None:
    annotations = getattr(metadata, "annotations", None) or {}
    value = annotations.get(key)
    return value if isinstance(value, str) else None


def _selector(deployment: Any) -> str:
    labels = getattr(deployment.spec.selector, "match_labels", None) or {}
    return ",".join(f"{key}={value}" for key, value in sorted(labels.items()))


def _container_image(deployment: Any, container: str) -> str | None:
    containers = getattr(deployment.spec.template.spec, "containers", []) or []
    for item in containers:
        if getattr(item, "name", None) == container:
            return getattr(item, "image", None)
    return None
