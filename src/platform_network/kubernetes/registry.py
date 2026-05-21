from __future__ import annotations

import builtins
import json
import stat
from datetime import UTC, datetime
from pathlib import Path

from platform_network.config.policy import validate_kubernetes_target_trust
from platform_network.config.settings import KubernetesTargetSettings
from platform_network.schemas.kubernetes_target import (
    KubernetesTargetCreate,
    KubernetesTargetHealth,
    KubernetesTargetRecord,
    KubernetesTargetUpdate,
    KubernetesTargetView,
)


class KubernetesTargetNotFoundError(KeyError):
    pass


class KubernetesTargetAlreadyExistsError(ValueError):
    pass


class KubernetesTargetSecretError(ValueError):
    pass


class FileKubernetesTargetRegistry:
    def __init__(
        self,
        state_file: str | Path,
        *,
        secret_dir: str | Path,
        configured_targets: list[KubernetesTargetSettings] | None = None,
        production_policy: bool = False,
    ) -> None:
        self.state_file = Path(state_file)
        self.secret_dir = Path(secret_dir)
        self._records: dict[str, KubernetesTargetRecord] = {}
        self._assignments: dict[str, str] = {}
        self._assignment_metadata: dict[str, dict[str, object]] = {}
        self._assignment_audit: list[dict[str, object]] = []
        self._configured_agent_tokens: dict[str, str] = {}
        self.production_policy = production_policy
        self._load()
        for target in configured_targets or []:
            validate_kubernetes_target_trust(
                mode=target.mode,
                agent_url=target.agent_url,
                verify_tls=target.verify_tls,
                production=self.production_policy,
                subject=f"Kubernetes target {target.id!r}",
            )
            agent_token = _read_secret(target.agent_token, target.agent_token_file)
            if agent_token:
                self._configured_agent_tokens[target.id] = agent_token
            if target.id not in self._records:
                kubeconfig = _read_secret(target.kubeconfig, target.kubeconfig_file)
                kubeconfig_file = target.kubeconfig_file
                if kubeconfig:
                    kubeconfig_file = str(self._write_kubeconfig(target.id, kubeconfig))
                now = datetime.now(UTC)
                self._records[target.id] = KubernetesTargetRecord(
                    id=target.id,
                    mode=target.mode,
                    api_url=target.api_url,
                    agent_url=target.agent_url,
                    namespace=target.namespace,
                    service_account=target.service_account,
                    kubeconfig_file=kubeconfig_file,
                    agent_token_hint=_secret_hint(agent_token),
                    enabled=target.enabled,
                    draining=target.draining,
                    verify_tls=target.verify_tls,
                    timeout_seconds=target.timeout_seconds,
                    description=target.description,
                    labels=dict(target.labels),
                    gpu_count=target.gpu_count,
                    storage_class=target.storage_class,
                    node_selector=dict(target.node_selector),
                    tolerations=list(target.tolerations),
                    runtime_class_name=target.runtime_class_name,
                    created_at=now,
                    updated_at=now,
                )
        for record in self._records.values():
            self._validate_record(record)

    def list(self) -> list[KubernetesTargetRecord]:
        self._load()
        return list(self._records.values())

    def get(self, target_id: str) -> KubernetesTargetRecord:
        self._load()
        record = self._records.get(target_id)
        if record is None:
            raise KubernetesTargetNotFoundError(target_id)
        return record

    def create(self, payload: KubernetesTargetCreate) -> KubernetesTargetRecord:
        self._load()
        validate_kubernetes_target_trust(
            mode=payload.mode,
            agent_url=payload.agent_url,
            verify_tls=payload.verify_tls,
            production=self.production_policy,
            subject=f"Kubernetes target {payload.id!r}",
        )
        if payload.id in self._records:
            raise KubernetesTargetAlreadyExistsError(payload.id)
        now = datetime.now(UTC)
        kubeconfig = _read_secret_required(
            payload.kubeconfig, payload.kubeconfig_file, secret_name="kubeconfig"
        )
        agent_token = _read_secret_required(
            payload.agent_token, payload.agent_token_file, secret_name="agent_token"
        )
        kubeconfig_file = None
        if kubeconfig:
            kubeconfig_file = str(self._write_kubeconfig(payload.id, kubeconfig))
        if agent_token:
            self._write_agent_token(payload.id, agent_token)
        record = KubernetesTargetRecord(
            id=payload.id,
            mode=payload.mode,
            api_url=payload.api_url,
            agent_url=payload.agent_url,
            namespace=payload.namespace,
            service_account=payload.service_account,
            kubeconfig_file=kubeconfig_file,
            agent_token_hint=_secret_hint(agent_token),
            enabled=payload.enabled,
            draining=payload.draining,
            verify_tls=payload.verify_tls,
            timeout_seconds=payload.timeout_seconds,
            description=payload.description,
            labels=dict(payload.labels),
            gpu_count=payload.gpu_count,
            storage_class=payload.storage_class,
            node_selector=dict(payload.node_selector),
            tolerations=list(payload.tolerations),
            runtime_class_name=payload.runtime_class_name,
            created_at=now,
            updated_at=now,
        )
        self._validate_record(record)
        self._records[payload.id] = record
        self._save()
        return record

    def update(
        self, target_id: str, payload: KubernetesTargetUpdate
    ) -> KubernetesTargetRecord:
        record = self.get(target_id)
        data = record.model_dump()
        updates = payload.model_dump(exclude_unset=True)
        kubeconfig = _read_secret_required(
            updates.pop("kubeconfig", None),
            updates.pop("kubeconfig_file", None),
            secret_name="kubeconfig",
        )
        agent_token = _read_secret_required(
            updates.pop("agent_token", None),
            updates.pop("agent_token_file", None),
            secret_name="agent_token",
        )
        candidate_verify_tls = updates.get("verify_tls", record.verify_tls)
        validate_kubernetes_target_trust(
            mode=updates.get("mode", record.mode),
            agent_url=updates.get("agent_url", record.agent_url),
            verify_tls=candidate_verify_tls,
            production=self.production_policy,
            subject=f"Kubernetes target {target_id!r}",
        )
        data.update(updates)
        if kubeconfig:
            data["kubeconfig_file"] = str(self._write_kubeconfig(target_id, kubeconfig))
        if agent_token:
            self._write_agent_token(target_id, agent_token)
            data["agent_token_hint"] = _secret_hint(agent_token)
        data["updated_at"] = datetime.now(UTC)
        updated = KubernetesTargetRecord(**data)
        self._validate_record(updated)
        self._records[target_id] = updated
        if not updated.enabled:
            self._remove_assignments_for_target(target_id, reason="target disabled")
        self._save()
        return updated

    def delete(self, target_id: str) -> None:
        self.get(target_id)
        self._records.pop(target_id, None)
        self._remove_assignments_for_target(target_id, reason="target deleted")
        self._kubeconfig_path(target_id).unlink(missing_ok=True)
        self._agent_token_path(target_id).unlink(missing_ok=True)
        self._save()

    def set_enabled(self, target_id: str, enabled: bool) -> KubernetesTargetRecord:
        return self.update(target_id, KubernetesTargetUpdate(enabled=enabled))

    def get_kubeconfig(self, target_id: str) -> str:
        record = self.get(target_id)
        if not record.kubeconfig_file:
            return ""
        path = Path(record.kubeconfig_file)
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8").strip()

    def get_kubeconfig_file(self, target_id: str) -> str:
        return self.get(target_id).kubeconfig_file or ""

    def get_agent_token(self, target_id: str) -> str:
        path = self._agent_token_path(target_id)
        if path.is_file():
            return path.read_text(encoding="utf-8").strip()
        return self._configured_agent_tokens.get(target_id, "")

    def view(self, target_id: str) -> KubernetesTargetView:
        return KubernetesTargetView(**self.get(target_id).model_dump())

    def views(self) -> builtins.list[KubernetesTargetView]:
        return [KubernetesTargetView(**record.model_dump()) for record in self.list()]

    def health(self, target_id: str) -> KubernetesTargetHealth:
        record = self.get(target_id)
        if not record.enabled:
            return KubernetesTargetHealth(
                id=target_id, status="error", detail="target disabled"
            )
        if record.draining:
            return KubernetesTargetHealth(
                id=target_id, status="draining", detail="target draining"
            )
        if record.mode == "direct":
            if not record.kubeconfig_file:
                return KubernetesTargetHealth(
                    id=target_id, status="error", detail="missing kubeconfig"
                )
            if not Path(record.kubeconfig_file).is_file():
                return KubernetesTargetHealth(
                    id=target_id, status="error", detail="kubeconfig file not found"
                )
            try:
                from platform_network.kubernetes.client import KubernetesClient

                KubernetesClient(
                    namespace=record.namespace,
                    kubeconfig=record.kubeconfig_file,
                    in_cluster=False,
                )
            except Exception as exc:
                return KubernetesTargetHealth(
                    id=target_id, status="error", detail=str(exc)
                )
            return KubernetesTargetHealth(id=target_id, status="ok", detail="direct")
        if not record.agent_url:
            return KubernetesTargetHealth(
                id=target_id, status="error", detail="missing agent_url"
            )
        token = self.get_agent_token(target_id)
        if not token:
            return KubernetesTargetHealth(
                id=target_id, status="error", detail="missing agent token"
            )
        try:
            from platform_network.kubernetes.agent import KubernetesAgentClient

            KubernetesAgentClient(
                target_id=target_id,
                base_url=record.agent_url,
                token=token,
                timeout_seconds=record.timeout_seconds,
                verify_tls=record.verify_tls,
            ).health()
        except Exception as exc:
            return KubernetesTargetHealth(id=target_id, status="error", detail=str(exc))
        return KubernetesTargetHealth(id=target_id, status="ok", detail="agent")

    def assign_challenge(
        self, slug: str, target_id: str, gpu_count: int | None = None
    ) -> None:
        self.get(target_id)
        self._assignments[slug] = target_id
        metadata = {
            "target_id": target_id,
            "gpu_count": int(gpu_count or 0),
            "assigned_at": datetime.now(UTC).isoformat(),
        }
        self._assignment_metadata[slug] = metadata
        self._assignment_audit.append({"slug": slug, "action": "assigned", **metadata})
        self._save()

    def get_assignment(self, slug: str) -> str | None:
        self._load()
        return self._assignments.get(slug)

    def get_assignment_metadata(self, slug: str) -> dict[str, object] | None:
        self._load()
        metadata = self._assignment_metadata.get(slug)
        return dict(metadata) if metadata is not None else None

    def assignments(self) -> dict[str, str]:
        self._load()
        return dict(self._assignments)

    def assignment_audit(self) -> builtins.list[dict[str, object]]:
        self._load()
        return [dict(item) for item in self._assignment_audit]

    def clear_assignment(self, slug: str) -> None:
        self._load()
        assigned = self._assignments.pop(slug, None)
        if assigned is not None:
            self._assignment_metadata.pop(slug, None)
            self._assignment_audit.append(
                {
                    "slug": slug,
                    "target_id": assigned,
                    "action": "cleared",
                    "assigned_at": datetime.now(UTC).isoformat(),
                }
            )
            self._save()

    def _load(self) -> None:
        if not self.state_file.is_file():
            return
        payload = json.loads(self.state_file.read_text(encoding="utf-8"))
        records = payload.get("records", {})
        if isinstance(records, dict):
            self._records = {
                target_id: KubernetesTargetRecord.model_validate(record)
                for target_id, record in records.items()
            }
        assignments = payload.get("assignments", {})
        if isinstance(assignments, dict):
            self._assignments = {}
            self._assignment_metadata = {}
            for slug, target in assignments.items():
                if isinstance(target, dict):
                    target_id = str(target.get("target_id", ""))
                    metadata = dict(target)
                else:
                    target_id = str(target)
                    metadata = {"target_id": target_id, "gpu_count": 0}
                if target_id in self._records:
                    self._assignments[str(slug)] = target_id
                    self._assignment_metadata[str(slug)] = metadata
        metadata = payload.get("assignment_metadata", {})
        if isinstance(metadata, dict):
            for slug, value in metadata.items():
                if slug in self._assignments and isinstance(value, dict):
                    self._assignment_metadata[str(slug)] = dict(value)
        audit = payload.get("assignment_audit", [])
        if isinstance(audit, list):
            self._assignment_audit = [item for item in audit if isinstance(item, dict)]

    def _save(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "records": {
                target_id: record.model_dump(mode="json")
                for target_id, record in self._records.items()
            },
            "assignments": dict(self._assignments),
            "assignment_metadata": dict(self._assignment_metadata),
            "assignment_audit": list(self._assignment_audit),
        }
        self.state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _validate_record(self, record: KubernetesTargetRecord) -> None:
        validate_kubernetes_target_trust(
            mode=record.mode,
            agent_url=record.agent_url,
            verify_tls=record.verify_tls,
            production=self.production_policy,
            subject=f"Kubernetes target {record.id!r}",
        )
        if record.mode == "direct" and not record.kubeconfig_file:
            raise KubernetesTargetSecretError(
                "direct Kubernetes targets require kubeconfig material"
            )
        if record.mode == "agent" and not record.agent_url:
            raise KubernetesTargetSecretError(
                "agent Kubernetes targets require agent_url"
            )

    def _remove_assignments_for_target(self, target_id: str, *, reason: str) -> None:
        removed = [
            slug
            for slug, assigned in self._assignments.items()
            if assigned == target_id
        ]
        for slug in removed:
            self._assignments.pop(slug, None)
            self._assignment_metadata.pop(slug, None)
            self._assignment_audit.append(
                {
                    "slug": slug,
                    "target_id": target_id,
                    "action": "cleared",
                    "reason": reason,
                    "assigned_at": datetime.now(UTC).isoformat(),
                }
            )

    def _kubeconfig_path(self, target_id: str) -> Path:
        return self.secret_dir / f"{target_id}_kubernetes_kubeconfig"

    def _agent_token_path(self, target_id: str) -> Path:
        return self.secret_dir / f"{target_id}_kubernetes_agent_token"

    def _write_kubeconfig(self, target_id: str, kubeconfig: str) -> Path:
        return self._write_secret(self._kubeconfig_path(target_id), kubeconfig)

    def _write_agent_token(self, target_id: str, token: str) -> Path:
        return self._write_secret(self._agent_token_path(target_id), token)

    def _write_secret(self, path: Path, value: str) -> Path:
        self.secret_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return path


def _read_secret(value: str | None = None, file_path: str | None = None) -> str:
    if value:
        return value
    if file_path:
        path = Path(file_path)
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8").strip()
    return ""


def _read_secret_required(
    value: str | None = None,
    file_path: str | None = None,
    *,
    secret_name: str,
) -> str:
    if file_path and not Path(file_path).is_file():
        raise KubernetesTargetSecretError(f"{secret_name} file not found: {file_path}")
    return _read_secret(value, file_path)


def _secret_hint(secret: str) -> str | None:
    if not secret:
        return None
    if len(secret) <= 8:
        return "****"
    return f"{secret[:4]}…{secret[-4:]}"
