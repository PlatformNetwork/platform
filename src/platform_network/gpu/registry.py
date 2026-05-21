from __future__ import annotations

import builtins
import json
import stat
from datetime import UTC, datetime
from pathlib import Path

from platform_network.config.policy import validate_tls_enabled
from platform_network.config.settings import GpuServerSettings
from platform_network.schemas.gpu_server import (
    GpuServerCreate,
    GpuServerRecord,
    GpuServerUpdate,
    GpuServerView,
)
from platform_network.security.admin_auth import read_secret


class GpuServerNotFoundError(KeyError):
    pass


class GpuServerAlreadyExistsError(ValueError):
    pass


class FileGpuServerRegistry:
    def __init__(
        self,
        state_file: str | Path,
        *,
        secret_dir: str | Path,
        configured_servers: list[GpuServerSettings] | None = None,
        production_policy: bool = False,
    ) -> None:
        self.state_file = Path(state_file)
        self.secret_dir = Path(secret_dir)
        self._records: dict[str, GpuServerRecord] = {}
        self._configured_tokens: dict[str, str] = {}
        self.production_policy = production_policy
        self._load()
        for server in configured_servers or []:
            validate_tls_enabled(
                verify_tls=server.verify_tls,
                production=self.production_policy,
                subject=f"GPU server {server.id!r}",
            )
            token = read_secret(server.token, server.token_file)
            if token:
                self._configured_tokens[server.id] = token
            if server.id not in self._records:
                self._records[server.id] = GpuServerRecord(
                    id=server.id,
                    base_url=server.base_url,
                    enabled=server.enabled,
                    verify_tls=server.verify_tls,
                    timeout_seconds=server.timeout_seconds,
                    token_hint=_token_hint(token),
                )

    def list(self) -> list[GpuServerRecord]:
        self._load()
        return list(self._records.values())

    def get(self, server_id: str) -> GpuServerRecord:
        self._load()
        record = self._records.get(server_id)
        if record is None:
            raise GpuServerNotFoundError(server_id)
        return record

    def create(self, payload: GpuServerCreate) -> GpuServerRecord:
        self._load()
        validate_tls_enabled(
            verify_tls=payload.verify_tls,
            production=self.production_policy,
            subject=f"GPU server {payload.id!r}",
        )
        if payload.id in self._records:
            raise GpuServerAlreadyExistsError(payload.id)
        now = datetime.now(UTC)
        token = read_secret(payload.token, payload.token_file)
        record = GpuServerRecord(
            id=payload.id,
            base_url=payload.base_url,
            enabled=payload.enabled,
            verify_tls=payload.verify_tls,
            timeout_seconds=payload.timeout_seconds,
            description=payload.description,
            labels=dict(payload.labels),
            min_gpu_count=payload.min_gpu_count,
            token_hint=_token_hint(token),
            created_at=now,
            updated_at=now,
        )
        self._records[payload.id] = record
        if token:
            self._write_token(payload.id, token)
        self._save()
        return record

    def update(self, server_id: str, payload: GpuServerUpdate) -> GpuServerRecord:
        record = self.get(server_id)
        data = record.model_dump()
        updates = payload.model_dump(exclude_unset=True)
        token = read_secret(updates.pop("token", None), updates.pop("token_file", None))
        candidate_verify_tls = updates.get("verify_tls", record.verify_tls)
        validate_tls_enabled(
            verify_tls=candidate_verify_tls,
            production=self.production_policy,
            subject=f"GPU server {server_id!r}",
        )
        data.update(updates)
        if token:
            self._write_token(server_id, token)
            data["token_hint"] = _token_hint(token)
        data["updated_at"] = datetime.now(UTC)
        updated = GpuServerRecord(**data)
        self._records[server_id] = updated
        self._save()
        return updated

    def delete(self, server_id: str) -> None:
        self.get(server_id)
        self._records.pop(server_id, None)
        self._token_path(server_id).unlink(missing_ok=True)
        self._save()

    def set_enabled(self, server_id: str, enabled: bool) -> GpuServerRecord:
        return self.update(server_id, GpuServerUpdate(enabled=enabled))

    def get_token(self, server_id: str) -> str:
        path = self._token_path(server_id)
        if path.is_file():
            return path.read_text(encoding="utf-8").strip()
        return self._configured_tokens.get(server_id, "")

    def view(self, server_id: str) -> GpuServerView:
        return GpuServerView(**self.get(server_id).model_dump())

    def views(self) -> builtins.list[GpuServerView]:
        return [GpuServerView(**record.model_dump()) for record in self.list()]

    def _load(self) -> None:
        if not self.state_file.is_file():
            return
        payload = json.loads(self.state_file.read_text(encoding="utf-8"))
        records = payload.get("records", {})
        if isinstance(records, dict):
            self._records = {
                server_id: GpuServerRecord.model_validate(record)
                for server_id, record in records.items()
            }

    def _save(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "records": {
                server_id: record.model_dump(mode="json")
                for server_id, record in self._records.items()
            }
        }
        self.state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _token_path(self, server_id: str) -> Path:
        return self.secret_dir / f"{server_id}_gpu_server_token"

    def _write_token(self, server_id: str, token: str) -> None:
        self.secret_dir.mkdir(parents=True, exist_ok=True)
        path = self._token_path(server_id)
        path.write_text(token, encoding="utf-8")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def _token_hint(token: str) -> str | None:
    if not token:
        return None
    if len(token) <= 8:
        return "****"
    return f"{token[:4]}…{token[-4:]}"
