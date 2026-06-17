"""Challenge registry storage and serialization helpers."""

from __future__ import annotations

import hashlib
import json
import secrets
import stat
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from threading import RLock
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from platform_network.config.policy import validate_image_reference
from platform_network.db.models import (
    Challenge,
    ChallengeAuth,
    ChallengeCapability,
    ChallengeEnv,
    ChallengeImage,
    ChallengeResource,
    ChallengeSecret,
    ChallengeVolume,
)
from platform_network.db.models import (
    ChallengeStatus as DbChallengeStatus,
)
from platform_network.db.session import session_scope
from platform_network.schemas.challenge import (
    ChallengeAdminView,
    ChallengeCreate,
    ChallengeRecord,
    ChallengeStatus,
    ChallengeUpdate,
    RegistryChallenge,
    RegistryResponse,
)


class ChallengeAlreadyExistsError(ValueError):
    """Raised when a challenge slug already exists."""


class ChallengeNotFoundError(KeyError):
    """Raised when a challenge slug is unknown."""


def _hash_token(token: str) -> str:
    """Return a deterministic non-reversible hash for a challenge token."""

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _token_hint(token: str) -> str:
    """Return a non-secret token hint suitable for admin display."""

    return f"{token[:4]}…{token[-4:]}"


def default_internal_base_url(slug: str) -> str:
    """Build the Docker-network URL for a challenge container."""

    return f"http://challenge-{slug}:8000"


def default_public_proxy_base_path(slug: str) -> str:
    """Build the public proxy base path for a challenge."""

    return f"/challenges/{slug}"


def default_sqlite_volume_name(slug: str) -> str:
    """Build the default Docker volume name for challenge SQLite storage."""

    return f"platform_{slug.replace('-', '_')}_sqlite"


class ChallengeRegistry:
    """Thread-safe in-memory challenge registry.

    The class is deliberately small and storage-agnostic so it can be replaced by
    database-backed repositories without changing the FastAPI layers.
    """

    def __init__(
        self,
        *,
        network: str = "platform",
        api_version: str = "1.0",
        master_uid: int = 0,
        production_policy: bool = False,
    ) -> None:
        self.network = network
        self.api_version = api_version
        self.master_uid = master_uid
        self.production_policy = production_policy
        self._records: dict[str, ChallengeRecord] = {}
        self._tokens: dict[str, str] = {}
        self._broker_tokens: dict[str, str] = {}
        self._lock = RLock()

    def create(self, payload: ChallengeCreate) -> tuple[ChallengeRecord, str]:
        """Create a challenge record and return it with the one-time clear token."""

        with self._lock:
            if payload.slug in self._records:
                raise ChallengeAlreadyExistsError(payload.slug)
            validate_image_reference(payload.image, production=self.production_policy)

            token = secrets.token_urlsafe(32)
            broker_token = secrets.token_urlsafe(32)
            volumes = dict(payload.volumes)
            volumes.setdefault("sqlite", default_sqlite_volume_name(payload.slug))

            now = datetime.now(UTC)
            record = ChallengeRecord(
                slug=payload.slug,
                name=payload.name,
                image=payload.image,
                version=payload.version,
                emission_percent=payload.emission_percent,
                status=payload.status,
                token_hash=_hash_token(token),
                token_hint=_token_hint(token),
                broker_token_hash=_hash_token(broker_token),
                broker_token_hint=_token_hint(broker_token),
                description=payload.description,
                api_version=payload.api_version,
                internal_base_url=payload.internal_base_url
                or default_internal_base_url(payload.slug),
                public_proxy_base_path=default_public_proxy_base_path(payload.slug),
                required_capabilities=list(payload.required_capabilities),
                resources=dict(payload.resources),
                volumes=volumes,
                env=dict(payload.env),
                secrets=list(payload.secrets),
                metadata=dict(payload.metadata),
                created_at=now,
                updated_at=now,
            )
            self._records[payload.slug] = record
            self._tokens[payload.slug] = token
            self._broker_tokens[payload.slug] = broker_token
            return record, token

    def update(self, slug: str, payload: ChallengeUpdate) -> ChallengeRecord:
        """Patch mutable metadata for an existing challenge."""

        with self._lock:
            record = self._get_locked(slug)
            updates = payload.model_dump(exclude_unset=True)
            if "image" in updates:
                validate_image_reference(
                    updates["image"], production=self.production_policy
                )
            if not updates:
                return record

            data = record.model_dump()
            data.update(updates)
            data["updated_at"] = datetime.now(UTC)
            updated = ChallengeRecord(**data)
            self._records[slug] = updated
            return updated

    def set_status(self, slug: str, status: ChallengeStatus) -> ChallengeRecord:
        """Set the lifecycle status for a challenge."""

        return self.update(slug, ChallengeUpdate(status=status))

    def get(self, slug: str) -> ChallengeRecord:
        """Return a challenge by slug."""

        with self._lock:
            return self._get_locked(slug)

    def list(self, *, active_only: bool = False) -> list[ChallengeRecord]:
        """List challenges, optionally filtering to active records only."""

        with self._lock:
            records = list(self._records.values())
        if active_only:
            return [
                record for record in records if record.status == ChallengeStatus.ACTIVE
            ]
        return records

    def registry_response(self) -> RegistryResponse:
        """Serialize active challenges for normal validators."""

        return RegistryResponse(
            network=self.network,
            api_version=self.api_version,
            master_uid=self.master_uid,
            challenges=[
                record_to_registry_view(record)
                for record in self.list()
                if record.status != ChallengeStatus.DRAFT
            ],
        )

    def _get_locked(self, slug: str) -> ChallengeRecord:
        record = self._records.get(slug)
        if record is None:
            raise ChallengeNotFoundError(slug)
        return record

    def get_token(self, slug: str) -> str:
        """Return a clear challenge token for local runtime wiring."""

        token = self._tokens.get(slug)
        if not token:
            raise RuntimeError(f"Challenge token for {slug!r} is unavailable")
        return token

    def get_broker_token(self, slug: str) -> str:
        """Return a clear Docker broker token for local runtime wiring."""

        token = self._broker_tokens.get(slug)
        if not token:
            raise RuntimeError(f"Docker broker token for {slug!r} is unavailable")
        return token


class FileChallengeRegistry(ChallengeRegistry):
    """Small persistent registry shared by admin/proxy processes.

    PostgreSQL remains the production source of truth for the master, but this
    file-backed adapter gives split admin/proxy apps a shared
    registry without exposing challenge tokens or requiring both processes to
    share memory.
    """

    def __init__(
        self,
        state_file: str | Path,
        secret_dir: str | Path | None = None,
        **kwargs: Any,
    ) -> None:
        self.state_file = Path(state_file)
        self.secret_dir = Path(secret_dir) if secret_dir else self.state_file.parent
        super().__init__(**kwargs)
        self._load()

    def create(self, payload: ChallengeCreate) -> tuple[ChallengeRecord, str]:
        record, token = super().create(payload)
        self._write_token(record.slug, token)
        self._write_broker_token(record.slug, super().get_broker_token(record.slug))
        self._save()
        return record, token

    def update(self, slug: str, payload: ChallengeUpdate) -> ChallengeRecord:
        record = super().update(slug, payload)
        self._save()
        return record

    def set_status(self, slug: str, status: ChallengeStatus) -> ChallengeRecord:
        record = super().set_status(slug, status)
        self._save()
        return record

    def _load(self) -> None:
        if not self.state_file.exists():
            return
        data = json.loads(self.state_file.read_text(encoding="utf-8"))
        records = data.get("records", {})
        if not isinstance(records, dict):
            return
        with self._lock:
            self._records = {
                slug: ChallengeRecord.model_validate(record)
                for slug, record in records.items()
            }

    def get(self, slug: str) -> ChallengeRecord:
        self._load()
        return super().get(slug)

    def list(self, *, active_only: bool = False) -> list[ChallengeRecord]:
        self._load()
        return super().list(active_only=active_only)

    def get_token(self, slug: str) -> str:
        path = self._token_path(slug)
        if not path.is_file():
            raise RuntimeError(f"Challenge token file is missing for {slug!r}")
        return path.read_text(encoding="utf-8").strip()

    def get_broker_token(self, slug: str) -> str:
        path = self._broker_token_path(slug)
        if not path.is_file():
            raise RuntimeError(f"Docker broker token file is missing for {slug!r}")
        return path.read_text(encoding="utf-8").strip()

    def _token_path(self, slug: str) -> Path:
        return self.secret_dir / f"{slug}_challenge_token"

    def _broker_token_path(self, slug: str) -> Path:
        return self.secret_dir / f"{slug}_docker_broker_token"

    def _write_token(self, slug: str, token: str) -> None:
        self.secret_dir.mkdir(parents=True, exist_ok=True)
        path = self._token_path(slug)
        path.write_text(token, encoding="utf-8")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    def _write_broker_token(self, slug: str, token: str) -> None:
        self.secret_dir.mkdir(parents=True, exist_ok=True)
        path = self._broker_token_path(slug)
        path.write_text(token, encoding="utf-8")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    def _save(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "records": {
                slug: record.model_dump(mode="json")
                for slug, record in self._records.items()
            }
        }
        self.state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")


class DatabaseChallengeRegistry:
    """SQLite/SQLAlchemy-backed challenge registry used by master runtimes."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        secret_dir: str | Path,
        network: str = "platform",
        api_version: str = "1.0",
        master_uid: int = 0,
        production_policy: bool = False,
    ) -> None:
        self.session_factory = session_factory
        self.secret_dir = Path(secret_dir)
        self.network = network
        self.api_version = api_version
        self.master_uid = master_uid
        self.production_policy = production_policy

    async def create(self, payload: ChallengeCreate) -> tuple[ChallengeRecord, str]:
        validate_image_reference(payload.image, production=self.production_policy)
        token = secrets.token_urlsafe(32)
        broker_token = secrets.token_urlsafe(32)
        async with session_scope(self.session_factory) as session:
            existing = await self._get_model(session, payload.slug, required=False)
            if existing is not None:
                raise ChallengeAlreadyExistsError(payload.slug)
            model = _model_from_payload(payload, token, broker_token)
            session.add(model)
            await session.flush()
            await session.refresh(model)
            await self._load_relationships(session, model)
            record = _record_from_model(model)
        self._write_token(payload.slug, token)
        self._write_broker_token(payload.slug, broker_token)
        return record, token

    async def update(self, slug: str, payload: ChallengeUpdate) -> ChallengeRecord:
        async with session_scope(self.session_factory) as session:
            model = await self._get_model(session, slug)
            assert model is not None
            updates = payload.model_dump(exclude_unset=True)
            if "image" in updates:
                validate_image_reference(
                    updates["image"], production=self.production_policy
                )
            if not updates:
                return _record_from_model(model)
            await _apply_model_updates(session, model, updates)
            await session.flush()
            await session.refresh(model)
            await self._load_relationships(session, model)
            return _record_from_model(model)

    async def set_status(self, slug: str, status: ChallengeStatus) -> ChallengeRecord:
        return await self.update(slug, ChallengeUpdate(status=status))

    async def get(self, slug: str) -> ChallengeRecord:
        async with session_scope(self.session_factory) as session:
            model = await self._get_model(session, slug)
            assert model is not None
            return _record_from_model(model)

    async def list(self, *, active_only: bool = False) -> list[ChallengeRecord]:
        async with session_scope(self.session_factory) as session:
            query = select(Challenge).order_by(Challenge.slug).options(*_LOAD_OPTIONS)
            if active_only:
                query = query.where(Challenge.status == DbChallengeStatus.ACTIVE)
            result = await session.execute(query)
            return [_record_from_model(model) for model in result.scalars().all()]

    async def registry_response(self) -> RegistryResponse:
        records = await self.list()
        return RegistryResponse(
            network=self.network,
            api_version=self.api_version,
            master_uid=self.master_uid,
            challenges=[
                record_to_registry_view(record)
                for record in records
                if record.status != ChallengeStatus.DRAFT
            ],
        )

    def get_token(self, slug: str) -> str:
        path = self._token_path(slug)
        if not path.is_file():
            raise RuntimeError(f"Challenge token file is missing for {slug!r}")
        return path.read_text(encoding="utf-8").strip()

    def get_broker_token(self, slug: str) -> str:
        path = self._broker_token_path(slug)
        if not path.is_file():
            raise RuntimeError(f"Docker broker token file is missing for {slug!r}")
        return path.read_text(encoding="utf-8").strip()

    async def _get_model(
        self, session: AsyncSession, slug: str, *, required: bool = True
    ) -> Challenge | None:
        result = await session.execute(
            select(Challenge).where(Challenge.slug == slug).options(*_LOAD_OPTIONS)
        )
        model = result.scalar_one_or_none()
        if model is None and required:
            raise ChallengeNotFoundError(slug)
        return model

    async def _load_relationships(
        self, session: AsyncSession, model: Challenge
    ) -> None:
        await session.refresh(model, attribute_names=_RELATIONSHIP_NAMES)

    def _token_path(self, slug: str) -> Path:
        return self.secret_dir / f"{slug}_challenge_token"

    def _broker_token_path(self, slug: str) -> Path:
        return self.secret_dir / f"{slug}_docker_broker_token"

    def _write_token(self, slug: str, token: str) -> None:
        self.secret_dir.mkdir(parents=True, exist_ok=True)
        path = self._token_path(slug)
        path.write_text(token, encoding="utf-8")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    def _write_broker_token(self, slug: str, token: str) -> None:
        self.secret_dir.mkdir(parents=True, exist_ok=True)
        path = self._broker_token_path(slug)
        path.write_text(token, encoding="utf-8")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def record_to_admin_view(record: ChallengeRecord) -> ChallengeAdminView:
    """Convert internal metadata to an admin-safe response model."""

    data = record.model_dump(exclude={"token_hash", "broker_token_hash"})
    return ChallengeAdminView(**data)


PUBLIC_REGISTRY_METADATA_KEYS = {
    "tagline",
    "summary",
    "docs_url",
    "miner_docs_url",
    "validator_docs_url",
    "repository_url",
    "website_url",
    "banner_url",
    "icon_url",
    "category",
    "difficulty",
    "benchmark_label",
    "submission_format",
    "evaluation_timeout_seconds",
    "rate_limit_label",
}


def public_registry_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in metadata.items()
        if key in PUBLIC_REGISTRY_METADATA_KEYS
        and (value is None or isinstance(value, str | int | float | bool))
    }


def record_to_registry_view(record: ChallengeRecord) -> RegistryChallenge:
    """Convert internal metadata to the validator-facing registry model."""

    return RegistryChallenge(
        slug=record.slug,
        name=record.name,
        image=record.image,
        version=record.version,
        emission_percent=Decimal(record.emission_percent),
        status=record.status,
        description=record.description,
        metadata=public_registry_metadata(record.metadata),
        internal_base_url=record.internal_base_url,
        public_proxy_base_path=record.public_proxy_base_path,
        required_capabilities=list(record.required_capabilities),
        resources=dict(record.resources),
        volumes=dict(record.volumes),
        env=dict(record.env),
        secrets=list(record.secrets),
    )


_RELATIONSHIP_NAMES = [
    "image",
    "auth",
    "resources",
    "volumes",
    "secrets",
    "env",
    "capabilities",
    "routes",
]

_LOAD_OPTIONS = tuple(
    selectinload(getattr(Challenge, relationship_name))
    for relationship_name in _RELATIONSHIP_NAMES
)


def _split_image(image: str) -> tuple[str, str, str, str | None]:
    image_without_digest, digest_sep, digest = image.partition("@")
    slash_index = image_without_digest.rfind("/")
    colon_index = image_without_digest.rfind(":")
    has_tag = colon_index > slash_index
    image_name = image_without_digest[:colon_index] if has_tag else image_without_digest
    tag = image_without_digest[colon_index + 1 :] if has_tag else ""
    if not digest_sep:
        tag = tag or "latest"
    registry, slash, repository = image_name.partition("/")
    if not slash:
        return "docker.io", registry, tag, digest or None
    if "." not in registry and ":" not in registry and registry != "localhost":
        return "docker.io", image_name, tag, digest or None
    return registry, repository, tag, digest or None


def _join_image(image: ChallengeImage | None) -> str:
    if image is None:
        return ""
    prefix = "" if image.registry_name == "docker.io" else f"{image.registry_name}/"
    reference = f"{prefix}{image.repository}"
    if image.tag:
        reference = f"{reference}:{image.tag}"
    if image.digest:
        return f"{reference}@{image.digest}"
    return reference


def _model_from_payload(
    payload: ChallengeCreate, token: str, broker_token: str
) -> Challenge:
    registry, repository, tag, digest = _split_image(payload.image)
    volumes = dict(payload.volumes)
    volumes.setdefault("sqlite", default_sqlite_volume_name(payload.slug))
    metadata = dict(payload.metadata)
    if payload.internal_base_url:
        metadata["internal_base_url"] = payload.internal_base_url
    model = Challenge(
        id=uuid.uuid4(),
        slug=payload.slug,
        name=payload.name,
        description=payload.description,
        status=DbChallengeStatus(payload.status.value),
        emission_percent=payload.emission_percent,
        version=payload.version,
        api_version=payload.api_version,
        metadata_=metadata,
        image=ChallengeImage(
            id=uuid.uuid4(),
            registry_name=registry,
            repository=repository,
            tag=tag,
            digest=digest,
        ),
        auth=ChallengeAuth(
            id=uuid.uuid4(),
            token_hash=_hash_token(token),
            token_hint=_token_hint(token),
            broker_token_hash=_hash_token(broker_token),
            broker_token_hint=_token_hint(broker_token),
        ),
        resources=[
            ChallengeResource(id=uuid.uuid4(), key=key, value=value)
            for key, value in payload.resources.items()
        ],
        volumes=[
            ChallengeVolume(
                id=uuid.uuid4(),
                name=name,
                mount_path=value,
                type="volume",
            )
            for name, value in volumes.items()
        ],
        secrets=[
            ChallengeSecret(
                id=uuid.uuid4(),
                name=name,
                mount_path=f"/run/secrets/platform/{name}",
                source_path=name,
            )
            for name in payload.secrets
        ],
        env=[
            ChallengeEnv(id=uuid.uuid4(), key=key, value_encrypted=value)
            for key, value in payload.env.items()
        ],
        capabilities=[
            ChallengeCapability(id=uuid.uuid4(), name=name)
            for name in payload.required_capabilities
        ],
    )
    return model


async def _replace_collection(
    session: AsyncSession, model: Challenge, attribute: str, new_rows: list[Any]
) -> None:
    """Replace a child collection delete-before-insert to avoid UNIQUE clashes.

    Reassigning ``model.<attribute> = [new rows]`` in one flush makes SQLAlchemy
    emit the INSERT of the new rows BEFORE the orphan DELETE of the old rows,
    which transiently violates the per-(parent, key/name) unique constraints on
    e.g. ``challenge_env`` and ``challenge_capabilities``. Clearing the
    collection and flushing first guarantees the orphan DELETE is issued before
    the new rows are inserted on the subsequent flush.
    """

    setattr(model, attribute, [])
    await session.flush()
    setattr(model, attribute, new_rows)


async def _apply_model_updates(
    session: AsyncSession, model: Challenge, updates: dict[str, Any]
) -> None:
    if "name" in updates:
        model.name = updates["name"]
    if "description" in updates:
        model.description = updates["description"]
    if "status" in updates:
        model.status = DbChallengeStatus(str(updates["status"]))
    if "emission_percent" in updates:
        model.emission_percent = updates["emission_percent"]
    if "version" in updates:
        model.version = updates["version"]
    if "api_version" in updates:
        model.api_version = updates["api_version"]
    if "metadata" in updates:
        model.metadata_ = dict(updates["metadata"] or {})
    if "internal_base_url" in updates:
        metadata = dict(model.metadata_ or {})
        if updates["internal_base_url"]:
            metadata["internal_base_url"] = updates["internal_base_url"]
        else:
            metadata.pop("internal_base_url", None)
        model.metadata_ = metadata
    if "image" in updates:
        registry, repository, tag, digest = _split_image(updates["image"])
        if model.image is None:
            model.image = ChallengeImage(id=uuid.uuid4())
        model.image.registry_name = registry
        model.image.repository = repository
        model.image.tag = tag
        model.image.digest = digest
    if "resources" in updates:
        await _replace_collection(
            session,
            model,
            "resources",
            [
                ChallengeResource(id=uuid.uuid4(), key=key, value=value)
                for key, value in (updates["resources"] or {}).items()
            ],
        )
    if "volumes" in updates:
        volumes = dict(updates["volumes"] or {})
        volumes.setdefault("sqlite", default_sqlite_volume_name(model.slug))
        await _replace_collection(
            session,
            model,
            "volumes",
            [
                ChallengeVolume(
                    id=uuid.uuid4(), name=name, mount_path=value, type="volume"
                )
                for name, value in volumes.items()
            ],
        )
    if "env" in updates:
        await _replace_collection(
            session,
            model,
            "env",
            [
                ChallengeEnv(id=uuid.uuid4(), key=key, value_encrypted=value)
                for key, value in (updates["env"] or {}).items()
            ],
        )
    if "secrets" in updates:
        await _replace_collection(
            session,
            model,
            "secrets",
            [
                ChallengeSecret(
                    id=uuid.uuid4(),
                    name=name,
                    mount_path=f"/run/secrets/platform/{name}",
                    source_path=name,
                )
                for name in (updates["secrets"] or [])
            ],
        )
    if "required_capabilities" in updates:
        await _replace_collection(
            session,
            model,
            "capabilities",
            [
                ChallengeCapability(id=uuid.uuid4(), name=name)
                for name in (updates["required_capabilities"] or [])
            ],
        )


def _record_from_model(model: Challenge) -> ChallengeRecord:
    return ChallengeRecord(
        slug=model.slug,
        name=model.name,
        image=_join_image(model.image),
        version=model.version,
        emission_percent=Decimal(model.emission_percent),
        status=ChallengeStatus(str(model.status.value)),
        token_hash=model.auth.token_hash if model.auth else "",
        token_hint=(model.auth.token_hint if model.auth else "") or "",
        broker_token_hash=model.auth.broker_token_hash if model.auth else None,
        broker_token_hint=model.auth.broker_token_hint if model.auth else None,
        description=model.description,
        api_version=model.api_version,
        internal_base_url=dict(model.metadata_ or {}).get(
            "internal_base_url", default_internal_base_url(model.slug)
        ),
        public_proxy_base_path=default_public_proxy_base_path(model.slug),
        required_capabilities=[capability.name for capability in model.capabilities],
        resources={resource.key: resource.value for resource in model.resources},
        volumes={volume.name: volume.mount_path for volume in model.volumes},
        env={item.key: item.value_encrypted for item in model.env},
        secrets=[secret.name for secret in model.secrets],
        metadata=dict(model.metadata_ or {}),
        created_at=model.created_at,
        updated_at=model.updated_at,
    )
