from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Protocol

from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from platform_network.bittensor.metagraph_cache import MetagraphCache
from platform_network.db.models import MinerRequestNonce
from platform_network.db.session import session_scope


class MinerAuthError(ValueError):
    pass


class NonceReplayError(MinerAuthError):
    pass


class MinerNonceStore(Protocol):
    async def reserve(
        self,
        *,
        netuid: int,
        challenge_slug: str,
        hotkey: str,
        nonce: str,
        body_hash: str,
        created_at: datetime,
    ) -> None: ...


@dataclass(frozen=True)
class MinerIdentity:
    hotkey: str
    uid: int | None
    nonce: str
    timestamp: int
    body_hash: str


class SqlAlchemyMinerNonceStore:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        ttl_seconds: int = 86_400,
    ) -> None:
        self.session_factory = session_factory
        self.ttl_seconds = ttl_seconds

    async def reserve(
        self,
        *,
        netuid: int,
        challenge_slug: str,
        hotkey: str,
        nonce: str,
        body_hash: str,
        created_at: datetime,
    ) -> None:
        cutoff = created_at - timedelta(seconds=self.ttl_seconds)
        try:
            async with session_scope(self.session_factory) as session:
                await session.execute(
                    delete(MinerRequestNonce).where(
                        MinerRequestNonce.created_at < cutoff
                    )
                )
                session.add(
                    MinerRequestNonce(
                        id=uuid.uuid4(),
                        netuid=netuid,
                        challenge_slug=challenge_slug,
                        hotkey=hotkey,
                        nonce=nonce,
                        body_hash=body_hash,
                        created_at=created_at,
                    )
                )
        except IntegrityError as exc:
            raise NonceReplayError("nonce already used") from exc


SignatureVerifier = Callable[[str, bytes, str], bool]


def canonical_upload_message(
    *,
    netuid: int,
    challenge_slug: str,
    method: str,
    path: str,
    hotkey: str,
    nonce: str,
    timestamp: str,
    body_hash: str,
) -> bytes:
    return (
        "platform-upload-v1:"
        f"{netuid}:{challenge_slug}:{method.upper()}:{path}:"
        f"{hotkey}:{nonce}:{timestamp}:{body_hash}"
    ).encode()


def verify_substrate_signature(hotkey: str, message: bytes, signature: str) -> bool:
    try:
        import bittensor as bt  # type: ignore

        keypair = bt.Keypair(ss58_address=hotkey)
        return bool(keypair.verify(message, _decode_signature(signature)))
    except Exception:
        return False


class MinerUploadVerifier:
    def __init__(
        self,
        *,
        netuid: int,
        nonce_store: MinerNonceStore,
        metagraph_cache: MetagraphCache | None = None,
        ttl_seconds: int = 300,
        require_registered_hotkey: bool = True,
        blocked_uids: set[int] | None = None,
        signature_verifier: SignatureVerifier = verify_substrate_signature,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.netuid = netuid
        self.nonce_store = nonce_store
        self.metagraph_cache = metagraph_cache
        self.ttl_seconds = ttl_seconds
        self.require_registered_hotkey = require_registered_hotkey
        self.blocked_uids = blocked_uids if blocked_uids is not None else {0}
        self.signature_verifier = signature_verifier
        self.now_fn = now_fn

    async def verify(
        self,
        *,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        challenge_slug: str,
    ) -> MinerIdentity:
        hotkey = _required_header(headers, "x-hotkey")
        signature = _required_header(headers, "x-signature")
        nonce = _required_header(headers, "x-nonce")
        timestamp_raw = _required_header(headers, "x-timestamp")
        try:
            timestamp = int(timestamp_raw)
        except ValueError as exc:
            raise MinerAuthError("invalid timestamp") from exc
        now = self.now_fn()
        if abs(int(now) - timestamp) > self.ttl_seconds:
            raise MinerAuthError("stale signature")
        body_hash = sha256(body).hexdigest()
        message = canonical_upload_message(
            netuid=self.netuid,
            challenge_slug=challenge_slug,
            method=method,
            path=path,
            hotkey=hotkey,
            nonce=nonce,
            timestamp=timestamp_raw,
            body_hash=body_hash,
        )
        if not self.signature_verifier(hotkey, message, signature):
            raise MinerAuthError("invalid signature")
        uid = self._uid_for_hotkey(hotkey)
        await self.nonce_store.reserve(
            netuid=self.netuid,
            challenge_slug=challenge_slug,
            hotkey=hotkey,
            nonce=nonce,
            body_hash=body_hash,
            created_at=datetime.fromtimestamp(now, UTC),
        )
        return MinerIdentity(
            hotkey=hotkey,
            uid=uid,
            nonce=nonce,
            timestamp=timestamp,
            body_hash=body_hash,
        )

    def _uid_for_hotkey(self, hotkey: str) -> int | None:
        if self.metagraph_cache is None:
            if self.require_registered_hotkey:
                raise MinerAuthError("metagraph unavailable")
            return None
        hotkey_to_uid = self.metagraph_cache.get()
        if not hotkey_to_uid:
            if self.require_registered_hotkey:
                raise MinerAuthError("metagraph unavailable")
            return None
        uid = hotkey_to_uid.get(hotkey)
        if uid is None:
            raise MinerAuthError("unknown hotkey")
        if uid in self.blocked_uids:
            raise MinerAuthError("blocked uid")
        return uid


def _decode_signature(signature: str) -> bytes | str:
    value = signature.removeprefix("0x")
    try:
        return bytes.fromhex(value)
    except ValueError:
        return signature


def _required_header(headers: Mapping[str, str], key: str) -> str:
    value = headers.get(key) or headers.get(key.title())
    if not value:
        raise MinerAuthError(f"missing {key}")
    return value
