"""Validator coordination registration endpoints on the master app.

Implements the hotkey-signed, metagraph-permit-gated ``register`` and
``heartbeat`` routes of the coordination plane (architecture.md sec 4). The
master only records validator liveness here; it never executes work.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from base.bittensor.identity_cache import ValidatorIdentityResolver
from base.db.models import (
    DEFAULT_VALIDATOR_VERSION,
    Validator,
    ValidatorHealthEvent,
    ValidatorHealthEventType,
    ValidatorStatus,
)
from base.db.session import session_scope
from base.schemas.validator import (
    PublicIdentityView,
    PublicValidatorView,
    ValidatorHeartbeatRequest,
    ValidatorHeartbeatResponse,
    ValidatorListResponse,
    ValidatorRegisterRequest,
    ValidatorRegisterResponse,
    ValidatorSubscriptionRequest,
    ValidatorSubscriptionResponse,
    ValidatorView,
)
from base.security.validator_auth import ValidatorIdentity

logger = logging.getLogger(__name__)

DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 60
DEFAULT_HEARTBEAT_TIMEOUT_SECONDS = 180


class ValidatorNotRegisteredError(LookupError):
    """Heartbeat received for a hotkey without a ``validators`` row (HTTP 404)."""


class ValidatorCoordinationService:
    """Persist validator registration and heartbeat liveness transitions."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        heartbeat_interval_seconds: int = DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
        heartbeat_timeout_seconds: int = DEFAULT_HEARTBEAT_TIMEOUT_SECONDS,
        now_fn: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._session_factory = session_factory
        self.heartbeat_interval_seconds = heartbeat_interval_seconds
        self.heartbeat_timeout_seconds = heartbeat_timeout_seconds
        self._now_fn = now_fn

    async def register(
        self,
        *,
        hotkey: str,
        uid: int | None,
        capabilities: list[str],
        version: str | None,
        last_seen_meta: Mapping[str, Any] | None = None,
    ) -> Validator:
        """Create or update the validator row and emit lifecycle events.

        First registration appends ``registered`` + ``online`` events; an
        idempotent re-register updates the same row (capabilities, version,
        ``last_heartbeat_at``) and preserves ``registered_at``. Re-registering a
        previously-offline validator records the ``online`` recovery.

        First-registration is atomic: the ``validators.hotkey`` unique constraint
        makes the row insert authoritative, so a concurrent first-register of the
        same new hotkey that loses the race raises ``IntegrityError`` on insert
        and is transparently retried as an idempotent update (no 500, single
        row).
        """

        now = self._now_fn()
        resolved_version = version if version is not None else DEFAULT_VALIDATOR_VERSION
        try:
            async with session_scope(self._session_factory) as session:
                return await self._register_in_session(
                    session,
                    now=now,
                    hotkey=hotkey,
                    uid=uid,
                    capabilities=capabilities,
                    version=resolved_version,
                    last_seen_meta=last_seen_meta,
                )
        except IntegrityError:
            # Lost the first-register race on validators.hotkey: the winning
            # insert is now committed, so re-run deterministically as an update.
            async with session_scope(self._session_factory) as session:
                return await self._register_in_session(
                    session,
                    now=now,
                    hotkey=hotkey,
                    uid=uid,
                    capabilities=capabilities,
                    version=resolved_version,
                    last_seen_meta=last_seen_meta,
                )

    async def _register_in_session(
        self,
        session: AsyncSession,
        *,
        now: datetime,
        hotkey: str,
        uid: int | None,
        capabilities: list[str],
        version: str,
        last_seen_meta: Mapping[str, Any] | None,
    ) -> Validator:
        existing = (
            await session.execute(select(Validator).where(Validator.hotkey == hotkey))
        ).scalar_one_or_none()

        if existing is None:
            validator = Validator(
                hotkey=hotkey,
                uid=uid,
                status=ValidatorStatus.ONLINE,
                capabilities=list(capabilities),
                version=version,
                registered_at=now,
                last_heartbeat_at=now,
                last_seen_meta=dict(last_seen_meta or {}),
            )
            session.add(validator)
            await self._add_event(
                session,
                hotkey,
                ValidatorHealthEventType.REGISTERED,
                now,
            )
            await self._add_event(session, hotkey, ValidatorHealthEventType.ONLINE, now)
            return validator

        was_offline = existing.status == ValidatorStatus.OFFLINE
        existing.uid = uid
        existing.status = ValidatorStatus.ONLINE
        existing.capabilities = list(capabilities)
        existing.version = version
        existing.last_heartbeat_at = now
        if last_seen_meta is not None:
            existing.last_seen_meta = dict(last_seen_meta)
        if was_offline:
            await self._add_event(
                session,
                hotkey,
                ValidatorHealthEventType.ONLINE,
                now,
                message="re-registered after offline",
            )
        return existing

    async def heartbeat(
        self,
        *,
        hotkey: str,
        last_seen_meta: Mapping[str, Any] | None = None,
    ) -> tuple[Validator, datetime]:
        """Refresh liveness; flip an offline validator back to online.

        Raises :class:`ValidatorNotRegisteredError` when the hotkey has no
        registered row (the validator must ``register`` first).
        """

        now = self._now_fn()
        async with session_scope(self._session_factory) as session:
            validator = (
                await session.execute(
                    select(Validator).where(Validator.hotkey == hotkey)
                )
            ).scalar_one_or_none()
            if validator is None:
                raise ValidatorNotRegisteredError(hotkey)

            was_offline = validator.status == ValidatorStatus.OFFLINE
            validator.status = ValidatorStatus.ONLINE
            validator.last_heartbeat_at = now
            if last_seen_meta is not None:
                validator.last_seen_meta = dict(last_seen_meta)
            if was_offline:
                await self._add_event(
                    session,
                    hotkey,
                    ValidatorHealthEventType.ONLINE,
                    now,
                    message="recovered via heartbeat",
                )
            return validator, now

    async def set_subscriptions(
        self,
        *,
        hotkey: str,
        slugs: Sequence[str],
    ) -> Validator:
        """Persist a validator's challenge subscription set.

        Replaces the validator's ``subscriptions`` with the (de-duplicated,
        order-preserving) ``slugs``. An empty list clears the subscription so the
        validator validates ALL challenges (back-compat). Mirrors the
        ``heartbeat`` transaction shape and raises
        :class:`ValidatorNotRegisteredError` (-> HTTP 404) for a hotkey without a
        registered row.

        Slug validity (against the active registry) is enforced at the route
        layer before this is called.
        """

        deduped = list(dict.fromkeys(slugs))
        async with session_scope(self._session_factory) as session:
            validator = (
                await session.execute(
                    select(Validator).where(Validator.hotkey == hotkey)
                )
            ).scalar_one_or_none()
            if validator is None:
                raise ValidatorNotRegisteredError(hotkey)
            validator.subscriptions = deduped
            return validator

    async def detect_offline_validators(
        self, *, session: AsyncSession | None = None
    ) -> list[str]:
        """Mark validators offline whose last heartbeat exceeded the timeout.

        Edge-triggered: only validators currently ``online`` are considered, so
        repeated passes over an already-offline validator record nothing. Each
        ``online``->``offline`` transition appends a single ``crash_detected``
        event. Returns the hotkeys that transitioned this pass so callers (e.g.
        assignment reassignment) can react to crashes.

        When ``session`` is provided the detection runs inside the caller's
        transaction (so the full reassignment pass can be one atomic
        transaction); otherwise a fresh transaction is opened and committed here.
        """

        now = self._now_fn()
        if session is not None:
            return await self._detect_offline_in_session(session, now)
        async with session_scope(self._session_factory) as own_session:
            return await self._detect_offline_in_session(own_session, now)

    async def _detect_offline_in_session(
        self, session: AsyncSession, now: datetime
    ) -> list[str]:
        timeout = timedelta(seconds=self.heartbeat_timeout_seconds)
        transitioned: list[str] = []
        rows = (
            (
                await session.execute(
                    select(Validator).where(Validator.status == ValidatorStatus.ONLINE)
                )
            )
            .scalars()
            .all()
        )
        for validator in rows:
            last_heartbeat = validator.last_heartbeat_at
            if last_heartbeat is None:
                continue
            if last_heartbeat.tzinfo is None:
                last_heartbeat = last_heartbeat.replace(tzinfo=UTC)
            if now - last_heartbeat > timeout:
                validator.status = ValidatorStatus.OFFLINE
                await self._add_event(
                    session,
                    validator.hotkey,
                    ValidatorHealthEventType.CRASH_DETECTED,
                    now,
                    message="heartbeat timeout",
                )
                transitioned.append(validator.hotkey)
        return transitioned

    async def list_validators(self) -> list[Validator]:
        """Return all registered validators ordered for stable observability."""

        async with self._session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(Validator).order_by(
                            Validator.registered_at, Validator.hotkey
                        )
                    )
                )
                .scalars()
                .all()
            )
        return list(rows)

    async def list_health_events(self, hotkey: str) -> list[ValidatorHealthEvent]:
        """Return a validator's append-only audit trail in deterministic order.

        Ordered by ``(created_at, seq)`` so events that share an instant (the
        ``registered``/``online`` pair, same-tick recoveries) always read back in
        their monotonic append order.
        """

        async with self._session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(ValidatorHealthEvent)
                        .where(ValidatorHealthEvent.validator_hotkey == hotkey)
                        .order_by(
                            ValidatorHealthEvent.created_at,
                            ValidatorHealthEvent.seq,
                        )
                    )
                )
                .scalars()
                .all()
            )
        return list(rows)

    @staticmethod
    async def _add_event(
        session: AsyncSession,
        hotkey: str,
        event: ValidatorHealthEventType,
        created_at: datetime,
        *,
        message: str | None = None,
    ) -> None:
        max_seq = await session.scalar(
            select(func.coalesce(func.max(ValidatorHealthEvent.seq), 0))
        )
        next_seq = (max_seq or 0) + 1
        session.add(
            ValidatorHealthEvent(
                validator_hotkey=hotkey,
                event=event,
                message=message,
                created_at=created_at,
                seq=next_seq,
            )
        )
        # Flush so a later event in the same transaction observes this seq and
        # the monotonic ordering holds for same-instant appends.
        await session.flush()


def validator_to_view(validator: Validator) -> ValidatorView:
    """Convert a persisted validator row to its public view."""

    return ValidatorView(
        hotkey=validator.hotkey,
        uid=validator.uid,
        status=ValidatorStatus(validator.status).value,
        capabilities=list(validator.capabilities),
        subscriptions=list(validator.subscriptions),
        version=validator.version,
        registered_at=validator.registered_at,
        last_heartbeat_at=validator.last_heartbeat_at,
        last_seen_meta=dict(validator.last_seen_meta),
    )


def validator_validates_challenge(validator: Validator, slug: str) -> bool:
    """Whether ``validator`` validates ``slug``.

    A validator validates a challenge when it explicitly subscribed to that slug
    OR when it is unrestricted (an empty/absent subscription set == ALL
    challenges, mirroring the assignment filter and preserving back-compat).
    """

    subscriptions = validator.subscriptions
    return not subscriptions or slug in subscriptions


def public_validator_to_view(
    validator: Validator,
    resolver: ValidatorIdentityResolver | None = None,
) -> PublicValidatorView:
    """Convert a validator row to the safe, anonymous-facing directory view.

    Exposes ONLY safe fields and NEVER the raw ``last_seen_meta``, tokens, or any
    secret. When ``resolver`` is provided, the validator's display identity is
    resolved (on-chain, else the self-declared fallback) and only its
    ``display_name``/``logo_url`` are surfaced.
    """

    status_value = ValidatorStatus(validator.status)
    identity_view: PublicIdentityView | None = None
    if resolver is not None:
        resolved = resolver.resolve(validator.hotkey, validator.last_seen_meta)
        if resolved is not None and not resolved.is_empty:
            identity_view = PublicIdentityView(
                display_name=resolved.display_name,
                logo_url=resolved.logo_url,
            )
    return PublicValidatorView(
        hotkey=validator.hotkey,
        uid=validator.uid,
        status=status_value.value,
        online=status_value == ValidatorStatus.ONLINE,
        capabilities=list(validator.capabilities),
        subscriptions=list(validator.subscriptions),
        last_heartbeat_at=validator.last_heartbeat_at,
        identity=identity_view,
    )


async def _active_challenge_slugs(registry: Any) -> set[str]:
    """Return the set of active challenge slugs from the registry.

    Tolerates a registry whose ``list`` is sync or async (or absent), so the
    subscription route can validate slugs against the live active set.
    """

    lister = getattr(registry, "list", None)
    if lister is None:
        return set()
    result = lister(active_only=True)
    if inspect.isawaitable(result):
        result = await result
    return {record.slug for record in result}


def build_validator_coordination_router(
    *,
    service: ValidatorCoordinationService,
    auth_dependency: Callable[..., Any],
    admin_dependency: Callable[..., Any] | None = None,
    registry: Any = None,
) -> APIRouter:
    """Build the validator coordination router (register + heartbeat + read view).

    ``auth_dependency`` is the FastAPI dependency from
    :func:`base.security.validator_auth.build_validator_auth_dependency`; it
    yields a :class:`ValidatorIdentity` for an authenticated, eligible validator.
    ``admin_dependency`` (when provided) gates the token-protected admin read
    view ``GET /v1/validators``. ``registry`` (when provided) is the challenge
    registry used to validate subscription slugs against the active set.
    """

    router = APIRouter()

    @router.post("/v1/validators/register", response_model=ValidatorRegisterResponse)
    async def register_validator(
        payload: ValidatorRegisterRequest,
        identity: ValidatorIdentity = Depends(auth_dependency),
    ) -> ValidatorRegisterResponse:
        validator = await service.register(
            hotkey=identity.hotkey,
            uid=identity.uid,
            capabilities=payload.capabilities,
            version=payload.version,
            last_seen_meta=payload.last_seen_meta,
        )
        return ValidatorRegisterResponse(
            validator=validator_to_view(validator),
            heartbeat_interval_seconds=service.heartbeat_interval_seconds,
        )

    @router.post("/v1/validators/heartbeat", response_model=ValidatorHeartbeatResponse)
    async def heartbeat_validator(
        payload: ValidatorHeartbeatRequest,
        identity: ValidatorIdentity = Depends(auth_dependency),
    ) -> ValidatorHeartbeatResponse:
        try:
            validator, now = await service.heartbeat(
                hotkey=identity.hotkey,
                last_seen_meta=payload.last_seen_meta,
            )
        except ValidatorNotRegisteredError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="validator not registered",
            ) from exc
        return ValidatorHeartbeatResponse(
            status=ValidatorStatus(validator.status).value,
            now=now,
        )

    @router.post(
        "/v1/validators/subscriptions",
        response_model=ValidatorSubscriptionResponse,
    )
    async def set_subscriptions(
        payload: ValidatorSubscriptionRequest,
        identity: ValidatorIdentity = Depends(auth_dependency),
    ) -> ValidatorSubscriptionResponse:
        active = await _active_challenge_slugs(registry)
        unknown = [slug for slug in payload.slugs if slug not in active]
        if unknown:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"unknown or inactive challenge slug(s): {sorted(set(unknown))}",
            )
        try:
            validator = await service.set_subscriptions(
                hotkey=identity.hotkey,
                slugs=payload.slugs,
            )
        except ValidatorNotRegisteredError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="validator not registered",
            ) from exc
        return ValidatorSubscriptionResponse(
            validator=validator_to_view(validator),
            subscriptions=list(validator.subscriptions),
        )

    if admin_dependency is not None:

        @router.get(
            "/v1/validators",
            response_model=ValidatorListResponse,
            dependencies=[Depends(admin_dependency)],
        )
        async def list_validators() -> ValidatorListResponse:
            validators = await service.list_validators()
            return ValidatorListResponse(
                validators=[validator_to_view(row) for row in validators]
            )

    return router


async def run_validator_health_loop(
    service: ValidatorCoordinationService,
    *,
    interval_seconds: float,
    shutdown_event: asyncio.Event,
) -> None:
    """Run the crash-detection pass every ``interval_seconds`` until shutdown.

    A failing pass is logged and the loop continues, so one transient error
    never stops crash detection.
    """

    while not shutdown_event.is_set():
        try:
            await service.detect_offline_validators()
        except Exception:
            logger.exception("validator health detection pass failed")
        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=interval_seconds)
        except TimeoutError:
            continue


def build_validator_health_lifespan(
    service: ValidatorCoordinationService | None,
    interval_seconds: float | None,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]] | None:
    """Build a FastAPI lifespan that runs the crash-detection loop.

    Returns ``None`` (no lifespan) when detection is not configured, i.e. no
    validator service or a non-positive interval.
    """

    if service is None or interval_seconds is None or interval_seconds <= 0:
        return None

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> Any:
        shutdown = asyncio.Event()
        task = asyncio.create_task(
            run_validator_health_loop(
                service,
                interval_seconds=interval_seconds,
                shutdown_event=shutdown,
            )
        )
        try:
            yield
        finally:
            shutdown.set()
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    return lifespan
