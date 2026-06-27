"""Database layer for the base network master service."""

from base.db.base import Base
from base.db.models import (
    Challenge,
    ChallengeAuth,
    ChallengeCapability,
    ChallengeEnv,
    ChallengeHealthEvent,
    ChallengeImage,
    ChallengeResource,
    ChallengeRoute,
    ChallengeSecret,
    ChallengeStatus,
    ChallengeVolume,
    LlmUsageRecord,
    MinerRequestNonce,
    Validator,
    ValidatorHealthEvent,
    ValidatorHealthEventType,
    ValidatorRequestNonce,
    ValidatorStatus,
)
from base.db.repositories import ChallengeRepository
from base.db.session import (
    create_engine,
    create_session_factory,
    session_scope,
)

__all__ = [
    "Base",
    "Challenge",
    "ChallengeAuth",
    "ChallengeCapability",
    "ChallengeEnv",
    "ChallengeHealthEvent",
    "ChallengeImage",
    "ChallengeRepository",
    "ChallengeResource",
    "ChallengeRoute",
    "ChallengeSecret",
    "ChallengeStatus",
    "ChallengeVolume",
    "LlmUsageRecord",
    "MinerRequestNonce",
    "Validator",
    "ValidatorHealthEvent",
    "ValidatorHealthEventType",
    "ValidatorRequestNonce",
    "ValidatorStatus",
    "create_engine",
    "create_session_factory",
    "session_scope",
]
