from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def is_rejected_set_weights_result(result: Any) -> bool:
    # bittensor >=10 returns ``ExtrinsicResponse`` (a dataclass with a ``success``
    # bool), NOT a bool/tuple and with no ``__bool__`` -- a failed response is
    # still truthy. Detect rejection via ``.success`` first; the legacy bool/tuple
    # shapes below remain for older mocks/callers. Without the ``.success`` branch
    # a rejected commit-reveal submission is silently treated as success.
    success = getattr(result, "success", None)
    if success is not None:
        return not bool(success)
    if result is False:
        return True
    if isinstance(result, (tuple, list)) and result and result[0] is False:
        return True
    return False


def set_weights_rejection_message(result: Any) -> str:
    if getattr(result, "success", None) is not None:
        message = getattr(result, "message", None)
        if message:
            return f"subtensor rejected weight submission: {message}"
        return "subtensor rejected weight submission"
    if isinstance(result, (tuple, list)) and len(result) > 1:
        return f"subtensor rejected weight submission: {result[1]}"
    return "subtensor rejected weight submission"


@dataclass
class WeightSetter:
    subtensor: Any | None
    wallet: Any | None
    netuid: int
    # netuid 100 has commit-reveal ENABLED; subtensor.set_weights auto-routes to
    # the timelocked CR path and signs with this version_key (recon: on-chain
    # weights_version == 0).
    version_key: int = 0

    def set_weights(self, uids: list[int], weights: list[float]) -> Any:
        if not uids:
            raise ValueError("Cannot submit empty weights")
        if self.subtensor is None:
            raise RuntimeError("Subtensor is required to submit weights")
        if self.wallet is None:
            raise RuntimeError("Wallet is required to submit weights")
        result = self.subtensor.set_weights(
            wallet=self.wallet,
            netuid=self.netuid,
            uids=uids,
            weights=weights,
            version_key=self.version_key,
            wait_for_inclusion=False,
            wait_for_finalization=False,
        )
        if is_rejected_set_weights_result(result):
            raise RuntimeError(set_weights_rejection_message(result))
        return result
