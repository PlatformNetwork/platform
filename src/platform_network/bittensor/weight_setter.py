from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class WeightSetter:
    subtensor: Any | None
    wallet: Any | None
    netuid: int

    def set_weights(self, uids: list[int], weights: list[float]) -> Any:
        if 0 in uids:
            raise ValueError("UID 0 cannot receive submitted weights")
        if not uids:
            raise ValueError("Cannot submit empty weights")
        if self.subtensor is None:
            raise RuntimeError("Subtensor is required to submit weights")
        if self.wallet is None:
            raise RuntimeError("Wallet is required to submit weights")
        return self.subtensor.set_weights(
            wallet=self.wallet,
            netuid=self.netuid,
            uids=uids,
            weights=weights,
            wait_for_inclusion=False,
            wait_for_finalization=False,
        )
