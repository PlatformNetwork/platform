from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class MetagraphCache:
    netuid: int
    ttl_seconds: int = 300
    subtensor: Any | None = None
    _hotkey_to_uid: dict[str, int] = field(default_factory=dict)
    _updated_at: float = 0.0

    @property
    def hotkey_to_uid(self) -> dict[str, int]:
        return dict(self._hotkey_to_uid)

    def expired(self) -> bool:
        return time.time() - self._updated_at > self.ttl_seconds

    def update_from_hotkeys(self, hotkeys: list[str]) -> dict[str, int]:
        self._hotkey_to_uid = {hotkey: uid for uid, hotkey in enumerate(hotkeys)}
        self._updated_at = time.time()
        return self.hotkey_to_uid

    def refresh(self) -> dict[str, int]:
        if self.subtensor is None:
            raise RuntimeError("Subtensor is required to refresh metagraph")
        metagraph = self.subtensor.metagraph(self.netuid)
        hotkeys = list(getattr(metagraph, "hotkeys", []))
        return self.update_from_hotkeys(hotkeys)

    def get(self, *, force: bool = False) -> dict[str, int]:
        if force or self.expired():
            return self.refresh()
        return self.hotkey_to_uid
