from __future__ import annotations

import pytest

from platform_network.bittensor.metagraph_cache import MetagraphCache
from platform_network.bittensor.weight_setter import WeightSetter


def test_metagraph_cache_from_hotkeys() -> None:
    cache = MetagraphCache(netuid=1)
    assert cache.update_from_hotkeys(["a", "b"]) == {"a": 0, "b": 1}


def test_weight_setter_requires_subtensor() -> None:
    with pytest.raises(RuntimeError, match="Subtensor is required"):
        WeightSetter(subtensor=None, wallet=None, netuid=1).set_weights([1], [1.0])
