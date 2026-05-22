from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any

from platform_network.bittensor.metagraph_cache import MetagraphCache
from platform_network.bittensor.weight_setter import WeightSetter
from platform_network.config.settings import Settings


class BittensorDependencyError(RuntimeError):
    pass


@dataclass(frozen=True)
class BittensorRuntime:
    metagraph_cache: MetagraphCache
    weight_setter: WeightSetter


def _load_bittensor() -> Any:
    try:
        return importlib.import_module("bittensor")
    except ImportError as exc:
        raise BittensorDependencyError(
            "Install the bittensor extra to submit weights: "
            "`pip install 'platform-network[bittensor]'`."
        ) from exc


def create_bittensor_runtime(settings: Settings) -> BittensorRuntime:
    bittensor = _load_bittensor()
    subtensor_kwargs = {}
    if settings.network.chain_endpoint:
        subtensor_kwargs["network"] = settings.network.chain_endpoint
    subtensor = bittensor.Subtensor(**subtensor_kwargs)
    wallet_kwargs = {
        "name": settings.network.wallet_name,
        "hotkey": settings.network.wallet_hotkey,
    }
    if settings.network.wallet_path:
        wallet_kwargs["path"] = settings.network.wallet_path
    wallet = bittensor.Wallet(**wallet_kwargs)

    return BittensorRuntime(
        metagraph_cache=MetagraphCache(
            netuid=settings.network.netuid,
            ttl_seconds=settings.master.metagraph_cache_ttl_seconds,
            subtensor=subtensor,
        ),
        weight_setter=WeightSetter(
            subtensor=subtensor,
            wallet=wallet,
            netuid=settings.network.netuid,
        ),
    )
