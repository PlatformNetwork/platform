from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any

from base.bittensor.metagraph_cache import MetagraphCache
from base.bittensor.weight_setter import WeightSetter
from base.config.settings import Settings


class BittensorDependencyError(RuntimeError):
    pass


@dataclass(frozen=True)
class BittensorRuntime:
    metagraph_cache: MetagraphCache
    weight_setter: WeightSetter | None = None


def _load_bittensor() -> Any:
    try:
        return importlib.import_module("bittensor")
    except ImportError as exc:
        raise BittensorDependencyError(
            "Install the bittensor extra to submit weights: "
            "`pip install 'base[bittensor]'`."
        ) from exc


def _create_subtensor(settings: Settings) -> Any:
    bittensor = _load_bittensor()
    subtensor_kwargs = {}
    if settings.network.chain_endpoint:
        subtensor_kwargs["network"] = settings.network.chain_endpoint
    return bittensor.Subtensor(**subtensor_kwargs)


def _create_wallet(settings: Settings) -> Any:
    bittensor = _load_bittensor()
    wallet_kwargs = {
        "name": settings.network.wallet_name,
        "hotkey": settings.network.wallet_hotkey,
    }
    if settings.network.wallet_path:
        wallet_kwargs["path"] = settings.network.wallet_path
    return bittensor.Wallet(**wallet_kwargs)


def create_validator_keypair(settings: Settings) -> Any:
    """Return the validator hotkey keypair used to sign coordination requests."""

    return _create_wallet(settings).hotkey


def _seed_mock_metagraph_cache(settings: Settings) -> MetagraphCache | None:
    """Seed a static ``MetagraphCache`` from ``network.mock_metagraph``.

    Returns ``None`` (the seam is OFF) when no static nodes are configured, so
    the live-metagraph path is unchanged. When configured the cache is marked
    ``static`` and carries no subtensor, so eligibility is served entirely from
    the configured set without ever constructing a live Subtensor.
    """

    nodes = settings.network.mock_metagraph
    if not nodes:
        return None
    cache = MetagraphCache(
        netuid=settings.network.netuid,
        ttl_seconds=settings.master.metagraph_cache_ttl_seconds,
        subtensor=None,
        static=True,
    )
    cache.update_from_metagraph(
        [node.hotkey for node in nodes],
        uids=[
            node.uid if node.uid is not None else index
            for index, node in enumerate(nodes)
        ],
        validator_permits=[node.validator_permit for node in nodes],
        stakes=[node.stake for node in nodes],
    )
    return cache


def create_bittensor_runtime(settings: Settings) -> BittensorRuntime:
    mock_cache = _seed_mock_metagraph_cache(settings)
    if mock_cache is not None:
        return BittensorRuntime(metagraph_cache=mock_cache)
    subtensor = _create_subtensor(settings)
    return BittensorRuntime(
        metagraph_cache=MetagraphCache(
            netuid=settings.network.netuid,
            ttl_seconds=settings.master.metagraph_cache_ttl_seconds,
            subtensor=subtensor,
        ),
    )


def create_bittensor_submit_runtime(settings: Settings) -> BittensorRuntime:
    subtensor = _create_subtensor(settings)
    wallet = _create_wallet(settings)
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
