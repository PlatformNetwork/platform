from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from platform_network.bittensor.factory import (
    BittensorDependencyError,
    create_bittensor_runtime,
)
from platform_network.config.loader import load_settings


def _settings(tmp_path: Path):
    config = tmp_path / "config.yaml"
    config.write_text(
        "\n".join(
            [
                "network:",
                "  netuid: 42",
                "  chain_endpoint: ws://localhost:9944",
                "  wallet_name: test-wallet",
                "  wallet_hotkey: test-hotkey",
                "master:",
                "  metagraph_cache_ttl_seconds: 5",
            ]
        ),
        encoding="utf-8",
    )
    return load_settings(config)


def test_bittensor_runtime_uses_configured_network_and_wallet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    class Subtensor:
        def __init__(self, **kwargs: object) -> None:
            calls.append(("subtensor", kwargs))

    class Wallet:
        def __init__(self, **kwargs: object) -> None:
            calls.append(("wallet", kwargs))

    monkeypatch.setitem(
        sys.modules,
        "bittensor",
        SimpleNamespace(Subtensor=Subtensor, Wallet=Wallet),
    )

    runtime = create_bittensor_runtime(_settings(tmp_path))

    assert runtime.metagraph_cache.netuid == 42
    assert runtime.metagraph_cache.ttl_seconds == 5
    assert runtime.weight_setter.netuid == 42
    assert calls == [
        ("subtensor", {"network": "ws://localhost:9944"}),
        ("wallet", {"name": "test-wallet", "hotkey": "test-hotkey"}),
    ]


def test_bittensor_runtime_requires_dependency_for_submit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "bittensor", None)

    with pytest.raises(BittensorDependencyError):
        create_bittensor_runtime(_settings(tmp_path))
