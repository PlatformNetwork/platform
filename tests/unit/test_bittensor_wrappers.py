from __future__ import annotations

import pytest

from base.bittensor.metagraph_cache import MetagraphCache
from base.bittensor.weight_setter import WeightSetter


def test_metagraph_cache_from_hotkeys() -> None:
    cache = MetagraphCache(netuid=1)
    assert cache.update_from_hotkeys(["a", "b"]) == {"a": 0, "b": 1}


def test_weight_setter_requires_subtensor() -> None:
    with pytest.raises(RuntimeError, match="Subtensor is required"):
        WeightSetter(subtensor=None, wallet=None, netuid=1).set_weights([1], [1.0])


def test_weight_setter_allows_uid_zero_fallback() -> None:
    class Subtensor:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def set_weights(self, **kwargs: object) -> dict[str, object]:
            self.calls.append(kwargs)
            return {"ok": True, **kwargs}

    subtensor = Subtensor()

    result = WeightSetter(subtensor=subtensor, wallet="wallet", netuid=1).set_weights(
        [0], [1.0]
    )

    assert result["ok"] is True
    assert subtensor.calls == [
        {
            "wallet": "wallet",
            "netuid": 1,
            "uids": [0],
            "weights": [1.0],
            "version_key": 0,
            "wait_for_inclusion": False,
            "wait_for_finalization": False,
        }
    ]


@pytest.mark.parametrize(
    ("result", "match"),
    [
        (False, "subtensor rejected weight submission"),
        ((False, "chain rejected"), "chain rejected"),
        ([False, "chain rejected"], "chain rejected"),
    ],
)
def test_weight_setter_raises_on_rejected_set_weights_result(
    result: object,
    match: str,
) -> None:
    class Subtensor:
        def set_weights(self, **kwargs: object) -> object:
            return result

    with pytest.raises(RuntimeError, match=match):
        WeightSetter(subtensor=Subtensor(), wallet="wallet", netuid=1).set_weights(
            [1], [1.0]
        )


class _FakeExtrinsicResponse:
    """Duck-typed stand-in for bittensor's ``ExtrinsicResponse`` dataclass.

    The real type exposes ``success: bool`` and ``message: Optional[str]`` and is
    NOT a ``bool``/``tuple``/``list`` (and defines no ``__bool__``), so a failed
    response is still truthy. This fake reproduces exactly that contract so the
    rejection-detection logic is exercised without importing bittensor.
    """

    def __init__(self, success: bool, message: str | None = None) -> None:
        self.success = success
        self.message = message


def test_weight_setter_passes_version_key_zero_for_commit_reveal() -> None:
    # netuid 100 has commit-reveal ENABLED; subtensor.set_weights auto-routes to
    # the timelocked CR path and uses `version_key` (recon weights_version=0).
    captured: dict[str, object] = {}

    class Subtensor:
        def set_weights(self, **kwargs: object) -> object:
            captured.update(kwargs)
            return _FakeExtrinsicResponse(success=True, message=None)

    result = WeightSetter(
        subtensor=Subtensor(), wallet="wallet", netuid=100
    ).set_weights([0], [1.0])

    assert captured["version_key"] == 0
    assert result.success is True  # type: ignore[attr-defined]


def test_weight_setter_surfaces_extrinsic_response_rejection() -> None:
    # The core bug: a rejected ExtrinsicResponse (success=False) must NOT be
    # silently treated as success. The setter must raise with the chain message.
    class Subtensor:
        def set_weights(self, **kwargs: object) -> object:
            return _FakeExtrinsicResponse(
                success=False, message="SettingWeightsTooFast"
            )

    with pytest.raises(RuntimeError, match="SettingWeightsTooFast"):
        WeightSetter(subtensor=Subtensor(), wallet="wallet", netuid=100).set_weights(
            [0], [1.0]
        )


def test_weight_setter_accepts_successful_extrinsic_response() -> None:
    response = _FakeExtrinsicResponse(success=True, message=None)

    class Subtensor:
        def set_weights(self, **kwargs: object) -> object:
            return response

    result = WeightSetter(
        subtensor=Subtensor(), wallet="wallet", netuid=100
    ).set_weights([0], [1.0])

    assert result is response
