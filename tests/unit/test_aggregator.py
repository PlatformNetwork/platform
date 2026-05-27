from __future__ import annotations

from platform_network.master.aggregator import (
    aggregate_challenge_weights,
    normalize_weights,
)
from platform_network.schemas.weights import ChallengeWeightsResult


def test_normalize_weights_clamps_invalid_values() -> None:
    assert normalize_weights({"a": 2, "b": -1, "c": float("nan"), "d": 2}) == {
        "a": 0.5,
        "d": 0.5,
    }


def test_aggregate_normalizes_emissions_and_ignores_unknown_hotkeys() -> None:
    results = [
        ChallengeWeightsResult(
            slug="a", emission_percent=40, weights={"hk1": 1, "missing": 3}
        ),
        ChallengeWeightsResult(slug="b", emission_percent=60, weights={"hk2": 2}),
    ]
    final = aggregate_challenge_weights(results, {"hk1": 1, "hk2": 2})
    assert final.uids == [1, 2]
    assert round(sum(final.weights), 8) == 1.0
    assert round(final.weights[0], 8) == round(1 / 7, 8)
    assert round(final.weights[1], 8) == round(6 / 7, 8)


def test_prism_and_agent_challenge_emissions_normalize_by_successful_total() -> None:
    results = [
        ChallengeWeightsResult(
            slug="prism", emission_percent=30, weights={"prism-hotkey": 1}
        ),
        ChallengeWeightsResult(
            slug="agent-challenge", emission_percent=15, weights={"agent-hotkey": 1}
        ),
        ChallengeWeightsResult(
            slug="other-active", emission_percent=5, weights={"other-hotkey": 1}
        ),
        ChallengeWeightsResult(
            slug="failed-active",
            emission_percent=50,
            weights={"failed-hotkey": 1},
            ok=False,
        ),
    ]

    source_emissions = {result.slug: result.emission_percent for result in results}
    assert source_emissions["prism"] == 30
    assert source_emissions["agent-challenge"] == 15

    final = aggregate_challenge_weights(
        results,
        {
            "prism-hotkey": 30,
            "agent-hotkey": 15,
            "other-hotkey": 5,
            "failed-hotkey": 50,
        },
    )

    assert final.uids == [5, 15, 30]
    assert [round(weight, 8) for weight in final.weights] == [
        round(5 / 50, 8),
        round(15 / 50, 8),
        round(30 / 50, 8),
    ]
    assert final.hotkey_weights == {
        "prism-hotkey": 30 / 50,
        "agent-hotkey": 15 / 50,
        "other-hotkey": 5 / 50,
    }


def test_failed_challenge_contributes_zero() -> None:
    results = [
        ChallengeWeightsResult(slug="a", emission_percent=50, weights={"hk1": 1}),
        ChallengeWeightsResult(
            slug="b", emission_percent=50, weights={"hk2": 1}, ok=False
        ),
    ]
    final = aggregate_challenge_weights(results, {"hk1": 1, "hk2": 2})
    assert final.uids == [1]
    assert final.weights == [1.0]


def test_aggregate_falls_back_to_uid_zero_without_active_challenges() -> None:
    final = aggregate_challenge_weights([], {})

    assert final.uids == [0]
    assert final.weights == [1.0]
    assert final.hotkey_weights == {}


def test_aggregate_falls_back_to_uid_zero_for_empty_challenge_weights() -> None:
    results = [ChallengeWeightsResult(slug="a", emission_percent=100, weights={})]

    final = aggregate_challenge_weights(results, {"validator": 0})

    assert final.uids == [0]
    assert final.weights == [1.0]
    assert final.hotkey_weights == {}


def test_aggregate_falls_back_to_uid_zero_for_uid_zero_only_weights() -> None:
    results = [
        ChallengeWeightsResult(slug="a", emission_percent=100, weights={"validator": 1})
    ]

    final = aggregate_challenge_weights(results, {"validator": 0})

    assert final.uids == [0]
    assert final.weights == [1.0]
    assert final.hotkey_weights == {}
