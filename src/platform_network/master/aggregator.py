from __future__ import annotations

import math
from collections import defaultdict

from platform_network.schemas.weights import ChallengeWeightsResult, FinalWeights


def _clean_weights(raw: dict[str, float]) -> dict[str, float]:
    cleaned: dict[str, float] = {}
    for hotkey, value in raw.items():
        weight = float(value)
        if not math.isfinite(weight):
            continue
        if weight <= 0:
            continue
        cleaned[str(hotkey)] = weight
    return cleaned


def normalize_weights(raw: dict[str, float]) -> dict[str, float]:
    cleaned = _clean_weights(raw)
    total = sum(cleaned.values())
    if total <= 0:
        return {}
    return {hotkey: value / total for hotkey, value in cleaned.items()}


def normalize_emissions(results: list[ChallengeWeightsResult]) -> dict[str, float]:
    active = {r.slug: max(float(r.emission_percent), 0.0) for r in results if r.ok}
    total = sum(active.values())
    if total <= 0:
        return {slug: 0.0 for slug in active}
    return {slug: value / total for slug, value in active.items()}


def aggregate_challenge_weights(
    challenge_results: list[ChallengeWeightsResult],
    hotkey_to_uid: dict[str, int],
) -> FinalWeights:
    emissions = normalize_emissions(challenge_results)
    hotkey_scores: defaultdict[str, float] = defaultdict(float)

    for result in challenge_results:
        if not result.ok:
            continue
        emission = emissions.get(result.slug, 0.0)
        for hotkey, weight in normalize_weights(result.weights).items():
            hotkey_scores[hotkey] += emission * weight

    uid_scores: defaultdict[int, float] = defaultdict(float)
    kept_hotkeys: dict[str, float] = {}
    for hotkey, weight in hotkey_scores.items():
        uid = hotkey_to_uid.get(hotkey)
        if uid is None:
            continue
        if uid == 0:
            continue
        uid_scores[uid] += weight
        kept_hotkeys[hotkey] = weight

    total = sum(uid_scores.values())
    if total > 0:
        normalized = {uid: value / total for uid, value in uid_scores.items()}
    else:
        normalized = {}

    ordered = sorted(normalized.items())
    return FinalWeights(
        uids=[uid for uid, _ in ordered],
        weights=[weight for _, weight in ordered],
        hotkey_weights=kept_hotkeys,
    )
