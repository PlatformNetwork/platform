"""SVG dashboard rendering for registered challenges."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from html import escape
from typing import Protocol

from platform_network.schemas.challenge import ChallengeRecord, ChallengeStatus


@dataclass(frozen=True)
class ChallengeMetrics:
    miner_count: int | None = None


@dataclass(frozen=True)
class DashboardChallenge:
    slug: str
    name: str
    description: str
    emission_percent: Decimal
    status: ChallengeStatus | str
    source: str = "live"


class ChallengeMetricsProvider(Protocol):
    def metrics_for(self, challenge: ChallengeRecord) -> ChallengeMetrics:
        """Return runtime metrics for a challenge."""


class EmptyChallengeMetricsProvider:
    def metrics_for(self, challenge: ChallengeRecord) -> ChallengeMetrics:
        return ChallengeMetrics()


def _status_color(status: ChallengeStatus | str) -> str:
    if status == ChallengeStatus.ACTIVE:
        return "#22c55e"
    if status == ChallengeStatus.INACTIVE:
        return "#f59e0b"
    if status == ChallengeStatus.DISABLED:
        return "#ef4444"
    return "#94a3b8"


def _status_background(status: ChallengeStatus | str) -> str:
    if status == ChallengeStatus.ACTIVE:
        return "#dcfce7"
    if status == ChallengeStatus.INACTIVE:
        return "#fef3c7"
    if status == ChallengeStatus.DISABLED:
        return "#fee2e2"
    return "#f1f5f9"


def _online_label(status: ChallengeStatus | str) -> str:
    return "online" if status == ChallengeStatus.ACTIVE else "offline"


def _format_emission(value: Decimal) -> str:
    normalized = value.normalize()
    text = format(normalized, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return f"{text}%"


def _format_miner_count(count: int | None) -> str:
    return "N/A" if count is None else str(count)


def _shorten(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[: max(0, limit - 1)].rstrip()}…"


def _to_dashboard_challenges(
    challenges: list[ChallengeRecord],
) -> list[DashboardChallenge]:
    return [
        DashboardChallenge(
            slug=challenge.slug,
            name=challenge.name,
            description=challenge.description or "Live Platform challenge",
            emission_percent=challenge.emission_percent,
            status=challenge.status,
        )
        for challenge in challenges
    ]


def render_challenges_dashboard_svg(
    challenges: list[ChallengeRecord],
    *,
    metrics_provider: ChallengeMetricsProvider | None = None,
) -> str:
    provider = metrics_provider or EmptyChallengeMetricsProvider()
    dashboard_challenges = _to_dashboard_challenges(challenges)
    sorted_challenges = sorted(
        dashboard_challenges, key=lambda challenge: challenge.slug
    )
    live_by_slug = {challenge.slug: challenge for challenge in challenges}
    row_height = 68
    header_height = 178
    width = 1120
    table_x = 34
    table_width = width - table_x * 2
    height = max(430, header_height + row_height * len(sorted_challenges) + 48)
    total_emission = sum(
        (challenge.emission_percent for challenge in sorted_challenges), Decimal("0")
    )
    active_count = sum(
        1
        for challenge in sorted_challenges
        if challenge.status == ChallengeStatus.ACTIVE
    )

    rows: list[str] = []
    if not sorted_challenges:
        rows.append(
            "\n".join(
                [
                    f'<rect x="{table_x}" y="{header_height + 8}" '
                    f'width="{table_width}" height="96" rx="28" '
                    'fill="#ffffff" fill-opacity="0.94" filter="url(#rowShadow)"/>',
                    f'<text x="{table_x + 40}" y="{header_height + 48}" '
                    'class="emptyTitle">No registered challenges</text>',
                    f'<text x="{table_x + 40}" y="{header_height + 72}" '
                    'class="emptyText">Create a challenge to populate this '
                    "dashboard.</text>",
                ]
            )
        )
    for index, challenge in enumerate(sorted_challenges):
        y = header_height + index * row_height
        status = str(challenge.status)
        metrics_record = live_by_slug.get(challenge.slug)
        metrics = (
            provider.metrics_for(metrics_record)
            if metrics_record
            else ChallengeMetrics()
        )
        status_color = _status_color(challenge.status)
        status_bg = _status_background(challenge.status)
        online = _online_label(challenge.status)
        online_bg = "#dbeafe" if online == "online" else "#f1f5f9"
        online_color = "#2563eb" if online == "online" else "#64748b"
        rows.append(
            "\n".join(
                [
                    f'<rect x="{table_x}" y="{y + 3}" width="{table_width}" '
                    'height="58" rx="24" fill="#ffffff" fill-opacity="0.94" '
                    'filter="url(#rowShadow)"/>',
                    f'<circle cx="62" cy="{y + 32}" r="12" fill="{status_bg}"/>',
                    f'<circle cx="62" cy="{y + 32}" r="5" fill="{status_color}"/>',
                    f'<text x="84" y="{y + 26}" class="cell strong">'
                    f"{escape(challenge.name)}</text>",
                    f'<text x="84" y="{y + 46}" class="small muted">'
                    f"{escape(challenge.slug)} · "
                    f"{escape(_shorten(challenge.description, 62))}</text>",
                    f'<rect x="562" y="{y + 20}" width="96" height="24" rx="12" '
                    f'fill="{status_bg}"/>',
                    f'<text x="580" y="{y + 37}" class="pill" fill="{status_color}">'
                    f"{escape(status)}</text>",
                    f'<rect x="688" y="{y + 20}" width="86" height="24" rx="12" '
                    f'fill="{online_bg}"/>',
                    f'<text x="706" y="{y + 37}" class="pill" fill="{online_color}">'
                    f"{online}</text>",
                    f'<text x="830" y="{y + 37}" class="cell number">'
                    f"{escape(_format_miner_count(metrics.miner_count))}</text>",
                    f'<text x="950" y="{y + 37}" class="cell number">'
                    f"{escape(_format_emission(challenge.emission_percent))}</text>",
                ]
            )
        )

    return "\n".join(
        [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
            f'height="{height}" viewBox="0 0 {width} {height}" role="img" '
            'aria-labelledby="title desc">',
            "<title>Platform challenge dashboard</title>",
            "<desc>Registered challenges with status, miners and emissions</desc>",
            "<defs>",
            '<linearGradient id="page" x1="0" x2="1" y1="0" y2="1">',
            '<stop offset="0%" stop-color="#020617"/>',
            '<stop offset="48%" stop-color="#0f172a"/>',
            '<stop offset="100%" stop-color="#164e63"/>',
            "</linearGradient>",
            '<radialGradient id="glow" cx="50%" cy="0%" r="70%">',
            '<stop offset="0%" stop-color="#38bdf8" stop-opacity="0.42"/>',
            '<stop offset="100%" stop-color="#38bdf8" stop-opacity="0"/>',
            "</radialGradient>",
            '<linearGradient id="heroCard" x1="0" x2="1" y1="0" y2="1">',
            '<stop offset="0%" stop-color="#ffffff" stop-opacity="0.98"/>',
            '<stop offset="100%" stop-color="#ecfeff" stop-opacity="0.92"/>',
            "</linearGradient>",
            '<filter id="cardShadow" x="-5%" y="-15%" width="110%" height="140%">',
            '<feDropShadow dx="0" dy="22" stdDeviation="18" '
            'flood-color="#000000" flood-opacity="0.24"/>',
            "</filter>",
            '<filter id="rowShadow" x="-4%" y="-40%" width="108%" height="190%">',
            '<feDropShadow dx="0" dy="10" stdDeviation="8" '
            'flood-color="#0f172a" flood-opacity="0.12"/>',
            "</filter>",
            "</defs>",
            "<style>",
            "text{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}",
            ".title{font-size:30px;font-weight:850;fill:#0f172a}",
            ".summary{font-size:14px;fill:#475569}",
            ".kpiLabel{font-size:11px;font-weight:800;fill:#64748b;letter-spacing:.08em}",
            ".kpiValue{font-size:22px;font-weight:850;fill:#0f172a}",
            ".head{font-size:11px;font-weight:850;fill:#cbd5e1;letter-spacing:.10em}",
            ".cell{font-size:14px;fill:#1e293b}",
            ".small{font-size:12px;fill:#64748b}",
            ".strong{font-weight:750}",
            ".muted{fill:#64748b}",
            ".pill{font-size:12px;font-weight:850}",
            ".number{font-weight:700}",
            ".emptyIcon{font-size:20px;font-weight:850;fill:#0284c7}",
            ".emptyTitle{font-size:18px;font-weight:850;fill:#0f172a}",
            ".emptyText{font-size:13px;fill:#64748b}",
            "</style>",
            '<rect width="100%" height="100%" rx="38" fill="url(#page)"/>',
            '<rect width="100%" height="100%" rx="38" fill="url(#glow)"/>',
            f'<rect x="24" y="24" width="{width - 48}" height="{height - 48}" '
            'rx="34" fill="#f8fafc" fill-opacity="0.08" stroke="#ffffff" '
            'stroke-opacity="0.16"/>',
            '<circle cx="900" cy="72" r="92" fill="#22d3ee" opacity="0.16"/>',
            '<circle cx="84" cy="332" r="120" fill="#818cf8" opacity="0.12"/>',
            f'<rect x="34" y="34" width="{table_width}" height="96" rx="30" '
            'fill="url(#heroCard)" filter="url(#cardShadow)"/>',
            '<text id="title" x="64" y="76" class="title">Platform challenges</text>',
            f'<text id="desc" x="64" y="100" class="summary">'
            f"{len(sorted_challenges)} challenges · {active_count} active · "
            f"{escape(_format_emission(total_emission))} emissions · refreshable"
            "</text>",
            '<rect x="612" y="54" width="86" height="56" rx="18" fill="#eff6ff"/>',
            f'<text x="632" y="76" class="kpiValue">{len(sorted_challenges)}</text>',
            '<text x="632" y="96" class="kpiLabel">TOTAL</text>',
            '<rect x="714" y="54" width="86" height="56" rx="18" fill="#dcfce7"/>',
            f'<text x="734" y="76" class="kpiValue">{active_count}</text>',
            '<text x="734" y="96" class="kpiLabel">ACTIVE</text>',
            '<rect x="816" y="54" width="112" height="56" rx="18" fill="#ecfeff"/>',
            '<text x="836" y="76" class="kpiValue">'
            f"{escape(_format_emission(total_emission))}</text>",
            '<text x="836" y="96" class="kpiLabel">EMISSIONS</text>',
            f'<rect x="{table_x}" y="150" width="{table_width}" height="38" '
            'rx="19" fill="#ffffff" fill-opacity="0.14" stroke="#ffffff" '
            'stroke-opacity="0.12"/>',
            '<text x="84" y="174" class="head">Challenge</text>',
            '<text x="580" y="174" class="head">Status</text>',
            '<text x="706" y="174" class="head">Online</text>',
            '<text x="830" y="174" class="head">Miners</text>',
            '<text x="950" y="174" class="head">Emissions</text>',
            *rows,
            "</svg>",
        ]
    )
