from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from platform_network.config.settings import Settings


def _parse_env_value(value: str) -> Any:
    stripped = value.strip()
    if stripped.startswith(("[", "{")):
        parsed = yaml.safe_load(stripped)
        if isinstance(parsed, list | dict):
            return parsed
    return value


def _set_nested(data: dict[str, Any], path: list[str], value: Any) -> None:
    node = data
    for part in path[:-1]:
        node = node.setdefault(part, {})
    node[path[-1]] = value


def _apply_env(data: dict[str, Any], prefix: str = "PLATFORM_") -> dict[str, Any]:
    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
        raw = key[len(prefix) :].lower()
        _set_nested(data, raw.split("__"), _parse_env_value(value))
    return data


def load_settings(path: str | Path | None = None) -> Settings:
    data: dict[str, Any] = {}
    if path:
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"Config file must contain a mapping: {config_path}")
        data.update(loaded)
    return Settings.model_validate(_apply_env(data))
