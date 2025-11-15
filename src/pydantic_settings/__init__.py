"""Lightweight stand-in for :mod:`pydantic_settings` used in tests."""
from __future__ import annotations

import os
from typing import Any, Dict

from pydantic import BaseModel

__all__ = ["BaseSettings", "SettingsConfigDict"]


class SettingsConfigDict(dict):
    """Dictionary-based configuration compatible with Pydantic v2."""

    pass


class BaseSettings(BaseModel):
    """Minimal settings base that reads environment variable overrides."""

    model_config: SettingsConfigDict = SettingsConfigDict()

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        overrides = self._collect_env_overrides()
        if overrides:
            self._apply_overrides(overrides)

    @classmethod
    def _collect_env_overrides(cls) -> Dict[str, Any]:
        config = getattr(cls, "model_config", {}) or {}
        prefix = config.get("env_prefix", "")
        delimiter = config.get("env_nested_delimiter", "__")
        if not prefix:
            return {}

        overrides: Dict[str, Any] = {}
        for env_key, raw_value in os.environ.items():
            if not env_key.startswith(prefix):
                continue
            remainder = env_key[len(prefix) :]
            if not remainder:
                continue
            path = [remainder]
            if delimiter:
                path = [segment for segment in remainder.split(delimiter) if segment]
            target = overrides
            for segment in path[:-1]:
                target = target.setdefault(segment.lower(), {})  # type: ignore[assignment]
            target[path[-1].lower()] = raw_value
        return overrides

    def _apply_overrides(self, overrides: Dict[str, Any]) -> None:
        for field, value in overrides.items():
            self._assign_override(self, field, value)

    def _assign_override(self, target: Any, field: str, value: Any) -> None:
        attr = getattr(target, field, None)
        if isinstance(value, dict) and isinstance(attr, BaseModel):
            for sub_field, sub_value in value.items():
                self._assign_override(attr, sub_field, sub_value)
            return
        setattr(target, field, value)
