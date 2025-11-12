"""Simple connectivity check tool."""
from __future__ import annotations

from typing import Any, Dict

from . import register_tool


@register_tool("ping")
def ping(*, message: str | None = None) -> Dict[str, Any]:
    """Return a pong-style payload useful for health checks."""
    payload = {"status": "ok", "message": message or "pong"}
    return payload


__all__ = ["ping"]
