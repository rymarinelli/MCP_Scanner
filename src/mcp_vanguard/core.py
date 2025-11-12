"""Core execution helpers for MCP Vanguard tools."""
from __future__ import annotations

from typing import Any, Dict

from .registry import TOOL_REGISTRY


class ToolNotFoundError(LookupError):
    """Raised when a requested tool is not present in the registry."""


class ToolExecutionError(RuntimeError):
    """Raised when a tool encounters an unexpected error."""


ToolResponse = Dict[str, Any]


def run_tool(tool_name: str, parameters: Dict[str, Any] | None = None) -> ToolResponse:
    """Execute a tool from the registry and return a HTTP-style response."""

    parameters = parameters or {}

    if tool_name not in TOOL_REGISTRY:
        return {
            "status": "error",
            "error": {
                "type": "ToolNotFound",
                "message": f"Unknown tool: {tool_name}",
            },
        }

    tool = TOOL_REGISTRY[tool_name]

    try:
        result = tool(**parameters)
    except Exception as exc:  # pragma: no cover - defensive wrapper
        return {
            "status": "error",
            "tool": tool_name,
            "error": {
                "type": exc.__class__.__name__,
                "message": str(exc) or repr(exc),
            },
        }

    return {
        "status": "success",
        "tool": tool_name,
        "result": result,
    }
