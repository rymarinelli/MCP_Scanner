"""Tool registry for MCP Vanguard."""
from __future__ import annotations

from typing import Any, Callable, Dict

ToolCallable = Callable[..., Any]

TOOL_REGISTRY: Dict[str, ToolCallable] = {}


def register_tool(name: str) -> Callable[[ToolCallable], ToolCallable]:
    """Register a callable as a tool under ``name``."""

    def decorator(func: ToolCallable) -> ToolCallable:
        TOOL_REGISTRY[name] = func
        return func

    return decorator


@register_tool("echo")
def echo_tool(**parameters: Any) -> Dict[str, Any]:
    """Simple echo tool used for examples and smoke tests."""

    return {
        "received": parameters,
    }
