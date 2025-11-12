"""Core utilities for MCP Vanguard tools."""
from collections.abc import Callable
from typing import Any, Dict

TOOL_REGISTRY: Dict[str, Callable[..., Any]] = {}


def register_tool(name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Register a callable as a tool under the provided ``name``.

    Parameters
    ----------
    name:
        The identifier that should be associated with the decorated tool.

    Returns
    -------
    Callable
        A decorator that stores the wrapped callable inside :data:`TOOL_REGISTRY`.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        if not callable(func):
            raise TypeError("Tools must be callable")

        TOOL_REGISTRY[name] = func
        return func

    return decorator


def run_tool(name: str, /, **params: Any) -> Any:
    """Execute the tool registered under ``name`` with ``params``.

    Parameters
    ----------
    name:
        The registered name of the tool to execute.
    **params:
        Keyword arguments forwarded to the tool callable.

    Raises
    ------
    KeyError
        If no tool is registered under ``name``.
    """

    if name not in TOOL_REGISTRY:
        raise KeyError(f"No tool registered under name '{name}'")

    return TOOL_REGISTRY[name](**params)


__all__ = ["TOOL_REGISTRY", "register_tool", "run_tool"]
