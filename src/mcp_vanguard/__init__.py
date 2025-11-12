"""MCP Vanguard package initialization."""
from . import core, tools
from .core import TOOL_REGISTRY, register_tool, run_tool

# Ensure all tool modules are imported so that the registry is populated.
tools.ensure_tools_registered()

__all__ = [
    "TOOL_REGISTRY",
    "register_tool",
    "run_tool",
]
