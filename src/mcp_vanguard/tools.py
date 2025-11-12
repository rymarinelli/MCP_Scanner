"""Tool registry for MCP Vanguard.

This module is imported on application start-up to ensure side effects such as
registering tools are executed before handling requests. The concrete
implementation lives elsewhere in the project.
"""

from __future__ import annotations

INITIALIZED = True


def register_tool(name: str, func) -> None:
    """Placeholder registration function."""
    raise NotImplementedError("Tool registration should be implemented by the application.")
