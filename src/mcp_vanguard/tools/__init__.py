"""Tool registration and discovery for MCP Vanguard."""
from importlib import import_module
from pathlib import Path
from typing import Iterable
import pkgutil

from ..core import register_tool

__all__ = ["register_tool", "ensure_tools_registered"]

_TOOLS_REGISTERED = False


def _iter_tool_module_names() -> Iterable[str]:
    package_dir = Path(__file__).resolve().parent
    for module_info in pkgutil.iter_modules([str(package_dir)]):
        if module_info.ispkg:
            continue
        name = module_info.name
        if name.startswith("_") or name == "__init__":
            continue
        yield name


def ensure_tools_registered() -> None:
    """Import every tool module exactly once so decorators execute."""
    global _TOOLS_REGISTERED
    if _TOOLS_REGISTERED:
        return

    for module_name in _iter_tool_module_names():
        import_module(f"{__name__}.{module_name}")

    _TOOLS_REGISTERED = True
