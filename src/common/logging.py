"""Shared logging helpers for the MCP Scanner project."""
from __future__ import annotations

import logging
from typing import Optional

_LOGGER_CONFIGURED = False


def configure_logging(level: int = logging.INFO) -> None:
    """Configure the root logger if it has not been configured yet."""

    global _LOGGER_CONFIGURED
    if _LOGGER_CONFIGURED:
        return

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    _LOGGER_CONFIGURED = True


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a module-level logger configured with the shared settings."""

    configure_logging()
    return logging.getLogger(name if name else "mcp_scanner")


__all__ = ["configure_logging", "get_logger"]
