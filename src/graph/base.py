"""Base graph client interfaces."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any


class GraphClient(ABC):
    """Abstract graph client defining operations used by scanners."""

    @abstractmethod
    def connect(self) -> None:
        """Establish a connection to the graph provider."""

    @abstractmethod
    def close(self) -> None:
        """Close any open connections."""

    @abstractmethod
    def upsert_nodes(self, nodes: Iterable[dict[str, Any]]) -> None:
        """Create or update nodes in the backing graph store."""

    @abstractmethod
    def upsert_edges(self, edges: Iterable[dict[str, Any]]) -> None:
        """Create or update relationships in the backing graph store."""


__all__ = ["GraphClient"]
