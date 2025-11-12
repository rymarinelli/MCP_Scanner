"""LLM service abstractions."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Sequence


class LLMClient(ABC):
    """Abstract interface for large language model providers."""

    @abstractmethod
    def complete(self, prompt: str, *, context: Sequence[str] | None = None) -> str:
        """Generate a response for the provided prompt."""

    @abstractmethod
    def embed(self, text: str) -> Sequence[float]:
        """Return an embedding vector for the provided text."""


__all__ = ["LLMClient"]
