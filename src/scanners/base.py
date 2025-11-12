"""Scanner interface definitions."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol

from common.config import ScannerSettings
from common.logging import get_logger


class ScanResult(Protocol):
    """Protocol for scan results."""

    message: str


class Scanner(ABC):
    """Base scanner implementation."""

    def __init__(self, settings: ScannerSettings | None = None) -> None:
        self.settings = settings or ScannerSettings()
        self.logger = get_logger(self.__class__.__name__)

    @abstractmethod
    def scan(self) -> ScanResult:
        """Run the scanning workflow and return a result."""


__all__ = ["Scanner", "ScanResult"]
