"""Minimal FastAPI substitute for testing purposes."""
from __future__ import annotations

from .app import FastAPI
from .testclient import TestClient

__all__ = ["FastAPI", "TestClient"]
