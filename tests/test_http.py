"""Tests for the HTTP API layer."""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure the src/ directory is importable before other imports.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

import importlib
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient


def reload_http_module():
    """Reload the HTTP module to evaluate import-time side effects."""
    sys.modules.pop("mcp_vanguard.http", None)
    return importlib.import_module("mcp_vanguard.http")


def test_tools_module_is_imported_on_startup():
    """The HTTP module should import the tools registry during startup."""
    sys.modules.pop("mcp_vanguard.tools", None)
    module = reload_http_module()
    assert "mcp_vanguard.tools" in sys.modules
    assert hasattr(module, "_tools")


def test_call_tool_delegates_to_core(monkeypatch: pytest.MonkeyPatch):
    """The route should delegate execution to the core runner."""
    module = reload_http_module()
    client = TestClient(module.app)

    expected_payload = {"result": {"echo": "pong"}}
    captured: Dict[str, Any] = {}

    def fake_run_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        captured["name"] = name
        captured["arguments"] = arguments
        return expected_payload

    monkeypatch.setattr(module.core, "run_tool", fake_run_tool)

    response = client.post(
        "/call_tool",
        json={"tool": "ping", "arguments": {"message": "pong"}},
    )

    assert response.status_code == 200
    assert response.json() == expected_payload
    assert captured == {
        "name": "ping",
        "arguments": {"message": "pong"},
    }


def test_call_tool_uses_default_arguments(monkeypatch: pytest.MonkeyPatch):
    """The route should supply an empty arguments mapping when omitted."""
    module = reload_http_module()
    client = TestClient(module.app)

    expected_payload = {"status": "ok"}
    captured: Dict[str, Any] = {}

    def fake_run_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        captured["name"] = name
        captured["arguments"] = arguments
        return expected_payload

    monkeypatch.setattr(module.core, "run_tool", fake_run_tool)

    response = client.post("/call_tool", json={"tool": "noop"})

    assert response.status_code == 200
    assert response.json() == expected_payload
    assert captured == {"name": "noop", "arguments": {}}
