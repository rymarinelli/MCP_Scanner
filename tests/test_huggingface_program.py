"""Tests for the Hugging Face remediation program integration."""

from __future__ import annotations

import json

import pytest

from mcp_scanner.models import VulnerabilityContext
from remediation.huggingface_program import HuggingFacePatchSuggestionProgram


class DummyClient:
    def __init__(self, response: str) -> None:
        self.response = response
        self.prompts: list[str] = []

    def complete(self, prompt: str, *, context=None):  # type: ignore[override]
        self.prompts.append(prompt)
        return self.response

    def embed(self, text: str):  # pragma: no cover - not used in tests
        raise NotImplementedError


def make_context() -> VulnerabilityContext:
    return VulnerabilityContext(
        vulnerability_id="demo-1",
        metadata={"severity": "HIGH", "rule": "demo.rule"},
        graph_context={"node_id": "node-1", "function": "handle_request"},
        code_snippets=["def handle_request():\n    pass"],
    )


def test_program_builds_prompt_and_parses_response() -> None:
    response = json.dumps(
        {
            "patches": [
                {
                    "file_path": "src/app.py",
                    "diff": "--- a/src/app.py\n+++ b/src/app.py\n@@\n-pass\n+return True",
                    "rationale": "Ensure the handler returns a truthy value.",
                    "confidence": 0.6,
                }
            ]
        }
    )
    client = DummyClient(response)
    program = HuggingFacePatchSuggestionProgram(client=client)

    result = program.forward(make_context())

    assert result.patches and result.patches[0]["file_path"] == "src/app.py"
    assert any("Vulnerability Metadata" in prompt for prompt in client.prompts)


def test_program_returns_empty_on_invalid_json() -> None:
    client = DummyClient("not-json")
    program = HuggingFacePatchSuggestionProgram(client=client)

    result = program.forward(make_context())
    assert result.patches == []


def test_default_patch_program_prefers_huggingface(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp_scanner import remediation as remediation_module

    monkeypatch.setenv("MCP_LLM__PROVIDER", "huggingface")
    monkeypatch.setenv("MCP_LLM__MODEL", "dummy/model")

    import types
    import sys

    stub_module = types.ModuleType("remediation.huggingface_program")

    class StubProgram:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    stub_module.HuggingFacePatchSuggestionProgram = StubProgram  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "remediation.huggingface_program", stub_module)

    program = remediation_module._default_patch_program()

    assert isinstance(program, StubProgram)

    monkeypatch.delenv("MCP_LLM__PROVIDER", raising=False)
    monkeypatch.delenv("MCP_LLM__MODEL", raising=False)
