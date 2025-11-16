from __future__ import annotations

import importlib
import json
import sys
from types import ModuleType, SimpleNamespace

import pytest

from mcp_scanner.dspy_programs import PatchSuggestionProgram, dspy_is_available
from mcp_scanner.models import VulnerabilityContext


@pytest.fixture(autouse=True)
def _reset_dspy_module(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure cached DSPy imports are reset between tests."""

    monkeypatch.setattr("mcp_scanner.dspy_programs._DSPY_MODULE", None)
    monkeypatch.delitem(sys.modules, "dspy", raising=False)


def _make_context() -> VulnerabilityContext:
    return VulnerabilityContext(
        vulnerability_id="test::file",
        metadata={"rule_id": "rule", "path": "file.py", "severity": "WARNING"},
        graph_context={},
        code_snippets=["print('hello world')"],
    )


def test_heuristic_program_surfaces_import_error(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = importlib.import_module

    def fake_import(name: str, *args, **kwargs):  # type: ignore[no-untyped-def]
        if name == "dspy":
            raise ImportError("DSPy not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", fake_import)

    program = PatchSuggestionProgram()

    assert program.uses_dspy is False
    assert "DSPy not installed" in program.instructions
    assert dspy_is_available() is False


def _install_stub_dspy(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    stub = ModuleType("dspy")

    class Signature:  # noqa: D401 - simple stub matching DSPy's shape
        """Stub signature base class."""

    def input_field(**kwargs):  # type: ignore[no-untyped-def]
        return kwargs

    def output_field(**kwargs):  # type: ignore[no-untyped-def]
        return kwargs

    class Predict:  # noqa: D401
        """Return a canned response for testing."""

        def __init__(self, signature):  # type: ignore[no-untyped-def]
            self.signature = signature

        def __call__(self, **kwargs):  # type: ignore[no-untyped-def]
            del kwargs
            diff_text = "\n".join(
                [
                    "diff --git a/file.py b/file.py",
                    "--- a/file.py",
                    "+++ b/file.py",
                    "@@",
                    "-print('hello')",
                    "+print('patched')",
                    "diff --git a/second.py b/second.py",
                    "--- a/second.py",
                    "+++ b/second.py",
                    "@@",
                    "-return 1",
                    "+return 2",
                ]
            ) + "\n"
            payload = {
                "commits": [
                    {
                        "id": "stub-commit",
                        "title": "fix: stub patch",
                        "message": "fix: stub patch\n\n- replace prints\n- adjust math",
                        "touched_findings": ["TEST-1"],
                        "patch": diff_text,
                    }
                ],
                "pull_request": {
                    "title": "stub",
                    "body_markdown": "## Summary\n- stub",
                },
            }
            return SimpleNamespace(patches=json.dumps(payload))

    stub.Signature = Signature  # type: ignore[attr-defined]
    stub.InputField = staticmethod(input_field)  # type: ignore[attr-defined]
    stub.OutputField = staticmethod(output_field)  # type: ignore[attr-defined]
    stub.Predict = Predict  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "dspy", stub)
    monkeypatch.setattr("mcp_scanner.dspy_programs._DSPY_MODULE", None)
    return stub


def test_program_switches_to_dspy_when_module_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    # First instantiation fails to import DSPy.
    first = PatchSuggestionProgram()
    assert first.uses_dspy is False

    # Installing the stub makes subsequent instantiations use DSPy.
    _install_stub_dspy(monkeypatch)
    second = PatchSuggestionProgram()
    assert second.uses_dspy is True

    response = second.forward(_make_context())
    paths = {patch["file_path"] for patch in response.patches}
    assert paths == {"file.py", "second.py"}
    assert all("stub patch" in patch["rationale"] for patch in response.patches)
    assert dspy_is_available() is True
