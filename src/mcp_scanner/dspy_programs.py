"""DSPy programs that transform vulnerability context into remediation patches."""

from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Iterable, List, Optional

from .models import PatchProposal, VulnerabilityContext
from remediation.heuristic_patches import HeuristicPatchGenerator

_DSPY_MODULE: ModuleType | None = None


def _import_dspy() -> tuple[ModuleType | None, Optional[str]]:
    """Attempt to import DSPy and return the module and any error string."""

    global _DSPY_MODULE

    if _DSPY_MODULE is not None:
        return _DSPY_MODULE, None

    try:  # pragma: no cover - import guard for optional dependency
        module = importlib.import_module("dspy")
    except Exception as exc:  # pragma: no cover - surface import reason
        return None, f"{exc.__class__.__name__}: {exc}"

    _DSPY_MODULE = module
    return module, None


def _format_dict(data: Dict[str, Any], prefix: str = "") -> str:
    """Format a dictionary into a deterministic, human-friendly string."""

    lines: List[str] = []
    for key in sorted(data):
        value = data[key]
        if isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            lines.append(_format_dict(value, prefix=prefix + "  "))
        elif isinstance(value, list):
            lines.append(f"{prefix}{key}:")
            for item in value:
                if isinstance(item, dict):
                    lines.append(_format_dict(item, prefix=prefix + "  - "))
                else:
                    lines.append(f"{prefix}  - {item}")
        else:
            lines.append(f"{prefix}{key}: {value}")
    return "\n".join(lines)


@dataclass
class DSPyResponse:
    """Normalized response returned by a DSPy program."""

    patches: List[Dict[str, Any]]
    raw_output: Optional[str] = None


def _parse_json_output(text: str) -> List[Dict[str, Any]]:
    """Attempt to parse a JSON payload containing patch suggestions."""

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []

    items = payload
    if isinstance(payload, dict):
        items = payload.get("patches", [])

    if not isinstance(items, list):
        return []

    result: List[Dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            result.append(item)
    return result


_DSPY_PROMPT = "You are an expert security engineer. Generate precise remediation patches."
_HEURISTIC_PROMPT = "DSPy is unavailable; generating heuristic remediation suggestions."


class PatchSuggestionProgram:
    """Program that delegates to DSPy when available and heuristics otherwise."""

    def __init__(
        self,
        *,
        instructions: Optional[str] = None,
        repo_root: Path | str | None = None,
    ) -> None:
        self.repo_root = Path(repo_root) if repo_root else None
        self._dspy, self._import_error = _import_dspy()
        self.uses_dspy = self._dspy is not None

        if self.uses_dspy:
            self.instructions = instructions or _DSPY_PROMPT
            self._init_dspy_generator()
            self.heuristics: HeuristicPatchGenerator | None = None
        else:
            message = instructions or _HEURISTIC_PROMPT
            if instructions is None and self._import_error:
                message = f"{message} ({self._import_error})"
            self.instructions = message
            self.heuristics = HeuristicPatchGenerator(self.repo_root)

    def _init_dspy_generator(self) -> None:
        """Initialize the DSPy signature and generator lazily."""

        assert self._dspy is not None  # Defensive: only called when DSPy is available
        dspy = self._dspy

        class PatchSuggestionSignature(dspy.Signature):  # type: ignore[valid-type]
            """Signature instructing DSPy to emit structured remediation patches."""

            instructions = dspy.InputField(desc="High level task description")
            vulnerability_metadata = dspy.InputField(desc="Metadata describing the vulnerability")
            graph_context = dspy.InputField(
                desc="Code/property graph insights relevant to the issue"
            )
            code_snippets = dspy.InputField(desc="Relevant code snippets", optional=True)
            patches = dspy.OutputField(
                desc=(
                    "JSON array of patch suggestions. Each entry must contain 'file_path', 'diff', "
                    "'rationale', and optional 'confidence'."
                )
            )

        self._signature = PatchSuggestionSignature
        self.generator = dspy.Predict(PatchSuggestionSignature)

    def forward(self, context: VulnerabilityContext) -> DSPyResponse:
        if self._dspy is None:
            return self._run_heuristics(context)
        return self._run_dspy(context)

    def _run_dspy(self, context: VulnerabilityContext) -> DSPyResponse:
        assert self._dspy is not None
        prompt_metadata = _format_dict(context.metadata)
        prompt_graph = _format_dict(context.graph_context)
        snippets = "\n\n".join(context.code_snippets or [])

        response = self.generator(  # type: ignore[operator]
            instructions=self.instructions,
            vulnerability_metadata=prompt_metadata,
            graph_context=prompt_graph,
            code_snippets=snippets or None,
        )

        patches = _parse_json_output(response.patches)
        raw_output = response.patches if isinstance(response.patches, str) else json.dumps(response.patches)
        return DSPyResponse(patches=patches, raw_output=raw_output)

    def _run_heuristics(self, context: VulnerabilityContext) -> DSPyResponse:
        assert self.heuristics is not None
        heuristic_patches = self.heuristics.generate(context)
        if heuristic_patches:
            raw_output = json.dumps({"patches": heuristic_patches}, indent=2)
            return DSPyResponse(patches=heuristic_patches, raw_output=raw_output)

        metadata_text = _format_dict(context.metadata)
        graph_text = _format_dict(context.graph_context)
        snippet_text = "\n\n".join(context.code_snippets or [])

        raw_output = json.dumps(
            [
                {
                    "file_path": "<unknown>",
                    "diff": (
                        "// Investigate vulnerability\n"
                        f"// Metadata:\n{metadata_text}\n"
                        f"// Graph Context:\n{graph_text}\n"
                        + (f"// Code Snippets:\n{snippet_text}" if snippet_text else "")
                    ),
                    "rationale": self.instructions,
                    "confidence": 0.0,
                }
            ]
        )
        patches = _parse_json_output(raw_output)
        return DSPyResponse(patches=patches, raw_output=raw_output)


def normalize_patches(
    *,
    context: VulnerabilityContext,
    response: DSPyResponse,
) -> List[PatchProposal]:
    """Convert a DSPy response into typed patch proposals."""

    if not response.patches:
        return []

    return PatchProposal.from_iterable(response.patches, vulnerability_id=context.vulnerability_id)


def dspy_is_available() -> bool:
    """Return ``True`` when the optional DSPy dependency can be imported."""

    module, _ = _import_dspy()
    return module is not None


__all__ = ["PatchSuggestionProgram", "DSPyResponse", "normalize_patches", "dspy_is_available"]
