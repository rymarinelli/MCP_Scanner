"""DSPy programs that transform vulnerability context into remediation patches."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .models import PatchProposal, VulnerabilityContext
from remediation.heuristic_patches import HeuristicPatchGenerator

try:  # pragma: no cover - import guard for optional dependency
    import dspy
except ImportError:  # pragma: no cover - fallback if DSPy is unavailable
    dspy = None  # type: ignore[assignment]

DSPY_AVAILABLE = dspy is not None


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


if dspy is not None:  # pragma: no cover - requires DSPy at runtime

    class PatchSuggestionSignature(dspy.Signature):
        """Signature instructing DSPy to emit structured remediation patches."""

        instructions = dspy.InputField(desc="High level task description")
        vulnerability_metadata = dspy.InputField(desc="Metadata describing the vulnerability")
        graph_context = dspy.InputField(desc="Code/property graph insights relevant to the issue")
        code_snippets = dspy.InputField(desc="Relevant code snippets", optional=True)
        patches = dspy.OutputField(
            desc=(
                "JSON array of patch suggestions. Each entry must contain 'file_path', 'diff', "
                "'rationale', and optional 'confidence'."
            )
        )

    class PatchSuggestionProgram(dspy.Module):
        """DSPy module that generates remediation patches from vulnerability context."""

        uses_dspy = True

        def __init__(self, *, instructions: Optional[str] = None):
            super().__init__()
            self.instructions = instructions or (
                "You are an expert security engineer. Generate precise remediation patches."
            )
            self.generator = dspy.Predict(PatchSuggestionSignature)

        def forward(self, context: VulnerabilityContext) -> DSPyResponse:
            prompt_metadata = _format_dict(context.metadata)
            prompt_graph = _format_dict(context.graph_context)
            snippets = "\n\n".join(context.code_snippets or [])

            response = self.generator(
                instructions=self.instructions,
                vulnerability_metadata=prompt_metadata,
                graph_context=prompt_graph,
                code_snippets=snippets or None,
            )

            patches = _parse_json_output(response.patches)
            return DSPyResponse(patches=patches, raw_output=response.patches)

else:

    class PatchSuggestionProgram:
        """Fallback implementation when DSPy is unavailable."""

        uses_dspy = False

        def __init__(
            self,
            *,
            instructions: Optional[str] = None,
            repo_root: Path | str | None = None,
        ):
            self.instructions = instructions or (
                "DSPy is unavailable; generating heuristic remediation suggestions."
            )
            self.repo_root = Path(repo_root) if repo_root else None
            self.heuristics = HeuristicPatchGenerator(self.repo_root)

        def forward(self, context: VulnerabilityContext) -> DSPyResponse:
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

    return DSPY_AVAILABLE


__all__ = ["PatchSuggestionProgram", "DSPyResponse", "normalize_patches", "dspy_is_available"]
