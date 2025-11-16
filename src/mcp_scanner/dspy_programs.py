"""DSPy programs that transform vulnerability context into remediation patches."""

from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent
from types import ModuleType
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

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


def _split_diff_by_file(diff_text: str) -> List[Tuple[str, str]]:
    """Split a unified diff string into (file_path, diff) tuples."""

    if not diff_text.strip():
        return []

    blocks: List[Tuple[str, str]] = []
    current_lines: List[str] = []
    current_path = ""

    def flush() -> None:
        if not current_lines:
            return
        block_text = "\n".join(current_lines)
        if not block_text.endswith("\n"):
            block_text += "\n"
        blocks.append((current_path, block_text))

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            flush()
            current_lines = [line]
            parts = line.split()
            if len(parts) >= 4 and parts[3].startswith("b/"):
                current_path = parts[3][2:]
            elif len(parts) >= 3 and parts[2].startswith("a/"):
                current_path = parts[2][2:]
            else:
                current_path = ""
            continue

        current_lines.append(line)
        if line.startswith("+++ b/"):
            candidate = line[6:].strip()
            if candidate != "/dev/null":
                current_path = candidate
        elif not current_path and line.startswith("--- a/"):
            candidate = line[6:].strip()
            if candidate != "/dev/null":
                current_path = candidate

    flush()
    return [(path, diff) for path, diff in blocks if diff.strip()]


def _patches_from_commits(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract patch dictionaries from the structured commit payload."""

    commits = payload.get("commits")
    if not isinstance(commits, Sequence):
        return []

    global_notes = payload.get("rationale_markdown")
    global_text = global_notes.strip() if isinstance(global_notes, str) else ""

    patches: List[Dict[str, Any]] = []
    for commit in commits:
        if not isinstance(commit, dict):
            continue
        patch_text = commit.get("patch")
        if not isinstance(patch_text, str) or not patch_text.strip():
            continue

        rationale_parts: List[str] = []
        for field in ("message", "title"):
            value = commit.get(field)
            if isinstance(value, str) and value.strip():
                rationale_parts.append(value.strip())

        commit_notes = commit.get("rationale_markdown")
        if isinstance(commit_notes, str) and commit_notes.strip():
            rationale_parts.append(commit_notes.strip())

        if global_text:
            rationale_parts.append(global_text)

        rationale = "\n\n".join(rationale_parts) if rationale_parts else "See commit description for details."
        for file_path, diff in _split_diff_by_file(patch_text):
            patches.append(
                {
                    "file_path": file_path or commit.get("file_path", ""),
                    "diff": diff,
                    "rationale": rationale,
                }
            )

    return patches


def _parse_json_output(text: str) -> List[Dict[str, Any]]:
    """Attempt to parse a JSON payload containing patch suggestions."""

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []

    if isinstance(payload, dict):
        commit_patches = _patches_from_commits(payload)
        if commit_patches:
            return commit_patches
        items = payload.get("patches", [])
    else:
        items = payload

    if not isinstance(items, list):
        return []

    result: List[Dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            result.append(item)
    return result


_DSPY_PROMPT = dedent(
    """
    You are a senior application security engineer AND long-term maintainer of the current
    repository. Given repository context (languages, frameworks, notable patterns), sample
    commit messages, and Semgrep findings with vulnerable code snippets, produce SMALL,
    SAFE patches that directly remediate every finding.

    =====================================
    GOALS
    =====================================
    1. Fix the referenced vulnerabilities using idiomatic patterns for the repository.
       - Prefer parameterized queries, validated inputs, secure configuration, and other
         straightforward hardening techniques.
       - Only change the lines necessary for the fix and preserve legitimate behavior.
    2. Match the repository's coding conventions (indentation, quote style, logging).
    3. Organize fixes into logical commits that a reviewer can easily merge.

    =====================================
    REQUIRED OUTPUT FORMAT (JSON)
    =====================================
    Always return a single JSON object with two top-level keys:
      {
        "commits": [
          {
            "id": "short-stable-id",
            "title": "short commit title (<= 72 chars)",
            "message": "multi-line commit message in repo style",
            "touched_findings": ["F1", "F2"],
            "patch": "UNIFIED DIFF APPLYABLE WITH git apply"
          }
        ],
        "pull_request": {
          "title": "short PR title summarizing fixes",
          "body_markdown": "Markdown body with sections: Summary, Changes by Area, Security Impact,"
                           " Risk if Unpatched, Testing, Notes"
        }
      }

    =====================================
    ADDITIONAL REQUIREMENTS
    =====================================
    - Each commit should reference the relevant finding ids in "touched_findings".
    - Diffs must only touch the lines required for the remediation; do not reformat other code.
    - When a finding cannot be safely auto-fixed, leave it untouched and mention the follow-up
      in the PR "Notes" section instead of emitting speculative code.
    - Prefer conservative, obviously correct fixes. Preserve the app's behavior for honest users.
    - Return ONLY the JSON object—no prose outside the JSON payload.
    """
).strip()
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
