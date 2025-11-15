"""Heuristic patch generation for well-known Semgrep findings."""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence

from mcp_scanner.models import VulnerabilityContext


@dataclass
class _PatchResult:
    """Lightweight container describing a synthesized remediation patch."""

    file_path: str
    diff: str
    rationale: str
    confidence: float

    def to_dict(self) -> Dict[str, object]:
        return {
            "file_path": self.file_path,
            "diff": self.diff,
            "rationale": self.rationale,
            "confidence": self.confidence,
        }


class HeuristicPatchGenerator:
    """Generate targeted patches without invoking an external LLM."""

    def __init__(self, repo_root: Path | None = None) -> None:
        self.repo_root = Path(repo_root) if repo_root else None
        self._handlers = {
            "python.flask.security.audit.debug-enabled": self._disable_flask_debug,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def generate(self, context: VulnerabilityContext) -> List[Dict[str, object]]:
        """Return heuristic patches for ``context`` when possible."""

        if self.repo_root is None:
            return []

        rule_id = str(context.metadata.get("rule_id") or "").lower()
        if not rule_id:
            return []

        for key, handler in self._handlers.items():
            if key in rule_id:
                patch = handler(context)
                return [patch.to_dict()] if patch else []
        return []

    # ------------------------------------------------------------------
    # Rule handlers
    # ------------------------------------------------------------------
    def _disable_flask_debug(self, context: VulnerabilityContext) -> _PatchResult | None:
        """Flip ``debug=True`` to ``debug=False`` in Flask entrypoints."""

        rel_path = context.metadata.get("path")
        if not isinstance(rel_path, str) or not rel_path:
            return None

        target_path = self.repo_root / rel_path
        if not target_path.exists():
            return None

        original_text = target_path.read_text(encoding="utf-8")
        original_lines = original_text.splitlines()
        line_index = self._locate_debug_line(original_lines, context.code_snippets)
        if line_index is None:
            return None

        updated_lines = list(original_lines)
        updated_lines[line_index] = self._rewrite_debug_line(updated_lines[line_index])

        if updated_lines == original_lines:
            return None

        diff = "\n".join(
            difflib.unified_diff(
                original_lines,
                updated_lines,
                fromfile=f"a/{rel_path}",
                tofile=f"b/{rel_path}",
                lineterm="",
            )
        )
        if not diff.strip():
            return None

        rationale = (
            "Disable Flask debug mode before deployment so the server does not expose stack traces "
            "or the Werkzeug debugger. Mirrors the approach used in the MPC_OWASP_POC remediation "
            "pipeline by forcing `debug=False` when starting the app."
        )
        return _PatchResult(
            file_path=rel_path,
            diff=diff,
            rationale=rationale,
            confidence=0.65,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _locate_debug_line(
        lines: Sequence[str],
        snippets: Sequence[str] | None,
    ) -> int | None:
        """Locate the first line that appears to toggle Flask debug mode."""

        candidates: List[str] = []
        if snippets:
            for snippet in snippets:
                snippet = snippet.strip()
                if snippet:
                    candidates.append(snippet)
                for snippet_line in snippet.splitlines():
                    snippet_line = snippet_line.strip()
                    if snippet_line:
                        candidates.append(snippet_line)

        candidates.extend(["app.run(debug=True)", "app.debug = True"])

        for index, line in enumerate(lines):
            normalized = line.strip()
            if "debug=True" in line or normalized in candidates:
                return index
        return None

    @staticmethod
    def _rewrite_debug_line(line: str) -> str:
        """Rewrite ``line`` so that debug mode is disabled."""

        if "debug=True" in line:
            return line.replace("debug=True", "debug=False")

        stripped = line.lstrip()
        indent = line[: len(line) - len(stripped)]
        if stripped.startswith("app.debug"):
            return f"{indent}app.debug = False"
        return line


__all__ = ["HeuristicPatchGenerator"]
