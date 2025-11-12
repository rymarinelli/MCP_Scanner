"""Data models that define vulnerability and remediation artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class VulnerabilityContext:
    """Container holding the input context for remediation generation."""

    vulnerability_id: str
    metadata: Dict[str, Any]
    graph_context: Dict[str, Any]
    code_snippets: Optional[List[str]] = None

    def to_prompt_dict(self) -> Dict[str, Any]:
        """Produce a sanitized dictionary suitable for LLM consumption."""

        prompt_dict = {
            "vulnerability_id": self.vulnerability_id,
            "metadata": self.metadata,
            "graph_context": self.graph_context,
        }
        if self.code_snippets:
            prompt_dict["code_snippets"] = self.code_snippets
        return prompt_dict


@dataclass
class PatchProposal:
    """Represents a suggested code modification with supporting details."""

    vulnerability_id: str
    file_path: str
    diff: str
    rationale: str
    confidence: float = 0.0
    validator_results: List["ValidationResult"] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the proposal to a JSON-serializable dictionary."""

        return {
            "vulnerability_id": self.vulnerability_id,
            "file_path": self.file_path,
            "diff": self.diff,
            "rationale": self.rationale,
            "confidence": self.confidence,
            "validator_results": [result.to_dict() for result in self.validator_results],
        }

    @classmethod
    def from_iterable(cls, items: Iterable[Dict[str, Any]], *, vulnerability_id: str) -> List["PatchProposal"]:
        """Construct proposals from an iterable of dictionaries."""

        proposals: List[PatchProposal] = []
        for item in items:
            proposals.append(
                cls(
                    vulnerability_id=vulnerability_id,
                    file_path=item.get("file_path", ""),
                    diff=item.get("diff", ""),
                    rationale=item.get("rationale", ""),
                    confidence=float(item.get("confidence", 0.0) or 0.0),
                )
            )
        return proposals


@dataclass
class ValidationResult:
    """Captures the result of a validation command run against a proposal."""

    command: str
    succeeded: bool
    stdout: str
    stderr: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "succeeded": self.succeeded,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def ensure_directory(path: Path) -> None:
    """Ensure that a directory exists."""

    path.mkdir(parents=True, exist_ok=True)
