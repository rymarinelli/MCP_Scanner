"""High-level orchestration for generating and persisting remediation patches."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List, Sequence

from .dspy_programs import DSPyResponse, PatchSuggestionProgram, normalize_patches


def _default_patch_program() -> PatchSuggestionProgram:
    """Select the default patch suggestion program based on configuration."""

    import os

    provider = os.getenv("MCP_LLM__PROVIDER", "").strip().lower()
    model_name = os.getenv("MCP_LLM__MODEL", "ise-uiuc/Magicoder-S-DS-6.7B")

    try:
        from common.config import get_settings
    except Exception:  # pragma: no cover - optional dependency fallback
        settings_provider = provider
        settings_model = model_name
    else:
        settings = get_settings()
        settings_provider = settings.llm.provider.lower()
        settings_model = settings.llm.model

    if settings_provider == "huggingface":
        from remediation.huggingface_program import HuggingFacePatchSuggestionProgram

        return HuggingFacePatchSuggestionProgram(model_name=settings_model)

    return PatchSuggestionProgram()
from .models import PatchProposal, ValidationResult, VulnerabilityContext, ensure_directory


class RemediationSuggester:
    """Coordinates DSPy programs to produce remediation artifacts."""

    def __init__(
        self,
        *,
        program: PatchSuggestionProgram | None = None,
        output_dir: Path | str = Path("reports/remediations"),
    ) -> None:
        self.program = program or _default_patch_program()
        self.output_dir = Path(output_dir)
        ensure_directory(self.output_dir)

    def suggest(self, contexts: Sequence[VulnerabilityContext]) -> List[PatchProposal]:
        """Generate patch proposals for each vulnerability context provided."""

        proposals: List[PatchProposal] = []
        for context in contexts:
            response = self.program.forward(context)
            normalized = normalize_patches(context=context, response=response)
            if not normalized:
                continue

            self._persist(context=context, response=response, proposals=normalized)
            proposals.extend(normalized)
        return proposals

    def _persist(
        self,
        *,
        context: VulnerabilityContext,
        response: DSPyResponse,
        proposals: Iterable[PatchProposal],
    ) -> None:
        """Write the generated proposals and raw response to disk."""

        ensure_directory(self.output_dir)
        payload = {
            "vulnerability_id": context.vulnerability_id,
            "metadata": context.metadata,
            "graph_context": context.graph_context,
            "proposals": [proposal.to_dict() for proposal in proposals],
            "raw_output": response.raw_output,
        }
        output_path = self.output_dir / f"{context.vulnerability_id}.json"
        output_path.write_text(json.dumps(payload, indent=2, sort_keys=True))

    def attach_validation_results(
        self,
        *,
        proposal: PatchProposal,
        results: Sequence[ValidationResult],
    ) -> PatchProposal:
        """Attach validation results to a proposal and refresh persistence."""

        proposal.validator_results.extend(results)
        output_path = self.output_dir / f"{proposal.vulnerability_id}.json"
        if output_path.exists():
            payload = json.loads(output_path.read_text())
            for entry in payload.get("proposals", []):
                if entry.get("file_path") == proposal.file_path and entry.get("diff") == proposal.diff:
                    entry["validator_results"] = [result.to_dict() for result in proposal.validator_results]
            output_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
        return proposal
