"""High-level driver that turns Semgrep findings into DSPy remediation plans."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from graph.enrichers import correlate_semgrep_findings
from mcp_scanner.models import PatchProposal, VulnerabilityContext, ensure_directory
from mcp_scanner.remediation import RemediationSuggester


@dataclass
class FindingBundle:
    """Container bundling raw inputs used to construct remediation suggestions."""

    context: VulnerabilityContext
    finding: Dict[str, Any]
    node_id: Optional[str]
    match_confidence: str
    matched_attributes: Dict[str, Any]
    node_context: Dict[str, Any]


class DSPyRemediationDriver:
    """Orchestrates DSPy programs to produce actionable remediation plans."""

    def __init__(
        self,
        *,
        suggester: RemediationSuggester | None = None,
        manual_review_threshold: float = 0.85,
        output_markdown: Path | str = Path("reports/remediation/dspy_suggestions.md"),
    ) -> None:
        self.suggester = suggester or RemediationSuggester()
        self.manual_review_threshold = manual_review_threshold
        self.output_markdown = Path(output_markdown)

    # ------------------------------------------------------------------
    # Loading helpers
    # ------------------------------------------------------------------
    @staticmethod
    def load_semgrep_findings(path: Path | str) -> Dict[str, Any]:
        """Load Semgrep findings from a JSON file."""

        findings_path = Path(path)
        payload = json.loads(findings_path.read_text())
        if not isinstance(payload, MutableMapping):
            raise TypeError("Semgrep findings must be a JSON object")
        return dict(payload)

    @staticmethod
    def load_rag_context(path: Path | str) -> Dict[str, Any]:
        """Load retrieval-augmented generation context from JSON."""

        context_path = Path(path)
        if not context_path.exists():
            return {}
        payload = json.loads(context_path.read_text())
        if not isinstance(payload, MutableMapping):
            raise TypeError("RAG context must be a JSON object")
        return dict(payload)

    # ------------------------------------------------------------------
    # Context construction
    # ------------------------------------------------------------------
    def _resolve_graph_data(self, rag_context: Mapping[str, Any]) -> Mapping[str, Any]:
        graph_section = rag_context.get("graph")
        if isinstance(graph_section, Mapping):
            if "nodes" in graph_section and isinstance(graph_section["nodes"], Mapping):
                return graph_section["nodes"]
            return graph_section
        return rag_context.get("nodes", {}) if isinstance(rag_context.get("nodes"), Mapping) else {}

    @staticmethod
    def _node_lookup(rag_context: Mapping[str, Any]) -> Mapping[str, Any]:
        node_context = rag_context.get("node_context")
        if isinstance(node_context, Mapping):
            return node_context
        return {}

    @staticmethod
    def _build_metadata(finding: Mapping[str, Any]) -> Dict[str, Any]:
        extra = finding.get("extra", {}) if isinstance(finding.get("extra"), Mapping) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), Mapping) else {}
        message = extra.get("message") if isinstance(extra.get("message"), str) else ""
        severity = extra.get("severity") if isinstance(extra.get("severity"), str) else "unknown"
        path = finding.get("path") if isinstance(finding.get("path"), str) else ""
        rule_id = finding.get("check_id") or finding.get("rule_id")
        return {
            "rule_id": rule_id,
            "message": message,
            "severity": severity,
            "path": path,
            "metadata": dict(metadata),
            "start": finding.get("start"),
            "end": finding.get("end"),
        }

    @staticmethod
    def _collect_snippets(finding: Mapping[str, Any], node_context: Mapping[str, Any]) -> List[str]:
        snippets: List[str] = []
        extra = finding.get("extra", {}) if isinstance(finding.get("extra"), Mapping) else {}
        finding_snippet = extra.get("lines") if isinstance(extra.get("lines"), str) else None
        if finding_snippet:
            snippets.append(finding_snippet)
        node_snippets = node_context.get("code_snippets")
        if isinstance(node_snippets, Sequence) and not isinstance(node_snippets, (str, bytes)):
            snippets.extend(str(item) for item in node_snippets)
        elif isinstance(node_snippets, str):
            snippets.append(node_snippets)
        contextual_snippet = node_context.get("source")
        if isinstance(contextual_snippet, str):
            snippets.append(contextual_snippet)
        return [snippet for snippet in snippets if snippet]

    @staticmethod
    def _make_vulnerability_id(
        finding: Mapping[str, Any],
        node_id: Optional[str],
        index: int,
    ) -> str:
        base = finding.get("extra", {}).get("metadata", {}).get("id") if isinstance(finding.get("extra"), Mapping) else None
        if not isinstance(base, str) or not base:
            base = finding.get("check_id") or finding.get("rule_id")
        if not isinstance(base, str) or not base:
            base = finding.get("path")
        suffix = node_id or f"{index}"
        return f"{base}-{suffix}" if base else f"finding-{index}"

    def _build_contexts(
        self,
        semgrep: Mapping[str, Any],
        rag_context: Mapping[str, Any],
    ) -> Tuple[List[VulnerabilityContext], Dict[str, FindingBundle]]:
        graph_data = self._resolve_graph_data(rag_context)
        correlated = correlate_semgrep_findings(graph_data, dict(semgrep))
        node_lookup = self._node_lookup(rag_context)

        contexts: List[VulnerabilityContext] = []
        bundles: Dict[str, FindingBundle] = {}

        for index, entry in enumerate(correlated):
            finding = entry.get("finding", {})
            if not isinstance(finding, Mapping):
                continue
            node_id = entry.get("node_id") if isinstance(entry.get("node_id"), str) else None
            metadata = self._build_metadata(finding)
            node_context = node_lookup.get(node_id, {}) if node_id else {}
            if not isinstance(node_context, Mapping):
                node_context = {}
            snippets = self._collect_snippets(finding, node_context)
            graph_context = {
                "node_id": node_id,
                "match_confidence": entry.get("match_confidence"),
                "matched_attributes": entry.get("matched_attributes", {}),
                "context": dict(node_context),
            }
            vulnerability_id = self._make_vulnerability_id(finding, node_id, index)
            context = VulnerabilityContext(
                vulnerability_id=vulnerability_id,
                metadata=metadata,
                graph_context=graph_context,
                code_snippets=snippets or None,
            )
            contexts.append(context)
            confidence_value = entry.get("match_confidence")
            confidence_text = str(confidence_value) if confidence_value is not None else ""
            matched_attrs = entry.get("matched_attributes", {})
            if not isinstance(matched_attrs, Mapping):
                matched_attrs = {}

            bundles[vulnerability_id] = FindingBundle(
                context=context,
                finding=dict(finding),
                node_id=node_id,
                match_confidence=confidence_text,
                matched_attributes=dict(matched_attrs),
                node_context=dict(node_context),
            )
        return contexts, bundles

    # ------------------------------------------------------------------
    # Output helpers
    # ------------------------------------------------------------------
    def _manual_review_required(self, proposal: PatchProposal) -> bool:
        try:
            return float(proposal.confidence) < self.manual_review_threshold
        except (TypeError, ValueError):
            return True

    def _format_attributes(self, attributes: Mapping[str, Any]) -> str:
        if not attributes:
            return "None"
        return ", ".join(f"{key}={value}" for key, value in attributes.items())

    @staticmethod
    def _normalized_confidence(value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    def _write_markdown(
        self,
        proposals: Iterable[PatchProposal],
        bundles: Mapping[str, FindingBundle],
    ) -> None:
        ensure_directory(self.output_markdown.parent)

        proposals_by_vuln: Dict[str, List[PatchProposal]] = {}
        for proposal in proposals:
            proposals_by_vuln.setdefault(proposal.vulnerability_id, []).append(proposal)

        lines: List[str] = ["# DSPy Remediation Suggestions", ""]
        if not bundles:
            lines.append("No remediation suggestions were generated.")
        else:
            for vulnerability_id, bundle in bundles.items():
                finding_meta = bundle.context.metadata
                lines.extend(
                    [
                        f"## Vulnerability {vulnerability_id}",
                        f"- **Rule**: {finding_meta.get('rule_id') or 'unknown'}",
                        f"- **Severity**: {finding_meta.get('severity', 'unknown')}",
                        f"- **Message**: {finding_meta.get('message') or 'n/a'}",
                        f"- **File**: {finding_meta.get('path') or 'n/a'}",
                        f"- **Graph Node**: {bundle.node_id or 'unmatched'}",
                        f"- **Match Confidence**: {bundle.match_confidence or 'unmatched'}",
                        f"- **Matched Attributes**: {self._format_attributes(bundle.matched_attributes)}",
                    ]
                )
                node_summary = bundle.node_context.get("summary")
                if isinstance(node_summary, str) and node_summary:
                    lines.append(f"- **Node Summary**: {node_summary}")
                lines.append("")

                vuln_proposals = proposals_by_vuln.get(vulnerability_id, [])
                if not vuln_proposals:
                    lines.append("No DSPy suggestions were produced for this finding.\n")
                    continue

                for idx, proposal in enumerate(vuln_proposals, start=1):
                    manual_review = self._manual_review_required(proposal)
                    confidence_value = self._normalized_confidence(proposal.confidence)
                    lines.extend(
                        [
                            f"### Suggested Fix {idx}: `{proposal.file_path or '<unspecified>'}`",
                            f"- Confidence Score: {confidence_value:.2f}",
                            f"- Manual Review Required: {'Yes' if manual_review else 'No'}",
                            f"- Rationale: {proposal.rationale or 'n/a'}",
                            "",
                            "```diff",
                            proposal.diff or "// No diff provided",
                            "```",
                            "",
                        ]
                    )

        self.output_markdown.write_text("\n".join(lines))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def run(
        self,
        *,
        semgrep_path: Path | str,
        rag_context_path: Path | str,
    ) -> List[PatchProposal]:
        """Execute the remediation pipeline and return generated patch proposals."""

        semgrep_findings = self.load_semgrep_findings(semgrep_path)
        rag_context = self.load_rag_context(rag_context_path)
        contexts, bundles = self._build_contexts(semgrep_findings, rag_context)

        if not contexts:
            ensure_directory(self.output_markdown.parent)
            self.output_markdown.write_text("# DSPy Remediation Suggestions\n\nNo remediation suggestions were generated.")
            return []

        proposals = self.suggester.suggest(contexts)
        self._write_markdown(proposals, bundles)
        return proposals


__all__ = ["DSPyRemediationDriver"]
