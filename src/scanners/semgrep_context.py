"""Context-aware Semgrep orchestration built from RAG nodes."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence

from graph.enrichers import correlate_semgrep_findings
from semgrep_runner import RunnerConfig, build_command, execute_semgrep, interpret_result

DEFAULT_RISK_RULES: Mapping[str, str] = {
    "prompt_injection": "semgrep_rules/custom/llm_prompt_injection.yaml",
    "unsafe_tool_execution": "semgrep_rules/custom/llm_tool_execution.yaml",
    "insecure_model_invocation": "semgrep_rules/custom/llm_model_invocation.yaml",
}


@dataclass
class MatchPosition:
    """Represents the location of a fallback finding."""

    start_line: int
    start_col: int
    end_line: int
    end_col: int
    excerpt: str

    def to_span(self) -> Dict[str, int]:
        return {
            "start_line": self.start_line,
            "start_col": self.start_col,
            "end_line": self.end_line,
            "end_col": self.end_col,
        }


@dataclass
class FallbackRule:
    """Heuristic rule used when Semgrep is unavailable."""

    rule_id: str
    message: str
    severity: str
    category: str
    detector: Callable[[str], List[MatchPosition]]


@dataclass
class RAGNode:
    """Normalized representation of a RAG node."""

    node_id: str
    file_path: str
    symbol: Optional[str]
    risk_tags: List[str]
    description: Optional[str]
    raw: Mapping[str, Any] = field(repr=False)

    @staticmethod
    def _normalise_tags(raw_tags: Any) -> List[str]:
        tags: List[str] = []
        if isinstance(raw_tags, str):
            tokens = re.split(r"[\s,]+", raw_tags)
            tags.extend(token for token in tokens if token)
        elif isinstance(raw_tags, Sequence):
            for item in raw_tags:
                if isinstance(item, str) and item:
                    tags.append(item)
        return [tag.strip() for tag in tags if tag.strip()]

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RAGNode":
        node_id = str(data.get("id") or data.get("node_id") or data.get("uuid") or "")
        if not node_id:
            raise ValueError("RAG nodes must include an 'id' field")

        file_path: Optional[str] = None
        for key in ("file_path", "filepath", "path", "source_path", "filename"):
            value = data.get(key)
            if isinstance(value, str) and value:
                file_path = value
                break
        if not file_path:
            raise ValueError(f"RAG node {node_id} does not specify a file path")

        symbol: Optional[str] = None
        for key in ("symbol", "function", "callable", "name"):
            value = data.get(key)
            if isinstance(value, str) and value:
                symbol = value
                break
        metadata = data.get("metadata")
        if isinstance(metadata, Mapping):
            if not symbol:
                for key in ("symbol", "function", "callable", "name"):
                    value = metadata.get(key)
                    if isinstance(value, str) and value:
                        symbol = value
                        break

        risk_tags: List[str] = []
        for key in ("risk_tags", "tags", "labels", "categories"):
            risk_tags.extend(cls._normalise_tags(data.get(key)))
            if isinstance(metadata, Mapping):
                risk_tags.extend(cls._normalise_tags(metadata.get(key)))
        risk_tags = list(dict.fromkeys(risk_tags))

        description: Optional[str] = None
        for key in ("description", "summary", "notes"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                description = value.strip()
                break
            if isinstance(metadata, Mapping):
                meta_value = metadata.get(key)
                if isinstance(meta_value, str) and meta_value.strip():
                    description = meta_value.strip()
                    break

        return cls(
            node_id=node_id,
            file_path=file_path,
            symbol=symbol,
            risk_tags=risk_tags,
            description=description,
            raw=data,
        )

    def to_summary(self) -> Dict[str, Any]:
        summary = {
            "id": self.node_id,
            "file_path": self.file_path,
            "risk_tags": self.risk_tags,
        }
        if self.symbol:
            summary["symbol"] = self.symbol
        if self.description:
            summary["description"] = self.description
        return summary


@dataclass
class SemgrepTargetSpec:
    """Plan describing which ruleset to run for a set of nodes."""

    risk_tag: str
    config: RunnerConfig
    targets: List[str]
    node_ids: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_tag": self.risk_tag,
            "config": self.config.value,
            "targets": self.targets,
            "node_ids": self.node_ids,
        }


class SemgrepContextPlanner:
    """Translate RAG nodes into Semgrep scan targets."""

    def __init__(
        self,
        nodes: Iterable[Mapping[str, Any]],
        *,
        risk_rules: Mapping[str, str] | None = None,
        base_dir: Path | None = None,
    ) -> None:
        self.base_dir = (base_dir or Path.cwd()).resolve()
        self.risk_rules = dict(DEFAULT_RISK_RULES)
        if risk_rules:
            self.risk_rules.update(risk_rules)
        self.nodes: List[RAGNode] = []
        for raw in nodes:
            if not isinstance(raw, Mapping):
                continue
            try:
                node = RAGNode.from_mapping(raw)
            except ValueError:
                continue
            if not any(tag in self.risk_rules for tag in node.risk_tags):
                continue
            node_path = Path(node.file_path)
            resolved_path = node_path.resolve() if node_path.is_absolute() else (self.base_dir / node_path).resolve()
            try:
                node.file_path = str(resolved_path.relative_to(self.base_dir))
            except ValueError:
                node.file_path = str(resolved_path)
            self.nodes.append(node)

    @property
    def node_lookup(self) -> Dict[str, RAGNode]:
        return {node.node_id: node for node in self.nodes}

    def build_plan(self) -> List[SemgrepTargetSpec]:
        grouped_targets: Dict[str, Dict[str, Any]] = {}
        for node in self.nodes:
            for risk_tag in node.risk_tags:
                config_path = self.risk_rules.get(risk_tag)
                if not config_path:
                    continue
                key = risk_tag
                bucket = grouped_targets.setdefault(
                    key,
                    {
                        "config": RunnerConfig(type="local", value=config_path, label=risk_tag),
                        "targets": set(),
                        "node_ids": [],
                    },
                )
                bucket["targets"].add(node.file_path)
                if node.node_id not in bucket["node_ids"]:
                    bucket["node_ids"].append(node.node_id)

        plan: List[SemgrepTargetSpec] = []
        for risk_tag, data in grouped_targets.items():
            targets = sorted(data["targets"])
            node_ids = data["node_ids"]
            plan.append(
                SemgrepTargetSpec(
                    risk_tag=risk_tag,
                    config=data["config"],
                    targets=targets,
                    node_ids=node_ids,
                )
            )
        plan.sort(key=lambda spec: spec.risk_tag)
        return plan


def _load_rag_nodes(path: Path) -> List[Mapping[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Unable to locate RAG nodes file: {path}")
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, Mapping):
        nodes = payload.get("nodes")
        if isinstance(nodes, list):
            return nodes  # type: ignore[return-value]
    if isinstance(payload, list):
        return payload  # type: ignore[return-value]
    raise TypeError("RAG node payload must be a list or contain a 'nodes' list")


def _compute_position(text: str, start: int, end: int) -> MatchPosition:
    start_line = text.count("\n", 0, start) + 1
    line_start_index = text.rfind("\n", 0, start)
    if line_start_index == -1:
        start_col = start + 1
    else:
        start_col = start - line_start_index

    end_line = text.count("\n", 0, end) + 1
    end_line_start = text.rfind("\n", 0, end)
    if end_line_start == -1:
        end_col = end + 1
    else:
        end_col = end - end_line_start

    excerpt = text[start:end].strip()
    return MatchPosition(start_line=start_line, start_col=start_col, end_line=end_line, end_col=end_col, excerpt=excerpt)


PROMPT_ASSIGN_PATTERN = re.compile(
    r"(?P<var>\b\w*prompt\w*\b)\s*(?P<op>\+?=)\s*(?P<value>[^#\n]+)",
    re.IGNORECASE,
)
USER_CONTROLLED_PATTERN = re.compile(r"(input|message|payload|instruction|query)", re.IGNORECASE)
SUBPROCESS_PATTERN = re.compile(r"subprocess\.run\((?P<args>[^)]*)\)", re.IGNORECASE | re.DOTALL)
SHELL_TRUE_PATTERN = re.compile(r"shell\s*=\s*True", re.IGNORECASE)
LLM_IDENTIFIER_PATTERN = re.compile(r"(llm|model|prompt|ai)", re.IGNORECASE)
OS_SYSTEM_PATTERN = re.compile(r"os\.system\((?P<arg>[^)]*)\)", re.IGNORECASE)
REQUESTS_POST_PATTERN = re.compile(r"requests\.post\((?P<args>[^)]*)\)", re.IGNORECASE | re.DOTALL)
VERIFY_FALSE_PATTERN = re.compile(r"verify\s*=\s*False", re.IGNORECASE)
HTTP_URL_PATTERN = re.compile(r"^\"http://", re.IGNORECASE)


def _detect_prompt_injection(text: str) -> List[MatchPosition]:
    matches: List[MatchPosition] = []
    for match in PROMPT_ASSIGN_PATTERN.finditer(text):
        value = match.group("value")
        if USER_CONTROLLED_PATTERN.search(value):
            matches.append(_compute_position(text, match.start(), match.end()))
    return matches


def _detect_subprocess_shell(text: str) -> List[MatchPosition]:
    matches: List[MatchPosition] = []
    for match in SUBPROCESS_PATTERN.finditer(text):
        args = match.group("args")
        if not SHELL_TRUE_PATTERN.search(args):
            continue
        if not LLM_IDENTIFIER_PATTERN.search(args):
            continue
        matches.append(_compute_position(text, match.start(), match.end()))
    return matches


def _detect_os_system(text: str) -> List[MatchPosition]:
    matches: List[MatchPosition] = []
    for match in OS_SYSTEM_PATTERN.finditer(text):
        arg = match.group("arg")
        if not LLM_IDENTIFIER_PATTERN.search(arg):
            continue
        matches.append(_compute_position(text, match.start(), match.end()))
    return matches


def _detect_insecure_request(text: str) -> List[MatchPosition]:
    matches: List[MatchPosition] = []
    for match in REQUESTS_POST_PATTERN.finditer(text):
        args = match.group("args")
        if not VERIFY_FALSE_PATTERN.search(args):
            continue
        # Attempt to extract the URL literal
        url_match = re.search(r"\"[^\"]+\"", args)
        url_text = url_match.group(0).strip() if url_match else ""
        if not HTTP_URL_PATTERN.match(url_text):
            continue
        matches.append(_compute_position(text, match.start(), match.end()))
    return matches


FALLBACK_RULES: Mapping[str, List[FallbackRule]] = {
    "prompt_injection": [
        FallbackRule(
            rule_id="llm.prompt-injection.unescaped-user-input",
            message=(
                "User-controlled content is concatenated into an LLM prompt without sanitisation. "
                "Consider templating or strong validation to defend against prompt injection."
            ),
            severity="WARNING",
            category="prompt_injection",
            detector=_detect_prompt_injection,
        )
    ],
    "unsafe_tool_execution": [
        FallbackRule(
            rule_id="llm.unsafe-tool-exec.subprocess-shell",
            message=(
                "LLM-provided commands are executed with shell=True. Validate or sandbox commands before execution."
            ),
            severity="ERROR",
            category="unsafe_tool_execution",
            detector=_detect_subprocess_shell,
        ),
        FallbackRule(
            rule_id="llm.unsafe-tool-exec.os-system",
            message="LLM-provided scripts are executed via os.system without validation.",
            severity="WARNING",
            category="unsafe_tool_execution",
            detector=_detect_os_system,
        ),
    ],
    "insecure_model_invocation": [
        FallbackRule(
            rule_id="llm.insecure-model-invocation.insecure-transport",
            message="Model invocation occurs over HTTP with certificate checks disabled.",
            severity="WARNING",
            category="insecure_model_invocation",
            detector=_detect_insecure_request,
        )
    ],
}


def _run_fallback(spec: SemgrepTargetSpec, base_dir: Path) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    rules = FALLBACK_RULES.get(spec.risk_tag, [])
    for relative_target in spec.targets:
        target_path = (base_dir / relative_target).resolve()
        if not target_path.exists():
            continue
        text = target_path.read_text(encoding="utf-8")
        for rule in rules:
            for match in rule.detector(text):
                result = {
                    "check_id": rule.rule_id,
                    "path": str(relative_target),
                    "start": {"line": match.start_line, "col": match.start_col},
                    "end": {"line": match.end_line, "col": match.end_col},
                    "extra": {
                        "message": rule.message,
                        "metadata": {"category": rule.category, "fallback": True},
                        "severity": rule.severity,
                        "lines": match.excerpt,
                    },
                }
                results.append(result)
    return results


def _aggregate_semgrep_results(plan: List[SemgrepTargetSpec], base_dir: Path) -> Dict[str, Any]:
    aggregated_results: List[Dict[str, Any]] = []
    plan_runs: List[Dict[str, Any]] = []
    fallback_used = False

    for spec in plan:
        run_entry: Dict[str, Any] = {
            "risk_tag": spec.risk_tag,
            "config": spec.config.value,
            "targets": spec.targets,
            "node_ids": spec.node_ids,
        }
        try:
            command = build_command([spec.config], spec.targets, base_dir)
            result = execute_semgrep(command)
            output = interpret_result(result, command)
            run_entry.update(
                {
                    "command": command,
                    "semgrep_exit_code": output.semgrep_exit_code,
                    "stderr": output.stderr,
                }
            )
            aggregated_results.extend(output.results.get("results", []))
            if output.results.get("errors"):
                run_entry["errors"] = output.results["errors"]
        except FileNotFoundError as exc:
            fallback_used = True
            run_entry["command"] = None
            run_entry["error"] = str(exc)
            fallback_results = _run_fallback(spec, base_dir)
            aggregated_results.extend(fallback_results)
        plan_runs.append(run_entry)

    return {
        "results": aggregated_results,
        "plan_runs": plan_runs,
        "fallback_used": fallback_used,
    }


def _build_graph_payload(nodes: Iterable[RAGNode]) -> Dict[str, Dict[str, Any]]:
    payload: Dict[str, Dict[str, Any]] = {}
    for node in nodes:
        entry: Dict[str, Any] = {"file_path": node.file_path}
        if node.symbol:
            entry["symbol"] = node.symbol
        payload[node.node_id] = entry
    return payload


def _generate_summary(
    planner: SemgrepContextPlanner,
    correlated_findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    node_lookup = planner.node_lookup
    summary_by_node: Dict[str, Dict[str, Any]] = {}
    risk_counter: Dict[str, int] = {}

    for correlated in correlated_findings:
        finding = correlated.get("finding", {})
        extra = finding.get("extra", {}) if isinstance(finding, Mapping) else {}
        metadata = extra.get("metadata", {}) if isinstance(extra, Mapping) else {}
        category = metadata.get("category") if isinstance(metadata, Mapping) else None
        if isinstance(category, str):
            risk_counter[category] = risk_counter.get(category, 0) + 1
        node_id = correlated.get("node_id")
        key = node_id or "__unmapped__"
        node = node_lookup.get(node_id) if isinstance(node_id, str) else None
        if node and isinstance(category, str) and category not in node.risk_tags:
            continue
        entry = summary_by_node.setdefault(
            key,
            {
                "node": node.to_summary() if node else None,
                "findings": [],
            },
        )
        entry["findings"].append(
            {
                "rule_id": finding.get("check_id"),
                "message": extra.get("message"),
                "path": finding.get("path"),
                "severity": extra.get("severity"),
                "match_confidence": correlated.get("match_confidence"),
                "matched_attributes": correlated.get("matched_attributes"),
            }
        )

    overview = {
        "total_findings": len(correlated_findings),
        "nodes_with_findings": len([key for key in summary_by_node if key != "__unmapped__"]),
        "risk_counts": risk_counter,
    }

    return {
        "overview": overview,
        "by_node": summary_by_node,
    }


def run_semgrep_with_rag(
    nodes: Iterable[Mapping[str, Any]],
    *,
    output_path: Path,
    risk_rules: Mapping[str, str] | None = None,
    base_dir: Path | None = None,
) -> Dict[str, Any]:
    planner = SemgrepContextPlanner(nodes, risk_rules=risk_rules, base_dir=base_dir)
    plan = planner.build_plan()
    base_dir = planner.base_dir

    aggregated = _aggregate_semgrep_results(plan, base_dir)
    graph_payload = _build_graph_payload(planner.nodes)
    correlated = correlate_semgrep_findings(graph_payload, {"results": aggregated["results"]})
    summary = _generate_summary(planner, correlated)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "plan": [spec.to_dict() for spec in plan],
        "runs": aggregated["plan_runs"],
        "fallback_used": aggregated["fallback_used"],
        "raw_results": aggregated["results"],
        "correlated_findings": correlated,
        "summary": summary,
        "rag_nodes": [node.to_summary() for node in planner.nodes],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Semgrep scans using RAG node context")
    parser.add_argument(
        "--rag-nodes",
        type=Path,
        default=Path("reports/rag/nodes.json"),
        help="Path to the RAG nodes JSON file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/semgrep/llm_findings.json"),
        help="Destination for the structured Semgrep results.",
    )
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=Path.cwd(),
        help="Project root used to resolve relative file paths.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    nodes = _load_rag_nodes(args.rag_nodes)
    run_semgrep_with_rag(nodes, output_path=args.output, base_dir=args.base_dir)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
