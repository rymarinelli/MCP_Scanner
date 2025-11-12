"""Utilities for correlating Semgrep findings with graph nodes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, MutableMapping, Optional, Sequence, Tuple

GraphInput = Any


@dataclass
class CorrelatedFinding:
    """Represents a Semgrep finding mapped to a graph node."""

    finding: Dict[str, Any]
    node_id: Optional[str]
    match_confidence: str
    matched_attributes: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding": self.finding,
            "node_id": self.node_id,
            "match_confidence": self.match_confidence,
            "matched_attributes": self.matched_attributes,
        }


class SemgrepFindingCorrelator:
    """Match Semgrep findings to nodes in an in-memory graph."""

    def __init__(self, graph: GraphInput):
        self._file_index: Dict[str, List[str]] = {}
        self._symbol_index: Dict[Tuple[str, str], List[str]] = {}
        self._ingest_graph(graph)

    @staticmethod
    def _normalise_path(raw_path: str) -> str:
        return str(Path(raw_path).as_posix()).lower()

    def _register_file(self, node_id: str, file_path: str) -> None:
        key = self._normalise_path(file_path)
        self._file_index.setdefault(key, []).append(node_id)

    def _register_symbol(self, node_id: str, file_path: str, symbol: str) -> None:
        key = (self._normalise_path(file_path), symbol.lower())
        self._symbol_index.setdefault(key, []).append(node_id)

    @staticmethod
    def _iter_graph_nodes(graph: GraphInput) -> Iterator[Tuple[str, MutableMapping[str, Any]]]:
        """Yield ``(node_id, metadata)`` pairs from supported graph structures."""
        if graph is None:
            return iter(())

        if hasattr(graph, "nodes"):
            nodes_attr = graph.nodes  # type: ignore[attr-defined]
            if callable(nodes_attr):
                try:
                    for node_id, data in nodes_attr(data=True):
                        yield str(node_id), data or {}
                    return
                except TypeError:
                    pass
            if isinstance(nodes_attr, MutableMapping):
                for node_id, data in nodes_attr.items():
                    yield str(node_id), data or {}
                return

        if isinstance(graph, MutableMapping):
            for node_id, data in graph.items():
                if isinstance(data, MutableMapping):
                    yield str(node_id), data
            return

        if isinstance(graph, Sequence):
            for entry in graph:
                if isinstance(entry, MutableMapping):
                    node_id = entry.get("id")
                    if node_id is not None:
                        yield str(node_id), entry
            return

        raise TypeError("Unsupported graph representation")

    @staticmethod
    def _extract_file_path(metadata: MutableMapping[str, Any]) -> Optional[str]:
        for key in ("file_path", "filepath", "path", "source_path", "filename"):
            value = metadata.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    @staticmethod
    def _extract_symbol(metadata: MutableMapping[str, Any]) -> Optional[str]:
        for key in ("function", "symbol", "name", "callable"):
            value = metadata.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    def _ingest_graph(self, graph: GraphInput) -> None:
        for node_id, metadata in self._iter_graph_nodes(graph):
            file_path = self._extract_file_path(metadata)
            if not file_path:
                continue
            self._register_file(node_id, file_path)

            symbol = self._extract_symbol(metadata)
            if symbol:
                self._register_symbol(node_id, file_path, symbol)

    @staticmethod
    def _extract_symbol_from_finding(finding: MutableMapping[str, Any]) -> Optional[str]:
        extra = finding.get("extra", {}) if isinstance(finding, MutableMapping) else {}
        if isinstance(extra, MutableMapping):
            metadata = extra.get("metadata", {})
            if isinstance(metadata, MutableMapping):
                for key in ("function", "symbol", "method", "callable", "name"):
                    value = metadata.get(key)
                    if isinstance(value, str) and value:
                        return value

            metavars = extra.get("metavars", {})
            if isinstance(metavars, MutableMapping):
                for candidate in ("$FUNC", "$FUNCTION", "$METHOD", "$CALLABLE"):
                    match = metavars.get(candidate)
                    if isinstance(match, MutableMapping):
                        content = match.get("abstract_content") or match.get("metavar")
                        if isinstance(content, str) and content:
                            return content.split("(")[0].strip()
        return None

    def correlate(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Correlate Semgrep findings with graph nodes."""
        if not isinstance(findings, MutableMapping):
            raise TypeError("Semgrep findings must be a mapping")

        correlated: List[Dict[str, Any]] = []
        results = findings.get("results", [])
        if not isinstance(results, Iterable):
            return correlated

        for finding in results:
            if not isinstance(finding, MutableMapping):
                continue
            file_path = finding.get("path")
            node_ids: List[str] = []
            matched_attributes: Dict[str, Any] = {}
            confidence = "unmatched"

            if isinstance(file_path, str) and file_path:
                normalised_path = self._normalise_path(file_path)
                symbol = self._extract_symbol_from_finding(finding)

                if symbol:
                    node_ids = list(self._symbol_index.get((normalised_path, symbol.lower()), []))
                    if node_ids:
                        confidence = "symbol"
                        matched_attributes = {"file_path": file_path, "symbol": symbol}

                if not node_ids:
                    node_ids = list(self._file_index.get(normalised_path, []))
                    if node_ids:
                        confidence = "file"
                        matched_attributes = {"file_path": file_path}

            if not node_ids:
                correlated.append(
                    CorrelatedFinding(
                        finding=finding,
                        node_id=None,
                        match_confidence=confidence,
                        matched_attributes=matched_attributes,
                    ).to_dict()
                )
            else:
                for node_id in node_ids:
                    correlated.append(
                        CorrelatedFinding(
                            finding=finding,
                            node_id=node_id,
                            match_confidence=confidence,
                            matched_attributes=matched_attributes,
                        ).to_dict()
                    )

        return correlated


def correlate_semgrep_findings(graph: GraphInput, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convenience helper around :class:`SemgrepFindingCorrelator`."""

    correlator = SemgrepFindingCorrelator(graph)
    return correlator.correlate(findings)
