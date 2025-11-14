"""Utilities for translating repository graphs into RAG context payloads."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable

from .collector import GraphArtifact, GraphEdge, GraphNode


def _node_payload(node: GraphNode) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "type": node.type,
        "label": node.label,
    }
    payload.update(node.properties)

    if node.type == "file":
        file_path = node.properties.get("path")
        if isinstance(file_path, str) and file_path:
            payload.setdefault("file_path", file_path)
        else:
            payload.setdefault("file_path", node.id)
    elif node.type == "function":
        defined_in = node.properties.get("defined_in")
        if isinstance(defined_in, str) and defined_in:
            payload.setdefault("file_path", defined_in)
        payload.setdefault("symbol", node.label)
    return payload


def _edge_payload(edge: GraphEdge) -> Dict[str, Any]:
    return {
        "source": edge.source,
        "target": edge.target,
        "type": edge.type,
        "properties": dict(edge.properties),
    }


def _clean_mapping(items: Iterable[tuple[str, Any]]) -> Dict[str, Any]:
    cleaned: Dict[str, Any] = {}
    for key, value in items:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, list) and not value:
            continue
        cleaned[key] = value
    return cleaned


def _function_context(node: GraphNode) -> Dict[str, Any]:
    properties = node.properties
    summary = properties.get("summary")
    if isinstance(summary, str) and summary.strip():
        summary_text = summary.strip()
    else:
        defined_in = properties.get("defined_in")
        location = f" in {defined_in}" if isinstance(defined_in, str) and defined_in else ""
        summary_text = f"Function {node.label}{location}".strip()

    source_snippet = properties.get("source")
    snippets = []
    if isinstance(source_snippet, str) and source_snippet.strip():
        snippets.append(source_snippet.strip())

    context_entries = _clean_mapping(
        [
            ("summary", summary_text),
            ("docstring", properties.get("docstring")),
            ("code_snippets", snippets),
            ("source", source_snippet if isinstance(source_snippet, str) and source_snippet.strip() else None),
            ("lineno", properties.get("lineno")),
            ("end_lineno", properties.get("end_lineno")),
            ("defined_in", properties.get("defined_in")),
        ]
    )
    if "code_snippets" not in context_entries and snippets:
        context_entries["code_snippets"] = snippets
    return context_entries


def build_rag_context(artifact: GraphArtifact) -> Dict[str, Any]:
    """Construct a retrieval-augmented context payload from ``artifact``."""

    graph_nodes: Dict[str, Any] = {}
    node_context: Dict[str, Any] = {}

    for node in artifact.nodes:
        graph_nodes[node.id] = _node_payload(node)
        if node.type == "function":
            function_context = _function_context(node)
            if function_context:
                node_context[node.id] = function_context

    graph_edges = [_edge_payload(edge) for edge in artifact.edges]

    return {
        "graph": {
            "nodes": graph_nodes,
            "edges": graph_edges,
        },
        "node_context": node_context,
    }


def write_rag_context(context: Dict[str, Any], output_path: Path) -> None:
    """Persist a RAG context payload to disk."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(context, indent=2, sort_keys=True)
    output_path.write_text(encoded + "\n", encoding="utf-8")


__all__ = ["build_rag_context", "write_rag_context"]

