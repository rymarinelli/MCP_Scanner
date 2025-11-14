"""Repository data ingestion utilities for building RAG graphs."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from textwrap import dedent
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

IGNORED_PARTS = {
    ".git",
    "__pycache__",
    "node_modules",
    "venv",
    ".venv",
    "reports",
}


@dataclass
class GraphNode:
    """A single node in the repository graph."""

    id: str
    type: str
    label: str
    properties: Dict[str, object] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """A connection between two nodes in the repository graph."""

    source: str
    target: str
    type: str
    properties: Dict[str, object] = field(default_factory=dict)


@dataclass
class GraphArtifact:
    """Collection of nodes and edges describing the repository."""

    nodes: List[GraphNode]
    edges: List[GraphEdge]

    def to_dict(self) -> Dict[str, object]:
        return {
            "nodes": [
                {
                    "id": node.id,
                    "type": node.type,
                    "label": node.label,
                    "properties": node.properties,
                }
                for node in self.nodes
            ],
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "type": edge.type,
                    "properties": edge.properties,
                }
                for edge in self.edges
            ],
        }


class RepositoryCollector:
    """Walk a repository and collect dependency metadata."""

    def __init__(self, root: Path, ignore_parts: Optional[Sequence[str]] = None) -> None:
        self.root = root.resolve()
        self.ignore_parts = set(ignore_parts or []) | IGNORED_PARTS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def collect(self) -> GraphArtifact:
        files = list(self._iter_files())
        module_index = self._build_module_index(files)

        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        function_index: Dict[Tuple[str, str], str] = {}

        for path in files:
            relative_path = path.relative_to(self.root)
            file_id = relative_path.as_posix()
            file_node = GraphNode(
                id=file_id,
                type="file",
                label=relative_path.name,
                properties=self._file_metadata(path),
            )
            nodes.append(file_node)

            if path.suffix == ".py":
                module_name = ".".join(relative_path.with_suffix("").parts)
                # Provide a stable default for __init__ modules.
                if relative_path.name == "__init__.py":
                    module_name = module_name.rsplit(".__init__", 1)[0]

                py_nodes, py_edges = self._collect_python_metadata(
                    path=path,
                    file_id=file_id,
                    module_name=module_name,
                    module_index=module_index,
                    function_index=function_index,
                )
                nodes.extend(py_nodes)
                edges.extend(py_edges)

        return GraphArtifact(nodes=nodes, edges=edges)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _iter_files(self) -> Iterator[Path]:
        for path in self.root.rglob("*"):
            if not path.is_file():
                continue
            try:
                relative = path.relative_to(self.root)
            except ValueError:
                continue
            if any(part in self.ignore_parts for part in relative.parts[:-1]):
                continue
            if relative.name.startswith(".") and relative.name != ".env":
                continue
            yield path

    def _file_metadata(self, path: Path) -> Dict[str, object]:
        stat = path.stat()
        checksum = hashlib.sha1(path.read_bytes()).hexdigest()
        language = self._guess_language(path)
        return {
            "path": path.relative_to(self.root).as_posix(),
            "extension": path.suffix,
            "size_bytes": stat.st_size,
            "modified": stat.st_mtime,
            "sha1": checksum,
            "language": language,
        }

    def _guess_language(self, path: Path) -> str:
        suffix = path.suffix.lower()
        if suffix == ".py":
            return "python"
        if suffix in {".md", ".rst"}:
            return "markdown"
        if suffix in {".json", ".jsonl"}:
            return "json"
        if suffix in {".toml"}:
            return "toml"
        if suffix in {".yml", ".yaml"}:
            return "yaml"
        return "unknown"

    def _build_module_index(self, files: Sequence[Path]) -> Dict[str, str]:
        module_index: Dict[str, str] = {}
        for path in files:
            if path.suffix != ".py":
                continue
            relative = path.relative_to(self.root)
            module_name = ".".join(relative.with_suffix("").parts)
            module_index[module_name] = relative.as_posix()
            if relative.name == "__init__.py":
                package = ".".join(relative.with_suffix("").parts[:-1])
                if package:
                    module_index[package] = relative.as_posix()
        return module_index

    def _collect_python_metadata(
        self,
        path: Path,
        file_id: str,
        module_name: str,
        module_index: Dict[str, str],
        function_index: Dict[Tuple[str, str], str],
    ) -> Tuple[List[GraphNode], List[GraphEdge]]:
        try:
            source_text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            return [], []

        try:
            tree = ast.parse(source_text)
        except SyntaxError:
            return [], []

        relative = path.relative_to(self.root)
        file_node_id = file_id
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []

        for func in [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            function_id = f"{relative.as_posix()}::def::{func.name}:{func.lineno}"
            function_index[(module_name, func.name)] = function_id
            docstring = ast.get_docstring(func) or ""
            summary = docstring.strip().split("\n", 1)[0] if docstring.strip() else ""
            raw_source = ast.get_source_segment(source_text, func) or ""
            source_snippet = dedent(raw_source).strip("\n")
            end_lineno = getattr(func, "end_lineno", None)
            nodes.append(
                GraphNode(
                    id=function_id,
                    type="function",
                    label=func.name,
                    properties={
                        "defined_in": relative.as_posix(),
                        "lineno": func.lineno,
                        "end_lineno": end_lineno,
                        "docstring": docstring,
                        "summary": summary,
                        "source": source_snippet,
                        "async": isinstance(func, ast.AsyncFunctionDef),
                    },
                )
            )
            edges.append(
                GraphEdge(
                    source=file_node_id,
                    target=function_id,
                    type="contains",
                    properties={},
                )
            )

        import_edges = self._extract_import_edges(tree, file_node_id, module_index, module_name)
        edges.extend(import_edges)

        call_edges = self._extract_call_edges(tree, module_name, function_index)
        edges.extend(call_edges)

        return nodes, edges

    def _extract_import_edges(
        self,
        tree: ast.AST,
        file_node_id: str,
        module_index: Dict[str, str],
        module_name: str,
    ) -> List[GraphEdge]:
        edges: List[GraphEdge] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target = self._resolve_module(alias.name, module_index)
                    if target:
                        edges.append(
                            GraphEdge(
                                source=file_node_id,
                                target=target,
                                type="imports",
                                properties={"import": alias.name},
                            )
                        )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                resolved_module = self._resolve_relative_module(module_name, module, node.level)
                for alias in node.names:
                    candidate = alias.name if module else alias.name
                    target_module = f"{resolved_module}.{candidate}" if resolved_module and module else (resolved_module or candidate)
                    target = self._resolve_module(target_module, module_index)
                    if not target and resolved_module:
                        target = self._resolve_module(resolved_module, module_index)
                    if target:
                        edges.append(
                            GraphEdge(
                                source=file_node_id,
                                target=target,
                                type="imports",
                                properties={"import": f"{module or ''}:{alias.name}".strip(":" )},
                            )
                        )
        return edges

    def _extract_call_edges(
        self,
        tree: ast.AST,
        module_name: str,
        function_index: Dict[Tuple[str, str], str],
    ) -> List[GraphEdge]:
        edges: List[GraphEdge] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                caller_id = function_index.get((module_name, node.name))
                if not caller_id:
                    continue
                for call in [n for n in ast.walk(node) if isinstance(n, ast.Call)]:
                    call_name = self._call_name(call)
                    if not call_name:
                        continue
                    callee_id = function_index.get((module_name, call_name))
                    if callee_id:
                        edges.append(
                            GraphEdge(
                                source=caller_id,
                                target=callee_id,
                                type="calls",
                                properties={"call": call_name},
                            )
                        )
        return edges

    def _resolve_module(self, module: str, module_index: Dict[str, str]) -> Optional[str]:
        if not module:
            return None
        if module in module_index:
            return module_index[module]
        probe = module
        while "." in probe:
            probe = probe.rsplit(".", 1)[0]
            if probe in module_index:
                return module_index[probe]
        return None

    def _resolve_relative_module(self, current_module: str, target_module: str, level: int) -> str:
        if not level:
            return target_module
        parts = current_module.split(".") if current_module else []
        if level <= len(parts):
            base = parts[: len(parts) - level]
        else:
            base = []
        if target_module:
            base.extend(target_module.split("."))
        return ".".join(part for part in base if part)

    def _call_name(self, call: ast.Call) -> Optional[str]:
        func = call.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None


def write_graph(artifact: GraphArtifact, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(artifact.to_dict(), handle, indent=2)


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Collect repository metadata for RAG graphs")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root to scan")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/rag/raw_graph.json"),
        help="Path to write the graph JSON",
    )
    args = parser.parse_args(argv)

    collector = RepositoryCollector(args.root)
    artifact = collector.collect()
    write_graph(artifact, args.output)


if __name__ == "__main__":
    main()
