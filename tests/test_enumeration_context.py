from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from enumeration.collector import RepositoryCollector
from enumeration.context import build_rag_context


def test_build_rag_context_includes_function_snippet(tmp_path: Path) -> None:
    source = '''
from typing import Any


def greet(name: str) -> str:
    """Return a friendly greeting."""
    message = f"Hello {name}"
    return message
'''
    file_path = tmp_path / "app.py"
    file_path.write_text(source)

    collector = RepositoryCollector(tmp_path)
    artifact = collector.collect()
    context = build_rag_context(artifact)

    graph_nodes = context["graph"]["nodes"]
    function_id = next(key for key, data in graph_nodes.items() if data.get("label") == "greet")
    node_data = graph_nodes[function_id]
    assert node_data["file_path"] == "app.py"
    assert node_data["symbol"] == "greet"

    node_context = context["node_context"][function_id]
    assert "friendly greeting" in node_context["summary"].lower()
    snippets = node_context.get("code_snippets", [])
    assert any("return message" in snippet for snippet in snippets)
