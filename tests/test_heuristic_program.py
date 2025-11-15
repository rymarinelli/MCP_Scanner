from __future__ import annotations

import sys
import textwrap
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from remediation.heuristic_program import HeuristicPatchSuggestionProgram
from mcp_scanner.models import VulnerabilityContext


def _context(path: str, start_line: int, snippet: str) -> VulnerabilityContext:
    return VulnerabilityContext(
        vulnerability_id="test-vuln",
        metadata={
            "rule_id": "test.rule",
            "message": "Detected SQL string built from user input",
            "severity": "ERROR",
            "path": path,
            "start": {"line": start_line, "col": 1},
            "end": {"line": start_line, "col": 10},
        },
        graph_context={},
        code_snippets=[snippet],
    )


def test_heuristic_generates_patch_for_fstring_sql(tmp_path: Path) -> None:
    source = textwrap.dedent(
        """
        import sqlite3

        def login(username, password):
            db = sqlite3.connect("example.db")
            cur = db.cursor()
            sql = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"
            cur.execute(sql)
            return cur.fetchone()
        """
    ).strip()
    file_path = tmp_path / "app.py"
    file_path.write_text(source)

    program = HeuristicPatchSuggestionProgram(repo_root=tmp_path)
    context = _context("app.py", start_line=7, snippet=source)

    response = program.forward(context)
    assert response.patches, "Expected heuristic to generate a patch"
    diff = response.patches[0]["diff"]
    assert "username = ?" in diff
    assert "password = ?" in diff
    assert "cur.execute" in diff and "(username, password)" in diff


def test_heuristic_generates_patch_for_concatenated_like(tmp_path: Path) -> None:
    source = textwrap.dedent(
        """
        def search(q):
            cur = get_cursor()
            sql = "SELECT * FROM users WHERE username LIKE '%" + q + "%'"
            cur.execute(sql)
            return cur.fetchall()
        """
    ).strip()
    file_path = tmp_path / "handlers.py"
    file_path.write_text(source)

    program = HeuristicPatchSuggestionProgram(repo_root=tmp_path)
    context = _context("handlers.py", start_line=4, snippet=source)

    response = program.forward(context)
    assert response.patches, "Expected heuristic to generate a patch"
    diff = response.patches[0]["diff"]
    assert "LIKE ?" in diff
    assert "(f\"%{q}%\",)" in diff


def test_heuristic_generates_patch_for_flask_debug(tmp_path: Path) -> None:
    source = textwrap.dedent(
        """
        from flask import Flask

        app = Flask(__name__)

        if __name__ == "__main__":
            app.run(host="0.0.0.0", debug=True)
        """
    ).strip()
    file_path = tmp_path / "server.py"
    file_path.write_text(source)

    program = HeuristicPatchSuggestionProgram(repo_root=tmp_path)
    context = VulnerabilityContext(
        vulnerability_id="debug-vuln",
        metadata={
            "rule_id": "python.flask.security.audit.debug-enabled.debug-enabled",
            "message": "Detected Flask app with debug=True.",
            "severity": "WARNING",
            "path": "server.py",
            "start": {"line": 6, "col": 5},
            "end": {"line": 6, "col": 10},
        },
        graph_context={},
        code_snippets=[source],
    )

    response = program.forward(context)
    assert response.patches, "Expected heuristic to generate a patch"
    diff = response.patches[0]["diff"]
    assert "import os" in diff
    assert "debug=os.environ.get(\"FLASK_DEBUG\"" in diff
