from __future__ import annotations

import sys
from pathlib import Path
from textwrap import dedent

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from mcp_scanner.dspy_programs import PatchSuggestionProgram
from mcp_scanner.models import VulnerabilityContext
from remediation.heuristic_patches import HeuristicPatchGenerator


def make_flask_context() -> VulnerabilityContext:
    return VulnerabilityContext(
        vulnerability_id="python.flask.security.audit.debug-enabled::app",
        metadata={
            "rule_id": "python.flask.security.audit.debug-enabled",
            "path": "app.py",
            "severity": "WARNING",
        },
        graph_context={},
        code_snippets=["app.run(debug=True)"],
    )


def make_llm_context(rule_id: str, path: str, snippet: str) -> VulnerabilityContext:
    return VulnerabilityContext(
        vulnerability_id=f"{rule_id}::{path}",
        metadata={"rule_id": rule_id, "path": path, "severity": "WARNING"},
        graph_context={},
        code_snippets=[snippet],
    )


def _write_flask_app(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        dedent(
            """
            from flask import Flask

            app = Flask(__name__)

            if __name__ == "__main__":
                app.run(debug=True)
            """
        ).strip(),
        encoding="utf-8",
    )


def _write_insecure_llm_examples(tmp_path: Path) -> Path:
    source = tmp_path / "llm_examples.py"
    source.write_text(
        dedent(
            """
            import os
            import subprocess

            import requests


            def build_prompt(user_input: str, system_prompt: str = "You are a helpful AI") -> str:
                prompt = system_prompt + "\\n\\nUser instruction:\\n" + user_input
                return prompt


            def execute_tool_response(llm_command: str) -> int:
                return subprocess.run(llm_command, shell=True, check=False).returncode


            def dispatch_with_os_system(llm_script: str) -> int:
                return os.system(llm_script)


            def invoke_insecure_model(prompt: str, model_url: str | None = None) -> str:
                response = requests.post(
                    "http://insecure-model.local/invoke",
                    json={"prompt": prompt, "temperature": 1.0},
                    timeout=30,
                    verify=False,
                )
                return response.text
            """
        ).strip(),
        encoding="utf-8",
    )
    return source


def _write_sql_injection_app(tmp_path: Path) -> Path:
    source = tmp_path / "app_vuln.py"
    source.write_text(
        dedent(
            """
            from flask import Flask, request, render_template_string

            app = Flask(__name__)

            SEARCH_HTML = "search"
            LOGIN_HTML = "login"

            def get_db():
                ...

            def search():
                q = request.args.get("q", "")
                results = None
                if q:
                    db = get_db()
                    cur = db.cursor()
                    sql = "SELECT id, username FROM users WHERE username LIKE '%" + q + "%';"
                    cur.execute(sql)
                    results = cur.fetchall()
                return render_template_string(SEARCH_HTML, results=results)


            def login():
                user = None
                if request.method == "POST":
                    username = request.form.get("username", "")
                    password = request.form.get("password", "")
                    db = get_db()
                    cur = db.cursor()
                    sql = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}' LIMIT 1;"
                    cur.execute(sql)
                    row = cur.fetchone()
                    user = row
                return render_template_string(LOGIN_HTML, user=user)
            """
        ).strip(),
        encoding="utf-8",
    )
    return source


def test_generator_disables_flask_debug(tmp_path: Path) -> None:
    _write_flask_app(tmp_path)

    generator = HeuristicPatchGenerator(repo_root=tmp_path)
    patches = generator.generate(make_flask_context())

    assert len(patches) == 1
    patch = patches[0]
    assert patch["file_path"] == "app.py"
    assert "-    app.run(debug=True)" in patch["diff"]
    assert "+    app.run(debug=False)" in patch["diff"]


def test_patch_program_uses_heuristics(tmp_path: Path) -> None:
    _write_flask_app(tmp_path)
    context = make_flask_context()

    program = PatchSuggestionProgram(repo_root=tmp_path)
    response = program.forward(context)

    assert response.patches
    assert response.patches[0]["file_path"] == "app.py"


def test_prompt_builder_is_sanitized(tmp_path: Path) -> None:
    source = _write_insecure_llm_examples(tmp_path)
    generator = HeuristicPatchGenerator(repo_root=tmp_path)
    context = make_llm_context(
        "llm.prompt-injection.unescaped-user-input",
        source.name,
        "prompt = system_prompt + \"\\n\\nUser instruction:\\n\" + user_input",
    )

    patch = generator.generate(context)[0]
    assert "User instruction (sanitized)" in patch["diff"]


def test_model_invocation_enforces_https(tmp_path: Path) -> None:
    source = _write_insecure_llm_examples(tmp_path)
    generator = HeuristicPatchGenerator(repo_root=tmp_path)
    context = make_llm_context(
        "llm.insecure-model-invocation.insecure-transport",
        source.name,
        "requests.post(\"http://insecure-model.local/invoke\", verify=False)",
    )

    patch = generator.generate(context)[0]
    assert "verify=True" in patch["diff"]
    assert "model_url must use https" in patch["diff"]


def test_subprocess_shell_usage_is_blocked(tmp_path: Path) -> None:
    source = _write_insecure_llm_examples(tmp_path)
    generator = HeuristicPatchGenerator(repo_root=tmp_path)
    context = make_llm_context(
        "llm.unsafe-tool-exec.subprocess-shell",
        source.name,
        "subprocess.run(llm_command, shell=True, check=False)",
    )

    patch = generator.generate(context)[0]
    additions = [line for line in patch["diff"].splitlines() if line.startswith("+")]
    assert not any("shell=True" in line for line in additions)
    assert "allowed_commands" in patch["diff"]


def test_os_system_requires_allowlist(tmp_path: Path) -> None:
    source = _write_insecure_llm_examples(tmp_path)
    generator = HeuristicPatchGenerator(repo_root=tmp_path)
    context = make_llm_context(
        "llm.unsafe-tool-exec.os-system",
        source.name,
        "os.system(llm_script)",
    )

    patch = generator.generate(context)[0]
    assert "allowed_binaries" in patch["diff"]
    assert "shlex.split" in patch["diff"]


def test_sql_injection_handlers_are_parameterized(tmp_path: Path) -> None:
    source = _write_sql_injection_app(tmp_path)
    generator = HeuristicPatchGenerator(repo_root=tmp_path)
    context = make_llm_context(
        "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
        source.name,
        """sql = "SELECT id, username FROM users WHERE username LIKE '%" + q + "%';""",
    )

    patch = generator.generate(context)[0]
    assert "LIKE ?" in patch["diff"]
    assert "cur.execute(sql, (like_pattern,))" in patch["diff"]
    assert "AND password = ? LIMIT 1" in patch["diff"]
