"""Heuristic patch generation for well-known Semgrep findings."""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Mapping, Sequence

import ast
import textwrap

if TYPE_CHECKING:  # pragma: no cover - avoid circular import at runtime
    from mcp_scanner.models import VulnerabilityContext


@dataclass
class _PatchResult:
    """Lightweight container describing a synthesized remediation patch."""

    file_path: str
    diff: str
    rationale: str
    confidence: float

    def to_dict(self) -> Dict[str, object]:
        return {
            "file_path": self.file_path,
            "diff": self.diff,
            "rationale": self.rationale,
            "confidence": self.confidence,
        }


class HeuristicPatchGenerator:
    """Generate targeted patches without invoking an external LLM."""

    def __init__(self, repo_root: Path | None = None) -> None:
        self.repo_root = Path(repo_root) if repo_root else None
        self._handlers = {
            "python.flask.security.audit.debug-enabled": self._disable_flask_debug,
            "llm.prompt-injection.unescaped-user-input": self._sanitize_prompt_builder,
            "llm.insecure-model-invocation.insecure-transport": self._enforce_secure_model_invocation,
            "llm.unsafe-tool-exec.subprocess-shell": self._enforce_tool_allowlist,
            "llm.unsafe-tool-exec.os-system": self._enforce_os_allowlist,
            "python.flask.security.injection.tainted-sql-string": self._parameterize_flask_sql,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def generate(self, context: "VulnerabilityContext") -> List[Dict[str, object]]:
        """Return heuristic patches for ``context`` when possible."""

        if self.repo_root is None:
            return []

        rule_id = str(context.metadata.get("rule_id") or "").lower()
        if not rule_id:
            return []

        for key, handler in self._handlers.items():
            if key in rule_id:
                patch = handler(context)
                return [patch.to_dict()] if patch else []
        return []

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    def _load_target(self, context: "VulnerabilityContext") -> tuple[str, Path, str] | None:
        rel_path = context.metadata.get("path")
        if not isinstance(rel_path, str) or not rel_path:
            return None

        target_path = self.repo_root / rel_path
        if not target_path.exists():
            return None

        return rel_path, target_path, target_path.read_text(encoding="utf-8")

    @staticmethod
    def _make_diff(rel_path: str, original: str, updated: str) -> str:
        original_lines = original.splitlines()
        updated_lines = updated.splitlines()
        return "\n".join(
            difflib.unified_diff(
                original_lines,
                updated_lines,
                fromfile=f"a/{rel_path}",
                tofile=f"b/{rel_path}",
                lineterm="",
            )
        )

    def _replace_function(self, text: str, name: str, replacement: str) -> tuple[str, bool]:
        try:
            module = ast.parse(text)
        except SyntaxError:
            return text, False

        lines = text.splitlines()
        for node in module.body:
            if isinstance(node, ast.FunctionDef) and node.name == name and node.end_lineno:
                start = node.lineno - 1
                end = node.end_lineno
                new_lines = lines[:start] + replacement.strip("\n").splitlines() + lines[end:]
                updated = "\n".join(new_lines)
                if text.endswith("\n"):
                    updated += "\n"
                return updated, True
        return text, False

    @staticmethod
    def _ensure_import(text: str, statement: str) -> tuple[str, bool]:
        if statement in text:
            return text, False
        lines = text.splitlines()
        insert_index = 0
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("import") or stripped.startswith("from"):
                insert_index = idx + 1
        lines.insert(insert_index, statement)
        return "\n".join(lines), True

    # ------------------------------------------------------------------
    # Rule handlers
    # ------------------------------------------------------------------
    def _disable_flask_debug(self, context: "VulnerabilityContext") -> _PatchResult | None:
        """Flip ``debug=True`` to ``debug=False`` in Flask entrypoints."""

        rel_path = context.metadata.get("path")
        if not isinstance(rel_path, str) or not rel_path:
            return None

        target_path = self.repo_root / rel_path
        if not target_path.exists():
            return None

        original_text = target_path.read_text(encoding="utf-8")
        original_lines = original_text.splitlines()
        line_index = self._locate_debug_line(original_lines, context.code_snippets)
        if line_index is None:
            return None

        updated_lines = list(original_lines)
        updated_lines[line_index] = self._rewrite_debug_line(updated_lines[line_index])

        if updated_lines == original_lines:
            return None

        diff = "\n".join(
            difflib.unified_diff(
                original_lines,
                updated_lines,
                fromfile=f"a/{rel_path}",
                tofile=f"b/{rel_path}",
                lineterm="",
            )
        )
        if not diff.strip():
            return None

        rationale = (
            "Disable Flask debug mode before deployment so the server does not expose stack traces "
            "or the Werkzeug debugger. Mirrors the approach used in the MPC_OWASP_POC remediation "
            "pipeline by forcing `debug=False` when starting the app."
        )
        return _PatchResult(
            file_path=rel_path,
            diff=diff,
            rationale=rationale,
            confidence=0.65,
        )

    def _sanitize_prompt_builder(self, context: "VulnerabilityContext") -> _PatchResult | None:
        """Rewrite the prompt builder to normalise and quote user input."""

        loaded = self._load_target(context)
        if not loaded:
            return None
        rel_path, target_path, original_text = loaded

        if "User instruction (sanitized)" in original_text:
            return None

        sanitized_body = textwrap.dedent(
            """
            def build_prompt(user_input: str, *, system_prompt: str = \"You are a helpful AI\") -> str:
                \"\"\"Construct a prompt that treats untrusted input as inert content.\"\"\"

                normalized = user_input.replace(\"\\r\\n\", \"\\n\").replace(\"\\r\", \"\\n\")
                safe_lines: list[str] = []
                for raw_line in normalized.splitlines():
                    stripped = \"\".join(ch for ch in raw_line if ch.isprintable()).strip()
                    if stripped:
                        safe_lines.append(stripped)
                sanitized_input = \"\\n\".join(safe_lines).strip()
                if len(sanitized_input) > 4000:
                    sanitized_input = sanitized_input[:4000]
                if not sanitized_input:
                    sanitized_input = \"[no user input provided]\"
                quoted = textwrap.indent(sanitized_input, prefix=\"> \")
                prompt = f\"{system_prompt}\\n\\nUser instruction (sanitized):\\n{quoted}\"
                return prompt
            """
        ).strip("\n")

        updated_text, changed = self._replace_function(original_text, "build_prompt", sanitized_body)
        if not changed:
            return None

        updated_text, _ = self._ensure_import(updated_text, "import textwrap")

        diff = self._make_diff(rel_path, original_text, updated_text)
        rationale = (
            "Normalise and bound user-provided instructions before including them in the prompt. "
            "Collapsing control characters and rendering the payload as a quoted block mirrors "
            "the Semgrep recommendation for mitigating prompt-injection."
        )
        target_path.write_text(updated_text, encoding="utf-8")
        return _PatchResult(
            file_path=rel_path,
            diff=diff,
            rationale=rationale,
            confidence=0.6,
        )

    def _enforce_secure_model_invocation(self, context: "VulnerabilityContext") -> _PatchResult | None:
        """Ensure model invocations require HTTPS and certificate validation."""

        loaded = self._load_target(context)
        if not loaded:
            return None
        rel_path, target_path, original_text = loaded

        if "verify=True" in original_text and "raise_for_status" in original_text:
            return None

        updated_text, added_import = self._ensure_import(original_text, "import os")
        updated_text, added_urlparse = self._ensure_import(updated_text, "from urllib.parse import urlparse")
        updated_text = updated_text

        secure_body = textwrap.dedent(
            """
            def invoke_insecure_model(
                prompt: str,
                *,
                model_url: str | None = None,
                session: _RequestsShim | None = None,
            ) -> str:
                \"\"\"Send a prompt to an LLM endpoint over HTTPS with certificate validation.\"\"\"

                target_url = model_url or os.environ.get(\"MCP_SECURE_MODEL_URL\") or \"https://secure-model.local/invoke\"
                parsed = urlparse(target_url)
                if parsed.scheme != \"https\":
                    raise ValueError(\"model_url must use https\")

                http_client = session or requests
                response = http_client.post(
                    target_url,
                    json={\"prompt\": prompt, \"temperature\": 1.0},
                    timeout=30,
                    verify=True,
                )
                response.raise_for_status()
                return response.text
            """
        ).strip("\n")

        refreshed_text, changed = self._replace_function(updated_text, "invoke_insecure_model", secure_body)
        if not changed:
            return None

        diff = self._make_diff(rel_path, original_text, refreshed_text)
        rationale = (
            "LLM calls should always use HTTPS endpoints with certificate verification enabled. "
            "The patch enforces TLS-only URLs, honours MCP_SECURE_MODEL_URL overrides, and ensures "
            "transport failures surface via raise_for_status()."
        )
        target_path.write_text(refreshed_text, encoding="utf-8")
        return _PatchResult(
            file_path=rel_path,
            diff=diff,
            rationale=rationale,
            confidence=0.6,
        )

    def _ensure_command_helper(self, text: str) -> tuple[str, bool]:
        if "def _resolve_command" in text:
            return text, False

        helper_block = textwrap.dedent(
            """
            def _resolve_command(
                llm_command: str,
                *,
                allowed_commands: Mapping[str, Sequence[str]] | None = None,
            ) -> Sequence[str]:
                normalized = llm_command.strip()
                if not normalized:
                    raise ValueError(\"Command must not be empty\")

                parts = shlex.split(normalized, posix=True)
                if not parts:
                    raise ValueError(\"Command must not be empty\")

                allowlist = dict(allowed_commands or {})
                if not allowlist:
                    raise ValueError(\"allowed_commands must contain at least one permitted entry\")

                canonical = allowlist.get(parts[0])
                if not canonical:
                    raise ValueError(f\"Command '{parts[0]}' is not permitted\")

                return list(canonical) + parts[1:]
            """
        ).strip("\n")
        return f"{helper_block}\n\n{text}", True

    def _parameterize_flask_sql(self, context: "VulnerabilityContext") -> _PatchResult | None:
        """Rewrite vulnerable Flask SQL handlers to use parameterised queries."""

        loaded = self._load_target(context)
        if not loaded:
            return None
        rel_path, target_path, original_text = loaded

        secure_search = textwrap.dedent(
            """
            def search():
                q = request.args.get("q", "")
                results = None
                if q:
                    db = get_db()
                    cur = db.cursor()
                    sql = "SELECT id, username FROM users WHERE username LIKE ?;"
                    like_pattern = f"%{q}%"
                    cur.execute(sql, (like_pattern,))
                    results = cur.fetchall()
                return render_template_string(SEARCH_HTML, results=results)
            """
        ).strip("\n")

        secure_login = textwrap.dedent(
            """
            def login():
                user = None
                if request.method == "POST":
                    username = request.form.get("username", "")
                    password = request.form.get("password", "")
                    db = get_db()
                    cur = db.cursor()
                    sql = (
                        "SELECT id, username FROM users WHERE username = ? "
                        "AND password = ? LIMIT 1;"
                    )
                    cur.execute(sql, (username, password))
                    row = cur.fetchone()
                    user = row
                return render_template_string(LOGIN_HTML, user=user)
            """
        ).strip("\n")

        updated_text = original_text
        changed = False

        updated_text, search_changed = self._replace_function(updated_text, "search", secure_search)
        changed = changed or search_changed

        updated_text, login_changed = self._replace_function(updated_text, "login", secure_login)
        changed = changed or login_changed

        if not changed:
            return None

        diff = self._make_diff(rel_path, original_text, updated_text)
        rationale = (
            "Use parameterised SQL queries to prevent injection vulnerabilities in the Flask demo app. "
            "The rewritten handlers avoid manual string concatenation and safely bind untrusted user input."
        )
        target_path.write_text(updated_text, encoding="utf-8")
        return _PatchResult(
            file_path=rel_path,
            diff=diff,
            rationale=rationale,
            confidence=0.55,
        )

    def _enforce_tool_allowlist(self, context: "VulnerabilityContext") -> _PatchResult | None:
        """Replace shell=True execution with an allow-listed subprocess invocation."""

        loaded = self._load_target(context)
        if not loaded:
            return None
        rel_path, target_path, original_text = loaded

        if "shell=True" not in original_text:
            return None

        updated_text, _ = self._ensure_import(original_text, "import shlex")
        updated_text, _ = self._ensure_import(updated_text, "from typing import Mapping, Sequence")
        updated_text, _ = self._ensure_command_helper(updated_text)

        hardened_body = textwrap.dedent(
            """
            def execute_tool_response(
                llm_command: str,
                *,
                runner: Runner | None = None,
                allowed_commands: Mapping[str, Sequence[str]] | None = None,
            ) -> int:
                \"\"\"Safely execute an allow-listed tool invocation.\"\"\"

                command = _resolve_command(llm_command, allowed_commands=allowed_commands)
                executor = runner or (lambda args: subprocess.run(args, check=False).returncode)
                return executor(command)
            """
        ).strip("\n")

        refreshed_text, changed = self._replace_function(updated_text, "execute_tool_response", hardened_body)
        if not changed:
            return None

        diff = self._make_diff(rel_path, original_text, refreshed_text)
        rationale = (
            "Executing LLM-sourced commands via shell=True invites injection. The updated helper "
            "tokenises the command, enforces an allow-list, and executes without a shell."
        )
        target_path.write_text(refreshed_text, encoding="utf-8")
        return _PatchResult(
            file_path=rel_path,
            diff=diff,
            rationale=rationale,
            confidence=0.6,
        )

    def _enforce_os_allowlist(self, context: "VulnerabilityContext") -> _PatchResult | None:
        """Require explicit allow-lists before dispatching binaries via os.system."""

        loaded = self._load_target(context)
        if not loaded:
            return None
        rel_path, target_path, original_text = loaded

        if "allowed_binaries" in original_text and "shlex.split" in original_text:
            return None

        updated_text, _ = self._ensure_import(original_text, "import shlex")

        hardened_body = textwrap.dedent(
            """
            def dispatch_with_os_system(
                llm_script: str,
                *,
                runner: Runner | None = None,
                allowed_binaries: Sequence[str] | None = None,
            ) -> int:
                \"\"\"Execute a shell-free, allow-listed script invocation.\"\"\"

                if not allowed_binaries:
                    raise ValueError(\"allowed_binaries must contain at least one executable\")

                allowed = set(allowed_binaries)
                command = shlex.split(llm_script.strip(), posix=True)
                if not command:
                    raise ValueError(\"Command must not be empty\")

                binary = command[0]
                if binary not in allowed:
                    raise ValueError(f\"Binary '{binary}' is not permitted\")

                executor = runner or (lambda args: subprocess.run(args, check=False).returncode)
                return executor(command)
            """
        ).strip("\n")

        refreshed_text, changed = self._replace_function(updated_text, "dispatch_with_os_system", hardened_body)
        if not changed:
            return None

        diff = self._make_diff(rel_path, original_text, refreshed_text)
        rationale = (
            "Avoid feeding raw LLM output into os.system. Parsing commands without a shell and enforcing "
            "explicit binary allow-lists prevents arbitrary code execution."
        )
        target_path.write_text(refreshed_text, encoding="utf-8")
        return _PatchResult(
            file_path=rel_path,
            diff=diff,
            rationale=rationale,
            confidence=0.6,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _locate_debug_line(
        lines: Sequence[str],
        snippets: Sequence[str] | None,
    ) -> int | None:
        """Locate the first line that appears to toggle Flask debug mode."""

        candidates: List[str] = []
        if snippets:
            for snippet in snippets:
                snippet = snippet.strip()
                if snippet:
                    candidates.append(snippet)
                for snippet_line in snippet.splitlines():
                    snippet_line = snippet_line.strip()
                    if snippet_line:
                        candidates.append(snippet_line)

        candidates.extend(["app.run(debug=True)", "app.debug = True"])

        for index, line in enumerate(lines):
            normalized = line.strip()
            if "debug=True" in line or normalized in candidates:
                return index
        return None

    @staticmethod
    def _rewrite_debug_line(line: str) -> str:
        """Rewrite ``line`` so that debug mode is disabled."""

        if "debug=True" in line:
            return line.replace("debug=True", "debug=False")

        stripped = line.lstrip()
        indent = line[: len(line) - len(stripped)]
        if stripped.startswith("app.debug"):
            return f"{indent}app.debug = False"
        return line


__all__ = ["HeuristicPatchGenerator"]
