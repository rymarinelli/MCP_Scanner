from __future__ import annotations

import ast
import difflib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from mcp_scanner.dspy_programs import DSPyResponse
from mcp_scanner.models import VulnerabilityContext


@dataclass
class _Token:
    kind: str  # 'text' or 'param'
    value: str


class _SQLExpressionParser(ast.NodeVisitor):
    """Parse SQL expressions that build strings via f-strings or concatenation."""

    def __init__(self) -> None:
        self.tokens: List[_Token] = []
        self.valid = True

    def parse(self, expression: str) -> Optional[tuple[str, List[str]]]:
        try:
            tree = ast.parse(expression, mode="eval")
        except SyntaxError:
            return None

        self.tokens.clear()
        self.valid = True
        self.visit(tree.body)
        if not self.valid:
            return None
        if not any(token.kind == "param" for token in self.tokens):
            return None

        params: List[str] = []
        safe_parts: List[str] = []
        tokens = list(self.tokens)
        for index, token in enumerate(tokens):
            if token.kind == "text":
                safe_parts.append(token.value)
                continue

            prev_text = safe_parts[-1] if safe_parts else ""
            next_token = tokens[index + 1] if index + 1 < len(tokens) else None
            next_text = next_token.value if next_token and next_token.kind == "text" else ""

            if prev_text.endswith("'") or prev_text.endswith('"'):
                safe_parts[-1] = prev_text[:-1]
                prev_text = safe_parts[-1]
            prefix_percent = prev_text.endswith("%")
            if prefix_percent:
                safe_parts[-1] = prev_text[:-1]

            if next_token and next_token.kind == "text" and (
                next_text.startswith("'") or next_text.startswith('"')
            ):
                tokens[index + 1] = _Token("text", next_text[1:])
                next_token = tokens[index + 1]
                next_text = next_token.value
            suffix_percent = bool(next_text.startswith("%"))
            if suffix_percent and next_token and next_token.kind == "text":
                tokens[index + 1] = _Token("text", next_text[1:])
                next_token = tokens[index + 1]
                next_text = next_token.value

            param_name = token.value
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", param_name):
                self.valid = False
                return None

            if prefix_percent and suffix_percent:
                param_expr = f'f"%{{{param_name}}}%"'
            elif prefix_percent:
                param_expr = f'f"%{{{param_name}}}"'
            elif suffix_percent:
                param_expr = f'f"{{{param_name}}}%"'
            else:
                param_expr = param_name

            safe_parts.append("?")
            params.append(param_expr)

        query = "".join(safe_parts)
        query = self._normalize_query(query)
        return query, params

    @staticmethod
    def _normalize_query(query: str) -> str:
        replacements = {
            "'%?%'": "'%' || ? || '%'",
            '"%?%"': '"%" || ? || "%"',
            "'%?'": "'%' || ?",
            '"%?"': '"%" || ?',
        }
        for target, value in replacements.items():
            query = query.replace(target, value)
        query = query.replace("'?'", "?")
        query = query.replace('"?"', '?')
        return query

    def visit_BinOp(self, node: ast.BinOp) -> None:  # type: ignore[override]
        if not isinstance(node.op, ast.Add):
            self.valid = False
            return
        self.visit(node.left)
        self.visit(node.right)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:  # type: ignore[override]
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                inner = value.value
                if isinstance(inner, ast.Name):
                    self.tokens.append(_Token("param", inner.id))
                else:
                    self.valid = False
                    return
            elif isinstance(value, ast.Constant) and isinstance(value.value, str):
                self.tokens.append(_Token("text", value.value))
            else:
                self.valid = False
                return

    def visit_Constant(self, node: ast.Constant) -> None:  # type: ignore[override]
        if isinstance(node.value, str):
            self.tokens.append(_Token("text", node.value))
        else:
            self.valid = False

    def visit_Name(self, node: ast.Name) -> None:  # type: ignore[override]
        self.tokens.append(_Token("param", node.id))

    def generic_visit(self, node: ast.AST) -> None:  # type: ignore[override]
        allowed = (ast.Expression, ast.FormattedValue)
        if not isinstance(node, allowed):
            self.valid = False
            return
        super().generic_visit(node)


class HeuristicPatchSuggestionProgram:
    """Fallback patch generator that applies deterministic heuristics."""

    def __init__(self, *, repo_root: Path, instructions: str | None = None) -> None:
        self.repo_root = Path(repo_root)
        self.instructions = instructions or (
            "Applying rule-based remediations using Semgrep metadata and code context."
        )
        self._parser = _SQLExpressionParser()

    def forward(self, context: VulnerabilityContext) -> DSPyResponse:
        patches = []

        sql_patch = self._try_fix_sql_issue(context)
        if sql_patch:
            patches.append(sql_patch)

        debug_patch = self._try_fix_flask_debug(context)
        if debug_patch:
            patches.append(debug_patch)

        raw_summary = json.dumps(
            {
                "vulnerability_id": context.vulnerability_id,
                "patches": [patch["rationale"] for patch in patches],
            }
        )
        return DSPyResponse(patches=patches, raw_output=raw_summary)

    def _try_fix_sql_issue(self, context: VulnerabilityContext) -> Optional[dict]:
        metadata = context.metadata or {}
        message = metadata.get("message", "")
        if "sql" not in message.lower():
            return None

        file_path = metadata.get("path")
        if not file_path:
            return None
        source_path = self.repo_root / file_path
        if not source_path.exists():
            return None

        start = metadata.get("start", {}) or {}
        line_number = start.get("line")
        lines = source_path.read_text().splitlines()
        if not line_number or line_number < 1 or line_number > len(lines):
            search_start = 0
        else:
            search_start = max(0, line_number - 5)
        search_end = min(len(lines), (line_number or len(lines)) + 5)

        assign_idx = None
        execute_idx = None
        for idx in range(search_start, search_end):
            stripped = lines[idx].strip()
            if assign_idx is None and "=" in stripped and "SELECT" in stripped.upper():
                assign_idx = idx
            if "execute" in stripped and "(" in stripped:
                execute_idx = idx
                if assign_idx is None:
                    assign_idx = max(search_start, idx - 3)
                break

        if assign_idx is None or execute_idx is None:
            return None

        assign_line = lines[assign_idx]
        if "=" not in assign_line:
            return None
        lhs, rhs = assign_line.split("=", 1)
        expression = rhs.strip()
        parsed = self._parser.parse(expression)
        if not parsed:
            return None
        query, params = parsed
        if not params:
            return None

        updated_lines = list(lines)
        assign_indent = assign_line[: len(assign_line) - len(assign_line.lstrip())]
        query_literal = json.dumps(query)
        target_name = lhs.strip().split()[0]
        updated_lines[assign_idx] = f"{assign_indent}{target_name} = {query_literal}"

        execute_line = lines[execute_idx]
        exec_code, _, exec_comment = execute_line.partition("#")
        exec_indent = exec_code[: len(exec_code) - len(exec_code.lstrip())]
        exec_prefix = exec_code.strip().split("(", 1)[0]
        params_tuple = self._format_params(params)
        new_call = f"{exec_prefix}({target_name}, {params_tuple})"
        new_line = f"{exec_indent}{new_call}".rstrip()
        if exec_comment:
            new_line += f"  #{exec_comment.strip()}"
        updated_lines[execute_idx] = new_line

        if updated_lines == lines:
            return None

        diff = self._build_diff(source_path, lines, updated_lines)
        return {
            "file_path": file_path,
            "diff": diff,
            "rationale": "Parameterize SQL query execution to avoid string interpolation vulnerabilities.",
            "confidence": 0.4,
        }

    def _format_params(self, params: Sequence[str]) -> str:
        formatted = list(params)
        if not formatted:
            return "()"
        if len(formatted) == 1:
            return f"({formatted[0]},)"
        return "(" + ", ".join(formatted) + ")"

    def _try_fix_flask_debug(self, context: VulnerabilityContext) -> Optional[dict]:
        metadata = context.metadata or {}
        rule_id = metadata.get("rule_id", "")
        message = metadata.get("message", "")
        if "debug" not in message.lower() and "debug" not in str(rule_id).lower():
            return None

        file_path = metadata.get("path")
        if not file_path:
            return None
        source_path = self.repo_root / file_path
        if not source_path.exists():
            return None

        lines = source_path.read_text().splitlines()
        run_idx = None
        for idx, line in enumerate(lines):
            if "app.run" in line and "debug=True" in line:
                run_idx = idx
                break
        if run_idx is None:
            return None

        updated_lines = list(lines)
        original_line = lines[run_idx]
        indent = original_line[: len(original_line) - len(original_line.lstrip())]
        before, after = original_line.split("debug=True", 1)
        new_debug = ("debug=os.environ.get(\"FLASK_DEBUG\", \"0\").lower() in {\"1\", \"true\", \"yes\"}")
        updated_lines[run_idx] = f"{indent}{before}{new_debug}{after}"

        if not any(re.match(r"\s*import os\b", line) for line in lines):
            insert_idx = 0
            for idx, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("import ") or stripped.startswith("from "):
                    insert_idx = idx + 1
            updated_lines.insert(insert_idx, "import os")

        if updated_lines == lines:
            return None

        diff = self._build_diff(source_path, lines, updated_lines)
        return {
            "file_path": file_path,
            "diff": diff,
            "rationale": "Disable Flask debug mode by default and defer to environment configuration.",
            "confidence": 0.3,
        }

    @staticmethod
    def _build_diff(path: Path, original: Sequence[str], updated: Sequence[str]) -> str:
        diff_lines = difflib.unified_diff(
            [line + "\n" for line in original],
            [line + "\n" for line in updated],
            fromfile=str(path),
            tofile=str(path),
        )
        return "".join(diff_lines)


__all__ = ["HeuristicPatchSuggestionProgram"]
