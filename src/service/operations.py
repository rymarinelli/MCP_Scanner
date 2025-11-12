"""Operational helpers for executing MCP scans via the HTTP service."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Mapping, MutableMapping, Optional

from mcp_scanner.remediation import RemediationSuggester
from remediation.dspy_driver import DSPyRemediationDriver

from semgrep_runner import (
    RunnerOutput,
    build_command,
    execute_semgrep,
    interpret_result,
    load_config,
)


class ScanExecutionError(RuntimeError):
    """Raised when a step in the scan workflow fails."""


def _run_subprocess(command: List[str], *, cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
    """Execute a subprocess command and capture its output."""

    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd is not None else None,
    )


def clone_repository(repo_url: str, branch: str | None, workspace: Path) -> Path:
    """Clone the requested repository into ``workspace`` and return the path."""

    repo_dir = workspace / "repository"
    command = ["git", "clone", "--depth", "1"]
    if branch:
        command.extend(["--branch", branch])
    command.extend([repo_url, str(repo_dir)])

    result = _run_subprocess(command)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "Unknown git error"
        raise ScanExecutionError(f"git clone failed: {message}")

    return repo_dir


def run_semgrep_scan(repo_path: Path) -> RunnerOutput:
    """Run Semgrep against ``repo_path`` using the bundled configuration."""

    config_path = Path("semgrep_rules/config.json")
    configs = load_config(config_path)
    command = build_command(configs, targets=["."], base_dir=config_path.parent.resolve())
    result = execute_semgrep(command, cwd=repo_path)
    return interpret_result(result, command)


def _ensure_mapping(payload: Mapping[str, object]) -> Dict[str, object]:
    if isinstance(payload, MutableMapping):
        return dict(payload)
    return dict(payload)


def generate_remediations(semgrep_output: RunnerOutput, workspace: Path) -> Dict[str, object]:
    """Generate remediation proposals from Semgrep findings."""

    semgrep_results = semgrep_output.results
    if not isinstance(semgrep_results, Mapping):
        raise ScanExecutionError("Semgrep output did not contain a results mapping")

    findings_path = workspace / "semgrep_results.json"
    findings_path.write_text(json.dumps(_ensure_mapping(semgrep_results), indent=2))

    suggester = RemediationSuggester(output_dir=workspace / "remediations")
    driver = DSPyRemediationDriver(
        suggester=suggester,
        output_markdown=workspace / "dspy_suggestions.md",
    )

    proposals = driver.run(
        semgrep_path=findings_path,
        rag_context_path=workspace / "rag_context.json",
    )

    summary_markdown = driver.output_markdown.read_text(encoding="utf-8")
    return {
        "proposals": [proposal.to_dict() for proposal in proposals],
        "summary_markdown": summary_markdown,
    }


def perform_scan(*, repo_url: str, branch: str | None = None) -> Dict[str, object]:
    """Execute the full scan and remediation workflow for a repository."""

    if not repo_url:
        raise ValueError("repo_url is required")

    with tempfile.TemporaryDirectory(prefix="mcp-scan-") as tmpdir:
        workspace = Path(tmpdir)
        repo_path = clone_repository(repo_url, branch, workspace)
        semgrep_output = run_semgrep_scan(repo_path)

        semgrep_payload = semgrep_output.to_dict()
        if semgrep_output.normalized_exit_code != 0:
            raise ScanExecutionError(
                "Semgrep execution failed",
            )

        remediation_payload = generate_remediations(semgrep_output, workspace)

        return {
            "repository": {
                "url": repo_url,
                "branch": branch,
            },
            "semgrep": semgrep_payload,
            "remediation": remediation_payload,
        }
