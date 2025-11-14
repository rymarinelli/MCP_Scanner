"""Unit tests for the service orchestration helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import json
import subprocess
import pytest

import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from semgrep_runner import RunnerConfig, RunnerOutput

from service.operations import (
    CommitApplicationResult,
    CommitRecord,
    RemediationOutcome,
    ScanExecutionError,
    apply_remediation_commits,
    clone_repository,
    generate_remediations,
    perform_scan,
    run_semgrep_scan,
    _parse_repo_slug,
)

from mcp_scanner.models import PatchProposal


class DummyCompletedProcess:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_clone_repository_success(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: Dict[str, Any] = {}

    def fake_run(command, **kwargs):  # type: ignore[no-redef]
        captured["command"] = command
        captured["kwargs"] = kwargs
        target = Path(command[-1])
        target.mkdir(parents=True, exist_ok=True)
        return DummyCompletedProcess(returncode=0)

    monkeypatch.setattr("service.operations._run_subprocess", fake_run)

    repo = clone_repository("https://example.com/repo.git", "main", tmp_path)
    assert repo.exists()
    assert captured["command"][0:4] == ["git", "clone", "--depth", "1"]


def test_clone_repository_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(command, **kwargs):  # type: ignore[no-redef]
        return DummyCompletedProcess(returncode=1, stderr="fatal: not found")

    monkeypatch.setattr("service.operations._run_subprocess", fake_run)

    with pytest.raises(ScanExecutionError, match="git clone failed"):
        clone_repository("https://invalid/repo.git", None, tmp_path)


def test_run_semgrep_scan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_load_config(path):  # type: ignore[no-redef]
        return ["cfg"]

    def fake_build(configs, targets, base_dir):  # type: ignore[no-redef]
        assert configs == ["cfg"]
        assert targets == ["."]
        assert base_dir.is_dir()
        return ["semgrep", "scan"]

    def fake_execute(command, *, cwd):  # type: ignore[no-redef]
        assert command == ["semgrep", "scan"]
        assert cwd == tmp_path
        return DummyCompletedProcess(returncode=0, stdout="{}")

    def fake_interpret(result, command):  # type: ignore[no-redef]
        return RunnerOutput(
            status="ok",
            normalized_exit_code=0,
            semgrep_exit_code=0,
            command=command,
            results={"results": []},
            stderr=None,
        )

    monkeypatch.setattr("service.operations.load_config", fake_load_config)
    monkeypatch.setattr("service.operations.build_command", fake_build)
    monkeypatch.setattr("service.operations.execute_semgrep", fake_execute)
    monkeypatch.setattr("service.operations.interpret_result", fake_interpret)

    output = run_semgrep_scan(tmp_path)
    assert output.status == "ok"


def test_run_semgrep_scan_quick_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def fake_build(configs, targets, base_dir):  # type: ignore[no-redef]
        assert len(configs) == 1
        assert configs[0].value == "auto"
        command = ["semgrep", "scan"]
        for config in configs:
            command.extend(["--config", config.value])
        command.extend(targets)
        return command

    def fake_execute(command, *, cwd):  # type: ignore[no-redef]
        assert command == ["semgrep", "scan", "--config", "auto", "."]
        assert cwd == repo
        return DummyCompletedProcess(returncode=0, stdout="{}", stderr="")

    def fake_interpret(result, command):  # type: ignore[no-redef]
        return RunnerOutput(
            status="ok",
            normalized_exit_code=0,
            semgrep_exit_code=0,
            command=command,
            results={"results": []},
            stderr=None,
        )

    monkeypatch.setattr("service.operations.build_command", fake_build)
    monkeypatch.setattr("service.operations.execute_semgrep", fake_execute)
    monkeypatch.setattr("service.operations.interpret_result", fake_interpret)

    output = run_semgrep_scan(repo, quick=True)
    assert output.status == "ok"


def test_run_semgrep_scan_falls_back_when_remote_config_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def fake_load_config(path):  # type: ignore[no-redef]
        return [
            RunnerConfig(type="local", value="custom", label="local-rules"),
            RunnerConfig(type="registry", value="p/owasp-top-ten", label="owasp-top-ten"),
        ]

    calls: list[list[str]] = []

    def fake_build(configs, targets, base_dir):  # type: ignore[no-redef]
        command = ["semgrep"]
        command.extend(f"{cfg.type}:{cfg.value}" for cfg in configs)
        command.extend(targets)
        return command

    def fake_execute(command, *, cwd):  # type: ignore[no-redef]
        calls.append(list(command))
        if len(calls) == 1:
            return DummyCompletedProcess(returncode=2, stdout="", stderr="ProxyError")
        return DummyCompletedProcess(returncode=0, stdout="{}", stderr="")

    def fake_interpret(result, command):  # type: ignore[no-redef]
        if result.returncode != 0:
            return RunnerOutput(
                status="failed",
                normalized_exit_code=1,
                semgrep_exit_code=result.returncode,
                command=command,
                results={"results": [], "errors": []},
                stderr=result.stderr,
            )
        return RunnerOutput(
            status="ok",
            normalized_exit_code=0,
            semgrep_exit_code=0,
            command=command,
            results={"results": [], "errors": []},
            stderr=None,
        )

    monkeypatch.setattr("service.operations.load_config", fake_load_config)
    monkeypatch.setattr("service.operations.build_command", fake_build)
    monkeypatch.setattr("service.operations.execute_semgrep", fake_execute)
    monkeypatch.setattr("service.operations.interpret_result", fake_interpret)

    output = run_semgrep_scan(repo)
    assert output.normalized_exit_code == 0
    assert len(calls) == 2
    errors = output.results.get("errors", [])
    assert any(err.get("reason") == "remote_config_unavailable" for err in errors)
    skipped = next(
        err["skipped_configs"]
        for err in errors
        if err.get("reason") == "remote_config_unavailable"
    )
    assert skipped == ["owasp-top-ten"]


def test_generate_remediations_creates_summary(tmp_path: Path) -> None:
    output = RunnerOutput(
        status="ok",
        normalized_exit_code=0,
        semgrep_exit_code=0,
        command=["semgrep"],
        results={"results": []},
        stderr=None,
    )

    rag_context_path = tmp_path / "rag_context.json"
    rag_context_path.write_text(json.dumps({"graph": {"nodes": {}, "edges": []}, "node_context": {}}))
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    result = generate_remediations(output, tmp_path, rag_context_path, repo_path)
    assert isinstance(result, RemediationOutcome)
    assert result.proposals == []
    assert "No remediation suggestions" in result.summary_markdown
    serialized = result.to_dict()
    assert serialized["proposals"] == []
    assert "artifacts" in serialized
    artifacts = serialized["artifacts"]
    assert "semgrep_results" in artifacts
    assert artifacts["semgrep_results"].endswith("semgrep_results.json")
    assert "dspy_summary" in artifacts


def test_generate_remediations_adds_builtin_sql_patch(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    vulnerable_source = """
from flask import Flask

def search():
    q = "demo"
    if q:
        db = object()
        cur = db.cursor()
        # ---- VULNERABLE: concatenating user input into SQL ----
        sql = "SELECT id, username FROM users WHERE username LIKE '%" + q + "%';"
        # For the demo we intentionally execute this unsafe SQL
        cur.execute(sql)
        results = cur.fetchall()


def login():
    username = "user"
    password = "pass"
    db = object()
    cur = db.cursor()
    # ---- VULNERABLE: direct string formatting into SQL ----
    sql = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}' LIMIT 1;"
    cur.execute(sql)
    row = cur.fetchone()
    return row
""".strip()

    (repo_path / "app_vuln.py").write_text(vulnerable_source + "\n", encoding="utf-8")

    rag_context_path = workspace / "rag_context.json"
    rag_context_path.write_text(json.dumps({"graph": {"nodes": {}, "edges": []}, "node_context": {}}))

    output = RunnerOutput(
        status="ok",
        normalized_exit_code=0,
        semgrep_exit_code=0,
        command=["semgrep"],
        results={
            "results": [
                {
                    "check_id": "workspace.MCP_Scanner.semgrep_rules.custom.python-sql-injection-string-concat",
                    "path": "app_vuln.py",
                }
            ]
        },
        stderr=None,
    )

    result = generate_remediations(output, workspace, rag_context_path, repo_path)
    assert any(
        proposal.file_path == "app_vuln.py"
        and "SELECT id, username FROM users WHERE username LIKE ?" in proposal.diff
        for proposal in result.proposals
    )


def test_perform_scan_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_clone(repo_url, branch, workspace):  # type: ignore[no-redef]
        path = workspace / "repo"
        path.mkdir()
        return path

    fake_output = RunnerOutput(
        status="ok",
        normalized_exit_code=0,
        semgrep_exit_code=0,
        command=["semgrep"],
        results={"results": []},
        stderr=None,
    )

    def fake_semgrep(path, *, quick=False):  # type: ignore[no-redef]
        assert quick is False
        return fake_output

    def fake_enumeration(repo_path, workspace):  # type: ignore[no-redef]
        dummy_path = workspace / "rag_context.json"
        dummy_path.write_text("{}")
        rag_dir = workspace / "rag"
        rag_dir.mkdir()
        raw_graph = rag_dir / "raw_graph.json"
        raw_graph.write_text("{}")
        graph_html = rag_dir / "rag_graph.html"
        graph_html.write_text("<html></html>")
        payload = {
            "rag_context": {},
            "artifacts": {
                "raw_graph": str(raw_graph),
                "graph_html": str(graph_html),
                "rag_context": str(dummy_path),
            },
        }
        artifact_paths = {
            "raw_graph": raw_graph,
            "graph_html": graph_html,
            "rag_context": dummy_path,
        }
        return payload, dummy_path, artifact_paths

    def fake_remediation(output, workspace, rag_context_path, repo_path):  # type: ignore[no-redef]
        return RemediationOutcome(proposals=[], summary_markdown="report", artifacts={})

    def fake_apply(repo_path, proposals):  # type: ignore[no-redef]
        assert proposals == []
        return CommitApplicationResult(branch="mcp/remediation-demo", commits=[], errors=[])

    def fail_push(*args, **kwargs):  # type: ignore[no-redef]
        raise AssertionError("push should not be invoked when no commits are produced")

    def fail_pr(*args, **kwargs):  # type: ignore[no-redef]
        raise AssertionError("pull request should not be attempted when no commits exist")

    monkeypatch.setattr("service.operations.clone_repository", fake_clone)
    monkeypatch.setattr("service.operations.enumerate_repository", fake_enumeration)
    monkeypatch.setattr("service.operations.run_semgrep_scan", fake_semgrep)
    monkeypatch.setattr("service.operations.generate_remediations", fake_remediation)
    monkeypatch.setattr("service.operations.apply_remediation_commits", fake_apply)
    monkeypatch.setattr("service.operations.push_remediation_branch", fail_push)
    monkeypatch.setattr("service.operations.open_remediation_pull_request", fail_pr)

    result = perform_scan(repo_url="https://example.com/demo.git", branch="main")
    assert result["repository"]["url"] == "https://example.com/demo.git"
    assert result["remediation"]["proposals"] == []
    assert result["remediation"]["summary_markdown"] == "report"
    assert result["enumeration"]["rag_context"] == {}


def test_perform_scan_skips_commits_when_disabled(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    def fake_clone(repo_url, branch, workspace):  # type: ignore[no-redef]
        return repo_dir

    fake_output = RunnerOutput(
        status="ok",
        normalized_exit_code=0,
        semgrep_exit_code=0,
        command=["semgrep"],
        results={"results": []},
        stderr=None,
    )

    def fake_semgrep(path, *, quick=False):  # type: ignore[no-redef]
        assert quick is True
        return fake_output

    def fake_enumeration(repo_path, workspace):  # type: ignore[no-redef]
        rag_context_path = workspace / "rag_context.json"
        rag_context_path.write_text("{}")
        return {"rag_context": {}}, rag_context_path, {}

    def fake_remediation(output, workspace, rag_context_path, repo_path):  # type: ignore[no-redef]
        return RemediationOutcome(proposals=[], summary_markdown="summary", artifacts={})

    def fail_apply(*args, **kwargs):  # type: ignore[no-redef]
        raise AssertionError("apply_remediation_commits should not be invoked")

    monkeypatch.setattr("service.operations.clone_repository", fake_clone)
    monkeypatch.setattr("service.operations.enumerate_repository", fake_enumeration)
    monkeypatch.setattr("service.operations.run_semgrep_scan", fake_semgrep)
    monkeypatch.setattr("service.operations.generate_remediations", fake_remediation)
    monkeypatch.setattr("service.operations.apply_remediation_commits", fail_apply)

    result = perform_scan(
        repo_url="https://example.com/project.git",
        branch="main",
        quick=True,
        apply_commits=False,
    )

    remediation = result["remediation"]
    assert remediation["summary_markdown"] == "summary"
    assert remediation["proposals"] == []
    assert "push" not in remediation
    assert "pull_request" not in remediation


def test_perform_scan_skips_push_and_pr_when_disabled(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    def fake_clone(repo_url, branch, workspace):  # type: ignore[no-redef]
        return repo_dir

    fake_output = RunnerOutput(
        status="ok",
        normalized_exit_code=0,
        semgrep_exit_code=0,
        command=["semgrep"],
        results={"results": []},
        stderr=None,
    )

    def fake_semgrep(path, *, quick=False):  # type: ignore[no-redef]
        return fake_output

    def fake_enumeration(repo_path, workspace):  # type: ignore[no-redef]
        rag_context_path = workspace / "rag_context.json"
        rag_context_path.write_text("{}")
        return {"rag_context": {}}, rag_context_path, {}

    proposal = PatchProposal(
        vulnerability_id="demo",
        file_path="app.py",
        diff="diff --git a/app.py b/app.py\n",
        rationale="",
        confidence=1.0,
    )

    def fake_remediation(output, workspace, rag_context_path, repo_path):  # type: ignore[no-redef]
        return RemediationOutcome(proposals=[proposal], summary_markdown="summary", artifacts={})

    def fake_apply(repo_path, proposals):  # type: ignore[no-redef]
        commit = CommitRecord(
            vulnerability_id="demo",
            commit_sha="abc1234",
            message="fix(demo): apply remediation",
            proposals=list(proposals),
        )
        return CommitApplicationResult(branch="mcp/remediation-1234", commits=[commit], errors=[])

    def fail_push(*args, **kwargs):  # type: ignore[no-redef]
        raise AssertionError("push_remediation_branch should not be called when disabled")

    def fail_pr(*args, **kwargs):  # type: ignore[no-redef]
        raise AssertionError("open_remediation_pull_request should not be called when push is skipped")

    monkeypatch.setattr("service.operations.clone_repository", fake_clone)
    monkeypatch.setattr("service.operations.enumerate_repository", fake_enumeration)
    monkeypatch.setattr("service.operations.run_semgrep_scan", fake_semgrep)
    monkeypatch.setattr("service.operations.generate_remediations", fake_remediation)
    monkeypatch.setattr("service.operations.apply_remediation_commits", fake_apply)
    monkeypatch.setattr("service.operations.push_remediation_branch", fail_push)
    monkeypatch.setattr("service.operations.open_remediation_pull_request", fail_pr)

    result = perform_scan(
        repo_url="https://example.com/project.git",
        branch="main",
        push=False,
        create_pr=True,
    )

    remediation = result["remediation"]
    assert remediation["push"]["status"] == "skipped"
    assert remediation["push"]["reason"] == "push disabled by configuration"
    assert remediation["pull_request"]["status"] == "skipped"
    assert remediation["pull_request"]["reason"] == "push disabled by configuration"


def test_perform_scan_rejects_option_like_repo_url(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="repo_url must not start with '-'"):
        perform_scan(repo_url="--upload-pack=/tmp/x", branch=None)


def test_perform_scan_rejects_option_like_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="branch must not start with '-'"):
        perform_scan(repo_url="https://example.com/demo.git", branch="-bad")


def _init_git_repo(path: Path) -> Path:
    repo = path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "tester@example.com"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo, check=True, capture_output=True, text=True)
    (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, check=True, capture_output=True, text=True)
    return repo


def test_apply_remediation_commits_creates_commits(tmp_path: Path) -> None:
    repo = _init_git_repo(tmp_path)
    patch = """diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1,2 @@\n-print('hello')\n+print('hello')\n+print('secure')\n"""
    proposal = PatchProposal(
        vulnerability_id="vuln-1",
        file_path="app.py",
        diff=patch,
        rationale="",
        confidence=0.9,
    )

    result = apply_remediation_commits(repo, [proposal])
    assert result.branch is not None
    assert len(result.commits) == 1
    assert not result.errors
    commit = result.commits[0]
    assert commit.vulnerability_id == "vuln-1"
    assert commit.commit_sha
    assert "print('secure')" in (repo / "app.py").read_text(encoding="utf-8")


def test_apply_remediation_commits_handles_failed_patch(tmp_path: Path) -> None:
    repo = _init_git_repo(tmp_path)
    proposal = PatchProposal(
        vulnerability_id="vuln-bad",
        file_path="app.py",
        diff="this is not a diff",
        rationale="",
        confidence=0.0,
    )

    result = apply_remediation_commits(repo, [proposal])
    assert result.commits == []
    assert result.errors
    assert result.errors[0].vulnerability_id == "vuln-bad"
    assert "secure" not in (repo / "app.py").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://github.com/example/project.git", ("example", "project")),
        ("git@github.com:example/project.git", ("example", "project")),
        ("ssh://git@github.com/example/project.git", ("example", "project")),
    ],
)
def test_parse_repo_slug_supports_common_git_urls(url: str, expected: tuple[str, str]) -> None:
    assert _parse_repo_slug(url) == expected

