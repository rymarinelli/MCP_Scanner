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
    _authenticated_remote_candidates,
    _looks_like_patch,
    _normalize_github_token,
    _normalize_git_username,
    _normalize_patch_text,
    _sanitize_remote,
    CommitApplicationResult,
    CommitRecord,
    PullRequestResult,
    RemediationOutcome,
    ScanExecutionError,
    apply_remediation_commits,
    clone_repository,
    PushResult,
    push_remediation_branch,
    generate_remediations,
    perform_scan,
    run_semgrep_scan,
    _parse_repo_slug,
)

from mcp_scanner.models import PatchProposal
from mcp_vanguard.tools.open_pull_request import open_pull_request as open_pull_request_tool


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

    def fail_pr_tool(**kwargs):  # type: ignore[no-redef]
        raise AssertionError("pull request tool should not be invoked when no commits exist")

    monkeypatch.setattr("service.operations._invoke_pull_request_tool", fail_pr_tool)

    result = perform_scan(repo_url="https://example.com/demo.git", branch="main")
    assert result["repository"]["url"] == "https://example.com/demo.git"
    remediation = result["remediation"]
    assert remediation["proposals"] == []
    assert remediation["summary_markdown"] == "report"
    assert remediation["pull_request"]["status"] == "skipped"
    assert remediation["pull_request"]["reason"] == "no remediation commits produced"
    assert remediation["push"]["status"] == "skipped"
    assert remediation["push"]["reason"] == "no remediation commits produced"
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
    assert remediation["push"]["status"] == "skipped"
    assert remediation["push"]["reason"] == "apply_commits disabled by configuration"
    assert remediation["pull_request"]["status"] == "skipped"
    assert remediation["pull_request"]["reason"] == "apply_commits disabled by configuration"


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

    def fail_pr_tool(**kwargs):  # type: ignore[no-redef]
        raise AssertionError("pull request tool should not be called when push is skipped")

    monkeypatch.setattr("service.operations._invoke_pull_request_tool", fail_pr_tool)

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


def test_perform_scan_uses_provided_token(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
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
        confidence=0.9,
    )

    def fake_remediation(output, workspace, rag_context_path, repo_path):  # type: ignore[no-redef]
        return RemediationOutcome(proposals=[proposal], summary_markdown="summary", artifacts={})

    commit = CommitRecord(
        vulnerability_id="demo",
        commit_sha="abcdef1",
        message="fix(demo): remediation",
        proposals=[proposal],
    )

    def fake_apply(repo_path, proposals):  # type: ignore[no-redef]
        return CommitApplicationResult(branch="mcp/remediation-1", commits=[commit], errors=[])

    captured: dict[str, object] = {}

    def fake_push(*, repo_path, repo_url, branch_name, token=None):  # type: ignore[no-redef]
        captured["push_token"] = token
        return PushResult(status="success", branch=branch_name, remote="origin", message="ok")

    def fake_pr_tool(
        *,
        repo_url,
        branch_name,
        base_branch,
        summary_markdown,
        commits,
        token,
        pr_labels,
    ):
        captured["pr_token"] = token
        return PullRequestResult(status="success", url="https://example/pr/1", number=1)

    monkeypatch.setattr("service.operations.clone_repository", fake_clone)
    monkeypatch.setattr("service.operations.enumerate_repository", fake_enumeration)
    monkeypatch.setattr("service.operations.run_semgrep_scan", fake_semgrep)
    monkeypatch.setattr("service.operations.generate_remediations", fake_remediation)
    monkeypatch.setattr("service.operations.apply_remediation_commits", fake_apply)
    monkeypatch.setattr("service.operations.push_remediation_branch", fake_push)
    monkeypatch.setattr("service.operations._invoke_pull_request_tool", fake_pr_tool)

    def fail_pr(*args, **kwargs):  # type: ignore[no-redef]
        raise AssertionError("open_remediation_pull_request should not be used when tool succeeds")

    monkeypatch.setattr("service.operations.open_remediation_pull_request", fail_pr)

    result = perform_scan(
        repo_url="https://example.com/project.git",
        branch="main",
        github_token="ghp_secret",
    )

    remediation = result["remediation"]
    assert remediation["push"]["status"] == "success"
    assert remediation["pull_request"]["status"] == "success"
    assert captured["push_token"] == "ghp_secret"
    assert captured["pr_token"] == "ghp_secret"


def test_perform_scan_uses_env_token_when_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
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
        confidence=0.9,
    )

    def fake_remediation(output, workspace, rag_context_path, repo_path):  # type: ignore[no-redef]
        return RemediationOutcome(proposals=[proposal], summary_markdown="summary", artifacts={})

    commit = CommitRecord(
        vulnerability_id="demo",
        commit_sha="abcdef1",
        message="fix(demo): remediation",
        proposals=[proposal],
    )

    def fake_apply(repo_path, proposals):  # type: ignore[no-redef]
        return CommitApplicationResult(branch="mcp/remediation-1", commits=[commit], errors=[])

    captured: dict[str, object] = {}

    def fake_push(*, repo_path, repo_url, branch_name, token=None):  # type: ignore[no-redef]
        captured["push_token"] = token
        return PushResult(status="success", branch=branch_name, remote="origin", message="ok")

    def fake_pr_tool(
        *,
        repo_url,
        branch_name,
        base_branch,
        summary_markdown,
        commits,
        token,
        pr_labels,
    ):
        captured["pr_token"] = token
        return PullRequestResult(status="success", url="https://example/pr/1", number=1)

    monkeypatch.setenv("GITHUB_TOKEN", "env_secret")
    monkeypatch.setattr("service.operations.clone_repository", fake_clone)
    monkeypatch.setattr("service.operations.enumerate_repository", fake_enumeration)
    monkeypatch.setattr("service.operations.run_semgrep_scan", fake_semgrep)
    monkeypatch.setattr("service.operations.generate_remediations", fake_remediation)
    monkeypatch.setattr("service.operations.apply_remediation_commits", fake_apply)
    monkeypatch.setattr("service.operations.push_remediation_branch", fake_push)
    monkeypatch.setattr("service.operations._invoke_pull_request_tool", fake_pr_tool)

    def fail_pr(*args, **kwargs):  # type: ignore[no-redef]
        raise AssertionError("open_remediation_pull_request should not be used when tool succeeds")

    monkeypatch.setattr("service.operations.open_remediation_pull_request", fail_pr)

    result = perform_scan(
        repo_url="https://example.com/project.git",
        branch="main",
    )

    remediation = result["remediation"]
    assert remediation["push"]["status"] == "success"
    assert remediation["pull_request"]["status"] == "success"
    assert captured["push_token"] == "env_secret"
    assert captured["pr_token"] == "env_secret"


def test_perform_scan_falls_back_when_pull_request_tool_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
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
        confidence=0.9,
    )

    def fake_remediation(output, workspace, rag_context_path, repo_path):  # type: ignore[no-redef]
        return RemediationOutcome(proposals=[proposal], summary_markdown="summary", artifacts={})

    commit = CommitRecord(
        vulnerability_id="demo",
        commit_sha="abcdef1",
        message="fix(demo): remediation",
        proposals=[proposal],
    )

    def fake_apply(repo_path, proposals):  # type: ignore[no-redef]
        return CommitApplicationResult(branch="mcp/remediation-1", commits=[commit], errors=[])

    captured: dict[str, object] = {}

    def fake_push(*, repo_path, repo_url, branch_name, token=None):  # type: ignore[no-redef]
        captured["push_token"] = token
        return PushResult(status="success", branch=branch_name, remote="origin", message="ok")

    def missing_tool(
        *,
        repo_url,
        branch_name,
        base_branch,
        summary_markdown,
        commits,
        token,
        pr_labels,
    ):
        captured["tool_invoked"] = True
        return None

    def fallback_pr(
        *,
        repo_url,
        branch_name,
        base_branch,
        summary_markdown,
        commits,
        token=None,
        pr_labels=None,
    ):
        captured["fallback_token"] = token
        return PullRequestResult(status="success", url="https://example/pr/2", number=2)

    monkeypatch.setenv("GITHUB_TOKEN", "env_secret")
    monkeypatch.setattr("service.operations.clone_repository", fake_clone)
    monkeypatch.setattr("service.operations.enumerate_repository", fake_enumeration)
    monkeypatch.setattr("service.operations.run_semgrep_scan", fake_semgrep)
    monkeypatch.setattr("service.operations.generate_remediations", fake_remediation)
    monkeypatch.setattr("service.operations.apply_remediation_commits", fake_apply)
    monkeypatch.setattr("service.operations.push_remediation_branch", fake_push)
    monkeypatch.setattr("service.operations._invoke_pull_request_tool", missing_tool)
    monkeypatch.setattr("service.operations.open_remediation_pull_request", fallback_pr)

    result = perform_scan(
        repo_url="https://example.com/project.git",
        branch="main",
    )

    remediation = result["remediation"]
    assert remediation["pull_request"]["status"] == "success"
    assert captured["tool_invoked"] is True
    assert captured["fallback_token"] == "env_secret"


def test_open_pull_request_tool_invokes_service(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_open(
        *,
        repo_url,
        branch_name,
        base_branch,
        summary_markdown,
        commits,
        token=None,
        pr_labels=None,
    ):
        captured["repo_url"] = repo_url
        captured["branch_name"] = branch_name
        captured["base_branch"] = base_branch
        captured["summary"] = summary_markdown
        captured["commits"] = commits
        captured["token"] = token
        captured["labels"] = pr_labels
        return PullRequestResult(status="success", url="https://example/pr/99", number=99)

    import mcp_vanguard.tools.open_pull_request as pr_module

    monkeypatch.setattr(pr_module, "open_remediation_pull_request", fake_open)

    result = open_pull_request_tool(
        repo_url="https://github.com/example/project",
        branch_name="mcp/remediation-branch",
        base_branch="main",
        summary_markdown="Summary",
        commits=[{"vulnerability_id": "v1", "commit": "abcdef1", "message": "fix"}],
        github_token="env_secret",
        pr_labels=["automated"],
    )

    assert result["status"] == "success"
    assert captured["repo_url"] == "https://github.com/example/project"
    assert captured["branch_name"] == "mcp/remediation-branch"
    assert captured["base_branch"] == "main"
    assert captured["summary"] == "Summary"
    assert captured["token"] == "env_secret"
    assert captured["labels"] == ["automated"]
    commits = captured["commits"]
    assert isinstance(commits, list)
    assert len(commits) == 1
    assert isinstance(commits[0], CommitRecord)
    assert commits[0].commit_sha == "abcdef1"


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


def test_normalize_patch_text_strips_code_fences() -> None:
    raw_patch = """```diff\n--- a/app.py\n+++ b/app.py\n@@ -1 +1,2 @@\n-print('hello')\n+print('hello world')\n```"""
    normalized = _normalize_patch_text(raw_patch)
    assert normalized.startswith("--- a/app.py")
    assert "```" not in normalized
    assert _looks_like_patch(raw_patch)


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


def test_apply_remediation_commits_handles_code_fence_patch(tmp_path: Path) -> None:
    repo = _init_git_repo(tmp_path)
    patch = """```diff\ndiff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1,2 @@\n-print('hello')\n+print('hello')\n+print('patched')\n```"""
    proposal = PatchProposal(
        vulnerability_id="vuln-fenced",
        file_path="app.py",
        diff=patch,
        rationale="",
        confidence=0.9,
    )

    result = apply_remediation_commits(repo, [proposal])
    assert result.branch is not None
    assert len(result.commits) == 1
    assert not result.errors
    content = (repo / "app.py").read_text(encoding="utf-8")
    assert "print('patched')" in content


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
    assert result.branch is None
    assert result.commits == []
    assert result.errors
    assert result.errors[0].vulnerability_id == "vuln-bad"
    assert result.errors[0].reason == "invalid_patch_format"
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


def test_authenticated_remote_candidates_include_multiple_formats(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_USER", "security-bot")
    candidates = _authenticated_remote_candidates(
        "https://github.com/example/project.git", "ghp_secret"
    )
    assert candidates[0] == "https://x-access-token:ghp_secret@github.com/example/project.git"
    assert "https://security-bot:ghp_secret@github.com/example/project.git" in candidates
    assert "https://example:ghp_secret@github.com/example/project.git" in candidates
    assert candidates[-1] == "https://ghp_secret@github.com/example/project.git"


def test_authenticated_remote_candidates_strip_whitespace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GIT_USER", raising=False)
    candidates = _authenticated_remote_candidates(
        "https://github.com/example/project.git", "  ghp_secret\n"
    )
    assert candidates[0] == "https://x-access-token:ghp_secret@github.com/example/project.git"
    assert candidates[-1] == "https://ghp_secret@github.com/example/project.git"


def test_authenticated_remote_candidates_strip_wrapping_quotes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_USER", '"security-bot"')
    candidates = _authenticated_remote_candidates(
        "https://github.com/example/project.git", "ghp_secret"
    )
    assert "https://security-bot:ghp_secret@github.com/example/project.git" in candidates


def test_authenticated_remote_candidates_include_repo_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GIT_USER", raising=False)
    monkeypatch.delenv("GITHUB_ACTOR", raising=False)
    candidates = _authenticated_remote_candidates(
        "https://github.com/rymarinelli/vulnerable_flask_SQL.git", "ghp_secret"
    )
    assert (
        "https://rymarinelli:ghp_secret@github.com/rymarinelli/vulnerable_flask_SQL.git"
        in candidates
    )


def test_normalize_github_token() -> None:
    assert _normalize_github_token("  ghp_secret\n") == "ghp_secret"
    assert _normalize_github_token("\n\t  ") is None
    assert _normalize_github_token('"ghp_wrapped"') == "ghp_wrapped"
    assert _normalize_github_token("'quoted-token'") == "quoted-token"


@pytest.mark.parametrize(
    "raw, expected",
    [
        (None, None),
        ("", None),
        ("  security-bot  ", "security-bot"),
        ("'quoted-bot'", "quoted-bot"),
        ('"quoted-bot"', "quoted-bot"),
        ('""nested""', '"nested"'),
    ],
)
def test_normalize_git_username(raw: str | None, expected: str | None) -> None:
    assert _normalize_git_username(raw) == expected


def test_sanitize_remote_preserves_scheme_and_username() -> None:
    with_username = _sanitize_remote("https://security-bot:ghp_secret@github.com/example/project.git")
    assert with_username == "https://github.com/example/project.git"
    without_username = _sanitize_remote("https://ghp_secret@github.com/example/project.git")
    assert without_username == "https://github.com/example/project.git"


def test_push_remediation_branch_retries_with_alternate_credentials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    push_invocations = {"count": 0}
    commands: list[list[str]] = []

    def fake_run(command, *, cwd=None, input=None):  # type: ignore[no-redef]
        assert cwd == repo
        commands.append(command)
        if command[:3] == ["git", "push", "--set-upstream"]:
            push_invocations["count"] += 1
            if push_invocations["count"] == 1:
                return subprocess.CompletedProcess(command, 1, "", "fatal: Authentication failed")
            return subprocess.CompletedProcess(command, 0, "ok", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setenv("GIT_USER", "security-bot")
    monkeypatch.setattr("service.operations._run_subprocess", fake_run)

    result = push_remediation_branch(
        repo_path=repo,
        repo_url="https://github.com/example/project.git",
        branch_name="mcp/remediation-test",
        token=" ghp_secret\n",
    )

    assert result.status == "success"
    assert push_invocations["count"] == 2

    set_url_commands = [cmd for cmd in commands if cmd[:3] == ["git", "remote", "set-url"]]
    assert len(set_url_commands) >= 2
    assert any("security-bot:ghp_secret" in cmd[-1] for cmd in set_url_commands)

