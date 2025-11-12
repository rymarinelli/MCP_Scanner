"""Unit tests for the service orchestration helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from semgrep_runner import RunnerOutput

from service.operations import (
    ScanExecutionError,
    clone_repository,
    generate_remediations,
    perform_scan,
    run_semgrep_scan,
)


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


def test_generate_remediations_creates_summary(tmp_path: Path) -> None:
    output = RunnerOutput(
        status="ok",
        normalized_exit_code=0,
        semgrep_exit_code=0,
        command=["semgrep"],
        results={"results": []},
        stderr=None,
    )

    payload = generate_remediations(output, tmp_path)
    assert payload["proposals"] == []
    assert "No remediation suggestions" in payload["summary_markdown"]


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

    def fake_semgrep(path):  # type: ignore[no-redef]
        return fake_output

    def fake_remediation(output, workspace):  # type: ignore[no-redef]
        return {"proposals": [], "summary_markdown": "report"}

    monkeypatch.setattr("service.operations.clone_repository", fake_clone)
    monkeypatch.setattr("service.operations.run_semgrep_scan", fake_semgrep)
    monkeypatch.setattr("service.operations.generate_remediations", fake_remediation)

    result = perform_scan(repo_url="https://example.com/demo.git", branch="main")
    assert result["repository"]["url"] == "https://example.com/demo.git"
    assert result["remediation"]["proposals"] == []

