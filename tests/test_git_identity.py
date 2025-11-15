from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from service.operations import _ensure_git_identity


def _run_git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)
    return repo


def test_ensure_git_identity_uses_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    monkeypatch.setenv("GIT_USER", "Remediation Bot")
    monkeypatch.setenv("GIT_EMAIL", "bot@example.com")
    monkeypatch.delenv("GIT_AUTHOR_NAME", raising=False)
    monkeypatch.delenv("GIT_AUTHOR_EMAIL", raising=False)

    _ensure_git_identity(repo)

    name = _run_git(repo, "config", "--get", "user.name").stdout.strip()
    email = _run_git(repo, "config", "--get", "user.email").stdout.strip()

    assert name == "Remediation Bot"
    assert email == "bot@example.com"


def test_ensure_git_identity_falls_back_to_defaults(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    for key in ("GIT_USER", "GIT_EMAIL", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL"):
        monkeypatch.delenv(key, raising=False)

    _ensure_git_identity(repo)

    name = _run_git(repo, "config", "--get", "user.name").stdout.strip()
    email = _run_git(repo, "config", "--get", "user.email").stdout.strip()

    assert name == "MCP Scanner"
    assert email == "scanner@example.com"
