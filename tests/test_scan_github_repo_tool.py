from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from mcp_vanguard.tools import scan_github_repo as scan_module
from mcp_vanguard.tools.scan_github_repo import scan_github_repo


def test_scan_github_repo_invokes_full_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_perform_scan(**kwargs) -> dict[str, object]:  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        return {"repository": {"url": kwargs["repo_url"], "branch": kwargs["branch"]}}

    monkeypatch.setattr(scan_module, "perform_scan", fake_perform_scan)

    result = scan_github_repo(
        repo_url="https://github.com/example/demo",
        branch="main",
        quick=True,
        apply_commits=False,
        push=False,
        create_pr=False,
        base_branch="develop",
        pr_labels=["security"],
        github_token="ghp_token",
    )

    assert result == {"repository": {"url": "https://github.com/example/demo", "branch": "main"}}
    assert captured["repo_url"] == "https://github.com/example/demo"
    assert captured["branch"] == "main"
    assert captured["quick"] is True
    assert captured["apply_commits"] is False
    assert captured["push"] is False
    assert captured["create_pr"] is False
    assert captured["base_branch"] == "develop"
    assert captured["pr_labels"] == ["security"]
    assert captured["github_token"] == "ghp_token"


def test_scan_github_repo_rejects_non_github_url() -> None:
    with pytest.raises(ValueError, match="github.com"):
        scan_github_repo(repo_url="https://gitlab.com/example/demo")
