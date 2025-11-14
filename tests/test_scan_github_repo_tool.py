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

    def fake_perform_scan(*, repo_url: str, branch: str | None) -> dict[str, object]:
        captured["repo_url"] = repo_url
        captured["branch"] = branch
        return {"repository": {"url": repo_url, "branch": branch}}

    monkeypatch.setattr(scan_module, "perform_scan", fake_perform_scan)

    result = scan_github_repo(
        repo_url="https://github.com/example/demo", branch="main"
    )

    assert result == {"repository": {"url": "https://github.com/example/demo", "branch": "main"}}
    assert captured == {"repo_url": "https://github.com/example/demo", "branch": "main"}


def test_scan_github_repo_rejects_non_github_url() -> None:
    with pytest.raises(ValueError, match="github.com"):
        scan_github_repo(repo_url="https://gitlab.com/example/demo")
