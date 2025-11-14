"""GitHub repository scanning tool."""
from __future__ import annotations

from typing import Any, Dict, Sequence
from urllib.parse import urlparse

from service.operations import ScanExecutionError, perform_scan

from . import register_tool


def _validate_github_url(repo_url: str) -> None:
    parsed = urlparse(repo_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("repo_url must be an absolute URL")
    if "github.com" not in parsed.netloc:
        raise ValueError("repo_url must point to github.com")
    if parsed.path.count("/") < 2:
        raise ValueError("repo_url must include the owner and repository name")


@register_tool("scan_github_repo")
def scan_github_repo(
    *,
    repo_url: str,
    branch: str | None = None,
    quick: bool = False,
    apply_commits: bool = True,
    push: bool = True,
    create_pr: bool = True,
    base_branch: str | None = None,
    pr_labels: Sequence[str] | None = None,
) -> Dict[str, Any]:
    """Execute the full MCP scan pipeline against a GitHub repository.

    The tool validates the URL, clones the repository, runs enumeration,
    Semgrep analysis, and remediation synthesis before returning the
    aggregated results. Any `ScanExecutionError` raised during the workflow
    is re-raised as a :class:`RuntimeError` so the MCP tool surface can
    report the failure cleanly.
    """

    if not repo_url:
        raise ValueError("repo_url is required")

    _validate_github_url(repo_url)

    try:
        return perform_scan(
            repo_url=repo_url,
            branch=branch,
            quick=quick,
            apply_commits=apply_commits,
            push=push,
            create_pr=create_pr,
            base_branch=base_branch,
            pr_labels=pr_labels,
        )
    except ScanExecutionError as exc:
        raise RuntimeError(str(exc)) from exc


__all__ = ["scan_github_repo"]
