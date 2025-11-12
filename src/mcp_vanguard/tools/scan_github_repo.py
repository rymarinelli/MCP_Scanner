"""GitHub repository scanning tool."""
from __future__ import annotations

from typing import Any, Dict
from urllib.parse import urlparse

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
def scan_github_repo(*, repo_url: str, branch: str | None = None) -> Dict[str, Any]:
    """Return metadata describing the GitHub repository to scan.

    This minimal implementation performs basic validation and returns
    normalized data that can be consumed by higher-level scanners.
    """

    if not repo_url:
        raise ValueError("repo_url is required")

    _validate_github_url(repo_url)

    data: Dict[str, Any] = {"repo_url": repo_url}
    if branch:
        data["branch"] = branch
    return data


__all__ = ["scan_github_repo"]
