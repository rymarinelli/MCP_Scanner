"""Tool for opening remediation pull requests via GitHub."""
from __future__ import annotations

from typing import Iterable, Mapping, Sequence

from service.operations import CommitRecord, open_remediation_pull_request

from . import register_tool


def _to_commit_records(commits: Iterable[Mapping[str, object]]) -> Sequence[CommitRecord]:
    records: list[CommitRecord] = []
    for entry in commits:
        vulnerability_id = str(entry.get("vulnerability_id", "unknown"))
        commit_sha = entry.get("commit") or entry.get("commit_sha")
        commit_sha = str(commit_sha) if commit_sha is not None else ""
        message = entry.get("message")
        message = str(message) if message is not None else "Automated remediation commit"
        records.append(
            CommitRecord(
                vulnerability_id=vulnerability_id,
                commit_sha=commit_sha,
                message=message,
                proposals=[],
            )
        )
    return records


@register_tool("open_pull_request")
def open_pull_request(
    *,
    repo_url: str,
    branch_name: str,
    base_branch: str | None = None,
    summary_markdown: str = "",
    commits: Sequence[Mapping[str, object]] | None = None,
    github_token: str | None = None,
    pr_labels: Sequence[str] | None = None,
) -> Mapping[str, object]:
    """Open a pull request summarising the supplied remediation commits."""

    commit_records = _to_commit_records(commits or [])

    result = open_remediation_pull_request(
        repo_url=repo_url,
        branch_name=branch_name,
        base_branch=base_branch,
        summary_markdown=summary_markdown,
        commits=commit_records,
        token=github_token,
        pr_labels=pr_labels,
    )

    return result.to_dict()


__all__ = ["open_pull_request"]
