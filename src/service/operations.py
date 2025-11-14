"""Operational helpers for executing MCP scans via the HTTP service."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import shutil
import uuid
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Tuple
from urllib.parse import urlparse, urlunparse

from enumeration.collector import RepositoryCollector, write_graph
from enumeration.context import build_rag_context, write_rag_context
from mcp_scanner.models import PatchProposal
from mcp_scanner.remediation import RemediationSuggester
from remediation.dspy_driver import DSPyRemediationDriver
from visualization.rag_graph import write_html as write_rag_html

from semgrep_runner import (
    RunnerOutput,
    build_command,
    execute_semgrep,
    interpret_result,
    load_config,
)


class ScanExecutionError(RuntimeError):
    """Raised when a step in the scan workflow fails."""


@dataclass
class RemediationOutcome:
    """Container describing remediation artifacts generated from a scan."""

    proposals: List[PatchProposal]
    summary_markdown: str
    artifacts: Dict[str, Path]

    def to_dict(self) -> Dict[str, object]:
        return {
            "proposals": [proposal.to_dict() for proposal in self.proposals],
            "summary_markdown": self.summary_markdown,
            "artifacts": {key: str(path) for key, path in self.artifacts.items()},
        }


@dataclass
class CommitRecord:
    """Details about a commit produced for a specific vulnerability."""

    vulnerability_id: str
    commit_sha: str
    message: str
    proposals: List[PatchProposal]

    def to_dict(self) -> Dict[str, object]:
        return {
            "vulnerability_id": self.vulnerability_id,
            "commit": self.commit_sha,
            "message": self.message,
            "proposals": [proposal.to_dict() for proposal in self.proposals],
        }


@dataclass
class CommitError:
    """Represents an error that occurred while attempting to create a commit."""

    vulnerability_id: str
    reason: str
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "vulnerability_id": self.vulnerability_id,
            "reason": self.reason,
        }
        if self.details:
            payload["details"] = self.details
        return payload


@dataclass
class CommitApplicationResult:
    """Aggregate result describing remediation commits applied to a repository."""

    branch: Optional[str]
    commits: List[CommitRecord]
    errors: List[CommitError]


@dataclass
class PushResult:
    """Outcome of attempting to push a remediation branch to a remote."""

    status: str
    branch: Optional[str] = None
    remote: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        payload: Dict[str, object] = {"status": self.status}
        if self.branch:
            payload["branch"] = self.branch
        if self.remote:
            payload["remote"] = self.remote
        if self.message:
            payload["message"] = self.message
        if self.error:
            payload["error"] = self.error
        if self.reason:
            payload["reason"] = self.reason
        return payload


@dataclass
class PullRequestResult:
    """Outcome of attempting to open a pull request with remediation commits."""

    status: str
    url: Optional[str] = None
    number: Optional[int] = None
    error: Optional[str] = None
    reason: Optional[str] = None
    response: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, object]:
        payload: Dict[str, object] = {"status": self.status}
        if self.url:
            payload["url"] = self.url
        if self.number is not None:
            payload["number"] = self.number
        if self.error:
            payload["error"] = self.error
        if self.reason:
            payload["reason"] = self.reason
        if self.response is not None:
            payload["response"] = self.response
        return payload


def _run_subprocess(
    command: List[str],
    *,
    cwd: Optional[Path] = None,
    input: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute a subprocess command and capture its output."""

    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd is not None else None,
        input=input,
    )


def _validate_repo_inputs(repo_url: str, branch: str | None) -> None:
    """Validate repository parameters before invoking git."""

    if not isinstance(repo_url, str) or not repo_url.strip():
        raise ValueError("repo_url is required")

    if repo_url.lstrip().startswith("-"):
        raise ValueError("repo_url must not start with '-' characters")

    if branch is not None:
        if not isinstance(branch, str) or not branch.strip():
            raise ValueError("branch must be a non-empty string when provided")
        if branch.lstrip().startswith("-"):
            raise ValueError("branch must not start with '-' characters")


def clone_repository(repo_url: str, branch: str | None, workspace: Path) -> Path:
    """Clone the requested repository into ``workspace`` and return the path."""

    _validate_repo_inputs(repo_url, branch)

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


def enumerate_repository(
    repo_path: Path, workspace: Path
) -> Tuple[Dict[str, object], Path, Dict[str, Path]]:
    """Build RAG artifacts describing ``repo_path``.

    Returns a tuple containing the serialized payload, the path to the RAG
    context file, and a mapping of artifact names to their on-disk locations.
    """

    collector = RepositoryCollector(repo_path)
    artifact = collector.collect()

    rag_dir = workspace / "rag"
    raw_graph_path = rag_dir / "raw_graph.json"
    write_graph(artifact, raw_graph_path)

    graph_payload = artifact.to_dict()
    graph_html_path = rag_dir / "rag_graph.html"
    write_rag_html(graph_payload, graph_html_path)

    rag_context = build_rag_context(artifact)
    rag_context_path = workspace / "rag_context.json"
    write_rag_context(rag_context, rag_context_path)

    artifact_paths: Dict[str, Path] = {
        "raw_graph": raw_graph_path,
        "graph_html": graph_html_path,
        "rag_context": rag_context_path,
    }

    enumeration_payload = {
        "graph": {
            "node_count": len(graph_payload.get("nodes", [])),
            "edge_count": len(graph_payload.get("edges", [])),
        },
        "artifacts": {
            key: str(path) for key, path in artifact_paths.items()
        },
        "rag_context": rag_context,
    }

    return enumeration_payload, rag_context_path, artifact_paths


def _copy_artifact(src: Path, dest_dir: Path, *, name: str | None = None) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        destination = dest_dir / (name or src.name)
        if destination.exists():
            if destination.is_dir():
                shutil.rmtree(destination)
            else:
                destination.unlink()
        shutil.copytree(src, destination)
        return destination

    filename = name or src.name
    destination = dest_dir / filename
    if destination.exists():
        counter = 1
        stem = destination.stem
        suffix = destination.suffix
        while destination.exists():
            destination = dest_dir / f"{stem}_{counter}{suffix}"
            counter += 1
    shutil.copy2(src, destination)
    return destination


def _persist_enumeration_artifacts(
    artifact_paths: Mapping[str, Path],
    artifact_root: Path,
) -> Dict[str, str]:
    persisted: Dict[str, str] = {}
    for key, src in artifact_paths.items():
        if not src.exists():
            raise ScanExecutionError(f"Enumeration artifact missing: {src}")
        suffix = src.suffix
        filename = f"{key}{suffix}" if suffix else key
        persisted_path = _copy_artifact(src, artifact_root / "enumeration", name=filename)
        persisted[key] = str(persisted_path)
    return persisted


def _persist_remediation_artifacts(
    artifact_paths: Mapping[str, Path],
    artifact_root: Path,
) -> Dict[str, str]:
    persisted: Dict[str, str] = {}
    for key, src in artifact_paths.items():
        if not src.exists():
            raise ScanExecutionError(f"Remediation artifact missing: {src}")
        if src.is_file():
            suffix = src.suffix
            name = f"{key}{suffix}" if suffix else key
        else:
            name = key
        persisted_path = _copy_artifact(src, artifact_root / "remediation", name=name)
        persisted[key] = str(persisted_path)
    return persisted


def _ensure_git_identity(repo_path: Path) -> None:
    """Ensure the repository has git identity configuration for committing."""

    defaults = {
        "user.name": "MCP Scanner",
        "user.email": "scanner@example.com",
    }
    for key, value in defaults.items():
        result = _run_subprocess(["git", "config", "--get", key], cwd=repo_path)
        if result.returncode != 0 or not result.stdout.strip():
            _run_subprocess(["git", "config", key, value], cwd=repo_path)


def _reset_worktree(repo_path: Path) -> None:
    """Reset any uncommitted modifications in ``repo_path``."""

    _run_subprocess(["git", "reset", "--hard"], cwd=repo_path)
    _run_subprocess(["git", "clean", "-fd"], cwd=repo_path)


def _group_proposals(proposals: Sequence[PatchProposal]) -> Dict[str, List[PatchProposal]]:
    grouped: Dict[str, List[PatchProposal]] = defaultdict(list)
    for proposal in proposals:
        grouped[proposal.vulnerability_id].append(proposal)
    return grouped


def apply_remediation_commits(
    repo_path: Path,
    proposals: Sequence[PatchProposal],
) -> CommitApplicationResult:
    """Apply remediation proposals to the repository and commit them."""

    if not proposals:
        return CommitApplicationResult(branch=None, commits=[], errors=[])

    branch_name = f"mcp/remediation-{uuid.uuid4().hex[:8]}"
    checkout = _run_subprocess(["git", "checkout", "-b", branch_name], cwd=repo_path)
    if checkout.returncode != 0:
        message = checkout.stderr.strip() or checkout.stdout.strip() or "Unknown git error"
        raise ScanExecutionError(f"git checkout -b {branch_name} failed: {message}")

    _ensure_git_identity(repo_path)

    commits: List[CommitRecord] = []
    errors: List[CommitError] = []
    for vulnerability_id, group in _group_proposals(proposals).items():
        if not group:
            continue

        apply_failed = False
        for proposal in group:
            patch_text = proposal.diff or ""
            if not patch_text.strip():
                errors.append(CommitError(vulnerability_id=vulnerability_id, reason="empty_diff"))
                apply_failed = True
                break

            apply_result = _run_subprocess(
                ["git", "apply", "--whitespace=fix"],
                cwd=repo_path,
                input=patch_text,
            )
            if apply_result.returncode != 0:
                details = (apply_result.stderr or apply_result.stdout or "").strip()
                errors.append(
                    CommitError(
                        vulnerability_id=vulnerability_id,
                        reason="git apply failed",
                        details=details or None,
                    )
                )
                _reset_worktree(repo_path)
                apply_failed = True
                break

        if apply_failed:
            continue

        add_result = _run_subprocess(["git", "add", "-A"], cwd=repo_path)
        if add_result.returncode != 0:
            details = (add_result.stderr or add_result.stdout or "").strip()
            errors.append(
                CommitError(
                    vulnerability_id=vulnerability_id,
                    reason="git add failed",
                    details=details or None,
                )
            )
            _reset_worktree(repo_path)
            continue

        status = _run_subprocess(["git", "status", "--porcelain"], cwd=repo_path)
        if not status.stdout.strip():
            errors.append(
                CommitError(
                    vulnerability_id=vulnerability_id,
                    reason="no_changes_staged",
                )
            )
            continue

        message = f"fix({vulnerability_id}): apply DSPy remediation"
        commit_result = _run_subprocess(["git", "commit", "-m", message], cwd=repo_path)
        if commit_result.returncode != 0:
            details = (commit_result.stderr or commit_result.stdout or "").strip()
            errors.append(
                CommitError(
                    vulnerability_id=vulnerability_id,
                    reason="git commit failed",
                    details=details or None,
                )
            )
            _reset_worktree(repo_path)
            continue

        rev_parse = _run_subprocess(["git", "rev-parse", "HEAD"], cwd=repo_path)
        commit_sha = rev_parse.stdout.strip() if rev_parse.returncode == 0 else ""
        commits.append(
            CommitRecord(
                vulnerability_id=vulnerability_id,
                commit_sha=commit_sha,
                message=message,
                proposals=list(group),
            )
        )

    return CommitApplicationResult(branch=branch_name, commits=commits, errors=errors)


def _build_authenticated_remote(repo_url: str, token: str) -> Optional[str]:
    parsed = urlparse(repo_url)
    if parsed.scheme.lower() != "https":
        return None
    netloc = f"x-access-token:{token}@{parsed.netloc}"
    return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))


def _parse_repo_slug(repo_url: str) -> Optional[Tuple[str, str]]:
    """Derive the ``(owner, repo)`` tuple from common Git remote formats."""

    path: str = ""

    if repo_url.startswith("git@"):
        # Handle scp-like SSH URLs such as ``git@github.com:owner/repo.git``.
        try:
            _, path = repo_url.split(":", 1)
        except ValueError:
            return None
    else:
        parsed = urlparse(repo_url)
        if parsed.scheme and parsed.netloc:
            path = parsed.path
        elif parsed.path and not parsed.scheme and not parsed.netloc:
            path = parsed.path
        else:
            return None

    path = path.strip("/")
    if not path:
        return None

    parts = path.split("/")
    if len(parts) < 2:
        return None

    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def push_remediation_branch(
    repo_path: Path,
    repo_url: str,
    branch_name: Optional[str],
    *,
    token: Optional[str] = None,
) -> PushResult:
    """Push the remediation branch to origin if credentials are available."""

    if not branch_name:
        return PushResult(status="skipped", reason="no branch provided")

    token = token if token is not None else os.environ.get("GITHUB_TOKEN")
    if not token:
        return PushResult(status="skipped", branch=branch_name, reason="GITHUB_TOKEN not provided")

    remote_url = _build_authenticated_remote(repo_url, token)
    if remote_url:
        _run_subprocess(["git", "remote", "set-url", "origin", remote_url], cwd=repo_path)

    push = _run_subprocess(["git", "push", "--set-upstream", "origin", branch_name], cwd=repo_path)
    if push.returncode != 0:
        message = push.stderr.strip() or push.stdout.strip() or "Unknown git error"
        return PushResult(status="error", branch=branch_name, remote="origin", error=message)

    return PushResult(status="success", branch=branch_name, remote="origin", message="Branch pushed to origin")


def open_remediation_pull_request(
    *,
    repo_url: str,
    branch_name: str,
    base_branch: Optional[str],
    summary_markdown: str,
    commits: Sequence[CommitRecord],
    token: Optional[str] = None,
) -> PullRequestResult:
    """Open a pull request summarizing the remediation commits."""

    if not commits:
        return PullRequestResult(status="skipped", reason="no commits to include")

    token = token if token is not None else os.environ.get("GITHUB_TOKEN")
    if not token:
        return PullRequestResult(status="skipped", reason="GITHUB_TOKEN not provided")

    slug = _parse_repo_slug(repo_url)
    if not slug:
        return PullRequestResult(status="error", error="Unable to parse repository slug from repo_url")

    owner, repo = slug
    api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls"

    plural = "ies" if len(commits) != 1 else "y"
    title = f"Automated remediation for {len(commits)} vulnerabilit{plural}"

    commit_lines = "\n".join(
        f"- {record.vulnerability_id}: `{record.message}` ({record.commit_sha[:7]})"
        for record in commits
        if record.commit_sha
    )

    body_sections: List[str] = []
    summary = summary_markdown.strip()
    if summary:
        body_sections.append(summary)
    if commit_lines:
        body_sections.extend(["", "## Commits", commit_lines])

    body = "\n".join(body_sections).strip() or "Automated remediation proposals."
    payload = json.dumps(
        {
            "title": title,
            "head": f"{owner}:{branch_name}",
            "base": base_branch or "main",
            "body": body,
        }
    ).encode("utf-8")

    request = urllib.request.Request(api_url, data=payload, method="POST")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(request) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:  # pragma: no cover - requires HTTP interaction
        error_body = exc.read().decode("utf-8", errors="ignore")
        return PullRequestResult(
            status="error",
            error=f"GitHub API returned {exc.code}",
            response={"body": error_body},
        )
    except Exception as exc:  # pragma: no cover - defensive guard
        return PullRequestResult(status="error", error=str(exc))

    return PullRequestResult(
        status="success",
        url=data.get("html_url"),
        number=data.get("number"),
        response=data,
    )


def generate_remediations(
    semgrep_output: RunnerOutput,
    workspace: Path,
    rag_context_path: Path,
) -> RemediationOutcome:
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
        rag_context_path=rag_context_path,
    )

    summary_markdown = driver.output_markdown.read_text(encoding="utf-8")
    artifacts: Dict[str, Path] = {
        "semgrep_results": findings_path,
        "dspy_summary": driver.output_markdown,
    }
    remediation_dir = driver.suggester.output_dir
    if isinstance(remediation_dir, Path) and remediation_dir.exists():
        artifacts["dspy_cases"] = remediation_dir

    return RemediationOutcome(
        proposals=proposals,
        summary_markdown=summary_markdown,
        artifacts=artifacts,
    )


def perform_scan(*, repo_url: str, branch: str | None = None) -> Dict[str, object]:
    """Execute the full scan and remediation workflow for a repository."""

    _validate_repo_inputs(repo_url, branch)

    artifact_root = Path(tempfile.mkdtemp(prefix="mcp-scan-artifacts-"))

    with tempfile.TemporaryDirectory(prefix="mcp-scan-") as tmpdir:
        workspace = Path(tmpdir)
        repo_path = clone_repository(repo_url, branch, workspace)
        enumeration_payload, rag_context_path, artifact_paths = enumerate_repository(repo_path, workspace)
        semgrep_output = run_semgrep_scan(repo_path)

        semgrep_payload = semgrep_output.to_dict()
        if semgrep_output.normalized_exit_code != 0:
            raise ScanExecutionError(
                "Semgrep execution failed",
            )

        remediation_result = generate_remediations(semgrep_output, workspace, rag_context_path)

        commit_result = apply_remediation_commits(repo_path, remediation_result.proposals)
        push_result: PushResult | None = None
        pr_result: PullRequestResult | None = None

        if commit_result.commits:
            push_result = push_remediation_branch(
                repo_path=repo_path,
                repo_url=repo_url,
                branch_name=commit_result.branch,
            )
            if push_result.status == "success" and commit_result.branch:
                pr_result = open_remediation_pull_request(
                    repo_url=repo_url,
                    branch_name=commit_result.branch,
                    base_branch=branch,
                    summary_markdown=remediation_result.summary_markdown,
                    commits=commit_result.commits,
                )
            elif push_result.status == "skipped":
                pr_result = PullRequestResult(status="skipped", reason=push_result.reason)

        remediation_artifacts = _persist_remediation_artifacts(
            remediation_result.artifacts,
            artifact_root,
        )

        remediation_payload = remediation_result.to_dict()
        if remediation_artifacts:
            remediation_payload["artifacts"] = remediation_artifacts
        if commit_result.branch and commit_result.commits:
            remediation_payload["branch"] = commit_result.branch
        if commit_result.commits:
            remediation_payload["commits"] = [record.to_dict() for record in commit_result.commits]
        if commit_result.errors:
            remediation_payload["commit_errors"] = [error.to_dict() for error in commit_result.errors]
        if push_result:
            remediation_payload["push"] = push_result.to_dict()
        if pr_result:
            remediation_payload["pull_request"] = pr_result.to_dict()

        enumeration_payload["artifacts"] = _persist_enumeration_artifacts(artifact_paths, artifact_root)

        return {
            "repository": {
                "url": repo_url,
                "branch": branch,
            },
            "enumeration": enumeration_payload,
            "semgrep": semgrep_payload,
            "remediation": remediation_payload,
        }
