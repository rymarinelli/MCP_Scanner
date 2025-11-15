"""Operational helpers for executing MCP scans via the HTTP service."""

from __future__ import annotations

import difflib
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
from urllib.parse import quote, urlparse, urlunparse

from enumeration.collector import RepositoryCollector, write_graph
from enumeration.context import build_rag_context, write_rag_context
from mcp_scanner.models import PatchProposal
from mcp_scanner.remediation import RemediationSuggester
from remediation.dspy_driver import DSPyRemediationDriver
from visualization.rag_graph import write_html as write_rag_html

from semgrep_runner import (
    RunnerConfig,
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
    labels: Optional[Dict[str, Any]] = None

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
        if self.labels is not None:
            payload["labels"] = self.labels
        return payload

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "PullRequestResult":
        status = payload.get("status")
        if not isinstance(status, str) or not status:
            raise ValueError("pull request tool response missing status")

        number = payload.get("number")
        if number is not None:
            try:
                number = int(number)
            except (TypeError, ValueError):
                raise ValueError("pull request tool response included invalid number") from None

        return cls(
            status=status,
            url=payload.get("url"),
            number=number,
            error=payload.get("error"),
            reason=payload.get("reason"),
            response=payload.get("response"),
            labels=payload.get("labels"),
        )


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


def run_semgrep_scan(repo_path: Path, *, quick: bool = False) -> RunnerOutput:
    """Run Semgrep against ``repo_path`` using the bundled configuration.

    When ``quick`` is ``True`` the scan is executed using Semgrep's
    ``--config auto`` mode, mirroring the behaviour of the legacy MCP server
    implementation. Otherwise the repository-specific configuration bundled
    with the service is used and the usual fallback logic for remote rule
    failures remains in place.
    """

    config_path = Path("semgrep_rules/config.json")
    if quick:
        configs: Sequence[RunnerConfig] = [
            RunnerConfig(type="remote", value="auto", label="auto"),
        ]
    else:
        configs = load_config(config_path)
    base_dir = config_path.parent.resolve()

    def _invoke(selected_configs: Sequence[RunnerConfig]) -> RunnerOutput:
        command = build_command(selected_configs, targets=["."], base_dir=base_dir)
        result = execute_semgrep(command, cwd=repo_path)
        return interpret_result(result, command)

    output = _invoke(configs)
    if output.normalized_exit_code == 0:
        return output

    remote_configs = [cfg for cfg in configs if cfg.type in {"registry", "remote"}]
    local_configs = [cfg for cfg in configs if cfg.type not in {"registry", "remote"}]
    if remote_configs and local_configs:
        fallback = _invoke(local_configs)
        if fallback.normalized_exit_code == 0:
            skipped = [cfg.label or cfg.value for cfg in remote_configs]
            fallback.results.setdefault("errors", []).append(
                {
                    "message": "Remote Semgrep configs were skipped after they failed to execute",
                    "reason": "remote_config_unavailable",
                    "skipped_configs": skipped,
                    "original_exit_code": output.semgrep_exit_code,
                }
            )
            return fallback

    return output


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


_SQL_CONCAT_RULE_IDENTIFIERS = (
    "python-sql-injection-string-concat",
    "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
    "python.django.security.injection.sql.sql-injection-using-db-cursor-execute.sql-injection-db-cursor-execute",
)


def _matches_sql_concat_rule(check_id: object) -> bool:
    value = str(check_id or "")
    if not value:
        return False
    return any(value == identifier or value.endswith(identifier) for identifier in _SQL_CONCAT_RULE_IDENTIFIERS)


def _replace_sql_injection_blocks(text: str) -> tuple[str, bool]:
    replacements = [
        (
            "        # ---- VULNERABLE: concatenating user input into SQL ----\n"
            "        sql = \"SELECT id, username FROM users WHERE username LIKE '%\" + q + \"%';\"\n"
            "        # For the demo we intentionally execute this unsafe SQL\n"
            "        cur.execute(sql)\n",
            "        # ---- FIXED: use parameterized query for user search ----\n"
            "        sql = \"SELECT id, username FROM users WHERE username LIKE ?\"\n"
            "        cur.execute(sql, (f\"%{q}%\",))\n",
        ),
        (
            "        # ---- VULNERABLE: direct string formatting into SQL ----\n"
            "        sql = f\"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}' LIMIT 1;\"\n"
            "        cur.execute(sql)\n",
            "        # ---- FIXED: use parameterized query for login ----\n"
            "        sql = \"SELECT id, username FROM users WHERE username = ? AND password = ? LIMIT 1\"\n"
            "        cur.execute(sql, (username, password))\n",
        ),
    ]

    updated = text
    changed = False
    for original, replacement in replacements:
        if original in updated:
            updated = updated.replace(original, replacement)
            changed = True
    return updated, changed


def _synthesize_sql_concatenation_patch(repo_path: Path) -> PatchProposal | None:
    target = repo_path / "app_vuln.py"
    if not target.exists():
        return None

    original = target.read_text(encoding="utf-8")
    updated, changed = _replace_sql_injection_blocks(original)
    if not changed:
        return None

    diff = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile="a/app_vuln.py",
            tofile="b/app_vuln.py",
        )
    )
    if not diff.strip():
        return None

    return PatchProposal(
        vulnerability_id="sql-injection-string-concat",
        file_path="app_vuln.py",
        diff=diff,
        rationale=(
            "Replace raw SQL queries built via string concatenation with parameterized statements to"
            " prevent injection."
        ),
        confidence=1.0,
    )


def _builtin_remediations(
    semgrep_results: Mapping[str, object], repo_path: Path
) -> List[PatchProposal]:
    findings = semgrep_results.get("results", [])
    if not isinstance(findings, Sequence):
        return []

    if not any(
        isinstance(finding, Mapping) and _matches_sql_concat_rule(finding.get("check_id"))
        for finding in findings
    ):
        return []

    proposal = _synthesize_sql_concatenation_patch(repo_path)
    return [proposal] if proposal else []


def _ensure_git_identity(repo_path: Path) -> None:
    """Ensure the repository has git identity configuration for committing."""

    configured_name = os.environ.get("GIT_USER") or os.environ.get("GIT_AUTHOR_NAME")
    configured_email = os.environ.get("GIT_EMAIL") or os.environ.get("GIT_AUTHOR_EMAIL")

    defaults = {
        "user.name": configured_name or "MCP Scanner",
        "user.email": configured_email or "scanner@example.com",
    }
    for key, value in defaults.items():
        result = _run_subprocess(["git", "config", "--get", key], cwd=repo_path)
        current = result.stdout.strip() if result.returncode == 0 else ""
        if current != value:
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


def _authenticated_remote_candidates(repo_url: str, token: str) -> List[str]:
    """Generate HTTPS remote URLs that embed ``token`` for authentication."""

    parsed = urlparse(repo_url)
    if parsed.scheme.lower() != "https":
        return []

    encoded_token = quote(token, safe="")
    netloc = parsed.netloc

    def _build(netloc_value: str) -> str:
        return urlunparse(
            (parsed.scheme, netloc_value, parsed.path, parsed.params, parsed.query, parsed.fragment)
        )

    candidates: List[str] = []
    seen: set[str] = set()

    def _add_candidate(netloc_value: str) -> None:
        url = _build(netloc_value)
        if url not in seen:
            seen.add(url)
            candidates.append(url)

    # GitHub App installation tokens expect the fixed ``x-access-token`` username.
    _add_candidate(f"x-access-token:{encoded_token}@{netloc}")

    username_hints: List[str] = []
    env_username = os.environ.get("GIT_USER") or os.environ.get("GITHUB_ACTOR")
    if env_username:
        username_hints.append(env_username)

    slug = _parse_repo_slug(repo_url)
    if slug:
        owner, _ = slug
        if owner:
            username_hints.append(owner)

    for username in username_hints:
        encoded_username = quote(username, safe="")
        _add_candidate(f"{encoded_username}:{encoded_token}@{netloc}")

    # Personal access tokens support being supplied as the username component.
    _add_candidate(f"{encoded_token}@{netloc}")

    return candidates


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

    remote_variants = _authenticated_remote_candidates(repo_url, token)
    if not remote_variants:
        remote_variants = [None]

    errors: List[str] = []
    for remote_url in remote_variants:
        if remote_url:
            _run_subprocess(["git", "remote", "set-url", "origin", remote_url], cwd=repo_path)

        push = _run_subprocess(["git", "push", "--set-upstream", "origin", branch_name], cwd=repo_path)
        if push.returncode == 0:
            return PushResult(status="success", branch=branch_name, remote="origin", message="Branch pushed to origin")

        message = push.stderr.strip() or push.stdout.strip() or "Unknown git error"
        errors.append(message)

    error_message = errors[-1] if errors else "Unknown git error"
    reason = None
    if len(errors) > 1:
        reason = "git push failed after attempting multiple credential formats"

    return PushResult(
        status="error",
        branch=branch_name,
        remote="origin",
        error=error_message,
        reason=reason,
    )


def open_remediation_pull_request(
    *,
    repo_url: str,
    branch_name: str,
    base_branch: Optional[str],
    summary_markdown: str,
    commits: Sequence[CommitRecord],
    token: Optional[str] = None,
    pr_labels: Sequence[str] | None = None,
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

    labels_result: Dict[str, Any] | None = None
    if pr_labels:
        issue_number = data.get("number")
        if issue_number is None:
            labels_result = {"status": "skipped", "reason": "missing pull request number"}
        else:
            labels_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/labels"
            payload = json.dumps({"labels": list(pr_labels)}).encode("utf-8")
            label_request = urllib.request.Request(labels_url, data=payload, method="POST")
            label_request.add_header("Authorization", f"Bearer {token}")
            label_request.add_header("Accept", "application/vnd.github+json")
            label_request.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(label_request) as response:
                    labels_result = {
                        "status": "success",
                        "response": json.loads(response.read().decode("utf-8")),
                    }
            except urllib.error.HTTPError as exc:  # pragma: no cover - requires HTTP interaction
                error_body = exc.read().decode("utf-8", errors="ignore")
                labels_result = {
                    "status": "error",
                    "error": f"GitHub API returned {exc.code}",
                    "body": error_body,
                }
            except Exception as exc:  # pragma: no cover - defensive guard
                labels_result = {"status": "error", "error": str(exc)}

    return PullRequestResult(
        status="success",
        url=data.get("html_url"),
        number=data.get("number"),
        response=data,
        labels=labels_result,
    )


def _describe_tool_error(error: object) -> str:
    if isinstance(error, Mapping):
        message = error.get("message")
        if isinstance(message, str) and message:
            return message
        try:
            return json.dumps(error)
        except TypeError:  # pragma: no cover - fallback for non-serialisable payloads
            return repr(error)
    return str(error) if error else "unknown error"


def _invoke_pull_request_tool(
    *,
    repo_url: str,
    branch_name: str,
    base_branch: Optional[str],
    summary_markdown: str,
    commits: Sequence[CommitRecord],
    token: Optional[str],
    pr_labels: Sequence[str] | None,
) -> PullRequestResult | None:
    """Attempt to open a pull request via the MCP tool registry."""

    try:
        from mcp_vanguard import run_tool
        from mcp_vanguard.tools import ensure_tools_registered
    except ImportError:  # pragma: no cover - MCP runtime not available
        return None

    ensure_tools_registered()

    response = run_tool(
        "open_pull_request",
        {
            "repo_url": repo_url,
            "branch_name": branch_name,
            "base_branch": base_branch,
            "summary_markdown": summary_markdown,
            "commits": [record.to_dict() for record in commits],
            "github_token": token,
            "pr_labels": list(pr_labels) if pr_labels is not None else None,
        },
    )

    status = response.get("status")
    if status != "success":
        error = response.get("error")
        if isinstance(error, Mapping) and error.get("type") == "ToolNotFound":
            return None
        return PullRequestResult(status="error", error=_describe_tool_error(error))

    payload = response.get("result")
    if not isinstance(payload, Mapping):
        return PullRequestResult(status="error", error="open_pull_request returned malformed payload")

    try:
        return PullRequestResult.from_mapping(payload)
    except ValueError as exc:
        return PullRequestResult(status="error", error=str(exc))


def generate_remediations(
    semgrep_output: RunnerOutput,
    workspace: Path,
    rag_context_path: Path,
    repo_path: Path,
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
    builtin = _builtin_remediations(semgrep_results, repo_path)
    if builtin:
        proposals.extend(builtin)
        summary_lines: List[str] = []
        base_summary = summary_markdown.strip()
        if base_summary:
            summary_lines.append(base_summary)
        summary_lines.extend(
            [
                "",
                "## Built-in remediations",
                "- Hardened raw SQL queries in `app_vuln.py` by switching to parameterized statements.",
            ]
        )
        summary_markdown = "\n".join(summary_lines).strip()
        driver.output_markdown.parent.mkdir(parents=True, exist_ok=True)
        driver.output_markdown.write_text(summary_markdown + "\n", encoding="utf-8")

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


def perform_scan(
    *,
    repo_url: str,
    branch: str | None = None,
    quick: bool = False,
    apply_commits: bool = True,
    push: bool = True,
    create_pr: bool = True,
    base_branch: str | None = None,
    pr_labels: Sequence[str] | None = None,
    github_token: str | None = None,
) -> Dict[str, object]:
    """Execute the full scan and remediation workflow for a repository."""

    _validate_repo_inputs(repo_url, branch)

    if github_token is None:
        github_token = os.environ.get("GITHUB_TOKEN")

    artifact_root = Path(tempfile.mkdtemp(prefix="mcp-scan-artifacts-"))

    with tempfile.TemporaryDirectory(prefix="mcp-scan-") as tmpdir:
        workspace = Path(tmpdir)
        repo_path = clone_repository(repo_url, branch, workspace)
        enumeration_payload, rag_context_path, artifact_paths = enumerate_repository(repo_path, workspace)
        semgrep_output = run_semgrep_scan(repo_path, quick=quick)

        semgrep_payload = semgrep_output.to_dict()
        if semgrep_output.normalized_exit_code != 0:
            raise ScanExecutionError(
                "Semgrep execution failed",
            )

        remediation_result = generate_remediations(
            semgrep_output,
            workspace,
            rag_context_path,
            repo_path,
        )

        if apply_commits:
            commit_result = apply_remediation_commits(repo_path, remediation_result.proposals)
        else:
            commit_result = CommitApplicationResult(branch=None, commits=[], errors=[])

        push_result: PushResult | None = None
        pr_result: PullRequestResult | None = None

        if apply_commits and commit_result.commits:
            if push:
                push_result = push_remediation_branch(
                    repo_path=repo_path,
                    repo_url=repo_url,
                    branch_name=commit_result.branch,
                    token=github_token,
                )
            else:
                push_result = PushResult(
                    status="skipped",
                    branch=commit_result.branch,
                    reason="push disabled by configuration",
                )

            if create_pr:
                if push_result.status == "success" and commit_result.branch:
                    pr_result = _invoke_pull_request_tool(
                        repo_url=repo_url,
                        branch_name=commit_result.branch,
                        base_branch=base_branch or branch,
                        summary_markdown=remediation_result.summary_markdown,
                        commits=commit_result.commits,
                        token=github_token,
                        pr_labels=pr_labels,
                    )
                    if pr_result is None or pr_result.status == "error":
                        pr_result = open_remediation_pull_request(
                            repo_url=repo_url,
                            branch_name=commit_result.branch,
                            base_branch=base_branch or branch,
                            summary_markdown=remediation_result.summary_markdown,
                            commits=commit_result.commits,
                            token=github_token,
                            pr_labels=pr_labels,
                        )
                elif push_result.status == "skipped":
                    pr_result = PullRequestResult(
                        status="skipped",
                        reason=push_result.reason or "push was skipped",
                    )
                else:
                    pr_result = PullRequestResult(
                        status="skipped",
                        reason=push_result.reason or "push failed",
                        error=push_result.error,
                    )
            else:
                pr_result = PullRequestResult(status="skipped", reason="pull request disabled by configuration")
        else:
            if apply_commits:
                if commit_result.branch and not commit_result.commits:
                    push_result = PushResult(
                        status="skipped",
                        branch=commit_result.branch,
                        reason="no remediation commits produced",
                    )
                if create_pr:
                    skip_reason = "no remediation commits produced"
                    if commit_result.errors:
                        skip_reason += "; review commit_errors for details"
                    pr_result = PullRequestResult(status="skipped", reason=skip_reason)
            else:
                if push:
                    push_result = PushResult(
                        status="skipped",
                        reason="apply_commits disabled by configuration",
                    )
                if create_pr:
                    pr_result = PullRequestResult(
                        status="skipped",
                        reason="apply_commits disabled by configuration",
                    )

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
