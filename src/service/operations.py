"""Operational helpers for executing MCP scans via the HTTP service."""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
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


LOGGER = logging.getLogger("mcp_scanner.service.operations")

_ENV_ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def _format_command(command: Sequence[str]) -> str:
    """Return a shell-quoted representation of ``command`` for logging."""

    return " ".join(shlex.quote(part) for part in command)


def _log_multiline(header: str, content: str | None) -> None:
    """Emit a multi-line INFO log with ``header`` and ``content``."""

    if not content:
        LOGGER.info("%s: <empty>", header)
        return
    LOGGER.info("%s:\n%s", header, content)


def _json_for_logging(payload: object) -> str:
    """Serialize ``payload`` for logging, falling back to ``repr`` if needed."""

    try:
        return json.dumps(payload, indent=2, sort_keys=True)
    except TypeError:
        return repr(payload)


def _sanitize_remote(remote_url: str | None) -> str:
    """Scrub authentication tokens from remote URLs before logging.

    The sanitised representation intentionally omits any username/password
    components entirely so log output mirrors the canonical repository URL and
    avoids inserting placeholder characters (for example ``***``) that can be
    mistaken for part of the remote.
    """

    if not remote_url:
        return ""

    try:
        parsed = urlparse(remote_url)
    except Exception:  # pragma: no cover - defensive guard
        return ""

    if "@" not in parsed.netloc:
        return remote_url

    host = parsed.netloc.split("@", 1)[1]
    return urlunparse((parsed.scheme, host, parsed.path, parsed.params, parsed.query, parsed.fragment))


def _normalize_github_token(token: Optional[str]) -> Optional[str]:
    """Normalize ``token`` by trimming whitespace and surrounding quotes."""

    if token is None:
        return None

    normalized = token.strip()
    if not normalized:
        return None

    if len(normalized) >= 2 and normalized[0] == normalized[-1] and normalized[0] in {'"', "'"}:
        normalized = normalized[1:-1].strip()

    if not normalized:
        return None
    return normalized


def _parse_env_assignment(line: str) -> Optional[Tuple[str, str]]:
    """Parse a ``KEY=VALUE`` assignment from ``line`` if present."""

    match = _ENV_ASSIGNMENT.match(line)
    if not match:
        return None

    key, raw_value = match.groups()
    key = key.strip()
    if not key:
        return None

    value = raw_value.strip()
    if not value:
        return key, ""

    if value[0] in {'"', "'"}:
        quote = value[0]
        if value.endswith(quote) and len(value) > 1:
            value = value[1:-1]
        else:
            value = value[1:]
        return key, value.strip()

    comment_index = None
    for delimiter in (" #", "\t#"):
        idx = value.find(delimiter)
        if idx != -1:
            comment_index = idx
            break
    if comment_index is None:
        hash_index = value.find("#")
        if hash_index != -1 and (hash_index == 0 or value[hash_index - 1].isspace()):
            comment_index = hash_index
    if comment_index is not None:
        value = value[:comment_index]

    return key, value.strip()


def _load_github_token_from_env_file() -> Tuple[Optional[str], Optional[Path]]:
    """Attempt to read ``GITHUB_TOKEN`` from ``.env`` style files."""

    env_file_override = os.environ.get("MCP_ENV_FILE")
    candidates: List[Path] = []
    if env_file_override:
        candidates.append(Path(env_file_override))
    candidates.append(Path(".env"))

    seen: set[Path] = set()
    for candidate in candidates:
        normalized = candidate if candidate.is_absolute() else Path.cwd() / candidate
        if normalized in seen:
            continue
        seen.add(normalized)
        try:
            content = normalized.read_text(encoding="utf-8")
        except FileNotFoundError:
            continue
        except OSError as exc:  # pragma: no cover - filesystem errors are rare
            LOGGER.warning("Unable to read %s: %s", normalized, exc)
            continue

        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            assignment = _parse_env_assignment(stripped)
            if not assignment:
                continue
            key, value = assignment
            if key == "GITHUB_TOKEN":
                return value.strip(), normalized

    return None, None


def resolve_github_token(explicit_token: Optional[str] = None) -> Optional[str]:
    """Return the best available GitHub token from explicit, env, or ``.env`` sources."""

    sources = [
        (explicit_token, "explicit parameter"),
        (os.environ.get("GITHUB_TOKEN"), "GITHUB_TOKEN env"),
        (os.environ.get("MCP_GITHUB_TOKEN"), "MCP_GITHUB_TOKEN env"),
    ]

    for candidate, source in sources:
        token = _normalize_github_token(candidate)
        if token:
            LOGGER.info("Using GitHub token from %s", source)
            return token

    env_token, env_path = _load_github_token_from_env_file()
    token = _normalize_github_token(env_token)
    if token and env_path:
        LOGGER.info("Using GitHub token from %s", env_path)
        return token

    return None


def _normalize_git_username(username: Optional[str]) -> Optional[str]:
    """Normalize ``username`` by trimming whitespace and surrounding quotes."""

    if username is None:
        return None

    normalized = username.strip()
    if not normalized:
        return None

    if len(normalized) >= 2 and normalized[0] == normalized[-1] and normalized[0] in {'"', "'"}:
        normalized = normalized[1:-1].strip()

    if not normalized:
        return None

    return normalized


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

    LOGGER.info(
        "Cloning repository %s (branch=%s) into %s",
        repo_url,
        branch or "default",
        repo_dir,
    )

    result = _run_subprocess(command)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "Unknown git error"
        raise ScanExecutionError(f"git clone failed: {message}")

    LOGGER.info("Repository cloned successfully to %s", repo_dir)
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
        LOGGER.info("Running Semgrep (quick=%s): %s", quick, _format_command(command))
        result = execute_semgrep(command, cwd=repo_path)
        return interpret_result(result, command)

    output = _invoke(configs)
    if output.normalized_exit_code == 0:
        LOGGER.info(
            "Semgrep completed with exit=%s (normalized=%s, status=%s)",
            output.semgrep_exit_code,
            output.normalized_exit_code,
            output.status,
        )
        findings = output.results.get("results", []) if isinstance(output.results, Mapping) else []
        errors = output.results.get("errors", []) if isinstance(output.results, Mapping) else []
        LOGGER.info(
            "Semgrep reported %s findings and %s errors", len(findings), len(errors)
        )
        _log_multiline("Semgrep report", _json_for_logging(output.results))
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
            LOGGER.warning(
                "Remote Semgrep configs failed; retried with local configs: %s",
                ", ".join(skipped),
            )
            LOGGER.info(
                "Semgrep completed with exit=%s (normalized=%s, status=%s)",
                fallback.semgrep_exit_code,
                fallback.normalized_exit_code,
                fallback.status,
            )
            findings = (
                fallback.results.get("results", [])
                if isinstance(fallback.results, Mapping)
                else []
            )
            errors = (
                fallback.results.get("errors", [])
                if isinstance(fallback.results, Mapping)
                else []
            )
            LOGGER.info(
                "Semgrep reported %s findings and %s errors", len(findings), len(errors)
            )
            _log_multiline("Semgrep report", _json_for_logging(fallback.results))
            return fallback

    LOGGER.error(
        "Semgrep failed with exit=%s (normalized=%s, status=%s)",
        output.semgrep_exit_code,
        output.normalized_exit_code,
        output.status,
    )
    if isinstance(output.results, Mapping):
        _log_multiline("Semgrep report", _json_for_logging(output.results))
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

    LOGGER.info(
        "Repository enumeration complete: %s nodes, %s edges",
        enumeration_payload["graph"]["node_count"],
        enumeration_payload["graph"]["edge_count"],
    )
    LOGGER.info(
        "RAG artifacts written: %s",
        {key: str(path) for key, path in artifact_paths.items()},
    )
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
        LOGGER.info("Persisted enumeration artifact %s -> %s", key, persisted_path)
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
        LOGGER.info("Persisted remediation artifact %s -> %s", key, persisted_path)
    return persisted


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


def _strip_code_fence(diff_text: str) -> str:
    """Remove leading and trailing markdown code fences from ``diff_text``."""

    stripped = diff_text.strip()
    if not stripped.startswith("```"):
        return diff_text

    lines = stripped.splitlines()
    if len(lines) < 2:
        return diff_text

    opening = lines[0].strip().lower()
    closing = lines[-1].strip()
    if closing != "```":
        return diff_text

    body = lines[1:-1]
    if not body:
        return ""

    # Some models prefix the fence language (e.g. "```diff" or "```patch").
    if opening.startswith("```diff") or opening.startswith("```patch"):
        return "\n".join(body)

    # Generic fences like ````` may still wrap a diff payload.
    if opening == "```":
        return "\n".join(body)

    return diff_text


def _normalize_patch_text(diff_text: str) -> str:
    """Normalize a proposed patch by stripping fences and extraneous whitespace."""

    if not diff_text:
        return ""

    stripped = _strip_code_fence(diff_text)
    if not stripped:
        return ""

    normalized = stripped.strip()
    if normalized and not normalized.endswith("\n"):
        normalized += "\n"
    return normalized


def _looks_like_patch(diff_text: str) -> bool:
    """Heuristically determine whether ``diff_text`` appears to be a patch."""

    normalized = _normalize_patch_text(diff_text)
    if not normalized:
        return False

    stripped = normalized.lstrip()
    if not stripped:
        return False

    # Common diff formats start with ``diff --git`` or file markers.
    if stripped.startswith("diff --git"):
        return True

    lines = stripped.splitlines()
    if not lines:
        return False

    # Unified diffs begin with ``---``/``+++`` headers and contain ``@@`` hunks.
    for candidate in lines[:5]:
        if candidate.startswith("--- ") or candidate.startswith("+++ "):
            return True

    return any(line.startswith("@@") for line in lines)


def apply_remediation_commits(
    repo_path: Path,
    proposals: Sequence[PatchProposal],
) -> CommitApplicationResult:
    """Apply remediation proposals to the repository and commit them."""

    if not proposals:
        return CommitApplicationResult(branch=None, commits=[], errors=[])

    commits: List[CommitRecord] = []
    errors: List[CommitError] = []
    branch_name: Optional[str] = None
    branch_initialized = False

    def _ensure_branch() -> None:
        nonlocal branch_initialized, branch_name
        if branch_initialized:
            return
        branch_name = f"mcp/remediation-{uuid.uuid4().hex[:8]}"
        LOGGER.info("Creating remediation branch %s", branch_name)
        checkout = _run_subprocess(["git", "checkout", "-b", branch_name], cwd=repo_path)
        if checkout.returncode != 0:
            message = checkout.stderr.strip() or checkout.stdout.strip() or "Unknown git error"
            raise ScanExecutionError(f"git checkout -b {branch_name} failed: {message}")

        _ensure_git_identity(repo_path)
        LOGGER.info("Git identity configured for remediation commits")
        branch_initialized = True

    for vulnerability_id, group in _group_proposals(proposals).items():
        if not group:
            continue

        valid_proposals: List[Tuple[PatchProposal, str]] = []
        for proposal in group:
            patch_text = proposal.diff or ""
            if not patch_text.strip():
                errors.append(CommitError(vulnerability_id=vulnerability_id, reason="empty_diff"))
                LOGGER.warning("Skipping proposal for %s due to empty diff", vulnerability_id)
                continue
            normalized_patch = _normalize_patch_text(patch_text)
            if not normalized_patch:
                errors.append(
                    CommitError(
                        vulnerability_id=vulnerability_id,
                        reason="empty_diff",
                        details="proposal diff became empty after normalization",
                    )
                )
                LOGGER.warning(
                    "Skipping proposal for %s due to empty diff after normalization",
                    vulnerability_id,
                )
                continue
            if not _looks_like_patch(normalized_patch):
                errors.append(
                    CommitError(
                        vulnerability_id=vulnerability_id,
                        reason="invalid_patch_format",
                        details="proposal diff does not resemble a unified diff",
                    )
                )
                LOGGER.warning(
                    "Skipping proposal for %s due to non-diff content", vulnerability_id
                )
                continue
            valid_proposals.append((proposal, normalized_patch))

        if not valid_proposals:
            continue

        _ensure_branch()

        LOGGER.info(
            "Applying %s proposal(s) for vulnerability %s",
            len(valid_proposals),
            vulnerability_id,
        )
        apply_failed = False
        for proposal, normalized_patch in valid_proposals:
            apply_result = _run_subprocess(
                ["git", "apply", "--whitespace=fix"],
                cwd=repo_path,
                input=normalized_patch,
            )
            if apply_result.returncode != 0:
                details = (apply_result.stderr or apply_result.stdout or "").strip()
                LOGGER.error(
                    "git apply failed for %s: %s",
                    vulnerability_id,
                    details or "unknown error",
                )
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
            LOGGER.error("git add failed for %s: %s", vulnerability_id, details or "unknown error")
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
            LOGGER.warning("No staged changes for %s; skipping commit", vulnerability_id)
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
            LOGGER.error(
                "git commit failed for %s: %s", vulnerability_id, details or "unknown error"
            )
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
                proposals=[proposal for proposal, _ in valid_proposals],
            )
        )
        LOGGER.info(
            "Created commit %s for %s", commit_sha[:7] if commit_sha else "<unknown>", vulnerability_id
        )

    return CommitApplicationResult(branch=branch_name, commits=commits, errors=errors)


def _authenticated_remote_candidates(repo_url: str, token: str | None) -> List[str]:
    """Generate HTTPS remote URLs that embed ``token`` for authentication."""

    token = _normalize_github_token(token)
    if not token:
        return []

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
    env_username = _normalize_git_username(
        os.environ.get("GIT_USER") or os.environ.get("GITHUB_ACTOR")
    )
    if env_username:
        username_hints.append(env_username)

    slug = _parse_repo_slug(repo_url)
    if slug:
        owner, _ = slug
        owner = _normalize_git_username(owner)
        if owner:
            username_hints.append(owner)

    if username_hints:
        LOGGER.info(
            "Derived Git username hints for authentication: %s",
            username_hints,
        )

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

    token = resolve_github_token(token)
    if not token:
        LOGGER.warning("Skipping push for %s: no GITHUB_TOKEN provided", branch_name)
        return PushResult(status="skipped", branch=branch_name, reason="GITHUB_TOKEN not provided")

    remote_variants = _authenticated_remote_candidates(repo_url, token)
    if not remote_variants:
        remote_variants = [None]

    LOGGER.info(
        "Attempting to push remediation branch %s (remote candidates=%s)",
        branch_name,
        [
            _sanitize_remote(variant)
            if variant is not None
            else "origin"
            for variant in remote_variants
        ],
    )
    errors: List[str] = []
    for remote_url in remote_variants:
        if remote_url:
            _run_subprocess(["git", "remote", "set-url", "origin", remote_url], cwd=repo_path)
            LOGGER.info("Configured remote origin as %s", _sanitize_remote(remote_url))

        push = _run_subprocess(["git", "push", "--set-upstream", "origin", branch_name], cwd=repo_path)
        if push.returncode == 0:
            LOGGER.info("Successfully pushed branch %s to origin", branch_name)
            return PushResult(status="success", branch=branch_name, remote="origin", message="Branch pushed to origin")

        message = push.stderr.strip() or push.stdout.strip() or "Unknown git error"
        LOGGER.warning(
            "git push failed for branch %s via %s: %s",
            branch_name,
            _sanitize_remote(remote_url) if remote_url else "origin",
            message,
        )
        errors.append(message)

    error_message = errors[-1] if errors else "Unknown git error"
    reason = None
    if len(errors) > 1:
        reason = "git push failed after attempting multiple credential formats"

    LOGGER.error(
        "git push failed for branch %s after %s attempt(s): %s",
        branch_name,
        len(remote_variants),
        error_message,
    )
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
        LOGGER.warning("Skipping pull request creation: no commits available")
        return PullRequestResult(status="skipped", reason="no commits to include")

    token = resolve_github_token(token)
    if not token:
        LOGGER.warning("Skipping pull request creation: no GITHUB_TOKEN provided")
        return PullRequestResult(status="skipped", reason="GITHUB_TOKEN not provided")

    slug = _parse_repo_slug(repo_url)
    if not slug:
        LOGGER.error("Unable to parse repository slug from repo_url: %s", repo_url)
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

    LOGGER.info(
        "Creating pull request against %s/%s: title=%s, head=%s, base=%s",
        owner,
        repo,
        title,
        branch_name,
        base_branch or "main",
    )

    try:
        with urllib.request.urlopen(request) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:  # pragma: no cover - requires HTTP interaction
        error_body = exc.read().decode("utf-8", errors="ignore")
        LOGGER.error(
            "GitHub API returned %s while creating pull request: %s",
            exc.code,
            error_body,
        )
        return PullRequestResult(
            status="error",
            error=f"GitHub API returned {exc.code}",
            response={"body": error_body},
        )
    except Exception as exc:  # pragma: no cover - defensive guard
        LOGGER.exception("Unexpected error while creating pull request")
        return PullRequestResult(status="error", error=str(exc))

    labels_result: Dict[str, Any] | None = None
    if pr_labels:
        issue_number = data.get("number")
        if issue_number is None:
            labels_result = {"status": "skipped", "reason": "missing pull request number"}
            LOGGER.warning("Skipping label application: missing pull request number in response")
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
                    LOGGER.info(
                        "Applied labels %s to pull request #%s", list(pr_labels), issue_number
                    )
            except urllib.error.HTTPError as exc:  # pragma: no cover - requires HTTP interaction
                error_body = exc.read().decode("utf-8", errors="ignore")
                LOGGER.error(
                    "GitHub API returned %s while applying labels: %s",
                    exc.code,
                    error_body,
                )
                labels_result = {
                    "status": "error",
                    "error": f"GitHub API returned {exc.code}",
                    "body": error_body,
                }
            except Exception as exc:  # pragma: no cover - defensive guard
                LOGGER.exception("Unexpected error while applying labels")
                labels_result = {"status": "error", "error": str(exc)}

    LOGGER.info(
        "Pull request created: %s (number=%s)",
        data.get("html_url"),
        data.get("number"),
    )
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
    LOGGER.info(
        "Invoking open_pull_request tool for branch %s (base=%s)",
        branch_name,
        base_branch,
    )

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
    LOGGER.info("open_pull_request tool returned transport status=%s", status)
    if status != "success":
        error = response.get("error")
        if isinstance(error, Mapping) and error.get("type") == "ToolNotFound":
            LOGGER.warning("open_pull_request tool not found in registry")
            return None
        LOGGER.error("open_pull_request tool invocation failed: %s", _describe_tool_error(error))
        return PullRequestResult(status="error", error=_describe_tool_error(error))

    payload = response.get("result")
    if not isinstance(payload, Mapping):
        LOGGER.error("open_pull_request tool returned malformed payload: %s", response)
        return PullRequestResult(status="error", error="open_pull_request returned malformed payload")

    try:
        result = PullRequestResult.from_mapping(payload)
        LOGGER.info(
            "open_pull_request tool result: status=%s url=%s number=%s",
            result.status,
            result.url,
            result.number,
        )
        return result
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
    LOGGER.info("Semgrep findings saved to %s", findings_path)

    suggester = RemediationSuggester(output_dir=workspace / "remediations", repo_root=repo_path)
    LOGGER.info(
        "Initializing DSPy remediation driver (output_markdown=%s)",
        workspace / "dspy_suggestions.md",
    )
    driver = DSPyRemediationDriver(
        suggester=suggester,
        output_markdown=workspace / "dspy_suggestions.md",
    )

    LOGGER.info("Starting DSPy remediation generation")
    proposals = driver.run(
        semgrep_path=findings_path,
        rag_context_path=rag_context_path,
    )
    LOGGER.info("DSPy remediation generation complete (%s proposals)", len(proposals))

    summary_markdown = driver.output_markdown.read_text(encoding="utf-8")
    LOGGER.info("DSPy summary written to %s", driver.output_markdown)
    _log_multiline("DSPy summary", summary_markdown)

    artifacts: Dict[str, Path] = {
        "semgrep_results": findings_path,
        "dspy_summary": driver.output_markdown,
    }
    remediation_dir = driver.suggester.output_dir
    if isinstance(remediation_dir, Path) and remediation_dir.exists():
        artifacts["dspy_cases"] = remediation_dir
        LOGGER.info("DSPy remediation cases written to %s", remediation_dir)

    for proposal in proposals:
        header = f"DSPy proposal {proposal.vulnerability_id} ({proposal.file_path})"
        diff = proposal.diff.strip() if proposal.diff else ""
        _log_multiline(header, diff or "<empty diff>")
        normalized_diff = _normalize_patch_text(diff)
        if normalized_diff and normalized_diff != diff:
            _log_multiline(f"{header} (normalized)", normalized_diff)
        if proposal.rationale:
            _log_multiline(
                f"DSPy rationale {proposal.vulnerability_id}", proposal.rationale.strip()
            )

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

    LOGGER.info(
        "Starting scan: repo=%s branch=%s quick=%s apply_commits=%s push=%s create_pr=%s",
        repo_url,
        branch or "default",
        quick,
        apply_commits,
        push,
        create_pr,
    )

    github_token = resolve_github_token(github_token)
    if github_token is None:
        LOGGER.warning("GitHub token unavailable; push/PR steps may be skipped")

    artifact_root = Path(tempfile.mkdtemp(prefix="mcp-scan-artifacts-"))
    LOGGER.info("Artifacts will be persisted under %s", artifact_root)

    with tempfile.TemporaryDirectory(prefix="mcp-scan-") as tmpdir:
        workspace = Path(tmpdir)
        repo_path = clone_repository(repo_url, branch, workspace)
        enumeration_payload, rag_context_path, artifact_paths = enumerate_repository(repo_path, workspace)
        LOGGER.info("Repository cloned to %s; RAG context at %s", repo_path, rag_context_path)
        semgrep_output = run_semgrep_scan(repo_path, quick=quick)

        semgrep_payload = semgrep_output.to_dict()
        if semgrep_output.normalized_exit_code != 0:
            raise ScanExecutionError(
                "Semgrep execution failed",
            )
        LOGGER.info("Semgrep scan completed successfully")

        remediation_result = generate_remediations(
            semgrep_output,
            workspace,
            rag_context_path,
            repo_path,
        )
        LOGGER.info(
            "Generated %s remediation proposal(s)", len(remediation_result.proposals)
        )

        if apply_commits:
            commit_result = apply_remediation_commits(repo_path, remediation_result.proposals)
        else:
            commit_result = CommitApplicationResult(branch=None, commits=[], errors=[])
        LOGGER.info(
            "Commit application result: branch=%s commits=%s errors=%s",
            commit_result.branch,
            len(commit_result.commits),
            len(commit_result.errors),
        )

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
            LOGGER.info(
                "Push result: %s", push_result.to_dict() if push_result else {"status": "unknown"}
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
            if pr_result:
                LOGGER.info("Pull request result: %s", pr_result.to_dict())
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
            if push_result:
                LOGGER.info("Push result: %s", push_result.to_dict())
            if create_pr and pr_result:
                LOGGER.info("Pull request result: %s", pr_result.to_dict())

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

        LOGGER.info("Scan complete; results ready for response")
        return {
            "repository": {
                "url": repo_url,
                "branch": branch,
            },
            "enumeration": enumeration_payload,
            "semgrep": semgrep_payload,
            "remediation": remediation_payload,
        }
