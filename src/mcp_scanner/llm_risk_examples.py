"""Illustrative helpers that mirror risky LLM orchestration patterns."""

from __future__ import annotations

import os
import shlex
import subprocess
import textwrap
from typing import Callable, Mapping, Protocol, Sequence
from urllib.parse import urlparse

try:  # pragma: no cover - optional dependency for illustrative examples
    import requests
except ImportError:  # pragma: no cover - minimal shim if requests is unavailable
    class _RequestsShim(Protocol):
        def post(self, *args, **kwargs):  # type: ignore[empty-body]
            ...

    class _RequestsFallback:
        def post(self, *args, **kwargs):  # pragma: no cover - not exercised in tests
            raise RuntimeError("requests is required to invoke remote models")

    requests: _RequestsShim = _RequestsFallback()  # type: ignore[assignment]

DEFAULT_MODEL_URL = "https://secure-model.local/invoke"


MAX_USER_INPUT_LENGTH = 4000
Runner = Callable[[Sequence[str]], int]


def _sanitize_user_input(user_input: str) -> str:
    """Return a bounded, sanitised representation of ``user_input``."""

    normalized = user_input.replace("\r\n", "\n").replace("\r", "\n")
    normalized = normalized.replace("```", "'''")
    collapsed = "\n".join(line.strip() for line in normalized.splitlines())
    collapsed = collapsed.strip()
    if len(collapsed) > MAX_USER_INPUT_LENGTH:
        return collapsed[:MAX_USER_INPUT_LENGTH]
    return collapsed


def build_prompt(user_input: str, *, system_prompt: str = "You are a helpful AI") -> str:
    """Construct a prompt that treats untrusted input as inert content."""

    sanitized_input = _sanitize_user_input(user_input)
    if not sanitized_input:
        sanitized_input = "[no user input provided]"
    quoted = textwrap.indent(sanitized_input, prefix="> ")
    prompt = f"{system_prompt}\n\nUser instruction (sanitized):\n{quoted}"
    return prompt


def _resolve_command(
    llm_command: str,
    *,
    allowed_commands: Mapping[str, Sequence[str]] | None = None,
) -> Sequence[str]:
    normalized = llm_command.strip()
    if not normalized:
        raise ValueError("Command must not be empty")

    parts = shlex.split(normalized, posix=True)
    if not parts:
        raise ValueError("Command must not be empty")

    allowlist = allowed_commands or {}
    canonical = allowlist.get(parts[0])
    if canonical is None:
        raise ValueError(f"Command '{parts[0]}' is not permitted")

    return list(canonical) + parts[1:]


def execute_tool_response(
    llm_command: str,
    *,
    runner: Runner | None = None,
    allowed_commands: Mapping[str, Sequence[str]] | None = None,
) -> int:
    """Safely execute an allow-listed tool invocation."""

    command = _resolve_command(llm_command, allowed_commands=allowed_commands)
    executor = runner or (lambda args: subprocess.run(args, check=False).returncode)
    return executor(command)


def invoke_insecure_model(
    prompt: str,
    *,
    model_url: str | None = None,
    session: _RequestsShim | None = None,
) -> str:
    """Send a prompt to an LLM endpoint over HTTPS with certificate validation."""

    target_url = model_url or os.environ.get("MCP_SECURE_MODEL_URL") or DEFAULT_MODEL_URL
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        raise ValueError("model_url must use https")

    http_client = session or requests
    response = http_client.post(
        target_url,
        json={"prompt": prompt, "temperature": 1.0},
        timeout=30,
        verify=True,
    )
    response.raise_for_status()
    return response.text


def dispatch_with_os_system(
    llm_script: str,
    *,
    runner: Runner | None = None,
    allowed_binaries: Sequence[str] | None = None,
) -> int:
    """Execute a shell-free, allow-listed script invocation."""

    allowed = set(allowed_binaries or ())
    command = shlex.split(llm_script.strip(), posix=True)
    if not command:
        raise ValueError("Command must not be empty")

    binary = command[0]
    if binary not in allowed:
        raise ValueError(f"Binary '{binary}' is not permitted")

    executor = runner or (lambda args: subprocess.run(args, check=False).returncode)
    return executor(command)
