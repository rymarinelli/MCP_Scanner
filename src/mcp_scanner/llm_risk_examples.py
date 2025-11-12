"""Example module containing intentionally insecure LLM integration patterns.

The functions in this module are not used by the application. They exist solely to
provide concrete examples of risky LLM orchestration behaviours so that Semgrep and
other scanners can validate rule coverage for MCP Scanner.
"""

from __future__ import annotations

import os
import subprocess
from typing import Callable, Protocol

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


def build_prompt(user_input: str, *, system_prompt: str = "You are a helpful AI") -> str:
    """Construct a prompt by directly embedding untrusted user input."""

    prompt = system_prompt + "\n\nUser instruction:\n" + user_input
    return prompt


def execute_tool_response(llm_command: str, *, runner: Callable[[str], int] | None = None) -> int:
    """Invoke a shell command suggested by an LLM without validation."""

    if runner is not None:
        return runner(llm_command)
    return subprocess.run(llm_command, shell=True, check=False).returncode


def invoke_insecure_model(prompt: str) -> str:
    """Send a prompt to an LLM endpoint over an insecure transport channel."""

    response = requests.post(
        "http://insecure-model.local/invoke",
        json={"prompt": prompt, "temperature": 1.0},
        timeout=30,
        verify=False,
    )
    response.raise_for_status()
    return response.text


def dispatch_with_os_system(llm_script: str) -> int:
    """Execute an LLM-provided script using os.system."""

    return os.system(llm_script)
