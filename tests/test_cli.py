from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest


PYTHONPATH = os.pathsep.join(filter(None, [os.environ.get("PYTHONPATH"), os.path.abspath("src")]))


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = PYTHONPATH
    cmd = [sys.executable, "-m", "mcp_vanguard", *args]
    return subprocess.run(cmd, check=False, capture_output=True, text=True, env=env)


@pytest.mark.parametrize(
    "parameters, expected",
    [
        (("--message", "hello"), {"message": "hello"}),
        (("--count", "1"), {"count": 1}),
    ],
)
def test_run_tool_echo(parameters, expected):
    result = run_cli("run-tool", "echo", *parameters)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout.strip())
    assert payload["status"] == "success"
    assert payload["tool"] == "echo"
    assert payload["result"]["received"] == expected


def test_run_tool_unknown():
    result = run_cli("run-tool", "missing")
    assert result.returncode == 1
    payload = json.loads(result.stdout.strip())
    assert payload["status"] == "error"
    assert payload["error"]["type"] == "ToolNotFound"
