"""Tests for the mytunnel test deployment helper."""

from __future__ import annotations

import subprocess
from typing import List

import pytest

from mcp_scanner.scripts.deploy_test_tunnel import (
    build_lt_command,
    ensure_localtunnel,
    parse_public_url,
)


@pytest.mark.parametrize(
    "line,expected",
    [
        ("your url is: https://busy-papers-melt.loca.lt", "https://busy-papers-melt.loca.lt"),
        ("connect via http://example.com/path", "http://example.com/path"),
        ("no url here", None),
    ],
)
def test_parse_public_url(line: str, expected: str | None) -> None:
    """Ensure URLs are extracted from localtunnel output."""

    assert parse_public_url(line) == expected


def test_build_lt_command_with_options() -> None:
    """Construct a command with optional host and subdomain."""

    command = build_lt_command(8000, subdomain="demo", host="https://tunnels.test")
    assert command == ["lt", "--port", "8000", "--subdomain", "demo", "--host", "https://tunnels.test"]


def test_build_lt_command_requires_positive_port() -> None:
    """A non-positive port raises a ValueError."""

    with pytest.raises(ValueError):
        build_lt_command(0)


def test_ensure_localtunnel_requires_install_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without --install-lt the helper surfaces a clear error."""

    monkeypatch.setattr("mcp_scanner.scripts.deploy_test_tunnel.shutil.which", lambda _: None)
    with pytest.raises(RuntimeError):
        ensure_localtunnel(allow_install=False)


def test_ensure_localtunnel_runs_npm_when_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The helper invokes npm install when lt is missing and installation is allowed."""

    calls: List[List[str]] = []

    def fake_which(name: str) -> str | None:
        if name == "lt":
            return None
        if name == "npm":
            return "/usr/bin/npm"
        return None

    def fake_run(cmd: List[str], check: bool) -> subprocess.CompletedProcess[None]:  # type: ignore[override]
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0)

    monkeypatch.setattr("mcp_scanner.scripts.deploy_test_tunnel.shutil.which", fake_which)
    monkeypatch.setattr("mcp_scanner.scripts.deploy_test_tunnel.subprocess.run", fake_run)

    ensure_localtunnel(allow_install=True)

    assert calls == [["/usr/bin/npm", "install", "-g", "localtunnel"]]
