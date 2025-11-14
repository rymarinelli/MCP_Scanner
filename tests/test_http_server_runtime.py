"""Integration-style tests for the standalone HTTP server."""  

from __future__ import annotations

import json
import threading
import time
from http.client import HTTPConnection
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def test_scan_endpoint(monkeypatch):
    from service import http_server

    captured: dict[str, object] = {}

    def fake_handler(
        *,
        repo_url: str,
        branch: str | None = None,
        quick: bool,
        apply_commits: bool,
        push: bool,
        create_pr: bool,
        base_branch: str | None,
        pr_labels: list[str] | None,
        github_token: str | None,
    ):  # type: ignore[no-redef]
        captured.update(
            {
                "repo_url": repo_url,
                "branch": branch,
                "quick": quick,
                "apply_commits": apply_commits,
                "push": push,
                "create_pr": create_pr,
                "base_branch": base_branch,
                "pr_labels": pr_labels,
                "github_token": github_token,
            }
        )
        return {
            "repository": {"url": repo_url, "branch": branch},
            "semgrep": {"status": "ok"},
            "remediation": {"proposals": [], "summary_markdown": ""},
        }

    original_handler = http_server.SCAN_HANDLER
    http_server.SCAN_HANDLER = fake_handler

    server = http_server.ThreadingHTTPServer(("127.0.0.1", 0), http_server.MCPRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    try:
        host, port = server.server_address
        conn = HTTPConnection(host, port)
        payload = json.dumps(
            {
                "repo_url": "https://example.com/repo.git",
                "branch": "main",
                "quick": True,
                "apply_commits": False,
                "push": False,
                "create_pr": False,
                "base_branch": "develop",
                "pr_labels": ["automated", "security"],
                "github_token": "ghp_123",
            }
        )
        conn.request("POST", "/scan", body=payload, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        body = response.read()
        data = json.loads(body)

        assert response.status == 200
        assert data["status"] == "success"
        assert data["data"]["repository"]["url"] == "https://example.com/repo.git"
        assert captured == {
            "repo_url": "https://example.com/repo.git",
            "branch": "main",
            "quick": True,
            "apply_commits": False,
            "push": False,
            "create_pr": False,
            "base_branch": "develop",
            "pr_labels": ["automated", "security"],
            "github_token": "ghp_123",
        }
    finally:
        http_server.SCAN_HANDLER = original_handler
        server.shutdown()
        thread.join(timeout=1)


def test_scan_endpoint_rejects_invalid_pr_labels(monkeypatch):
    from service import http_server

    def fake_handler(**_: object):  # type: ignore[no-redef]
        raise AssertionError("handler should not be invoked for invalid payloads")

    original_handler = http_server.SCAN_HANDLER
    http_server.SCAN_HANDLER = fake_handler

    server = http_server.ThreadingHTTPServer(("127.0.0.1", 0), http_server.MCPRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    try:
        host, port = server.server_address
        conn = HTTPConnection(host, port)
        payload = json.dumps({"repo_url": "https://example.com/repo.git", "pr_labels": "oops"})
        conn.request("POST", "/scan", body=payload, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        body = response.read()
        data = json.loads(body)

        assert response.status == 400
        assert data["status"] == "error"
        assert data["error"]["message"] == "Field 'pr_labels' must be an array of strings if provided"
    finally:
        http_server.SCAN_HANDLER = original_handler
        server.shutdown()
        thread.join(timeout=1)


def test_scan_endpoint_rejects_non_string_token(monkeypatch):
    from service import http_server

    def fake_handler(**_: object):  # type: ignore[no-redef]
        raise AssertionError("handler should not be invoked for invalid payloads")

    original_handler = http_server.SCAN_HANDLER
    http_server.SCAN_HANDLER = fake_handler

    server = http_server.ThreadingHTTPServer(("127.0.0.1", 0), http_server.MCPRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    try:
        host, port = server.server_address
        conn = HTTPConnection(host, port)
        payload = json.dumps({"repo_url": "https://example.com/repo.git", "github_token": ["oops"]})
        conn.request("POST", "/scan", body=payload, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        body = response.read()
        data = json.loads(body)

        assert response.status == 400
        assert data["status"] == "error"
        assert data["error"]["message"] == "Field 'github_token' must be a string if provided"
    finally:
        http_server.SCAN_HANDLER = original_handler
        server.shutdown()
        thread.join(timeout=1)
