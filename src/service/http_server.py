"""Lightweight HTTP server exposing the MCP scan workflow."""

from __future__ import annotations

import json
import logging
import os
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Sequence, Tuple

from .operations import ScanExecutionError, perform_scan, resolve_github_token

LOGGER = logging.getLogger("mcp_scanner.service")

SCAN_HANDLER = perform_scan
MAX_REQUEST_BODY_BYTES = 1_048_576  # 1 MiB limit to mitigate request flooding


def _json_response(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")


class MCPRequestHandler(BaseHTTPRequestHandler):
    """Handle HTTP requests for the MCP scanner service."""

    server_version = "MCPScannerHTTP/1.0"
    error_content_type = "application/json"

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        if self.path.rstrip("/") == "/scan":
            self._handle_scan()
        else:
            self._send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003 - matches parent signature
        LOGGER.info("%s - - %s", self.address_string(), format % args)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _send_json(self, status: HTTPStatus, payload: Dict[str, Any]) -> None:
        body = _json_response(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: HTTPStatus, message: str, *, details: Dict[str, Any] | None = None) -> None:
        payload: Dict[str, Any] = {
            "status": "error",
            "error": {
                "code": status.value,
                "message": message,
            },
        }
        if details:
            payload["error"].update(details)
        self._send_json(status, payload)

    def _read_json_body(self) -> Tuple[Dict[str, Any], bool]:
        content_length = self.headers.get("Content-Length")
        if content_length is None:
            self._send_error(HTTPStatus.LENGTH_REQUIRED, "Content-Length header missing")
            return {}, False

        try:
            length = int(content_length)
        except ValueError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Invalid Content-Length header")
            return {}, False

        if length <= 0:
            self._send_error(HTTPStatus.BAD_REQUEST, "Content-Length must be a positive integer")
            return {}, False

        if length > MAX_REQUEST_BODY_BYTES:
            self._send_error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                f"Request body exceeds {MAX_REQUEST_BODY_BYTES} bytes",
            )
            return {}, False

        raw_body = self.rfile.read(length)
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Request body must be valid JSON")
            return {}, False

        if not isinstance(payload, dict):
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON payload must be an object")
            return {}, False
        return payload, True

    def _handle_scan(self) -> None:
        payload, ok = self._read_json_body()
        if not ok:
            return

        repo_url = payload.get("repo_url")
        branch = payload.get("branch")
        quick = payload.get("quick", False)
        apply_commits = payload.get("apply_commits", True)
        push = payload.get("push", True)
        create_pr = payload.get("create_pr", True)
        base_branch = payload.get("base_branch")
        pr_labels = payload.get("pr_labels")
        github_token_input = payload.get("github_token")

        if not isinstance(repo_url, str) or not repo_url.strip():
            self._send_error(HTTPStatus.BAD_REQUEST, "Field 'repo_url' is required")
            return

        if branch is not None and not isinstance(branch, str):
            self._send_error(HTTPStatus.BAD_REQUEST, "Field 'branch' must be a string if provided")
            return

        if not isinstance(quick, bool):
            self._send_error(HTTPStatus.BAD_REQUEST, "Field 'quick' must be a boolean")
            return

        if not isinstance(apply_commits, bool):
            self._send_error(HTTPStatus.BAD_REQUEST, "Field 'apply_commits' must be a boolean")
            return

        if not isinstance(push, bool):
            self._send_error(HTTPStatus.BAD_REQUEST, "Field 'push' must be a boolean")
            return

        if not isinstance(create_pr, bool):
            self._send_error(HTTPStatus.BAD_REQUEST, "Field 'create_pr' must be a boolean")
            return

        if base_branch is not None and not isinstance(base_branch, str):
            self._send_error(HTTPStatus.BAD_REQUEST, "Field 'base_branch' must be a string if provided")
            return
        if github_token_input is not None and not isinstance(github_token_input, str):
            self._send_error(HTTPStatus.BAD_REQUEST, "Field 'github_token' must be a string if provided")
            return

        parsed_labels: Sequence[str] | None
        if pr_labels is None:
            parsed_labels = None
        elif isinstance(pr_labels, list) and all(isinstance(label, str) for label in pr_labels):
            parsed_labels = pr_labels
        else:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "Field 'pr_labels' must be an array of strings if provided",
            )
            return

        github_token = resolve_github_token(github_token_input)

        try:
            result = SCAN_HANDLER(
                repo_url=repo_url,
                branch=branch,
                quick=quick,
                apply_commits=apply_commits,
                push=push,
                create_pr=create_pr,
                base_branch=base_branch,
                pr_labels=parsed_labels,
                github_token=github_token,
            )
        except ValueError as exc:
            self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        except ScanExecutionError as exc:
            LOGGER.exception("Scan execution error")
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))
            return
        except Exception as exc:  # pragma: no cover - defensive guard
            LOGGER.exception("Unhandled error during scan")
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Unexpected error: {exc}")
            return

        self._send_json(HTTPStatus.OK, {"status": "success", "data": result})


def run_server(host: str = "0.0.0.0", port: int = 8000) -> ThreadingHTTPServer:
    """Start the HTTP server and return the server instance."""

    server = ThreadingHTTPServer((host, port), MCPRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    LOGGER.info("Server started on %s:%s", host, port)
    return server


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    host = os.environ.get("MCP_SERVER_HOST", "0.0.0.0")
    port = int(os.environ.get("MCP_SERVER_PORT", "8000"))

    server = ThreadingHTTPServer((host, port), MCPRequestHandler)
    LOGGER.info("Serving MCP Scanner on http://%s:%s", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown
        LOGGER.info("Shutting down server")
    finally:
        server.server_close()


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    main()
