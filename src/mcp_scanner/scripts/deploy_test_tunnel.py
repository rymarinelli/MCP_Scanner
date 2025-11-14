"""Helper script to expose the MCP scanner via a public localtunnel URL."""

from __future__ import annotations

import argparse
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import Callable, Iterable, List, Optional

from service.http_server import run_server

LOGGER = logging.getLogger("mcp_scanner.test_deployment")
_URL_PATTERN = re.compile(r"https?://[^\s]+", re.IGNORECASE)


def parse_public_url(text: str) -> Optional[str]:
    """Extract a public URL from a localtunnel log line."""

    match = _URL_PATTERN.search(text)
    return match.group(0) if match else None


def build_lt_command(port: int, subdomain: Optional[str] = None, host: Optional[str] = None) -> List[str]:
    """Construct the localtunnel command for the provided options."""

    if port <= 0:
        raise ValueError("Port must be a positive integer")

    command = ["lt", "--port", str(port)]
    if subdomain:
        command.extend(["--subdomain", subdomain])
    if host:
        command.extend(["--host", host])
    return command


def ensure_localtunnel(allow_install: bool, npm_executable: str = "npm") -> None:
    """Ensure the `lt` CLI is available, optionally installing via npm."""

    if shutil.which("lt"):
        return

    if not allow_install:
        raise RuntimeError(
            "localtunnel CLI 'lt' was not found. Re-run with --install-lt or install manually."
        )

    npm_path = shutil.which(npm_executable)
    if npm_path is None:
        raise RuntimeError(
            "npm executable not found; cannot install localtunnel automatically."
        )

    LOGGER.info("Installing localtunnel globally via npm")
    subprocess.run([npm_path, "install", "-g", "localtunnel"], check=True)


def _stream_process_output(
    proc: subprocess.Popen[str], prefix: str, callback: Optional[Callable[[str], None]] = None
) -> None:
    """Stream a subprocess' stdout lines with a prefix, invoking callback if provided."""

    assert proc.stdout is not None  # For type checkers
    for raw_line in iter(proc.stdout.readline, ""):
        if not raw_line:
            break
        line = raw_line.rstrip()
        if not line:
            continue
        LOGGER.info("%s %s", prefix, line)
        if callback:
            callback(line)


def _terminate_process(proc: Optional[subprocess.Popen[str]], name: str) -> None:
    """Terminate a subprocess gracefully."""

    if proc is None or proc.poll() is not None:
        return

    LOGGER.info("Stopping %s", name)
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        LOGGER.warning("%s did not exit in time; killing", name)
        proc.kill()


def _setup_signal_handlers(stop_event: threading.Event) -> None:
    """Install Ctrl+C/TERM signal handlers that set the provided event."""

    def _handler(signum: int, _frame: object) -> None:
        LOGGER.info("Received signal %s; shutting down", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


def main(argv: Optional[Iterable[str]] = None) -> int:
    """Entry point for the test deployment helper."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("MCP_SERVER_HOST", "0.0.0.0"), help="Host for the MCP server")
    parser.add_argument("--port", type=int, default=int(os.environ.get("MCP_SERVER_PORT", "8000")), help="Port for the MCP server")
    parser.add_argument("--subdomain", help="Preferred mytunnel/localtunnel subdomain", default=None)
    parser.add_argument("--lt-host", help="Override the localtunnel upstream host", default=None)
    parser.add_argument("--install-lt", action="store_true", help="Install localtunnel globally if missing")
    parser.add_argument(
        "--npm-executable", default="npm", help="Path to the npm executable used for --install-lt"
    )
    parser.add_argument(
        "--server-log-level",
        default=os.environ.get("MCP_SERVER_LOG_LEVEL", "INFO"),
        help="Logging level for the embedded MCP server",
    )

    args = parser.parse_args(list(argv) if argv is not None else None)

    logging.basicConfig(level=getattr(logging, args.server_log_level.upper(), logging.INFO))

    ensure_localtunnel(args.install_lt, npm_executable=args.npm_executable)

    LOGGER.info("Starting MCP scanner HTTP server on %s:%s", args.host, args.port)
    http_server = run_server(host=args.host, port=args.port)

    lt_command = build_lt_command(args.port, subdomain=args.subdomain, host=args.lt_host)
    LOGGER.info("Launching localtunnel: %s", " ".join(lt_command))
    lt_proc = subprocess.Popen(
        lt_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    url_event = threading.Event()

    def _handle_lt_line(line: str) -> None:
        url = parse_public_url(line)
        if url and not url_event.is_set():
            print(f"\n🌐 Public MCP URL: {url}\n", flush=True)
            url_event.set()

    lt_thread = threading.Thread(
        target=_stream_process_output,
        args=(lt_proc, "[LT]", _handle_lt_line),
        daemon=True,
    )
    lt_thread.start()

    if not url_event.wait(timeout=30):
        LOGGER.warning("localtunnel did not provide a public URL within 30 seconds")

    stop_event = threading.Event()
    _setup_signal_handlers(stop_event)

    print("MCP scanner and localtunnel are running. Press Ctrl+C to stop.")

    try:
        while not stop_event.is_set():
            time.sleep(1)
    finally:
        stop_event.set()
        _terminate_process(lt_proc, "localtunnel")
        LOGGER.info("Stopping MCP scanner HTTP server")
        http_server.shutdown()
        http_server.server_close()

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI execution
    sys.exit(main())
