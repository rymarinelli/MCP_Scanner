"""Command line interface for MCP Vanguard."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Iterable

from . import core


def _parse_parameter_arguments(arguments: Iterable[str]) -> Dict[str, Any]:
    """Parse ``--key value`` pairs from ``arguments`` into a dictionary."""

    parameters: Dict[str, Any] = {}
    args = list(arguments)
    index = 0
    while index < len(args):
        name = args[index]
        if not name.startswith("--") or len(name) == 2:
            raise ValueError(f"Expected --key value pair, got '{name}'")
        key = name[2:]
        index += 1
        if index >= len(args):
            raise ValueError(f"Missing value for argument '{name}'")
        raw_value = args[index]
        index += 1
        value = _coerce_value(raw_value)
        parameters[key] = value
    return parameters


def _coerce_value(raw: str) -> Any:
    """Attempt to coerce a CLI value into JSON, falling back to ``str``."""

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MCP Vanguard command line interface")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run-tool", help="Execute a registered tool")
    run_parser.add_argument("tool", help="Name of the tool to execute")
    run_parser.add_argument("tool_args", nargs=argparse.REMAINDER, help="Tool-specific parameters")

    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "run-tool":
        try:
            parameters = _parse_parameter_arguments(args.tool_args)
        except ValueError as exc:
            print(json.dumps({
                "status": "error",
                "error": {
                    "type": "InvalidParameters",
                    "message": str(exc),
                },
            }), file=sys.stdout)
            return 2

        response = core.run_tool(args.tool, parameters)
        print(json.dumps(response), file=sys.stdout)
        return 0 if response.get("status") == "success" else 1

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
