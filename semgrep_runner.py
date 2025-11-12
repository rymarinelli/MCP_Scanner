#!/usr/bin/env python3
"""Utilities for executing Semgrep scans with curated rule bundles.

This runner loads project-specific configuration from ``semgrep_rules/config.json``
so that we can execute both our custom rules and the upstream Semgrep OWASP
Top 10 rules in a single invocation. The script normalises Semgrep's exit
codes (``0`` for success, ``1`` for findings) into a JSON payload that can be
consumed by other tooling without forcing the surrounding automation to treat
findings as a hard failure.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

DEFAULT_CONFIG_PATH = Path("semgrep_rules/config.json")


@dataclass
class RunnerConfig:
    """Represents a single Semgrep configuration source."""

    type: str
    value: str
    label: Optional[str] = None

    def resolve(self, base_dir: Path) -> str:
        """Resolve the configuration value for the Semgrep CLI command."""
        if self.type == "local":
            return str((base_dir / self.value).resolve())
        if self.type in {"registry", "remote"}:
            return self.value
        raise ValueError(f"Unsupported ruleset type: {self.type}")


@dataclass
class RunnerOutput:
    """Structured response from a Semgrep invocation."""

    status: str
    normalized_exit_code: int
    semgrep_exit_code: int
    command: List[str]
    results: Dict[str, object]
    stderr: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "status": self.status,
            "normalized_exit_code": self.normalized_exit_code,
            "semgrep_exit_code": self.semgrep_exit_code,
            "command": self.command,
            "results": self.results,
        }
        if self.stderr:
            payload["stderr"] = self.stderr
        return payload


def load_config(config_path: Path) -> List[RunnerConfig]:
    """Load runner configuration from disk."""
    if not config_path.exists():
        raise FileNotFoundError(f"Unable to locate configuration file: {config_path}")

    with config_path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)

    rulesets = raw.get("rulesets", [])
    if not isinstance(rulesets, list) or not rulesets:
        raise ValueError("Configuration file must contain a non-empty 'rulesets' list")

    configs: List[RunnerConfig] = []
    for entry in rulesets:
        if not isinstance(entry, dict):
            raise ValueError("Each ruleset entry must be an object")
        try:
            ruleset_type = entry["type"]
            ruleset_value = entry["value"]
        except KeyError as exc:
            raise ValueError("Ruleset entries must include 'type' and 'value'") from exc

        label = entry.get("label")
        configs.append(RunnerConfig(type=ruleset_type, value=ruleset_value, label=label))
    return configs


def build_command(configs: Iterable[RunnerConfig], targets: Iterable[str], base_dir: Path) -> List[str]:
    """Construct the Semgrep CLI command."""
    command = ["semgrep", "scan", "--json", "--quiet"]
    for config in configs:
        command.extend(["--config", config.resolve(base_dir)])
    for target in targets:
        command.append(str(target))
    return command


def execute_semgrep(
    command: List[str],
    *,
    cwd: Optional[Path | str] = None,
) -> subprocess.CompletedProcess[str]:
    """Execute Semgrep and capture the output."""

    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd is not None else None,
    )


def interpret_result(result: subprocess.CompletedProcess[str], command: List[str]) -> RunnerOutput:
    """Interpret Semgrep's exit code and stdout/stderr into a structured response."""
    stdout = result.stdout.strip() or "{}"

    try:
        parsed_output = json.loads(stdout)
    except json.JSONDecodeError:
        parsed_output = {
            "results": [],
            "errors": [{
                "message": "Unable to parse Semgrep output as JSON",
                "raw": stdout,
            }],
        }

    exit_code = result.returncode
    stderr = result.stderr.strip() or None

    if exit_code in (0, 1):
        status = "results_found" if exit_code == 1 else "ok"
        normalized_exit = 0
    else:
        status = "failed"
        normalized_exit = exit_code if exit_code > 0 else 1
        if "errors" not in parsed_output:
            parsed_output["errors"] = []
        parsed_output["errors"].append({
            "message": "Semgrep execution failed",
            "exit_code": exit_code,
        })

    parsed_output.setdefault("results", [])
    parsed_output.setdefault("errors", [])

    return RunnerOutput(
        status=status,
        normalized_exit_code=normalized_exit,
        semgrep_exit_code=exit_code,
        command=command,
        results=parsed_output,
        stderr=stderr,
    )


def write_output(output: RunnerOutput, output_path: Optional[Path]) -> None:
    payload = output.to_dict()
    encoded = json.dumps(payload, indent=2)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Semgrep with project defaults")
    parser.add_argument(
        "targets",
        nargs="*",
        default=["."],
        help="Targets to scan (files or directories). Defaults to the current directory.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="Path to the Semgrep runner configuration file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write the JSON payload to in addition to stdout.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    config_base = args.config.parent.resolve()

    try:
        configs = load_config(args.config)
    except FileNotFoundError as exc:
        output = RunnerOutput(
            status="missing_configuration",
            normalized_exit_code=2,
            semgrep_exit_code=2,
            command=[],
            results={
                "results": [],
                "errors": [{"message": str(exc)}],
            },
            stderr=None,
        )
    except Exception as exc:  # pragma: no cover - guardrail for unexpected errors
        output = RunnerOutput(
            status="failed",
            normalized_exit_code=2,
            semgrep_exit_code=2,
            command=[],
            results={
                "results": [],
                "errors": [{"message": str(exc)}],
            },
            stderr=None,
        )
    else:
        try:
            command = build_command(configs, args.targets, config_base)
            result = execute_semgrep(command)
            output = interpret_result(result, command)
        except FileNotFoundError as exc:
            output = RunnerOutput(
                status="semgrep_not_found",
                normalized_exit_code=2,
                semgrep_exit_code=127,
                command=[],
                results={
                    "results": [],
                    "errors": [{"message": str(exc)}],
                },
                stderr=None,
            )
        except Exception as exc:  # pragma: no cover - guardrail for unexpected errors
            output = RunnerOutput(
                status="failed",
                normalized_exit_code=2,
                semgrep_exit_code=2,
                command=[],
                results={
                    "results": [],
                    "errors": [{"message": str(exc)}],
                },
                stderr=None,
            )

    write_output(output, args.output)
    return output.normalized_exit_code


if __name__ == "__main__":
    sys.exit(main())
