"""Utilities for executing validation commands against generated patches."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Iterable, List, Sequence

from .models import ValidationResult


@dataclass
class ValidationRequest:
    """Describes a validation command to be executed."""

    command: Sequence[str]
    description: str | None = None


class PatchValidationExecutor:
    """Runs validation commands (tests, lint) to vet generated patches."""

    def __init__(self, *, working_directory: str | None = None) -> None:
        self.working_directory = working_directory

    def run(self, commands: Iterable[ValidationRequest]) -> List[ValidationResult]:
        """Execute validation commands and return their results."""

        results: List[ValidationResult] = []
        for request in commands:
            completed = subprocess.run(
                list(request.command),
                cwd=self.working_directory,
                capture_output=True,
                text=True,
                check=False,
            )
            results.append(
                ValidationResult(
                    command=" ".join(request.command),
                    succeeded=completed.returncode == 0,
                    stdout=completed.stdout,
                    stderr=completed.stderr,
                )
            )
        return results
