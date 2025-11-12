"""Core package for DSPy-driven remediation suggestions."""

from .models import PatchProposal, VulnerabilityContext
from .dspy_programs import PatchSuggestionProgram
from .remediation import RemediationSuggester
from .validation import PatchValidationExecutor, ValidationRequest, ValidationResult

__all__ = [
    "PatchProposal",
    "VulnerabilityContext",
    "PatchSuggestionProgram",
    "RemediationSuggester",
    "ValidationRequest",
    "PatchValidationExecutor",
    "ValidationResult",
]
