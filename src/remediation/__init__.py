"""Remediation package exports."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - imported for type checking only
    from .dspy_driver import DSPyRemediationDriver as _DSPyRemediationDriver

__all__ = ["DSPyRemediationDriver"]


def __getattr__(name: str) -> Any:  # pragma: no cover - simple delegation logic
    """Lazily import heavy modules to avoid circular import chains."""

    if name == "DSPyRemediationDriver":
        from .dspy_driver import DSPyRemediationDriver

        return DSPyRemediationDriver
    raise AttributeError(f"module 'remediation' has no attribute {name!r}")
