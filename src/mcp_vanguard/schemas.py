"""Pydantic models for the MCP Vanguard HTTP API."""
from __future__ import annotations

from typing import Any, Dict

from pydantic import BaseModel, Field

try:  # pragma: no cover - compatibility shim
    from pydantic import RootModel
except ImportError:  # pragma: no cover
    RootModel = None  # type: ignore


class ToolCallRequest(BaseModel):
    """Request payload describing a tool invocation."""

    tool: str
    arguments: Dict[str, Any] = Field(default_factory=dict)


if RootModel is not None:  # pragma: no branch
    try:

        class ToolCallResponse(RootModel[Dict[str, Any]]):
            """Response payload wrapping arbitrary tool output."""

    except TypeError:  # pragma: no cover - fallback for stub RootModel

        class ToolCallResponse(RootModel):
            """Response payload wrapping arbitrary tool output."""

else:

    class ToolCallResponse(BaseModel):
        """Fallback response model for environments without RootModel."""

        __root__: Dict[str, Any]

        def __init__(self, __root__: Dict[str, Any], **data: Any) -> None:
            super().__init__(__root__=__root__, **data)

        def dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:  # type: ignore[override]
            return super().dict(*args, **kwargs)["__root__"]

        def model_dump(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:  # type: ignore[override]
            return self.dict(*args, **kwargs)
