"""HTTP interface for the MCP Vanguard tool runner."""
from __future__ import annotations

import inspect
from typing import Any, Dict

from fastapi import FastAPI

from . import core
from . import tools as _tools  # noqa: F401  # Ensure tools register on import
from .schemas import ToolCallRequest, ToolCallResponse

app = FastAPI()


def _coerce_response(result: Dict[str, Any]) -> ToolCallResponse:
    """Convert a raw tool result into a response model."""
    if hasattr(ToolCallResponse, "model_validate"):
        return ToolCallResponse.model_validate(result)  # type: ignore[attr-defined]
    return ToolCallResponse(result)


@app.post("/call_tool", response_model=ToolCallResponse)
async def call_tool(payload: ToolCallRequest) -> ToolCallResponse:
    """Invoke a registered tool via the core runner."""
    result: Any = core.run_tool(payload.tool, payload.arguments)
    if inspect.isawaitable(result):
        result = await result
    return _coerce_response(result)
