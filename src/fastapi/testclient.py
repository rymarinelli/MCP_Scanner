"""Simplified TestClient compatible with the minimal FastAPI app."""
from __future__ import annotations

import asyncio
from typing import Dict

from .app import FastAPI, Response, _build_payload, _ensure_awaitable, _render_response


class TestClient:
    """Minimal test client for invoking FastAPI handlers directly."""

    __test__ = False

    def __init__(self, app: FastAPI) -> None:
        self.app = app

    def post(self, path: str, json: Dict[str, object]) -> Response:
        route = self.app.resolve("POST", path)
        payload_kwargs = _build_payload(route.handler, json)
        result = route.handler(**payload_kwargs)
        result = asyncio.run(_ensure_awaitable(result))
        response_body = _render_response(route.handler, route.response_model, result)
        return Response(200, response_body)
