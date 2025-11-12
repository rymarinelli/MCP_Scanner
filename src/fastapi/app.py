"""Simplified FastAPI application core used in tests."""
from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

RouteHandler = Callable[..., Any]


@dataclass
class Route:
    handler: RouteHandler
    response_model: Optional[type]


class FastAPI:
    """Minimal FastAPI-compatible interface for unit tests."""

    def __init__(self) -> None:
        self._routes: Dict[Tuple[str, str], Route] = {}

    def post(self, path: str, *, response_model: Optional[type] = None) -> Callable[[RouteHandler], RouteHandler]:
        """Register a POST route."""

        def decorator(func: RouteHandler) -> RouteHandler:
            self._routes[("POST", path)] = Route(func, response_model)
            return func

        return decorator

    def resolve(self, method: str, path: str) -> Route:
        try:
            return self._routes[(method, path)]
        except KeyError as exc:  # pragma: no cover - defensive guard
            raise ValueError(f"Route {method} {path} not found") from exc


async def _ensure_awaitable(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _evaluate_annotation(handler: RouteHandler, annotation: Any) -> Any:
    if isinstance(annotation, str):
        annotation = eval(annotation, handler.__globals__)  # noqa: S307 - trusted scope
    return annotation


def _build_payload(handler: RouteHandler, data: Dict[str, Any]) -> Dict[str, Any]:
    signature = inspect.signature(handler)
    params = list(signature.parameters.values())
    if not params:
        return {}
    param = params[0]
    annotation = _evaluate_annotation(handler, param.annotation)
    if annotation is inspect._empty:
        payload = data
    elif hasattr(annotation, "model_validate"):
        payload = annotation.model_validate(data)
    else:
        payload = data
    return {param.name: payload}


def _render_response(handler: RouteHandler, response_model: Optional[type], result: Any) -> Any:
    if response_model is not None:
        response_model = _evaluate_annotation(handler, response_model)
        if hasattr(response_model, "model_validate"):
            result = response_model.model_validate(result)
    if hasattr(result, "model_dump"):
        return result.model_dump()
    if hasattr(result, "dict"):
        return result.dict()
    return result


class Response:
    """Simplified HTTP response used by the TestClient."""

    def __init__(self, status_code: int, json_body: Any) -> None:
        self.status_code = status_code
        self._json = json_body

    def json(self) -> Any:
        return self._json
