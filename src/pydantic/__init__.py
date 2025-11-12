"""Minimal subset of the Pydantic API used for tests."""
from __future__ import annotations

from typing import Any, Dict, Optional

__all__ = ["BaseModel", "Field", "RootModel"]


class _Missing:
    pass


MISSING = _Missing()


class FieldInfo:
    def __init__(self, default: Any = MISSING, default_factory: Optional[Any] = None) -> None:
        self.default = default
        self.default_factory = default_factory


def Field(*, default: Any = MISSING, default_factory: Optional[Any] = None) -> FieldInfo:
    """Return metadata describing a model field."""
    return FieldInfo(default=default, default_factory=default_factory)


class BaseModel:
    """Simplified BaseModel supporting basic validation."""

    __fields__: Dict[str, FieldInfo]

    def __init_subclass__(cls, **kwargs: Any) -> None:  # pragma: no cover - class construction
        super().__init_subclass__(**kwargs)
        annotations = getattr(cls, "__annotations__", {})
        fields: Dict[str, FieldInfo] = {}
        for name, _ in annotations.items():
            default = getattr(cls, name, MISSING)
            if isinstance(default, FieldInfo):
                field_info = default
                if field_info.default is not MISSING:
                    setattr(cls, name, field_info.default)
                elif hasattr(cls, name):
                    delattr(cls, name)
            else:
                field_info = FieldInfo(default=default)
            fields[name] = field_info
        cls.__fields__ = fields

    def __init__(self, **data: Any) -> None:
        extras: Dict[str, Any] = {}
        remaining = dict(data)
        for name, field in self.__class__.__fields__.items():
            if name in remaining:
                value = remaining.pop(name)
            else:
                if field.default is not MISSING:
                    value = field.default
                elif field.default_factory is not None:
                    value = field.default_factory()  # type: ignore[misc]
                else:
                    raise ValueError(f"Field '{name}' is required")
            setattr(self, name, value)
        extras.update(remaining)
        for key, value in extras.items():
            setattr(self, key, value)
        self.__dict__["__extras__"] = extras

    @classmethod
    def model_validate(cls, data: Any) -> "BaseModel":
        if isinstance(data, cls):
            return data
        if not isinstance(data, dict):
            raise TypeError("Model data must be provided as a mapping")
        return cls(**data)

    def model_dump(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        for name in self.__class__.__fields__:
            payload[name] = getattr(self, name)
        payload.update(getattr(self, "__extras__", {}))
        return payload

    def dict(self) -> Dict[str, Any]:
        return self.model_dump()

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        fields = ", ".join(f"{k}={v!r}" for k, v in self.model_dump().items())
        return f"{self.__class__.__name__}({fields})"


class RootModel:
    """A minimal root model that wraps arbitrary data."""

    def __init__(self, root: Any) -> None:
        self.root = root

    @classmethod
    def model_validate(cls, data: Any) -> "RootModel":
        if isinstance(data, cls):
            return data
        return cls(data)

    def model_dump(self) -> Any:
        return self.root

    def dict(self) -> Any:
        return self.root

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"{self.__class__.__name__}({self.root!r})"
