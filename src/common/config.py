"""Application configuration management using Pydantic settings."""
from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class GraphSettings(BaseModel):
    """Settings related to graph storage and traversal."""

    provider: str = Field(
        default="neo4j",
        description="Graph database provider identifier.",
    )
    uri: str = Field(
        default="bolt://localhost:7687",
        description="Connection URI for the graph provider.",
    )
    username: str = Field(
        default="neo4j",
        description="Graph database username used for authentication.",
    )
    password: Optional[str] = Field(
        default=None,
        description="Graph database password. Can be provided via environment variable.",
    )


class LLMSettings(BaseModel):
    """Large language model configuration."""

    provider: str = Field(
        default="openai",
        description="Model provider identifier.",
    )
    model: str = Field(
        default="gpt-4",
        description="Model family or variant to use for inference.",
    )
    api_key: Optional[str] = Field(
        default=None,
        description="API key used to authenticate with the model provider.",
    )


class ScannerSettings(BaseModel):
    """Settings shared across scanning implementations."""

    concurrency: int = Field(
        default=4,
        ge=1,
        description="Number of scanner tasks to execute concurrently.",
    )
    include_paths: list[str] = Field(
        default_factory=list,
        description="Optional whitelist of repository paths to scan.",
    )
    exclude_paths: list[str] = Field(
        default_factory=list,
        description="Optional blacklist of repository paths to skip.",
    )

    @field_validator("include_paths", "exclude_paths", mode="before")
    @classmethod
    def _split_comma_separated(cls, value: object) -> object:
        """Allow simple comma-separated configuration values."""

        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


class AppSettings(BaseSettings):
    """Top-level application settings container."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="MCP_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    graph: GraphSettings = Field(default_factory=GraphSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    scanners: ScannerSettings = Field(default_factory=ScannerSettings)


@lru_cache
def get_settings() -> AppSettings:
    """Return the cached application settings instance."""

    return AppSettings()


def reset_settings_cache() -> None:
    """Clear the cached settings so future calls reflect new environment values."""

    get_settings.cache_clear()


__all__ = [
    "GraphSettings",
    "LLMSettings",
    "ScannerSettings",
    "AppSettings",
    "get_settings",
    "reset_settings_cache",
]
