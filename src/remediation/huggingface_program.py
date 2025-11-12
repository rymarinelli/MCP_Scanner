"""Patch suggestion program backed by a local Hugging Face model."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List

from mcp_scanner.dspy_programs import DSPyResponse
from mcp_scanner.models import VulnerabilityContext


def _format_section(title: str, content: str) -> str:
    return f"### {title}\n{content.strip()}" if content.strip() else f"### {title}\n<none>"


def _format_dict(data: dict, indent: int = 0) -> str:
    lines: List[str] = []
    prefix = " " * indent
    for key in sorted(data):
        value = data[key]
        if isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            lines.append(_format_dict(value, indent + 2))
        elif isinstance(value, list):
            lines.append(f"{prefix}{key}:")
            for item in value:
                if isinstance(item, dict):
                    lines.append(_format_dict(item, indent + 4))
                else:
                    lines.append(f"{prefix}  - {item}")
        else:
            lines.append(f"{prefix}{key}: {value}")
    return "\n".join(lines)


def _parse_json_output(text: str) -> List[dict]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []

    items = payload.get("patches") if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        return []

    results: List[dict] = []
    for item in items:
        if isinstance(item, dict):
            results.append(item)
    return results


@dataclass
class _PromptBundle:
    instructions: str
    metadata: str
    graph_context: str
    snippets: str

    def to_prompt(self) -> str:
        sections = [
            _format_section("Task", self.instructions),
            _format_section("Vulnerability Metadata", self.metadata),
            _format_section("Graph Context", self.graph_context),
        ]
        if self.snippets:
            sections.append(_format_section("Relevant Code", self.snippets))
        sections.append(
            "Respond with valid JSON containing a 'patches' array. Each patch must include "
            "'file_path', 'diff', 'rationale', and optional 'confidence'."
        )
        return "\n\n".join(sections)


class HuggingFacePatchSuggestionProgram:
    """Generate remediation patches using a local Hugging Face causal LM."""

    def __init__(
        self,
        *,
        model_name: str = "01-ai/Yi-Coder-9B-Chat",
        instructions: str | None = None,
        client=None,
    ) -> None:
        self.model_name = model_name
        self.instructions = instructions or (
            "You are a meticulous application security engineer. Propose minimal, high-quality patches "
            "that remediate the vulnerability while preserving functionality."
        )
        if client is not None:
            self.client = client
        else:
            from llm.huggingface import HuggingFaceCausalLMClient

            self.client = HuggingFaceCausalLMClient(model_name=model_name)

    def _build_prompt(self, context: VulnerabilityContext) -> _PromptBundle:
        metadata_text = _format_dict(context.metadata)
        graph_text = _format_dict(context.graph_context)
        snippets = "\n\n".join(context.code_snippets or [])
        return _PromptBundle(
            instructions=self.instructions,
            metadata=metadata_text or "{}",
            graph_context=graph_text or "{}",
            snippets=snippets,
        )

    def forward(self, context: VulnerabilityContext) -> DSPyResponse:
        prompt_bundle = self._build_prompt(context)
        prompt = prompt_bundle.to_prompt()
        response_text = self.client.complete(prompt)
        patches = _parse_json_output(response_text)
        return DSPyResponse(patches=patches, raw_output=response_text)


__all__ = ["HuggingFacePatchSuggestionProgram"]
