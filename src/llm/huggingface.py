"""Hugging Face-backed LLM client for local inference."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Sequence

import torch

from .base import LLMClient

try:  # pragma: no cover - optional dependency guard
    from transformers import AutoModelForCausalLM, AutoTokenizer, GenerationConfig
except ImportError as exc:  # pragma: no cover - surfaced at runtime when missing
    raise RuntimeError(
        "transformers must be installed to use the HuggingFaceCausalLMClient"
    ) from exc


@dataclass
class GenerationSettings:
    """Configuration controlling text generation behaviour."""

    max_new_tokens: int = 512
    temperature: float = 0.2
    top_p: float = 0.95
    repetition_penalty: float = 1.05


class HuggingFaceCausalLMClient(LLMClient):
    """LLM client that performs inference using Hugging Face Transformers."""

    def __init__(
        self,
        *,
        model_name: str = "ise-uiuc/Magicoder-S-DS-6.7B",
        device: str = "cpu",
        generation: GenerationSettings | None = None,
        tokenizer_kwargs: Dict[str, Any] | None = None,
        model_kwargs: Dict[str, Any] | None = None,
        model: Any | None = None,
        tokenizer: Any | None = None,
    ) -> None:
        self.model_name = model_name
        self.device = torch.device(device)
        self.generation = generation or GenerationSettings()
        self._tokenizer = tokenizer
        self._model = model
        self._tokenizer_kwargs = tokenizer_kwargs or {"trust_remote_code": True}
        default_model_kwargs: Dict[str, Any] = {
            "trust_remote_code": True,
            "torch_dtype": torch.float32,
        }
        if model_kwargs:
            default_model_kwargs.update(model_kwargs)
        self._model_kwargs = default_model_kwargs

        if self._tokenizer is None:
            self._tokenizer = AutoTokenizer.from_pretrained(
                self.model_name, **self._tokenizer_kwargs
            )
        if self._model is None:
            self._model = AutoModelForCausalLM.from_pretrained(
                self.model_name, **self._model_kwargs
            )
        self._model.to(self.device)
        self._model.eval()

    @property
    def tokenizer(self):  # type: ignore[override]
        return self._tokenizer

    @property
    def model(self):  # type: ignore[override]
        return self._model

    def _build_prompt(self, prompt: str, context: Sequence[str] | None) -> str:
        if not context:
            return prompt
        context_text = "\n\n".join(context)
        return f"{context_text}\n\n{prompt}"

    def complete(self, prompt: str, *, context: Sequence[str] | None = None) -> str:
        generation_prompt = self._build_prompt(prompt, context)
        inputs = self.tokenizer(
            generation_prompt,
            return_tensors="pt",
            add_special_tokens=True,
        )
        input_ids = inputs["input_ids"].to(self.device)
        attention_mask = inputs.get("attention_mask")
        if attention_mask is not None:
            attention_mask = attention_mask.to(self.device)

        generation_config = GenerationConfig(
            max_new_tokens=self.generation.max_new_tokens,
            temperature=self.generation.temperature,
            top_p=self.generation.top_p,
            repetition_penalty=self.generation.repetition_penalty,
            pad_token_id=self.tokenizer.eos_token_id,
        )

        with torch.no_grad():
            output_ids = self.model.generate(
                input_ids=input_ids,
                attention_mask=attention_mask,
                generation_config=generation_config,
            )

        generated_ids = output_ids[0, input_ids.shape[-1] :]
        text = self.tokenizer.decode(generated_ids, skip_special_tokens=True)
        return text.strip()

    def embed(self, text: str) -> Sequence[float]:
        raise NotImplementedError("Embedding generation is not implemented for HuggingFaceCausalLMClient")


__all__ = [
    "GenerationSettings",
    "HuggingFaceCausalLMClient",
]
