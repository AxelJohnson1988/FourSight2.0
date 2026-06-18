"""LLM Adapter — abstract interface + stub for testing (§3.1).

The VL-LLM layer treats the LLM as an untrusted stochastic text generator.
This module defines the minimal interface the pipeline requires, keeping
the rest of the layer completely independent of any specific LLM provider.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class LLMResponse:
    """Raw, untrusted output from the LLM (Step A — §4).

    Attributes
    ----------
    text:
        The generated text.  Always treated as DRAFT until Claims are
        extracted and evaluated by the PCG.
    raw:
        Provider-specific response object (tokens, logprobs, etc.).
        ``None`` for stub implementations.
    """

    text: str
    raw: Optional[Any] = None


@dataclass(frozen=True)
class LLMInput:
    """Input envelope passed to :meth:`LLMAdapter.generate`."""

    prompt: str
    context: Optional[str] = None
    output_schema: Optional[Dict[str, Any]] = None


class LLMAdapter(ABC):
    """Abstract base class for LLM providers (§3.1).

    Implementors wrap a specific provider (Claude, GPT-4, Gemini, …).
    The pipeline only calls :meth:`generate`; all other LLM capabilities
    are irrelevant at this layer.

    The contract is deliberately minimal:
    - Input: prompt + optional context + optional output schema hint.
    - Output: :class:`LLMResponse` with ``text`` and optional raw data.
    - The adapter MUST NOT perform any claim extraction or validation —
      that is the pipeline's responsibility.
    """

    @abstractmethod
    def generate(self, input_: LLMInput) -> LLMResponse:
        """Generate text for *input_*.  Returns untrusted draft text."""
        ...


class StubLLMAdapter(LLMAdapter):
    """Deterministic stub for unit testing.

    Returns a pre-configured sequence of responses in order, then repeats
    the last one.  Useful for testing the pipeline without real API calls.

    Parameters
    ----------
    responses:
        List of text strings to return in sequence.

    Examples
    --------
    >>> adapter = StubLLMAdapter(["The patient arrived at 9am.", "She was discharged at 5pm."])
    >>> adapter.generate(LLMInput(prompt="summarise")).text
    'The patient arrived at 9am.'
    >>> adapter.generate(LLMInput(prompt="summarise")).text
    'She was discharged at 5pm.'
    >>> adapter.generate(LLMInput(prompt="summarise")).text  # repeats last
    'She was discharged at 5pm.'
    """

    def __init__(self, responses: List[str]) -> None:
        if not responses:
            raise ValueError("StubLLMAdapter requires at least one response.")
        self._responses = responses
        self._index = 0

    def generate(self, input_: LLMInput) -> LLMResponse:  # noqa: ARG002
        text = self._responses[self._index]
        self._index = min(self._index + 1, len(self._responses) - 1)
        return LLMResponse(text=text)

    def reset(self) -> None:
        """Reset the response pointer to the beginning."""
        self._index = 0
