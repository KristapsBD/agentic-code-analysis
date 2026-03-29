"""
Abstract base class for LLM providers.

Defines the interface that all LLM providers must implement,
ensuring consistent behavior across different providers.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Response from an LLM provider."""

    content: str
    model: str
    tokens_used: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    finish_reason: str = "stop"
    raw_response: Optional[dict] = field(default=None, repr=False)

    @property
    def total_tokens(self) -> int:
        """Total tokens used in the request."""
        return self.prompt_tokens + self.completion_tokens


@dataclass
class Message:
    """A message in a conversation."""

    role: str  # "system", "user", or "assistant"
    content: str

    def to_dict(self) -> dict:
        """Convert to dictionary format for API calls."""
        return {"role": self.role, "content": self.content}


class BaseLLMProvider(ABC):
    """
    Abstract base class for LLM providers.

    All LLM provider implementations must inherit from this class
    and implement the required abstract methods.
    """

    def __init__(
        self,
        api_key: str,
        model: str,
        temperature: float = 0.7,
    ):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the name of the provider."""
        pass

    @abstractmethod
    async def complete(
        self,
        messages: list[Message],
        temperature: Optional[float] = None,
        web_search: bool = False,
        json_mode: bool = False,
    ) -> LLMResponse:
        """
        Send messages to the LLM and get a response.

        Args:
            messages: List of messages in the conversation.
            temperature: Optional override for sampling temperature.
            web_search: When True, enable the provider's built-in web search.
                        Anthropic uses web_search_20260209; Gemini uses Google
                        Search grounding. Both are executed server-side with no
                        client-side round-trips required.
            json_mode: When True, instruct the provider to return valid JSON.
                       For Gemini this sets response_mime_type="application/json"
                       (enforced at the API level, not via prompt). Ignored when
                       web_search=True because search grounding is incompatible
                       with structured output on Gemini.

        Returns:
            LLMResponse containing the model's response.
        """
        pass

    async def complete_simple(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        web_search: bool = False,
        json_mode: bool = False,
    ) -> str:
        """Simple single-turn completion."""
        messages = []
        if system_prompt:
            messages.append(Message(role="system", content=system_prompt))
        messages.append(Message(role="user", content=prompt))
        response = await self.complete(
            messages, temperature=temperature, web_search=web_search, json_mode=json_mode
        )
        return response.content

    @staticmethod
    def _is_rate_limit_error(exc: Exception) -> bool:
        """Detect 429 / quota-exceeded errors across all SDK types."""
        msg = str(exc).lower()
        return (
            "429" in str(exc)
            or "resource exhausted" in msg
            or "rate limit" in msg
            or "too many requests" in msg
            or "quota exceeded" in msg
            or "ratelimit" in msg
        )

    async def _with_retry(
        self,
        call_fn: Callable[[], Coroutine[Any, Any, Any]],
        max_retries: int = 3,
        base_delay: float = 30.0,
        max_delay: float = 120.0,
    ) -> Any:
        """
        Execute an async API call with exponential backoff on rate-limit errors.

        Delays: 30s → 60s → 120s (capped at max_delay).
        Non-rate-limit errors are re-raised immediately without retry.
        """
        for attempt in range(max_retries):
            try:
                return await call_fn()
            except Exception as exc:
                if self._is_rate_limit_error(exc) and attempt < max_retries - 1:
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    logger.warning(
                        f"Rate limit hit (attempt {attempt + 1}/{max_retries}), "
                        f"retrying in {delay:.0f}s — {exc}"
                    )
                    await asyncio.sleep(delay)
                else:
                    raise

    def _validate_messages(self, messages: list[Message]) -> None:
        """Validate that messages are properly formatted."""
        if not messages:
            raise ValueError("Messages list cannot be empty")

        valid_roles = {"system", "user", "assistant"}
        for msg in messages:
            if msg.role not in valid_roles:
                raise ValueError(f"Invalid message role: {msg.role}")
