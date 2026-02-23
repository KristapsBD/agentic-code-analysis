"""
Abstract base class for LLM providers.

Defines the interface that all LLM providers must implement,
ensuring consistent behavior across different providers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


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
        max_tokens: int = 4096,
    ):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

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
        max_tokens: Optional[int] = None,
        web_search: bool = False,
    ) -> LLMResponse:
        """
        Send messages to the LLM and get a response.

        Args:
            messages: List of messages in the conversation.
            temperature: Optional override for sampling temperature.
            max_tokens: Optional override for max tokens.
            web_search: When True, enable the provider's built-in web search.
                        Anthropic uses web_search_20250305; Gemini uses Google
                        Search grounding. Both are executed server-side with no
                        client-side round-trips required.

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
    ) -> str:
        """Simple single-turn completion."""
        messages = []
        if system_prompt:
            messages.append(Message(role="system", content=system_prompt))
        messages.append(Message(role="user", content=prompt))
        response = await self.complete(messages, temperature=temperature, web_search=web_search)
        return response.content

    def _validate_messages(self, messages: list[Message]) -> None:
        """Validate that messages are properly formatted."""
        if not messages:
            raise ValueError("Messages list cannot be empty")

        valid_roles = {"system", "user", "assistant"}
        for msg in messages:
            if msg.role not in valid_roles:
                raise ValueError(f"Invalid message role: {msg.role}")
