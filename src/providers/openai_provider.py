"""
OpenAI LLM provider implementation.

Implements the BaseLLMProvider interface for OpenAI's API,
supporting GPT-4 and other OpenAI models.
"""

from typing import Optional

from openai import AsyncOpenAI

from src.providers.base_provider import BaseLLMProvider, LLMResponse, Message


class OpenAIProvider(BaseLLMProvider):
    """
    OpenAI LLM provider.

    Uses the OpenAI API to generate completions using models
    like GPT-4o, GPT-4-turbo, etc.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ):
        """
        Initialize the OpenAI provider.

        Args:
            api_key: OpenAI API key
            model: Model to use (default: gpt-4o)
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response
        """
        super().__init__(api_key, model, temperature, max_tokens)
        self.client = AsyncOpenAI(api_key=api_key)

    @property
    def provider_name(self) -> str:
        """Return the provider name."""
        return "openai"

    async def complete(
        self,
        messages: list[Message],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """
        Send messages to OpenAI and get a response.

        Args:
            messages: List of messages in the conversation
            temperature: Optional override for sampling temperature
            max_tokens: Optional override for max tokens

        Returns:
            LLMResponse containing the model's response
        """
        self._validate_messages(messages)

        # Convert messages to OpenAI format
        openai_messages = [msg.to_dict() for msg in messages]

        # Make the API call
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=openai_messages,
            temperature=temperature if temperature is not None else self.temperature,
            max_tokens=max_tokens if max_tokens is not None else self.max_tokens,
        )

        # Extract response data
        choice = response.choices[0]
        usage = response.usage

        return LLMResponse(
            content=choice.message.content or "",
            model=response.model,
            tokens_used=usage.total_tokens if usage else 0,
            prompt_tokens=usage.prompt_tokens if usage else 0,
            completion_tokens=usage.completion_tokens if usage else 0,
            finish_reason=choice.finish_reason or "stop",
            raw_response=response.model_dump(),
        )
