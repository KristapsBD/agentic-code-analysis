"""
Anthropic LLM provider implementation.

Implements the BaseLLMProvider interface for Anthropic's API,
supporting Claude models.
"""

from typing import Optional

from anthropic import AsyncAnthropic

from src.providers.base_provider import BaseLLMProvider, LLMResponse, Message


class AnthropicProvider(BaseLLMProvider):
    """
    Anthropic LLM provider.

    Uses the Anthropic API to generate completions using Claude models.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-3-5-sonnet-20241022",
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ):
        """
        Initialize the Anthropic provider.

        Args:
            api_key: Anthropic API key
            model: Model to use (default: claude-3-5-sonnet-20241022)
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response
        """
        super().__init__(api_key, model, temperature, max_tokens)
        self.client = AsyncAnthropic(api_key=api_key)

    @property
    def provider_name(self) -> str:
        """Return the provider name."""
        return "anthropic"

    async def complete(
        self,
        messages: list[Message],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """
        Send messages to Anthropic and get a response.

        Args:
            messages: List of messages in the conversation
            temperature: Optional override for sampling temperature
            max_tokens: Optional override for max tokens

        Returns:
            LLMResponse containing the model's response
        """
        self._validate_messages(messages)

        # Anthropic requires system prompt to be separate
        system_prompt = None
        anthropic_messages = []

        for msg in messages:
            if msg.role == "system":
                system_prompt = msg.content
            else:
                anthropic_messages.append(msg.to_dict())

        # Build the request
        request_kwargs = {
            "model": self.model,
            "messages": anthropic_messages,
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": max_tokens if max_tokens is not None else self.max_tokens,
        }

        if system_prompt:
            request_kwargs["system"] = system_prompt

        # Make the API call
        response = await self.client.messages.create(**request_kwargs)

        # Extract response data
        content = ""
        if response.content:
            content = response.content[0].text

        return LLMResponse(
            content=content,
            model=response.model,
            tokens_used=response.usage.input_tokens + response.usage.output_tokens,
            prompt_tokens=response.usage.input_tokens,
            completion_tokens=response.usage.output_tokens,
            finish_reason=response.stop_reason or "stop",
            raw_response=response.model_dump(),
        )
