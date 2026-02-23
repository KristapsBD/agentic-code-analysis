"""
OpenAI LLM provider implementation.

Implements the BaseLLMProvider interface for OpenAI's API,
supporting GPT-4 and other OpenAI models.

Note: web_search=True is accepted but ignored — OpenAI does not expose
a native server-side search tool in the chat completions API.
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
        super().__init__(api_key, model, temperature, max_tokens)
        self.client = AsyncOpenAI(api_key=api_key)

    @property
    def provider_name(self) -> str:
        return "openai"

    async def complete(
        self,
        messages: list[Message],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        web_search: bool = False,
    ) -> LLMResponse:
        """
        Send messages to OpenAI and get a response.

        Args:
            messages: List of messages in the conversation.
            temperature: Optional override for sampling temperature.
            max_tokens: Optional override for max tokens.
            web_search: Accepted for interface compatibility but not implemented
                        for OpenAI — no native server-side search tool available.
        """
        self._validate_messages(messages)

        openai_messages = [msg.to_dict() for msg in messages]

        response = await self.client.chat.completions.create(
            model=self.model,
            messages=openai_messages,
            temperature=temperature if temperature is not None else self.temperature,
            max_tokens=max_tokens if max_tokens is not None else self.max_tokens,
        )

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
