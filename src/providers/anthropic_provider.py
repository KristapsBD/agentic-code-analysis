"""Anthropic LLM provider using web_search_20260209 for server-side web search."""

import logging
from typing import Optional

from anthropic import AsyncAnthropic

from src.providers.base_provider import BaseLLMProvider, LLMResponse, Message

logger = logging.getLogger(__name__)

# "name" field is required; type string pins the tool version.
_WEB_SEARCH_TOOL = {"type": "web_search_20260209", "name": "web_search"}

# max_tokens is required by the Anthropic API; 8192 gives headroom without triggering streaming.
_ANTHROPIC_MAX_TOKENS = 8192


class AnthropicProvider(BaseLLMProvider):
    """Anthropic provider; only claude-sonnet-4-6+ supports web_search=True."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-6",
        temperature: float = 0.7,
    ):
        super().__init__(api_key, model, temperature)
        self.client = AsyncAnthropic(api_key=api_key)

    @property
    def provider_name(self) -> str:
        return "anthropic"

    async def complete(
        self,
        messages: list[Message],
        temperature: Optional[float] = None,
        web_search: bool = False,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Send messages to Anthropic; json_mode is a no-op (JSON enforced via prompt)."""
        self._validate_messages(messages)

        system_prompt = None
        anthropic_messages = []
        for msg in messages:
            if msg.role == "system":
                system_prompt = msg.content
            else:
                anthropic_messages.append(msg.to_dict())

        request_kwargs = {
            "model": self.model,
            "messages": anthropic_messages,
            "temperature": temperature if temperature is not None else self.temperature,
            # max_tokens is required by the Anthropic API
            "max_tokens": _ANTHROPIC_MAX_TOKENS,
        }
        if system_prompt:
            request_kwargs["system"] = system_prompt
        if web_search:
            request_kwargs["tools"] = [_WEB_SEARCH_TOOL]

        response = await self._with_retry(
            lambda: self.client.messages.create(**request_kwargs)
        )

        # Ignore non-text blocks (e.g. web search result blocks)
        content = "".join(
            block.text
            for block in response.content
            if hasattr(block, "type") and block.type == "text"
        )

        if web_search:
            tool_blocks = [
                b for b in response.content
                if hasattr(b, "type") and b.type != "text"
            ]
            if tool_blocks:
                block_types = [getattr(b, "type", "?") for b in tool_blocks]
                logger.info(
                    f"[Anthropic] Web search used: {len(tool_blocks)} tool block(s) — "
                    f"{block_types}"
                )
            else:
                logger.debug("[Anthropic] Web search enabled but model did not use the tool")

        return LLMResponse(
            content=content,
            model=response.model,
            tokens_used=response.usage.input_tokens + response.usage.output_tokens,
            prompt_tokens=response.usage.input_tokens,
            completion_tokens=response.usage.output_tokens,
            finish_reason=response.stop_reason or "stop",
            raw_response=response.model_dump(),
        )
