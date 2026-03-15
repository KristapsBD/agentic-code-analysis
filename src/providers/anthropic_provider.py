"""
Anthropic LLM provider implementation.

Implements the BaseLLMProvider interface for Anthropic's API,
supporting Claude models with optional built-in web search.

Web search is enabled via the web_search_20260209 server-side tool.
Anthropic executes the search transparently; no client-side round-trips
or tool executors are required. The tool requires a supported model
(claude-sonnet-4-6, claude-opus-4-6, etc.) — see the Anthropic docs for
the full list.

Reference: https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-search-tool
"""

import logging
from typing import Optional

from anthropic import AsyncAnthropic

from src.providers.base_provider import BaseLLMProvider, LLMResponse, Message

logger = logging.getLogger(__name__)

# Anthropic server-tool descriptor for web search.
# Uses the latest version (web_search_20260209) which supports dynamic
# filtering on claude-sonnet-4-6 and claude-opus-4-6.
# The "name" field is required by the Anthropic API.
_WEB_SEARCH_TOOL = {"type": "web_search_20260209", "name": "web_search"}

# Anthropic's messages API requires max_tokens to be set explicitly.
# 8192 is the maximum output token limit for current Claude models.
_ANTHROPIC_MAX_TOKENS = 8192


class AnthropicProvider(BaseLLMProvider):
    """
    Anthropic LLM provider.

    Uses the Anthropic API to generate completions using Claude models.
    Pass web_search=True to complete() to enable real-time web grounding.
    The default model (claude-sonnet-4-6) supports web search; older models
    such as claude-3-5-sonnet-20241022 do not.
    """

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
        """
        Send messages to Anthropic and get a response.

        Args:
            messages: List of messages in the conversation.
            temperature: Optional override for sampling temperature.
            web_search: When True, enables Anthropic's built-in web search.
                        Claude will search the web when needed and incorporate
                        results into its response automatically.
            json_mode: When True (and web_search is False), sets output_config
                       with a permissive json_schema, enforcing valid JSON output
                       via constrained decoding. Requires a supported model
                       (claude-sonnet-4-6, claude-opus-4-6, claude-sonnet-4-5,
                       claude-opus-4-5, claude-haiku-4-5).
        """
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
        elif json_mode:
            # output_config is incompatible with tools (including web search)
            request_kwargs["output_config"] = {
                "format": {
                    "type": "json_schema",
                    "schema": {"type": "object", "additionalProperties": True},
                }
            }

        response = await self._with_retry(
            lambda: self.client.messages.create(**request_kwargs)
        )

        # Extract text from content blocks; ignore non-text blocks (e.g. web
        # search result blocks that Anthropic may include in the response)
        content = "".join(
            block.text
            for block in response.content
            if hasattr(block, "type") and block.type == "text"
        )

        # Log whether web search was actually invoked
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
