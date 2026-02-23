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

from typing import Optional

from anthropic import AsyncAnthropic

from src.providers.base_provider import BaseLLMProvider, LLMResponse, Message

# Anthropic server-tool descriptor for web search.
# Uses the latest version (web_search_20260209) which supports dynamic
# filtering on claude-sonnet-4-6 and claude-opus-4-6.
# The "name" field is required by the Anthropic API.
_WEB_SEARCH_TOOL = {"type": "web_search_20260209", "name": "web_search"}


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
        max_tokens: int = 4096,
    ):
        super().__init__(api_key, model, temperature, max_tokens)
        self.client = AsyncAnthropic(api_key=api_key)

    @property
    def provider_name(self) -> str:
        return "anthropic"

    async def complete(
        self,
        messages: list[Message],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        web_search: bool = False,
    ) -> LLMResponse:
        """
        Send messages to Anthropic and get a response.

        Args:
            messages: List of messages in the conversation.
            temperature: Optional override for sampling temperature.
            max_tokens: Optional override for max tokens.
            web_search: When True, enables Anthropic's built-in web search.
                        Claude will search the web when needed and incorporate
                        results into its response automatically.
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
            "max_tokens": max_tokens if max_tokens is not None else self.max_tokens,
        }
        if system_prompt:
            request_kwargs["system"] = system_prompt
        if web_search:
            request_kwargs["tools"] = [_WEB_SEARCH_TOOL]

        response = await self.client.messages.create(**request_kwargs)

        # Extract text from content blocks; ignore non-text blocks (e.g. web
        # search result blocks that Anthropic may include in the response)
        content = "".join(
            block.text
            for block in response.content
            if hasattr(block, "type") and block.type == "text"
        )

        return LLMResponse(
            content=content,
            model=response.model,
            tokens_used=response.usage.input_tokens + response.usage.output_tokens,
            prompt_tokens=response.usage.input_tokens,
            completion_tokens=response.usage.output_tokens,
            finish_reason=response.stop_reason or "stop",
            raw_response=response.model_dump(),
        )
