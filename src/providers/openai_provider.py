"""
OpenAI LLM provider implementation.

Implements the BaseLLMProvider interface for OpenAI's API,
supporting GPT-4 and other OpenAI models.

Web search is enabled via the web_search_options parameter, which requires
a search-capable model (gpt-4o-search-preview, gpt-4o-mini-search-preview).
When web_search=True is requested with a non-search model the provider
automatically uses gpt-4o-search-preview instead.

Reference: https://developers.openai.com/api/docs/guides/tools-web-search/
"""

import logging
from typing import Optional

from openai import AsyncOpenAI

from src.providers.base_provider import BaseLLMProvider, LLMResponse, Message

logger = logging.getLogger(__name__)

# Models that support web_search_options in the Chat Completions API
_SEARCH_MODELS = {"gpt-4o-search-preview", "gpt-4o-mini-search-preview", "gpt-5-search-api"}
_DEFAULT_SEARCH_MODEL = "gpt-4o-search-preview"


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
    ):
        super().__init__(api_key, model, temperature)
        self.client = AsyncOpenAI(api_key=api_key)

    @property
    def provider_name(self) -> str:
        return "openai"

    async def complete(
        self,
        messages: list[Message],
        temperature: Optional[float] = None,
        web_search: bool = False,
        json_mode: bool = False,
    ) -> LLMResponse:
        """
        Send messages to OpenAI and get a response.

        Args:
            messages: List of messages in the conversation.
            temperature: Optional override for sampling temperature.
            web_search: When True, adds web_search_options to the request so the
                        model can search the web before answering. Requires a
                        search-capable model; if the configured model is not one,
                        gpt-4o-search-preview is used automatically.
                        Incompatible with json_mode — json_mode is ignored when
                        web_search is True.
            json_mode: When True, sets response_format={"type": "json_object"},
                       instructing the model to return valid JSON. Requires the
                       prompt to ask for JSON output as well. Ignored when
                       web_search=True.
        """
        self._validate_messages(messages)

        openai_messages = [msg.to_dict() for msg in messages]

        # Determine the model to use
        model = self.model
        if web_search and model not in _SEARCH_MODELS:
            logger.info(
                f"[OpenAI] web_search=True — switching from {model!r} to "
                f"{_DEFAULT_SEARCH_MODEL!r} (search-capable model required)"
            )
            model = _DEFAULT_SEARCH_MODEL

        create_kwargs: dict = {
            "model": model,
            "messages": openai_messages,
            "temperature": temperature if temperature is not None else self.temperature,
        }
        if web_search:
            create_kwargs["web_search_options"] = {}
        elif json_mode:
            # json_mode is incompatible with web_search_options
            create_kwargs["response_format"] = {"type": "json_object"}

        response = await self.client.chat.completions.create(**create_kwargs)

        choice = response.choices[0]
        usage = response.usage

        # Log whether web search was actually used (citations appear in annotations)
        if web_search:
            annotations = getattr(choice.message, "annotations", None) or []
            citations = [a for a in annotations if getattr(a, "type", None) == "url_citation"]
            if citations:
                logger.info(
                    f"[OpenAI] Web search used: {len(citations)} source(s) cited"
                )
                for c in citations:
                    url_obj = getattr(c, "url_citation", None)
                    if url_obj:
                        logger.debug(
                            f"[OpenAI] Source: {getattr(url_obj, 'title', '?')!r} "
                            f"— {getattr(url_obj, 'url', '?')}"
                        )
            else:
                logger.debug("[OpenAI] Web search enabled but no citations in response")

        return LLMResponse(
            content=choice.message.content or "",
            model=response.model,
            tokens_used=usage.total_tokens if usage else 0,
            prompt_tokens=usage.prompt_tokens if usage else 0,
            completion_tokens=usage.completion_tokens if usage else 0,
            finish_reason=choice.finish_reason or "stop",
            raw_response=response.model_dump(),
        )
