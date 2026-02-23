"""
Google Gemini LLM provider implementation.

Implements the BaseLLMProvider interface for Google's Gemini API.
Uses the official google-genai SDK (v1.0.0+) with proper Content/Part
objects for correct multi-turn conversation handling.

Web search is enabled via Google Search grounding — pass web_search=True
to complete(). Gemini executes the search transparently server-side;
no client-side round-trips or result handling are required.

Reference: https://ai.google.dev/gemini-api/docs/google-search
"""

import asyncio
import logging
from typing import Any, Optional

from google import genai
from google.genai import types

from src.providers.base_provider import BaseLLMProvider, LLMResponse, Message

logger = logging.getLogger(__name__)


class GeminiProvider(BaseLLMProvider):
    """
    Google Gemini LLM provider.

    Uses proper Content/Part objects for all messages, enabling correct
    multi-turn conversation history. Pass web_search=True to complete()
    to enable Google Search grounding.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-2.5-flash",
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ):
        super().__init__(api_key, model, temperature, max_tokens)
        logger.debug(f"Initializing GeminiProvider with model={model}")
        self.client = genai.Client(api_key=api_key)
        logger.debug("Gemini client created successfully")

    @property
    def provider_name(self) -> str:
        return "gemini"

    async def complete(
        self,
        messages: list[Message],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        web_search: bool = False,
    ) -> LLMResponse:
        """
        Send messages to Gemini and get a response.

        Args:
            messages: List of messages in the conversation.
            temperature: Optional override for sampling temperature.
            max_tokens: Optional override for max tokens.
            web_search: When True, enables Google Search grounding. Gemini
                        will search the web when needed and incorporate results
                        into its response automatically.
        """
        self._validate_messages(messages)

        system_instruction, contents = self._build_contents(messages)

        config_kwargs: dict[str, Any] = {
            "temperature": temperature if temperature is not None else self.temperature,
            "max_output_tokens": max_tokens if max_tokens is not None else self.max_tokens,
        }
        if system_instruction:
            config_kwargs["system_instruction"] = system_instruction
        if web_search:
            config_kwargs["tools"] = [types.Tool(google_search=types.GoogleSearch())]

        config = types.GenerateContentConfig(**config_kwargs)

        logger.debug(
            f"Sending request to Gemini (model={self.model}, "
            f"turns={len(contents)}, web_search={web_search})"
        )

        response = await self._call_api(contents, config)

        content = self._extract_text(response)

        prompt_tokens = 0
        completion_tokens = 0
        total_tokens = 0
        if hasattr(response, "usage_metadata") and response.usage_metadata:
            usage = response.usage_metadata
            prompt_tokens = getattr(usage, "prompt_token_count", 0) or 0
            completion_tokens = getattr(usage, "candidates_token_count", 0) or 0
            total_tokens = getattr(usage, "total_token_count", 0) or 0

        logger.debug(
            f"Gemini response: {len(content)} chars, {total_tokens} tokens"
        )

        return LLMResponse(
            content=content,
            model=self.model,
            tokens_used=total_tokens,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            finish_reason="stop",
            raw_response=None,  # proto objects are not JSON-serialisable
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _call_api(
        self,
        contents: list[types.Content],
        config: types.GenerateContentConfig,
    ) -> Any:
        """Attempt async API call; fall back to sync-in-executor."""
        try:
            return await self.client.aio.models.generate_content(
                model=self.model,
                contents=contents,
                config=config,
            )
        except Exception as exc:
            logger.debug(f"Async Gemini call failed ({exc}), retrying with executor")
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None,
                lambda: self.client.models.generate_content(
                    model=self.model,
                    contents=contents,
                    config=config,
                ),
            )

    @staticmethod
    def _build_contents(
        messages: list[Message],
    ) -> tuple[Optional[str], list[types.Content]]:
        """
        Convert Message list to Gemini Content objects.

        Gemini requires:
        - system prompt as system_instruction (not a Content entry)
        - user messages  → Content(role="user",  parts=[Part.from_text(...)])
        - assistant msgs → Content(role="model", parts=[Part.from_text(...)])
        """
        system_instruction: Optional[str] = None
        contents: list[types.Content] = []

        for msg in messages:
            if msg.role == "system":
                system_instruction = msg.content
            elif msg.role == "user":
                contents.append(types.Content(
                    role="user",
                    parts=[types.Part.from_text(text=msg.content)],
                ))
            elif msg.role == "assistant":
                contents.append(types.Content(
                    role="model",
                    parts=[types.Part.from_text(text=msg.content)],
                ))

        return system_instruction, contents

    @staticmethod
    def _extract_text(response: Any) -> str:
        """Extract plain text from a Gemini GenerateContentResponse."""
        if not response.candidates:
            return ""
        return "".join(
            part.text
            for part in response.candidates[0].content.parts
            if hasattr(part, "text") and part.text
        )
