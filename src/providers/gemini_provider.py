"""Google Gemini LLM provider using the google-genai SDK with Google Search grounding support."""

import asyncio
import logging
from typing import Any, Optional

from google import genai
from google.genai import types

from src.providers.base_provider import BaseLLMProvider, LLMResponse, Message

logger = logging.getLogger(__name__)

_SEP = "─" * 60


class GeminiProvider(BaseLLMProvider):
    """Google Gemini provider with proper multi-turn Content/Part message handling."""

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-2.5-flash",
        temperature: float = 0.7,
    ):
        super().__init__(api_key, model, temperature)
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
        web_search: bool = False,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Send messages to Gemini; web_search is disabled when json_mode=True."""
        self._validate_messages(messages)

        system_instruction, contents = self._build_contents(messages)

        # Disable web search, code analysis doesn't benefit from it anyway.
        effective_web_search = web_search and not json_mode

        config_kwargs: dict[str, Any] = {
            "temperature": temperature if temperature is not None else self.temperature,
        }
        if system_instruction:
            config_kwargs["system_instruction"] = system_instruction
        if effective_web_search:
            config_kwargs["tools"] = [types.Tool(google_search=types.GoogleSearch())]
        elif json_mode:
            config_kwargs["response_mime_type"] = "application/json"

        config = types.GenerateContentConfig(**config_kwargs)

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                f"[Gemini] → Request: model={self.model}, "
                f"content_turns={len(contents)}, web_search={effective_web_search}, "
                f"json_mode={json_mode}, "
                f"temperature={config_kwargs.get('temperature')}, "
                f"response_mime_type={config_kwargs.get('response_mime_type', 'text/plain')}"
            )

        response = await self._call_api(contents, config)

        content = self._extract_text(response)

        if effective_web_search:
            grounding = None
            if response.candidates:
                grounding = getattr(response.candidates[0], "grounding_metadata", None)
            if grounding:
                queries = getattr(grounding, "web_search_queries", None) or []
                chunks = getattr(grounding, "grounding_chunks", None) or []
                if queries:
                    logger.info(
                        f"[Gemini] Web search used: {len(queries)} "
                        f"quer{'y' if len(queries) == 1 else 'ies'}, "
                        f"{len(chunks)} source(s)"
                    )
                    for q in queries:
                        logger.debug(f"[Gemini] Search query: {q!r}")
                else:
                    logger.debug("[Gemini] Web search enabled but model did not query")
            else:
                logger.debug("[Gemini] Web search enabled but no grounding metadata returned")

        prompt_tokens = 0
        completion_tokens = 0
        total_tokens = 0
        if hasattr(response, "usage_metadata") and response.usage_metadata:
            usage = response.usage_metadata
            prompt_tokens = getattr(usage, "prompt_token_count", 0) or 0
            completion_tokens = getattr(usage, "candidates_token_count", 0) or 0
            total_tokens = getattr(usage, "total_token_count", 0) or 0

        finish_reason_raw = getattr(
            response.candidates[0] if response.candidates else None,
            "finish_reason", None,
        )
        # Gemini returns an enum (FinishReason.STOP); normalise to plain string
        if finish_reason_raw is None:
            finish_reason = "stop"
        elif hasattr(finish_reason_raw, "name"):
            finish_reason = finish_reason_raw.name.lower()
        else:
            finish_reason = str(finish_reason_raw).lower()

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                f"[Gemini] ← Response: {len(content)} chars | "
                f"tokens: {total_tokens} total / {prompt_tokens} prompt / {completion_tokens} completion | "
                f"finish_reason={finish_reason}"
            )

        return LLMResponse(
            content=content,
            model=self.model,
            tokens_used=total_tokens,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            finish_reason=finish_reason,
            raw_response=None,  # proto objects are not JSON-serialisable
        )

    async def _call_api(
        self,
        contents: list[types.Content],
        config: types.GenerateContentConfig,
    ) -> Any:
        """Async API call with rate-limit retry; falls back to sync executor if async is unavailable."""
        async def _attempt() -> Any:
            try:
                return await self.client.aio.models.generate_content(
                    model=self.model,
                    contents=contents,
                    config=config,
                )
            except Exception as exc:
                if self._is_rate_limit_error(exc):
                    raise  # let _with_retry handle it
                logger.debug(f"Async Gemini call failed ({exc}), falling back to executor")
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    None,
                    lambda: self.client.models.generate_content(
                        model=self.model,
                        contents=contents,
                        config=config,
                    ),
                )

        return await self._with_retry(_attempt)

    @staticmethod
    def _build_contents(
        messages: list[Message],
    ) -> tuple[Optional[str], list[types.Content]]:
        """Convert Messages to Gemini Content objects, extracting the system prompt separately."""
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
