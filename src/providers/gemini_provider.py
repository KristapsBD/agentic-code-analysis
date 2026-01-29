"""
Google Gemini LLM provider implementation.

Implements the BaseLLMProvider interface for Google's Gemini API.
Uses the official google-genai SDK (v1.0.0+).

Reference: https://ai.google.dev/gemini-api/docs/quickstart
"""

import logging
from typing import Optional

from google import genai

from src.providers.base_provider import BaseLLMProvider, LLMResponse, Message

logger = logging.getLogger(__name__)


class GeminiProvider(BaseLLMProvider):
    """
    Google Gemini LLM provider.

    Uses the official Google GenAI SDK with simplified API calls.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-2.0-flash-exp",
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ):
        """
        Initialize the Gemini provider.

        Args:
            api_key: Google AI API key
            model: Model to use (default: gemini-1.5-flash-latest for free tier)
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response
        """
        super().__init__(api_key, model, temperature, max_tokens)
        logger.debug(f"Initializing GeminiProvider with model={model}")
        self.client = genai.Client(api_key=api_key)
        logger.debug("Gemini client created successfully")

    @property
    def provider_name(self) -> str:
        """Return the provider name."""
        return "gemini"

    async def complete(
        self,
        messages: list[Message],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """
        Send messages to Gemini and get a response.

        Args:
            messages: List of messages in the conversation
            temperature: Optional override for sampling temperature
            max_tokens: Optional override for max tokens

        Returns:
            LLMResponse containing the model's response
        """
        self._validate_messages(messages)

        # Build the prompt from messages
        # For simplicity, concatenate all messages into a single prompt
        prompt_parts = []
        
        for msg in messages:
            if msg.role == "system":
                prompt_parts.append(f"System: {msg.content}")
            elif msg.role == "user":
                prompt_parts.append(f"User: {msg.content}")
            elif msg.role == "assistant":
                prompt_parts.append(f"Assistant: {msg.content}")
        
        # Add final instruction
        prompt_parts.append("\nAssistant:")
        prompt = "\n\n".join(prompt_parts)
        
        logger.debug(f"Sending request to Gemini API (model={self.model}, prompt_length={len(prompt)} chars)")

        # Use the simplified API from the quickstart
        # The generate_content method accepts model name and contents directly
        try:
            logger.debug("Calling Gemini API (async)...")
            response = await self.client.aio.models.generate_content(
                model=self.model,
                contents=prompt,
            )
            logger.debug("Gemini API response received (async)")
        except Exception as e:
            # Fallback: try synchronous version in executor
            logger.debug(f"Async call failed ({e}), falling back to sync in executor")
            import asyncio
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.client.models.generate_content(
                    model=self.model,
                    contents=prompt,
                )
            )
            logger.debug("Gemini API response received (sync)")

        # Extract response text
        text_content = ""
        if hasattr(response, 'text'):
            text_content = response.text
        elif hasattr(response, 'candidates') and response.candidates:
            candidate = response.candidates[0]
            if hasattr(candidate, 'content'):
                if hasattr(candidate.content, 'parts'):
                    text_content = "".join(
                        str(part.text) for part in candidate.content.parts 
                        if hasattr(part, 'text')
                    )

        # Extract token usage
        prompt_tokens = 0
        completion_tokens = 0
        total_tokens = 0
        
        if hasattr(response, 'usage_metadata'):
            usage = response.usage_metadata
            prompt_tokens = getattr(usage, 'prompt_token_count', 0)
            completion_tokens = getattr(usage, 'candidates_token_count', 0)
            total_tokens = getattr(usage, 'total_token_count', 0)

        logger.debug(f"Token usage - Prompt: {prompt_tokens}, Completion: {completion_tokens}, Total: {total_tokens}")
        logger.debug(f"Response length: {len(text_content)} chars")

        return LLMResponse(
            content=text_content,
            model=self.model,
            tokens_used=total_tokens,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            finish_reason="stop",
            raw_response={},
        )
