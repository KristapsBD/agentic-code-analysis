"""
Factory for creating LLM provider instances.

Provides a clean interface for instantiating the appropriate
LLM provider based on configuration.
"""

from typing import Optional

from src.config import LLMProvider, settings
from src.providers.anthropic_provider import AnthropicProvider
from src.providers.base_provider import BaseLLMProvider
from src.providers.gemini_provider import GeminiProvider
from src.providers.openai_provider import OpenAIProvider


class ProviderFactory:
    """Factory class for creating LLM provider instances."""

    @staticmethod
    def create(
        provider: Optional[LLMProvider] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> BaseLLMProvider:
        """
        Create an LLM provider instance.

        Args:
            provider: The LLM provider to use (defaults to settings)
            model: Model to use (defaults to provider's default)
            temperature: Sampling temperature (defaults to settings)

        Returns:
            An instance of the appropriate LLM provider

        Raises:
            ValueError: If provider is unknown or API key is not configured
        """
        provider = provider or settings.default_provider
        resolved_temperature = temperature if temperature is not None else 0.7
        model = model or settings.get_model_for_provider(provider)
        api_key = settings.get_api_key_for_provider(provider)

        if not api_key:
            raise ValueError(
                f"API key for {provider.value} is not configured. "
                f"Please set the appropriate environment variable."
            )

        if provider == LLMProvider.OPENAI:
            return OpenAIProvider(api_key=api_key, model=model, temperature=resolved_temperature)
        elif provider == LLMProvider.ANTHROPIC:
            return AnthropicProvider(api_key=api_key, model=model, temperature=resolved_temperature)
        elif provider == LLMProvider.GEMINI:
            return GeminiProvider(api_key=api_key, model=model, temperature=resolved_temperature)
        else:
            raise ValueError(f"Unknown provider: {provider}")

    @staticmethod
    def create_all_configured(
        temperature: Optional[float] = None,
    ) -> dict[str, BaseLLMProvider]:
        """
        Create instances of all configured providers.

        Returns a dictionary mapping provider names to provider instances
        for all providers that have API keys configured.

        Args:
            temperature: Sampling temperature (defaults to settings)

        Returns:
            Dictionary of provider name -> provider instance
        """
        providers = {}

        for provider in LLMProvider:
            try:
                providers[provider.value] = ProviderFactory.create(
                    provider=provider,
                    temperature=temperature,
                )
            except ValueError:
                # Skip providers without API keys
                continue

        return providers
