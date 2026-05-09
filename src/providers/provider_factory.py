from typing import Optional

from src.config import LLMProvider, settings
from src.providers.anthropic_provider import AnthropicProvider
from src.providers.base_provider import BaseLLMProvider
from src.providers.gemini_provider import GeminiProvider
from src.providers.openai_provider import OpenAIProvider


class ProviderFactory:
    @staticmethod
    def create(
        provider: Optional[LLMProvider] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> BaseLLMProvider:
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
