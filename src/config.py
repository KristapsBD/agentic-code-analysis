"""
Configuration management for the Adversarial Agent System.

Handles environment variables, default settings, and configuration validation.
"""

from enum import Enum
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings

# Load environment variables from .env file
load_dotenv()


class LLMProvider(str, Enum):
    """Supported LLM providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # API Keys
    openai_api_key: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")
    anthropic_api_key: Optional[str] = Field(default=None, alias="ANTHROPIC_API_KEY")

    # Default Provider Configuration
    default_provider: LLMProvider = Field(
        default=LLMProvider.OPENAI, alias="DEFAULT_PROVIDER"
    )
    default_model_openai: str = Field(
        default="gpt-4o", alias="DEFAULT_MODEL_OPENAI"
    )
    default_model_anthropic: str = Field(
        default="claude-3-5-sonnet-20241022", alias="DEFAULT_MODEL_ANTHROPIC"
    )

    # Debate Configuration
    default_debate_rounds: int = Field(default=2, alias="DEFAULT_DEBATE_ROUNDS", ge=1, le=5)
    default_temperature: float = Field(
        default=0.7, alias="DEFAULT_TEMPERATURE", ge=0.0, le=2.0
    )

    # Logging
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # Paths
    data_dir: Path = Field(default=Path("data"))
    results_dir: Path = Field(default=Path("data/results"))
    benchmarks_dir: Path = Field(default=Path("data/benchmarks"))

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level is a valid Python logging level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper_v = v.upper()
        if upper_v not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return upper_v

    def get_model_for_provider(self, provider: Optional[LLMProvider] = None) -> str:
        """Get the default model for a given provider."""
        provider = provider or self.default_provider
        if provider == LLMProvider.OPENAI:
            return self.default_model_openai
        elif provider == LLMProvider.ANTHROPIC:
            return self.default_model_anthropic
        else:
            raise ValueError(f"Unknown provider: {provider}")

    def get_api_key_for_provider(self, provider: Optional[LLMProvider] = None) -> Optional[str]:
        """Get the API key for a given provider."""
        provider = provider or self.default_provider
        if provider == LLMProvider.OPENAI:
            return self.openai_api_key
        elif provider == LLMProvider.ANTHROPIC:
            return self.anthropic_api_key
        else:
            raise ValueError(f"Unknown provider: {provider}")

    def validate_provider_config(self, provider: Optional[LLMProvider] = None) -> None:
        """Validate that the provider has required configuration."""
        provider = provider or self.default_provider
        api_key = self.get_api_key_for_provider(provider)
        if not api_key:
            raise ValueError(
                f"API key for {provider.value} is not configured. "
                f"Please set the appropriate environment variable."
            )


# Global settings instance
settings = Settings()
