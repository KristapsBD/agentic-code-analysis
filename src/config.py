"""
Configuration management for the Adversarial Agent System.

Handles environment variables, default settings, and configuration validation.
"""

import logging
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings

# Load environment variables from .env file (if it exists and is readable)
try:
    load_dotenv()
except (PermissionError, FileNotFoundError):
    pass  # .env file not accessible, will use environment variables or defaults


def setup_logging(log_level: str = "INFO") -> Optional[Path]:
    """
    Configure logging for the application.

    When log_level is DEBUG, the full transcript is also written to a
    timestamped file under data/logs/ so the complete pipeline output
    can be reviewed after the run.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        Path to the debug log file, or None when not in DEBUG mode.
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    fmt = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Console handler — always present
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(fmt)
    root.addHandler(console_handler)

    # File handler — only when DEBUG is requested
    if numeric_level == logging.DEBUG:
        log_dir = Path("data/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = log_dir / f"debug_{timestamp}.log"
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
        return log_file

    return None


class LLMProvider(str, Enum):
    """Supported LLM providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # API Keys
    openai_api_key: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")
    anthropic_api_key: Optional[str] = Field(default=None, alias="ANTHROPIC_API_KEY")
    gemini_api_key: Optional[str] = Field(default=None, alias="GEMINI_API_KEY")

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
    default_model_gemini: str = Field(
        default="gemini-2.0-flash-exp", alias="DEFAULT_MODEL_GEMINI"
    )

    # Debate Configuration
    default_debate_rounds: int = Field(default=2, alias="DEFAULT_DEBATE_ROUNDS", ge=1, le=5)
    default_temperature: float = Field(
        default=0.7, alias="DEFAULT_TEMPERATURE", ge=0.0, le=2.0
    )
    judge_confidence_threshold: float = Field(
        default=0.7, alias="JUDGE_CONFIDENCE_THRESHOLD", ge=0.0, le=1.0
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
        elif provider == LLMProvider.GEMINI:
            return self.default_model_gemini
        else:
            raise ValueError(f"Unknown provider: {provider}")

    def get_api_key_for_provider(self, provider: Optional[LLMProvider] = None) -> Optional[str]:
        """Get the API key for a given provider."""
        provider = provider or self.default_provider
        if provider == LLMProvider.OPENAI:
            return self.openai_api_key
        elif provider == LLMProvider.ANTHROPIC:
            return self.anthropic_api_key
        elif provider == LLMProvider.GEMINI:
            return self.gemini_api_key
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
