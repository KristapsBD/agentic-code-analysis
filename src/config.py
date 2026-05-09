import logging
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings

try:
    load_dotenv()
except (PermissionError, FileNotFoundError):
    pass  # .env file not accessible, will use environment variables or defaults


def setup_logging(log_level: str = "INFO") -> Optional[Path]:
    """Configure logging; returns a debug log file path when level is DEBUG."""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    fmt = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(numeric_level)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(fmt)
    root.addHandler(console_handler)

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
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"


_CONFIDENCE_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


class ConfidenceLevel(str, Enum):
    """Three-tier confidence signal: HIGH (clear evidence), MEDIUM (plausible), LOW (ambiguous)."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    def __lt__(self, other: "ConfidenceLevel") -> bool:
        return _CONFIDENCE_ORDER[self.value] < _CONFIDENCE_ORDER[other.value]

    def __le__(self, other: "ConfidenceLevel") -> bool:
        return _CONFIDENCE_ORDER[self.value] <= _CONFIDENCE_ORDER[other.value]

    def __gt__(self, other: "ConfidenceLevel") -> bool:
        return _CONFIDENCE_ORDER[self.value] > _CONFIDENCE_ORDER[other.value]

    def __ge__(self, other: "ConfidenceLevel") -> bool:
        return _CONFIDENCE_ORDER[self.value] >= _CONFIDENCE_ORDER[other.value]


class Settings(BaseSettings):
    openai_api_key: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")
    anthropic_api_key: Optional[str] = Field(default=None, alias="ANTHROPIC_API_KEY")
    gemini_api_key: Optional[str] = Field(default=None, alias="GEMINI_API_KEY")

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

    default_debate_rounds: int = Field(default=2, alias="DEFAULT_DEBATE_ROUNDS", ge=1, le=5)

    temp_attacker_scan: float = Field(
        default=0.4, alias="TEMP_ATTACKER_SCAN", ge=0.0, le=2.0
    )
    temp_debate: float = Field(
        default=0.3, alias="TEMP_DEBATE", ge=0.0, le=2.0
    )
    temp_clarification: float = Field(
        default=0.2, alias="TEMP_CLARIFICATION", ge=0.0, le=2.0
    )
    temp_judge: float = Field(
        default=0.2, alias="TEMP_JUDGE", ge=0.0, le=2.0
    )

    judge_clarification_trigger: ConfidenceLevel = Field(
        default=ConfidenceLevel.LOW, alias="JUDGE_CLARIFICATION_TRIGGER"
    )

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

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
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper_v = v.upper()
        if upper_v not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return upper_v

    def get_model_for_provider(self, provider: Optional[LLMProvider] = None) -> str:
        provider = provider or self.default_provider
        models = {
            LLMProvider.OPENAI: self.default_model_openai,
            LLMProvider.ANTHROPIC: self.default_model_anthropic,
            LLMProvider.GEMINI: self.default_model_gemini,
        }
        if provider not in models:
            raise ValueError(f"Unknown provider: {provider}")
        return models[provider]

    def get_api_key_for_provider(self, provider: Optional[LLMProvider] = None) -> Optional[str]:
        provider = provider or self.default_provider
        keys = {
            LLMProvider.OPENAI: self.openai_api_key,
            LLMProvider.ANTHROPIC: self.anthropic_api_key,
            LLMProvider.GEMINI: self.gemini_api_key,
        }
        if provider not in keys:
            raise ValueError(f"Unknown provider: {provider}")
        return keys[provider]

    def validate_provider_config(self, provider: Optional[LLMProvider] = None) -> None:
        provider = provider or self.default_provider
        api_key = self.get_api_key_for_provider(provider)
        if not api_key:
            raise ValueError(
                f"API key for {provider.value} is not configured. "
                f"Please set the appropriate environment variable."
            )


settings = Settings()
