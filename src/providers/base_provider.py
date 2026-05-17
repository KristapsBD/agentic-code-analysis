import asyncio
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    content: str
    model: str
    tokens_used: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    finish_reason: str = "stop"
    raw_response: Optional[dict] = field(default=None, repr=False)



@dataclass
class Message:
    role: str
    content: str

    def to_dict(self) -> dict:
        return {"role": self.role, "content": self.content}


class BaseLLMProvider(ABC):
    def __init__(
        self,
        api_key: str,
        model: str,
        temperature: float = 0.7,
    ):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature

    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

    @abstractmethod
    async def complete(
        self,
        messages: list[Message],
        temperature: Optional[float] = None,
        web_search: bool = False,
        json_mode: bool = False,
    ) -> LLMResponse:
        pass

    @staticmethod
    def _is_rate_limit_error(exc: Exception) -> bool:
        msg = str(exc).lower()
        return (
            "429" in str(exc)
            or "resource exhausted" in msg
            or "rate limit" in msg
            or "too many requests" in msg
            or "quota exceeded" in msg
            or "ratelimit" in msg
        )

    async def _with_retry(
        self,
        call_fn: Callable[[], Coroutine[Any, Any, Any]],
        max_retries: int = 3,
        base_delay: float = 30.0,
        max_delay: float = 120.0,
    ) -> Any:
        for attempt in range(max_retries):
            try:
                return await call_fn()
            except Exception as exc:
                if self._is_rate_limit_error(exc) and attempt < max_retries - 1:
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    logger.warning(
                        f"Rate limit hit (attempt {attempt + 1}/{max_retries}), "
                        f"retrying in {delay:.0f}s — {exc}"
                    )
                    await asyncio.sleep(delay)
                else:
                    raise

    def _validate_messages(self, messages: list[Message]) -> None:
        if not messages:
            raise ValueError("Messages list cannot be empty")

        valid_roles = {"system", "user", "assistant"}
        for msg in messages:
            if msg.role not in valid_roles:
                raise ValueError(f"Invalid message role: {msg.role}")
