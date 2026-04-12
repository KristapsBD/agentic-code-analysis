"""Abstract base class for all agents in the system."""

import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from src.config import ConfidenceLevel
from src.providers.base_provider import BaseLLMProvider, Message

logger = logging.getLogger(__name__)


class AgentRole(str, Enum):
    """Roles that agents can take in the system."""

    ATTACKER = "attacker"
    DEFENDER = "defender"
    JUDGE = "judge"


@dataclass
class VulnerabilityClaim:
    """A vulnerability claim made by an agent."""

    id: str
    vulnerability_type: str
    severity: str  # "critical", "high", "medium", "low", "info"
    location: str  # Function name, line number, or code snippet
    description: str
    evidence: str  # Code snippet or reasoning
    confidence: ConfidenceLevel

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "location": self.location,
            "description": self.description,
            "evidence": self.evidence,
            "confidence": self.confidence.value,
        }


@dataclass
class AgentResponse:
    """Response from an agent's analysis."""

    agent_role: AgentRole
    content: str
    claims: list[VulnerabilityClaim] = field(default_factory=list)
    reasoning: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    tokens_used: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "agent_role": self.agent_role.value,
            "content": self.content,
            "claims": [claim.to_dict() for claim in self.claims],
            "reasoning": self.reasoning,
            "confidence": self.confidence.value,
            "tokens_used": self.tokens_used,
            "metadata": self.metadata,
        }


class BaseAgent(ABC):
    """Base class for Attacker, Defender, and Judge agents.

    History accumulates within a single claim's debate and is cleared between claims.
    """

    def __init__(
        self,
        provider: BaseLLMProvider,
        name: str,
        role: AgentRole,
        system_prompt: str,
        web_search: bool = False,
    ):
        self.provider = provider
        self.name = name
        self.role = role
        self.system_prompt = system_prompt
        self.web_search = web_search
        self.conversation_history: list[Message] = []

    @abstractmethod
    async def analyze(self, context: dict) -> AgentResponse:
        """Perform agent-specific analysis."""
        pass

    async def _send_message(
        self,
        user_message: str,
        include_history: bool = True,
        temperature: Optional[float] = None,
        json_mode: bool = False,
    ) -> str:
        messages = [Message(role="system", content=self.system_prompt)]

        if include_history:
            messages.extend(self.conversation_history)

        messages.append(Message(role="user", content=user_message))

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                f"[{self.name}] → Sending {len(messages)} message(s) to LLM "
                f"(history_turns={len(self.conversation_history)}, "
                f"temperature={temperature}, web_search={self.web_search}, "
                f"json_mode={json_mode})"
            )
        response = await self.provider.complete(
            messages, temperature=temperature, web_search=self.web_search, json_mode=json_mode
        )

        if logger.isEnabledFor(logging.DEBUG):
            _SEP = "─" * 60
            logger.debug(
                f"[{self.name}] ← Raw LLM response "
                f"({len(response.content)} chars | "
                f"tokens: {response.tokens_used} total / "
                f"{response.prompt_tokens} prompt / {response.completion_tokens} completion | "
                f"finish_reason={response.finish_reason!r}):\n"
                f"{_SEP}\n{response.content}\n{_SEP}"
            )

        self.conversation_history.append(Message(role="user", content=user_message))
        self.conversation_history.append(Message(role="assistant", content=response.content))

        return response.content

    async def _send_message_json(
        self,
        user_message: str,
        include_history: bool = True,
        temperature: Optional[float] = None,
    ) -> dict[str, Any]:
        """Send a message and return the response parsed as JSON."""
        json_instruction = (
            "\n\nIMPORTANT: You MUST respond with valid JSON only. "
            "Do not include any text outside the JSON object. "
            "Do not wrap the JSON in markdown code blocks."
        )
        raw_response = await self._send_message(
            user_message + json_instruction,
            include_history=include_history,
            temperature=temperature,
            json_mode=True,
        )

        logger.debug(f"[{self.name}] Attempting JSON parse on {len(raw_response)}-char response")
        parsed = self._parse_json_response(raw_response)

        if parsed.get("_parse_failed"):
            logger.warning(
                f"[{self.name}] JSON parsing FAILED — raw_content fallback used. "
                f"First 300 chars of response: {raw_response[:300]!r}"
            )
        else:
            logger.debug(
                f"[{self.name}] JSON parsed successfully. "
                f"Top-level keys: {sorted(parsed.keys())}"
            )

        return parsed

    @staticmethod
    def _parse_json_response(response: str) -> dict[str, Any]:
        """Parse a JSON response, trying direct parse → markdown extraction → brace extraction."""
        try:
            result = json.loads(response.strip())
            logger.debug("JSON parse strategy: direct parse succeeded")
            return result
        except json.JSONDecodeError:
            pass

        json_pattern = r"```(?:json)?\s*([\s\S]*?)\s*```"
        match = re.search(json_pattern, response)
        if match:
            try:
                result = json.loads(match.group(1).strip())
                logger.debug("JSON parse strategy: markdown code block extraction succeeded")
                return result
            except json.JSONDecodeError:
                pass

        brace_start = response.find("{")
        brace_end = response.rfind("}")
        if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
            try:
                result = json.loads(response[brace_start:brace_end + 1])
                logger.debug("JSON parse strategy: brace-extraction succeeded")
                return result
            except json.JSONDecodeError:
                pass

        logger.warning("JSON parse strategy: all strategies failed — using raw_content fallback")
        return {"raw_content": response, "_parse_failed": True}

    @staticmethod
    def _parse_confidence_level(
        value: Any, default: ConfidenceLevel = ConfidenceLevel.MEDIUM
    ) -> ConfidenceLevel:
        """Parse a value into a ConfidenceLevel enum member."""
        if value is None:
            return default
        if isinstance(value, ConfidenceLevel):
            return value
        try:
            return ConfidenceLevel(str(value).strip().upper())
        except ValueError:
            return default

    @staticmethod
    def _normalize_confidence(value: Any, default: float = 0.5) -> float:
        """Normalize a numeric score to the [0, 1] range (used for attacker/defender scores)."""
        try:
            conf = float(value) if value is not None else default
            if conf > 1:
                conf = conf / 100
            return max(0.0, min(1.0, conf))
        except (ValueError, TypeError):
            return default

    @staticmethod
    def _to_claim_dict(claim: Any) -> dict:
        """Convert a VulnerabilityClaim or dict to a plain dict."""
        return claim.to_dict() if isinstance(claim, VulnerabilityClaim) else claim

    def clear_history(self) -> None:
        self.conversation_history = []

