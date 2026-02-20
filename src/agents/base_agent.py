"""
Abstract base class for all agents in the system.

Defines the common interface and shared functionality
for Attacker, Defender, and Judge agents.
"""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

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
    confidence: float  # 0.0 to 1.0

    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            "id": self.id,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "location": self.location,
            "description": self.description,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


@dataclass
class ClaimContext:
    """
    Structured context passed between agents for a single claim.

    Distills the key arguments into a clean format instead of passing raw text,
    reducing token waste and ensuring agents see focused context.
    """

    claim: VulnerabilityClaim
    contract_code: str
    attacker_argument: str = ""
    defender_argument: str = ""
    attacker_confidence: float = 0.0
    defender_confidence: float = 0.0
    debate_history: list[dict[str, str]] = field(default_factory=list)
    judge_question: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "claim": self.claim.to_dict(),
            "contract_code": self.contract_code,
            "attacker_argument": self.attacker_argument,
            "defender_argument": self.defender_argument,
            "attacker_confidence": self.attacker_confidence,
            "defender_confidence": self.defender_confidence,
            "debate_history": self.debate_history,
            "judge_question": self.judge_question,
        }


@dataclass
class AgentResponse:
    """Response from an agent's analysis."""

    agent_role: AgentRole
    content: str
    claims: list[VulnerabilityClaim] = field(default_factory=list)
    reasoning: str = ""
    confidence: float = 0.5
    tokens_used: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            "agent_role": self.agent_role.value,
            "content": self.content,
            "claims": [claim.to_dict() for claim in self.claims],
            "reasoning": self.reasoning,
            "confidence": self.confidence,
            "tokens_used": self.tokens_used,
            "metadata": self.metadata,
        }


class BaseAgent(ABC):
    """
    Abstract base class for all agents.

    Provides common functionality for interacting with LLM providers
    and managing conversation context with token budget awareness
    and sliding window history.
    """

    def __init__(
        self,
        provider: BaseLLMProvider,
        name: str,
        role: AgentRole,
        system_prompt: str,
    ):
        self.provider = provider
        self.name = name
        self.role = role
        self.system_prompt = system_prompt
        self.conversation_history: list[Message] = []

    @abstractmethod
    async def analyze(self, context: dict) -> AgentResponse:
        """
        Perform agent-specific analysis.

        Args:
            context: Dictionary containing analysis context
                (contract code, previous claims, etc.)

        Returns:
            AgentResponse containing the agent's analysis
        """
        pass

    async def _send_message(
        self,
        user_message: str,
        include_history: bool = True,
        temperature: Optional[float] = None,
    ) -> str:
        messages = [Message(role="system", content=self.system_prompt)]

        if include_history:
            messages.extend(self.conversation_history)

        messages.append(Message(role="user", content=user_message))

        response = await self.provider.complete(messages, temperature=temperature)

        # Store in history
        self.conversation_history.append(Message(role="user", content=user_message))
        self.conversation_history.append(Message(role="assistant", content=response.content))

        return response.content

    async def _send_message_json(
        self,
        user_message: str,
        include_history: bool = True,
        temperature: Optional[float] = None,
    ) -> dict[str, Any]:
        """
        Send a message and parse the response as JSON.

        Appends a JSON instruction to the user message and attempts
        to extract a valid JSON object from the response. Falls back
        to wrapping the raw content if parsing fails.

        Args:
            user_message: The message to send
            include_history: Whether to include conversation history
            temperature: Optional temperature override

        Returns:
            Parsed JSON dictionary from the response
        """
        json_instruction = (
            "\n\nIMPORTANT: You MUST respond with valid JSON only. "
            "Do not include any text outside the JSON object. "
            "Do not wrap the JSON in markdown code blocks."
        )
        raw_response = await self._send_message(
            user_message + json_instruction,
            include_history=include_history,
            temperature=temperature,
        )

        return self._parse_json_response(raw_response)

    @staticmethod
    def _parse_json_response(response: str) -> dict[str, Any]:
        """
        Parse a JSON response from the LLM, handling common formatting issues.

        Attempts direct parsing first, then tries to extract JSON from
        markdown code blocks, and finally falls back to wrapping the raw
        content in a dictionary.

        Args:
            response: The raw LLM response string

        Returns:
            Parsed dictionary
        """
        # Try direct JSON parse
        try:
            return json.loads(response.strip())
        except json.JSONDecodeError:
            pass

        # Try extracting from markdown code blocks
        import re
        json_pattern = r"```(?:json)?\s*([\s\S]*?)\s*```"
        matches = re.findall(json_pattern, response)
        for match in matches:
            try:
                return json.loads(match.strip())
            except json.JSONDecodeError:
                continue

        # Try finding a JSON object in the text
        brace_start = response.find("{")
        brace_end = response.rfind("}")
        if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
            try:
                return json.loads(response[brace_start:brace_end + 1])
            except json.JSONDecodeError:
                pass

        # Fallback: wrap raw content
        logger.warning(f"Could not parse JSON from response, using raw content fallback")
        return {"raw_content": response, "_parse_failed": True}

    def clear_history(self) -> None:
        """Clear the conversation history."""
        self.conversation_history = []

