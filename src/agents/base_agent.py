"""
Abstract base class for all agents in the system.

Defines the common interface and shared functionality
for Attacker, Defender, and Judge agents.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from src.providers.base_provider import BaseLLMProvider, Message


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
class AgentResponse:
    """Response from an agent's analysis."""

    agent_role: AgentRole
    content: str
    claims: list[VulnerabilityClaim] = field(default_factory=list)
    reasoning: str = ""
    tokens_used: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            "agent_role": self.agent_role.value,
            "content": self.content,
            "claims": [claim.to_dict() for claim in self.claims],
            "reasoning": self.reasoning,
            "tokens_used": self.tokens_used,
            "metadata": self.metadata,
        }


class BaseAgent(ABC):
    """
    Abstract base class for all agents.

    Provides common functionality for interacting with LLM providers
    and managing conversation context.
    """

    def __init__(
        self,
        provider: BaseLLMProvider,
        name: str,
        role: AgentRole,
        system_prompt: str,
    ):
        """
        Initialize the agent.

        Args:
            provider: LLM provider for generating responses
            name: Human-readable name for the agent
            role: The role this agent plays
            system_prompt: System prompt defining agent behavior
        """
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
        """
        Send a message to the LLM and get a response.

        Args:
            user_message: The message to send
            include_history: Whether to include conversation history
            temperature: Optional temperature override

        Returns:
            The LLM's response content
        """
        messages = [Message(role="system", content=self.system_prompt)]

        if include_history:
            messages.extend(self.conversation_history)

        messages.append(Message(role="user", content=user_message))

        response = await self.provider.complete(messages, temperature=temperature)

        # Store in history
        self.conversation_history.append(Message(role="user", content=user_message))
        self.conversation_history.append(Message(role="assistant", content=response.content))

        return response.content

    def clear_history(self) -> None:
        """Clear the conversation history."""
        self.conversation_history = []

    def get_history_tokens(self) -> int:
        """Estimate tokens in conversation history."""
        # Rough estimate: 4 characters per token
        total_chars = sum(len(msg.content) for msg in self.conversation_history)
        return total_chars // 4
