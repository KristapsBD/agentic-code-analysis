"""
Conversation state management for agent debates.

Tracks the history of exchanges between agents.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class TurnType(str, Enum):
    """Types of conversation turns."""

    ATTACK = "attack"
    DEFENSE = "defense"
    REBUTTAL = "rebuttal"
    JUDGMENT = "judgment"
    CLARIFICATION = "clarification"
    CLARIFICATION_RESPONSE = "clarification_response"
    SYSTEM = "system"


@dataclass
class ConversationTurn:
    """A single turn in the conversation."""

    turn_type: TurnType
    agent_name: str
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    claim_id: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            "turn_type": self.turn_type.value,
            "agent_name": self.agent_name,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "claim_id": self.claim_id,
            "metadata": self.metadata,
        }


class Conversation:
    """
    Manages the conversation state for a vulnerability analysis session.

    Tracks all turns between agents across the debate pipeline.
    """

    def __init__(self, contract_path: str):
        """
        Initialize a new conversation.

        Args:
            contract_path: Path to the contract being analyzed
        """
        self.contract_path = contract_path
        self.turns: list[ConversationTurn] = []
        self.started_at = datetime.now()
        self.metadata: dict[str, Any] = {}

    def add_turn(
        self,
        turn_type: TurnType,
        agent_name: str,
        content: str,
        claim_id: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> ConversationTurn:
        """
        Add a new turn to the conversation.

        Args:
            turn_type: Type of this turn
            agent_name: Name of the agent making this turn
            content: The content of the turn
            claim_id: Optional ID of related claim
            metadata: Optional additional metadata

        Returns:
            The created ConversationTurn
        """
        turn = ConversationTurn(
            turn_type=turn_type,
            agent_name=agent_name,
            content=content,
            claim_id=claim_id,
            metadata=metadata or {},
        )
        self.turns.append(turn)
        return turn
