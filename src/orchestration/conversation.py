"""
Conversation state management for agent debates.

Tracks the history of exchanges between agents and provides
context for multi-round debates.
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


@dataclass
class DebateRound:
    """A single round of debate about a specific claim."""

    round_number: int
    claim_id: str
    attacker_argument: str
    defender_argument: str
    attacker_rebuttal: Optional[str] = None
    defender_response: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            "round_number": self.round_number,
            "claim_id": self.claim_id,
            "attacker_argument": self.attacker_argument,
            "defender_argument": self.defender_argument,
            "attacker_rebuttal": self.attacker_rebuttal,
            "defender_response": self.defender_response,
        }


class Conversation:
    """
    Manages the conversation state for a vulnerability analysis session.

    Tracks all turns, organizes debate rounds, and provides context
    for agents to reference previous exchanges.
    """

    def __init__(self, contract_path: str):
        """
        Initialize a new conversation.

        Args:
            contract_path: Path to the contract being analyzed
        """
        self.contract_path = contract_path
        self.turns: list[ConversationTurn] = []
        self.debate_rounds: dict[str, list[DebateRound]] = {}  # claim_id -> rounds
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

    def add_debate_round(
        self,
        claim_id: str,
        attacker_argument: str,
        defender_argument: str,
        attacker_rebuttal: Optional[str] = None,
        defender_response: Optional[str] = None,
    ) -> DebateRound:
        """
        Add a complete debate round.

        Args:
            claim_id: ID of the claim being debated
            attacker_argument: The Attacker's argument
            defender_argument: The Defender's response
            attacker_rebuttal: Optional rebuttal from Attacker
            defender_response: Optional response to rebuttal

        Returns:
            The created DebateRound
        """
        if claim_id not in self.debate_rounds:
            self.debate_rounds[claim_id] = []

        round_number = len(self.debate_rounds[claim_id]) + 1
        debate_round = DebateRound(
            round_number=round_number,
            claim_id=claim_id,
            attacker_argument=attacker_argument,
            defender_argument=defender_argument,
            attacker_rebuttal=attacker_rebuttal,
            defender_response=defender_response,
        )
        self.debate_rounds[claim_id].append(debate_round)
        return debate_round

    def get_debate_history(self, claim_id: str) -> list[dict]:
        """
        Get the debate history for a specific claim.

        Args:
            claim_id: ID of the claim

        Returns:
            List of debate round dictionaries
        """
        rounds = self.debate_rounds.get(claim_id, [])
        return [
            {
                "attacker": r.attacker_argument,
                "defender": r.defender_argument,
                "attacker_rebuttal": r.attacker_rebuttal,
                "defender_response": r.defender_response,
            }
            for r in rounds
        ]

    def get_turns_by_claim(self, claim_id: str) -> list[ConversationTurn]:
        """Get all turns related to a specific claim."""
        return [t for t in self.turns if t.claim_id == claim_id]

    def get_turns_by_type(self, turn_type: TurnType) -> list[ConversationTurn]:
        """Get all turns of a specific type."""
        return [t for t in self.turns if t.turn_type == turn_type]

    def distill_claim_context(self, claim_id: str) -> dict[str, Any]:
        """
        Distill the debate for a specific claim into a structured summary.

        Instead of passing raw conversation text between agents, this method
        creates a clean, focused summary of the key arguments and their
        evolution across rounds.

        Args:
            claim_id: ID of the claim to summarize

        Returns:
            Dictionary with distilled context:
                - attacker_key_points: list of the Attacker's main arguments
                - defender_key_points: list of the Defender's main arguments
                - areas_of_agreement: points both sides agree on
                - areas_of_contention: points still in dispute
                - round_count: number of debate rounds completed
        """
        claim_turns = self.get_turns_by_claim(claim_id)

        attacker_points: list[str] = []
        defender_points: list[str] = []

        for turn in claim_turns:
            # Truncate long arguments to their first 300 chars for distillation
            summary = turn.content[:300]
            if len(turn.content) > 300:
                summary += "..."

            if turn.turn_type in (TurnType.ATTACK, TurnType.REBUTTAL):
                attacker_points.append(summary)
            elif turn.turn_type == TurnType.DEFENSE:
                defender_points.append(summary)

        rounds = self.debate_rounds.get(claim_id, [])

        return {
            "attacker_key_points": attacker_points,
            "defender_key_points": defender_points,
            "round_count": len(rounds),
            "total_turns": len(claim_turns),
        }

    def get_context_summary(self, claim_id: Optional[str] = None) -> str:
        """
        Generate a summary of the conversation for context.

        Args:
            claim_id: Optional claim ID to filter by

        Returns:
            A formatted summary string
        """
        summary_parts = [f"Conversation for: {self.contract_path}"]
        summary_parts.append(f"Total turns: {len(self.turns)}")

        if claim_id and claim_id in self.debate_rounds:
            rounds = self.debate_rounds[claim_id]
            summary_parts.append(f"Debate rounds for claim {claim_id}: {len(rounds)}")

        return "\n".join(summary_parts)

    def to_dict(self) -> dict:
        """Convert the entire conversation to dictionary format."""
        return {
            "contract_path": self.contract_path,
            "started_at": self.started_at.isoformat(),
            "turns": [t.to_dict() for t in self.turns],
            "debate_rounds": {
                claim_id: [r.to_dict() for r in rounds]
                for claim_id, rounds in self.debate_rounds.items()
            },
            "metadata": self.metadata,
        }

    def clear(self) -> None:
        """Clear all conversation history."""
        self.turns = []
        self.debate_rounds = {}
