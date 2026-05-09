from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class TurnType(str, Enum):
    ATTACK = "attack"
    DEFENSE = "defense"
    REBUTTAL = "rebuttal"
    JUDGMENT = "judgment"
    CLARIFICATION = "clarification"
    CLARIFICATION_RESPONSE = "clarification_response"
    SYSTEM = "system"


@dataclass
class ConversationTurn:
    turn_type: TurnType
    agent_name: str
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    claim_id: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "turn_type": self.turn_type.value,
            "agent_name": self.agent_name,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "claim_id": self.claim_id,
            "metadata": self.metadata,
        }


class Conversation:
    def __init__(self, contract_path: str):
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
        turn = ConversationTurn(
            turn_type=turn_type,
            agent_name=agent_name,
            content=content,
            claim_id=claim_id,
            metadata=metadata or {},
        )
        self.turns.append(turn)
        return turn
