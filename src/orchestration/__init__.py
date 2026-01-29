"""
Orchestration layer for managing agent debates.

Coordinates the interaction between Attacker, Defender, and Judge agents
to analyze smart contracts through adversarial debate.
"""

from src.orchestration.conversation import Conversation, ConversationTurn
from src.orchestration.debate_manager import DebateManager, DebateResult

__all__ = ["DebateManager", "DebateResult", "Conversation", "ConversationTurn"]
