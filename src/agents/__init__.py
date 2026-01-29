"""
Agent implementations for the Adversarial Agent System.

Contains the three specialized agents:
- AttackerAgent: Scans for vulnerabilities
- DefenderAgent: Verifies and challenges claims
- JudgeAgent: Makes final decisions
"""

from src.agents.attacker_agent import AttackerAgent
from src.agents.base_agent import AgentResponse, BaseAgent
from src.agents.defender_agent import DefenderAgent
from src.agents.judge_agent import JudgeAgent

__all__ = [
    "BaseAgent",
    "AgentResponse",
    "AttackerAgent",
    "DefenderAgent",
    "JudgeAgent",
]
