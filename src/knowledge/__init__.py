"""
Knowledge base for vulnerability detection.

Contains vulnerability patterns, definitions, and prompt templates
for the agent system.
"""

from src.knowledge.vulnerability_db import VulnerabilityCategory, VulnerabilityDB, VulnerabilityPattern

__all__ = ["VulnerabilityDB", "VulnerabilityPattern", "VulnerabilityCategory"]
