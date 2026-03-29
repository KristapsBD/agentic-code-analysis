"""
Defender Agent implementation.

The Defender Agent acts as a developer advocate, reviewing vulnerability
claims and providing counter-arguments when claims are invalid or exaggerated.
"""

import logging
from typing import Any

from src.agents.base_agent import AgentResponse, AgentRole, BaseAgent, VulnerabilityClaim
from src.knowledge.prompts.defender import (
    CLARIFICATION_RESPONSE_PROMPT_TEMPLATE,
    DEFENDER_SYSTEM_PROMPT,
    DEFENSE_PROMPT_TEMPLATE,
    REBUTTAL_RESPONSE_PROMPT_TEMPLATE,
)
from src.config import ConfidenceLevel, settings
from src.providers.base_provider import BaseLLMProvider

logger = logging.getLogger(__name__)


class DefenderAgent(BaseAgent):
    """
    Defender Agent that verifies vulnerability claims.

    This agent takes the role of a developer, critically examining
    vulnerability claims and providing counter-arguments. It looks for:
    - Existing mitigations (modifiers, checks, guards)
    - Context that invalidates the claim
    - Misunderstandings of the code's intent
    """

    def __init__(self, provider: BaseLLMProvider, web_search: bool = False):
        """
        Initialize the Defender Agent.

        Args:
            provider: LLM provider for generating responses
            web_search: Whether to enable built-in web search on every LLM call
        """
        super().__init__(
            provider=provider,
            name="Defender",
            role=AgentRole.DEFENDER,
            system_prompt=DEFENDER_SYSTEM_PROMPT,
            web_search=web_search,
        )

    async def analyze(self, context: dict) -> AgentResponse:
        """
        Review a vulnerability claim and provide a defense.

        Args:
            context: Dictionary containing:
                - contract_code: The smart contract source code
                - claim: The VulnerabilityClaim to review

        Returns:
            AgentResponse containing the defense argument
        """
        contract_code = context.get("contract_code", "")
        claim = context.get("claim")

        claim_dict = self._to_claim_dict(claim)

        prompt = DEFENSE_PROMPT_TEMPLATE.format(
            contract_code=contract_code,
            vulnerability_type=claim_dict.get("vulnerability_type", "Unknown"),
            severity=claim_dict.get("severity", "Unknown"),
            location=claim_dict.get("location", "Unknown"),
            description=claim_dict.get("description", "No description"),
            evidence=claim_dict.get("evidence", "No evidence provided"),
            attacker_confidence=claim_dict.get("confidence", ConfidenceLevel.MEDIUM.value),
        )

        parsed = await self._send_message_json(prompt, include_history=False, temperature=settings.temp_debate)

        # Extract structured defense data
        defense_verdict = parsed.get("verdict", "unknown")
        confidence = self._parse_confidence_level(parsed.get("confidence"), default=ConfidenceLevel.MEDIUM)
        defense_text = parsed.get("defense", str(parsed))

        return AgentResponse(
            agent_role=self.role,
            content=defense_text,
            claims=[],
            reasoning=defense_verdict,
            confidence=confidence,
            metadata={
                "claim_id": claim_dict.get("id", "unknown"),
                "defense_verdict": defense_verdict,
                "mitigations_found": parsed.get("mitigations_found", []),
                "recommended_severity": parsed.get("recommended_severity", ""),
                "evidence": parsed.get("evidence", ""),
            },
        )

    async def respond_to_rebuttal(self, context: dict) -> AgentResponse:
        """
        Respond to the Attacker's rebuttal.

        Args:
            context: Dictionary containing:
                - original_claim: The original vulnerability claim
                - original_defense: The Defender's initial argument
                - rebuttal: The Attacker's counter-argument

        Returns:
            AgentResponse with updated defense or concession
        """
        claim = context.get("original_claim", {})
        original_defense = context.get("original_defense", "")
        rebuttal = context.get("rebuttal", "")

        prompt = REBUTTAL_RESPONSE_PROMPT_TEMPLATE.format(
            vulnerability_type=claim.get("vulnerability_type", "Unknown"),
            location=claim.get("location", "Unknown"),
            description=claim.get("description", "No description"),
            original_defense=original_defense,
            rebuttal=rebuttal,
        )

        parsed = await self._send_message_json(prompt, include_history=True, temperature=settings.temp_debate)

        # Determine verdict from structured output
        verdict = parsed.get("verdict", "MAINTAIN_DEFENSE").upper()
        acknowledges_vuln = "ACKNOWLEDGE" in verdict
        confidence = self._parse_confidence_level(parsed.get("confidence"), default=ConfidenceLevel.MEDIUM)

        return AgentResponse(
            agent_role=self.role,
            content=parsed.get("reasoning", str(parsed)),
            claims=[],
            reasoning="Acknowledges vulnerability" if acknowledges_vuln else "Maintains defense",
            confidence=confidence,
            metadata={
                "claim_id": claim.get("id", "unknown"),
                "acknowledges_vulnerability": acknowledges_vuln,
                "final_assessment": parsed.get("final_assessment", ""),
            },
        )

    async def respond_to_clarification(self, context: dict) -> AgentResponse:
        """
        Respond to a clarification request from the Judge.

        Args:
            context: Dictionary containing:
                - original_claim: The original vulnerability claim
                - judge_question: The Judge's specific question

        Returns:
            AgentResponse with targeted answer to the Judge's question
        """
        claim = context.get("original_claim", {})
        judge_question = context.get("judge_question", "")

        prompt = CLARIFICATION_RESPONSE_PROMPT_TEMPLATE.format(
            vulnerability_type=claim.get("vulnerability_type", "Unknown"),
            location=claim.get("location", "Unknown"),
            description=claim.get("description", "No description"),
            judge_question=judge_question,
        )

        parsed = await self._send_message_json(prompt, include_history=False, temperature=settings.temp_clarification)

        confidence = self._parse_confidence_level(parsed.get("confidence"), default=ConfidenceLevel.MEDIUM)

        return AgentResponse(
            agent_role=self.role,
            content=parsed.get("answer", str(parsed)),
            claims=[],
            reasoning="Clarification response",
            confidence=confidence,
            metadata={
                "claim_id": claim.get("id", "unknown"),
                "supporting_evidence": parsed.get("supporting_evidence", ""),
                "is_clarification": True,
            },
        )
