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
    def __init__(self, provider: BaseLLMProvider, web_search: bool = False):
        super().__init__(
            provider=provider,
            name="Defender",
            role=AgentRole.DEFENDER,
            system_prompt=DEFENDER_SYSTEM_PROMPT,
            web_search=web_search,
        )

    async def analyze(self, context: dict) -> AgentResponse:
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

        defense_verdict = parsed.get("verdict", "unknown")
        confidence = self._parse_confidence_level(parsed.get("confidence"), default=ConfidenceLevel.MEDIUM)
        defense_text = parsed.get("defense", parsed.get("raw_content", str(parsed)))

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

        verdict = parsed.get("verdict", "MAINTAIN_DEFENSE").upper()
        acknowledges_vuln = "ACKNOWLEDGE" in verdict
        confidence = self._parse_confidence_level(parsed.get("confidence"), default=ConfidenceLevel.MEDIUM)

        return AgentResponse(
            agent_role=self.role,
            content=parsed.get("reasoning", parsed.get("raw_content", str(parsed))),
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
            content=parsed.get("answer", parsed.get("raw_content", str(parsed))),
            claims=[],
            reasoning="Clarification response",
            confidence=confidence,
            metadata={
                "claim_id": claim.get("id", "unknown"),
                "supporting_evidence": parsed.get("supporting_evidence", ""),
                "is_clarification": True,
            },
        )
