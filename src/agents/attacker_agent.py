"""
Attacker Agent implementation.

The Attacker Agent aggressively scans smart contract code for potential
vulnerabilities, acting as a security auditor trying to find flaws.
"""

import logging
import uuid
from typing import Any

from src.agents.base_agent import AgentResponse, AgentRole, BaseAgent, VulnerabilityClaim
from src.knowledge.prompts.attacker import (
    ATTACKER_SYSTEM_PROMPT,
    CLARIFICATION_RESPONSE_PROMPT_TEMPLATE,
    REBUTTAL_PROMPT_TEMPLATE,
    SCAN_PROMPT_TEMPLATE,
    VULNERABILITY_TYPES,
)
from src.config import ConfidenceLevel, settings
from src.providers.base_provider import BaseLLMProvider

logger = logging.getLogger(__name__)


class AttackerAgent(BaseAgent):
    """
    Attacker Agent that scans for vulnerabilities.

    This agent takes an aggressive stance, flagging any code patterns
    that could potentially be exploited. It prioritizes sensitivity
    over specificity (better to flag a false positive than miss a real bug).
    """

    def __init__(self, provider: BaseLLMProvider, web_search: bool = False):
        """
        Initialize the Attacker Agent.

        Args:
            provider: LLM provider for generating responses
            web_search: Whether to enable built-in web search on every LLM call
        """
        super().__init__(
            provider=provider,
            name="Attacker",
            role=AgentRole.ATTACKER,
            system_prompt=ATTACKER_SYSTEM_PROMPT,
            web_search=web_search,
        )

    async def analyze(self, context: dict) -> AgentResponse:
        """
        Scan the contract for vulnerabilities.

        Args:
            context: Dictionary containing:
                - contract_code: The smart contract source code

        Returns:
            AgentResponse containing vulnerability claims
        """
        contract_code = context.get("contract_code", "")

        prompt = SCAN_PROMPT_TEMPLATE.format(
            contract_code=contract_code,
            vulnerability_types=", ".join(VULNERABILITY_TYPES),
        )

        parsed = await self._send_message_json(prompt, include_history=False, temperature=settings.temp_attacker_scan)

        # Extract claims from the structured JSON response
        claims = self._extract_claims(parsed)

        return AgentResponse(
            agent_role=self.role,
            content=str(parsed),
            claims=claims,
            reasoning="Initial vulnerability scan completed",
            confidence=ConfidenceLevel.HIGH,
            metadata={
                "scan_type": "initial",
            },
        )

    async def respond_to_defense(self, context: dict) -> AgentResponse:
        """
        Respond to the Defender's arguments.

        The Attacker can either:
        - Provide additional evidence to support their claim
        - Concede if the Defender's argument is valid

        Args:
            context: Dictionary containing:
                - original_claim: The original vulnerability claim
                - defense_argument: The Defender's counter-argument

        Returns:
            AgentResponse with rebuttal or concession
        """
        claim = context.get("original_claim", {})
        defense = context.get("defense_argument", "")

        prompt = REBUTTAL_PROMPT_TEMPLATE.format(
            vulnerability_type=claim.get("vulnerability_type", "Unknown"),
            location=claim.get("location", "Unknown"),
            description=claim.get("description", "No description"),
            evidence=claim.get("evidence", ""),
            defense_argument=defense,
        )

        parsed = await self._send_message_json(prompt, include_history=True, temperature=settings.temp_debate)

        # Determine if this is a rebuttal or concession from structured output
        verdict = parsed.get("verdict", "REBUTTAL").upper()
        is_concession = "CONCEDE" in verdict
        confidence = self._parse_confidence_level(parsed.get("confidence"), default=ConfidenceLevel.MEDIUM)

        return AgentResponse(
            agent_role=self.role,
            content=parsed.get("reasoning", str(parsed)),
            claims=[],
            reasoning="Concession" if is_concession else "Rebuttal",
            confidence=confidence,
            metadata={
                "claim_id": claim.get("id", "unknown"),
                "is_concession": is_concession,
                "additional_evidence": parsed.get("additional_evidence", ""),
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

        confidence = self._parse_confidence_level(parsed.get("confidence"), default=ConfidenceLevel.HIGH)

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

    def _extract_claims(self, parsed: dict[str, Any]) -> list[VulnerabilityClaim]:
        """
        Extract vulnerability claims from the parsed JSON response.

        Args:
            parsed: Parsed JSON dictionary from the LLM response

        Returns:
            List of VulnerabilityClaim objects
        """
        claims: list[VulnerabilityClaim] = []

        # Handle both direct vulnerabilities list and wrapped format
        vuln_list = parsed.get("vulnerabilities", [])
        if not vuln_list and parsed.get("raw_content"):
            # Fallback: try to parse from raw content if JSON parsing failed
            vuln_list = self._fallback_parse_claims(parsed["raw_content"])

        for item in vuln_list:
            claim = self._dict_to_claim(item)
            if claim:
                claims.append(claim)

        return claims

    def _dict_to_claim(self, data: dict[str, Any]) -> VulnerabilityClaim | None:
        """
        Convert a dictionary to a VulnerabilityClaim.

        Args:
            data: Dictionary with vulnerability data

        Returns:
            VulnerabilityClaim or None if conversion fails
        """
        try:
            return VulnerabilityClaim(
                id=data.get("id", str(uuid.uuid4())[:8]),
                vulnerability_type=data.get("type", data.get("vulnerability_type", "Unknown")),
                severity=data.get("severity", "medium").lower(),
                location=data.get("location", data.get("function", "Unknown")),
                description=data.get("description", "No description provided"),
                evidence=data.get("evidence", data.get("code_snippet", "")),
                confidence=self._parse_confidence_level(data.get("confidence"), default=ConfidenceLevel.HIGH),
            )
        except (KeyError, ValueError, TypeError):
            return None

    def _fallback_parse_claims(self, raw_content: str) -> list[dict[str, Any]]:
        """
        Fallback parser for when JSON parsing fails.

        Attempts to extract vulnerability information from unstructured text.

        Args:
            raw_content: Raw text content from the LLM

        Returns:
            List of vulnerability dictionaries
        """
        claims: list[dict[str, Any]] = []
        current_claim: dict[str, Any] = {}

        lines = raw_content.split("\n")
        for line in lines:
            line = line.strip()
            upper_line = line.upper()

            if upper_line.startswith("VULNERABILITY:") or upper_line.startswith("TYPE:"):
                if current_claim and current_claim.get("vulnerability_type"):
                    claims.append(current_claim)
                    current_claim = {}
                current_claim["vulnerability_type"] = line.split(":", 1)[1].strip()
            elif upper_line.startswith("SEVERITY:"):
                current_claim["severity"] = line.split(":", 1)[1].strip()
            elif upper_line.startswith("LOCATION:") or upper_line.startswith("FUNCTION:"):
                current_claim["location"] = line.split(":", 1)[1].strip()
            elif upper_line.startswith("DESCRIPTION:"):
                current_claim["description"] = line.split(":", 1)[1].strip()
            elif upper_line.startswith("EVIDENCE:") or upper_line.startswith("CODE:"):
                current_claim["evidence"] = line.split(":", 1)[1].strip()
            elif upper_line.startswith("CONFIDENCE:"):
                current_claim["confidence"] = line.split(":", 1)[1].strip()

        # Don't forget the last claim
        if current_claim and current_claim.get("vulnerability_type"):
            claims.append(current_claim)

        return claims
