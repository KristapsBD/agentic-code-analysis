"""Attacker Agent — aggressively scans smart contracts for potential vulnerabilities."""

import json
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
    """Scans for vulnerabilities, prioritizing sensitivity over specificity."""

    def __init__(self, provider: BaseLLMProvider, web_search: bool = False):
        super().__init__(
            provider=provider,
            name="Attacker",
            role=AgentRole.ATTACKER,
            system_prompt=ATTACKER_SYSTEM_PROMPT,
            web_search=web_search,
        )

    async def analyze(self, context: dict) -> AgentResponse:
        """Scan the contract for vulnerabilities."""
        contract_code = context.get("contract_code", "")

        prompt = SCAN_PROMPT_TEMPLATE.format(
            contract_code=contract_code,
            vulnerability_types=", ".join(VULNERABILITY_TYPES),
        )

        parsed = await self._send_message_json(prompt, include_history=False, temperature=settings.temp_attacker_scan)

        claims = self._extract_claims(parsed)

        return AgentResponse(
            agent_role=self.role,
            content=parsed.get("raw_content", str(parsed)),
            claims=claims,
            reasoning="Initial vulnerability scan completed",
            confidence=ConfidenceLevel.HIGH,
            metadata={
                "scan_type": "initial",
            },
        )

    async def respond_to_defense(self, context: dict) -> AgentResponse:
        """Respond to the Defender's arguments with a rebuttal or concession."""
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

        verdict = parsed.get("verdict", "REBUTTAL").upper()
        is_concession = "CONCEDE" in verdict
        confidence = self._parse_confidence_level(parsed.get("confidence"), default=ConfidenceLevel.MEDIUM)

        return AgentResponse(
            agent_role=self.role,
            content=parsed.get("reasoning", parsed.get("raw_content", str(parsed))),
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
        """Respond to the Judge's clarification question."""
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

    def _extract_claims(self, parsed: dict[str, Any]) -> list[VulnerabilityClaim]:
        """Extract VulnerabilityClaim objects from a parsed LLM response dict."""
        claims: list[VulnerabilityClaim] = []

        vuln_list = parsed.get("vulnerabilities", [])
        if not vuln_list and parsed.get("raw_content"):
            raw = parsed["raw_content"]
            # Try re-parsing JSON from raw content before falling back to line-by-line parser.
            # This handles cases where _parse_json_response failed on embedded escaping/markdown.
            try:
                brace_start = raw.find("{")
                brace_end = raw.rfind("}")
                if brace_start != -1 and brace_end > brace_start:
                    candidate = json.loads(raw[brace_start:brace_end + 1])
                    vuln_list = candidate.get("vulnerabilities", [])
            except Exception:
                pass
            if not vuln_list:
                vuln_list = self._fallback_parse_claims(raw)

        for item in vuln_list:
            claim = self._dict_to_claim(item)
            if claim:
                claims.append(claim)

        return claims

    def _dict_to_claim(self, data: dict[str, Any]) -> VulnerabilityClaim | None:
        """Convert a dict to a VulnerabilityClaim, returning None on failure."""
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
        """Extract vulnerability dicts from unstructured text when JSON parsing fails."""
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

        if current_claim and current_claim.get("vulnerability_type"):
            claims.append(current_claim)

        return claims
