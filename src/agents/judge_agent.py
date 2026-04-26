"""Judge Agent — evaluates Attacker/Defender arguments and renders verdicts."""

import logging
import re
from dataclasses import dataclass
from typing import Any

from src.agents.base_agent import AgentResponse, AgentRole, BaseAgent, VulnerabilityClaim
from src.knowledge.prompts.judge import (
    CLARIFICATION_PROMPT_TEMPLATE,
    JUDGE_SYSTEM_PROMPT,
    JUDGMENT_PROMPT_TEMPLATE,
)
from src.config import ConfidenceLevel, settings
from src.providers.base_provider import BaseLLMProvider

logger = logging.getLogger(__name__)


@dataclass
class Verdict:
    claim_id: str
    is_valid: bool
    severity: str
    confidence: ConfidenceLevel
    reasoning: str
    recommendation: str
    attacker_score: float  # How convincing was the Attacker (0-1)
    defender_score: float  # How convincing was the Defender (0-1)

    def to_dict(self) -> dict:
        return {
            "claim_id": self.claim_id,
            "is_valid": self.is_valid,
            "severity": self.severity,
            "confidence": self.confidence.value,
            "reasoning": self.reasoning,
            "recommendation": self.recommendation,
            "attacker_score": self.attacker_score,
            "defender_score": self.defender_score,
        }


class JudgeAgent(BaseAgent):
    """Impartial arbiter that evaluates Attacker/Defender arguments and renders verdicts."""

    def __init__(self, provider: BaseLLMProvider, web_search: bool = False):
        super().__init__(
            provider=provider,
            name="Judge",
            role=AgentRole.JUDGE,
            system_prompt=JUDGE_SYSTEM_PROMPT,
            web_search=web_search,
        )

    async def analyze(self, context: dict) -> AgentResponse:
        """Render an initial verdict; sets needs_clarification if confidence is low."""
        contract_code = context.get("contract_code", "")
        claim = context.get("claim")
        attacker_arg = context.get("attacker_argument", "")
        defender_arg = context.get("defender_argument", "")
        debate_history = context.get("debate_history", [])

        claim_dict = self._to_claim_dict(claim)

        # Format debate history if available
        debate_summary = ""
        if debate_history:
            debate_summary = "\n\nDEBATE HISTORY:\n"
            for i, exchange in enumerate(debate_history, 1):
                debate_summary += f"\n--- Round {i} ---\n"
                debate_summary += f"Attacker: {exchange.get('attacker', 'N/A')}\n"
                debate_summary += f"Defender: {exchange.get('defender', 'N/A')}\n"

        prompt = JUDGMENT_PROMPT_TEMPLATE.format(
            contract_code=contract_code,
            vulnerability_type=claim_dict.get("vulnerability_type", "Unknown"),
            severity=claim_dict.get("severity", "Unknown"),
            location=claim_dict.get("location", "Unknown"),
            description=claim_dict.get("description", "No description"),
            evidence=claim_dict.get("evidence", "No evidence"),
            attacker_argument=attacker_arg,
            defender_argument=defender_arg,
            debate_history=debate_summary,
        )

        parsed = await self._send_message_json(prompt, include_history=False, temperature=settings.temp_judge)

        verdict = self._extract_verdict(parsed, claim_dict.get("id", "unknown"))
        needs_clarification = parsed.get("needs_clarification", False)
        clarification_question = parsed.get("clarification_question", "")

        return AgentResponse(
            agent_role=self.role,
            content=parsed.get("reasoning", parsed.get("raw_content", str(parsed))),
            claims=[],
            reasoning=verdict.reasoning,
            confidence=verdict.confidence,
            metadata={
                "verdict": verdict.to_dict(),
                "is_valid": verdict.is_valid,
                "final_severity": verdict.severity,
                "judge_confidence": verdict.confidence.value,
                "needs_clarification": needs_clarification,
                "clarification_question": clarification_question,
            },
        )

    async def render_final_verdict(self, context: dict) -> AgentResponse:
        """Render a final verdict after receiving clarification from both sides."""
        contract_code = context.get("contract_code", "")
        claim = context.get("claim", {})
        original_question = context.get("original_question", "")
        attacker_clarification = context.get("attacker_clarification", "")
        defender_clarification = context.get("defender_clarification", "")
        attacker_argument = context.get("attacker_argument", "")
        defender_argument = context.get("defender_argument", "")

        claim_dict = self._to_claim_dict(claim)

        prompt = CLARIFICATION_PROMPT_TEMPLATE.format(
            contract_code=contract_code,
            vulnerability_type=claim_dict.get("vulnerability_type", "Unknown"),
            location=claim_dict.get("location", "Unknown"),
            description=claim_dict.get("description", "No description"),
            original_question=original_question,
            attacker_clarification=attacker_clarification,
            defender_clarification=defender_clarification,
            attacker_argument=attacker_argument,
            defender_argument=defender_argument,
        )

        parsed = await self._send_message_json(prompt, include_history=False, temperature=settings.temp_judge)

        verdict = self._extract_verdict(parsed, claim_dict.get("id", "unknown"))

        return AgentResponse(
            agent_role=self.role,
            content=parsed.get("reasoning", parsed.get("raw_content", str(parsed))),
            claims=[],
            reasoning=verdict.reasoning,
            confidence=verdict.confidence,
            metadata={
                "verdict": verdict.to_dict(),
                "is_valid": verdict.is_valid,
                "final_severity": verdict.severity,
                "judge_confidence": verdict.confidence.value,
                "is_final_after_clarification": True,
            },
        )

    def _extract_verdict(self, parsed: dict[str, Any], claim_id: str) -> Verdict:
        """Extract a Verdict from a parsed LLM response, falling back to raw text parsing."""
        if parsed.get("_parse_failed"):
            return self._fallback_parse_verdict(parsed.get("raw_content", ""), claim_id)

        # Use an explicit allowlist to avoid substring false-matches
        # (e.g. "VALID" in "INVALID" is True in Python).
        verdict_str = parsed.get("verdict", "NOT_VULNERABLE").upper().strip()
        _VALID_VERDICTS = {"VALID_VULNERABILITY", "VALID", "VULNERABLE", "CONFIRMED"}
        _INVALID_VERDICTS = {"NOT_VULNERABLE", "NOT VULNERABLE", "INVALID", "NOT_VALID", "INVALID_CLAIM"}
        if verdict_str in _VALID_VERDICTS:
            is_valid = True
        elif verdict_str in _INVALID_VERDICTS:
            is_valid = False
        else:
            # Fallback for unexpected strings: exact prefix match, not "INVALID"
            is_valid = verdict_str.startswith("VALID") and not verdict_str.startswith("INVALID")

        severity = parsed.get("severity", "medium")
        if isinstance(severity, str):
            severity = severity.lower()

        confidence = self._parse_confidence_level(parsed.get("confidence"))
        attacker_score = self._normalize_confidence(parsed.get("attacker_score"))
        defender_score = self._normalize_confidence(parsed.get("defender_score"))

        return Verdict(
            claim_id=claim_id,
            is_valid=is_valid,
            severity=severity,
            confidence=confidence,
            reasoning=str(parsed.get("reasoning", "No detailed reasoning provided")),
            recommendation=str(parsed.get("recommendation", "Review and address as needed")),
            attacker_score=attacker_score,
            defender_score=defender_score,
        )

    def _fallback_parse_verdict(self, raw_content: str, claim_id: str) -> Verdict:
        """Best-effort verdict extraction from unstructured text when JSON parsing fails."""
        response_upper = raw_content.upper()

        is_valid = False
        raw_lower = raw_content.lower()
        if "verdict: valid" in raw_lower or "verdict: vulnerable" in raw_lower:
            is_valid = True
        elif '"verdict": "valid' in raw_lower or "'verdict': 'valid" in raw_lower:
            is_valid = True
        elif "verdict: invalid" in raw_lower or "verdict: not vulnerable" in raw_lower or "verdict: not_vulnerable" in raw_lower:
            is_valid = False
        elif '"verdict": "not_vulnerable' in raw_lower or '"verdict": "invalid' in raw_lower:
            is_valid = False
        else:
            vuln_indicators = ["is vulnerable", "vulnerability exists", "confirms the", "valid vulnerability"]
            safe_indicators = ["is safe", "not vulnerable", "properly protected", "invalid claim"]
            vuln_count = sum(1 for ind in vuln_indicators if ind in raw_content.lower())
            safe_count = sum(1 for ind in safe_indicators if ind in raw_content.lower())
            is_valid = vuln_count > safe_count

        severity = "medium"
        severity_match = re.search(
            r"SEVERITY[:\s]*(CRITICAL|HIGH|MEDIUM|LOW|INFO)",
            response_upper
        )
        if severity_match:
            severity = severity_match.group(1).lower()

        confidence = ConfidenceLevel.MEDIUM
        conf_match = re.search(r"CONFIDENCE[:\s]*(HIGH|MEDIUM|LOW)", raw_content, re.IGNORECASE)
        if conf_match:
            confidence = self._parse_confidence_level(conf_match.group(1))

        reasoning = ""
        reasoning_match = re.search(
            r"REASONING[:\s]*(.+?)(?=RECOMMENDATION|SEVERITY|CONFIDENCE|ATTACKER_SCORE|$)",
            raw_content,
            re.IGNORECASE | re.DOTALL
        )
        if reasoning_match:
            reasoning = reasoning_match.group(1).strip()
        else:
            paragraphs = raw_content.split("\n\n")
            if paragraphs:
                reasoning = paragraphs[0].strip()

        recommendation = ""
        rec_match = re.search(
            r"RECOMMENDATION[:\s]*(.+?)(?=SEVERITY|CONFIDENCE|ATTACKER_SCORE|$)",
            raw_content,
            re.IGNORECASE | re.DOTALL
        )
        if rec_match:
            recommendation = rec_match.group(1).strip()

        attacker_match = re.search(r"ATTACKER_SCORE[:\s]*([0-9.]+)", raw_content, re.IGNORECASE)
        attacker_score = self._normalize_confidence(attacker_match.group(1) if attacker_match else None)

        defender_match = re.search(r"DEFENDER_SCORE[:\s]*([0-9.]+)", raw_content, re.IGNORECASE)
        defender_score = self._normalize_confidence(defender_match.group(1) if defender_match else None)

        return Verdict(
            claim_id=claim_id,
            is_valid=is_valid,
            severity=severity,
            confidence=confidence,
            reasoning=reasoning if reasoning else "No detailed reasoning provided",
            recommendation=recommendation if recommendation else "Review and address as needed",
            attacker_score=attacker_score,
            defender_score=defender_score,
        )
