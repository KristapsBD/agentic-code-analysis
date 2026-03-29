"""
Judge Agent implementation.

The Judge Agent evaluates arguments from both the Attacker and Defender
to make final decisions about vulnerability claims. It can request
a single clarification round from both sides when confidence is low.
"""

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
from src.config import settings
from src.providers.base_provider import BaseLLMProvider

logger = logging.getLogger(__name__)


@dataclass
class Verdict:
    """A verdict on a vulnerability claim."""

    claim_id: str
    is_valid: bool
    severity: str
    confidence: float
    reasoning: str
    recommendation: str
    attacker_score: float  # How convincing was the Attacker (0-1)
    defender_score: float  # How convincing was the Defender (0-1)

    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            "claim_id": self.claim_id,
            "is_valid": self.is_valid,
            "severity": self.severity,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "recommendation": self.recommendation,
            "attacker_score": self.attacker_score,
            "defender_score": self.defender_score,
        }


class JudgeAgent(BaseAgent):
    """
    Judge Agent that renders verdicts on vulnerability claims.

    This agent acts as an impartial arbiter, evaluating the arguments
    from both the Attacker and Defender to determine:
    1. Whether the vulnerability claim is valid
    2. The actual severity (may differ from Attacker's claim)
    3. Recommended actions

    When confidence is below a threshold, the Judge can request
    a single clarification round from both sides before rendering
    a final verdict.
    """

    def __init__(self, provider: BaseLLMProvider, web_search: bool = False):
        """
        Initialize the Judge Agent.

        Args:
            provider: LLM provider for generating responses
            web_search: Whether to enable built-in web search on every LLM call
        """
        super().__init__(
            provider=provider,
            name="Judge",
            role=AgentRole.JUDGE,
            system_prompt=JUDGE_SYSTEM_PROMPT,
            web_search=web_search,
        )

    async def analyze(self, context: dict) -> AgentResponse:
        """
        Render a verdict on a vulnerability claim.

        Returns an initial assessment. If the Judge's confidence is below
        a threshold and the response indicates needs_clarification, the
        orchestrator should call request_clarification() followed by
        render_final_verdict().

        Args:
            context: Dictionary containing:
                - contract_code: The smart contract source code
                - claim: The VulnerabilityClaim being judged
                - attacker_argument: The Attacker's full argument
                - defender_argument: The Defender's full argument
                - debate_history: Optional list of debate exchanges

        Returns:
            AgentResponse containing the verdict (or clarification request)
        """
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

        # Extract verdict from structured JSON response
        verdict = self._extract_verdict(parsed, claim_dict.get("id", "unknown"))
        needs_clarification = parsed.get("needs_clarification", False)
        clarification_question = parsed.get("clarification_question", "")

        return AgentResponse(
            agent_role=self.role,
            content=parsed.get("reasoning", str(parsed)),
            claims=[],
            reasoning=verdict.reasoning,
            confidence=verdict.confidence,
            metadata={
                "verdict": verdict.to_dict(),
                "is_valid": verdict.is_valid,
                "final_severity": verdict.severity,
                "judge_confidence": verdict.confidence,
                "needs_clarification": needs_clarification,
                "clarification_question": clarification_question,
            },
        )

    async def render_final_verdict(self, context: dict) -> AgentResponse:
        """
        Render a final verdict after receiving clarification responses.

        This method is called after the Judge requested clarification and
        both the Attacker and Defender have responded.

        Args:
            context: Dictionary containing:
                - contract_code: The smart contract source code
                - claim: The original vulnerability claim
                - original_question: The Judge's clarification question
                - attacker_clarification: Attacker's response to the question
                - defender_clarification: Defender's response to the question
                - attacker_argument: The Attacker's main argument
                - defender_argument: The Defender's main argument

        Returns:
            AgentResponse containing the final verdict
        """
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

        # Extract final verdict
        verdict = self._extract_verdict(parsed, claim_dict.get("id", "unknown"))

        return AgentResponse(
            agent_role=self.role,
            content=parsed.get("reasoning", str(parsed)),
            claims=[],
            reasoning=verdict.reasoning,
            confidence=verdict.confidence,
            metadata={
                "verdict": verdict.to_dict(),
                "is_valid": verdict.is_valid,
                "final_severity": verdict.severity,
                "judge_confidence": verdict.confidence,
                "is_final_after_clarification": True,
            },
        )

    def _extract_verdict(self, parsed: dict[str, Any], claim_id: str) -> Verdict:
        """
        Extract a Verdict from the parsed JSON response.

        Handles both structured JSON responses and fallback cases
        where JSON parsing may have partially failed.

        Args:
            parsed: Parsed JSON dictionary from the LLM response
            claim_id: ID of the claim being judged

        Returns:
            Verdict object
        """
        # If JSON parsing failed, try to infer from raw content
        if parsed.get("_parse_failed"):
            return self._fallback_parse_verdict(parsed.get("raw_content", ""), claim_id)

        # Extract verdict validity.
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
            # Fallback for unexpected strings: require an exact prefix match on "VALID"
            # that is not part of "INVALID"
            is_valid = verdict_str.startswith("VALID") and not verdict_str.startswith("INVALID")

        # Extract severity
        severity = parsed.get("severity", "medium")
        if isinstance(severity, str):
            severity = severity.lower()

        confidence = self._normalize_confidence(parsed.get("confidence"))
        attacker_score = self._normalize_confidence(parsed.get("attacker_score"))
        defender_score = self._normalize_confidence(parsed.get("defender_score"))

        return Verdict(
            claim_id=claim_id,
            is_valid=is_valid,
            severity=severity,
            confidence=confidence,
            reasoning=str(parsed.get("reasoning", "No detailed reasoning provided"))[:500],
            recommendation=str(parsed.get("recommendation", "Review and address as needed"))[:300],
            attacker_score=attacker_score,
            defender_score=defender_score,
        )

    def _fallback_parse_verdict(self, raw_content: str, claim_id: str) -> Verdict:
        """
        Fallback parser for when JSON parsing fails completely.

        Attempts to extract verdict information from unstructured text.

        Args:
            raw_content: Raw text content from the LLM
            claim_id: ID of the claim being judged

        Returns:
            Verdict object with best-effort extraction
        """
        response_upper = raw_content.upper()

        # Determine validity
        is_valid = False
        if "VERDICT: VALID" in response_upper or "VERDICT: VULNERABLE" in response_upper:
            is_valid = True
        elif "VERDICT: INVALID" in response_upper or "VERDICT: NOT VULNERABLE" in response_upper:
            is_valid = False
        elif "VERDICT: NOT_VULNERABLE" in response_upper:
            is_valid = False
        else:
            vuln_indicators = ["is vulnerable", "vulnerability exists", "confirms the", "valid vulnerability"]
            safe_indicators = ["is safe", "not vulnerable", "properly protected", "invalid claim"]
            vuln_count = sum(1 for ind in vuln_indicators if ind in raw_content.lower())
            safe_count = sum(1 for ind in safe_indicators if ind in raw_content.lower())
            is_valid = vuln_count > safe_count

        # Extract severity
        severity = "medium"
        severity_match = re.search(
            r"SEVERITY[:\s]*(CRITICAL|HIGH|MEDIUM|LOW|INFO)",
            response_upper
        )
        if severity_match:
            severity = severity_match.group(1).lower()

        # Extract confidence
        confidence = 0.5
        conf_match = re.search(r"CONFIDENCE[:\s]*([0-9.]+)", raw_content, re.IGNORECASE)
        if conf_match:
            try:
                conf = float(conf_match.group(1))
                if conf > 1:
                    conf = conf / 100
                confidence = max(0.0, min(1.0, conf))
            except ValueError:
                pass

        # Extract reasoning
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

        # Extract recommendation
        recommendation = ""
        rec_match = re.search(
            r"RECOMMENDATION[:\s]*(.+?)(?=SEVERITY|CONFIDENCE|ATTACKER_SCORE|$)",
            raw_content,
            re.IGNORECASE | re.DOTALL
        )
        if rec_match:
            recommendation = rec_match.group(1).strip()

        # Extract scores
        attacker_score = 0.5
        defender_score = 0.5
        attacker_match = re.search(r"ATTACKER_SCORE[:\s]*([0-9.]+)", raw_content, re.IGNORECASE)
        if attacker_match:
            try:
                attacker_score = float(attacker_match.group(1))
                if attacker_score > 1:
                    attacker_score = attacker_score / 100
            except ValueError:
                pass

        defender_match = re.search(r"DEFENDER_SCORE[:\s]*([0-9.]+)", raw_content, re.IGNORECASE)
        if defender_match:
            try:
                defender_score = float(defender_match.group(1))
                if defender_score > 1:
                    defender_score = defender_score / 100
            except ValueError:
                pass

        return Verdict(
            claim_id=claim_id,
            is_valid=is_valid,
            severity=severity,
            confidence=confidence,
            reasoning=reasoning[:500] if reasoning else "No detailed reasoning provided",
            recommendation=recommendation[:300] if recommendation else "Review and address as needed",
            attacker_score=attacker_score,
            defender_score=defender_score,
        )
