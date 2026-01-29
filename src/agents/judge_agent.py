"""
Judge Agent implementation.

The Judge Agent evaluates arguments from both the Attacker and Defender
to make final decisions about vulnerability claims.
"""

import re
from dataclasses import dataclass
from typing import Optional

from src.agents.base_agent import AgentResponse, AgentRole, BaseAgent, VulnerabilityClaim
from src.knowledge.prompts.judge import JUDGE_SYSTEM_PROMPT, JUDGMENT_PROMPT_TEMPLATE
from src.providers.base_provider import BaseLLMProvider


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
    """

    def __init__(self, provider: BaseLLMProvider):
        """
        Initialize the Judge Agent.

        Args:
            provider: LLM provider for generating responses
        """
        super().__init__(
            provider=provider,
            name="Judge",
            role=AgentRole.JUDGE,
            system_prompt=JUDGE_SYSTEM_PROMPT,
        )

    async def analyze(self, context: dict) -> AgentResponse:
        """
        Render a verdict on a vulnerability claim.

        Args:
            context: Dictionary containing:
                - contract_code: The smart contract source code
                - claim: The VulnerabilityClaim being judged
                - attacker_argument: The Attacker's full argument
                - defender_argument: The Defender's full argument
                - debate_history: Optional list of debate exchanges

        Returns:
            AgentResponse containing the verdict
        """
        contract_code = context.get("contract_code", "")
        claim = context.get("claim")
        attacker_arg = context.get("attacker_argument", "")
        defender_arg = context.get("defender_argument", "")
        debate_history = context.get("debate_history", [])

        if isinstance(claim, VulnerabilityClaim):
            claim_dict = claim.to_dict()
        else:
            claim_dict = claim

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

        response = await self._send_message(prompt, include_history=False, temperature=0.2)

        # Parse the verdict
        verdict = self._parse_verdict(response, claim_dict.get("id", "unknown"))

        return AgentResponse(
            agent_role=self.role,
            content=response,
            claims=[],
            reasoning=verdict.reasoning,
            metadata={
                "verdict": verdict.to_dict(),
                "is_valid": verdict.is_valid,
                "final_severity": verdict.severity,
                "judge_confidence": verdict.confidence,
            },
        )

    def _parse_verdict(self, response: str, claim_id: str) -> Verdict:
        """
        Parse the Judge's response to extract the verdict.

        Args:
            response: The raw LLM response
            claim_id: ID of the claim being judged

        Returns:
            Verdict object
        """
        # Default values
        is_valid = False
        severity = "medium"
        confidence = 0.5
        reasoning = ""
        recommendation = ""
        attacker_score = 0.5
        defender_score = 0.5

        response_upper = response.upper()

        # Determine validity
        if "VERDICT: VALID" in response_upper or "VERDICT: VULNERABLE" in response_upper:
            is_valid = True
        elif "VERDICT: INVALID" in response_upper or "VERDICT: NOT VULNERABLE" in response_upper:
            is_valid = False
        elif "GUILTY" in response_upper or "CONFIRMS VULNERABILITY" in response_upper:
            is_valid = True
        elif "NOT GUILTY" in response_upper or "NO VULNERABILITY" in response_upper:
            is_valid = False
        else:
            # Try to infer from content
            vuln_indicators = ["is vulnerable", "vulnerability exists", "confirms the", "valid vulnerability"]
            safe_indicators = ["is safe", "not vulnerable", "properly protected", "invalid claim"]
            
            vuln_count = sum(1 for ind in vuln_indicators if ind in response.lower())
            safe_count = sum(1 for ind in safe_indicators if ind in response.lower())
            is_valid = vuln_count > safe_count

        # Extract severity
        severity_match = re.search(
            r"SEVERITY[:\s]*(CRITICAL|HIGH|MEDIUM|LOW|INFO)",
            response_upper
        )
        if severity_match:
            severity = severity_match.group(1).lower()

        # Extract confidence
        conf_match = re.search(r"CONFIDENCE[:\s]*([0-9.]+)", response, re.IGNORECASE)
        if conf_match:
            try:
                conf = float(conf_match.group(1))
                if conf > 1:
                    conf = conf / 100
                confidence = max(0.0, min(1.0, conf))
            except ValueError:
                pass

        # Extract reasoning
        reasoning_match = re.search(
            r"REASONING[:\s]*(.+?)(?=RECOMMENDATION|SEVERITY|CONFIDENCE|ATTACKER_SCORE|$)",
            response,
            re.IGNORECASE | re.DOTALL
        )
        if reasoning_match:
            reasoning = reasoning_match.group(1).strip()
        else:
            # Use first paragraph as reasoning
            paragraphs = response.split("\n\n")
            if paragraphs:
                reasoning = paragraphs[0].strip()

        # Extract recommendation
        rec_match = re.search(
            r"RECOMMENDATION[:\s]*(.+?)(?=SEVERITY|CONFIDENCE|ATTACKER_SCORE|$)",
            response,
            re.IGNORECASE | re.DOTALL
        )
        if rec_match:
            recommendation = rec_match.group(1).strip()

        # Extract scores
        attacker_match = re.search(r"ATTACKER_SCORE[:\s]*([0-9.]+)", response, re.IGNORECASE)
        if attacker_match:
            try:
                attacker_score = float(attacker_match.group(1))
                if attacker_score > 1:
                    attacker_score = attacker_score / 100
            except ValueError:
                pass

        defender_match = re.search(r"DEFENDER_SCORE[:\s]*([0-9.]+)", response, re.IGNORECASE)
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
