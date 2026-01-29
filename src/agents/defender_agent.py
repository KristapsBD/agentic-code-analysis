"""
Defender Agent implementation.

The Defender Agent acts as a developer advocate, reviewing vulnerability
claims and providing counter-arguments when claims are invalid or exaggerated.
"""

from src.agents.base_agent import AgentResponse, AgentRole, BaseAgent, VulnerabilityClaim
from src.knowledge.prompts.defender import DEFENDER_SYSTEM_PROMPT, DEFENSE_PROMPT_TEMPLATE
from src.providers.base_provider import BaseLLMProvider


class DefenderAgent(BaseAgent):
    """
    Defender Agent that verifies vulnerability claims.

    This agent takes the role of a developer, critically examining
    vulnerability claims and providing counter-arguments. It looks for:
    - Existing mitigations (modifiers, checks, guards)
    - Context that invalidates the claim
    - Misunderstandings of the code's intent
    """

    def __init__(self, provider: BaseLLMProvider):
        """
        Initialize the Defender Agent.

        Args:
            provider: LLM provider for generating responses
        """
        super().__init__(
            provider=provider,
            name="Defender",
            role=AgentRole.DEFENDER,
            system_prompt=DEFENDER_SYSTEM_PROMPT,
        )

    async def analyze(self, context: dict) -> AgentResponse:
        """
        Review a vulnerability claim and provide a defense.

        Args:
            context: Dictionary containing:
                - contract_code: The smart contract source code
                - claim: The VulnerabilityClaim to review
                - contract_path: Path to the contract file (optional)

        Returns:
            AgentResponse containing the defense argument
        """
        contract_code = context.get("contract_code", "")
        claim = context.get("claim")
        contract_path = context.get("contract_path", "unknown")

        if isinstance(claim, VulnerabilityClaim):
            claim_dict = claim.to_dict()
        else:
            claim_dict = claim

        prompt = DEFENSE_PROMPT_TEMPLATE.format(
            contract_code=contract_code,
            vulnerability_type=claim_dict.get("vulnerability_type", "Unknown"),
            severity=claim_dict.get("severity", "Unknown"),
            location=claim_dict.get("location", "Unknown"),
            description=claim_dict.get("description", "No description"),
            evidence=claim_dict.get("evidence", "No evidence provided"),
            attacker_confidence=claim_dict.get("confidence", 0.5),
        )

        response = await self._send_message(prompt, include_history=False, temperature=0.3)

        # Parse the defense response
        defense_verdict, confidence = self._parse_defense(response)

        return AgentResponse(
            agent_role=self.role,
            content=response,
            claims=[],
            reasoning=defense_verdict,
            metadata={
                "claim_id": claim_dict.get("id", "unknown"),
                "defense_verdict": defense_verdict,
                "defense_confidence": confidence,
                "contract_path": contract_path,
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

        prompt = f"""The Attacker has provided a rebuttal to your defense.

VULNERABILITY CLAIM:
- Type: {claim.get('vulnerability_type', 'Unknown')}
- Location: {claim.get('location', 'Unknown')}
- Description: {claim.get('description', 'No description')}

YOUR ORIGINAL DEFENSE:
{original_defense}

ATTACKER'S REBUTTAL:
{rebuttal}

Analyze the rebuttal and respond:
1. If the Attacker raises valid new evidence, ACKNOWLEDGE the vulnerability
2. If your defense still holds, MAINTAIN your position with clarification

Format your response as:
VERDICT: [ACKNOWLEDGE_VULNERABILITY or MAINTAIN_DEFENSE]
REASONING: [Your detailed analysis]
FINAL_ASSESSMENT: [Your final opinion on the validity of this claim]
CONFIDENCE: [0.0-1.0 that the code is SAFE]"""

        response = await self._send_message(prompt, include_history=True, temperature=0.3)

        # Determine verdict
        acknowledges_vuln = "ACKNOWLEDGE" in response.upper()[:100]

        return AgentResponse(
            agent_role=self.role,
            content=response,
            claims=[],
            reasoning="Acknowledges vulnerability" if acknowledges_vuln else "Maintains defense",
            metadata={
                "claim_id": claim.get("id", "unknown"),
                "acknowledges_vulnerability": acknowledges_vuln,
            },
        )

    def _parse_defense(self, response: str) -> tuple[str, float]:
        """
        Parse the defense response to extract verdict and confidence.

        Args:
            response: The raw LLM response

        Returns:
            Tuple of (verdict string, confidence float)
        """
        verdict = "unknown"
        confidence = 0.5

        response_upper = response.upper()

        # Determine verdict
        if "INVALID" in response_upper or "NOT VULNERABLE" in response_upper:
            verdict = "invalid_claim"
        elif "VALID" in response_upper or "VULNERABLE" in response_upper:
            verdict = "valid_vulnerability"
        elif "PARTIAL" in response_upper or "MITIGATED" in response_upper:
            verdict = "partially_mitigated"
        elif "ACKNOWLEDGE" in response_upper:
            verdict = "valid_vulnerability"
        else:
            verdict = "needs_review"

        # Extract confidence
        import re

        conf_patterns = [
            r"CONFIDENCE[:\s]*([0-9.]+)",
            r"confidence[:\s]*([0-9.]+)",
            r"([0-9]+)%\s*confident",
        ]

        for pattern in conf_patterns:
            match = re.search(pattern, response)
            if match:
                try:
                    conf = float(match.group(1))
                    if conf > 1:
                        conf = conf / 100
                    confidence = max(0.0, min(1.0, conf))
                    break
                except ValueError:
                    continue

        return verdict, confidence
