"""
Attacker Agent implementation.

The Attacker Agent aggressively scans smart contract code for potential
vulnerabilities, acting as a security auditor trying to find flaws.
"""

import json
import re
import uuid
from typing import Any

from src.agents.base_agent import AgentResponse, AgentRole, BaseAgent, VulnerabilityClaim
from src.knowledge.prompts.attacker import ATTACKER_SYSTEM_PROMPT, SCAN_PROMPT_TEMPLATE
from src.providers.base_provider import BaseLLMProvider


class AttackerAgent(BaseAgent):
    """
    Attacker Agent that scans for vulnerabilities.

    This agent takes an aggressive stance, flagging any code patterns
    that could potentially be exploited. It prioritizes sensitivity
    over specificity (better to flag a false positive than miss a real bug).
    """

    def __init__(self, provider: BaseLLMProvider):
        """
        Initialize the Attacker Agent.

        Args:
            provider: LLM provider for generating responses
        """
        super().__init__(
            provider=provider,
            name="Attacker",
            role=AgentRole.ATTACKER,
            system_prompt=ATTACKER_SYSTEM_PROMPT,
        )

    async def analyze(self, context: dict) -> AgentResponse:
        """
        Scan the contract for vulnerabilities.

        Args:
            context: Dictionary containing:
                - contract_code: The smart contract source code
                - contract_path: Path to the contract file
                - language: Detected programming language (optional)

        Returns:
            AgentResponse containing vulnerability claims
        """
        contract_code = context.get("contract_code", "")
        contract_path = context.get("contract_path", "unknown")
        language = context.get("language", "solidity")

        prompt = SCAN_PROMPT_TEMPLATE.format(
            contract_path=contract_path,
            language=language,
            contract_code=contract_code,
        )

        response = await self._send_message(prompt, include_history=False, temperature=0.3)

        # Parse the response to extract claims
        claims = self._parse_vulnerability_claims(response)

        return AgentResponse(
            agent_role=self.role,
            content=response,
            claims=claims,
            reasoning="Initial vulnerability scan completed",
            metadata={
                "contract_path": contract_path,
                "language": language,
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

        prompt = f"""The Defender has responded to your vulnerability claim.

ORIGINAL CLAIM:
- Type: {claim.get('vulnerability_type', 'Unknown')}
- Location: {claim.get('location', 'Unknown')}
- Description: {claim.get('description', 'No description')}

DEFENDER'S ARGUMENT:
{defense}

Analyze the Defender's argument and respond:
1. If their defense is valid, CONCEDE by starting with "CONCEDE:"
2. If you still believe the vulnerability exists, provide a REBUTTAL with additional evidence

Format your response as:
VERDICT: [REBUTTAL or CONCEDE]
REASONING: [Your detailed reasoning]
ADDITIONAL_EVIDENCE: [Any new evidence or code analysis, if rebutting]
CONFIDENCE: [0.0-1.0]"""

        response = await self._send_message(prompt, include_history=True, temperature=0.3)

        # Determine if this is a rebuttal or concession
        is_concession = "CONCEDE" in response.upper()[:50]

        return AgentResponse(
            agent_role=self.role,
            content=response,
            claims=[],
            reasoning="Rebuttal" if not is_concession else "Concession",
            metadata={
                "claim_id": claim.get("id", "unknown"),
                "is_concession": is_concession,
            },
        )

    def _parse_vulnerability_claims(self, response: str) -> list[VulnerabilityClaim]:
        """
        Parse the LLM response to extract vulnerability claims.

        Args:
            response: The raw LLM response

        Returns:
            List of VulnerabilityClaim objects
        """
        claims = []

        # Try to extract JSON blocks from the response
        json_pattern = r"```json\s*([\s\S]*?)\s*```"
        json_matches = re.findall(json_pattern, response)

        for json_str in json_matches:
            try:
                data = json.loads(json_str)
                if isinstance(data, list):
                    for item in data:
                        claim = self._dict_to_claim(item)
                        if claim:
                            claims.append(claim)
                elif isinstance(data, dict):
                    if "vulnerabilities" in data:
                        for item in data["vulnerabilities"]:
                            claim = self._dict_to_claim(item)
                            if claim:
                                claims.append(claim)
                    else:
                        claim = self._dict_to_claim(data)
                        if claim:
                            claims.append(claim)
            except json.JSONDecodeError:
                continue

        # If no JSON found, try to parse structured text
        if not claims:
            claims = self._parse_text_format(response)

        return claims

    def _dict_to_claim(self, data: dict[str, Any]) -> VulnerabilityClaim | None:
        """Convert a dictionary to a VulnerabilityClaim."""
        try:
            return VulnerabilityClaim(
                id=data.get("id", str(uuid.uuid4())[:8]),
                vulnerability_type=data.get("type", data.get("vulnerability_type", "Unknown")),
                severity=data.get("severity", "medium").lower(),
                location=data.get("location", data.get("function", "Unknown")),
                description=data.get("description", "No description provided"),
                evidence=data.get("evidence", data.get("code_snippet", "")),
                confidence=float(data.get("confidence", 0.7)),
            )
        except (KeyError, ValueError, TypeError):
            return None

    def _parse_text_format(self, response: str) -> list[VulnerabilityClaim]:
        """
        Parse vulnerability claims from text format.

        Looks for patterns like:
        - VULNERABILITY: <type>
        - SEVERITY: <level>
        - LOCATION: <location>
        """
        claims = []
        current_claim: dict[str, Any] = {}

        lines = response.split("\n")
        for line in lines:
            line = line.strip()

            if line.upper().startswith("VULNERABILITY:") or line.upper().startswith("TYPE:"):
                if current_claim and current_claim.get("vulnerability_type"):
                    claim = self._dict_to_claim(current_claim)
                    if claim:
                        claims.append(claim)
                    current_claim = {}
                current_claim["vulnerability_type"] = line.split(":", 1)[1].strip()

            elif line.upper().startswith("SEVERITY:"):
                current_claim["severity"] = line.split(":", 1)[1].strip()

            elif line.upper().startswith("LOCATION:") or line.upper().startswith("FUNCTION:"):
                current_claim["location"] = line.split(":", 1)[1].strip()

            elif line.upper().startswith("DESCRIPTION:"):
                current_claim["description"] = line.split(":", 1)[1].strip()

            elif line.upper().startswith("EVIDENCE:") or line.upper().startswith("CODE:"):
                current_claim["evidence"] = line.split(":", 1)[1].strip()

            elif line.upper().startswith("CONFIDENCE:"):
                try:
                    conf_str = line.split(":", 1)[1].strip().replace("%", "")
                    conf = float(conf_str)
                    if conf > 1:
                        conf = conf / 100
                    current_claim["confidence"] = conf
                except ValueError:
                    current_claim["confidence"] = 0.7

        # Don't forget the last claim
        if current_claim and current_claim.get("vulnerability_type"):
            claim = self._dict_to_claim(current_claim)
            if claim:
                claims.append(claim)

        return claims
