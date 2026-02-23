"""
Baseline Agent for benchmarking purposes.

Performs a single-prompt vulnerability scan with no debate loop.
Used as the comparison baseline against the full multi-agent pipeline.
"""

import logging
from typing import Any

from src.agents.base_agent import BaseAgent
from src.knowledge.prompts.attacker import SCAN_PROMPT_TEMPLATE
from src.providers.base_provider import BaseLLMProvider

logger = logging.getLogger(__name__)

JSON_INSTRUCTION = (
    "\n\nIMPORTANT: You MUST respond with valid JSON only. "
    "Do not include any text outside the JSON object. "
    "Do not wrap the JSON in markdown code blocks."
)


class BaselineAgent:
    """
    Single-prompt vulnerability scanner used as a benchmark baseline.

    Sends one LLM call per contract using the same SCAN_PROMPT_TEMPLATE
    as the Attacker agent, but with no Defender rebuttal or Judge verdict.
    All findings are accepted as-is.
    """

    def __init__(self, provider: BaseLLMProvider) -> None:
        self.provider = provider

    async def scan(
        self,
        contract_code: str,
        contract_path: str,
        language: str = "solidity",
    ) -> list[dict[str, Any]]:
        """
        Scan a contract with a single LLM call.

        Args:
            contract_code: The smart contract source code
            contract_path: Path to the contract file (used in the prompt)
            language: Detected programming language

        Returns:
            List of raw vulnerability dicts from the LLM response.
            Returns an empty list on parse failure instead of raising.
        """
        prompt = SCAN_PROMPT_TEMPLATE.format(
            contract_path=contract_path,
            language=language,
            contract_code=contract_code,
        ) + JSON_INSTRUCTION

        try:
            content = await self.provider.complete_simple(prompt, temperature=0.3)
        except Exception as e:
            logger.error(f"Baseline scan LLM call failed for {contract_path}: {e}")
            return []

        parsed = BaseAgent._parse_json_response(content)

        if parsed.get("_parse_failed"):
            logger.warning(f"Baseline scan JSON parse failed for {contract_path}")
            return []

        return parsed.get("vulnerabilities", [])
