"""
Debate Manager for orchestrating agent interactions.

Coordinates the Attacker, Defender, and Judge agents through
structured debate rounds to analyze smart contracts.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from rich.console import Console

from src.agents.attacker_agent import AttackerAgent
from src.agents.base_agent import VulnerabilityClaim
from src.agents.defender_agent import DefenderAgent
from src.agents.judge_agent import JudgeAgent, Verdict
from src.orchestration.conversation import Conversation, TurnType
from src.parsers.language_detector import LanguageDetector
from src.providers.base_provider import BaseLLMProvider

logger = logging.getLogger(__name__)


@dataclass
class ClaimResult:
    """Result of analyzing a single vulnerability claim."""

    claim: VulnerabilityClaim
    verdict: Verdict
    debate_rounds: int
    attacker_conceded: bool = False
    defender_acknowledged: bool = False
    final_assessment: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            "claim": self.claim.to_dict(),
            "verdict": self.verdict.to_dict(),
            "debate_rounds": self.debate_rounds,
            "attacker_conceded": self.attacker_conceded,
            "defender_acknowledged": self.defender_acknowledged,
            "final_assessment": self.final_assessment,
        }


@dataclass
class DebateResult:
    """Complete result of a contract analysis."""

    contract_path: str
    contract_language: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    initial_claims: list[VulnerabilityClaim] = field(default_factory=list)
    claim_results: list[ClaimResult] = field(default_factory=list)
    conversation: Optional[Conversation] = None
    total_tokens_used: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_vulnerabilities(self) -> int:
        """Total number of initial claims."""
        return len(self.initial_claims)

    @property
    def confirmed_vulnerabilities(self) -> int:
        """Number of claims confirmed by the Judge."""
        return sum(1 for r in self.claim_results if r.verdict.is_valid)

    @property
    def rejected_claims(self) -> int:
        """Number of claims rejected by the Judge."""
        return sum(1 for r in self.claim_results if not r.verdict.is_valid)

    @property
    def critical_count(self) -> int:
        """Number of confirmed critical vulnerabilities."""
        return sum(
            1 for r in self.claim_results
            if r.verdict.is_valid and r.verdict.severity == "critical"
        )

    @property
    def high_count(self) -> int:
        """Number of confirmed high severity vulnerabilities."""
        return sum(
            1 for r in self.claim_results
            if r.verdict.is_valid and r.verdict.severity == "high"
        )

    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            "contract_path": self.contract_path,
            "contract_language": self.contract_language,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_vulnerabilities": self.total_vulnerabilities,
            "confirmed_vulnerabilities": self.confirmed_vulnerabilities,
            "rejected_claims": self.rejected_claims,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "initial_claims": [c.to_dict() for c in self.initial_claims],
            "claim_results": [r.to_dict() for r in self.claim_results],
            "total_tokens_used": self.total_tokens_used,
            "metadata": self.metadata,
        }


class DebateManager:
    """
    Orchestrates the adversarial debate between agents.

    Manages the flow of analysis:
    1. Attacker scans for vulnerabilities
    2. For each claim, Defender provides counter-argument
    3. Optional: Multiple rounds of rebuttal
    4. Judge renders verdict
    """

    def __init__(
        self,
        provider: BaseLLMProvider,
        max_rounds: int = 2,
        verbose: bool = False,
        console: Optional[Console] = None,
    ):
        """
        Initialize the Debate Manager.

        Args:
            provider: LLM provider for agent interactions
            max_rounds: Maximum debate rounds per claim
            verbose: Whether to print verbose output
            console: Rich console for output (optional)
        """
        self.provider = provider
        self.max_rounds = max_rounds
        self.verbose = verbose
        self.console = console or Console()

        logger.debug(f"Initializing DebateManager with provider={provider.provider_name}, max_rounds={max_rounds}")
        
        # Initialize agents
        logger.debug("Creating Attacker Agent")
        self.attacker = AttackerAgent(provider)
        logger.debug("Creating Defender Agent")
        self.defender = DefenderAgent(provider)
        logger.debug("Creating Judge Agent")
        self.judge = JudgeAgent(provider)

        # Language detector
        self.language_detector = LanguageDetector()
        logger.debug("DebateManager initialization complete")

    async def run_debate(
        self,
        contract_code: str,
        contract_path: str,
    ) -> dict:
        """
        Run a complete adversarial debate on a contract.

        Args:
            contract_code: The smart contract source code
            contract_path: Path to the contract file

        Returns:
            Dictionary containing the complete analysis results
        """
        # Initialize result tracking
        detected_language = self.language_detector.detect(contract_code, contract_path)
        logger.info(f"Detected contract language: {detected_language}")
        
        result = DebateResult(
            contract_path=contract_path,
            contract_language=detected_language,
            started_at=datetime.now(),
        )
        conversation = Conversation(contract_path)
        result.conversation = conversation

        # Phase 1: Attacker scans for vulnerabilities
        logger.info("Phase 1: Attacker Agent scanning for vulnerabilities")
        if self.verbose:
            self.console.print("[bold blue]Phase 1:[/bold blue] Attacker scanning...")

        logger.debug(f"Sending contract to Attacker Agent (length: {len(contract_code)} chars)")
        attacker_response = await self.attacker.analyze({
            "contract_code": contract_code,
            "contract_path": contract_path,
            "language": result.contract_language,
        })
        logger.debug(f"Attacker response received: {attacker_response.tokens_used} tokens")

        conversation.add_turn(
            TurnType.ATTACK,
            self.attacker.name,
            attacker_response.content,
        )

        result.initial_claims = attacker_response.claims
        logger.info(f"Attacker Agent found {len(result.initial_claims)} potential vulnerabilities")

        if self.verbose:
            self.console.print(
                f"[green]Found {len(result.initial_claims)} potential vulnerabilities[/green]"
            )

        # Phase 2-4: Debate each claim
        logger.info(f"Phase 2-4: Starting debate rounds for {len(result.initial_claims)} claims")
        for i, claim in enumerate(result.initial_claims):
            logger.info(f"Debating claim {i+1}/{len(result.initial_claims)}: {claim.vulnerability_type}")
            if self.verbose:
                self.console.print(
                    f"\n[bold blue]Debating claim {i+1}/{len(result.initial_claims)}:[/bold blue] "
                    f"{claim.vulnerability_type}"
                )

            claim_result = await self._debate_claim(
                claim=claim,
                contract_code=contract_code,
                conversation=conversation,
            )
            result.claim_results.append(claim_result)

        # Finalize
        result.completed_at = datetime.now()
        result.metadata["provider"] = self.provider.provider_name
        result.metadata["model"] = self.provider.model
        result.metadata["max_rounds"] = self.max_rounds

        return result.to_dict()

    async def _debate_claim(
        self,
        claim: VulnerabilityClaim,
        contract_code: str,
        conversation: Conversation,
    ) -> ClaimResult:
        """
        Run a debate on a single vulnerability claim.

        Args:
            claim: The vulnerability claim to debate
            contract_code: The contract source code
            conversation: Conversation tracker

        Returns:
            ClaimResult with verdict and debate details
        """
        attacker_conceded = False
        defender_acknowledged = False
        rounds_completed = 0

        # Initial defender response
        defender_response = await self.defender.analyze({
            "contract_code": contract_code,
            "claim": claim,
        })

        conversation.add_turn(
            TurnType.DEFENSE,
            self.defender.name,
            defender_response.content,
            claim_id=claim.id,
        )

        attacker_argument = claim.description + "\n" + claim.evidence
        defender_argument = defender_response.content

        # Multi-round debate if enabled
        debate_history = []
        for round_num in range(1, self.max_rounds + 1):
            rounds_completed = round_num

            if self.verbose:
                self.console.print(f"  Round {round_num}/{self.max_rounds}")

            # Attacker rebuttal
            rebuttal_response = await self.attacker.respond_to_defense({
                "original_claim": claim.to_dict(),
                "defense_argument": defender_argument,
            })

            conversation.add_turn(
                TurnType.REBUTTAL,
                self.attacker.name,
                rebuttal_response.content,
                claim_id=claim.id,
            )

            # Check if attacker conceded
            if rebuttal_response.metadata.get("is_concession"):
                attacker_conceded = True
                if self.verbose:
                    self.console.print("  [yellow]Attacker conceded[/yellow]")
                break

            # Defender responds to rebuttal
            defender_rebuttal = await self.defender.respond_to_rebuttal({
                "original_claim": claim.to_dict(),
                "original_defense": defender_argument,
                "rebuttal": rebuttal_response.content,
            })

            conversation.add_turn(
                TurnType.DEFENSE,
                self.defender.name,
                defender_rebuttal.content,
                claim_id=claim.id,
            )

            # Check if defender acknowledged vulnerability
            if defender_rebuttal.metadata.get("acknowledges_vulnerability"):
                defender_acknowledged = True
                if self.verbose:
                    self.console.print("  [yellow]Defender acknowledged vulnerability[/yellow]")
                break

            # Record debate round
            debate_history.append({
                "attacker": rebuttal_response.content,
                "defender": defender_rebuttal.content,
            })

            # Update arguments for next round
            attacker_argument = rebuttal_response.content
            defender_argument = defender_rebuttal.content

        # Add debate round to conversation
        conversation.add_debate_round(
            claim_id=claim.id,
            attacker_argument=attacker_argument,
            defender_argument=defender_argument,
        )

        # Judge renders verdict
        if self.verbose:
            self.console.print("  [bold]Judge rendering verdict...[/bold]")

        judge_response = await self.judge.analyze({
            "contract_code": contract_code,
            "claim": claim,
            "attacker_argument": attacker_argument,
            "defender_argument": defender_argument,
            "debate_history": debate_history,
        })

        conversation.add_turn(
            TurnType.JUDGMENT,
            self.judge.name,
            judge_response.content,
            claim_id=claim.id,
        )

        # Extract verdict
        verdict_dict = judge_response.metadata.get("verdict", {})
        verdict = Verdict(
            claim_id=claim.id,
            is_valid=verdict_dict.get("is_valid", False),
            severity=verdict_dict.get("severity", "medium"),
            confidence=verdict_dict.get("confidence", 0.5),
            reasoning=verdict_dict.get("reasoning", ""),
            recommendation=verdict_dict.get("recommendation", ""),
            attacker_score=verdict_dict.get("attacker_score", 0.5),
            defender_score=verdict_dict.get("defender_score", 0.5),
        )

        if self.verbose:
            status = "[green]VALID[/green]" if verdict.is_valid else "[red]INVALID[/red]"
            self.console.print(f"  Verdict: {status} ({verdict.severity})")

        return ClaimResult(
            claim=claim,
            verdict=verdict,
            debate_rounds=rounds_completed,
            attacker_conceded=attacker_conceded,
            defender_acknowledged=defender_acknowledged,
            final_assessment=judge_response.content[:500],
        )

    def reset_agents(self) -> None:
        """Clear agent conversation histories."""
        self.attacker.clear_history()
        self.defender.clear_history()
        self.judge.clear_history()
