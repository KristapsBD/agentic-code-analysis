import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from rich.console import Console

from src.agents.attacker_agent import AttackerAgent
from src.agents.base_agent import VulnerabilityClaim
from src.agents.defender_agent import DefenderAgent
from src.agents.judge_agent import JudgeAgent, Verdict
from src.config import ConfidenceLevel
from src.orchestration.conversation import Conversation, TurnType
from src.providers.base_provider import BaseLLMProvider
from src.tools.static_analysis import StaticAnalysisResult, run_slither

logger = logging.getLogger(__name__)


_EXTENSION_MAP = {
    ".sol": "solidity",
    ".vy": "vyper",
    ".rs": "rust",
    ".move": "move",
}

_LANGUAGE_PATTERNS: dict[str, list[str]] = {
    "solidity": [r"pragma\s+solidity", r"contract\s+\w+", r"modifier\s+\w+", r"mapping\s*\(", r"msg\.sender"],
    "vyper": [r"@external", r"@internal", r"@view", r"@payable", r"#\s*@version", r"from\s+vyper"],
    "rust": [r"#\[program\]", r"#\[account\]", r"use\s+anchor_lang", r"use\s+solana_program", r"pub\s+fn\s+"],
    "move": [r"module\s+\w+", r"script\s*\{", r"fun\s+\w+", r"acquires\s+", r"borrow_global"],
}


def _detect_language(source_code: str, file_path: str = "") -> str:
    for ext, lang in _EXTENSION_MAP.items():
        if file_path.lower().endswith(ext):
            return lang
    scores = {lang: sum(1 for p in patterns if re.search(p, source_code, re.IGNORECASE))
              for lang, patterns in _LANGUAGE_PATTERNS.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "unknown"


@dataclass
class ClaimResult:
    claim: VulnerabilityClaim
    verdict: Verdict
    debate_rounds: int
    attacker_conceded: bool = False
    defender_acknowledged: bool = False
    judge_requested_clarification: bool = False
    final_assessment: str = ""
    defender_verdict: Optional[str] = None  # VALID_VULNERABILITY | INVALID_CLAIM | PARTIALLY_MITIGATED

    def to_dict(self) -> dict:
        return {
            "claim": self.claim.to_dict(),
            "verdict": self.verdict.to_dict(),
            "debate_rounds": self.debate_rounds,
            "attacker_conceded": self.attacker_conceded,
            "defender_acknowledged": self.defender_acknowledged,
            "judge_requested_clarification": self.judge_requested_clarification,
            "final_assessment": self.final_assessment,
            "defender_verdict": self.defender_verdict,
        }


@dataclass
class DebateResult:
    contract_path: str
    contract_language: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    initial_claims: list[VulnerabilityClaim] = field(default_factory=list)
    claim_results: list[ClaimResult] = field(default_factory=list)
    conversation: Optional[Conversation] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_vulnerabilities(self) -> int:
        return len(self.initial_claims)

    @property
    def confirmed_vulnerabilities(self) -> int:
        return sum(1 for r in self.claim_results if r.verdict.is_valid)

    @property
    def rejected_claims(self) -> int:
        return sum(1 for r in self.claim_results if not r.verdict.is_valid)

    @property
    def critical_count(self) -> int:
        return sum(
            1 for r in self.claim_results
            if r.verdict.is_valid and r.verdict.severity == "critical"
        )

    @property
    def high_count(self) -> int:
        return sum(
            1 for r in self.claim_results
            if r.verdict.is_valid and r.verdict.severity == "high"
        )

    def to_dict(self) -> dict:
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
            "conversation": ([t.to_dict() for t in self.conversation.turns] if self.conversation else []),
            "metadata": self.metadata,
        }


class DebateManager:

    def __init__(
        self,
        provider: BaseLLMProvider,
        max_rounds: int = 2,
        judge_clarification_trigger: ConfidenceLevel = ConfidenceLevel.LOW,
        verbose: bool = False,
        console: Optional[Console] = None,
        web_search: bool = False,
        static_analysis: bool = False,
    ):
        self.provider = provider
        self.max_rounds = max_rounds
        self.judge_clarification_trigger = judge_clarification_trigger
        self.verbose = verbose
        self.web_search = web_search
        self.static_analysis = static_analysis
        self.console = console or Console()

        logger.debug(
            f"Initializing DebateManager with provider={provider.provider_name}, "
            f"max_rounds={max_rounds}, judge_trigger={judge_clarification_trigger.value}, "
            f"web_search={web_search}, static_analysis={static_analysis}"
        )

        self.attacker = AttackerAgent(provider, web_search=web_search)
        self.defender = DefenderAgent(provider, web_search=web_search)
        self.judge = JudgeAgent(provider, web_search=web_search)

    async def run_debate(
        self,
        contract_code: str,
        contract_path: str,
    ) -> dict:
        detected_language = _detect_language(contract_code, contract_path)
        logger.info(f"Detected contract language: {detected_language}")

        result = DebateResult(
            contract_path=contract_path,
            contract_language=detected_language,
            started_at=datetime.now(),
        )
        conversation = Conversation(contract_path)
        result.conversation = conversation

        static_analysis_result: Optional[StaticAnalysisResult] = None
        static_analysis_context = ""
        if self.static_analysis:
            logger.info("Pre-Phase: Running Slither static analysis")
            if self.verbose:
                self.console.print("[bold blue]Pre-Phase:[/bold blue] Running Slither...")
            static_analysis_result = run_slither(contract_path)
            static_analysis_context = static_analysis_result.format_for_prompt()
            if self.verbose:
                if static_analysis_result.skipped:
                    self.console.print(
                        f"[yellow]Slither skipped:[/yellow] {static_analysis_result.skip_reason}"
                    )
                elif static_analysis_result.error:
                    self.console.print(
                        f"[yellow]Slither error:[/yellow] {static_analysis_result.error}"
                    )
                else:
                    self.console.print(
                        f"[green]Slither found {len(static_analysis_result.findings)} issue(s)[/green]"
                    )

        logger.info("Phase 1: Attacker Agent scanning for vulnerabilities")
        if self.verbose:
            self.console.print("[bold blue]Phase 1:[/bold blue] Attacker scanning...")

        logger.debug(f"Sending contract to Attacker Agent (length: {len(contract_code)} chars)")
        attacker_response = await self.attacker.analyze({
            "contract_code": contract_code,
            "static_analysis_context": static_analysis_context,
        })
        logger.debug(f"Attacker response received: {attacker_response.tokens_used} tokens")

        conversation.add_turn(
            TurnType.ATTACK,
            self.attacker.name,
            attacker_response.content,
        )

        result.initial_claims = attacker_response.claims
        logger.info(f"Attacker Agent found {len(result.initial_claims)} potential vulnerabilities")
        if result.initial_claims:
            for i, claim in enumerate(result.initial_claims):
                logger.debug(
                    f"  Claim {i+1}/{len(result.initial_claims)}: "
                    f"[{claim.severity.upper()}] {claim.vulnerability_type} "
                    f"@ {claim.location} (confidence={claim.confidence.value})"
                )
                logger.debug(f"    Description: {claim.description}")
                logger.debug(f"    Evidence:    {claim.evidence[:300]}")
        else:
            logger.warning(
                "Attacker found 0 claims — check debug logs for the raw LLM response "
                "to diagnose whether the model responded correctly or JSON parsing failed"
            )

        if self.verbose:
            self.console.print(
                f"[green]Found {len(result.initial_claims)} potential vulnerabilities[/green]"
            )

        logger.info(f"Phase 2-4: Starting debate rounds for {len(result.initial_claims)} claims")
        for i, claim in enumerate(result.initial_claims):
            logger.info(
                f"Debating claim {i+1}/{len(result.initial_claims)}: "
                f"[{claim.severity.upper()}] {claim.vulnerability_type} @ {claim.location}"
            )
            if self.verbose:
                self.console.print(
                    f"\n[bold blue]Debating claim {i+1}/{len(result.initial_claims)}:[/bold blue] "
                    f"{claim.vulnerability_type}"
                )

            self._reset_claim_context()

            claim_result = await self._debate_claim(
                claim=claim,
                contract_code=contract_code,
                conversation=conversation,
            )
            result.claim_results.append(claim_result)
            logger.info(
                f"Claim {i+1} verdict: {'CONFIRMED' if claim_result.verdict.is_valid else 'REJECTED'} "
                f"(judge_confidence={claim_result.verdict.confidence.value}, "
                f"rounds={claim_result.debate_rounds}, "
                f"attacker_conceded={claim_result.attacker_conceded})"
            )

        result.completed_at = datetime.now()
        result.metadata["provider"] = self.provider.provider_name
        result.metadata["model"] = self.provider.model
        result.metadata["max_rounds"] = self.max_rounds
        result.metadata["judge_clarification_trigger"] = self.judge_clarification_trigger.value
        result.metadata["web_search"] = self.web_search
        result.metadata["static_analysis"] = (
            static_analysis_result.to_dict() if static_analysis_result else None
        )

        return result.to_dict()

    async def _debate_claim(
        self,
        claim: VulnerabilityClaim,
        contract_code: str,
        conversation: Conversation,
    ) -> ClaimResult:
        attacker_conceded = False
        defender_acknowledged = False
        judge_requested_clarification = False

        logger.debug(f"[{claim.id}] Defender reviewing claim: {claim.vulnerability_type}")
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
        attacker_confidence = claim.confidence
        defender_confidence = defender_response.confidence
        defender_verdict = defender_response.metadata.get("defense_verdict", "VALID_VULNERABILITY")

        debate_history: list[dict[str, str]] = []
        for round_num in range(1, self.max_rounds + 1):
            rounds_completed = round_num

            if self.verbose:
                self.console.print(f"  Round {round_num}/{self.max_rounds}")

            if self._has_converged(attacker_confidence, defender_confidence):
                logger.info(
                    f"[{claim.id}] Convergence detected at round {round_num} "
                    f"(attacker={attacker_confidence.value}, defender={defender_confidence.value})"
                )
                if self.verbose:
                    self.console.print("  [yellow]Convergence detected - skipping remaining rounds[/yellow]")
                break

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

            attacker_confidence = rebuttal_response.confidence

            if rebuttal_response.metadata.get("is_concession"):
                attacker_conceded = True
                logger.info(f"[{claim.id}] Attacker conceded at round {round_num}")
                if self.verbose:
                    self.console.print("  [yellow]Attacker conceded[/yellow]")
                break

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

            defender_confidence = defender_rebuttal.confidence

            if defender_rebuttal.metadata.get("acknowledges_vulnerability"):
                defender_acknowledged = True
                logger.info(f"[{claim.id}] Defender acknowledged vulnerability at round {round_num}")
                if self.verbose:
                    self.console.print("  [yellow]Defender acknowledged vulnerability[/yellow]")
                break

            debate_history.append({
                "attacker": rebuttal_response.content,
                "defender": defender_rebuttal.content,
            })

            attacker_argument = rebuttal_response.content
            defender_argument = defender_rebuttal.content

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

        needs_clarification = judge_response.metadata.get("needs_clarification", False)
        clarification_question = judge_response.metadata.get("clarification_question", "")
        judge_confidence = judge_response.confidence

        if (
            needs_clarification
            and clarification_question
            and judge_confidence <= self.judge_clarification_trigger
        ):
            judge_requested_clarification = True
            logger.info(
                f"[{claim.id}] Judge requesting clarification "
                f"(confidence={judge_confidence.value}, trigger={self.judge_clarification_trigger.value})"
            )
            if self.verbose:
                self.console.print(
                    f"  [bold yellow]Judge requesting clarification[/bold yellow] "
                    f"(confidence: {judge_confidence.value})"
                )

            judge_response = await self._run_clarification_round(
                claim=claim,
                contract_code=contract_code,
                conversation=conversation,
                clarification_question=clarification_question,
                attacker_argument=attacker_argument,
                defender_argument=defender_argument,
            )

        verdict_dict = judge_response.metadata.get("verdict", {})
        verdict = Verdict(
            claim_id=claim.id,
            is_valid=verdict_dict.get("is_valid", False),
            severity=verdict_dict.get("severity", "medium"),
            confidence=ConfidenceLevel(str(verdict_dict.get("confidence", "MEDIUM")).upper()),
            reasoning=verdict_dict.get("reasoning", ""),
            recommendation=verdict_dict.get("recommendation", ""),
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
            judge_requested_clarification=judge_requested_clarification,
            final_assessment=judge_response.content,
            defender_verdict=defender_verdict,
        )

    async def _run_clarification_round(
        self,
        claim: VulnerabilityClaim,
        contract_code: str,
        conversation: Conversation,
        clarification_question: str,
        attacker_argument: str,
        defender_argument: str,
    ) -> Any:
        conversation.add_turn(
            TurnType.CLARIFICATION,
            self.judge.name,
            clarification_question,
            claim_id=claim.id,
        )

        if self.verbose:
            self.console.print(f"  [dim]Judge asks: {clarification_question[:100]}...[/dim]")

        claim_dict = claim.to_dict()
        attacker_clarification, defender_clarification = await asyncio.gather(
            self.attacker.respond_to_clarification({
                "original_claim": claim_dict,
                "judge_question": clarification_question,
            }),
            self.defender.respond_to_clarification({
                "original_claim": claim_dict,
                "judge_question": clarification_question,
            }),
        )

        conversation.add_turn(
            TurnType.CLARIFICATION_RESPONSE,
            self.attacker.name,
            attacker_clarification.content,
            claim_id=claim.id,
        )
        conversation.add_turn(
            TurnType.CLARIFICATION_RESPONSE,
            self.defender.name,
            defender_clarification.content,
            claim_id=claim.id,
        )

        if self.verbose:
            self.console.print("  [bold]Judge rendering final verdict after clarification...[/bold]")

        final_response = await self.judge.render_final_verdict({
            "contract_code": contract_code,
            "claim": claim,
            "original_question": clarification_question,
            "attacker_clarification": attacker_clarification.content,
            "defender_clarification": defender_clarification.content,
            "attacker_argument": attacker_argument,
            "defender_argument": defender_argument,
        })

        conversation.add_turn(
            TurnType.JUDGMENT,
            self.judge.name,
            final_response.content,
            claim_id=claim.id,
            metadata={"is_final_after_clarification": True},
        )

        return final_response

    @staticmethod
    def _has_converged(
        attacker_confidence: ConfidenceLevel, defender_confidence: ConfidenceLevel
    ) -> bool:
        """Return True when attacker confidence is LOW or defender confidence is HIGH."""
        if attacker_confidence == ConfidenceLevel.LOW:
            return True
        if defender_confidence == ConfidenceLevel.HIGH:
            return True
        return False

    def _reset_claim_context(self) -> None:
        """Clear agent histories between claims to prevent context bleed."""
        logger.debug("Resetting agent histories for new claim")
        self.attacker.clear_history()
        self.defender.clear_history()
        self.judge.clear_history()

    def reset_agents(self) -> None:
        self._reset_claim_context()
