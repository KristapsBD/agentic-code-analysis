"""
Evaluation module for benchmarking the adversarial agent system.

Provides tools for evaluating the system against benchmark datasets
and calculating precision, recall, and F1 scores.
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.progress import Progress, TaskID
from rich.table import Table

from src.config import LLMProvider, settings
from src.orchestration.debate_manager import DebateManager
from src.providers.provider_factory import ProviderFactory


@dataclass
class GroundTruth:
    """Ground truth vulnerability information for a contract."""

    contract_path: str
    vulnerabilities: list[dict[str, Any]]
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def vulnerability_types(self) -> set[str]:
        """Get unique vulnerability types."""
        return {v.get("type", "unknown") for v in self.vulnerabilities}

    @property
    def has_vulnerabilities(self) -> bool:
        """Check if contract has known vulnerabilities."""
        return len(self.vulnerabilities) > 0


@dataclass
class EvaluationResult:
    """Result of evaluating a single contract."""

    contract_path: str
    ground_truth: GroundTruth
    predicted_vulnerabilities: list[dict[str, Any]]
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    analysis_time_seconds: float = 0.0
    error: Optional[str] = None

    @property
    def precision(self) -> float:
        """Calculate precision."""
        total_predicted = self.true_positives + self.false_positives
        if total_predicted == 0:
            return 0.0
        return self.true_positives / total_predicted

    @property
    def recall(self) -> float:
        """Calculate recall."""
        total_actual = self.true_positives + self.false_negatives
        if total_actual == 0:
            return 1.0  # No vulnerabilities to find
        return self.true_positives / total_actual

    @property
    def f1_score(self) -> float:
        """Calculate F1 score."""
        p, r = self.precision, self.recall
        if p + r == 0:
            return 0.0
        return 2 * (p * r) / (p + r)

    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            "contract_path": self.contract_path,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "analysis_time_seconds": self.analysis_time_seconds,
            "error": self.error,
        }


@dataclass
class BenchmarkResult:
    """Complete benchmark evaluation results."""

    benchmark_name: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    contract_results: list[EvaluationResult] = field(default_factory=list)
    provider: str = ""
    model: str = ""
    total_contracts: int = 0
    successful_analyses: int = 0
    failed_analyses: int = 0

    @property
    def total_true_positives(self) -> int:
        """Total true positives across all contracts."""
        return sum(r.true_positives for r in self.contract_results)

    @property
    def total_false_positives(self) -> int:
        """Total false positives across all contracts."""
        return sum(r.false_positives for r in self.contract_results)

    @property
    def total_false_negatives(self) -> int:
        """Total false negatives across all contracts."""
        return sum(r.false_negatives for r in self.contract_results)

    @property
    def macro_precision(self) -> float:
        """Macro-averaged precision."""
        if not self.contract_results:
            return 0.0
        return sum(r.precision for r in self.contract_results) / len(self.contract_results)

    @property
    def macro_recall(self) -> float:
        """Macro-averaged recall."""
        if not self.contract_results:
            return 0.0
        return sum(r.recall for r in self.contract_results) / len(self.contract_results)

    @property
    def macro_f1(self) -> float:
        """Macro-averaged F1 score."""
        if not self.contract_results:
            return 0.0
        return sum(r.f1_score for r in self.contract_results) / len(self.contract_results)

    @property
    def micro_precision(self) -> float:
        """Micro-averaged precision."""
        total_predicted = self.total_true_positives + self.total_false_positives
        if total_predicted == 0:
            return 0.0
        return self.total_true_positives / total_predicted

    @property
    def micro_recall(self) -> float:
        """Micro-averaged recall."""
        total_actual = self.total_true_positives + self.total_false_negatives
        if total_actual == 0:
            return 1.0
        return self.total_true_positives / total_actual

    @property
    def micro_f1(self) -> float:
        """Micro-averaged F1 score."""
        p, r = self.micro_precision, self.micro_recall
        if p + r == 0:
            return 0.0
        return 2 * (p * r) / (p + r)

    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            "benchmark_name": self.benchmark_name,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "summary": {
                "total_contracts": self.total_contracts,
                "successful_analyses": self.successful_analyses,
                "failed_analyses": self.failed_analyses,
            },
            "metrics": {
                "macro_precision": self.macro_precision,
                "macro_recall": self.macro_recall,
                "macro_f1": self.macro_f1,
                "micro_precision": self.micro_precision,
                "micro_recall": self.micro_recall,
                "micro_f1": self.micro_f1,
            },
            "totals": {
                "true_positives": self.total_true_positives,
                "false_positives": self.total_false_positives,
                "false_negatives": self.total_false_negatives,
            },
            "provider": self.provider,
            "model": self.model,
            "contract_results": [r.to_dict() for r in self.contract_results],
        }


class Evaluator:
    """
    Evaluates the adversarial agent system against benchmark datasets.

    Supports various benchmark formats including SmartBugs.
    """

    # Mapping of vulnerability type variations to canonical names
    VULNERABILITY_TYPE_MAP = {
        "reentrancy": ["reentrancy", "re-entrancy", "reentrant"],
        "access_control": ["access_control", "access-control", "authorization", "unprotected"],
        "arithmetic": ["arithmetic", "integer_overflow", "integer_underflow", "overflow", "underflow"],
        "unchecked_calls": ["unchecked_call", "unchecked_return", "unchecked_low_level"],
        "denial_of_service": ["dos", "denial_of_service", "denial-of-service"],
        "front_running": ["front_running", "front-running", "frontrunning", "race_condition"],
        "time_manipulation": ["time_manipulation", "timestamp", "block_timestamp"],
        "bad_randomness": ["randomness", "bad_randomness", "weak_randomness"],
    }

    def __init__(
        self,
        provider: Optional[LLMProvider] = None,
        max_rounds: int = 2,
    ):
        """
        Initialize the evaluator.

        Args:
            provider: LLM provider to use
            max_rounds: Maximum debate rounds
        """
        self.provider = provider or settings.default_provider
        self.max_rounds = max_rounds

    async def evaluate_benchmark(
        self,
        benchmark_dir: Path,
        ground_truth_file: Optional[Path] = None,
    ) -> BenchmarkResult:
        """
        Evaluate the system against a benchmark dataset.

        Args:
            benchmark_dir: Directory containing benchmark contracts
            ground_truth_file: Optional JSON file with ground truth

        Returns:
            BenchmarkResult with evaluation metrics
        """
        result = BenchmarkResult(
            benchmark_name=benchmark_dir.name,
            started_at=datetime.now(),
            provider=self.provider.value,
            model=settings.get_model_for_provider(self.provider),
        )

        # Load ground truth
        ground_truths = self._load_ground_truth(benchmark_dir, ground_truth_file)

        # Find all contract files
        contract_files = self._find_contract_files(benchmark_dir)
        result.total_contracts = len(contract_files)

        # Create debate manager
        llm_provider = ProviderFactory.create(self.provider)
        debate_manager = DebateManager(
            provider=llm_provider,
            max_rounds=self.max_rounds,
            judge_confidence_threshold=settings.judge_confidence_threshold,
            verbose=False,
        )

        # Evaluate each contract
        for contract_path in contract_files:
            try:
                contract_code = contract_path.read_text()
                ground_truth = ground_truths.get(
                    str(contract_path),
                    GroundTruth(str(contract_path), [])
                )

                start_time = datetime.now()
                analysis_result = await debate_manager.run_debate(
                    contract_code, str(contract_path)
                )
                analysis_time = (datetime.now() - start_time).total_seconds()

                # Compare results
                eval_result = self._compare_results(
                    ground_truth=ground_truth,
                    analysis_result=analysis_result,
                    analysis_time=analysis_time,
                )
                result.contract_results.append(eval_result)
                result.successful_analyses += 1

                # Reset agents between contracts
                debate_manager.reset_agents()

            except Exception as e:
                result.contract_results.append(EvaluationResult(
                    contract_path=str(contract_path),
                    ground_truth=GroundTruth(str(contract_path), []),
                    predicted_vulnerabilities=[],
                    error=str(e),
                ))
                result.failed_analyses += 1

        result.completed_at = datetime.now()
        return result

    def _load_ground_truth(
        self,
        benchmark_dir: Path,
        ground_truth_file: Optional[Path],
    ) -> dict[str, GroundTruth]:
        """Load ground truth vulnerability information."""
        ground_truths = {}

        # Try to load from explicit file
        if ground_truth_file and ground_truth_file.exists():
            with open(ground_truth_file) as f:
                data = json.load(f)
                for item in data:
                    path = item.get("contract_path", "")
                    ground_truths[path] = GroundTruth(
                        contract_path=path,
                        vulnerabilities=item.get("vulnerabilities", []),
                        metadata=item.get("metadata", {}),
                    )
            return ground_truths

        # Try SmartBugs format (vulnerabilities in filename or directory)
        for sol_file in benchmark_dir.rglob("*.sol"):
            vulnerabilities = []

            # Check if parent directory indicates vulnerability type
            parent_name = sol_file.parent.name.lower()
            for canonical, variants in self.VULNERABILITY_TYPE_MAP.items():
                if any(v in parent_name for v in variants):
                    vulnerabilities.append({"type": canonical})
                    break

            # Check filename for vulnerability hints
            filename = sol_file.name.lower()
            for canonical, variants in self.VULNERABILITY_TYPE_MAP.items():
                if any(v in filename for v in variants):
                    if not any(v.get("type") == canonical for v in vulnerabilities):
                        vulnerabilities.append({"type": canonical})

            ground_truths[str(sol_file)] = GroundTruth(
                contract_path=str(sol_file),
                vulnerabilities=vulnerabilities,
            )

        return ground_truths

    def _find_contract_files(self, benchmark_dir: Path) -> list[Path]:
        """Find all smart contract files in the benchmark directory."""
        extensions = [".sol", ".vy", ".rs", ".move"]
        files = []
        for ext in extensions:
            files.extend(benchmark_dir.rglob(f"*{ext}"))
        return sorted(files)

    def _compare_results(
        self,
        ground_truth: GroundTruth,
        analysis_result: dict,
        analysis_time: float,
    ) -> EvaluationResult:
        """Compare analysis results with ground truth."""
        predicted = []
        for claim_result in analysis_result.get("claim_results", []):
            verdict = claim_result.get("verdict", {})
            if verdict.get("is_valid", False):
                claim = claim_result.get("claim", {})
                predicted.append({
                    "type": self._normalize_vuln_type(claim.get("vulnerability_type", "")),
                    "severity": verdict.get("severity", "medium"),
                    "location": claim.get("location", ""),
                })

        # Calculate metrics
        true_positives = 0
        false_positives = 0

        predicted_types = set()
        for p in predicted:
            predicted_types.add(p["type"])

        ground_truth_types = set()
        for gt in ground_truth.vulnerabilities:
            gt_type = self._normalize_vuln_type(gt.get("type", ""))
            ground_truth_types.add(gt_type)

        # True positives: predicted types that exist in ground truth
        for p_type in predicted_types:
            if p_type in ground_truth_types:
                true_positives += 1
            else:
                false_positives += 1

        # False negatives: ground truth types not predicted
        false_negatives = len(ground_truth_types - predicted_types)

        return EvaluationResult(
            contract_path=ground_truth.contract_path,
            ground_truth=ground_truth,
            predicted_vulnerabilities=predicted,
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            analysis_time_seconds=analysis_time,
        )

    def _normalize_vuln_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type to canonical form."""
        vuln_lower = vuln_type.lower().replace(" ", "_").replace("-", "_")

        for canonical, variants in self.VULNERABILITY_TYPE_MAP.items():
            if any(v in vuln_lower for v in variants):
                return canonical

        return vuln_lower

    def print_results(self, result: BenchmarkResult, console: Optional[Console] = None) -> None:
        """Print evaluation results to console."""
        console = console or Console()

        # Summary table
        summary = Table(title="Benchmark Results", show_header=True, header_style="bold magenta")
        summary.add_column("Metric", style="cyan")
        summary.add_column("Value", justify="right")

        summary.add_row("Benchmark", result.benchmark_name)
        summary.add_row("Total Contracts", str(result.total_contracts))
        summary.add_row("Successful", str(result.successful_analyses))
        summary.add_row("Failed", str(result.failed_analyses))
        summary.add_row("", "")
        summary.add_row("True Positives", str(result.total_true_positives))
        summary.add_row("False Positives", str(result.total_false_positives))
        summary.add_row("False Negatives", str(result.total_false_negatives))
        summary.add_row("", "")
        summary.add_row("Micro Precision", f"{result.micro_precision:.2%}")
        summary.add_row("Micro Recall", f"{result.micro_recall:.2%}")
        summary.add_row("Micro F1", f"{result.micro_f1:.2%}")
        summary.add_row("", "")
        summary.add_row("Macro Precision", f"{result.macro_precision:.2%}")
        summary.add_row("Macro Recall", f"{result.macro_recall:.2%}")
        summary.add_row("Macro F1", f"{result.macro_f1:.2%}")

        console.print(summary)

    def save_results(self, result: BenchmarkResult, output_path: Path) -> None:
        """Save evaluation results to JSON file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
