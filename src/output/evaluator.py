import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.table import Table

from src.config import LLMProvider, settings
from src.orchestration.debate_manager import DebateManager
from src.providers.provider_factory import ProviderFactory


@dataclass
class GroundTruth:
    contract_path: str
    vulnerabilities: list[dict[str, Any]]
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def vulnerability_types(self) -> set[str]:
        return {v.get("type", "unknown") for v in self.vulnerabilities}

    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.vulnerabilities) > 0


@dataclass
class EvaluationResult:
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
        total_predicted = self.true_positives + self.false_positives
        if total_predicted == 0:
            return 0.0
        return self.true_positives / total_predicted

    @property
    def recall(self) -> float:
        total_actual = self.true_positives + self.false_negatives
        if total_actual == 0:
            return 1.0  # No vulnerabilities to find
        return self.true_positives / total_actual

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        if p + r == 0:
            return 0.0
        return 2 * (p * r) / (p + r)

    @property
    def binary_predicted_vulnerable(self) -> bool:
        return len(self.predicted_vulnerabilities) > 0

    @property
    def binary_correct(self) -> bool:
        if self.error:
            return False
        return self.binary_predicted_vulnerable == self.ground_truth.has_vulnerabilities

    def to_dict(self) -> dict:
        return {
            "contract_path": self.contract_path,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "binary_predicted_vulnerable": self.binary_predicted_vulnerable,
            "binary_correct": self.binary_correct,
            "analysis_time_seconds": self.analysis_time_seconds,
            "error": self.error,
        }


@dataclass
class BenchmarkResult:
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
        return sum(r.true_positives for r in self.contract_results)

    @property
    def total_false_positives(self) -> int:
        return sum(r.false_positives for r in self.contract_results)

    @property
    def total_false_negatives(self) -> int:
        return sum(r.false_negatives for r in self.contract_results)

    @property
    def macro_precision(self) -> float:
        if not self.contract_results:
            return 0.0
        return sum(r.precision for r in self.contract_results) / len(self.contract_results)

    @property
    def macro_recall(self) -> float:
        if not self.contract_results:
            return 0.0
        return sum(r.recall for r in self.contract_results) / len(self.contract_results)

    @property
    def macro_f1(self) -> float:
        if not self.contract_results:
            return 0.0
        return sum(r.f1_score for r in self.contract_results) / len(self.contract_results)

    @property
    def micro_precision(self) -> float:
        total_predicted = self.total_true_positives + self.total_false_positives
        if total_predicted == 0:
            return 0.0
        return self.total_true_positives / total_predicted

    @property
    def micro_recall(self) -> float:
        total_actual = self.total_true_positives + self.total_false_negatives
        if total_actual == 0:
            return 1.0
        return self.total_true_positives / total_actual

    @property
    def micro_f1(self) -> float:
        p, r = self.micro_precision, self.micro_recall
        if p + r == 0:
            return 0.0
        return 2 * (p * r) / (p + r)

    @property
    def binary_accuracy(self) -> float:
        if not self.contract_results:
            return 0.0
        correct = sum(1 for r in self.contract_results if r.binary_correct)
        return correct / len(self.contract_results)

    # Detection metrics — binary vulnerable/safe per contract

    @property
    def detection_true_positives(self) -> int:
        return sum(
            1 for r in self.contract_results
            if r.binary_predicted_vulnerable and r.ground_truth.has_vulnerabilities
        )

    @property
    def detection_false_positives(self) -> int:
        return sum(
            1 for r in self.contract_results
            if r.binary_predicted_vulnerable and not r.ground_truth.has_vulnerabilities
        )

    @property
    def detection_false_negatives(self) -> int:
        return sum(
            1 for r in self.contract_results
            if not r.binary_predicted_vulnerable and r.ground_truth.has_vulnerabilities
        )

    @property
    def detection_precision(self) -> float:
        tp, fp = self.detection_true_positives, self.detection_false_positives
        return tp / (tp + fp) if (tp + fp) > 0 else 0.0

    @property
    def detection_recall(self) -> float:
        tp, fn = self.detection_true_positives, self.detection_false_negatives
        return tp / (tp + fn) if (tp + fn) > 0 else 0.0

    @property
    def detection_f1(self) -> float:
        p, r = self.detection_precision, self.detection_recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    # Classification metrics — type accuracy on vulnerable contracts only

    @property
    def classification_true_positives(self) -> int:
        return sum(
            r.true_positives for r in self.contract_results
            if r.ground_truth.has_vulnerabilities
        )

    @property
    def classification_false_positives(self) -> int:
        return sum(
            r.false_positives for r in self.contract_results
            if r.ground_truth.has_vulnerabilities
        )

    @property
    def classification_false_negatives(self) -> int:
        return sum(
            r.false_negatives for r in self.contract_results
            if r.ground_truth.has_vulnerabilities
        )

    @property
    def classification_precision(self) -> float:
        tp, fp = self.classification_true_positives, self.classification_false_positives
        return tp / (tp + fp) if (tp + fp) > 0 else 0.0

    @property
    def classification_recall(self) -> float:
        tp, fn = self.classification_true_positives, self.classification_false_negatives
        return tp / (tp + fn) if (tp + fn) > 0 else 0.0

    @property
    def classification_f1(self) -> float:
        p, r = self.classification_precision, self.classification_recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    def to_dict(self) -> dict:
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
                "binary_accuracy": self.binary_accuracy,
                "detection_precision": self.detection_precision,
                "detection_recall": self.detection_recall,
                "detection_f1": self.detection_f1,
                "classification_precision": self.classification_precision,
                "classification_recall": self.classification_recall,
                "classification_f1": self.classification_f1,
            },
            "totals": {
                "true_positives": self.total_true_positives,
                "false_positives": self.total_false_positives,
                "false_negatives": self.total_false_negatives,
                "detection_true_positives": self.detection_true_positives,
                "detection_false_positives": self.detection_false_positives,
                "detection_false_negatives": self.detection_false_negatives,
                "classification_true_positives": self.classification_true_positives,
                "classification_false_positives": self.classification_false_positives,
                "classification_false_negatives": self.classification_false_negatives,
            },
            "provider": self.provider,
            "model": self.model,
            "contract_results": [r.to_dict() for r in self.contract_results],
        }


class Evaluator:
    # Canonical keys must match VULNERABILITY_TYPES in src/knowledge/prompts/attacker.py.
    VULNERABILITY_TYPE_MAP = {
        "reentrancy": ["reentrancy", "re-entrancy", "reentrant"],
        "access_control": ["access_control", "access-control", "authorization", "unprotected", "privilege"],
        "arithmetic": ["arithmetic", "integer_overflow", "integer_underflow", "overflow", "underflow", "safeMath"],
        "unchecked_calls": ["unchecked_call", "unchecked_return", "unchecked_low_level", "return_value", "unchecked_send", "unsafe_send", "ignored_return"],
        "denial_of_service": ["dos", "denial_of_service", "denial-of-service", "gas_griefing", "unbounded_loop", "lock_of_ether", "locked_ether"],
        "time_manipulation": ["time_manipulation", "timestamp", "block_timestamp", "block_number"],
        "bad_randomness": ["randomness", "bad_randomness", "weak_randomness", "predictable_random"],
        "signature_replay": ["signature_replay", "replay_attack", "missing_nonce", "malleab"],
        "delegatecall": ["delegatecall", "delegate_call", "storage_collision", "proxy_collision"],
        "upgradeable_proxy": ["upgradeable", "upgradable", "uninitialized_impl", "storage_layout"],
    }

    def __init__(
        self,
        provider: Optional[LLMProvider] = None,
        max_rounds: int = 2,
    ):
        self.provider = provider or settings.default_provider
        self.max_rounds = max_rounds

    def _load_ground_truth(
        self,
        benchmark_dir: Path,
        ground_truth_file: Optional[Path],
    ) -> dict[str, GroundTruth]:
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

        predicted_types = {p["type"] for p in predicted}

        ground_truth_types = {
            self._normalize_vuln_type(gt.get("type", ""))
            for gt in ground_truth.vulnerabilities
        }

        # Strict type matching: predicted type must equal the GT canonical label exactly.
        true_positives = sum(1 for p in predicted_types if p in ground_truth_types)
        false_positives = sum(1 for p in predicted_types if p not in ground_truth_types)
        false_negatives = sum(1 for gt in ground_truth_types if gt not in predicted_types)

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
        vuln_lower = vuln_type.lower().replace(" ", "_").replace("-", "_")

        for canonical, variants in self.VULNERABILITY_TYPE_MAP.items():
            if any(v in vuln_lower for v in variants):
                return canonical

        return vuln_lower

    async def evaluate_both(
        self,
        benchmark_dir: Path,
        ground_truth_file: Optional[Path] = None,
        trace_dir: Optional[Path] = None,
        inter_contract_delay: float = 0.0,
    ) -> tuple[BenchmarkResult, BenchmarkResult, BenchmarkResult]:
        model = settings.get_model_for_provider(self.provider)

        multi_result = BenchmarkResult(
            benchmark_name=benchmark_dir.name,
            started_at=datetime.now(),
            provider=self.provider.value,
            model=model,
        )
        two_agent_result = BenchmarkResult(
            benchmark_name=f"{benchmark_dir.name}_two_agent",
            started_at=datetime.now(),
            provider=self.provider.value,
            model=model,
        )
        baseline_result = BenchmarkResult(
            benchmark_name=f"{benchmark_dir.name}_baseline",
            started_at=datetime.now(),
            provider=self.provider.value,
            model=model,
        )

        ground_truths = self._load_ground_truth(benchmark_dir, ground_truth_file)
        contract_files = self._find_contract_files(benchmark_dir)
        multi_result.total_contracts = len(contract_files)
        two_agent_result.total_contracts = len(contract_files)
        baseline_result.total_contracts = len(contract_files)

        llm_provider = ProviderFactory.create(self.provider)
        debate_manager = DebateManager(
            provider=llm_provider,
            max_rounds=self.max_rounds,
            judge_clarification_trigger=settings.judge_clarification_trigger,
            verbose=False,
        )

        for contract_path in contract_files:
            try:
                contract_code = contract_path.read_text()
                ground_truth = (
                    ground_truths.get(str(contract_path))
                    or ground_truths.get(contract_path.name)
                    or GroundTruth(str(contract_path), [])
                )

                start_time = datetime.now()
                analysis_result = await debate_manager.run_debate(
                    contract_code, str(contract_path)
                )
                analysis_time = (datetime.now() - start_time).total_seconds()

                if trace_dir is not None:
                    trace_dir.mkdir(parents=True, exist_ok=True)
                    (trace_dir / f"{contract_path.stem}.json").write_text(
                        json.dumps(analysis_result, indent=2, default=str)
                    )

                # Multi-agent: only judge-confirmed claims count
                multi_eval = self._compare_results(
                    ground_truth=ground_truth,
                    analysis_result=analysis_result,
                    analysis_time=analysis_time,
                )
                multi_result.contract_results.append(multi_eval)
                multi_result.successful_analyses += 1

                # 2-agent: claims the attacker did NOT concede after seeing the defense
                # (attacker wins ties — claim is valid unless explicitly retracted)
                two_agent_eval = self._compare_results_two_agent(
                    ground_truth=ground_truth,
                    analysis_result=analysis_result,
                    analysis_time=analysis_time,
                )
                two_agent_result.contract_results.append(two_agent_eval)
                two_agent_result.successful_analyses += 1

                # Baseline: attacker's initial claims accepted as-is (no debate filtering)
                baseline_analysis = {
                    "claim_results": [
                        {
                            "verdict": {"is_valid": True, "severity": c.get("severity", "medium")},
                            "claim": {
                                "vulnerability_type": c.get("vulnerability_type", ""),
                                "location": c.get("location", ""),
                            },
                        }
                        for c in analysis_result.get("initial_claims", [])
                    ]
                }
                baseline_eval = self._compare_results(
                    ground_truth=ground_truth,
                    analysis_result=baseline_analysis,
                    analysis_time=analysis_time,
                )
                baseline_result.contract_results.append(baseline_eval)
                baseline_result.successful_analyses += 1

                debate_manager.reset_agents()

                if inter_contract_delay > 0:
                    await asyncio.sleep(inter_contract_delay)

            except Exception as e:
                gt = ground_truths.get(contract_path.name) or GroundTruth(contract_path.name, [])
                error_result = EvaluationResult(
                    contract_path=contract_path.name,
                    ground_truth=gt,
                    predicted_vulnerabilities=[],
                    error=str(e),
                )
                multi_result.contract_results.append(error_result)
                multi_result.failed_analyses += 1
                two_agent_result.contract_results.append(error_result)
                two_agent_result.failed_analyses += 1
                baseline_result.contract_results.append(error_result)
                baseline_result.failed_analyses += 1

        multi_result.completed_at = datetime.now()
        two_agent_result.completed_at = datetime.now()
        baseline_result.completed_at = datetime.now()
        return multi_result, two_agent_result, baseline_result

    def _compare_results_two_agent(
        self,
        ground_truth: GroundTruth,
        analysis_result: dict,
        analysis_time: float,
    ) -> EvaluationResult:
        predicted = []
        for claim_result in analysis_result.get("claim_results", []):
            # Claim passes if defender did not explicitly reject it (INVALID_CLAIM).
            # VALID_VULNERABILITY and PARTIALLY_MITIGATED both indicate remaining attack surface.
            if claim_result.get("defender_verdict", "VALID_VULNERABILITY") != "INVALID_CLAIM":
                claim = claim_result.get("claim", {})
                predicted.append({
                    "type": self._normalize_vuln_type(claim.get("vulnerability_type", "")),
                    "severity": claim.get("severity", "medium"),
                    "location": claim.get("location", ""),
                })

        predicted_types = {p["type"] for p in predicted}

        ground_truth_types = {
            self._normalize_vuln_type(gt.get("type", ""))
            for gt in ground_truth.vulnerabilities
        }

        true_positives = sum(1 for p in predicted_types if p in ground_truth_types)
        false_positives = sum(1 for p in predicted_types if p not in ground_truth_types)
        false_negatives = sum(1 for gt in ground_truth_types if gt not in predicted_types)

        return EvaluationResult(
            contract_path=ground_truth.contract_path,
            ground_truth=ground_truth,
            predicted_vulnerabilities=predicted,
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            analysis_time_seconds=analysis_time,
        )

    def print_three_way_comparison(
        self,
        multi: BenchmarkResult,
        two_agent: BenchmarkResult,
        baseline: BenchmarkResult,
        console: Optional[Console] = None,
    ) -> None:
        console = console or Console()

        table = Table(
            title="Architecture Comparison: 3-Agent vs 2-Agent vs Baseline",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Metric", style="cyan")
        table.add_column("3-Agent (Judge)", justify="right")
        table.add_column("vs 2-Agent", justify="right")
        table.add_column("2-Agent (No Judge)", justify="right")
        table.add_column("vs Baseline", justify="right")
        table.add_column("Baseline (Attacker)", justify="right")

        def _delta(a: float, b: float, higher_is_better: bool = True) -> str:
            diff = a - b
            if diff == 0:
                return "[white]±0.00%[/white]"
            color = "green" if (diff > 0) == higher_is_better else "red"
            sign = "+" if diff > 0 else ""
            return f"[{color}]{sign}{diff:.2%}[/{color}]"

        def _int_delta(a: int, b: int, higher_is_better: bool = True) -> str:
            diff = a - b
            if diff == 0:
                return "[white]±0[/white]"
            color = "green" if (diff > 0) == higher_is_better else "red"
            sign = "+" if diff > 0 else ""
            return f"[{color}]{sign}{diff}[/{color}]"

        def _row(label, mv, tv, bv, higher=True, fmt="pct"):
            if fmt == "pct":
                table.add_row(label, f"{mv:.2%}", _delta(mv, tv, higher),
                              f"{tv:.2%}", _delta(tv, bv, higher), f"{bv:.2%}")
            else:
                table.add_row(label, str(mv), _int_delta(mv, tv, higher),
                              str(tv), _int_delta(tv, bv, higher), str(bv))

        def _blank():
            table.add_row("", "", "", "", "", "")

        _blank()
        table.add_row("── DETECTION ──", "", "", "", "", "")
        _row("Det Precision",  multi.detection_precision,  two_agent.detection_precision,  baseline.detection_precision)
        _row("Det Recall",     multi.detection_recall,     two_agent.detection_recall,     baseline.detection_recall)
        _row("Det F1",         multi.detection_f1,         two_agent.detection_f1,         baseline.detection_f1)
        _row("Det TP",         multi.detection_true_positives,  two_agent.detection_true_positives,  baseline.detection_true_positives,  True,  "int")
        _row("Det FP (alarms)",multi.detection_false_positives, two_agent.detection_false_positives, baseline.detection_false_positives, False, "int")
        _row("Det FN (missed)",multi.detection_false_negatives, two_agent.detection_false_negatives, baseline.detection_false_negatives, False, "int")

        _blank()
        table.add_row("── CLASSIFICATION (vuln only) ──", "", "", "", "", "")
        _row("Cls Precision",  multi.classification_precision,  two_agent.classification_precision,  baseline.classification_precision)
        _row("Cls Recall",     multi.classification_recall,     two_agent.classification_recall,     baseline.classification_recall)
        _row("Cls F1",         multi.classification_f1,         two_agent.classification_f1,         baseline.classification_f1)
        _row("Cls TP",         multi.classification_true_positives,  two_agent.classification_true_positives,  baseline.classification_true_positives,  True,  "int")
        _row("Cls FP",         multi.classification_false_positives, two_agent.classification_false_positives, baseline.classification_false_positives, False, "int")
        _row("Cls FN",         multi.classification_false_negatives, two_agent.classification_false_negatives, baseline.classification_false_negatives, False, "int")

        _blank()
        table.add_row("── JOINT (type, all) ──", "", "", "", "", "")
        _row("Binary Accuracy", multi.binary_accuracy, two_agent.binary_accuracy, baseline.binary_accuracy)
        _row("Micro Precision", multi.micro_precision, two_agent.micro_precision, baseline.micro_precision)
        _row("Micro Recall",    multi.micro_recall,    two_agent.micro_recall,    baseline.micro_recall)
        _row("Micro F1",        multi.micro_f1,        two_agent.micro_f1,        baseline.micro_f1)
        _row("Macro F1",        multi.macro_f1,        two_agent.macro_f1,        baseline.macro_f1)

        _blank()
        table.add_row("── JOINT counts ──", "", "", "", "", "")
        _row("True Positives",  multi.total_true_positives,  two_agent.total_true_positives,  baseline.total_true_positives,  True,  "int")
        _row("False Positives", multi.total_false_positives, two_agent.total_false_positives, baseline.total_false_positives, False, "int")
        _row("False Negatives", multi.total_false_negatives, two_agent.total_false_negatives, baseline.total_false_negatives, False, "int")

        console.print(table)

    def print_results(self, result: BenchmarkResult, console: Optional[Console] = None) -> None:
        console = console or Console()

        summary = Table(title="Benchmark Results", show_header=True, header_style="bold magenta")
        summary.add_column("Metric", style="cyan")
        summary.add_column("Value", justify="right")

        summary.add_row("Benchmark", result.benchmark_name)
        summary.add_row("Total Contracts", str(result.total_contracts))
        summary.add_row("Successful", str(result.successful_analyses))
        summary.add_row("Failed", str(result.failed_analyses))
        summary.add_row("", "")
        summary.add_row("── DETECTION (binary) ──", "")
        summary.add_row("Detected / Missed / False Alarm",
                        f"{result.detection_true_positives} / "
                        f"{result.detection_false_negatives} / "
                        f"{result.detection_false_positives}")
        summary.add_row("Detection Precision", f"{result.detection_precision:.2%}")
        summary.add_row("Detection Recall",    f"{result.detection_recall:.2%}")
        summary.add_row("Detection F1",        f"{result.detection_f1:.2%}")
        summary.add_row("", "")
        summary.add_row("── CLASSIFICATION (type, vuln contracts only) ──", "")
        summary.add_row("True Positives", str(result.classification_true_positives))
        summary.add_row("False Positives", str(result.classification_false_positives))
        summary.add_row("False Negatives", str(result.classification_false_negatives))
        summary.add_row("Classification Precision", f"{result.classification_precision:.2%}")
        summary.add_row("Classification Recall",    f"{result.classification_recall:.2%}")
        summary.add_row("Classification F1",        f"{result.classification_f1:.2%}")
        summary.add_row("", "")
        summary.add_row("── JOINT (type, all contracts) ──", "")
        summary.add_row("Binary Accuracy", f"{result.binary_accuracy:.2%}")
        summary.add_row("Micro Precision", f"{result.micro_precision:.2%}")
        summary.add_row("Micro Recall", f"{result.micro_recall:.2%}")
        summary.add_row("Micro F1", f"{result.micro_f1:.2%}")
        summary.add_row("", "")
        summary.add_row("Macro Precision", f"{result.macro_precision:.2%}")
        summary.add_row("Macro Recall", f"{result.macro_recall:.2%}")
        summary.add_row("Macro F1", f"{result.macro_f1:.2%}")

        console.print(summary)

