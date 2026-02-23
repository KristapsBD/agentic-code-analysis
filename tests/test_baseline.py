"""
Tests for the baseline agent and evaluate_baseline() / print_comparison().
"""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agents.baseline_agent import BaselineAgent
from src.config import LLMProvider
from src.output.evaluator import BenchmarkResult, EvaluationResult, Evaluator, GroundTruth
from src.providers.base_provider import LLMResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_llm_response(content: str) -> LLMResponse:
    return LLMResponse(content=content, model="test-model", tokens_used=10)


def _make_provider(response_content: str) -> MagicMock:
    provider = MagicMock()
    provider.complete_simple = AsyncMock(return_value=response_content)
    return provider


# ---------------------------------------------------------------------------
# BaselineAgent unit tests
# ---------------------------------------------------------------------------

class TestBaselineAgent:

    @pytest.mark.asyncio
    async def test_scan_returns_vulnerabilities(self):
        """Baseline scan returns a list of vulnerability dicts on valid JSON."""
        payload = json.dumps({
            "vulnerabilities": [
                {
                    "id": "vuln-1",
                    "type": "reentrancy",
                    "severity": "critical",
                    "location": "withdraw()",
                    "description": "CEI violation",
                    "evidence": "call before state update",
                    "confidence": 0.9,
                }
            ]
        })
        provider = _make_provider(payload)
        agent = BaselineAgent(provider)

        result = await agent.scan("contract code", "test.sol")

        assert len(result) == 1
        assert result[0]["type"] == "reentrancy"
        assert result[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_scan_returns_empty_on_no_vulnerabilities(self):
        """Baseline scan returns empty list when LLM finds nothing."""
        payload = json.dumps({"vulnerabilities": []})
        provider = _make_provider(payload)
        agent = BaselineAgent(provider)

        result = await agent.scan("safe contract code", "safe.sol")

        assert result == []

    @pytest.mark.asyncio
    async def test_scan_returns_empty_on_parse_failure(self):
        """Baseline scan returns empty list instead of raising on malformed JSON."""
        provider = _make_provider("This is not JSON at all.")
        agent = BaselineAgent(provider)

        result = await agent.scan("contract code", "test.sol")

        assert result == []

    @pytest.mark.asyncio
    async def test_scan_returns_empty_on_provider_exception(self):
        """Baseline scan returns empty list when the LLM call itself fails."""
        provider = MagicMock()
        provider.complete_simple = AsyncMock(side_effect=RuntimeError("API error"))
        agent = BaselineAgent(provider)

        result = await agent.scan("contract code", "test.sol")

        assert result == []

    @pytest.mark.asyncio
    async def test_scan_accepts_markdown_wrapped_json(self):
        """Baseline scan handles JSON wrapped in markdown code fences."""
        payload = '```json\n{"vulnerabilities": [{"type": "access_control", "severity": "high", "location": "setOwner()"}]}\n```'
        provider = _make_provider(payload)
        agent = BaselineAgent(provider)

        result = await agent.scan("contract code", "test.sol")

        assert len(result) == 1
        assert result[0]["type"] == "access_control"

    @pytest.mark.asyncio
    async def test_scan_passes_language_in_prompt(self):
        """Baseline scan includes language in the prompt sent to the provider."""
        provider = _make_provider('{"vulnerabilities": []}')
        agent = BaselineAgent(provider)

        await agent.scan("contract code", "vault.vy", language="vyper")

        call_args = provider.complete_simple.call_args
        prompt_text = call_args[0][0]
        assert "vyper" in prompt_text.lower()


# ---------------------------------------------------------------------------
# Evaluator.evaluate_baseline() integration tests
# ---------------------------------------------------------------------------

class TestEvaluateBaseline:

    def _make_evaluator(self) -> Evaluator:
        evaluator = Evaluator.__new__(Evaluator)
        evaluator.provider = LLMProvider.OPENAI
        evaluator.max_rounds = 1
        return evaluator

    @pytest.mark.asyncio
    async def test_evaluate_baseline_true_positive(self, tmp_path):
        """evaluate_baseline counts a TP when the baseline finds a known vuln type."""
        contract = tmp_path / "reentrancy_vuln.sol"
        contract.write_text("contract Foo {}")

        gt_file = tmp_path / "gt.json"
        gt_file.write_text(json.dumps([
            {
                "contract_path": "reentrancy_vuln.sol",
                "vulnerabilities": [{"type": "reentrancy", "severity": "critical"}],
            }
        ]))

        evaluator = self._make_evaluator()

        with patch("src.output.evaluator.ProviderFactory.create") as mock_factory:
            mock_llm = MagicMock()
            mock_factory.return_value = mock_llm

            with patch("src.output.evaluator.BaselineAgent") as MockAgent:
                mock_agent = MockAgent.return_value
                mock_agent.scan = AsyncMock(return_value=[
                    {"type": "reentrancy", "severity": "critical", "location": "withdraw()"}
                ])

                result = await evaluator.evaluate_baseline(tmp_path, gt_file)

        assert result.total_true_positives == 1
        assert result.total_false_positives == 0
        assert result.total_false_negatives == 0

    @pytest.mark.asyncio
    async def test_evaluate_baseline_false_positive(self, tmp_path):
        """evaluate_baseline counts an FP when the baseline flags a type not in ground truth."""
        contract = tmp_path / "safe_contract.sol"
        contract.write_text("contract Safe {}")

        gt_file = tmp_path / "gt.json"
        gt_file.write_text(json.dumps([
            {"contract_path": "safe_contract.sol", "vulnerabilities": []}
        ]))

        evaluator = self._make_evaluator()

        with patch("src.output.evaluator.ProviderFactory.create"):
            with patch("src.output.evaluator.BaselineAgent") as MockAgent:
                mock_agent = MockAgent.return_value
                mock_agent.scan = AsyncMock(return_value=[
                    {"type": "reentrancy", "severity": "high", "location": "foo()"}
                ])

                result = await evaluator.evaluate_baseline(tmp_path, gt_file)

        assert result.total_true_positives == 0
        assert result.total_false_positives == 1
        assert result.total_false_negatives == 0

    @pytest.mark.asyncio
    async def test_evaluate_baseline_false_negative(self, tmp_path):
        """evaluate_baseline counts an FN when the baseline misses a known vuln."""
        contract = tmp_path / "vuln.sol"
        contract.write_text("contract Vuln {}")

        gt_file = tmp_path / "gt.json"
        gt_file.write_text(json.dumps([
            {
                "contract_path": "vuln.sol",
                "vulnerabilities": [{"type": "arithmetic", "severity": "high"}],
            }
        ]))

        evaluator = self._make_evaluator()

        with patch("src.output.evaluator.ProviderFactory.create"):
            with patch("src.output.evaluator.BaselineAgent") as MockAgent:
                mock_agent = MockAgent.return_value
                mock_agent.scan = AsyncMock(return_value=[])  # missed it

                result = await evaluator.evaluate_baseline(tmp_path, gt_file)

        assert result.total_true_positives == 0
        assert result.total_false_positives == 0
        assert result.total_false_negatives == 1

    @pytest.mark.asyncio
    async def test_evaluate_baseline_benchmark_name(self, tmp_path):
        """evaluate_baseline sets benchmark_name to '<dir>_baseline'."""
        evaluator = self._make_evaluator()

        with patch("src.output.evaluator.ProviderFactory.create"):
            with patch("src.output.evaluator.BaselineAgent") as MockAgent:
                mock_agent = MockAgent.return_value
                mock_agent.scan = AsyncMock(return_value=[])
                result = await evaluator.evaluate_baseline(tmp_path)

        assert result.benchmark_name == f"{tmp_path.name}_baseline"


# ---------------------------------------------------------------------------
# Evaluator.print_comparison() smoke test
# ---------------------------------------------------------------------------

class TestPrintComparison:

    def _make_benchmark_result(self, name: str, tp: int, fp: int, fn: int) -> BenchmarkResult:
        gt = GroundTruth(contract_path="x.sol", vulnerabilities=[{"type": "reentrancy"}])
        eval_result = EvaluationResult(
            contract_path="x.sol",
            ground_truth=gt,
            predicted_vulnerabilities=[],
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
        )
        result = BenchmarkResult(
            benchmark_name=name,
            started_at=datetime.now(),
            completed_at=datetime.now(),
        )
        result.contract_results = [eval_result]
        result.total_contracts = 1
        result.successful_analyses = 1
        return result

    def test_print_comparison_runs_without_error(self):
        """print_comparison() produces output without raising exceptions."""
        from rich.console import Console
        from io import StringIO

        multi = self._make_benchmark_result("custom", tp=3, fp=1, fn=0)
        baseline = self._make_benchmark_result("custom_baseline", tp=2, fp=3, fn=1)

        evaluator = Evaluator.__new__(Evaluator)
        output = StringIO()
        rich_console = Console(file=output, highlight=False)

        evaluator.print_comparison(multi, baseline, rich_console)

        rendered = output.getvalue()
        assert "Multi-Agent" in rendered
        assert "Baseline" in rendered
        assert "Delta" in rendered

    def test_print_comparison_delta_signs(self):
        """Delta column shows correct sign when multi-agent outperforms baseline."""
        from rich.console import Console
        from io import StringIO

        # Multi-agent: perfect precision; baseline: 50%
        multi = self._make_benchmark_result("custom", tp=2, fp=0, fn=0)
        baseline = self._make_benchmark_result("custom_baseline", tp=1, fp=1, fn=1)

        evaluator = Evaluator.__new__(Evaluator)
        output = StringIO()
        rich_console = Console(file=output, highlight=False)

        # Should not raise
        evaluator.print_comparison(multi, baseline, rich_console)
