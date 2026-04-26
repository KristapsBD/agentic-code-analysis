import pytest
from unittest.mock import AsyncMock, MagicMock

import json
from src.agents.base_agent import AgentRole, VulnerabilityClaim, AgentResponse, BaseAgent
from src.config import ConfidenceLevel
from src.agents.attacker_agent import AttackerAgent
from src.agents.defender_agent import DefenderAgent
from src.agents.judge_agent import JudgeAgent, Verdict
from src.providers.base_provider import LLMResponse, Message


class TestVulnerabilityClaim:

    def test_claim_to_dict(self):
        claim = VulnerabilityClaim(
            id="test-1",
            vulnerability_type="Reentrancy",
            severity="critical",
            location="withdraw()",
            description="Test",
            evidence="Test evidence",
            confidence=ConfidenceLevel.HIGH,
        )
        result = claim.to_dict()
        assert result["id"] == "test-1"
        assert result["vulnerability_type"] == "Reentrancy"
        assert result["confidence"] == "HIGH"


class TestAttackerAgent:

    @pytest.fixture
    def attacker(self):
        provider = MagicMock()
        provider.provider_name = "test"
        provider.model = "test-model"
        return AttackerAgent(provider)

    @pytest.mark.asyncio
    async def test_analyze(self, attacker):
        mock_response = LLMResponse(
            content='{"vulnerabilities": [{"type": "Reentrancy", "severity": "critical", "location": "withdraw()", "description": "External call before state update", "evidence": "call before balance update", "confidence": 0.9}]}',
            model="test-model",
            tokens_used=100,
        )
        attacker.provider.complete = AsyncMock(return_value=mock_response)
        response = await attacker.analyze({
            "contract_code": "contract Test {}",
            "contract_path": "test.sol",
            "language": "solidity",
        })
        assert response.agent_role == AgentRole.ATTACKER
        assert len(response.claims) >= 1

    def test_extract_claims_from_json(self, attacker):
        parsed = {"vulnerabilities": [{"type": "Reentrancy", "severity": "high", "location": "withdraw()", "description": "Vulnerable", "evidence": "call before state update", "confidence": "HIGH"}]}
        claims = attacker._extract_claims(parsed)
        assert len(claims) == 1
        assert claims[0].vulnerability_type == "Reentrancy"

    def test_fallback_parse_claims(self, attacker):
        raw = "\nVULNERABILITY: Integer Overflow\nSEVERITY: medium\nLOCATION: add() function\nDESCRIPTION: Unchecked arithmetic\nCONFIDENCE: MEDIUM\n"
        claims = attacker._fallback_parse_claims(raw)
        assert len(claims) == 1
        assert claims[0]["vulnerability_type"] == "Integer Overflow"

    def test_extract_claims_fallback_path(self, attacker):
        parsed = {"raw_content": "VULNERABILITY: Test\nSEVERITY: high\nLOCATION: test()\nDESCRIPTION: Test vuln\nCONFIDENCE: HIGH", "_parse_failed": True}
        claims = attacker._extract_claims(parsed)
        assert len(claims) == 1
        assert claims[0].vulnerability_type == "Test"


class TestDefenderAgent:

    @pytest.fixture
    def defender(self):
        provider = MagicMock()
        provider.provider_name = "test"
        provider.model = "test-model"
        return DefenderAgent(provider)

    @pytest.mark.asyncio
    async def test_analyze(self, defender):
        mock_response = LLMResponse(
            content='{"verdict": "INVALID_CLAIM", "defense": "The contract uses a ReentrancyGuard modifier.", "evidence": "nonReentrant modifier applied", "mitigations_found": ["ReentrancyGuard"], "recommended_severity": "none", "confidence": 0.9}',
            model="test-model",
            tokens_used=100,
        )
        defender.provider.complete = AsyncMock(return_value=mock_response)
        claim = VulnerabilityClaim(id="test-1", vulnerability_type="Reentrancy", severity="high", location="withdraw()", description="Test", evidence="Test", confidence=ConfidenceLevel.HIGH)
        response = await defender.analyze({"contract_code": "contract Test {}", "claim": claim})
        assert response.agent_role == AgentRole.DEFENDER
        assert "INVALID_CLAIM" in response.reasoning


class TestJudgeAgent:

    @pytest.fixture
    def judge(self):
        provider = MagicMock()
        provider.provider_name = "test"
        provider.model = "test-model"
        return JudgeAgent(provider)

    def test_extract_verdict_valid(self, judge):
        parsed = {"verdict": "VALID_VULNERABILITY", "severity": "high", "confidence": "HIGH", "reasoning": "Confirmed.", "recommendation": "Add guard.", "attacker_score": 0.9, "defender_score": 0.4}
        verdict = judge._extract_verdict(parsed, "test-claim")
        assert verdict.is_valid is True
        assert verdict.severity == "high"
        assert verdict.confidence == ConfidenceLevel.HIGH

    def test_extract_verdict_not_vulnerable(self, judge):
        parsed = {"verdict": "NOT_VULNERABLE", "severity": "none", "confidence": "HIGH", "reasoning": "SafeMath used.", "recommendation": "None.", "attacker_score": 0.2, "defender_score": 0.9}
        verdict = judge._extract_verdict(parsed, "test-claim")
        assert verdict.is_valid is False

    def test_fallback_parse_verdict_valid(self, judge):
        response = "VERDICT: VALID_VULNERABILITY\n\nSEVERITY: HIGH\n\nREASONING: Confirmed.\n\nRECOMMENDATION: Add guard.\n\nCONFIDENCE: HIGH\n\nATTACKER_SCORE: 0.9\nDEFENDER_SCORE: 0.4"
        verdict = judge._fallback_parse_verdict(response, "test-claim")
        assert verdict.is_valid is True
        assert verdict.severity == "high"
        assert verdict.confidence == ConfidenceLevel.HIGH

    def test_fallback_parse_verdict_invalid(self, judge):
        response = "VERDICT: NOT_VULNERABLE\n\nSEVERITY: none\n\nREASONING: SafeMath used.\n\nCONFIDENCE: HIGH"
        verdict = judge._fallback_parse_verdict(response, "test-claim")
        assert verdict.is_valid is False


class TestParseJsonResponse:

    def test_markdown_extraction(self):
        result = BaseAgent._parse_json_response('```json\n{"key": "value"}\n```')
        assert result == {"key": "value"}

    def test_brace_extraction(self):
        result = BaseAgent._parse_json_response('some text {"key": "value"} trailing')
        assert result == {"key": "value"}

    def test_repair_truncated_mid_string(self):
        truncated = (
            '{\n'
            '  "vulnerabilities": [\n'
            '    {\n'
            '      "id": "vuln-1",\n'
            '      "type": "denial_of_service",\n'
            '      "severity": "high",\n'
            '      "evidence": "Lines 39-40 assign `new address[](0)` and `new uint'
        )
        result = BaseAgent._parse_json_response(truncated)
        assert "_parse_failed" not in result
        assert result["vulnerabilities"][0]["id"] == "vuln-1"
        assert "evidence" in result["vulnerabilities"][0]

    def test_fallback_on_unrecoverable(self):
        result = BaseAgent._parse_json_response("not json at all")
        assert result.get("_parse_failed") is True

    def test_repair_helper_mid_string(self):
        repaired = BaseAgent._repair_truncated_json('{"evidence": "foo `bar')
        assert json.loads(repaired) == {"evidence": "foo `bar"}

    def test_repair_helper_escaped_quote(self):
        repaired = BaseAgent._repair_truncated_json('{"key": "he said \\"hello')
        assert json.loads(repaired)["key"].startswith('he said "hello')


class TestWebSearchPipeline:

    def _make_provider(self, response_content: str):
        provider = MagicMock()
        provider.provider_name = "test"
        provider.model = "test-model"
        provider.complete = AsyncMock(
            return_value=LLMResponse(content=response_content, model="test-model", tokens_used=100)
        )
        return provider

    @pytest.mark.asyncio
    async def test_attacker_passes_web_search_to_provider(self):
        provider = self._make_provider('{"vulnerabilities": []}')
        attacker = AttackerAgent(provider, web_search=True)

        await attacker.analyze({
            "contract_code": "contract T {}",
            "contract_path": "t.sol",
            "language": "solidity",
        })

        _, call_kwargs = provider.complete.call_args
        assert call_kwargs.get("web_search") is True, (
            "web_search=True must reach provider.complete — "
            "if it doesn't, the API never receives the search tool"
        )

    @pytest.mark.asyncio
    async def test_defender_passes_web_search_to_provider(self):
        provider = self._make_provider(
            '{"verdict": "INVALID_CLAIM", "defense": "Safe", "evidence": "", '
            '"mitigations_found": [], "recommended_severity": "none", "confidence": 0.9}'
        )
        claim = VulnerabilityClaim(
            id="c1", vulnerability_type="Reentrancy", severity="high",
            location="withdraw()", description="Test", evidence="Test",
            confidence=ConfidenceLevel.HIGH,
        )
        defender = DefenderAgent(provider, web_search=True)

        await defender.analyze({"contract_code": "contract T {}", "claim": claim})

        _, call_kwargs = provider.complete.call_args
        assert call_kwargs.get("web_search") is True

    @pytest.mark.asyncio
    async def test_judge_passes_web_search_to_provider(self):
        provider = self._make_provider(
            '{"verdict": "VALID_VULNERABILITY", "severity": "high", "confidence": "HIGH", '
            '"reasoning": "Confirmed.", "recommendation": "Fix it.", '
            '"attacker_score": 0.8, "defender_score": 0.3}'
        )
        claim = VulnerabilityClaim(
            id="c1", vulnerability_type="Reentrancy", severity="high",
            location="withdraw()", description="Test", evidence="Test",
            confidence=ConfidenceLevel.HIGH,
        )
        judge = JudgeAgent(provider, web_search=True)

        await judge.analyze({
            "contract_code": "contract T {}",
            "claim": claim,
            "attacker_argument": "Vulnerable",
            "defender_argument": "Not vulnerable",
        })

        _, call_kwargs = provider.complete.call_args
        assert call_kwargs.get("web_search") is True

    @pytest.mark.asyncio
    async def test_agents_always_pass_json_mode_true(self):
        provider = self._make_provider('{"vulnerabilities": []}')
        attacker = AttackerAgent(provider, web_search=True)

        await attacker.analyze({
            "contract_code": "contract T {}",
            "contract_path": "t.sol",
            "language": "solidity",
        })

        _, call_kwargs = provider.complete.call_args
        assert call_kwargs.get("json_mode") is True, "all agent calls must use json_mode=True"
        assert call_kwargs.get("web_search") is True

    def test_debate_manager_propagates_web_search_to_all_agents(self):
        from src.orchestration.debate_manager import DebateManager

        provider = MagicMock()
        provider.provider_name = "test"
        provider.model = "test-model"
        dm = DebateManager(
            provider=provider,
            max_rounds=2,
            judge_clarification_trigger=ConfidenceLevel.LOW,
            web_search=True,
        )

        assert dm.attacker.web_search is True, "Attacker must inherit web_search=True"
        assert dm.defender.web_search is True, "Defender must inherit web_search=True"
        assert dm.judge.web_search is True, "Judge must inherit web_search=True"

    def test_debate_manager_web_search_false_by_default(self):
        from src.orchestration.debate_manager import DebateManager

        provider = MagicMock()
        provider.provider_name = "test"
        provider.model = "test-model"
        dm = DebateManager(provider=provider, max_rounds=2, judge_clarification_trigger=ConfidenceLevel.LOW)

        assert dm.attacker.web_search is False
        assert dm.defender.web_search is False
        assert dm.judge.web_search is False


class TestVerdict:

    def test_verdict_to_dict(self):
        verdict = Verdict(
            claim_id="test-1",
            is_valid=True,
            severity="critical",
            confidence=ConfidenceLevel.HIGH,
            reasoning="Test",
            recommendation="Fix",
            attacker_score=0.9,
            defender_score=0.2,
        )
        result = verdict.to_dict()
        assert result["is_valid"] is True
        assert result["severity"] == "critical"
        assert result["confidence"] == "HIGH"
