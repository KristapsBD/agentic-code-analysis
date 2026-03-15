"""
Tests for agent implementations.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from src.agents.base_agent import AgentRole, VulnerabilityClaim, AgentResponse
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
            confidence=0.8,
        )
        result = claim.to_dict()
        assert result["id"] == "test-1"
        assert result["vulnerability_type"] == "Reentrancy"
        assert result["confidence"] == 0.8


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
        parsed = {"vulnerabilities": [{"type": "Reentrancy", "severity": "high", "location": "withdraw()", "description": "Vulnerable", "evidence": "call before state update", "confidence": 0.85}]}
        claims = attacker._extract_claims(parsed)
        assert len(claims) == 1
        assert claims[0].vulnerability_type == "Reentrancy"

    def test_fallback_parse_claims(self, attacker):
        raw = "\nVULNERABILITY: Integer Overflow\nSEVERITY: medium\nLOCATION: add() function\nDESCRIPTION: Unchecked arithmetic\nCONFIDENCE: 0.7\n"
        claims = attacker._fallback_parse_claims(raw)
        assert len(claims) == 1
        assert claims[0]["vulnerability_type"] == "Integer Overflow"

    def test_extract_claims_fallback_path(self, attacker):
        parsed = {"raw_content": "VULNERABILITY: Test\nSEVERITY: high\nLOCATION: test()\nDESCRIPTION: Test vuln\nCONFIDENCE: 0.8", "_parse_failed": True}
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
        claim = VulnerabilityClaim(id="test-1", vulnerability_type="Reentrancy", severity="high", location="withdraw()", description="Test", evidence="Test", confidence=0.8)
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
        parsed = {"verdict": "VALID_VULNERABILITY", "severity": "high", "confidence": 0.85, "reasoning": "Confirmed.", "recommendation": "Add guard.", "attacker_score": 0.9, "defender_score": 0.4}
        verdict = judge._extract_verdict(parsed, "test-claim")
        assert verdict.is_valid is True
        assert verdict.severity == "high"
        assert verdict.confidence == 0.85

    def test_extract_verdict_not_vulnerable(self, judge):
        parsed = {"verdict": "NOT_VULNERABLE", "severity": "none", "confidence": 0.9, "reasoning": "SafeMath used.", "recommendation": "None.", "attacker_score": 0.2, "defender_score": 0.9}
        verdict = judge._extract_verdict(parsed, "test-claim")
        assert verdict.is_valid is False

    def test_fallback_parse_verdict_valid(self, judge):
        response = "VERDICT: VALID_VULNERABILITY\n\nSEVERITY: HIGH\n\nREASONING: Confirmed.\n\nRECOMMENDATION: Add guard.\n\nCONFIDENCE: 0.85\n\nATTACKER_SCORE: 0.9\nDEFENDER_SCORE: 0.4"
        verdict = judge._fallback_parse_verdict(response, "test-claim")
        assert verdict.is_valid is True
        assert verdict.severity == "high"
        assert verdict.confidence == 0.85

    def test_fallback_parse_verdict_invalid(self, judge):
        response = "VERDICT: NOT_VULNERABLE\n\nSEVERITY: none\n\nREASONING: SafeMath used.\n\nCONFIDENCE: 0.9"
        verdict = judge._fallback_parse_verdict(response, "test-claim")
        assert verdict.is_valid is False


class TestVerdict:

    def test_verdict_to_dict(self):
        verdict = Verdict(
            claim_id="test-1",
            is_valid=True,
            severity="critical",
            confidence=0.9,
            reasoning="Test",
            recommendation="Fix",
            attacker_score=0.9,
            defender_score=0.2,
        )
        result = verdict.to_dict()
        assert result["is_valid"] is True
        assert result["severity"] == "critical"
        assert result["confidence"] == 0.9
