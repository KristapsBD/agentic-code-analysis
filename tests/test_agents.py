"""
Tests for agent implementations.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from src.agents.base_agent import AgentRole, VulnerabilityClaim, AgentResponse, ClaimContext
from src.agents.attacker_agent import AttackerAgent
from src.agents.defender_agent import DefenderAgent
from src.agents.judge_agent import JudgeAgent, Verdict
from src.providers.base_provider import LLMResponse, Message


class TestVulnerabilityClaim:
    """Tests for VulnerabilityClaim."""

    def test_claim_creation(self):
        """Test creating a vulnerability claim."""
        claim = VulnerabilityClaim(
            id="test-1",
            vulnerability_type="Reentrancy",
            severity="high",
            location="withdraw()",
            description="External call before state update",
            evidence="balance[msg.sender] = 0 after call",
            confidence=0.9,
        )
        assert claim.vulnerability_type == "Reentrancy"
        assert claim.severity == "high"
        assert claim.confidence == 0.9

    def test_claim_to_dict(self):
        """Test converting claim to dictionary."""
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


class TestClaimContext:
    """Tests for ClaimContext."""

    def test_claim_context_creation(self):
        """Test creating a claim context."""
        claim = VulnerabilityClaim(
            id="test-1",
            vulnerability_type="Reentrancy",
            severity="high",
            location="withdraw()",
            description="Test",
            evidence="Test",
            confidence=0.9,
        )
        ctx = ClaimContext(
            claim=claim,
            contract_code="contract Test {}",
            attacker_argument="The code is vulnerable",
            defender_argument="The code is safe",
        )
        assert ctx.claim.id == "test-1"
        assert ctx.attacker_argument == "The code is vulnerable"

    def test_claim_context_to_dict(self):
        """Test converting claim context to dict."""
        claim = VulnerabilityClaim(
            id="test-1",
            vulnerability_type="Reentrancy",
            severity="high",
            location="withdraw()",
            description="Test",
            evidence="Test",
            confidence=0.9,
        )
        ctx = ClaimContext(
            claim=claim,
            contract_code="contract Test {}",
        )
        result = ctx.to_dict()
        assert "claim" in result
        assert "contract_code" in result
        assert result["attacker_confidence"] == 0.0


class TestAgentResponse:
    """Tests for AgentResponse."""

    def test_response_creation(self):
        """Test creating an agent response."""
        response = AgentResponse(
            agent_role=AgentRole.ATTACKER,
            content="Found vulnerability",
            claims=[],
            reasoning="Test reasoning",
        )
        assert response.agent_role == AgentRole.ATTACKER
        assert response.content == "Found vulnerability"

    def test_response_with_claims(self):
        """Test response with vulnerability claims."""
        claim = VulnerabilityClaim(
            id="test-1",
            vulnerability_type="Reentrancy",
            severity="high",
            location="test()",
            description="Test",
            evidence="Test",
            confidence=0.9,
        )
        response = AgentResponse(
            agent_role=AgentRole.ATTACKER,
            content="Found issues",
            claims=[claim],
        )
        assert len(response.claims) == 1
        assert response.claims[0].vulnerability_type == "Reentrancy"

    def test_response_confidence_field(self):
        """Test that confidence field exists on AgentResponse."""
        response = AgentResponse(
            agent_role=AgentRole.ATTACKER,
            content="Test",
            confidence=0.85,
        )
        assert response.confidence == 0.85


class TestAttackerAgent:
    """Tests for AttackerAgent."""

    @pytest.fixture
    def mock_provider(self):
        """Create a mock LLM provider."""
        provider = MagicMock()
        provider.provider_name = "test"
        provider.model = "test-model"
        return provider

    @pytest.fixture
    def attacker(self, mock_provider):
        """Create an Attacker agent."""
        return AttackerAgent(mock_provider)

    def test_attacker_initialization(self, attacker):
        """Test attacker initialization."""
        assert attacker.name == "Attacker"
        assert attacker.role == AgentRole.ATTACKER

    @pytest.mark.asyncio
    async def test_analyze(self, attacker, mock_provider):
        """Test vulnerability scanning."""
        # The agent uses _send_message_json which appends JSON instructions
        # and then parses the response. Mock returns parseable JSON.
        mock_response = LLMResponse(
            content='{"vulnerabilities": [{"type": "Reentrancy", "severity": "critical", "location": "withdraw()", "description": "External call before state update", "evidence": "call before balance update", "confidence": 0.9}]}',
            model="test-model",
            tokens_used=100,
        )
        mock_provider.complete = AsyncMock(return_value=mock_response)

        context = {
            "contract_code": "contract Test {}",
            "contract_path": "test.sol",
            "language": "solidity",
        }

        response = await attacker.analyze(context)

        assert response.agent_role == AgentRole.ATTACKER
        assert len(response.claims) >= 1

    def test_extract_claims_from_json(self, attacker):
        """Test extracting claims from parsed JSON data."""
        parsed = {
            "vulnerabilities": [
                {
                    "type": "Reentrancy",
                    "severity": "high",
                    "location": "withdraw()",
                    "description": "Vulnerable to reentrancy",
                    "evidence": "call before state update",
                    "confidence": 0.85,
                }
            ]
        }
        claims = attacker._extract_claims(parsed)
        assert len(claims) == 1
        assert claims[0].vulnerability_type == "Reentrancy"

    def test_fallback_parse_claims(self, attacker):
        """Test fallback parsing for when JSON parse fails."""
        raw_content = """
VULNERABILITY: Integer Overflow
SEVERITY: medium
LOCATION: add() function
DESCRIPTION: Unchecked arithmetic
CONFIDENCE: 0.7
"""
        claims = attacker._fallback_parse_claims(raw_content)
        assert len(claims) == 1
        assert claims[0]["vulnerability_type"] == "Integer Overflow"

    def test_extract_claims_fallback_path(self, attacker):
        """Test _extract_claims with raw_content fallback."""
        parsed = {
            "raw_content": "VULNERABILITY: Test\nSEVERITY: high\nLOCATION: test()\nDESCRIPTION: Test vuln\nCONFIDENCE: 0.8",
            "_parse_failed": True,
        }
        # No "vulnerabilities" key, so fallback parser extracts from raw_content
        claims = attacker._extract_claims(parsed)
        assert len(claims) == 1
        assert claims[0].vulnerability_type == "Test"


class TestDefenderAgent:
    """Tests for DefenderAgent."""

    @pytest.fixture
    def mock_provider(self):
        """Create a mock LLM provider."""
        provider = MagicMock()
        provider.provider_name = "test"
        provider.model = "test-model"
        return provider

    @pytest.fixture
    def defender(self, mock_provider):
        """Create a Defender agent."""
        return DefenderAgent(mock_provider)

    def test_defender_initialization(self, defender):
        """Test defender initialization."""
        assert defender.name == "Defender"
        assert defender.role == AgentRole.DEFENDER

    @pytest.mark.asyncio
    async def test_analyze(self, defender, mock_provider):
        """Test claim defense with JSON structured output."""
        mock_response = LLMResponse(
            content='{"verdict": "INVALID_CLAIM", "defense": "The contract uses a ReentrancyGuard modifier.", "evidence": "nonReentrant modifier applied", "mitigations_found": ["ReentrancyGuard"], "recommended_severity": "none", "confidence": 0.9}',
            model="test-model",
            tokens_used=100,
        )
        mock_provider.complete = AsyncMock(return_value=mock_response)

        claim = VulnerabilityClaim(
            id="test-1",
            vulnerability_type="Reentrancy",
            severity="high",
            location="withdraw()",
            description="Test",
            evidence="Test",
            confidence=0.8,
        )

        context = {
            "contract_code": "contract Test {}",
            "claim": claim,
        }

        response = await defender.analyze(context)

        assert response.agent_role == AgentRole.DEFENDER
        assert "INVALID_CLAIM" in response.reasoning


class TestJudgeAgent:
    """Tests for JudgeAgent."""

    @pytest.fixture
    def mock_provider(self):
        """Create a mock LLM provider."""
        provider = MagicMock()
        provider.provider_name = "test"
        provider.model = "test-model"
        return provider

    @pytest.fixture
    def judge(self, mock_provider):
        """Create a Judge agent."""
        return JudgeAgent(mock_provider)

    def test_judge_initialization(self, judge):
        """Test judge initialization."""
        assert judge.name == "Judge"
        assert judge.role == AgentRole.JUDGE

    def test_extract_verdict_valid(self, judge):
        """Test extracting a valid vulnerability verdict from JSON."""
        parsed = {
            "verdict": "VALID_VULNERABILITY",
            "severity": "high",
            "confidence": 0.85,
            "reasoning": "The vulnerability is confirmed because there is no reentrancy guard.",
            "recommendation": "Add nonReentrant modifier.",
            "attacker_score": 0.9,
            "defender_score": 0.4,
        }
        verdict = judge._extract_verdict(parsed, "test-claim")

        assert verdict.is_valid is True
        assert verdict.severity == "high"
        assert verdict.confidence == 0.85

    def test_extract_verdict_not_vulnerable(self, judge):
        """Test extracting a not-vulnerable verdict."""
        parsed = {
            "verdict": "NOT_VULNERABLE",
            "severity": "none",
            "confidence": 0.9,
            "reasoning": "The contract properly uses SafeMath.",
            "recommendation": "No action needed.",
            "attacker_score": 0.2,
            "defender_score": 0.9,
        }
        verdict = judge._extract_verdict(parsed, "test-claim")

        assert verdict.is_valid is False

    def test_fallback_parse_verdict_valid(self, judge):
        """Test fallback parsing for valid vulnerability text."""
        response = """VERDICT: VALID_VULNERABILITY

SEVERITY: HIGH

REASONING: The vulnerability is confirmed.

RECOMMENDATION: Add nonReentrant modifier.

CONFIDENCE: 0.85

ATTACKER_SCORE: 0.9
DEFENDER_SCORE: 0.4"""

        verdict = judge._fallback_parse_verdict(response, "test-claim")

        assert verdict.is_valid is True
        assert verdict.severity == "high"
        assert verdict.confidence == 0.85

    def test_fallback_parse_verdict_invalid(self, judge):
        """Test fallback parsing for invalid claim text."""
        response = """VERDICT: NOT_VULNERABLE

SEVERITY: none

REASONING: The contract properly uses SafeMath.

CONFIDENCE: 0.9"""

        verdict = judge._fallback_parse_verdict(response, "test-claim")

        assert verdict.is_valid is False

    def test_extract_verdict_with_clarification(self, judge):
        """Test extracting verdict with clarification flags."""
        parsed = {
            "verdict": "NOT_VULNERABLE",
            "severity": "none",
            "confidence": 0.5,
            "reasoning": "Unclear whether the guard is applied.",
            "recommendation": "Needs review.",
            "attacker_score": 0.5,
            "defender_score": 0.5,
            "needs_clarification": True,
            "clarification_question": "Is the nonReentrant modifier applied to all external functions?",
        }
        verdict = judge._extract_verdict(parsed, "test-claim")
        assert verdict.confidence == 0.5
        # needs_clarification is not part of Verdict, it's in metadata


class TestVerdict:
    """Tests for Verdict class."""

    def test_verdict_creation(self):
        """Test creating a verdict."""
        verdict = Verdict(
            claim_id="test-1",
            is_valid=True,
            severity="high",
            confidence=0.85,
            reasoning="Test reasoning",
            recommendation="Fix the issue",
            attacker_score=0.8,
            defender_score=0.3,
        )
        assert verdict.is_valid is True
        assert verdict.severity == "high"

    def test_verdict_to_dict(self):
        """Test converting verdict to dictionary."""
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
