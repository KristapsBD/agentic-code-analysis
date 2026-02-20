"""
Tests for debate orchestration.
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from src.orchestration.conversation import Conversation, ConversationTurn, TurnType, DebateRound
from src.orchestration.debate_manager import DebateManager, DebateResult, ClaimResult
from src.agents.base_agent import AgentResponse, AgentRole, VulnerabilityClaim
from src.agents.judge_agent import Verdict


class TestConversationTurn:
    """Tests for ConversationTurn."""

    def test_turn_creation(self):
        """Test creating a conversation turn."""
        turn = ConversationTurn(
            turn_type=TurnType.ATTACK,
            agent_name="Attacker",
            content="Found vulnerability",
        )
        assert turn.turn_type == TurnType.ATTACK
        assert turn.agent_name == "Attacker"

    def test_turn_to_dict(self):
        """Test converting turn to dictionary."""
        turn = ConversationTurn(
            turn_type=TurnType.DEFENSE,
            agent_name="Defender",
            content="No vulnerability",
            claim_id="test-1",
        )
        result = turn.to_dict()
        assert result["turn_type"] == "defense"
        assert result["claim_id"] == "test-1"

    def test_clarification_turn_type(self):
        """Test that CLARIFICATION turn type exists."""
        turn = ConversationTurn(
            turn_type=TurnType.CLARIFICATION,
            agent_name="Judge",
            content="What about the modifier?",
            claim_id="test-1",
        )
        assert turn.turn_type == TurnType.CLARIFICATION
        result = turn.to_dict()
        assert result["turn_type"] == "clarification"

    def test_clarification_response_turn_type(self):
        """Test that CLARIFICATION_RESPONSE turn type exists."""
        turn = ConversationTurn(
            turn_type=TurnType.CLARIFICATION_RESPONSE,
            agent_name="Attacker",
            content="The modifier is not applied.",
            claim_id="test-1",
        )
        assert turn.turn_type == TurnType.CLARIFICATION_RESPONSE
        result = turn.to_dict()
        assert result["turn_type"] == "clarification_response"


class TestDebateRound:
    """Tests for DebateRound."""

    def test_round_creation(self):
        """Test creating a debate round."""
        debate_round = DebateRound(
            round_number=1,
            claim_id="test-1",
            attacker_argument="Vulnerable",
            defender_argument="Protected",
        )
        assert debate_round.round_number == 1
        assert debate_round.claim_id == "test-1"

    def test_round_with_rebuttal(self):
        """Test round with rebuttal."""
        debate_round = DebateRound(
            round_number=1,
            claim_id="test-1",
            attacker_argument="Vulnerable",
            defender_argument="Protected",
            attacker_rebuttal="Still vulnerable",
            defender_response="No, safe",
        )
        result = debate_round.to_dict()
        assert result["attacker_rebuttal"] == "Still vulnerable"


class TestConversation:
    """Tests for Conversation."""

    @pytest.fixture
    def conversation(self):
        """Create a test conversation."""
        return Conversation(contract_path="test.sol")

    def test_conversation_initialization(self, conversation):
        """Test conversation initialization."""
        assert conversation.contract_path == "test.sol"
        assert len(conversation.turns) == 0

    def test_add_turn(self, conversation):
        """Test adding a turn."""
        turn = conversation.add_turn(
            TurnType.ATTACK,
            "Attacker",
            "Found issue",
            claim_id="test-1",
        )
        assert len(conversation.turns) == 1
        assert conversation.turns[0].content == "Found issue"

    def test_add_debate_round(self, conversation):
        """Test adding a debate round."""
        debate_round = conversation.add_debate_round(
            claim_id="test-1",
            attacker_argument="Vulnerable",
            defender_argument="Safe",
        )
        assert debate_round.round_number == 1
        assert "test-1" in conversation.debate_rounds

    def test_get_debate_history(self, conversation):
        """Test getting debate history."""
        conversation.add_debate_round(
            "test-1",
            "Attack 1",
            "Defense 1",
        )
        conversation.add_debate_round(
            "test-1",
            "Attack 2",
            "Defense 2",
        )
        history = conversation.get_debate_history("test-1")
        assert len(history) == 2

    def test_get_turns_by_claim(self, conversation):
        """Test filtering turns by claim."""
        conversation.add_turn(TurnType.ATTACK, "Attacker", "Content 1", claim_id="test-1")
        conversation.add_turn(TurnType.DEFENSE, "Defender", "Content 2", claim_id="test-1")
        conversation.add_turn(TurnType.ATTACK, "Attacker", "Content 3", claim_id="test-2")

        turns = conversation.get_turns_by_claim("test-1")
        assert len(turns) == 2

    def test_distill_claim_context(self, conversation):
        """Test context distillation for a claim."""
        conversation.add_turn(TurnType.ATTACK, "Attacker", "Vulnerable code", claim_id="c1")
        conversation.add_turn(TurnType.DEFENSE, "Defender", "Code is safe", claim_id="c1")
        conversation.add_turn(TurnType.REBUTTAL, "Attacker", "Still vulnerable", claim_id="c1")
        conversation.add_debate_round("c1", "attack", "defense")

        distilled = conversation.distill_claim_context("c1")
        assert distilled["round_count"] == 1
        assert distilled["total_turns"] == 3
        assert len(distilled["attacker_key_points"]) == 2  # ATTACK + REBUTTAL
        assert len(distilled["defender_key_points"]) == 1  # DEFENSE


class TestDebateResult:
    """Tests for DebateResult."""

    def test_result_creation(self):
        """Test creating a debate result."""
        result = DebateResult(
            contract_path="test.sol",
            contract_language="solidity",
            started_at=datetime.now(),
        )
        assert result.total_vulnerabilities == 0
        assert result.confirmed_vulnerabilities == 0

    def test_result_with_claims(self):
        """Test result with claims and verdicts."""
        claim = VulnerabilityClaim(
            id="test-1",
            vulnerability_type="Reentrancy",
            severity="high",
            location="test()",
            description="Test",
            evidence="Test",
            confidence=0.9,
        )
        verdict = Verdict(
            claim_id="test-1",
            is_valid=True,
            severity="high",
            confidence=0.9,
            reasoning="Test",
            recommendation="Fix",
            attacker_score=0.8,
            defender_score=0.3,
        )
        claim_result = ClaimResult(
            claim=claim,
            verdict=verdict,
            debate_rounds=2,
        )

        result = DebateResult(
            contract_path="test.sol",
            contract_language="solidity",
            started_at=datetime.now(),
            initial_claims=[claim],
            claim_results=[claim_result],
        )

        assert result.total_vulnerabilities == 1
        assert result.confirmed_vulnerabilities == 1
        assert result.high_count == 1


class TestDebateManager:
    """Tests for DebateManager."""

    @pytest.fixture
    def mock_provider(self):
        """Create a mock LLM provider."""
        provider = MagicMock()
        provider.provider_name = "test"
        provider.model = "test-model"
        return provider

    @pytest.fixture
    def debate_manager(self, mock_provider):
        """Create a debate manager."""
        return DebateManager(
            provider=mock_provider,
            max_rounds=2,
            judge_confidence_threshold=0.7,
            verbose=False,
        )

    def test_manager_initialization(self, debate_manager):
        """Test manager initialization."""
        assert debate_manager.max_rounds == 2
        assert debate_manager.judge_confidence_threshold == 0.7
        assert debate_manager.attacker is not None
        assert debate_manager.defender is not None
        assert debate_manager.judge is not None

    @pytest.mark.asyncio
    async def test_run_debate_no_vulnerabilities(self, debate_manager, mock_provider):
        """Test debate with no vulnerabilities found."""
        # Mock attacker response (no vulnerabilities)
        attacker_response = AgentResponse(
            agent_role=AgentRole.ATTACKER,
            content="No vulnerabilities found",
            claims=[],
        )

        with patch.object(debate_manager.attacker, 'analyze', new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = attacker_response

            result = await debate_manager.run_debate(
                "contract Test {}",
                "test.sol"
            )

            assert result["total_vulnerabilities"] == 0
            assert len(result["claim_results"]) == 0

    def test_reset_agents(self, debate_manager):
        """Test resetting agent histories."""
        debate_manager.attacker.conversation_history.append(
            MagicMock()
        )
        debate_manager.reset_agents()
        assert len(debate_manager.attacker.conversation_history) == 0

    def test_has_converged_attacker_low(self, debate_manager):
        """Test convergence when attacker confidence is low."""
        assert DebateManager._has_converged(0.3, 0.5) is True

    def test_has_converged_defender_high(self, debate_manager):
        """Test convergence when defender confidence is high."""
        assert DebateManager._has_converged(0.7, 0.85) is True

    def test_no_convergence(self, debate_manager):
        """Test no convergence when both are in middle range."""
        assert DebateManager._has_converged(0.6, 0.6) is False


class TestClaimResult:
    """Tests for ClaimResult."""

    def test_claim_result_creation(self):
        """Test creating a claim result."""
        claim = VulnerabilityClaim(
            id="test-1",
            vulnerability_type="Test",
            severity="high",
            location="test()",
            description="Test",
            evidence="Test",
            confidence=0.9,
        )
        verdict = Verdict(
            claim_id="test-1",
            is_valid=True,
            severity="high",
            confidence=0.9,
            reasoning="Test",
            recommendation="Fix",
            attacker_score=0.8,
            defender_score=0.3,
        )
        result = ClaimResult(
            claim=claim,
            verdict=verdict,
            debate_rounds=2,
        )
        assert result.debate_rounds == 2
        assert not result.attacker_conceded
        assert not result.judge_requested_clarification

    def test_claim_result_with_clarification(self):
        """Test claim result with judge clarification."""
        claim = VulnerabilityClaim(
            id="test-1",
            vulnerability_type="Test",
            severity="high",
            location="test()",
            description="Test",
            evidence="Test",
            confidence=0.9,
        )
        verdict = Verdict(
            claim_id="test-1",
            is_valid=True,
            severity="high",
            confidence=0.9,
            reasoning="Test",
            recommendation="Fix",
            attacker_score=0.8,
            defender_score=0.3,
        )
        result = ClaimResult(
            claim=claim,
            verdict=verdict,
            debate_rounds=2,
            judge_requested_clarification=True,
        )
        assert result.judge_requested_clarification is True
        data = result.to_dict()
        assert data["judge_requested_clarification"] is True

    def test_claim_result_to_dict(self):
        """Test converting claim result to dictionary."""
        claim = VulnerabilityClaim(
            id="test-1",
            vulnerability_type="Test",
            severity="high",
            location="test()",
            description="Test",
            evidence="Test",
            confidence=0.9,
        )
        verdict = Verdict(
            claim_id="test-1",
            is_valid=False,
            severity="low",
            confidence=0.7,
            reasoning="Test",
            recommendation="Review",
            attacker_score=0.4,
            defender_score=0.8,
        )
        result = ClaimResult(
            claim=claim,
            verdict=verdict,
            debate_rounds=1,
            attacker_conceded=True,
        )
        data = result.to_dict()
        assert data["attacker_conceded"] is True
