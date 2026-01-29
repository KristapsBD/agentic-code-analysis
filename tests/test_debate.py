"""
Tests for debate orchestration.
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from src.orchestration.conversation import Conversation, ConversationTurn, TurnType, DebateRound
from src.orchestration.debate_manager import DebateManager, DebateResult, ClaimResult
from src.agents.base_agent import VulnerabilityClaim, AgentResponse, AgentRole
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


class TestDebateRound:
    """Tests for DebateRound."""

    def test_round_creation(self):
        """Test creating a debate round."""
        round = DebateRound(
            round_number=1,
            claim_id="test-1",
            attacker_argument="Vulnerable",
            defender_argument="Protected",
        )
        assert round.round_number == 1
        assert round.claim_id == "test-1"

    def test_round_with_rebuttal(self):
        """Test round with rebuttal."""
        round = DebateRound(
            round_number=1,
            claim_id="test-1",
            attacker_argument="Vulnerable",
            defender_argument="Protected",
            attacker_rebuttal="Still vulnerable",
            defender_response="No, safe",
        )
        result = round.to_dict()
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
        round = conversation.add_debate_round(
            claim_id="test-1",
            attacker_argument="Vulnerable",
            defender_argument="Safe",
        )
        assert round.round_number == 1
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

    def test_estimate_tokens(self, conversation):
        """Test token estimation."""
        conversation.add_turn(TurnType.ATTACK, "Attacker", "A" * 100)
        tokens = conversation.estimate_tokens()
        assert tokens == 25  # 100 chars / 4


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
            verbose=False,
        )

    def test_manager_initialization(self, debate_manager):
        """Test manager initialization."""
        assert debate_manager.max_rounds == 2
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
