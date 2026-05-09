import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from src.orchestration.conversation import Conversation, ConversationTurn, TurnType
from src.orchestration.debate_manager import DebateManager, DebateResult, ClaimResult
from src.agents.base_agent import AgentResponse, AgentRole, VulnerabilityClaim
from src.agents.judge_agent import Verdict
from src.config import ConfidenceLevel


class TestConversationTurn:

    def test_turn_to_dict(self):
        turn = ConversationTurn(
            turn_type=TurnType.DEFENSE,
            agent_name="Defender",
            content="No vulnerability",
            claim_id="test-1",
        )
        result = turn.to_dict()
        assert result["turn_type"] == "defense"
        assert result["claim_id"] == "test-1"
        assert result["agent_name"] == "Defender"
        assert result["content"] == "No vulnerability"


class TestConversation:

    def test_add_turn(self):
        conv = Conversation(contract_path="test.sol")
        conv.add_turn(TurnType.ATTACK, "Attacker", "Found issue", claim_id="test-1")
        assert len(conv.turns) == 1
        assert conv.turns[0].content == "Found issue"


class TestDebateResult:

    def test_result_with_claims(self):
        claim = VulnerabilityClaim(
            id="test-1",
            vulnerability_type="Reentrancy",
            severity="high",
            location="test()",
            description="Test",
            evidence="Test",
            confidence=ConfidenceLevel.HIGH,
        )
        verdict = Verdict(
            claim_id="test-1",
            is_valid=True,
            severity="high",
            confidence=ConfidenceLevel.HIGH,
            reasoning="Test",
            recommendation="Fix",
        )
        result = DebateResult(
            contract_path="test.sol",
            contract_language="solidity",
            started_at=datetime.now(),
            initial_claims=[claim],
            claim_results=[ClaimResult(claim=claim, verdict=verdict, debate_rounds=2)],
        )
        assert result.total_vulnerabilities == 1
        assert result.confirmed_vulnerabilities == 1
        assert result.high_count == 1


class TestDebateManager:

    @pytest.fixture
    def debate_manager(self):
        provider = MagicMock()
        provider.provider_name = "test"
        provider.model = "test-model"
        return DebateManager(provider=provider, max_rounds=2, judge_clarification_trigger=ConfidenceLevel.LOW, verbose=False)

    @pytest.mark.asyncio
    async def test_run_debate_no_vulnerabilities(self, debate_manager):
        attacker_response = AgentResponse(agent_role=AgentRole.ATTACKER, content="No vulnerabilities found", claims=[])
        with patch.object(debate_manager.attacker, 'analyze', new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = attacker_response
            result = await debate_manager.run_debate("contract Test {}", "test.sol")
        assert result["total_vulnerabilities"] == 0
        assert len(result["claim_results"]) == 0

    def test_reset_agents(self, debate_manager):
        debate_manager.attacker.conversation_history.append(MagicMock())
        debate_manager.reset_agents()
        assert len(debate_manager.attacker.conversation_history) == 0

    def test_has_converged_attacker_low(self):
        assert DebateManager._has_converged(ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM) is True

    def test_has_converged_defender_high(self):
        assert DebateManager._has_converged(ConfidenceLevel.MEDIUM, ConfidenceLevel.HIGH) is True

    def test_no_convergence(self):
        assert DebateManager._has_converged(ConfidenceLevel.MEDIUM, ConfidenceLevel.MEDIUM) is False


class TestDebateResultConversation:

    def test_result_to_dict_includes_conversation(self):
        conv = Conversation("test.sol")
        conv.add_turn(TurnType.ATTACK, "Attacker", "Found reentrancy", claim_id="c1")
        conv.add_turn(TurnType.DEFENSE, "Defender", "No it isnt", claim_id="c1")

        result = DebateResult(
            contract_path="test.sol",
            contract_language="solidity",
            started_at=datetime.now(),
            conversation=conv,
        )
        data = result.to_dict()

        assert "conversation" in data
        assert len(data["conversation"]) == 2
        assert data["conversation"][0]["turn_type"] == "attack"
        assert data["conversation"][0]["agent_name"] == "Attacker"
        assert data["conversation"][0]["content"] == "Found reentrancy"
        assert data["conversation"][1]["turn_type"] == "defense"

    def test_result_to_dict_no_conversation(self):
        result = DebateResult(
            contract_path="test.sol",
            contract_language="solidity",
            started_at=datetime.now(),
        )
        data = result.to_dict()
        assert data["conversation"] == []


class TestClaimResult:

    @pytest.fixture
    def base_claim_result(self):
        claim = VulnerabilityClaim(
            id="test-1", vulnerability_type="Test", severity="high",
            location="test()", description="Test", evidence="Test", confidence=ConfidenceLevel.HIGH,
        )
        verdict = Verdict(
            claim_id="test-1", is_valid=True, severity="high", confidence=ConfidenceLevel.HIGH,
            reasoning="Test", recommendation="Fix",
        )
        return claim, verdict

    def test_final_assessment_not_truncated(self, base_claim_result):
        claim, verdict = base_claim_result
        long_text = "A" * 1000
        result = ClaimResult(claim=claim, verdict=verdict, debate_rounds=1, final_assessment=long_text)
        assert len(result.to_dict()["final_assessment"]) == 1000

    def test_to_dict_attacker_conceded(self, base_claim_result):
        claim, verdict = base_claim_result
        result = ClaimResult(claim=claim, verdict=verdict, debate_rounds=1, attacker_conceded=True)
        assert result.to_dict()["attacker_conceded"] is True

    def test_to_dict_judge_clarification(self, base_claim_result):
        claim, verdict = base_claim_result
        result = ClaimResult(claim=claim, verdict=verdict, debate_rounds=2, judge_requested_clarification=True)
        assert result.to_dict()["judge_requested_clarification"] is True

    def test_to_dict_defender_verdict(self, base_claim_result):
        claim, verdict = base_claim_result
        for dv in ("VALID_VULNERABILITY", "INVALID_CLAIM", "PARTIALLY_MITIGATED"):
            result = ClaimResult(claim=claim, verdict=verdict, debate_rounds=1, defender_verdict=dv)
            assert result.to_dict()["defender_verdict"] == dv

    def test_to_dict_defender_verdict_default_none(self, base_claim_result):
        claim, verdict = base_claim_result
        result = ClaimResult(claim=claim, verdict=verdict, debate_rounds=1)
        assert result.to_dict()["defender_verdict"] is None
