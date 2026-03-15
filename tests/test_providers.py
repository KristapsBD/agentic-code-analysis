"""
Tests for LLM provider implementations.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.providers.base_provider import BaseLLMProvider, LLMResponse, Message
from src.providers.openai_provider import OpenAIProvider
from src.providers.anthropic_provider import AnthropicProvider
from src.providers.gemini_provider import GeminiProvider
from src.providers.provider_factory import ProviderFactory
from src.config import LLMProvider


class TestMessage:

    def test_message_to_dict(self):
        msg = Message(role="assistant", content="Hi there")
        assert msg.to_dict() == {"role": "assistant", "content": "Hi there"}


class TestLLMResponse:

    def test_total_tokens_calculation(self):
        response = LLMResponse(content="Test", model="test-model", prompt_tokens=30, completion_tokens=20)
        assert response.total_tokens == 50


class TestOpenAIProvider:

    @pytest.fixture
    def provider(self):
        return OpenAIProvider(api_key="test-key", model="gpt-4o", temperature=0.7)

    @pytest.mark.asyncio
    async def test_complete(self, provider):
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Test response"), finish_reason="stop")]
        mock_response.usage = MagicMock(total_tokens=100, prompt_tokens=50, completion_tokens=50)
        mock_response.model = "gpt-4o"
        mock_response.model_dump = MagicMock(return_value={})
        provider.client.chat.completions.create = AsyncMock(return_value=mock_response)

        response = await provider.complete([Message(role="user", content="Hello")])
        assert response.content == "Test response"
        assert response.model == "gpt-4o"

    def test_validate_messages_empty(self, provider):
        with pytest.raises(ValueError, match="cannot be empty"):
            provider._validate_messages([])

    def test_validate_messages_invalid_role(self, provider):
        with pytest.raises(ValueError, match="Invalid message role"):
            provider._validate_messages([Message(role="invalid", content="test")])


class TestAnthropicProvider:

    @pytest.fixture
    def provider(self):
        return AnthropicProvider(api_key="test-key", model="claude-3-5-sonnet-20241022", temperature=0.7)

    @pytest.mark.asyncio
    async def test_complete(self, provider):
        mock_block = MagicMock()
        mock_block.type = "text"
        mock_block.text = "Test response"
        mock_response = MagicMock()
        mock_response.content = [mock_block]
        mock_response.model = "claude-3-5-sonnet-20241022"
        mock_response.usage = MagicMock(input_tokens=50, output_tokens=50)
        mock_response.stop_reason = "end_turn"
        mock_response.model_dump = MagicMock(return_value={})
        provider.client.messages.create = AsyncMock(return_value=mock_response)

        response = await provider.complete([Message(role="user", content="Hello")])
        assert response.content == "Test response"


class TestProviderFactory:

    @patch("src.providers.provider_factory.settings")
    def test_create_openai(self, mock_settings):
        mock_settings.default_provider = LLMProvider.OPENAI
        mock_settings.default_temperature = 0.7
        mock_settings.get_model_for_provider.return_value = "gpt-4o"
        mock_settings.get_api_key_for_provider.return_value = "test-key"
        assert isinstance(ProviderFactory.create(LLMProvider.OPENAI), OpenAIProvider)

    @patch("src.providers.provider_factory.settings")
    def test_create_anthropic(self, mock_settings):
        mock_settings.default_provider = LLMProvider.ANTHROPIC
        mock_settings.default_temperature = 0.7
        mock_settings.get_model_for_provider.return_value = "claude-3-5-sonnet-20241022"
        mock_settings.get_api_key_for_provider.return_value = "test-key"
        assert isinstance(ProviderFactory.create(LLMProvider.ANTHROPIC), AnthropicProvider)

    @patch("src.providers.provider_factory.settings")
    def test_create_without_api_key(self, mock_settings):
        mock_settings.get_api_key_for_provider.return_value = None
        mock_settings.default_provider = LLMProvider.OPENAI
        with pytest.raises(ValueError, match="API key"):
            ProviderFactory.create(LLMProvider.OPENAI)


# ---------------------------------------------------------------------------
# Web search tests
# ---------------------------------------------------------------------------

class TestAnthropicWebSearch:

    @pytest.fixture
    def provider(self):
        return AnthropicProvider(api_key="test-key", model="claude-3-5-sonnet-20241022")

    @pytest.mark.asyncio
    async def test_web_search_adds_tool_to_request(self, provider):
        mock_block = MagicMock()
        mock_block.type = "text"
        mock_block.text = "Here is the answer."
        mock_response = MagicMock()
        mock_response.content = [mock_block]
        mock_response.model = "claude-3-5-sonnet-20241022"
        mock_response.usage = MagicMock(input_tokens=20, output_tokens=10)
        mock_response.stop_reason = "end_turn"
        mock_response.model_dump = MagicMock(return_value={})
        provider.client.messages.create = AsyncMock(return_value=mock_response)

        await provider.complete([Message(role="user", content="What is the latest ETH price?")], web_search=True)

        call_kwargs = provider.client.messages.create.call_args.kwargs
        assert "tools" in call_kwargs
        assert any(t.get("type") == "web_search_20260209" and t.get("name") == "web_search" for t in call_kwargs["tools"])

    @pytest.mark.asyncio
    async def test_no_web_search_by_default(self, provider):
        mock_block = MagicMock()
        mock_block.type = "text"
        mock_block.text = "Answer."
        mock_response = MagicMock()
        mock_response.content = [mock_block]
        mock_response.model = "claude-3-5-sonnet-20241022"
        mock_response.usage = MagicMock(input_tokens=10, output_tokens=5)
        mock_response.stop_reason = "end_turn"
        mock_response.model_dump = MagicMock(return_value={})
        provider.client.messages.create = AsyncMock(return_value=mock_response)

        await provider.complete([Message(role="user", content="Hello")])

        call_kwargs = provider.client.messages.create.call_args.kwargs
        assert "tools" not in call_kwargs


class TestGeminiWebSearch:

    @pytest.fixture
    def provider(self):
        with patch("src.providers.gemini_provider.genai.Client"):
            return GeminiProvider(api_key="test-key", model="gemini-2.5-flash")

    def test_build_contents_system_extracted(self, provider):
        system_instr, contents = provider._build_contents([
            Message(role="system", content="You are a security auditor."),
            Message(role="user", content="Analyse this contract."),
        ])
        assert system_instr == "You are a security auditor."
        assert len(contents) == 1
        assert contents[0].role == "user"

    def test_build_contents_multi_turn(self, provider):
        _, contents = provider._build_contents([
            Message(role="user", content="Hello"),
            Message(role="assistant", content="Hi there"),
            Message(role="user", content="Question?"),
        ])
        assert len(contents) == 3
        assert contents[1].role == "model"

    @pytest.mark.asyncio
    async def test_web_search_adds_google_search_tool(self, provider):
        from google.genai import types

        mock_response = MagicMock()
        mock_response.candidates = [MagicMock(content=MagicMock(parts=[MagicMock(text="Answer", spec=["text"])]))]
        mock_response.usage_metadata = MagicMock(prompt_token_count=10, candidates_token_count=5, total_token_count=15)

        captured_config = {}

        async def fake_generate(model, contents, config):
            captured_config["config"] = config
            return mock_response

        provider.client.aio.models.generate_content = fake_generate

        await provider.complete([Message(role="user", content="Latest Solidity version?")], web_search=True)

        config = captured_config["config"]
        assert config.tools is not None
        assert any(isinstance(t, types.Tool) and t.google_search is not None for t in config.tools)

    @pytest.mark.asyncio
    async def test_no_web_search_by_default(self, provider):
        mock_response = MagicMock()
        mock_response.candidates = [MagicMock(content=MagicMock(parts=[MagicMock(text="Answer", spec=["text"])]))]
        mock_response.usage_metadata = MagicMock(prompt_token_count=10, candidates_token_count=5, total_token_count=15)

        captured_config = {}

        async def fake_generate(model, contents, config):
            captured_config["config"] = config
            return mock_response

        provider.client.aio.models.generate_content = fake_generate

        await provider.complete([Message(role="user", content="Hello")])

        assert not captured_config["config"].tools
