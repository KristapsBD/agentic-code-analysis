"""
Tests for LLM provider implementations.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.providers.base_provider import BaseLLMProvider, LLMResponse, Message
from src.providers.openai_provider import OpenAIProvider
from src.providers.anthropic_provider import AnthropicProvider
from src.providers.provider_factory import ProviderFactory
from src.config import LLMProvider


class TestMessage:
    """Tests for the Message class."""

    def test_message_creation(self):
        """Test creating a message."""
        msg = Message(role="user", content="Hello")
        assert msg.role == "user"
        assert msg.content == "Hello"

    def test_message_to_dict(self):
        """Test converting message to dictionary."""
        msg = Message(role="assistant", content="Hi there")
        result = msg.to_dict()
        assert result == {"role": "assistant", "content": "Hi there"}


class TestLLMResponse:
    """Tests for the LLMResponse class."""

    def test_response_creation(self):
        """Test creating an LLM response."""
        response = LLMResponse(
            content="Test response",
            model="gpt-4o",
            tokens_used=100,
            prompt_tokens=50,
            completion_tokens=50,
        )
        assert response.content == "Test response"
        assert response.total_tokens == 100

    def test_total_tokens_calculation(self):
        """Test total tokens property."""
        response = LLMResponse(
            content="Test",
            model="test-model",
            prompt_tokens=30,
            completion_tokens=20,
        )
        assert response.total_tokens == 50


class TestOpenAIProvider:
    """Tests for the OpenAI provider."""

    @pytest.fixture
    def provider(self):
        """Create a test provider."""
        return OpenAIProvider(
            api_key="test-key",
            model="gpt-4o",
            temperature=0.7,
        )

    def test_provider_name(self, provider):
        """Test provider name."""
        assert provider.provider_name == "openai"

    def test_initialization(self, provider):
        """Test provider initialization."""
        assert provider.model == "gpt-4o"
        assert provider.temperature == 0.7
        assert provider.api_key == "test-key"

    @pytest.mark.asyncio
    async def test_complete(self, provider):
        """Test completion with mocked API."""
        # Mock the OpenAI client
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(
                message=MagicMock(content="Test response"),
                finish_reason="stop"
            )
        ]
        mock_response.usage = MagicMock(
            total_tokens=100,
            prompt_tokens=50,
            completion_tokens=50
        )
        mock_response.model = "gpt-4o"
        mock_response.model_dump = MagicMock(return_value={})

        provider.client.chat.completions.create = AsyncMock(return_value=mock_response)

        messages = [Message(role="user", content="Hello")]
        response = await provider.complete(messages)

        assert response.content == "Test response"
        assert response.model == "gpt-4o"

    def test_validate_messages_empty(self, provider):
        """Test validation with empty messages."""
        with pytest.raises(ValueError, match="cannot be empty"):
            provider._validate_messages([])

    def test_validate_messages_invalid_role(self, provider):
        """Test validation with invalid role."""
        messages = [Message(role="invalid", content="test")]
        with pytest.raises(ValueError, match="Invalid message role"):
            provider._validate_messages(messages)


class TestAnthropicProvider:
    """Tests for the Anthropic provider."""

    @pytest.fixture
    def provider(self):
        """Create a test provider."""
        return AnthropicProvider(
            api_key="test-key",
            model="claude-3-5-sonnet-20241022",
            temperature=0.7,
        )

    def test_provider_name(self, provider):
        """Test provider name."""
        assert provider.provider_name == "anthropic"

    def test_initialization(self, provider):
        """Test provider initialization."""
        assert provider.model == "claude-3-5-sonnet-20241022"
        assert provider.temperature == 0.7

    @pytest.mark.asyncio
    async def test_complete(self, provider):
        """Test completion with mocked API."""
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Test response")]
        mock_response.model = "claude-3-5-sonnet-20241022"
        mock_response.usage = MagicMock(input_tokens=50, output_tokens=50)
        mock_response.stop_reason = "end_turn"
        mock_response.model_dump = MagicMock(return_value={})

        provider.client.messages.create = AsyncMock(return_value=mock_response)

        messages = [Message(role="user", content="Hello")]
        response = await provider.complete(messages)

        assert response.content == "Test response"


class TestProviderFactory:
    """Tests for the provider factory."""

    @patch("src.providers.provider_factory.settings")
    def test_create_openai(self, mock_settings):
        """Test creating OpenAI provider."""
        mock_settings.default_provider = LLMProvider.OPENAI
        mock_settings.default_temperature = 0.7
        mock_settings.get_model_for_provider.return_value = "gpt-4o"
        mock_settings.get_api_key_for_provider.return_value = "test-key"

        provider = ProviderFactory.create(LLMProvider.OPENAI)
        assert isinstance(provider, OpenAIProvider)

    @patch("src.providers.provider_factory.settings")
    def test_create_anthropic(self, mock_settings):
        """Test creating Anthropic provider."""
        mock_settings.default_provider = LLMProvider.ANTHROPIC
        mock_settings.default_temperature = 0.7
        mock_settings.get_model_for_provider.return_value = "claude-3-5-sonnet-20241022"
        mock_settings.get_api_key_for_provider.return_value = "test-key"

        provider = ProviderFactory.create(LLMProvider.ANTHROPIC)
        assert isinstance(provider, AnthropicProvider)

    @patch("src.providers.provider_factory.settings")
    def test_create_without_api_key(self, mock_settings):
        """Test creating provider without API key raises error."""
        mock_settings.get_api_key_for_provider.return_value = None
        mock_settings.default_provider = LLMProvider.OPENAI

        with pytest.raises(ValueError, match="API key"):
            ProviderFactory.create(LLMProvider.OPENAI)
