"""
Tests for smart contract language detection.
"""

import pytest

from src.parsers.language_detector import LanguageDetector, SmartContractLanguage


class TestLanguageDetector:
    """Tests for language detection."""

    @pytest.fixture
    def detector(self):
        """Create a language detector."""
        return LanguageDetector()

    def test_detect_solidity_by_extension(self, detector):
        """Test detecting Solidity by file extension."""
        result = detector.detect("", "contract.sol")
        assert result == "solidity"

    def test_detect_vyper_by_extension(self, detector):
        """Test detecting Vyper by file extension."""
        result = detector.detect("", "contract.vy")
        assert result == "vyper"

    def test_detect_rust_by_extension(self, detector):
        """Test detecting Rust by file extension."""
        result = detector.detect("", "contract.rs")
        assert result == "rust"

    def test_detect_solidity_by_content(self, detector):
        """Test detecting Solidity by content patterns."""
        code = """
        pragma solidity ^0.8.0;

        contract Test {
            function test() public {
                require(msg.sender != address(0));
            }
        }
        """
        result = detector.detect(code, "")
        assert result == "solidity"

    def test_detect_vyper_by_content(self, detector):
        """Test detecting Vyper by content patterns."""
        code = """
        # @version ^0.3.0

        @external
        def test():
            pass
        """
        result = detector.detect(code, "")
        assert result == "vyper"

    def test_detect_rust_by_content(self, detector):
        """Test detecting Rust/Solana by content patterns."""
        code = """
        use anchor_lang::prelude::*;

        #[program]
        pub mod test {
            pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
                Ok(())
            }
        }
        """
        result = detector.detect(code, "")
        assert result == "rust"
