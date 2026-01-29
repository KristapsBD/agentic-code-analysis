"""
Tests for smart contract parsers.
"""

import pytest

from src.parsers.language_detector import LanguageDetector, SmartContractLanguage
from src.parsers.solidity_parser import SolidityParser
from src.parsers.base_parser import FunctionInfo, StateVariableInfo


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

    def test_is_supported(self, detector):
        """Test language support check."""
        assert detector.is_supported("solidity")
        assert detector.is_supported("vyper")
        assert not detector.is_supported("cobol")


class TestSolidityParser:
    """Tests for Solidity parser."""

    @pytest.fixture
    def parser(self):
        """Create a Solidity parser."""
        return SolidityParser()

    def test_parser_language(self, parser):
        """Test parser language property."""
        assert parser.language == "solidity"

    def test_parser_extensions(self, parser):
        """Test parser file extensions."""
        assert ".sol" in parser.file_extensions

    def test_can_parse(self, parser):
        """Test can_parse check."""
        assert parser.can_parse("contract.sol")
        assert not parser.can_parse("contract.vy")

    def test_extract_pragma(self, parser):
        """Test pragma extraction."""
        code = "pragma solidity ^0.8.19;"
        result = parser._extract_pragma(code)
        assert result == "^0.8.19"

    def test_extract_imports(self, parser):
        """Test import extraction."""
        code = """
        import "./Base.sol";
        import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
        import {Ownable} from "./access/Ownable.sol";
        """
        imports = parser._extract_imports(code)
        assert len(imports) == 3
        assert "./Base.sol" in imports

    def test_parse_simple_contract(self, parser):
        """Test parsing a simple contract."""
        code = """
        pragma solidity ^0.8.0;
        
        contract SimpleContract {
            uint256 public value;
            
            function setValue(uint256 _value) public {
                value = _value;
            }
            
            function getValue() public view returns (uint256) {
                return value;
            }
        }
        """
        result = parser.parse(code, "Simple.sol")

        assert result.pragma_version == "^0.8.0"
        assert len(result.contracts) == 1
        assert result.contracts[0].name == "SimpleContract"
        assert len(result.contracts[0].functions) >= 2

    def test_parse_contract_with_inheritance(self, parser):
        """Test parsing contract with inheritance."""
        code = """
        pragma solidity ^0.8.0;
        
        contract Child is Parent, OtherParent {
            function test() public {}
        }
        """
        result = parser.parse(code)

        assert len(result.contracts) == 1
        assert "Parent" in result.contracts[0].base_contracts
        assert "OtherParent" in result.contracts[0].base_contracts

    def test_parse_function_visibility(self, parser):
        """Test parsing function visibility."""
        code = """
        contract Test {
            function publicFunc() public {}
            function externalFunc() external {}
            function internalFunc() internal {}
            function privateFunc() private {}
        }
        """
        result = parser.parse(code)
        functions = result.contracts[0].functions

        visibilities = {f.name: f.visibility for f in functions}
        assert visibilities.get("publicFunc") == "public"
        assert visibilities.get("externalFunc") == "external"
        assert visibilities.get("internalFunc") == "internal"
        assert visibilities.get("privateFunc") == "private"

    def test_parse_function_modifiers(self, parser):
        """Test parsing function modifiers."""
        code = """
        contract Test {
            modifier onlyOwner() { _; }
            
            function restricted() public onlyOwner {
            }
        }
        """
        result = parser.parse(code)

        # Find the restricted function
        restricted_func = None
        for func in result.contracts[0].functions:
            if func.name == "restricted":
                restricted_func = func
                break

        assert restricted_func is not None
        assert "onlyOwner" in restricted_func.modifiers

    def test_has_reentrancy_guard(self, parser):
        """Test reentrancy guard detection."""
        code_with_guard = """
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        contract Test is ReentrancyGuard {}
        """
        assert parser._has_reentrancy_guard(code_with_guard)

        code_with_modifier = """
        contract Test {
            function withdraw() public nonReentrant {}
        }
        """
        assert parser._has_reentrancy_guard(code_with_modifier)

        code_without_guard = """
        contract Test {
            function withdraw() public {}
        }
        """
        assert not parser._has_reentrancy_guard(code_without_guard)

    def test_uses_safemath(self, parser):
        """Test SafeMath detection."""
        code_with_safemath = """
        pragma solidity ^0.7.0;
        import "./SafeMath.sol";
        """
        assert parser._uses_safemath(code_with_safemath)

        code_solidity_8 = """
        pragma solidity ^0.8.0;
        contract Test {}
        """
        assert parser._uses_safemath(code_solidity_8)

        code_without_safemath = """
        pragma solidity ^0.6.0;
        contract Test {}
        """
        assert not parser._uses_safemath(code_without_safemath)


class TestFunctionInfo:
    """Tests for FunctionInfo."""

    def test_is_public(self):
        """Test public function detection."""
        public_func = FunctionInfo(name="test", visibility="public")
        external_func = FunctionInfo(name="test", visibility="external")
        internal_func = FunctionInfo(name="test", visibility="internal")

        assert public_func.is_public()
        assert external_func.is_public()
        assert not internal_func.is_public()

    def test_is_payable(self):
        """Test payable function detection."""
        payable_func = FunctionInfo(name="test", visibility="public", state_mutability="payable")
        view_func = FunctionInfo(name="test", visibility="public", state_mutability="view")

        assert payable_func.is_payable()
        assert not view_func.is_payable()

    def test_has_modifier(self):
        """Test modifier detection."""
        func = FunctionInfo(name="test", visibility="public", modifiers=["onlyOwner", "nonReentrant"])

        assert func.has_modifier("onlyOwner")
        assert func.has_modifier("nonReentrant")
        assert not func.has_modifier("onlyAdmin")


class TestStateVariableInfo:
    """Tests for StateVariableInfo."""

    def test_variable_creation(self):
        """Test creating state variable info."""
        var = StateVariableInfo(
            name="owner",
            var_type="address",
            visibility="public",
            is_constant=False,
            is_immutable=True,
        )
        assert var.name == "owner"
        assert var.is_immutable
        assert not var.is_constant

    def test_variable_to_dict(self):
        """Test converting variable to dictionary."""
        var = StateVariableInfo(
            name="MAX_SUPPLY",
            var_type="uint256",
            visibility="public",
            is_constant=True,
            initial_value="1000000",
        )
        result = var.to_dict()
        assert result["name"] == "MAX_SUPPLY"
        assert result["is_constant"] is True
