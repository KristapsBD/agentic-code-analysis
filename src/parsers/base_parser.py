"""
Abstract base class for smart contract parsers.

Defines the interface for parsing smart contracts and extracting
relevant information for security analysis.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class FunctionInfo:
    """Information about a function in a smart contract."""

    name: str
    visibility: str  # public, external, internal, private
    modifiers: list[str] = field(default_factory=list)
    parameters: list[dict[str, str]] = field(default_factory=list)
    returns: list[dict[str, str]] = field(default_factory=list)
    state_mutability: str = ""  # pure, view, payable, nonpayable
    line_start: int = 0
    line_end: int = 0
    body: str = ""

    def is_public(self) -> bool:
        """Check if function is publicly accessible."""
        return self.visibility in ("public", "external")

    def is_payable(self) -> bool:
        """Check if function can receive ETH."""
        return self.state_mutability == "payable"

    def has_modifier(self, modifier_name: str) -> bool:
        """Check if function has a specific modifier."""
        return any(modifier_name in m for m in self.modifiers)

    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            "name": self.name,
            "visibility": self.visibility,
            "modifiers": self.modifiers,
            "parameters": self.parameters,
            "returns": self.returns,
            "state_mutability": self.state_mutability,
            "line_start": self.line_start,
            "line_end": self.line_end,
        }


@dataclass
class StateVariableInfo:
    """Information about a state variable."""

    name: str
    var_type: str
    visibility: str
    is_constant: bool = False
    is_immutable: bool = False
    initial_value: Optional[str] = None
    line_number: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            "name": self.name,
            "type": self.var_type,
            "visibility": self.visibility,
            "is_constant": self.is_constant,
            "is_immutable": self.is_immutable,
            "initial_value": self.initial_value,
            "line_number": self.line_number,
        }


@dataclass
class ContractInfo:
    """Information about a contract definition."""

    name: str
    contract_type: str  # contract, interface, library, abstract
    base_contracts: list[str] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    state_variables: list[StateVariableInfo] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    line_start: int = 0
    line_end: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            "name": self.name,
            "contract_type": self.contract_type,
            "base_contracts": self.base_contracts,
            "functions": [f.to_dict() for f in self.functions],
            "state_variables": [v.to_dict() for v in self.state_variables],
            "events": self.events,
            "modifiers": self.modifiers,
            "line_start": self.line_start,
            "line_end": self.line_end,
        }


@dataclass
class ParsedContract:
    """Result of parsing a smart contract."""

    file_path: str
    language: str
    source_code: str
    pragma_version: Optional[str] = None
    imports: list[str] = field(default_factory=list)
    contracts: list[ContractInfo] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def line_count(self) -> int:
        """Number of lines in the source code."""
        return len(self.source_code.split("\n"))

    @property
    def has_errors(self) -> bool:
        """Check if there were parse errors."""
        return len(self.parse_errors) > 0

    def get_all_functions(self) -> list[FunctionInfo]:
        """Get all functions from all contracts."""
        functions = []
        for contract in self.contracts:
            functions.extend(contract.functions)
        return functions

    def get_public_functions(self) -> list[FunctionInfo]:
        """Get all publicly accessible functions."""
        return [f for f in self.get_all_functions() if f.is_public()]

    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            "file_path": self.file_path,
            "language": self.language,
            "pragma_version": self.pragma_version,
            "imports": self.imports,
            "contracts": [c.to_dict() for c in self.contracts],
            "line_count": self.line_count,
            "parse_errors": self.parse_errors,
            "metadata": self.metadata,
        }


class BaseParser(ABC):
    """
    Abstract base class for smart contract parsers.

    Each supported language should have its own parser implementation.
    """

    @property
    @abstractmethod
    def language(self) -> str:
        """Return the language this parser handles."""
        pass

    @property
    @abstractmethod
    def file_extensions(self) -> list[str]:
        """Return supported file extensions."""
        pass

    @abstractmethod
    def parse(self, source_code: str, file_path: str = "") -> ParsedContract:
        """
        Parse the smart contract source code.

        Args:
            source_code: The source code to parse
            file_path: Optional path to the source file

        Returns:
            ParsedContract containing extracted information
        """
        pass

    def can_parse(self, file_path: str) -> bool:
        """Check if this parser can handle the given file."""
        return any(file_path.endswith(ext) for ext in self.file_extensions)
