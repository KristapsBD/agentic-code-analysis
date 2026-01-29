"""
Solidity smart contract parser.

Parses Solidity source code to extract contracts, functions,
state variables, and other relevant information.
"""

import re
from typing import Optional

from src.parsers.base_parser import (
    BaseParser,
    ContractInfo,
    FunctionInfo,
    ParsedContract,
    StateVariableInfo,
)


class SolidityParser(BaseParser):
    """
    Parser for Solidity smart contracts.

    Extracts structural information from Solidity code for
    security analysis purposes.
    """

    @property
    def language(self) -> str:
        """Return the language this parser handles."""
        return "solidity"

    @property
    def file_extensions(self) -> list[str]:
        """Return supported file extensions."""
        return [".sol"]

    def parse(self, source_code: str, file_path: str = "") -> ParsedContract:
        """
        Parse Solidity source code.

        Args:
            source_code: The Solidity source code
            file_path: Path to the source file

        Returns:
            ParsedContract with extracted information
        """
        result = ParsedContract(
            file_path=file_path,
            language=self.language,
            source_code=source_code,
        )

        try:
            # Extract pragma version
            result.pragma_version = self._extract_pragma(source_code)

            # Extract imports
            result.imports = self._extract_imports(source_code)

            # Extract contracts
            result.contracts = self._extract_contracts(source_code)

            # Add metadata
            result.metadata["has_reentrancy_guard"] = self._has_reentrancy_guard(source_code)
            result.metadata["uses_safemath"] = self._uses_safemath(source_code)
            result.metadata["solidity_version"] = result.pragma_version

        except Exception as e:
            result.parse_errors.append(f"Parse error: {str(e)}")

        return result

    def _extract_pragma(self, source_code: str) -> Optional[str]:
        """Extract the Solidity pragma version."""
        match = re.search(r"pragma\s+solidity\s+([^;]+);", source_code)
        if match:
            return match.group(1).strip()
        return None

    def _extract_imports(self, source_code: str) -> list[str]:
        """Extract all import statements."""
        imports = []
        import_pattern = r'import\s+(?:{[^}]+}\s+from\s+)?["\']([^"\']+)["\'];?'
        for match in re.finditer(import_pattern, source_code):
            imports.append(match.group(1))
        return imports

    def _extract_contracts(self, source_code: str) -> list[ContractInfo]:
        """Extract all contract definitions."""
        contracts = []

        # Pattern to match contract definitions
        contract_pattern = (
            r"(abstract\s+)?(contract|interface|library)\s+"
            r"(\w+)(?:\s+is\s+([^{]+))?\s*\{"
        )

        for match in re.finditer(contract_pattern, source_code):
            is_abstract = match.group(1) is not None
            contract_type = match.group(2)
            if is_abstract:
                contract_type = "abstract"
            name = match.group(3)
            inheritance = match.group(4)

            base_contracts = []
            if inheritance:
                base_contracts = [b.strip() for b in inheritance.split(",")]

            # Find the contract body
            start_pos = match.end() - 1  # Position of opening brace
            body, end_pos = self._extract_block(source_code, start_pos)

            # Calculate line numbers
            line_start = source_code[:match.start()].count("\n") + 1
            line_end = source_code[:end_pos].count("\n") + 1

            # Extract functions and variables from body
            functions = self._extract_functions(body, line_start)
            state_variables = self._extract_state_variables(body, line_start)
            events = self._extract_events(body)
            modifiers = self._extract_modifiers(body)

            contracts.append(ContractInfo(
                name=name,
                contract_type=contract_type,
                base_contracts=base_contracts,
                functions=functions,
                state_variables=state_variables,
                events=events,
                modifiers=modifiers,
                line_start=line_start,
                line_end=line_end,
            ))

        return contracts

    def _extract_block(self, source_code: str, start_pos: int) -> tuple[str, int]:
        """Extract a code block enclosed in braces."""
        if source_code[start_pos] != "{":
            return "", start_pos

        depth = 1
        pos = start_pos + 1
        while pos < len(source_code) and depth > 0:
            char = source_code[pos]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            pos += 1

        return source_code[start_pos + 1:pos - 1], pos

    def _extract_functions(self, contract_body: str, base_line: int) -> list[FunctionInfo]:
        """Extract function definitions from contract body."""
        functions = []

        # Pattern to match function definitions
        func_pattern = (
            r"function\s+(\w+)\s*\(([^)]*)\)\s*"
            r"((?:public|external|internal|private|view|pure|payable|virtual|override|\w+\s*)*)"
            r"(?:\s*returns\s*\(([^)]*)\))?\s*[{;]"
        )

        for match in re.finditer(func_pattern, contract_body):
            name = match.group(1)
            params_str = match.group(2)
            modifiers_str = match.group(3)
            returns_str = match.group(4)

            # Parse visibility
            visibility = "internal"  # Default in Solidity
            for vis in ["public", "external", "internal", "private"]:
                if vis in modifiers_str:
                    visibility = vis
                    break

            # Parse state mutability
            state_mutability = "nonpayable"
            for mut in ["pure", "view", "payable"]:
                if mut in modifiers_str:
                    state_mutability = mut
                    break

            # Extract modifier names
            modifiers = []
            # Remove visibility and mutability from modifiers string
            mod_str = modifiers_str
            for keyword in ["public", "external", "internal", "private",
                           "pure", "view", "payable", "virtual", "override"]:
                mod_str = mod_str.replace(keyword, "")
            mod_str = mod_str.strip()
            if mod_str:
                modifiers = [m.strip() for m in mod_str.split() if m.strip()]

            # Parse parameters
            parameters = self._parse_parameters(params_str)

            # Parse returns
            returns = []
            if returns_str:
                returns = self._parse_parameters(returns_str)

            # Calculate line number
            line_start = base_line + contract_body[:match.start()].count("\n")

            functions.append(FunctionInfo(
                name=name,
                visibility=visibility,
                modifiers=modifiers,
                parameters=parameters,
                returns=returns,
                state_mutability=state_mutability,
                line_start=line_start,
            ))

        return functions

    def _parse_parameters(self, params_str: str) -> list[dict[str, str]]:
        """Parse function parameters."""
        parameters = []
        if not params_str.strip():
            return parameters

        # Split by comma, but handle nested types
        depth = 0
        current = ""
        for char in params_str:
            if char in "([":
                depth += 1
            elif char in ")]":
                depth -= 1
            elif char == "," and depth == 0:
                if current.strip():
                    parameters.append(self._parse_single_param(current.strip()))
                current = ""
                continue
            current += char

        if current.strip():
            parameters.append(self._parse_single_param(current.strip()))

        return parameters

    def _parse_single_param(self, param_str: str) -> dict[str, str]:
        """Parse a single parameter."""
        parts = param_str.split()
        if len(parts) >= 2:
            return {"type": parts[0], "name": parts[-1]}
        elif len(parts) == 1:
            return {"type": parts[0], "name": ""}
        return {"type": "unknown", "name": ""}

    def _extract_state_variables(
        self, contract_body: str, base_line: int
    ) -> list[StateVariableInfo]:
        """Extract state variable definitions."""
        variables = []

        # Pattern for state variables
        var_pattern = (
            r"^\s*(mapping\s*\([^)]+\)|[\w\[\]]+)\s+"
            r"(public|private|internal)?\s*"
            r"(constant|immutable)?\s*"
            r"(\w+)\s*(?:=\s*([^;]+))?;"
        )

        for match in re.finditer(var_pattern, contract_body, re.MULTILINE):
            var_type = match.group(1)
            visibility = match.group(2) or "internal"
            modifier = match.group(3)
            name = match.group(4)
            initial_value = match.group(5)

            line_number = base_line + contract_body[:match.start()].count("\n")

            variables.append(StateVariableInfo(
                name=name,
                var_type=var_type,
                visibility=visibility,
                is_constant=modifier == "constant",
                is_immutable=modifier == "immutable",
                initial_value=initial_value.strip() if initial_value else None,
                line_number=line_number,
            ))

        return variables

    def _extract_events(self, contract_body: str) -> list[str]:
        """Extract event definitions."""
        events = []
        event_pattern = r"event\s+(\w+)\s*\([^)]*\)\s*;"
        for match in re.finditer(event_pattern, contract_body):
            events.append(match.group(1))
        return events

    def _extract_modifiers(self, contract_body: str) -> list[str]:
        """Extract modifier definitions."""
        modifiers = []
        mod_pattern = r"modifier\s+(\w+)\s*(?:\([^)]*\))?\s*\{"
        for match in re.finditer(mod_pattern, contract_body):
            modifiers.append(match.group(1))
        return modifiers

    def _has_reentrancy_guard(self, source_code: str) -> bool:
        """Check if code uses reentrancy protection."""
        patterns = [
            r"ReentrancyGuard",
            r"nonReentrant",
            r"_notEntered",
            r"locked\s*=\s*true",
        ]
        for pattern in patterns:
            if re.search(pattern, source_code):
                return True
        return False

    def _uses_safemath(self, source_code: str) -> bool:
        """Check if code uses SafeMath or Solidity 0.8+."""
        # Check for SafeMath
        if "SafeMath" in source_code:
            return True

        # Check for Solidity 0.8+
        pragma_match = re.search(r"pragma\s+solidity\s+[>=^]*\s*0\.([0-9]+)", source_code)
        if pragma_match:
            minor_version = int(pragma_match.group(1))
            if minor_version >= 8:
                return True

        return False
