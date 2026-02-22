"""
Smart contract language detection.

Automatically detects the programming language of a smart contract
based on file extension and content analysis.
"""

import re
from enum import Enum
from typing import Optional


class SmartContractLanguage(str, Enum):
    """Supported smart contract languages."""

    SOLIDITY = "solidity"
    VYPER = "vyper"
    RUST = "rust"  # Solana, Near
    MOVE = "move"  # Aptos, Sui
    UNKNOWN = "unknown"


class LanguageDetector:
    """
    Detects the programming language of smart contracts.

    Uses both file extension and content analysis to determine
    the language with high accuracy.
    """

    # File extension mappings
    EXTENSION_MAP = {
        ".sol": SmartContractLanguage.SOLIDITY,
        ".vy": SmartContractLanguage.VYPER,
        ".rs": SmartContractLanguage.RUST,
        ".move": SmartContractLanguage.MOVE,
    }

    # Language-specific patterns
    LANGUAGE_PATTERNS = {
        SmartContractLanguage.SOLIDITY: [
            r"pragma\s+solidity",
            r"contract\s+\w+",
            r"function\s+\w+\s*\(",
            r"modifier\s+\w+",
            r"event\s+\w+",
            r"mapping\s*\(",
            r"require\s*\(",
            r"msg\.sender",
            r"msg\.value",
        ],
        SmartContractLanguage.VYPER: [
            r"@external",
            r"@internal",
            r"@view",
            r"@pure",
            r"@payable",
            r"def\s+\w+\s*\(",
            r"#\s*@version",
            r"implements:",
            r"from\s+vyper",
        ],
        SmartContractLanguage.RUST: [
            r"#\[program\]",
            r"#\[account\]",
            r"use\s+anchor_lang",
            r"use\s+solana_program",
            r"#\[derive\(",
            r"pub\s+fn\s+",
            r"impl\s+\w+",
            r"mod\s+\w+",
        ],
        SmartContractLanguage.MOVE: [
            r"module\s+\w+",
            r"script\s*\{",
            r"fun\s+\w+",
            r"struct\s+\w+\s+has",
            r"acquires\s+",
            r"move_to\s*\(",
            r"borrow_global",
        ],
    }

    def detect(self, source_code: str, file_path: Optional[str] = None) -> str:
        """
        Detect the language of a smart contract.

        Args:
            source_code: The source code content
            file_path: Optional file path for extension-based detection

        Returns:
            The detected language as a string
        """
        # Try extension-based detection first
        if file_path:
            lang = self._detect_by_extension(file_path)
            if lang != SmartContractLanguage.UNKNOWN:
                return lang.value

        # Fall back to content-based detection
        lang = self._detect_by_content(source_code)
        return lang.value

    def _detect_by_extension(self, file_path: str) -> SmartContractLanguage:
        """Detect language based on file extension."""
        file_path_lower = file_path.lower()
        for ext, lang in self.EXTENSION_MAP.items():
            if file_path_lower.endswith(ext):
                return lang
        return SmartContractLanguage.UNKNOWN

    def _detect_by_content(self, source_code: str) -> SmartContractLanguage:
        """Detect language based on content patterns."""
        scores = {lang: 0 for lang in SmartContractLanguage if lang != SmartContractLanguage.UNKNOWN}

        for lang, patterns in self.LANGUAGE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, source_code, re.IGNORECASE):
                    scores[lang] += 1

        # Return the language with highest score
        if not scores:
            return SmartContractLanguage.UNKNOWN

        max_lang = max(scores, key=scores.get)
        if scores[max_lang] > 0:
            return max_lang

        return SmartContractLanguage.UNKNOWN

