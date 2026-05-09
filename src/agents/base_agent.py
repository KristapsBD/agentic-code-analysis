import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from src.config import ConfidenceLevel
from src.providers.base_provider import BaseLLMProvider, Message

logger = logging.getLogger(__name__)


class AgentRole(str, Enum):
    ATTACKER = "attacker"
    DEFENDER = "defender"
    JUDGE = "judge"


@dataclass
class VulnerabilityClaim:
    id: str
    vulnerability_type: str
    severity: str
    location: str
    description: str
    evidence: str
    confidence: ConfidenceLevel

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "location": self.location,
            "description": self.description,
            "evidence": self.evidence,
            "confidence": self.confidence.value,
        }


@dataclass
class AgentResponse:
    agent_role: AgentRole
    content: str
    claims: list[VulnerabilityClaim] = field(default_factory=list)
    reasoning: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    tokens_used: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "agent_role": self.agent_role.value,
            "content": self.content,
            "claims": [claim.to_dict() for claim in self.claims],
            "reasoning": self.reasoning,
            "confidence": self.confidence.value,
            "tokens_used": self.tokens_used,
            "metadata": self.metadata,
        }


class BaseAgent(ABC):
    def __init__(
        self,
        provider: BaseLLMProvider,
        name: str,
        role: AgentRole,
        system_prompt: str,
        web_search: bool = False,
    ):
        self.provider = provider
        self.name = name
        self.role = role
        self.system_prompt = system_prompt
        self.web_search = web_search
        self.conversation_history: list[Message] = []
        self._last_llm_response: Any = None

    @abstractmethod
    async def analyze(self, context: dict) -> AgentResponse:
        pass

    async def _send_message(
        self,
        user_message: str,
        include_history: bool = True,
        temperature: Optional[float] = None,
        json_mode: bool = False,
    ) -> str:
        messages = [Message(role="system", content=self.system_prompt)]

        if include_history:
            messages.extend(self.conversation_history)

        messages.append(Message(role="user", content=user_message))

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                f"[{self.name}] → Sending {len(messages)} message(s) to LLM "
                f"(history_turns={len(self.conversation_history)}, "
                f"temperature={temperature}, web_search={self.web_search}, "
                f"json_mode={json_mode})"
            )
        response = await self.provider.complete(
            messages, temperature=temperature, web_search=self.web_search, json_mode=json_mode
        )
        self._last_llm_response = response

        if logger.isEnabledFor(logging.DEBUG):
            _SEP = "─" * 60
            logger.debug(
                f"[{self.name}] ← Raw LLM response "
                f"({len(response.content)} chars | "
                f"tokens: {response.tokens_used} total / "
                f"{response.prompt_tokens} prompt / {response.completion_tokens} completion | "
                f"finish_reason={response.finish_reason!r}):\n"
                f"{_SEP}\n{response.content}\n{_SEP}"
            )

        if response.finish_reason not in ("stop", "end_turn", "1", "stop_sequence"):
            logger.warning(
                f"[{self.name}] LLM response ended with finish_reason={response.finish_reason!r} "
                f"— output may be truncated. Response length: {len(response.content)} chars, "
                f"completion tokens: {response.completion_tokens}. "
                f"If JSON parsing fails after this, increase max_output_tokens."
            )

        self.conversation_history.append(Message(role="user", content=user_message))
        self.conversation_history.append(Message(role="assistant", content=response.content))

        return response.content

    async def _send_message_json(
        self,
        user_message: str,
        include_history: bool = True,
        temperature: Optional[float] = None,
    ) -> dict[str, Any]:
        json_instruction = (
            "\n\nIMPORTANT: Your entire response MUST be a single, complete, valid JSON object. "
            "Start your response with '{' and end it with '}'. "
            "Do not include any text, explanation, or markdown outside the JSON. "
            "Do not truncate or abbreviate the JSON — emit all fields fully before closing the object."
        )
        raw_response = await self._send_message(
            user_message + json_instruction,
            include_history=include_history,
            temperature=temperature,
            json_mode=True,
        )

        logger.debug(f"[{self.name}] Attempting JSON parse on {len(raw_response)}-char response")
        parsed = self._parse_json_response(raw_response)

        if parsed.get("_parse_failed"):
            r = self._last_llm_response
            token_info = (
                f"tokens: {r.tokens_used} total / {r.prompt_tokens} prompt / "
                f"{r.completion_tokens} completion | finish_reason={r.finish_reason!r}"
                if r else "token info unavailable"
            )
            logger.warning(
                f"[{self.name}] JSON parsing FAILED ({token_info}). "
                f"First 100 chars of raw response: {raw_response[:100]!r}"
            )
        else:
            logger.debug(
                f"[{self.name}] JSON parsed successfully. "
                f"Top-level keys: {sorted(parsed.keys())}"
            )

        return parsed

    @staticmethod
    def _repair_truncated_json(text: str) -> str:
        in_string = False
        escape_next = False
        stack: list[str] = []  # '{' or '[' for each open container

        for char in text:
            if escape_next:
                escape_next = False
                continue
            if char == "\\" and in_string:
                escape_next = True
                continue
            if char == '"':
                in_string = not in_string
                continue
            if not in_string:
                if char in ("{", "["):
                    stack.append(char)
                elif char == "}" and stack and stack[-1] == "{":
                    stack.pop()
                elif char == "]" and stack and stack[-1] == "[":
                    stack.pop()

        suffix = ""
        if in_string:
            suffix += '"'  # close the open string value
        for opener in reversed(stack):
            suffix += "}" if opener == "{" else "]"

        return text + suffix

    @staticmethod
    def _parse_json_response(response: str) -> dict[str, Any]:
        try:
            result = json.loads(response.strip())
            logger.debug("JSON parse strategy: direct parse succeeded")
            return result
        except json.JSONDecodeError:
            pass

        json_pattern = r"```(?:json)?\s*([\s\S]*?)\s*```"
        match = re.search(json_pattern, response)
        if match:
            try:
                result = json.loads(match.group(1).strip())
                logger.debug("JSON parse strategy: markdown code block extraction succeeded")
                return result
            except json.JSONDecodeError:
                pass

        brace_start = response.find("{")
        brace_end = response.rfind("}")
        if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
            try:
                result = json.loads(response[brace_start:brace_end + 1])
                logger.debug("JSON parse strategy: brace-extraction succeeded")
                return result
            except json.JSONDecodeError:
                pass

        # Strategy 4: close any unclosed strings/containers and retry.
        if brace_start != -1:
            candidate = response[brace_start:]
            repaired = BaseAgent._repair_truncated_json(candidate)
            try:
                result = json.loads(repaired)
                logger.debug("JSON parse strategy: truncation-repair succeeded (string values may be truncated)")
                return result
            except json.JSONDecodeError:
                pass

        logger.warning("JSON parse strategy: all strategies failed — using raw_content fallback")
        return {"raw_content": response, "_parse_failed": True}

    @staticmethod
    def _parse_confidence_level(
        value: Any, default: ConfidenceLevel = ConfidenceLevel.MEDIUM
    ) -> ConfidenceLevel:
        if value is None:
            return default
        if isinstance(value, ConfidenceLevel):
            return value
        try:
            return ConfidenceLevel(str(value).strip().upper())
        except ValueError:
            return default

    @staticmethod
    def _to_claim_dict(claim: Any) -> dict:
        return claim.to_dict() if isinstance(claim, VulnerabilityClaim) else claim

    def clear_history(self) -> None:
        self.conversation_history = []

