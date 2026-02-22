# Architecture Report — Adversarial Smart Contract Analyser

> Generated: 2026-02-22

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Directory Structure](#2-directory-structure)
3. [Entry Points and CLI](#3-entry-points-and-cli)
4. [Layer Architecture](#4-layer-architecture)
   - [Configuration Layer](#41-configuration-layer)
   - [Provider Layer](#42-provider-layer)
   - [Agent Layer](#43-agent-layer)
   - [Orchestration Layer](#44-orchestration-layer)
   - [Knowledge Layer](#45-knowledge-layer)
   - [Output Layer](#46-output-layer)
5. [The Debate Pipeline — Step by Step](#5-the-debate-pipeline--step-by-step)
6. [Key Data Structures](#6-key-data-structures)
7. [Data Flow Diagram](#7-data-flow-diagram)
8. [Configuration Reference](#8-configuration-reference)
9. [Design Decisions](#9-design-decisions)

---

## 1. System Overview

This system is a **multi-agent LLM framework for automated smart contract security auditing**. It uses an adversarial debate architecture — three specialised AI agents argue about potential vulnerabilities, and only claims that survive structured scrutiny are surfaced as confirmed findings.

The core idea is that a single LLM asked to audit a contract will both find bugs *and* hallucinate bugs. By pitting a second LLM against every claim the first makes, and having a third adjudicate, the system filters false positives without requiring a human to review every flagged issue.

**Three agents, one contract, one pipeline:**

```
Contract ──► Attacker ──► [N claims] ──► for each claim:
                                           Defender reviews
                                           ├── Debate rounds (Attacker rebuts ↔ Defender responds)
                                           └── Judge renders verdict
                                                ├── Confident → Final Verdict
                                                └── Low confidence → Clarification round → Final Verdict
```

**Supported LLM providers:** OpenAI, Anthropic, Google Gemini

**Supported contract languages:** Solidity, Vyper, Rust (Solana/Anchor), Move (Aptos/Sui)

---

## 2. Directory Structure

```
agentic-analysis/
├── src/
│   ├── main.py                        # CLI entry point (Typer app)
│   ├── config.py                      # Settings, env vars, provider config
│   │
│   ├── agents/                        # The three debate agents
│   │   ├── base_agent.py              # Abstract base class, JSON message handling
│   │   ├── attacker_agent.py          # Scans for vulnerabilities
│   │   ├── defender_agent.py          # Challenges and validates claims
│   │   └── judge_agent.py             # Renders verdicts, handles clarification
│   │
│   ├── orchestration/                 # Debate coordination
│   │   ├── debate_manager.py          # Main pipeline controller
│   │   └── conversation.py            # Turn-by-turn conversation log
│   │
│   ├── knowledge/                     # Prompts
│   │   └── prompts/
│   │       ├── attacker.py            # Attacker system prompt + templates
│   │       ├── defender.py            # Defender system prompt + templates
│   │       └── judge.py               # Judge system prompt + templates
│   │
│   ├── parsers/                       # Contract language detection
│   │   └── language_detector.py       # Regex-based language identification
│   │
│   ├── providers/                     # LLM API wrappers
│   │   ├── base_provider.py           # Abstract provider interface
│   │   ├── openai_provider.py         # OpenAI (GPT-4o etc.)
│   │   ├── anthropic_provider.py      # Anthropic (Claude etc.)
│   │   ├── gemini_provider.py         # Google Gemini
│   │   └── provider_factory.py        # Instantiation from config
│   │
│   └── output/
│       ├── report.py                  # Finding/Report dataclasses + formatting
│       └── evaluator.py               # Benchmark evaluation runner
│
├── tests/
│   ├── test_agents.py
│   ├── test_debate.py
│   ├── test_parsers.py
│   └── test_providers.py
│
└── data/
    ├── benchmarks/                    # Input contracts for evaluation
    └── results/                       # JSON + Markdown reports (auto-generated)
```

---

## 3. Entry Points and CLI

The CLI is built with **Typer** and exposes three commands, defined in `src/main.py`.

### `sca analyze <contract_path>`

Analyses a single smart contract.

```
python -m src.main analyze contracts/Token.sol --provider anthropic --rounds 2
```

| Option | Default | Description |
|--------|---------|-------------|
| `--provider` | `openai` | LLM provider (`openai`, `anthropic`, `gemini`) |
| `--rounds` | `2` | Maximum debate rounds per claim (1–5) |
| `--output` | none | Custom path for JSON output (auto-saves to `data/results/` regardless) |
| `--verbose` | off | Print each debate turn to console as it runs |

**Output:** Always saves two files to `data/results/`:
- `<contract_name>_<timestamp>.json` — full structured result
- `<contract_name>_<timestamp>.md` — human-readable Markdown report

### `sca evaluate <benchmark_dir>`

Runs analysis on every contract in a directory and calculates aggregate metrics (precision, recall, F1).

### `sca compare <contract_path>`

Runs the same contract through all configured providers in sequence and prints a side-by-side comparison table of findings.

### `sca info`

Displays current configuration: provider models, API key status, debate settings.

---

## 4. Layer Architecture

### 4.1 Configuration Layer

**File:** `src/config.py`

Settings are loaded from environment variables (or a `.env` file) via **Pydantic Settings**. The global singleton `settings` is imported throughout the codebase.

```python
settings = Settings()  # populated from env vars at import time
```

| Setting | Env Var | Default |
|---------|---------|---------|
| OpenAI API key | `OPENAI_API_KEY` | — |
| Anthropic API key | `ANTHROPIC_API_KEY` | — |
| Gemini API key | `GEMINI_API_KEY` | — |
| Default provider | `DEFAULT_PROVIDER` | `openai` |
| OpenAI model | `DEFAULT_MODEL_OPENAI` | `gpt-4o` |
| Anthropic model | `DEFAULT_MODEL_ANTHROPIC` | `claude-3-5-sonnet-20241022` |
| Gemini model | `DEFAULT_MODEL_GEMINI` | `gemini-2.0-flash-exp` |
| Debate rounds | `DEFAULT_DEBATE_ROUNDS` | `2` |
| Temperature | `DEFAULT_TEMPERATURE` | `0.7` |
| Judge threshold | `JUDGE_CONFIDENCE_THRESHOLD` | `0.7` |
| Log level | `LOG_LEVEL` | `INFO` |

The `LLMProvider` enum (`openai`, `anthropic`, `gemini`) is used across the codebase to identify providers without string literals.

---

### 4.2 Provider Layer

**Files:** `src/providers/`

All provider implementations share a common abstract interface defined in `BaseLLMProvider`. This means the entire debate pipeline is provider-agnostic — swapping OpenAI for Gemini requires only a config change.

```
BaseLLMProvider (abstract)
├── complete(messages) → LLMResponse   ← main method
└── complete_simple(prompt) → str      ← convenience wrapper

OpenAIProvider    ─── uses openai Python SDK (async)
AnthropicProvider ─── uses anthropic Python SDK (async)
GeminiProvider    ─── uses google-generativeai SDK (async)
```

**Key data structures:**

```python
@dataclass
class Message:
    role: str      # "system", "user", or "assistant"
    content: str

@dataclass
class LLMResponse:
    content: str
    model: str
    tokens_used: int
    prompt_tokens: int
    completion_tokens: int
    finish_reason: str
```

**`ProviderFactory.create(provider)`** reads the API key and model from `settings` and returns the appropriate concrete provider instance. Called once at the start of `_run_analysis()`.

---

### 4.3 Agent Layer

**Files:** `src/agents/`

All three agents share a common base class. The base class handles the mechanics of communicating with the LLM; each subclass implements the security-specific logic.

#### `BaseAgent`

Responsibilities:
- Holds the agent's **system prompt** (set once, reused across all calls)
- Maintains a **conversation history** (`list[Message]`) for multi-turn exchanges within a single claim
- Exposes `_send_message()` for raw text responses and `_send_message_json()` for structured JSON responses

**`_send_message_json()`** is the critical method — it:
1. Appends a JSON-enforcement instruction to every user message
2. Calls the provider
3. Tries three strategies to extract valid JSON from the response:
   - Direct `json.loads()`
   - Extract from a markdown code block (` ```json ... ``` `)
   - Find the outermost `{...}` substring
4. Falls back to `{"raw_content": <text>, "_parse_failed": True}` if all three fail

History is cleared between claims via `clear_history()` to prevent context bleed.

**Temperature settings used per agent:**

| Agent method | Temperature |
|---|---|
| Attacker — initial scan | `0.3` |
| Attacker — rebuttal | `0.3` |
| Attacker — clarification response | `0.2` |
| Defender — initial defense | `0.3` |
| Defender — rebuttal response | `0.3` |
| Defender — clarification response | `0.2` |
| Judge — initial assessment | `0.2` |
| Judge — final verdict | `0.2` |

Low temperatures are used throughout because these are structured analytical tasks, not creative ones.

---

#### `AttackerAgent`

Role: scan the contract and raise vulnerability claims.

**Methods:**

| Method | Called by | Purpose |
|--------|-----------|---------|
| `analyze(context)` | `DebateManager.run_debate()` | Initial scan — produces `list[VulnerabilityClaim]` |
| `respond_to_defense(context)` | `DebateManager._debate_claim()` | Rebuttal to Defender's argument |
| `respond_to_clarification(context)` | `DebateManager._run_clarification_round()` | Targeted answer to Judge's question |

The initial scan uses `include_history=False` — each scan is stateless. Rebuttals use `include_history=True` so the agent can reference its own prior rebuttal chain within a single claim's debate.

**JSON parsing for claims:** `_extract_claims()` reads the `"vulnerabilities"` array from the JSON response and maps each item to a `VulnerabilityClaim`. If JSON parsing failed entirely (the `_parse_failed` fallback), `_fallback_parse_claims()` parses line-by-line text with patterns like `VULNERABILITY:`, `SEVERITY:`, `LOCATION:`.

---

#### `DefenderAgent`

Role: challenge each claim — find mitigations, invalidate false positives, acknowledge real bugs.

**Methods:**

| Method | Called by | Purpose |
|--------|-----------|---------|
| `analyze(context)` | `DebateManager._debate_claim()` | Initial defense of a specific claim |
| `respond_to_rebuttal(context)` | `DebateManager._debate_claim()` | Respond to Attacker's rebuttal |
| `respond_to_clarification(context)` | `DebateManager._run_clarification_round()` | Targeted answer to Judge's question |

The Defender's `analyze()` uses `include_history=False` — each claim is evaluated fresh. `respond_to_rebuttal()` uses `include_history=True` to maintain continuity across rebuttal rounds.

The Defender can return three verdicts in its initial response:
- `VALID_VULNERABILITY` — acknowledges the claim
- `INVALID_CLAIM` — rejects it with evidence
- `PARTIALLY_MITIGATED` — confirms vulnerability exists but mitigations reduce the impact

---

#### `JudgeAgent`

Role: impartial arbiter — evaluate both arguments and render a binding verdict.

**Methods:**

| Method | Called by | Purpose |
|--------|-----------|---------|
| `analyze(context)` | `DebateManager._debate_claim()` | Initial assessment after debate rounds |
| `render_final_verdict(context)` | `DebateManager._run_clarification_round()` | Final verdict after clarification |

The Judge always uses `include_history=False` — each verdict is made on the full context provided in a single prompt, not a multi-turn conversation.

**`_extract_verdict(parsed, claim_id) → Verdict`** handles the structured JSON parsing. It specifically handles:
- Normalising `"VALID_VULNERABILITY"` vs `"NOT_VULNERABLE"` strings
- Clamping confidence to `[0.0, 1.0]` (handles cases where the model returns `85` instead of `0.85`)
- Clamping `attacker_score` and `defender_score` similarly
- Truncating `reasoning` to 500 chars and `recommendation` to 300 chars

**`_fallback_parse_verdict()`** handles the case where JSON parsing fails — uses regex to find `VERDICT:`, `SEVERITY:`, `CONFIDENCE:`, `REASONING:` etc. from plain text.

The Judge's response also carries two flags used by the orchestrator:
- `needs_clarification: bool` — whether the Judge wants a clarification round
- `clarification_question: str` — the specific question to ask both sides

---

### 4.4 Orchestration Layer

**Files:** `src/orchestration/`

#### `DebateManager`

The central controller. It owns the three agent instances and drives the full pipeline for a given contract.

**Convergence detection** — before each new debate round, `_has_converged()` checks:
- `attacker_confidence < 0.4` (Attacker is losing confidence → likely concession)
- `defender_confidence > 0.8` (Defender is very confident → strong mitigation found)

If either condition is met, the remaining rounds are skipped and the Judge is called immediately. This prevents wasted API calls when the debate has effectively settled.

**Context isolation** — `_reset_claim_context()` calls `clear_history()` on all three agents between claims, ensuring that the debate about claim #2 is not influenced by the conversation from claim #1.

**Agent histories across a single claim:**
- Attacker: `include_history=True` for rebuttals only — can reference its own prior rebuttal in the chain
- Defender: `include_history=True` for rebuttal responses only
- Judge: always `include_history=False` — receives full context in each single prompt

#### `Conversation`

A lightweight audit log. Stores every turn that occurs during the debate as a `ConversationTurn` record. Not used to drive pipeline logic — it is a passive record of what happened.

**`TurnType` enum maps to every step in the pipeline:**

| TurnType | When it is added |
|----------|-----------------|
| `ATTACK` | After Attacker's initial scan |
| `DEFENSE` | After Defender's initial review of a claim |
| `REBUTTAL` | After each Attacker rebuttal within a claim |
| `DEFENSE` | After each Defender response to a rebuttal |
| `JUDGMENT` | After Judge's initial assessment |
| `CLARIFICATION` | When Judge requests a clarification round |
| `CLARIFICATION_RESPONSE` | After each agent responds to the Judge's question |
| `JUDGMENT` | After Judge's final verdict (post-clarification) |

The `Conversation` object is stored in `DebateResult` but not included in the serialised output (`to_dict()`) — it exists as an in-memory audit trail for the duration of the analysis.

---

### 4.5 Knowledge Layer

**Files:** `src/knowledge/prompts/`

Each agent has its own prompt module with two components:

1. **System prompt** — a constant string passed as the `"system"` message on every API call. Sets the agent's persona, expertise, and behavioural rules for the entire session.

2. **User prompt templates** — Python format strings with `{variable}` placeholders, one per agent method. Filled at runtime with specific claim details, contract code, and prior arguments.

**Template inventory:**

| Agent | Template | Content passed |
|-------|----------|----------------|
| Attacker | `SCAN_PROMPT_TEMPLATE` | contract code, path, language |
| Attacker | `REBUTTAL_PROMPT_TEMPLATE` | claim details, original evidence, defender argument |
| Attacker | `CLARIFICATION_RESPONSE_PROMPT_TEMPLATE` | claim details, judge question |
| Defender | `DEFENSE_PROMPT_TEMPLATE` | contract code, full claim with evidence |
| Defender | `REBUTTAL_RESPONSE_PROMPT_TEMPLATE` | claim details, original defense, attacker rebuttal |
| Defender | `CLARIFICATION_RESPONSE_PROMPT_TEMPLATE` | claim details, judge question |
| Judge | `JUDGMENT_PROMPT_TEMPLATE` | contract code, claim, both arguments, debate history |
| Judge | `CLARIFICATION_PROMPT_TEMPLATE` | contract code, claim, judge question, both clarification responses |

**Important:** `base_agent._send_message_json()` automatically appends a JSON enforcement instruction to every user message before sending. The templates do not need to repeat this.

---

### 4.6 Output Layer

**Files:** `src/output/`

#### `ReportGenerator`

Converts the raw `DebateResult.to_dict()` into a typed `Report` object, then renders it in three formats.

**`generate(result, contract_path) → Report`** — filters `claim_results` to only include those where `verdict.is_valid == True`, maps each to a `Finding` dataclass.

**`Finding` fields surfaced in the report:**

| Field | Source |
|-------|--------|
| `vulnerability_type` | Original claim |
| `severity` | Judge's verdict (may differ from Attacker's claim) |
| `location` | Original claim |
| `description` | Original claim |
| `confidence` | Judge's verdict |
| `recommendation` | Judge's verdict |
| `attacker_evidence` | Original claim's evidence field |
| `judge_reasoning` | Judge's reasoning (truncated to 500 chars in extraction) |

Note: `defender_argument` is a field in `Finding` but is currently not populated by `generate()`.

**Output formats:**
- **Console** — rich-formatted panels and tables via the `rich` library
- **JSON** — `report.to_dict()` written with `json.dump(..., indent=2)`
- **Markdown** — manually assembled string with findings as `###` sections

#### `Evaluator`

Batch runner for benchmark evaluation. Runs `DebateManager.run_debate()` on every `.sol`/`.vy`/`.rs` file in a directory and computes aggregate metrics. Uses `asyncio.gather()` for concurrent execution across contracts.

---

## 5. The Debate Pipeline — Step by Step

This is the exact sequence of operations for a single `analyze` invocation.

```
main.py: analyze()
│
├── contract_code = contract_path.read_text()           # Raw text, no preprocessing
│
└── _run_analysis(contract_code, ...)
    │
    ├── ProviderFactory.create(provider)                 # Instantiate LLM client
    │
    └── DebateManager.run_debate(contract_code, path)
        │
        ├── LanguageDetector.detect(code, path)         # Regex-based language ID
        │
        ├── ── PHASE 1: INITIAL SCAN ──────────────────────────────────
        │   AttackerAgent.analyze({contract_code, path, language})
        │       → SCAN_PROMPT_TEMPLATE filled → LLM call (temp=0.3, no history)
        │       → JSON parsed → list[VulnerabilityClaim]
        │   Conversation.add_turn(ATTACK, ...)
        │
        └── ── PHASE 2–4: PER-CLAIM DEBATE ────────────────────────────
            for each claim in initial_claims:
            │
            ├── _reset_claim_context()                  # Clear all agent histories
            │
            ├── Step 1 — DEFENDER INITIAL REVIEW
            │   DefenderAgent.analyze({contract_code, claim})
            │       → DEFENSE_PROMPT_TEMPLATE → LLM call (temp=0.3, no history)
            │       → defense_verdict, defender_confidence extracted
            │   Conversation.add_turn(DEFENSE, ...)
            │
            ├── Step 2 — DEBATE ROUNDS (up to max_rounds)
            │   for round in range(1, max_rounds + 1):
            │   │
            │   ├── Check convergence (attacker_conf < 0.4 OR defender_conf > 0.8)
            │   │   └── if converged: break early
            │   │
            │   ├── AttackerAgent.respond_to_defense({claim, defense_argument})
            │   │       → REBUTTAL_PROMPT_TEMPLATE → LLM call (temp=0.3, with history)
            │   │       → attacker_confidence updated
            │   │   Conversation.add_turn(REBUTTAL, ...)
            │   │
            │   ├── Check attacker concession (is_concession flag)
            │   │   └── if conceded: break early
            │   │
            │   ├── DefenderAgent.respond_to_rebuttal({claim, original_defense, rebuttal})
            │   │       → REBUTTAL_RESPONSE_PROMPT_TEMPLATE → LLM call (temp=0.3, with history)
            │   │       → defender_confidence updated
            │   │   Conversation.add_turn(DEFENSE, ...)
            │   │
            │   └── Check defender acknowledgement (acknowledges_vulnerability flag)
            │       └── if acknowledged: break early
            │
            ├── Step 3 — JUDGE INITIAL ASSESSMENT
            │   JudgeAgent.analyze({contract_code, claim, attacker_arg, defender_arg, debate_history})
            │       → JUDGMENT_PROMPT_TEMPLATE → LLM call (temp=0.2, no history)
            │       → Verdict extracted; needs_clarification checked
            │   Conversation.add_turn(JUDGMENT, ...)
            │
            ├── Step 4 — OPTIONAL CLARIFICATION ROUND
            │   if needs_clarification AND judge_confidence < threshold (0.7):
            │   │
            │   ├── Conversation.add_turn(CLARIFICATION, ...)
            │   │
            │   ├── AttackerAgent.respond_to_clarification({claim, judge_question})
            │   │       → CLARIFICATION_RESPONSE_PROMPT_TEMPLATE → LLM call (temp=0.2, no history)
            │   │   Conversation.add_turn(CLARIFICATION_RESPONSE, ...)
            │   │
            │   ├── DefenderAgent.respond_to_clarification({claim, judge_question})
            │   │       → CLARIFICATION_RESPONSE_PROMPT_TEMPLATE → LLM call (temp=0.2, no history)
            │   │   Conversation.add_turn(CLARIFICATION_RESPONSE, ...)
            │   │
            │   └── JudgeAgent.render_final_verdict({all context + clarification responses})
            │           → CLARIFICATION_PROMPT_TEMPLATE → LLM call (temp=0.2, no history)
            │       Conversation.add_turn(JUDGMENT, ...)
            │
            └── Step 5 — EXTRACT FINAL VERDICT
                Verdict extracted from judge_response.metadata["verdict"]
                ClaimResult stored: {claim, verdict, rounds, flags}

    → DebateResult.to_dict() returned to main.py

ReportGenerator.generate(result) → Report
ReportGenerator.save_json(report, path)
ReportGenerator.save_markdown(report, path)
ReportGenerator.print_to_console(report)
```

---

## 6. Key Data Structures

### `VulnerabilityClaim`
```
id:                 str     — e.g. "vuln-1"
vulnerability_type: str     — e.g. "Reentrancy"
severity:           str     — "critical" | "high" | "medium" | "low"
location:           str     — function name and/or line number
description:        str     — human-readable explanation
evidence:           str     — quoted code + step-by-step exploit path
confidence:         float   — Attacker's self-assessed confidence [0, 1]
```

### `Verdict`
```
claim_id:       str     — matches VulnerabilityClaim.id
is_valid:       bool    — True = confirmed vulnerability
severity:       str     — Judge's severity (may differ from Attacker's)
confidence:     float   — Judge's confidence in this ruling [0, 1]
reasoning:      str     — Judge's explanation (≤500 chars)
recommendation: str     — Remediation advice (≤300 chars)
attacker_score: float   — Quality of Attacker's argument [0, 1]
defender_score: float   — Quality of Defender's argument [0, 1]
```

### `ClaimResult`
```
claim:                      VulnerabilityClaim
verdict:                    Verdict
debate_rounds:              int     — actual rounds that ran
attacker_conceded:          bool
defender_acknowledged:      bool
judge_requested_clarification: bool
final_assessment:           str     — first 500 chars of Judge's final content
```

### `DebateResult`
```
contract_path:      str
contract_language:  str
started_at:         datetime
completed_at:       datetime
initial_claims:     list[VulnerabilityClaim]   — everything Attacker flagged
claim_results:      list[ClaimResult]          — one per claim, with verdict
conversation:       Conversation               — full turn log
metadata:           dict    — provider, model, max_rounds, threshold
```

### `Finding` (report layer)
```
vulnerability_type: str
severity:           str     — from Judge's verdict
location:           str
description:        str
confidence:         float
recommendation:     str
attacker_evidence:  str
judge_reasoning:    str
```

---

## 7. Data Flow Diagram

```
  ┌─────────────────────────────────────────────────────────────┐
  │                        ENTRY POINT                          │
  │  main.py  analyze / evaluate / compare                      │
  └──────────────────────────┬──────────────────────────────────┘
                             │  contract_code (raw text)
                             ▼
  ┌──────────────────────────────────────────────────────────────┐
  │                    CONFIGURATION                              │
  │  config.py  ──  Settings (pydantic)  ──  .env / env vars    │
  │                 ProviderFactory.create()                      │
  └──────────────────────────┬───────────────────────────────────┘
                             │  BaseLLMProvider instance
                             ▼
  ┌──────────────────────────────────────────────────────────────┐
  │                    DEBATE MANAGER                             │
  │  orchestration/debate_manager.py                             │
  │                                                              │
  │  ┌────────────┐   ┌─────────────┐   ┌──────────────┐        │
  │  │  Attacker  │   │   Defender  │   │    Judge     │        │
  │  │  Agent     │   │   Agent     │   │    Agent     │        │
  │  └─────┬──────┘   └──────┬──────┘   └──────┬───────┘        │
  │        │                 │                  │                │
  │        └────────────────►├◄─────────────────┘                │
  │                    Claims flow per step                      │
  └──────────────────────────┬───────────────────────────────────┘
         │                   │                   │
         ▼                   ▼                   ▼
  ┌─────────────┐  ┌──────────────────┐  ┌──────────────────┐
  │  KNOWLEDGE  │  │    PROVIDERS     │  │  CONVERSATION    │
  │  Prompt     │  │  openai /        │  │  Turn log        │
  │  templates  │  │  anthropic /     │  │  (audit trail)   │
  │  per agent  │  │  gemini          │  │                  │
  └─────────────┘  └──────────────────┘  └──────────────────┘
                             │
                    DebateResult.to_dict()
                             │
                             ▼
  ┌──────────────────────────────────────────────────────────────┐
  │                      OUTPUT LAYER                             │
  │  ReportGenerator                                             │
  │  ├── Console  (rich panels + tables)                         │
  │  ├── JSON     (data/results/<name>_<timestamp>.json)         │
  │  └── Markdown (data/results/<name>_<timestamp>.md)           │
  └──────────────────────────────────────────────────────────────┘
```

---

## 8. Configuration Reference

The number of LLM API calls made per analysis depends on how many claims the Attacker raises and how many debate rounds occur. With `N` initial claims and `R` debate rounds per claim:

| Pipeline step | API calls |
|---|---|
| Attacker initial scan | 1 |
| Defender initial review | N |
| Attacker rebuttals (per round) | N × R (max) |
| Defender responses (per round) | N × R (max) |
| Judge initial assessment | N |
| Attacker clarification response | 0–N |
| Defender clarification response | 0–N |
| Judge final verdict (post-clarification) | 0–N |

**Minimum (0 claims):** 1 call
**Typical (5 claims, 2 rounds, no clarification):** 1 + 5 + 10 + 10 + 5 = **31 calls**
**Maximum (5 claims, 5 rounds, all clarification):** 1 + 5 + 25 + 25 + 5 + 5 + 5 + 5 = **76 calls**

Convergence-based early exit and Attacker concession reduce this in practice.

---

## 9. Design Decisions

### Single provider for all three agents
All three agents in a given run use the same LLM provider and model. The alternative — using different models for different agents — was not implemented. The `DebateManager` accepts one `BaseLLMProvider` instance shared by all agents.

### Raw contract code is sent without preprocessing
The contract is read as plain text and embedded directly in prompts. There is no AST parsing, comment stripping, or chunking. This is correct: LLMs are trained on raw Solidity and perform better on it than on extracted summaries. A `LanguageDetector` identifies the language by file extension and regex patterns, but produces only a label — it does not transform the code.

### Agents are stateless across claims, stateful within a claim
`clear_history()` is called between every claim. Within a single claim's debate, the Attacker and Defender accumulate conversation history across rebuttal rounds (via `include_history=True`). The Judge is always stateless.

### Convergence-based early exit
Rather than always running the maximum number of debate rounds, the system checks `attacker_confidence` and `defender_confidence` after each round. If either side has effectively settled (Attacker below 0.4, Defender above 0.8), remaining rounds are skipped. This reduces API costs without sacrificing quality on easy cases.

### JSON-first with fallback text parsing
All agents are instructed to produce JSON. `_send_message_json()` tries three extraction strategies before falling back. Both the Attacker (`_fallback_parse_claims`) and Judge (`_fallback_parse_verdict`) have dedicated fallback parsers for plain text. This makes the system robust to providers that ignore JSON instructions.

### The Judge's clarification is gated by two conditions
The clarification round only fires if **both** conditions hold:
1. The Judge's response sets `needs_clarification: true`
2. The Judge's `confidence < judge_confidence_threshold` (default 0.7)

This dual gate prevents the Judge from requesting unnecessary clarification on clear-cut cases where it marked `needs_clarification` out of caution but is actually fairly confident.

### Defender's verdict does not directly determine the final outcome
The Defender can return `VALID_VULNERABILITY` in its initial review, but this does not bypass the debate rounds or the Judge. The Defender's verdict is informational — the Judge always renders the binding decision.
