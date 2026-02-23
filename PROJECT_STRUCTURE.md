# Project Structure Guide

This document explains the architecture and organization of the Adversarial Agent System for Smart Contract Vulnerability Detection.

## Overview

The system uses a **multi-agent adversarial debate approach** where three specialized LLM agents (Attacker, Defender, Judge) collaborate to identify and verify vulnerabilities in smart contracts. The architecture is modular, extensible, and follows clean separation of concerns.

## Directory Structure

```
agentic-code-analysis/
├── src/                          # Main source code
│   ├── main.py                  # CLI entry point
│   ├── config.py                # Configuration management
│   │
│   ├── agents/                  # Agent implementations
│   │   ├── base_agent.py        # Abstract base class
│   │   ├── attacker_agent.py    # Vulnerability scanner
│   │   ├── defender_agent.py    # Claim verifier
│   │   └── judge_agent.py       # Final arbiter
│   │
│   ├── providers/               # LLM provider abstraction
│   │   ├── base_provider.py     # Interface definition
│   │   ├── openai_provider.py   # OpenAI implementation
│   │   ├── anthropic_provider.py # Anthropic implementation
│   │   └── provider_factory.py  # Factory pattern
│   │
│   ├── orchestration/            # Debate coordination
│   │   ├── debate_manager.py    # Main orchestrator
│   │   └── conversation.py      # State management
│   │
│   ├── knowledge/               # Vulnerability intelligence
│   │   ├── vulnerability_db.py  # Pattern database
│   │   └── prompts/             # Agent prompts
│   │       ├── attacker.py
│   │       ├── defender.py
│   │       └── judge.py
│   │
│   └── output/                   # Results & evaluation
│       ├── report.py            # Report generation
│       └── evaluator.py         # Benchmark evaluation
│
├── tests/                        # Test suite
│   ├── test_agents.py
│   ├── test_providers.py
│   └── test_debate.py
│
├── data/                         # Data directory
│   ├── benchmarks/              # Test contracts
│   │   └── custom/              # Sample vulnerable contracts
│   └── results/                 # Analysis results (gitignored)
│
├── .env.example                  # Environment template
├── .gitignore                    # Git ignore rules
├── requirements.txt             # Python dependencies
├── pyproject.toml               # Project configuration
└── README.md                    # User documentation
```

## Core Components

### 1. Agent Layer (`src/agents/`)

The system uses three specialized agents that mimic a real-world security audit:

#### **AttackerAgent** (`attacker_agent.py`)
- **Role**: Aggressively scans code for vulnerabilities
- **Behavior**: High sensitivity, flags potential issues
- **Output**: List of vulnerability claims with evidence
- **Key Methods**:
  - `analyze()`: Initial vulnerability scan
  - `respond_to_defense()`: Rebuttal or concession

#### **DefenderAgent** (`defender_agent.py`)
- **Role**: Reviews and challenges vulnerability claims
- **Behavior**: Critical analysis, looks for mitigations
- **Output**: Defense arguments or acknowledgments
- **Key Methods**:
  - `analyze()`: Review a claim and provide defense
  - `respond_to_rebuttal()`: Counter-argument or concession

#### **JudgeAgent** (`judge_agent.py`)
- **Role**: Impartial arbiter making final decisions
- **Behavior**: Evaluates both arguments objectively
- **Output**: Verdict with confidence scores
- **Key Methods**:
  - `analyze()`: Render verdict on a claim

**Base Agent** (`base_agent.py`):
- Abstract base class providing common functionality
- Manages conversation history
- Handles LLM communication

### 2. Provider Layer (`src/providers/`)

Abstracts LLM provider differences for easy switching:

#### **BaseLLMProvider** (`base_provider.py`)
- Defines interface: `complete()`, `complete_simple()`
- Handles message formatting
- Returns structured `LLMResponse` objects

#### **OpenAIProvider** (`openai_provider.py`)
- Implements OpenAI API (GPT-4o, GPT-4-turbo, etc.)
- Handles chat completions
- Extracts token usage

#### **AnthropicProvider** (`anthropic_provider.py`)
- Implements Anthropic API (Claude models)
- Handles system prompts separately
- Compatible with Claude 3.5 Sonnet

#### **ProviderFactory** (`provider_factory.py`)
- Creates provider instances based on configuration
- Validates API keys
- Supports multiple providers simultaneously

### 3. Orchestration Layer (`src/orchestration/`)

Coordinates the multi-agent debate:

#### **DebateManager** (`debate_manager.py`)
- Main orchestrator for the analysis pipeline
- **Flow**:
  1. Attacker scans contract → generates claims
  2. For each claim:
     - Defender reviews → provides defense
     - Attacker rebuts (optional rounds)
     - Defender responds (optional rounds)
     - Judge renders verdict
  3. Compiles final report

#### **Conversation** (`conversation.py`)
- Tracks all agent interactions
- Maintains debate history per claim
- Provides context for multi-round debates
- Estimates token usage

### 4. Knowledge Layer (`src/knowledge/`)

Contains vulnerability intelligence:

#### **VulnerabilityDB** (`vulnerability_db.py`)
- Database of 15+ vulnerability patterns:
  - Reentrancy (classic, read-only)
  - Access Control (unprotected, tx.origin)
  - Arithmetic (overflow, division by zero)
  - Unchecked Calls (return values, delegatecall)
  - Denial of Service (gas limit, revert)
  - Front-running, Oracle manipulation, etc.
- Each pattern includes:
  - Code patterns to detect
  - Indicators
  - Common mitigations
  - SWC Registry IDs

#### **Prompts** (`prompts/`)
- Carefully crafted system prompts for each agent
- Templates for different analysis scenarios
- Include vulnerability knowledge and best practices

### 5. Output Layer (`src/output/`)

Handles results and evaluation:

#### **ReportGenerator** (`report.py`)
- Generates reports in multiple formats:
  - **Console**: Rich-formatted terminal output
  - **JSON**: Structured data for programmatic use
  - **Markdown**: Human-readable documentation
- Summarizes findings by severity
- Includes recommendations

#### **Evaluator** (`evaluator.py`)
- Benchmarks system against test datasets
- Calculates metrics:
  - Precision, Recall, F1 Score
  - Macro and micro averages
  - True/False positives/negatives
- Supports SmartBugs format
- Generates evaluation reports

## Data Flow

```
┌─────────────────┐
│ Smart Contract │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Language        │
│ Detector       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Parser          │
│ (Extract        │
│  Structure)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Debate Manager  │
└────────┬────────┘
         │
         ├──► Attacker Agent ──► LLM Provider
         │         │
         │         └──► Vulnerability Claims
         │
         ├──► Defender Agent ──► LLM Provider
         │         │
         │         └──► Defense Arguments
         │
         └──► Judge Agent ────► LLM Provider
                   │
                   └──► Verdicts
         │
         ▼
┌─────────────────┐
│ Report Generator│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Output          │
│ (Console/JSON/  │
│  Markdown)      │
└─────────────────┘
```

## Configuration

### Environment Variables (`.env`)

The system uses environment variables for configuration:

- **API Keys**: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`
- **Provider**: `DEFAULT_PROVIDER` (openai/anthropic)
- **Models**: `DEFAULT_MODEL_OPENAI`, `DEFAULT_MODEL_ANTHROPIC`
- **Debate**: `DEFAULT_DEBATE_ROUNDS`, `DEFAULT_TEMPERATURE`
- **Logging**: `LOG_LEVEL`

See `.env.example` for template.

### Configuration Management (`src/config.py`)

- Uses Pydantic for type-safe settings
- Validates environment variables
- Provides defaults
- Supports multiple providers

## CLI Commands

The system provides three main commands:

### `analyze`
Analyze a single contract:
```bash
python -m src.main analyze contract.sol --provider openai --rounds 2
```

### `evaluate`
Run benchmark evaluation:
```bash
python -m src.main evaluate ./data/benchmarks/ --output results.json
```

### `compare`
Compare providers:
```bash
python -m src.main compare contract.sol
```

## Extension Points

The architecture supports easy extension:

1. **New LLM Providers**: Implement `BaseLLMProvider`
2. **New Languages**: Implement `BaseParser`
3. **New Vulnerability Patterns**: Add to `VulnerabilityDB`
4. **Custom Agents**: Extend `BaseAgent`
5. **New Output Formats**: Extend `ReportGenerator`

## Testing

Comprehensive test suite in `tests/`:
- Unit tests for each component
- Mock LLM providers for testing
- Integration tests for debate flow
- Parser validation tests

Run tests:
```bash
pytest
```

## Dependencies

Key dependencies:
- **openai**: OpenAI API client
- **anthropic**: Anthropic API client
- **pydantic**: Settings and data validation
- **typer**: CLI framework
- **rich**: Beautiful terminal output
- **aiofiles**: Async file operations

See `requirements.txt` for complete list.

## Design Principles

1. **Modularity**: Each component has a single responsibility
2. **Extensibility**: Easy to add new providers, languages, patterns
3. **Type Safety**: Pydantic models throughout
4. **Async-First**: All LLM calls are async for performance
5. **Testability**: Mock-friendly interfaces
6. **Documentation**: Comprehensive docstrings and type hints

## Future Enhancements

Potential improvements:
- Support for more smart contract languages (Rust, Move)
- Additional LLM providers (Gemini, Llama)
- Web UI for interactive analysis
- Integration with existing security tools (Slither, Mythril)
- Real-time analysis for development workflows
