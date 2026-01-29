# Adversarial Agent System for Smart Contract Vulnerability Detection

A multi-agent LLM system that uses adversarial debate to detect vulnerabilities in blockchain smart contracts. This approach mimics real-world security audits by having agents argue from different perspectives (Attacker vs. Defender) with a Judge making final decisions.

## Concept

The system employs three specialized agents:

1. **Attacker Agent**: Aggressively scans code for potential vulnerabilities
2. **Defender Agent**: Reviews and challenges the Attacker's claims, acting as a developer advocate
3. **Judge Agent**: Evaluates arguments from both sides and renders verdicts with confidence scores

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd agentic-code-analysis

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .

# Or install from requirements
pip install -r requirements.txt
```

## Configuration

Copy the example environment file and configure your API keys:

```bash
cp .env.example .env
```

Edit `.env` with your API keys:

```
OPENAI_API_KEY=sk-your-openai-api-key
ANTHROPIC_API_KEY=sk-ant-your-anthropic-api-key
GEMINI_API_KEY=your-gemini-api-key
```

### Provider Pricing & Free Tiers

For **testing and development**, we recommend using **Google Gemini**:

| Provider | Free/Cheap Option | Best For |
|----------|------------------|----------|
| **Google Gemini** | **Gemini 1.5 Flash (FREE tier)** ✓ | **Testing & refactoring** |
| **OpenAI** | GPT-4o mini (paid, ~$0.15/1M tokens) | Production, best reasoning |
| **Anthropic Claude** | Claude 3.5 Haiku (paid, ~$0.25/1M tokens) | Consistency, enterprise |

**Recommendation for thesis development:**
- Use **Gemini 1.5 Flash** (free tier) for rapid prototyping and testing
- Switch to **GPT-4o** for final evaluation runs (better vulnerability detection quality)
- Keep **Anthropic Claude** for comparative analysis

Get your Gemini API key (free): https://makersuite.google.com/app/apikey

## Usage

### Analyze a Single Contract

```bash
# Using OpenAI (default)
python -m src.main analyze contract.sol

# Using Anthropic
python -m src.main analyze contract.sol --provider anthropic

# Using Gemini (FREE tier - recommended for testing)
python -m src.main analyze contract.sol --provider gemini

# With multiple debate rounds
python -m src.main analyze contract.sol --rounds 3
```

### Batch Evaluation

```bash
# Evaluate against benchmark dataset
python -m src.main evaluate ./data/benchmarks/smartbugs/ --output results.json
```

### Compare Providers

```bash
# Compare results across all providers (OpenAI, Anthropic, Gemini)
python -m src.main compare contract.sol
```

## Project Structure

```
agentic-code-analysis/
├── src/
│   ├── agents/          # Agent implementations (Attacker, Defender, Judge)
│   ├── providers/       # LLM provider abstraction (OpenAI, Anthropic)
│   ├── orchestration/   # Debate management and conversation flow
│   ├── knowledge/       # Vulnerability database and prompt templates
│   ├── parsers/         # Smart contract parsing
│   └── output/          # Report generation and evaluation
├── data/
│   ├── benchmarks/      # Vulnerability datasets
│   └── results/         # Analysis results
└── tests/               # Unit and integration tests
```

## Supported Vulnerability Categories

| Category | Examples |
|----------|----------|
| Reentrancy | Classic, Cross-function, Read-only reentrancy |
| Access Control | Missing modifiers, tx.origin auth, Unprotected functions |
| Arithmetic | Integer overflow/underflow, Division by zero |
| Logic | Business logic flaws, Oracle/Price manipulation |
| Gas | DoS with gas limit, Unbounded loops |
| External Calls | Unchecked return values, Delegatecall risks |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=src

# Format code
black src tests

# Lint
ruff check src tests
```

## Quick Start

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .

# Configure API keys
cp .env.example .env
# Edit .env with your OpenAI/Anthropic API keys

# Run analysis on a sample contract
python -m src.main analyze data/benchmarks/custom/reentrancy_vulnerable.sol

# Run evaluation on benchmark dataset
python -m src.main evaluate data/benchmarks/custom/ --output results.json
```

## Project Structure

For a detailed explanation of the architecture and component organization, see [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md).

## License

MIT License
