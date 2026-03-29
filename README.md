# Adversarial Agent System for Smart Contract Vulnerability Detection

A multi-agent LLM system that uses adversarial debate to detect vulnerabilities in blockchain smart contracts. Three specialised agents (Attacker, Defender, Judge) argue from opposing perspectives before a final verdict is rendered, mimicking a real security audit.

## How It Works

```
Contract ──► Attacker (finds vulnerabilities)
                │
                ▼
         Defender (challenges each claim)
                │
         ◄──────┘  N debate rounds
                │
                ▼
           Judge (renders final verdict per claim)
                │
                ▼
           Confirmed findings → Report
```

## Installation

```bash
git clone <repository-url>
cd agentic-analysis

python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

pip install -e .
```

## Configuration

```bash
cp .env.example .env
```

Required keys in `.env`:

```
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GEMINI_API_KEY=AI...

# Optional overrides
DEFAULT_PROVIDER=gemini          # openai | anthropic | gemini
OPENAI_MODEL=gpt-4o
ANTHROPIC_MODEL=claude-sonnet-4-6
GEMINI_MODEL=gemini-2.5-flash
DEFAULT_DEBATE_ROUNDS=2
LOG_LEVEL=INFO                   # INFO | DEBUG

# Temperature per pipeline phase (0.0 = deterministic, 2.0 = very creative)
TEMP_ATTACKER_SCAN=0.4           # Initial vulnerability scan
TEMP_DEBATE=0.3                  # Attacker/defender debate rounds
TEMP_CLARIFICATION=0.2           # Factual clarification responses
TEMP_JUDGE=0.2                   # Judge verdict rendering

# Judge confidence threshold — below this the judge may request one clarification round
# LOW = only trigger clarification when judge is genuinely uncertain; MEDIUM = more rounds
JUDGE_CLARIFICATION_TRIGGER=LOW
```

### Provider comparison

| Provider | Default model | Free tier | Notes |
|---|---|---|---|
| **Gemini** | `gemini-3-pro-preview` | Yes (limited) | Recommended for development |
| **OpenAI** | `gpt-4o` | No | Best reasoning quality |
| **Anthropic** | `claude-sonnet-4-6` | No | Consistent, structured output |

---

## Commands

### `analyze` — scan a single contract

```bash
python -m src.main analyze <CONTRACT_PATH> [OPTIONS]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--provider` | `-p` | `gemini` | LLM provider: `openai`, `anthropic`, `gemini` |
| `--rounds` | `-r` | `2` | Debate rounds per claim (1–5) |
| `--output` | `-o` | auto | Output path for JSON + Markdown report |
| `--verbose` | `-v` | off | Print agent dialogue to console |
| `--web-search` | `-w` | off | Enable built-in web search grounding (Anthropic: `web_search_20260209`; Gemini: Google Search grounding) |

```bash
# Quick scan with Gemini
python -m src.main analyze data/benchmarks/medium/Reentrancy.sol

# Deep scan: 3 rounds, web search, verbose output
python -m src.main analyze contract.sol --rounds 3 --web-search --verbose

# Save to a specific path
python -m src.main analyze contract.sol --provider anthropic --output data/results/my_scan.json
```

---

### `benchmark` — compare architectures *(primary research command)*

Runs the full 3-agent debate once per contract, then derives all three architecture results from the same LLM run (no extra API calls), and prints a side-by-side precision/recall/F1 comparison.

| Architecture | What counts as a valid finding |
|---|---|
| **3-agent** | Judge confirmed (`verdict.is_valid = True`) |
| **2-agent** | Defender did not explicitly reject the claim (`defender_verdict != "INVALID_CLAIM"`) |
| **Baseline** | All initial Attacker claims, accepted as-is |

```bash
python -m src.main benchmark <BENCHMARK_DIR> [OPTIONS]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--ground-truth` | `-g` | — | JSON file with labelled ground truth (strongly recommended) |
| `--provider` | `-p` | `gemini` | LLM provider |
| `--rounds` | `-r` | `2` | Debate rounds per claim |
| `--output` | `-o` | auto | Combined JSON output path |
| `--delay` | `-d` | `5.0` | Seconds to wait between contracts (avoids API rate limiting) |

```bash
python -m src.main benchmark data/benchmarks/medium \
    --ground-truth data/benchmarks/ground_truth/medium_benchmark.json \
    --provider gemini \
    --delay 5
```

The output JSON contains three top-level keys: `"multi_agent"`, `"two_agent"`, and `"baseline"`.

---

### `evaluate` — run evaluation only (no baseline comparison)

```bash
python -m src.main evaluate <BENCHMARK_DIR> [OPTIONS]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--ground-truth` | `-g` | — | JSON file with labelled ground truth |
| `--provider` | `-p` | `gemini` | LLM provider |
| `--rounds` | `-r` | `2` | Debate rounds per claim |
| `--output` | `-o` | `data/results/evaluation.json` | Output path |

```bash
python -m src.main evaluate data/benchmarks/medium \
    --ground-truth data/benchmarks/ground_truth/medium_benchmark.json \
    --provider openai \
    --output data/results/openai_eval.json
```

---

### `compare` — run all three providers on one contract

```bash
python -m src.main compare <CONTRACT_PATH> [OPTIONS]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--rounds` | `-r` | `2` | Debate rounds |
| `--output` | `-o` | — | JSON output path |

```bash
python -m src.main compare data/benchmarks/medium/Reentrancy.sol
```

---

### `info` — display current configuration

```bash
python -m src.main info
```

---

## Ground truth format

```json
[
  {
    "contract_path": "data/benchmarks/medium/Reentrancy.sol",
    "vulnerabilities": [
      { "type": "reentrancy" }
    ]
  }
]
```

---

## Project structure

```
agentic-analysis/
├── src/
│   ├── agents/           # Attacker, Defender, Judge agent implementations
│   ├── providers/        # LLM provider abstraction (OpenAI, Anthropic, Gemini)
│   ├── orchestration/    # Debate manager and conversation tracking
│   ├── knowledge/        # Prompt templates and vulnerability type definitions
│   ├── output/           # Report generation and benchmark evaluation
│   ├── config.py         # Settings, environment loading
│   └── main.py           # CLI entry point
├── data/
│   ├── benchmarks/       # Smart contracts and ground truth labels
│   │   └── ground_truth/ # JSON ground truth files
│   ├── logs/             # Debug transcripts (created when LOG_LEVEL=DEBUG)
│   └── results/          # Analysis and evaluation output
└── tests/
```
