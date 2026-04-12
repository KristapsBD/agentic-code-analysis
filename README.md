# Agent Debate System for Smart Contract Vulnerability Detection

A multi agent LLM system that uses agent debate to detect vulnerabilities in blockchain smart contracts. Three specialised agents (Attacker, Defender, Judge) argue from opposing perspectives before a final verdict is rendered, mimicking a real security audit.

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
| `--web-search` | `-w` | on | Enable built-in web search grounding (Anthropic: `web_search_20260209`; Gemini: Google Search grounding). Use `--no-web-search` to disable. |

```bash
# Quick scan with Gemini
python -m src.main analyze data/benchmarks/medium/Reentrancy.sol
```

---

### `benchmark` — compare architectures

Runs the full 3-agent debate once per contract, then derives all three architecture results from the same LLM run (no extra API calls), and prints a side by side precision/recall/F1 comparison.

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
