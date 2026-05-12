# Agent Debate System for Smart Contract Vulnerability Detection

A multi agent LLM system that uses agent debate to detect vulnerabilities in blockchain smart contracts. Three agents (Attacker, Defender, Judge) argue from opposing perspectives before a final verdict is rendered, simulating a security audit.

## Installation

### Windows (PowerShell / CMD)

```bash
git clone <repository-url>
cd agentic-analysis

python -m venv venv
venv\Scripts\activate

pip install -e .
```

### WSL / Linux / macOS

```bash
git clone <repository-url>
cd agentic-analysis

python3 -m venv venv
source venv/bin/activate

pip install -e .
```

### Running from WSL when venv was created on Windows

```bash
venv/Scripts/python.exe -m src.main <command>
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
| `--web-search` | `-w` | on | Enable built-in web search grounding. Use `--no-web-search` to disable. |
| `--static-analysis` | `-s` | off | Run Slither before the debate and inject findings into the Attackers scan prompt. |

```bash
# Quick scan with Gemini
python -m src.main analyze data/benchmarks/medium/Reentrancy.sol
```

---

### `benchmark` — compare architectures

Runs full 3 agent debate once per contract, then calculates all three architecture results from the same LLM run, and prints a side by side precision/recall/F1 comparison.

```bash
python -m src.main benchmark <BENCHMARK_DIR> [OPTIONS]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--ground-truth` | `-g` | — | JSON file with labelled ground truth |
| `--provider` | `-p` | `gemini` | LLM provider |
| `--rounds` | `-r` | `2` | Debate rounds per claim |
| `--output` | `-o` | auto | Combined JSON output path |
| `--delay` | `-d` | `5.0` | Seconds to wait between contracts |

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
│   ├── tools/            # External tool integrations
│   ├── config.py         # Settings, environment loading
│   └── main.py           # CLI entry point
├── data/
│   ├── benchmarks/       # Smart contracts and ground truth labels
│   │   └── ground_truth/ # JSON ground truth files
│   ├── logs/             # Debug transcripts
│   └── results/          # Analysis and evaluation output
└── tests/
```
