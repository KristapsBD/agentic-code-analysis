"""CLI entry point for the Adversarial Agent System."""

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.config import LLMProvider, settings, setup_logging
from src.orchestration.debate_manager import DebateManager
from src.output.evaluator import Evaluator
from src.output.report import ReportGenerator
from src.providers.provider_factory import ProviderFactory

# Setup logging — returns a file path when DEBUG mode is active
_debug_log_file = setup_logging(settings.log_level)
logger = logging.getLogger(__name__)
if _debug_log_file:
    logger.debug(f"Full debug transcript → {_debug_log_file}")

app = typer.Typer(
    name="sca",
    help="Smart Contract Analyzer - Adversarial Agent System for Vulnerability Detection",
    add_completion=False,
)
console = Console()


def print_banner() -> None:
    """Print the application banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║     Smart Contract Analyzer - Adversarial Agent System        ║
║         Multi-Agent LLM Vulnerability Detection               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(Panel(banner, style="bold blue"))


@app.command()
def analyze(
    contract_path: Path = typer.Argument(
        ...,
        help="Path to the smart contract file to analyze",
        exists=True,
        readable=True,
    ),
    provider: LLMProvider = typer.Option(
        settings.default_provider,
        "--provider",
        "-p",
        help="LLM provider to use",
    ),
    rounds: int = typer.Option(
        settings.default_debate_rounds,
        "--rounds",
        "-r",
        help="Number of debate rounds",
        min=1,
        max=5,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path for the report (JSON format)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output",
    ),
    web_search: bool = typer.Option(
        True,
        "--web-search/--no-web-search",
        "-w",
        help=(
            "Enable built-in web search for all agents "
            "(Anthropic: web_search_20260209, Gemini: Google Search grounding). "
            "No effect on OpenAI. Increases latency and cost. Enabled by default."
        ),
    ),
) -> None:
    """
    Analyze a smart contract for vulnerabilities using adversarial debate.

    The system uses three agents (Attacker, Defender, Judge) to identify
    and verify potential security issues in the contract.
    """
    print_banner()

    try:
        settings.validate_provider_config(provider)
    except ValueError as e:
        console.print(f"[red]Configuration Error:[/red] {e}")
        raise typer.Exit(code=1)

    logger.info(f"Starting analysis of contract: {contract_path}")
    logger.info(f"Provider: {provider.value}, Rounds: {rounds}, Web Search: {web_search}")
    logger.debug(f"Verbose mode: {verbose}")

    console.print(f"[cyan]Analyzing:[/cyan] {contract_path}")
    console.print(f"[cyan]Provider:[/cyan] {provider.value}")
    console.print(f"[cyan]Debate Rounds:[/cyan] {rounds}")
    console.print(f"[cyan]Web Search:[/cyan] {'enabled' if web_search else 'disabled'}")
    if _debug_log_file:
        console.print(f"[cyan]Debug log:[/cyan] {_debug_log_file}")
    console.print()

    # Read the contract
    contract_code = contract_path.read_text()

    # Run the analysis
    with console.status("[bold green]Running adversarial analysis...") as status:
        result = asyncio.run(
            _run_analysis(contract_code, str(contract_path), provider, rounds, verbose, status, web_search)
        )

    # Generate and display report
    report_generator = ReportGenerator()
    report = report_generator.generate(result, str(contract_path))

    console.print()
    report_generator.print_to_console(report, console)

    # Save reports (always save to data/results/)
    results_dir = Path("data/results")
    results_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate filename from contract name and timestamp
    contract_name = contract_path.stem
    timestamp = result.get("started_at", "").replace(":", "-").split(".")[0] if isinstance(result.get("started_at"), str) else datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    json_path = results_dir / f"{contract_name}_{timestamp}.json"
    md_path = results_dir / f"{contract_name}_{timestamp}.md"
    
    # Save JSON (full details)
    report_generator.save_json(report, json_path)
    logger.info(f"JSON report saved to: {json_path}")

    # Save Markdown (human-readable)
    report_generator.save_markdown(report, md_path)
    logger.info(f"Markdown report saved to: {md_path}")

    # Save full debate transcript
    import json as _json
    transcript_path = results_dir / f"{contract_name}_{timestamp}_transcript.json"
    transcript_path.write_text(_json.dumps(result, indent=2, default=str))
    logger.info(f"Transcript saved to: {transcript_path}")

    console.print(f"\n[green]✓ Reports saved:[/green]")
    console.print(f"  JSON:       {json_path}")
    console.print(f"  Markdown:   {md_path}")
    console.print(f"  Transcript: {transcript_path}")
    
    # Save to custom path if specified
    if output:
        report_generator.save_json(report, output)
        console.print(f"  Custom: {output}")


async def _run_analysis(
    contract_code: str,
    contract_path: str,
    provider: LLMProvider,
    rounds: int,
    verbose: bool,
    status: "rich.status.Status",
    web_search: bool = False,
) -> dict:
    """Run the adversarial analysis asynchronously."""
    logger.debug(f"Creating LLM provider: {provider.value}")
    # Create provider
    llm_provider = ProviderFactory.create(provider)
    logger.debug(f"Provider created: {llm_provider.provider_name}")

    # Create debate manager
    logger.debug(f"Initializing DebateManager with {rounds} rounds, web_search={web_search}")
    debate_manager = DebateManager(
        provider=llm_provider,
        max_rounds=rounds,
        judge_clarification_trigger=settings.judge_clarification_trigger,
        verbose=verbose,
        web_search=web_search,
    )

    # Run debate
    status.update("[bold green]Agents scanning for vulnerabilities...")
    logger.info("Starting adversarial debate...")
    result = await debate_manager.run_debate(contract_code, contract_path)
    logger.info(
        f"Debate complete - {result.get('confirmed_vulnerabilities', 0)} confirmed "
        f"/ {result.get('total_vulnerabilities', 0)} total vulnerabilities"
    )

    return result


@app.command()
def benchmark(
    benchmark_dir: Path = typer.Argument(
        ...,
        help="Path to the benchmark directory containing smart contracts",
        exists=True,
        dir_okay=True,
        file_okay=False,
    ),
    ground_truth: Optional[Path] = typer.Option(
        None,
        "--ground-truth",
        "-g",
        help="JSON file with labeled ground truth vulnerabilities (strongly recommended)",
    ),
    provider: LLMProvider = typer.Option(
        settings.default_provider,
        "--provider",
        "-p",
        help="LLM provider to use",
    ),
    rounds: int = typer.Option(
        settings.default_debate_rounds,
        "--rounds",
        "-r",
        help="Number of debate rounds for the multi-agent pipeline",
        min=1,
        max=5,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path for combined benchmark results (JSON)",
    ),
    delay: float = typer.Option(
        5.0,
        "--delay",
        "-d",
        help="Seconds to wait between contracts to avoid API rate limiting",
        min=0.0,
    ),
) -> None:
    """
    Compare multi-agent pipeline vs. single-prompt baseline on a benchmark dataset.

    Runs both approaches on all contracts in the benchmark directory and
    prints a side-by-side precision/recall/F1 comparison.
    """
    import json as _json

    print_banner()

    try:
        settings.validate_provider_config(provider)
    except ValueError as e:
        console.print(f"[red]Configuration Error:[/red] {e}")
        raise typer.Exit(code=1)

    if not ground_truth:
        console.print(
            "[yellow]Warning:[/yellow] No --ground-truth file provided. "
            "Metrics will use filename-inferred labels (SmartBugs format)."
        )

    console.print(f"[cyan]Benchmark Directory:[/cyan] {benchmark_dir}")
    console.print(f"[cyan]Provider:[/cyan] {provider.value}")
    console.print(f"[cyan]Debate Rounds:[/cyan] {rounds}")
    console.print(f"[cyan]Inter-Contract Delay:[/cyan] {delay}s")
    console.print()

    evaluator = Evaluator(provider=provider, max_rounds=rounds)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    trace_dir = Path(f"data/results/transcripts/benchmark_{timestamp}")

    # Single pass — all three architectures derived from the same LLM run:
    #   3-agent:  Attacker → Defender → Judge (judge-confirmed claims)
    #   2-agent:  Attacker + Defender only (claims attacker did not concede)
    #   baseline: Attacker's raw initial claims, all accepted as-is
    with console.status("[bold green]Attacker → Defender → Judge debate in progress..."):
        multi_result, two_agent_result, baseline_result = asyncio.run(
            evaluator.evaluate_both(
                benchmark_dir, ground_truth, trace_dir=trace_dir, inter_contract_delay=delay
            )
        )

    console.print()
    console.print("[bold cyan]3-Agent Results (Attacker + Defender + Judge):[/bold cyan]")
    evaluator.print_results(multi_result, console)

    console.print()
    console.print("[bold cyan]2-Agent Results (Attacker + Defender, no Judge):[/bold cyan]")
    evaluator.print_results(two_agent_result, console)

    console.print()
    console.print("[bold cyan]Baseline Results (attacker-only, no debate):[/bold cyan]")
    evaluator.print_results(baseline_result, console)

    # Print three-way comparison
    console.print()
    evaluator.print_three_way_comparison(multi_result, two_agent_result, baseline_result, console)

    # Save combined output
    output_path = output or Path(f"data/results/benchmark_{timestamp}.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    combined = {
        "multi_agent": multi_result.to_dict(),
        "two_agent": two_agent_result.to_dict(),
        "baseline": baseline_result.to_dict(),
    }
    output_path.write_text(_json.dumps(combined, indent=2, default=str))
    console.print(f"\n[green]Results saved to:[/green] {output_path}")
    console.print(f"[green]Transcripts saved to:[/green] {trace_dir}/")


@app.command()
def info() -> None:
    """Display system configuration and status."""
    print_banner()

    table = Table(title="Configuration", show_header=True, header_style="bold magenta")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Default Provider", settings.default_provider.value)
    table.add_row("OpenAI Model", settings.default_model_openai)
    table.add_row("Anthropic Model", settings.default_model_anthropic)
    table.add_row("Gemini Model", settings.default_model_gemini)
    table.add_row("Debate Rounds", str(settings.default_debate_rounds))
    table.add_row("Temp (Attacker Scan)", str(settings.temp_attacker_scan))
    table.add_row("Temp (Debate)", str(settings.temp_debate))
    table.add_row("Temp (Clarification)", str(settings.temp_clarification))
    table.add_row("Temp (Judge)", str(settings.temp_judge))
    table.add_row("Judge Clarification Trigger", settings.judge_clarification_trigger.value)
    table.add_row("Log Level", settings.log_level)

    # API Key status
    openai_status = "✓ Configured" if settings.openai_api_key else "✗ Not Set"
    anthropic_status = "✓ Configured" if settings.anthropic_api_key else "✗ Not Set"
    gemini_status = "✓ Configured" if settings.gemini_api_key else "✗ Not Set"
    table.add_row("OpenAI API Key", openai_status)
    table.add_row("Anthropic API Key", anthropic_status)
    table.add_row("Gemini API Key", gemini_status)

    console.print(table)


if __name__ == "__main__":
    app()
